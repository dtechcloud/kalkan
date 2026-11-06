# SPDX-License-Identifier: MIT
"""Tests for the ``kalkan audit`` command through kalkan.cli.main.

No real doctor, setup, browser or Claude Code runs: the doctor returns prepared reports, the
setup records its commands, and the unattended runner gets a fake loop that finishes the run.
The engine itself runs in this process. ``fast_engine`` skips every external tool at once;
``no_tools`` leaves the real adapters with an empty PATH and an empty kalkan home, so only the
built-in matcher finds candidates.
"""

from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime
from pathlib import Path

import pytest

from kalkan import cli
from kalkan.audit import commands
from kalkan.audit.preflight import DATABASES_COMMAND, TOOLS_COMMAND, SetupStep
from kalkan.cli import main
from kalkan.findings.merge import merge_run
from kalkan.report.commands import write_report
from kalkan.report.model import build_model
from kalkan.run import ids, state
from kalkan.run import init as init_mod
from kalkan.run.init import init_run
from kalkan.run.state import load_context
from kalkan.sca.vulndb import DEFAULT_ECOSYSTEMS
from kalkan.scanners import base
from kalkan.tools.doctor import Check, DoctorReport
from kalkan.unattended import commands as unattended
from kalkan.unattended import hosts
from kalkan.unattended.hosts import ClaudeHost
from kalkan.unattended.loop import UnattendedResult

TARGETS = Path(__file__).resolve().parents[1] / "fixtures" / "targets"
ALL_DATABASES = {"osv_ecosystems": list(DEFAULT_ECOSYSTEMS), "grype": True, "go": {"x": 1}}
MOMENT = datetime(2026, 10, 25, 12, tzinfo=UTC)


@pytest.fixture(autouse=True)
def only_audit(monkeypatch):
    """Load only kalkan.audit.commands, so that other modules cannot break these tests."""
    selected = {k: v for k, v in cli.COMMANDS.items() if v[0] == "kalkan.audit.commands"}
    monkeypatch.setattr(cli, "COMMANDS", selected)


class Doctor:
    """Returns the prepared reports in order (the last one repeats) and records the calls."""

    def __init__(self, *reports: DoctorReport) -> None:
        self.reports = list(reports) or [clean_report()]
        self.calls: list[dict] = []

    def __call__(self, **kwargs):
        self.calls.append(kwargs)
        return self.reports[min(len(self.calls), len(self.reports)) - 1]


def make_report(*checks: Check) -> DoctorReport:
    return DoctorReport(tuple(checks), "linux-amd64", "/fake")


def clean_report() -> DoctorReport:
    return make_report(
        Check("python", "ok", "Python 3.13"),
        Check("claude", "ok", "2.1.301 (Claude Code); signed in"),
        Check("tool:trivy", "ok", "0.75.0 installed"),
        Check("vulndb", "ok", "OSV: 13 ecosystems", ALL_DATABASES),
    )


def missing_report() -> DoctorReport:
    return make_report(
        Check("python", "ok", "Python 3.13"),
        Check("tool:trivy", "fail", "not installed; run: kalkan tools install trivy"),
        Check("tool:opengrep", "fail", "not installed; run: kalkan tools install opengrep"),
        Check("vulndb", "warn", "no local vulnerability databases", {"osv_ecosystems": []}),
    )


@pytest.fixture
def env(tmp_path, monkeypatch):
    runs, repo, work = tmp_path / "runs", tmp_path / "repo", tmp_path / "work"
    repo.mkdir()
    app = work / "app"
    shutil.copytree(TARGETS / "webapp", app)
    monkeypatch.setenv(ids.RUNS_DIR_ENV, str(runs))
    monkeypatch.setattr(init_mod, "git_head", lambda directory: None)
    opened: list[Path] = []
    setups: list[list] = []
    asked: list[str] = []
    doctor = Doctor()

    def run_setup(found):
        setups.append(list(found))
        return [SetupStep(tuple(arguments), 0) for arguments in found]

    monkeypatch.setattr(commands, "_plugin_install", lambda: False)
    monkeypatch.setattr(commands, "_cwd", lambda: work)
    monkeypatch.setattr(commands, "_interactive", lambda: False)
    monkeypatch.setattr(commands, "_ask", lambda question: asked.append(question) or False)
    monkeypatch.setattr(commands, "_doctor", doctor)
    monkeypatch.setattr(commands, "_run_setup", run_setup)
    monkeypatch.setattr(commands, "_open_in_browser", lambda path: opened.append(path) or True)
    monkeypatch.setattr(unattended, "_plugin_install", lambda: False)
    monkeypatch.setattr(unattended, "_repo_root", lambda: repo)
    monkeypatch.setattr(unattended, "_runs_root", lambda: runs)
    monkeypatch.setattr(unattended, "_cwd", lambda: work)
    monkeypatch.setattr(unattended, "_workspace_trusted", lambda _repo: True)
    monkeypatch.setattr(
        unattended, "_create_host", lambda name, require: ClaudeHost("/opt/claude/bin/claude")
    )

    class Env:
        pass

    found = Env()
    found.__dict__.update(
        runs=runs,
        repo=repo,
        work=work,
        app=app,
        opened=opened,
        setups=setups,
        asked=asked,
        doctor=doctor,
        monkeypatch=monkeypatch,
    )
    return found


def use_doctor(env, *reports):
    env.doctor = Doctor(*reports)
    env.monkeypatch.setattr(commands, "_doctor", env.doctor)


@pytest.fixture
def fast_engine(monkeypatch):
    def run_adapter(adapter, ctx, *, timeout_seconds=None, **kwargs):
        return base.ScanResult(
            engine=adapter.name,
            status="skipped",
            output_path=None,
            message=f"tool not found: {adapter.name} (test)",
            duration_seconds=0.0,
            exit_code=None,
            tool_version=None,
        )

    monkeypatch.setattr(base, "run_adapter", run_adapter)


@pytest.fixture
def no_tools(tmp_path, monkeypatch):
    home, empty = tmp_path / "home", tmp_path / "empty-bin"
    home.mkdir()
    empty.mkdir()
    monkeypatch.setenv("KALKAN_HOME", str(home))
    monkeypatch.setenv("PATH", str(empty))


def runs_made(env) -> list[str]:
    if not env.runs.is_dir():
        return []
    return sorted(p.name for p in env.runs.iterdir() if p.is_dir())


def run_cli(capsys, *argv):
    code = main(["audit", *argv])
    captured = capsys.readouterr()
    return code, captured.out, captured.err


# ---------------------------------------------------------------------------------------------
# Arguments


def test_help_lists_the_options(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["audit", "--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    for option in ("--profile", "--tools-only", "--open", "--yes", "--no-latest", "--json"):
        assert option in out
    assert "exit codes: 0 done" in out


def test_usage_errors(env, capsys):
    for argv in (["app", "--max-hours", "0"], ["app", "--profile", "huge"], ["devam", "x"]):
        with pytest.raises(SystemExit) as exc:
            main(["audit", *argv])
        assert exc.value.code == 2
    capsys.readouterr()


def test_a_run_id_works_only_with_devam(env, capsys):
    code, _, err = run_cli(capsys, "app", "20261025T101500Z-app-1a2b")
    assert code == 1 and "works only with devam" in err


def test_devam_without_a_run(env, capsys):
    code, _, err = run_cli(capsys, "devam")
    assert code == 1 and "no run to resume" in err and "kalkan audit <target>" in err


def test_a_missing_target_folder(env, capsys):
    code, _, err = run_cli(capsys, "no-such-folder", "--tools-only")
    assert code == 1 and "does not exist" in err
    assert env.doctor.calls == []


# ---------------------------------------------------------------------------------------------
# Setup checks


def test_missing_tools_without_consent_stop_with_exit_code_5(env, capsys):
    use_doctor(env, missing_report())
    code, out, err = run_cli(capsys, "app", "--tools-only")
    assert code == commands.EXIT_SETUP == 5
    assert out == ""
    app = env.app.resolve().as_posix()
    assert "setup needed: 2 pinned tools are missing or broken: trivy, opengrep" in err
    assert "  kalkan tools install --all" in err and "  kalkan sca update-db --max-age 168" in err
    assert f"Or let the audit install them first: kalkan audit {app} --tools-only --yes" in err
    assert env.setups == [] and env.asked == []  # not a terminal: no question
    assert runs_made(env) == []  # no run was created
    assert env.doctor.calls[0]["skip"] == frozenset({"docker", "node", "claude"})


def test_yes_installs_then_audits(env, capsys, fast_engine):
    use_doctor(env, missing_report(), clean_report())
    code, out, err = run_cli(capsys, "app", "--tools-only", "--yes")
    assert code == 0, err
    assert env.setups == [[TOOLS_COMMAND, DATABASES_COMMAND]]
    assert len(env.doctor.calls) == 2  # the checks run again after the setup
    assert out.startswith("Tools-only audit done: run ")
    assert len(runs_made(env)) == 1


def test_the_question_on_a_terminal(env, capsys, fast_engine):
    use_doctor(env, missing_report(), clean_report())
    env.monkeypatch.setattr(commands, "_interactive", lambda: True)
    code, _, _ = run_cli(capsys, "app", "--tools-only")
    assert code == 5 and len(env.asked) == 1 and env.setups == []
    assert env.asked[0].startswith("Install them now?")
    env.monkeypatch.setattr(commands, "_ask", lambda question: True)
    use_doctor(env, missing_report(), clean_report())
    code, _, err = run_cli(capsys, "app", "--tools-only")
    assert code == 0, err
    assert env.setups == [[TOOLS_COMMAND, DATABASES_COMMAND]]


def test_a_failed_setup_names_each_fix(env, capsys):
    still = make_report(
        Check(
            "tool:opengrep",
            "fail",
            "installed, but it does not run; reinstall: kalkan tools install --force opengrep",
        ),
    )
    use_doctor(env, missing_report(), still)
    code, _, err = run_cli(capsys, "app", "--tools-only", "--yes")
    assert code == 5
    assert "the setup did not fix every tool" in err
    assert "kalkan tools install --force opengrep" in err
    assert runs_made(env) == []


def test_databases_that_stay_missing_only_warn(env, capsys, fast_engine):
    no_db = make_report(Check("vulndb", "warn", "no local vulnerability databases", {}))
    use_doctor(env, no_db, no_db)
    code, _, err = run_cli(capsys, "app", "--tools-only", "--yes")
    assert code == 0, err
    assert env.setups == [[DATABASES_COMMAND]]
    assert "a vulnerability database is still missing" in err


def test_stale_databases_only_warn(env, capsys, fast_engine):
    stale = make_report(Check("vulndb", "warn", "the databases are 30 days old", ALL_DATABASES))
    use_doctor(env, stale)
    code, _, err = run_cli(capsys, "app", "--tools-only")
    assert code == 0, err
    assert env.setups == []
    assert "warning: vulnerability databases: the databases are 30 days old" in err


def test_claude_missing_stops_the_agent_mode_before_any_setup(env, capsys):
    use_doctor(
        env,
        make_report(
            Check("claude", "warn", "Claude Code CLI not found: ... claude auth login"),
            *missing_report().checks,
        ),
    )
    env.monkeypatch.setattr(commands, "_interactive", lambda: True)
    code, _, err = run_cli(capsys, "app", "--profile", "deep")
    assert code == 5
    assert "error: Claude Code: Claude Code CLI not found" in err
    app = env.app.resolve().as_posix()
    assert (
        f"Or audit without agents and without Claude Code: kalkan audit {app} --tools-only" in err
    )
    assert env.asked == [] and env.setups == [] and runs_made(env) == []
    assert env.doctor.calls[0]["skip"] == frozenset({"docker", "node"})


def test_an_untrusted_checkout_stops(env, capsys):
    trust = Check("unattended:workspace-trust", "warn", "Claude Code does not trust this folder")
    use_doctor(env, make_report(trust))
    code, _, err = run_cli(capsys, "app")
    assert code == 1 and "does not trust this folder" in err


def test_a_broken_environment_stops(env, capsys):
    use_doctor(
        env, make_report(Check("runs-writable", "fail", "cannot write; set KALKAN_RUNS_DIR"))
    )
    code, _, err = run_cli(capsys, "app", "--tools-only", "--yes")
    assert code == 1 and "error: runs-writable: cannot write" in err
    assert env.setups == []


def test_the_json_document_of_a_stop(env, capsys):
    use_doctor(env, missing_report())
    code, out, _ = run_cli(capsys, "app", "--tools-only", "--json")
    data = json.loads(out)
    assert code == 5 and data["exit_code"] == 5 and data["reason"] == "setup_needed"
    assert data["run_id"] is None and data["mode"] == "tools-only"
    assert [item["check"] for item in data["preflight"]["tools"]] == ["tool:trivy", "tool:opengrep"]


# ---------------------------------------------------------------------------------------------
# Tools-only mode


def test_tools_only_with_the_real_matcher(env, capsys, no_tools):
    code, out, err = run_cli(capsys, "app", "--tools-only", "--open")
    assert code == 0, err
    assert "the agent phases (recon, plan, hunt, validate, poc) are skipped" in err
    assert "  scan:matcher: done (" in err
    assert "  scan:trivy: skipped (" in err and "tool not found" in err
    lines = out.splitlines()
    assert lines[0].startswith("Tools-only audit done: run ")
    assert lines[1] == "Posture: not assessed (tools-only mode: no agent validation)"
    assert any(line.startswith("  1. [") and "matcher: " in line for line in lines)
    assert lines[-1].startswith("Open the executive summary: ")
    (run_id,) = runs_made(env)
    report = env.runs / run_id / "report"
    assert env.opened == [report / "EXECUTIVE.html"]
    current = state.load_state(env.runs / run_id)
    assert current["options"]["mode"] == "tools-only" and current["tasks"] == {}
    assert ids.read_latest(env.runs) == run_id


def test_tools_only_json_and_no_latest(env, capsys, fast_engine):
    code, out, _ = run_cli(
        capsys, "app", "--tools-only", "--no-latest", "--json", "--profile", "deep"
    )
    data = json.loads(out)
    assert code == 0 and data["reason"] == "done" and data["mode"] == "tools-only"
    assert data["summary"]["mode"] == "tools-only" and data["summary"]["posture"] == "unknown"
    labels = [item["label"] for item in data["summary"]["deliverables"]]
    assert labels[:3] == ["EXECUTIVE.html", "REPORT.html", "REPORT.md"]
    assert data["unattended"] is None and data["opened"] is False
    assert ids.read_latest(env.runs) is None  # --no-latest
    current = state.load_state(env.runs / data["run_id"])
    assert current["options"]["profile"] == "standard"  # the profile means nothing without agents


def test_devam_finishes_a_tools_only_run_without_claude(env, capsys, fast_engine):
    ctx = init_run(str(env.app), runs_dir=env.runs, mode=state.MODE_TOOLS_ONLY)
    code, out, err = run_cli(capsys, "devam")
    assert code == 0, err
    assert f"devam: the newest run {ctx.run_id}" in err
    assert env.doctor.calls[0]["skip"] == frozenset({"docker", "node", "claude"})
    assert out.startswith(f"Tools-only audit done: run {ctx.run_id}")
    # A finished run needs no check at all.
    code, out, _ = run_cli(capsys, "devam", ctx.run_id)
    assert code == 0 and len(env.doctor.calls) == 1


# ---------------------------------------------------------------------------------------------
# Agent mode: the unattended runner, bound to the new run


class FakeLoop:
    def __init__(self, options, log, behavior="done") -> None:
        self.options = options
        self.log = log
        self.behavior = behavior
        self.run_id = options.run_id
        self.phase_at_start = None

    def run(self):
        ctx = load_context(self.options.run_id)
        self.phase_at_start = ctx.phase
        if self.behavior == "interrupt":
            raise KeyboardInterrupt
        incomplete = "validation_budget_exhausted" if self.behavior == "incomplete" else None
        with state.transaction(ctx) as tx:  # the agent rounds finished the run
            tx.state["phase"] = "done"
            tx.state["incomplete_reason"] = incomplete
        merge_run(ctx.run_dir)
        write_report(ctx.run_dir, build_model(ctx.run_dir))
        return UnattendedResult(
            exit_code=1 if incomplete else 0,
            reason="incomplete" if incomplete else "done",
            message=f"the audit is done: run {ctx.run_id}.",
            rounds=1,
            run_id=ctx.run_id,
            status=None,
            log_file=self.log.path.as_posix(),
            started_at=MOMENT,
            finished_at=MOMENT,
        )


def install_fake_loop(env, behavior="done"):
    built = {}

    def build(options, host, repo, log, runs_dir, say=None):
        loop = FakeLoop(options, log, behavior)
        built.update(options=options, host=host, repo=repo, runs_dir=runs_dir, say=say, loop=loop)
        return loop

    env.monkeypatch.setattr(unattended, "_build_loop", build)
    return built


def test_agents_run_the_scanners_here_and_bind_the_runner_to_the_run(env, capsys, fast_engine):
    built = install_fake_loop(env)
    code, out, err = run_cli(capsys, "app", "--profile", "fast", "--max-hours", "3")
    assert code == 0, err
    (run_id,) = runs_made(env)
    options = built["options"]
    assert options.run_id == run_id and options.target is None
    assert options.command == "kalkan audit" and options.max_hours == 3
    assert built["host"].skill == "/kalkan" and built["repo"] == env.repo
    assert built["runs_dir"] == env.runs and built["say"] is not None
    assert built["loop"].phase_at_start == "recon"  # the scanners and SCA ran in this process
    assert "phase deterministic" in err and "phase sca" in err
    assert f"run {run_id} created" in err
    assert "agents: Claude Code rounds start now" in err
    assert out.startswith(f"Audit done: run {run_id}")
    assert "Posture: Low" in out
    assert state.load_state(env.runs / run_id)["options"]["profile"] == "fast"
    assert len(list(env.runs.glob("unattended-*.log"))) == 1


def test_the_round_prompt_names_the_run(env, capsys, fast_engine, monkeypatch):
    seen = {}
    real_prepare = unattended.prepare

    def prepare(**kwargs):
        launch = real_prepare(**kwargs)
        seen["argv"] = launch.round_argv
        return launch

    monkeypatch.setattr(unattended, "prepare", prepare)
    install_fake_loop(env)
    code, _, _ = run_cli(capsys, "app")
    (run_id,) = runs_made(env)
    assert code == 0
    assert seen["argv"][:3] == [
        "/opt/claude/bin/claude",
        "-p",
        f"/kalkan devam {run_id} --headless",
    ]


def test_agents_in_the_plugin(env, capsys, fast_engine, monkeypatch):
    monkeypatch.setattr(commands, "_plugin_install", lambda: True)
    monkeypatch.setattr(unattended, "_plugin_install", lambda: True)
    built = install_fake_loop(env, behavior="interrupt")
    code, _, err = run_cli(capsys, "app", "--open")
    (run_id,) = runs_made(env)
    assert code == 1
    assert built["host"].skill == hosts.PLUGIN_SKILL and built["repo"] == env.runs
    assert built["options"].command == "kalkan-audit"
    assert f"Resume with: kalkan-audit devam {run_id}" in err
    assert "--open: the run is not done yet" in err and env.opened == []


def test_an_incomplete_agent_run_prints_its_partial_summary(env, capsys, fast_engine):
    install_fake_loop(env, behavior="incomplete")
    code, out, _ = run_cli(capsys, "app", "--json")
    data = json.loads(out)
    assert code == 1 and data["exit_code"] == 1 and data["reason"] == "incomplete"
    assert data["unattended"]["reason"] == "incomplete"
    assert data["summary"]["incomplete_reason"] == "validation_budget_exhausted"
    text = commands.summary_mod.format_summary(data["summary"])
    assert "finished incomplete (validation_budget_exhausted)" in text


def test_devam_of_an_agent_run_after_the_scanners_checks_only_claude(env, capsys, fast_engine):
    ctx = init_run(str(env.app), runs_dir=env.runs)
    with state.transaction(ctx) as tx:
        tx.state["phase"] = "hunt"
    built = install_fake_loop(env)
    code, _, err = run_cli(capsys, "devam", ctx.run_id, "--tools-only")
    assert code == 0, err
    assert "--tools-only has no effect with devam" in err
    assert env.doctor.calls[0]["skip"] == frozenset({"docker", "node", "tools"})
    assert built["options"].run_id == ctx.run_id
    assert built["loop"].phase_at_start == "hunt"
