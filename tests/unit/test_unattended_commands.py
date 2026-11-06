# SPDX-License-Identifier: MIT
"""Tests for the ``kalkan unattended`` command through kalkan.cli.main (no process starts)."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from kalkan import cli
from kalkan.cli import EXIT_ERROR, EXIT_OK, EXIT_TOOL_MISSING, EXIT_USAGE, main
from kalkan.errors import KalkanError
from kalkan.unattended import commands, hosts
from kalkan.unattended.hosts import ClaudeHost, CodexHost
from kalkan.unattended.loop import UnattendedResult

FLAGS = "--permission-mode dontAsk --output-format stream-json --verbose"
RUN = "20261016T151915Z-app-5fc6"
OTHER = "20261016T160000Z-other-0a1b"
#: The round prompt of a dry run that does not know the run yet.
PLACEHOLDER = f"/kalkan devam {commands.RUN_ID_PLACEHOLDER} --headless"


@pytest.fixture(autouse=True)
def only_unattended(monkeypatch):
    """Load only kalkan.unattended.commands, so that other modules cannot break these tests."""
    selected = {k: v for k, v in cli.COMMANDS.items() if v[0] == "kalkan.unattended.commands"}
    monkeypatch.setattr(cli, "COMMANDS", selected)


@pytest.fixture
def env(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    runs = repo / "runs"
    work = tmp_path / "work"
    app = work / "app"
    for folder in (repo, app):
        folder.mkdir(parents=True)
    monkeypatch.setattr(commands, "_plugin_install", lambda: False)
    monkeypatch.setattr(commands, "_repo_root", lambda: repo)
    monkeypatch.setattr(commands, "_workspace_trusted", lambda _repo: True)
    monkeypatch.setattr(commands, "_runs_root", lambda: runs)
    monkeypatch.setattr(commands, "_cwd", lambda: work)
    monkeypatch.setattr(commands, "_create_host", fake_host)
    return {"repo": repo, "runs": runs, "work": work, "app": app}


def fake_host(name, require):
    if name == "codex":
        return CodexHost("/opt/codex/bin/codex")
    return ClaudeHost("/opt/claude/bin/claude")


def test_the_command_is_registered(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["unattended", "--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    for option in (
        "--run",
        "--profile",
        "--no-latest",
        "--max-hours",
        "--round-hours",
        "--host",
        "--log-dir",
        "--dry-run",
    ):
        assert option in out


def test_dry_run_prints_run_init_and_the_round(env, capsys):
    assert main(["unattended", "app", "--dry-run"]) == EXIT_OK
    out = capsys.readouterr().out
    app = env["app"].resolve().as_posix()
    quote = '"' if os.name == "nt" else "'"  # list2cmdline on Windows, shlex.join elsewhere
    assert f"-m kalkan run init {app} --profile standard --json" in out
    assert f"-p {quote}{PLACEHOLDER}{quote} {FLAGS}" in out
    assert "run: new; run init creates it" in out
    assert "run init:" in out and "every round:" in out
    assert f"run status --run {commands.RUN_ID_PLACEHOLDER} --json" in out
    assert not env["runs"].exists()  # a dry run writes nothing


def test_dry_run_json(env, capsys):
    assert main(["unattended", str(env["app"]), "--profile", "deep", "--dry-run", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["dry_run"] is True and data["host"] == "claude"
    assert data["cwd"] == env["repo"].as_posix()
    assert Path(data["log_file"]).name.startswith("unattended-")
    assert data["run_id"] is None
    app = env["app"].resolve().as_posix()
    assert data["init_argv"][1:] == ["-m", "kalkan", "run", "init", app, "--profile", "deep"] + [
        "--json"
    ]
    assert [r["when"] for r in data["rounds"]] == ["every round"]
    argv = data["rounds"][0]["argv"]
    assert argv[0] == "/opt/claude/bin/claude"
    assert argv[1:] == [
        "-p",
        PLACEHOLDER,
        "--permission-mode",
        "dontAsk",
        "--output-format",
        "stream-json",
        "--verbose",
    ]
    assert data["status_argv"][1:] == [
        "-m",
        "kalkan",
        "run",
        "status",
        "--run",
        commands.RUN_ID_PLACEHOLDER,
        "--json",
    ]


def test_dry_run_no_latest_reaches_run_init(env, capsys):
    assert main(["unattended", "app", "--no-latest", "--dry-run", "--json"]) == EXIT_OK
    data = json.loads(capsys.readouterr().out)
    assert data["init_argv"][-2:] == ["--no-latest", "--json"]


def test_dry_run_devam(env, capsys):
    assert main(["unattended", "devam", "--dry-run", "--json"]) == EXIT_OK
    data = json.loads(capsys.readouterr().out)
    assert [r["when"] for r in data["rounds"]] == ["every round"]
    assert data["rounds"][0]["argv"][2] == PLACEHOLDER
    assert data["run_id"] is None and data["init_argv"] is None
    assert main(["unattended", "devam", "--dry-run"]) == EXIT_OK
    assert "run: none: runs/LATEST names no run" in capsys.readouterr().out


def test_dry_run_devam_shows_the_run_in_latest(env, capsys):
    env["runs"].mkdir(parents=True)
    (env["runs"] / "LATEST").write_text(RUN + "\n", encoding="utf-8")
    assert main(["unattended", "devam", "--dry-run", "--json"]) == EXIT_OK
    data = json.loads(capsys.readouterr().out)
    assert data["run_id"] == RUN
    assert data["rounds"][0]["argv"][2] == f"/kalkan devam {RUN} --headless"
    assert data["status_argv"][-3:] == ["--run", RUN, "--json"]
    assert main(["unattended", "devam", "--dry-run"]) == EXIT_OK
    assert f"run: {RUN} (from runs/LATEST, read once at the start)" in capsys.readouterr().out


@pytest.mark.parametrize(
    "argv",
    [
        ["devam", RUN],
        ["devam", "--run", RUN],
        ["resume", f"--run={RUN}"],
        ["devam", RUN, "--run", RUN],
    ],
)
def test_devam_with_a_run_id(env, capsys, argv):
    env["runs"].mkdir(parents=True)
    (env["runs"] / "LATEST").write_text(OTHER + "\n", encoding="utf-8")
    assert main(["unattended", *argv, "--dry-run", "--json"]) == EXIT_OK
    data = json.loads(capsys.readouterr().out)
    assert data["run_id"] == RUN  # the given run, not the one in runs/LATEST
    assert data["rounds"][0]["argv"][2] == f"/kalkan devam {RUN} --headless"


def test_a_run_id_reaches_the_loop(env, monkeypatch, capsys):
    built = install_fake_loop(monkeypatch)
    assert main(["unattended", "devam", RUN]) == EXIT_OK
    assert built["options"].run_id == RUN and built["options"].target is None
    assert main(["unattended", "app", "--no-latest"]) == EXIT_OK
    assert built["options"].run_id is None and built["options"].latest is False


@pytest.mark.parametrize(
    ("argv", "message"),
    [
        (["devam", RUN, "--run", OTHER], "two different run IDs"),
        (["app", RUN], "a run ID works only with devam"),
        (["app", "--run", RUN], "a run ID works only with devam"),
    ],
)
def test_run_id_errors(env, capsys, argv, message):
    assert main(["unattended", *argv, "--dry-run"]) == EXIT_ERROR
    assert message in capsys.readouterr().err


@pytest.mark.parametrize(
    "value", ["x", "../20261016T151915Z-app-5fc6", f"{RUN};rm", f"{RUN} x", "20261016-app-5fc6"]
)
def test_an_invalid_run_id_is_a_usage_error(env, capsys, value):
    for argv in (["devam", value], ["devam", "--run", value]):
        with pytest.raises(SystemExit) as exc:
            main(["unattended", *argv, "--dry-run"])
        assert exc.value.code == EXIT_USAGE
        assert "not a run ID" in capsys.readouterr().err


def test_profile_and_no_latest_with_devam_are_noted(env, capsys):
    assert main(["unattended", "devam", "--profile", "deep", "--dry-run"]) == EXIT_OK
    assert "--profile has no effect with devam" in capsys.readouterr().err
    assert main(["unattended", "devam", "--no-latest", "--dry-run"]) == EXIT_OK
    assert "--no-latest has no effect with devam" in capsys.readouterr().err


def test_a_target_with_spaces_stays_one_argument(env, capsys):
    spaced = env["work"] / "my app"
    spaced.mkdir()
    assert main(["unattended", "my app", "--dry-run", "--json"]) == EXIT_OK
    data = json.loads(capsys.readouterr().out)
    assert data["init_argv"][5] == spaced.resolve().as_posix()
    assert data["rounds"][0]["argv"][2] == PLACEHOLDER


@pytest.mark.parametrize(
    "url", ["https://github.com/org/repo.git", "git@github.com:org/repo.git", "ssh://h/r.git"]
)
def test_a_git_url_passes_unchanged(env, capsys, url):
    assert main(["unattended", url, "--dry-run", "--json"]) == EXIT_OK
    data = json.loads(capsys.readouterr().out)
    assert data["init_argv"][5] == url


def test_a_missing_folder_is_an_error(env, capsys):
    assert main(["unattended", "nowhere", "--dry-run"]) == EXIT_ERROR
    assert "does not exist" in capsys.readouterr().err


@pytest.mark.parametrize("target", ['app"x', "app$(id)", "app`id`", "app\nx", "  "])
def test_forbidden_target_characters(env, capsys, target):
    assert main(["unattended", target, "--dry-run"]) == EXIT_ERROR
    assert "kalkan: error:" in capsys.readouterr().err


@pytest.mark.parametrize("value", ["0", "-1", "nan", "inf", "abc", "1000"])
def test_invalid_hours_are_usage_errors(env, value):
    with pytest.raises(SystemExit) as exc:
        main(["unattended", "devam", "--max-hours", value])
    assert exc.value.code == EXIT_USAGE


def test_a_cmd_shim_takes_a_target_with_cmd_metacharacters(env, monkeypatch, capsys):
    # The target goes to run init (a Python process, no cmd.exe). The prompt of a round holds
    # only the run ID, so a claude.cmd shim never sees the "&".
    monkeypatch.setattr(
        commands, "_create_host", lambda name, require: ClaudeHost("C:/npm/claude.cmd")
    )
    (env["work"] / "a&b").mkdir()
    assert main(["unattended", "a&b", "--dry-run", "--json"]) == EXIT_OK
    data = json.loads(capsys.readouterr().out)
    assert data["init_argv"][5].endswith("/a&b")
    assert "&" not in data["rounds"][0]["argv"][2]


def test_a_real_run_without_claude_is_a_tool_error(env, monkeypatch, capsys):
    def no_claude(name, require):
        return hosts.create_host(name, finder=lambda _name: None, require=require)

    monkeypatch.setattr(commands, "_create_host", no_claude)
    assert main(["unattended", "devam"]) == EXIT_TOOL_MISSING
    assert "not on PATH" in capsys.readouterr().err
    # A dry run still works and says that claude is missing.
    assert main(["unattended", "devam", "--dry-run"]) == EXIT_OK
    assert "not on PATH" in capsys.readouterr().err


class FakeLoop:
    def __init__(self, log, behavior) -> None:
        self.log = log
        self.behavior = behavior
        self.run_id = None if behavior == "interrupt-before-init" else RUN

    def run(self):
        if self.behavior.startswith("interrupt"):
            raise KeyboardInterrupt
        self.log.note("fake loop ran")
        moment = datetime(2026, 10, 15, 12, tzinfo=UTC)
        return UnattendedResult(
            exit_code=0,
            reason="done",
            message="the audit is done: run X.",
            rounds=2,
            run_id="X",
            status=None,
            log_file=self.log.path.as_posix(),
            started_at=moment,
            finished_at=moment,
        )


def install_fake_loop(monkeypatch, behavior="done"):
    built = {}

    def build(options, host, repo, log, runs_dir, say=None):
        built.update(options=options, host=host, repo=repo, runs_dir=runs_dir, log=log, say=say)
        return FakeLoop(log, behavior)

    monkeypatch.setattr(commands, "_build_loop", build)
    return built


def test_a_real_run_writes_the_log_and_prints_json(env, monkeypatch, capsys):
    built = install_fake_loop(monkeypatch)
    assert main(["unattended", "app", "--max-hours", "3", "--json"]) == EXIT_OK
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["reason"] == "done" and data["rounds"] == 2
    assert "the audit is done" in captured.err
    logs = list(env["runs"].glob("unattended-*.log"))
    assert len(logs) == 1 and "fake loop ran" in logs[0].read_text(encoding="utf-8")
    assert built["options"].max_hours == 3 and built["repo"] == env["repo"]
    assert built["options"].target == env["app"].resolve().as_posix()


def test_log_dir_option(env, monkeypatch, capsys):
    install_fake_loop(monkeypatch)
    assert main(["unattended", "devam", "--log-dir", "logs"]) == EXIT_OK
    assert len(list((env["work"] / "logs").glob("unattended-*.log"))) == 1


def test_ctrl_c_is_reported_with_a_resume_hint(env, monkeypatch, capsys):
    install_fake_loop(monkeypatch, behavior="interrupt")
    assert main(["unattended", "devam"]) == EXIT_ERROR
    assert f"The run is resumable. Resume with: kalkan unattended devam {RUN}" in (
        capsys.readouterr().err
    )
    (log,) = env["runs"].glob("unattended-*.log")
    assert "interrupted by the user" in log.read_text(encoding="utf-8")


def test_ctrl_c_before_the_run_exists_names_the_target(env, monkeypatch, capsys):
    install_fake_loop(monkeypatch, behavior="interrupt-before-init")
    assert main(["unattended", "app", "--profile", "fast"]) == EXIT_ERROR
    app = env["app"].resolve().as_posix()
    expected = f"before the run was created. Start again with: kalkan unattended {app}"
    assert expected in capsys.readouterr().err


def test_normalize_target_rejects_a_file(tmp_path):
    file = tmp_path / "file.txt"
    file.write_text("x", encoding="utf-8")
    with pytest.raises(KalkanError, match="does not exist"):
        commands.normalize_target(str(file))


# ---------------------------------------------------------------------------------------------
# Codex host


def test_codex_dry_run(env, capsys):
    assert main(["unattended", "app", "--host", "codex", "--dry-run", "--json"]) == EXIT_OK
    data = json.loads(capsys.readouterr().out)
    assert data["host"] == "codex"
    (later,) = (item["argv"] for item in data["rounds"])
    flags = [
        "exec",
        "--sandbox",
        "workspace-write",
        "-c",
        "approval_policy=never",
        "-c",
        "sandbox_workspace_write.network_access=false",
        "-c",
        "web_search=disabled",
        "--json",
    ]
    app = env["app"].resolve().as_posix()
    assert data["init_argv"][1:] == ["-m", "kalkan", "run", "init", app, "--profile"] + [
        "standard",
        "--json",
    ]
    placeholder = f"$kalkan devam {commands.RUN_ID_PLACEHOLDER} --headless"
    assert later == ["/opt/codex/bin/codex", *flags, placeholder]
    assert main(["unattended", "devam", RUN, "--host", "codex", "--dry-run", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["rounds"][0]["argv"][-1] == f"$kalkan devam {RUN} --headless"


def test_codex_refuses_a_git_url(env, capsys):
    url = "https://github.com/org/repo.git"
    assert main(["unattended", url, "--host", "codex", "--dry-run"]) == EXIT_ERROR
    assert "Clone the repository first" in capsys.readouterr().err
    assert main(["unattended", url, "--dry-run"]) == EXIT_OK  # Claude Code clones it itself


def test_a_real_codex_run_without_codex_is_a_tool_error(env, monkeypatch, capsys):
    def no_program(name, require):
        return hosts.create_host(name, finder=lambda _name: None, require=require)

    monkeypatch.setattr(commands, "_create_host", no_program)
    assert main(["unattended", "devam", "--host", "codex"]) == EXIT_TOOL_MISSING
    assert "codex login" in capsys.readouterr().err


def test_ctrl_c_hint_names_the_codex_host(env, monkeypatch, capsys):
    install_fake_loop(monkeypatch, behavior="interrupt")
    assert main(["unattended", "devam", "--host", "codex"]) == EXIT_ERROR
    assert f"kalkan unattended devam {RUN} --host codex" in capsys.readouterr().err


def test_untrusted_workspace_stops_before_any_round(env, monkeypatch, capsys):
    monkeypatch.setattr(commands, "_workspace_trusted", lambda _repo: False)
    assert main(["unattended", "app"]) == 1
    assert "does not trust this folder" in capsys.readouterr().err


def test_a_checkout_runs_in_the_repository_and_names_kalkan_unattended(env, capsys):
    assert main(["unattended", "devam", "--dry-run", "--json"]) == EXIT_OK
    data = json.loads(capsys.readouterr().out)
    assert data["install"] == "checkout" and data["cwd"] == env["repo"].as_posix()
    assert data["rounds"][0]["argv"][2] == PLACEHOLDER


# ---------------------------------------------------------------------------------------------
# Claude Code plugin install


@pytest.fixture
def plugin_env(env, tmp_path, monkeypatch):
    """A plugin install: no checkout, the runs root ~/kalkan-runs, folder trust unknown."""
    runs = tmp_path / "home" / "kalkan-runs"

    def no_checkout():
        raise KalkanError("cannot find the kalkan repository root; set KALKAN_HOME")

    def no_trust_check(_repo):
        raise AssertionError("the plugin install must not check the folder trust")

    monkeypatch.setattr(commands, "_plugin_install", lambda: True)
    monkeypatch.setattr(commands, "_repo_root", no_checkout)
    monkeypatch.setattr(commands, "_runs_root", lambda: runs)
    monkeypatch.setattr(commands, "_workspace_trusted", no_trust_check)
    return {**env, "runs": runs}


def test_plugin_dry_run_sends_the_plugin_skill_from_the_runs_root(plugin_env, capsys):
    assert main(["unattended", "app", "--profile", "fast", "--dry-run", "--json"]) == EXIT_OK
    data = json.loads(capsys.readouterr().out)
    assert data["install"] == "plugin" and data["host"] == "claude"
    assert data["cwd"] == plugin_env["runs"].as_posix()
    assert Path(data["log_file"]).parent == plugin_env["runs"]
    (argv,) = (item["argv"] for item in data["rounds"])
    app = plugin_env["app"].resolve().as_posix()
    assert data["init_argv"][4:] == ["init", app, "--profile", "fast", "--json"]
    assert argv == [
        "/opt/claude/bin/claude",
        "-p",
        f"/kalkan:kalkan devam {commands.RUN_ID_PLACEHOLDER} --headless",
        "--permission-mode",
        "dontAsk",
        "--output-format",
        "stream-json",
        "--verbose",
    ]
    assert not plugin_env["runs"].exists()  # a dry run writes nothing


def test_plugin_dry_run_text(plugin_env, capsys):
    assert main(["unattended", "devam", "--run", RUN, "--dry-run"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "install: plugin" in out
    assert f"working directory: {plugin_env['runs'].as_posix()}" in out
    assert f"run: {RUN}" in out
    assert f"/kalkan:kalkan devam {RUN} --headless" in out


def test_a_plugin_run_skips_the_trust_check_and_creates_the_runs_root(
    plugin_env, monkeypatch, capsys
):
    built = install_fake_loop(monkeypatch)
    assert main(["unattended", "app", "--json"]) == EXIT_OK
    runs = plugin_env["runs"]
    assert runs.is_dir() and built["repo"] == runs and built["runs_dir"] == runs
    assert built["host"].skill == hosts.PLUGIN_SKILL
    assert built["host"].executable == "/opt/claude/bin/claude"
    assert built["options"].command == "kalkan-unattended"
    assert len(list(runs.glob("unattended-*.log"))) == 1


def test_plugin_ctrl_c_hint_names_the_launcher(plugin_env, monkeypatch, capsys):
    install_fake_loop(monkeypatch, behavior="interrupt")
    assert main(["unattended", "devam"]) == EXIT_ERROR
    assert f"Resume with: kalkan-unattended devam {RUN}" in capsys.readouterr().err


def test_the_plugin_refuses_the_codex_host(plugin_env, monkeypatch, capsys):
    def no_host(name, require):
        raise AssertionError("the host must not be created")

    monkeypatch.setattr(commands, "_create_host", no_host)
    assert main(["unattended", "app", "--host", "codex", "--dry-run"]) == EXIT_ERROR
    err = capsys.readouterr().err
    assert "only Claude Code rounds" in err and "docs/CODEX.md" in err


def test_the_plugin_refuses_a_runs_root_inside_a_claude_folder(plugin_env, monkeypatch, capsys):
    runs = plugin_env["work"] / ".claude" / "plugins" / "data" / "kalkan-kalkan" / "runs"
    monkeypatch.setattr(commands, "_runs_root", lambda: runs)
    assert main(["unattended", "app", "--dry-run"]) == EXIT_ERROR
    err = capsys.readouterr().err
    assert "inside a .claude folder" in err and "KALKAN_RUNS_DIR" in err
    assert not runs.exists()


def test_plugin_host_keeps_the_executable_and_refuses_other_hosts():
    host = commands.plugin_host(ClaudeHost("/usr/bin/claude"))
    assert host.executable == "/usr/bin/claude" and host.skill == "/kalkan:kalkan"
    with pytest.raises(KalkanError, match="codex"):
        commands.plugin_host(CodexHost("/usr/bin/codex"))
