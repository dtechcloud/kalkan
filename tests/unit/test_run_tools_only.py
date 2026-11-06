# SPDX-License-Identifier: MIT
"""Tools-only runs (``options.mode`` = ``tools-only``; docs/PHASES.md section 3).

``run init --tools-only`` records the mode and an agent task budget of 0. The phase engine then
marks every agent phase ``skipped`` with the step ``tools-only`` and its reason, skips the step
``sca:reach_tasks``, asks no question and never creates an agent task. The full drive below
uses only in-process parts: every external tool is missing (an empty PATH and an empty kalkan
home), and the built-in matcher finds the candidates.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from kalkan.cli import main
from kalkan.errors import StateError, ValidationError
from kalkan.findings.merge import FINDINGS_NAME
from kalkan.run import events, ids, phases, queue, state, steps
from kalkan.run import init as init_mod
from kalkan.run.init import init_run
from kalkan.run.runfiles import write_json

TARGETS = Path(__file__).resolve().parents[1] / "fixtures" / "targets"


@pytest.fixture
def runs(tmp_path, monkeypatch):
    folder = tmp_path / "runs"
    monkeypatch.setenv(ids.RUNS_DIR_ENV, str(folder))
    monkeypatch.setattr(init_mod, "git_head", lambda directory: None)
    return folder


@pytest.fixture
def target(tmp_path):
    folder = tmp_path / "webapp"
    shutil.copytree(TARGETS / "webapp", folder)
    return folder


@pytest.fixture
def ctx(runs, target):
    return init_run(str(target), runs_dir=runs, mode=state.MODE_TOOLS_ONLY)


def go_to(ctx, phase, steps=None, status="running"):
    with state.transaction(ctx) as tx:
        tx.state["phase"] = phase
        record = tx.state["phases"][phase]
        record["status"] = status
        if steps is not None:
            record["steps"] = {
                name: {"status": value, "detail": ""} for name, value in steps.items()
            }


# ---------------------------------------------------------------------------------------------
# run init


def test_init_records_the_mode_and_a_budget_of_zero(ctx):
    current = ctx.reload()
    assert current["options"]["mode"] == "tools-only"
    assert state.run_mode(current) == state.MODE_TOOLS_ONLY
    assert current["budget"]["max_agent_tasks"] == 0
    assert current["budget"]["reserve_critic"] == 0
    assert state.check_state(current) == []
    (initialized,) = [e for e in events.read_events(ctx.run_dir) if e["kind"] == "run_initialized"]
    assert initialized["mode"] == "tools-only"


def test_an_agents_run_writes_no_mode(runs, target):
    ctx = init_run(str(target), runs_dir=runs)
    current = ctx.reload()
    assert "mode" not in current["options"]
    assert state.run_mode(current) == state.MODE_AGENTS
    assert current["budget"]["max_agent_tasks"] == 150


def test_an_unknown_mode_is_refused(runs, target):
    with pytest.raises(ValidationError, match="mode must be one of"):
        init_run(str(target), runs_dir=runs, mode="robots")
    assert not runs.exists() or not any(runs.iterdir())


def test_the_state_schema_refuses_an_unknown_mode(ctx):
    current = ctx.reload()
    current["options"]["mode"] = "robots"
    assert state.check_state(current)
    with pytest.raises(StateError):
        state.save_state(ctx.run_dir, current)


def test_run_init_tools_only_on_the_command_line(runs, target, capsys):
    assert main(["run", "init", str(target), "--tools-only", "--json"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["options"]["mode"] == "tools-only"
    assert output["budget"]["max_agent_tasks"] == 0
    assert main(["run", "init", str(target), "--tools-only"]) == 0
    assert "Mode: tools-only" in capsys.readouterr().out
    assert main(["run", "status"]) == 0
    assert "mode tools-only" in capsys.readouterr().out


def test_no_agent_task_can_be_created(ctx):
    with pytest.raises(StateError):
        queue.create_task(ctx, "recon", "recon", {"kind": "product"})


# ---------------------------------------------------------------------------------------------
# Phase engine


def test_every_agent_phase_is_skipped_with_the_reason(ctx):
    go_to(ctx, "sca", {name: "done" for name in ("sca:sbom", "sca:match", "sca:govulncheck")})
    action = phases.next_action(ctx, "orchestrator")
    assert action == {"kind": "engine_step", "phase": "merge", "step": "merge"}
    current = ctx.reload()
    for name in phases.AGENT_PHASES:
        record = current["phases"][name]
        assert record["status"] == "skipped", name
        assert record["started_at"] and record["finished_at"]
        assert record["steps"] == {
            phases.TOOLS_ONLY_STEP: {"status": "skipped", "detail": phases.TOOLS_ONLY_REASON}
        }
    assert current["tasks"] == {}
    assert current["budget"]["used_agent_tasks"] == 0
    skipped = [e for e in events.read_events(ctx.run_dir) if e["kind"] == "phase_skipped"]
    assert [e["phase"] for e in skipped] == list(phases.AGENT_PHASES)
    assert skipped[0]["reason"] == phases.TOOLS_ONLY_REASON


def test_the_reason_names_unverified_tool_results():
    assert phases.TOOLS_ONLY_REASON == (
        "tools-only mode: no agent validation; all results are unverified tool results"
    )


def test_the_sca_reachability_step_is_skipped(ctx):
    go_to(ctx, "sca", status="pending")
    phases.ensure_entered(ctx)
    reach = ctx.reload()["phases"]["sca"]["steps"]["sca:reach_tasks"]
    assert reach == {"status": "skipped", "detail": phases.TOOLS_ONLY_REACH}


def test_run_step_also_skips_the_agent_phases(ctx):
    go_to(ctx, "recon", status="pending")
    outcome = steps.run_step(ctx, 60)
    assert outcome["phase"] == "merge" and outcome["step"] == "merge"
    assert ctx.reload()["phases"]["poc"]["status"] == "skipped"


def test_an_agents_run_keeps_its_agent_phases(runs, target):
    agents = init_run(str(target), runs_dir=runs)
    go_to(agents, "recon", status="pending")
    action = phases.next_action(agents, "orchestrator")
    assert action["kind"] == "agent_tasks" and action["phase"] == "recon"


def test_a_tools_only_run_asks_no_question(ctx):
    go_to(ctx, "report", {"report:tr": "done"})
    current = ctx.reload()
    assert phases.pending_question(current) is None
    assert phases.next_action(ctx, "orchestrator")["kind"] == "done"


def test_english_report_without_translation_tasks(ctx):
    write_json(
        ctx.run_dir / FINDINGS_NAME,
        [{"id": "KF-0000000000000001", "verdict": "rejected", "title": "t", "reason": "r"}],
    )
    go_to(ctx, "report", {"report:tr": "done"})
    assert phases.next_action(ctx, "orchestrator")["kind"] == "done"
    assert phases.answer(ctx, "english_report", "yes")["reopened"] is True
    action = phases.next_action(ctx, "orchestrator")
    assert action == {"kind": "engine_step", "phase": "report", "step": "report:en"}
    assert ctx.reload()["tasks"] == {}


# ---------------------------------------------------------------------------------------------
# A full drive with in-process parts only


@pytest.fixture
def no_tools(tmp_path, monkeypatch):
    """No external tool can be found: an empty kalkan home and an empty PATH."""
    home = tmp_path / "home"
    empty = tmp_path / "empty-bin"
    home.mkdir()
    empty.mkdir()
    monkeypatch.setenv("KALKAN_HOME", str(home))
    monkeypatch.setenv("PATH", str(empty))
    return home


def test_a_full_drive_reaches_done_with_the_matcher_only(ctx, no_tools):
    seen = []
    for _ in range(100):
        action = phases.next_action(ctx, "orchestrator", 0)
        if action["kind"] != "engine_step":
            break
        outcome = steps.run_step(ctx, 120)
        seen.append(outcome)
    assert action["kind"] == "done"
    by_step = {item["step"]: item for item in seen}
    assert by_step["scan:matcher"]["status"] == "done"
    assert "candidates" in by_step["scan:matcher"]["detail"]
    for name in ("scan:trivy", "scan:opengrep", "scan:gitleaks"):
        assert by_step[name]["status"] == "skipped", name
        assert "tool not found" in by_step[name]["detail"], name
    assert by_step["merge"]["status"] == "done"
    assert by_step["report:tr"]["status"] == "done"
    current = ctx.reload()
    assert current["tasks"] == {} and current["incomplete_reason"] is None
    report = ctx.run_dir / "report"
    for name in ("REPORT.md", "REPORT.html", "EXECUTIVE.html", "findings.sarif", "summary.json"):
        assert (report / name).is_file(), name
    summary = json.loads((report / "summary.json").read_text(encoding="utf-8"))
    assert summary["partial_reasons"][0] == {"code": "tools_only"}
    assert summary["counts"]["tool_results"] > 0
    markdown = (report / "REPORT.md").read_text(encoding="utf-8")
    assert "Yalnızca araç modu (tools-only)" in markdown
