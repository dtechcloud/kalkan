# SPDX-License-Identifier: MIT
"""Tests for the decision loop, phase entry and ``run answer`` (kalkan.run.phases) and the
``run next``, ``run step``, ``run answer`` and ``task prompt`` commands."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest

from kalkan.cli import EXIT_VALIDATION, main
from kalkan.errors import ValidationError
from kalkan.run import ids, lock, phases, queue, state
from kalkan.run import init as init_mod
from kalkan.run.init import init_run
from kalkan.run.runfiles import write_json

TARGETS = Path(__file__).resolve().parents[1] / "fixtures" / "targets"


@pytest.fixture
def ctx(tmp_path, monkeypatch):
    monkeypatch.setenv(ids.RUNS_DIR_ENV, str(tmp_path / "runs"))
    monkeypatch.setattr(init_mod, "git_head", lambda directory: None)
    target = tmp_path / "webapp"
    shutil.copytree(TARGETS / "webapp", target)
    return init_run(str(target), runs_dir=tmp_path / "runs", lang="tr")


def go_to(ctx, phase, steps=None, status="running"):
    with state.transaction(ctx) as tx:
        tx.state["phase"] = phase
        record = tx.state["phases"][phase]
        record["status"] = status
        if steps is not None:
            record["steps"] = {
                name: {"status": value, "detail": ""} for name, value in steps.items()
            }


def cli(capsys, *argv):
    code = main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_fresh_run_starts_with_the_first_scanner(ctx):
    action = phases.next_action(ctx, "orchestrator")
    assert action == {"kind": "engine_step", "phase": "deterministic", "step": "scan:trivy"}
    current = ctx.reload()
    assert current["phases"]["deterministic"]["status"] == "running"
    assert current["phases"]["deterministic"]["started_at"]
    phases.ensure_entered(ctx)  # idempotent
    assert ctx.reload()["phases"]["deterministic"] == current["phases"]["deterministic"]


def test_completed_phases_advance_and_enter_the_next_phase(ctx):
    go_to(ctx, "validate", steps={"review:tasks": "done", "consolidate": "done", "polish": "done"})
    action = phases.next_action(ctx, "orchestrator")
    assert action == {"kind": "engine_step", "phase": "poc", "step": "poc:skip"}
    current = ctx.reload()
    assert current["phases"]["validate"]["status"] == "done"
    assert current["phases"]["validate"]["finished_at"]
    assert current["phases"]["poc"]["status"] == "running"


def test_recon_tasks_are_claimed_in_batches(ctx):
    go_to(ctx, "recon", status="pending")
    first = phases.next_action(ctx, "orchestrator", 2)
    assert first["kind"] == "agent_tasks" and first["phase"] == "recon"
    assert [item["type"] for item in first["tasks"]] == ["recon", "recon"]
    for item in first["tasks"]:
        assert Path(item["prompt_file"]).is_file()
        assert item["agent"] == "kalkan-recon"
        assert item["result_file"].endswith(f"{item['id']}/result.json")
    second = phases.next_action(ctx, "other", 5)
    assert len(second["tasks"]) == 2
    assert phases.next_action(ctx, "orchestrator") == {
        "kind": "wait",
        "retry_after_seconds": 60,
        "reason": "agent tasks of this phase are leased",
    }
    kinds = sorted(
        json.loads((ctx.task_dir(t) / "input.json").read_text("utf-8"))["kind"]
        for t in ctx.reload()["tasks"]
    )
    assert kinds == ["execution", "principals", "product", "surfaces"]
    assert ctx.state["phases"]["recon"]["steps"] == {
        "recon:merge": {"status": "pending", "detail": ""}
    }


def test_limit_zero_and_a_missing_prompt(ctx):
    go_to(ctx, "recon", status="pending")
    assert phases.next_action(ctx, "orchestrator", 0)["kind"] == "wait"
    task_id = next(iter(ctx.reload()["tasks"]))
    (ctx.task_dir(task_id) / "prompt.md").unlink()
    action = phases.next_action(ctx, "orchestrator", 1)
    assert action["tasks"][0]["id"] == task_id
    assert (ctx.task_dir(task_id) / "prompt.md").is_file()


def test_recon_without_budget_records_a_pending_incomplete_reason(ctx):
    with state.transaction(ctx) as tx:
        tx.state["budget"]["max_agent_tasks"] = 6
    go_to(ctx, "recon", status="pending")
    action = phases.next_action(ctx, "orchestrator")
    assert action == {"kind": "engine_step", "phase": "recon", "step": "recon:merge"}
    current = ctx.reload()
    assert current["tasks"] == {}
    assert current["incomplete_pending"] == "budget_cannot_fund_reconnaissance_and_reserves"


def test_live_step_in_another_process_means_wait(ctx):
    go_to(ctx, "merge", {"merge": "pending"})
    with state.transaction(ctx) as tx:
        tx.state["phases"]["merge"]["steps"]["merge"].update(
            status="running",
            pid=os.getpid(),
            host=lock.hostname(),
            started_at=ids.format_ts(),
            timeout_seconds=480,
        )
    assert phases.next_action(ctx, "orchestrator")["kind"] == "wait"


def test_question_answer_and_done(ctx):
    go_to(ctx, "report", {"report:tr": "done"})
    assert phases.next_action(ctx, "orchestrator") == {
        "kind": "ask_user",
        "question": "english_report",
    }
    assert phases.answer(ctx, "english_report", "Hayır") == {
        "question": "english_report",
        "value": "no",
        "previous": None,
        "reopened": False,
    }
    done = phases.next_action(ctx, "orchestrator")
    assert done["kind"] == "done" and done["report"].endswith("report/REPORT.md")
    assert ctx.reload()["phases"]["done"]["status"] == "done"
    assert phases.next_action(ctx, "orchestrator")["kind"] == "done"

    # yes after done reopens the report phase; without findings only report:en remains.
    reopened = phases.answer(ctx, "english_report", "evet")
    assert reopened["reopened"] is True and reopened["previous"] == "no"
    assert ctx.reload()["phase"] == "report"
    action = phases.next_action(ctx, "orchestrator")
    assert action == {"kind": "engine_step", "phase": "report", "step": "report:en"}
    assert phases.answer(ctx, "english_report", "yes")["reopened"] is False


def test_yes_creates_translate_tasks(ctx):
    findings = [
        {
            "id": f"KF-{n:016X}",
            "verdict": "rejected",
            "title": "t",
            "description": "d",
            "reason": "r",
        }
        for n in range(25)
    ]
    write_json(ctx.run_dir / "findings.json", findings)
    go_to(ctx, "report", {"report:tr": "done"})
    phases.answer(ctx, "english_report", "yes")
    used = ctx.reload()["budget"]["used_agent_tasks"]
    action = phases.next_action(ctx, "orchestrator")
    assert action["kind"] == "agent_tasks"
    assert [item["type"] for item in action["tasks"]] == ["translate", "translate"]
    sizes = sorted(
        len(json.loads((ctx.task_dir(item["id"]) / "input.json").read_text("utf-8"))["findings"])
        for item in action["tasks"]
    )
    assert sizes == [5, 20]
    current = ctx.reload()
    assert current["budget"]["used_agent_tasks"] == used  # translations do not use the budget
    assert current["phases"]["report"]["steps"]["report:en"]["status"] == "pending"


def test_english_runs_ask_nothing(tmp_path, monkeypatch):
    monkeypatch.setenv(ids.RUNS_DIR_ENV, str(tmp_path / "runs"))
    monkeypatch.setattr(init_mod, "git_head", lambda directory: None)
    target = tmp_path / "webapp"
    shutil.copytree(TARGETS / "webapp", target)
    ctx = init_run(str(target), lang="en", runs_dir=tmp_path / "runs")
    go_to(ctx, "report", {"report:en": "done"})
    assert phases.next_action(ctx, "orchestrator")["kind"] == "done"


def test_incomplete_and_answer_errors(ctx):
    with pytest.raises(ValidationError, match="unknown question"):
        phases.answer(ctx, "color", "yes")
    with pytest.raises(ValidationError, match="invalid answer"):
        phases.answer(ctx, "english_report", "maybe")
    with state.transaction(ctx) as tx:
        tx.state["incomplete_reason"] = "validation_budget_exhausted"
    # An incomplete reason never stops the run early: the phases still run.
    assert phases.next_action(ctx, "orchestrator")["kind"] == "engine_step"
    go_to(ctx, "done", status="done")
    action = phases.next_action(ctx, "orchestrator")
    assert action == {
        "kind": "incomplete",
        "reason": "validation_budget_exhausted",
        "report": action["report"],
    }
    assert action["report"].endswith("report/REPORT.md")


def test_pending_incomplete_reason_ends_the_run_at_done(ctx):
    go_to(ctx, "report", {"report:tr": "skipped"})
    with state.transaction(ctx) as tx:
        tx.state["incomplete_pending"] = "validation_budget_exhausted"
    assert phases.next_action(ctx, "orchestrator")["kind"] == "incomplete"
    current = ctx.reload()
    assert current["phase"] == "done"
    assert current["phases"]["report"]["status"] == "done"
    assert current["incomplete_reason"] == "validation_budget_exhausted"


def test_english_report_after_an_incomplete_run_reopens_the_report(ctx):
    go_to(ctx, "done", status="done")
    with state.transaction(ctx) as tx:
        tx.state["incomplete_reason"] = "validation_budget_exhausted"
        tx.state["phases"]["report"]["steps"] = {"report:tr": {"status": "done", "detail": ""}}
    assert phases.answer(ctx, "english_report", "yes")["reopened"] is True
    assert ctx.reload()["phase"] == "report"


def test_commands(ctx, capsys):
    code, out, _ = cli(capsys, "run", "next", "--owner", "orchestrator", "--json")
    assert code == 0 and json.loads(out)["kind"] == "engine_step"
    code, out, _ = cli(capsys, "run", "next")
    assert code == 0 and out.startswith("engine step scan:trivy (phase deterministic)")
    code, out, _ = cli(capsys, "run", "answer", "english_report", "yes", "--json")
    assert code == 0 and json.loads(out)["value"] == "yes"
    code, _, err = cli(capsys, "run", "answer", "english_report", "perhaps")
    assert code == EXIT_VALIDATION and "invalid answer" in err

    go_to(ctx, "recon", status="pending")
    code, out, _ = cli(capsys, "run", "next", "--limit", "1", "--json")
    task_id = json.loads(out)["tasks"][0]["id"]
    code, out, _ = cli(capsys, "task", "prompt", task_id)
    assert code == 0 and out.startswith(f"# kalkan task {task_id}")
    code, out, _ = cli(capsys, "task", "prompt", task_id, "--json")
    data = json.loads(out)
    assert data["id"] == task_id and data["prompt"].startswith("# kalkan task")
    code, _, err = cli(capsys, "task", "prompt", "T0099-recon")
    assert code == 1 and "unknown task" in err
    code, out, _ = cli(capsys, "run", "step", "--json")
    assert json.loads(out)["status"] == "idle"
    code, out, _ = cli(capsys, "run", "step")
    assert code == 0 and "recon recon:merge: idle" in out
    ctx.reload()
    assert queue.get_task(ctx, task_id)["status"] == "leased"
