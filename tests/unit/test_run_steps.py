# SPDX-License-Identifier: MIT
"""Tests for engine steps and ``run step`` (kalkan.run.steps)."""

from __future__ import annotations

import json
import os
import shutil
import sys
from datetime import timedelta
from pathlib import Path

import pytest

from kalkan.errors import StateError, ToolError
from kalkan.run import ids, lock, phases, queue, state, steps
from kalkan.run import init as init_mod
from kalkan.run.init import init_run
from kalkan.run.runfiles import write_json

TARGETS = Path(__file__).resolve().parents[1] / "fixtures" / "targets"
DEAD_PID = 999_999


@pytest.fixture
def ctx(tmp_path, monkeypatch):
    monkeypatch.setenv(ids.RUNS_DIR_ENV, str(tmp_path / "runs"))
    monkeypatch.setattr(init_mod, "git_head", lambda directory: None)
    real = lock.pid_alive
    monkeypatch.setattr(lock, "pid_alive", lambda pid: pid != DEAD_PID and real(pid))
    target = tmp_path / "webapp"
    shutil.copytree(TARGETS / "webapp", target)
    return init_run(str(target), runs_dir=tmp_path / "runs", lang="tr")


@pytest.fixture
def fake_scanners(monkeypatch):
    from kalkan.scanners import base

    calls = []

    def run_adapter(adapter, scan_ctx, *, timeout_seconds=None, **kwargs):
        calls.append((adapter.name, timeout_seconds))
        status = "failed" if adapter.name == "trivy" else "ok"
        return base.ScanResult(adapter.name, status, None, f"{adapter.name} ran", 0.1, 0, "1", 2)

    monkeypatch.setattr(base, "run_adapter", run_adapter)
    return calls


def use_steps(ctx, phase, names):
    with state.transaction(ctx) as tx:
        tx.state["phase"] = phase
        record = tx.state["phases"][phase]
        record["status"] = "running"
        record["steps"] = {name: {"status": "pending", "detail": ""} for name in names}


def record_of(ctx, phase, name):
    return state.load_state(ctx.run_dir)["phases"][phase]["steps"][name]


def test_scanner_steps(ctx, fake_scanners):
    phases.ensure_entered(ctx)
    entered = ctx.reload()["phases"]["deterministic"]["steps"]
    assert entered["scan:gosec"]["status"] == "skipped"
    assert entered["scan:matcher"]["status"] == "pending"
    first = steps.run_step(ctx, 100)
    assert first["step"] == "scan:trivy" and first["status"] == "failed"
    second = steps.run_step(ctx, 100)
    assert second["status"] == "done" and second["detail"] == "ok: checkov ran (2 candidates)"
    record = record_of(ctx, "deterministic", "scan:checkov")
    assert record["attempts"] == 1 and "pid" not in record and record["finished_at"]
    assert fake_scanners[0] == ("trivy", 80)  # min(adapter timeout, max_seconds - 20)
    assert steps.run_step(ctx, 10)["status"] in ("done", "failed")
    assert fake_scanners[-1][1] == 5


def test_running_record_and_outcomes(ctx, monkeypatch):
    use_steps(ctx, "plan", ["plan:ledger", "plan:tasks"])
    seen = {}

    def ledger(run_ctx):
        record = run_ctx.reload()["phases"]["plan"]["steps"]["plan:ledger"]
        seen.update(record)
        raise StateError("the ledger is broken")

    def tasks(run_ctx):
        raise RuntimeError("boom")

    monkeypatch.setattr(steps, "plan_ledger", ledger)
    monkeypatch.setattr(steps, "plan_tasks", tasks)
    outcome = steps.run_step(ctx)
    assert seen["status"] == "running" and seen["pid"] == os.getpid()
    assert seen["host"] == lock.hostname() and seen["timeout_seconds"] == 480
    assert outcome["status"] == "failed" and outcome["detail"] == "the ledger is broken"
    outcome = steps.run_step(ctx)
    assert outcome == {**outcome, "step": "plan:tasks", "status": "failed"}
    assert outcome["detail"] == "internal error: RuntimeError: boom"
    assert steps.run_step(ctx)["status"] == "idle"


def test_missing_module_gives_skipped(ctx, monkeypatch):
    monkeypatch.setitem(sys.modules, "kalkan.sca.commands", None)
    use_steps(ctx, "sca", ["sca:sbom"])
    outcome = steps.run_step(ctx)
    assert outcome["status"] == "skipped"
    assert outcome["detail"] == "module_unavailable: kalkan.sca.commands"
    monkeypatch.setitem(sys.modules, "kalkan.scanners.registry", None)
    with state.transaction(ctx) as tx:
        tx.state["phase"] = "deterministic"
    phases.ensure_entered(ctx)
    assert ctx.reload()["phases"]["deterministic"]["steps"] == {
        "scan": {"status": "skipped", "detail": "module_unavailable: kalkan.scanners.registry"}
    }


def test_sca_steps(ctx, monkeypatch):
    from kalkan.sca import commands as sca_commands

    def run_sbom(run_dir, *, offline=False, timeout_seconds=None):
        assert timeout_seconds == 230  # each of two tools gets half of 480 - 20
        raise ToolError("no SBOM tool")

    monkeypatch.setattr(sca_commands, "run_sbom", run_sbom)
    use_steps(ctx, "sca", ["sca:sbom", "sca:govulncheck", "sca:reach_tasks"])
    assert steps.run_step(ctx)["detail"] == "no SBOM tool"
    assert steps.run_step(ctx)["step"] == "sca:govulncheck"
    statuses = {
        name: record["status"] for name, record in ctx.reload()["phases"]["sca"]["steps"].items()
    }
    assert statuses["sca:sbom"] == "failed"
    assert statuses["sca:govulncheck"] == "skipped"
    assert steps.run_step(ctx)["detail"] == "no vulnerability records"


def test_busy_stale_and_crash_loop(ctx):
    use_steps(ctx, "merge", ["merge"])
    with state.transaction(ctx) as tx:
        tx.state["phases"]["merge"]["steps"]["merge"].update(
            status="running",
            pid=os.getpid(),
            host=lock.hostname(),
            started_at=ids.format_ts(),
            timeout_seconds=480,
            attempts=1,
        )
    assert steps.run_step(ctx)["status"] == "busy"
    # Older than its timeout plus 120 seconds: the step counts as crashed.
    later = ids.utc_now() + timedelta(seconds=480 + 121)
    record = record_of(ctx, "merge", "merge")
    assert steps.step_is_live(record) and not steps.step_is_live(record, later)
    with state.transaction(ctx) as tx:
        tx.state["phases"]["merge"]["steps"]["merge"].update(pid=DEAD_PID, attempts=3)
    outcome = steps.run_step(ctx)
    assert outcome["status"] == "failed" and "started 3 times" in outcome["detail"]


def test_steps_wait_for_open_tasks(ctx):
    use_steps(ctx, "recon", ["recon:merge"])
    queue.create_task(ctx, "recon", "recon", {"kind": "product"})
    assert steps.run_step(ctx)["status"] == "idle"
    assert record_of(ctx, "recon", "recon:merge")["status"] == "pending"


def finding(fid, verdict, slug="sqli"):
    return {"id": fid, "verdict": verdict, "class": slug, "fingerprint": f"{slug}:a:b"}


def test_poc_skip(ctx):
    use_steps(ctx, "poc", ["poc:skip"])
    created = []
    for fid, verdict, slug in (
        ("KF-0000000000000001", "confirmed", "sqli"),
        ("KF-0000000000000002", "needs_validation", "xss"),
        ("KF-0000000000000003", "rejected", "sqli"),
        ("KF-0000000000000004", "confirmed", "iac-cloud-container"),
    ):
        task_id = queue.create_task(ctx, "verify", "validate", {})
        write_json(ctx.task_dir(task_id) / "finding.json", finding(fid, verdict, slug))
        created.append(task_id)
    with state.transaction(ctx) as tx:
        for task_id in created:
            tx.state["tasks"][task_id]["status"] = "done"
    outcome = steps.run_step(ctx)
    # The sandbox is part of the version now; the skip reason names the missing Docker engine
    # (the autouse fixture forces it off), and poc.json carries the localizable key.
    reason = "the Docker engine does not answer"
    assert outcome["status"] == "done"
    assert outcome["detail"] == f"{reason} (2 code findings)"
    poc = json.loads((ctx.task_dir(created[0]) / "poc.json").read_text("utf-8"))
    assert poc == {
        "finding_id": "KF-0000000000000001",
        "level": "unit",
        "status": "blocked",
        "observed_result": "sandbox_unavailable",
        "artifacts": [],
        "blocker": "sandbox_unavailable",
    }
    assert not (ctx.task_dir(created[2]) / "poc.json").exists()
    assert not (ctx.task_dir(created[3]) / "poc.json").exists()
    skip = json.loads((ctx.run_dir / "poc" / "skip.json").read_text("utf-8"))
    assert len(skip["findings"]) == 2
    assert (skip["reason"], skip["blocker"]) == (reason, "sandbox_unavailable")


def test_the_report_states_the_poc_scope_in_its_language():
    from kalkan.findings.merge import POC_OUT_OF_SCOPE
    from kalkan.report import i18n

    # A run before 1.7.0 recorded the ADR-0004 scope statement: it reads as "that version had
    # no sandbox", never as a limit of this version.
    english = i18n.poc_observed("en", POC_OUT_OF_SCOPE)
    assert english.startswith("The kalkan version that made this audit had no PoC sandbox.")
    assert "ADR-0004" not in english
    # A skipped PoC of this version reads as "the sandbox did not run", in the report language,
    # and names no final review (a fast run has none).
    turkish = i18n.poc_observed("tr", "sandbox_unavailable")
    assert turkish.startswith("PoC doğrulama sandbox'ı bu analizde çalışmadı.")
    assert "inceleme" not in turkish
    assert i18n.poc_observed("tr", "The PoC printed root.") == "The PoC printed root."
    assert "Docker" in i18n.blocker_note("en", "sandbox_unavailable")
    assert i18n.blocker_note("tr", "sandbox_timeout").startswith("PoC verilen süre")
    assert i18n.blocker_note("en", "confirmed_fields_missing") is None


def test_merge_and_report_steps(ctx, monkeypatch):
    from kalkan.findings import merge as merge_mod

    calls = []

    def merge_run(run_dir):
        assert (Path(run_dir) / lock.LOCK_NAME).exists()  # the step holds the run lock
        calls.append(run_dir)
        return {"findings": 0, "by_verdict": {"confirmed": 0}}

    monkeypatch.setattr(merge_mod, "merge_run", merge_run)
    use_steps(ctx, "merge", ["merge"])
    assert steps.run_step(ctx)["detail"] == "0 findings (confirmed 0)"
    use_steps(ctx, "report", ["report:tr"])
    with state.transaction(ctx) as tx:
        tx.state["incomplete_pending"] = "validation_budget_exhausted"
    # An SBOM input: the report step must deliver the SBOM files too (a live tools-only run
    # wrote every report file except them).
    (ctx.run_dir / "sca").mkdir(exist_ok=True)
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "components": [
            {"type": "library", "name": "flask", "version": "2.0.1", "purl": "pkg:pypi/flask@2.0.1"}
        ],
    }
    (ctx.run_dir / "sca" / "sbom.cdx.json").write_text(json.dumps(sbom), encoding="utf-8")
    outcome = steps.run_step(ctx)
    assert outcome["status"] == "done", outcome
    assert "REPORT.md" in outcome["detail"]
    assert ctx.reload()["incomplete_reason"] == "validation_budget_exhausted"
    assert (ctx.run_dir / "report" / "REPORT.html").is_file()
    assert (ctx.run_dir / "report" / "EXECUTIVE.html").is_file()
    assert (ctx.run_dir / "report" / "sbom.cdx.json").is_file()
    assert (ctx.run_dir / "report" / "sbom.spdx.json").is_file()
    # The run goes on to done: the question first, then the incomplete end with the report.
    assert phases.next_action(ctx, "o") == {"kind": "ask_user", "question": "english_report"}
    phases.answer(ctx, "english_report", "no")
    action = phases.next_action(ctx, "o")
    assert action["kind"] == "incomplete" and action["reason"] == "validation_budget_exhausted"
    assert action["report"].endswith("report/REPORT.md")
    assert ctx.reload()["phase"] == "done"
