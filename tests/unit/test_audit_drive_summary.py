# SPDX-License-Identifier: MIT
"""Tests for the engine drive, the run watcher and the end summary of ``kalkan audit``
(kalkan.audit.drive, kalkan.audit.summary).

The engine runs for real in this process. Only ``run_adapter`` is replaced: every external
scanner returns ``skipped`` at once (the full drive with the real matcher is in
tests/unit/test_run_tools_only.py and tests/unit/test_audit_commands.py).
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from kalkan.audit import drive, summary
from kalkan.report.model import build_model
from kalkan.run import ids, phases, state
from kalkan.run import init as init_mod
from kalkan.run.init import init_run
from kalkan.scanners import base

TARGETS = Path(__file__).resolve().parents[1] / "fixtures" / "targets"


@pytest.fixture
def fast_engine(monkeypatch):
    """Every scanner and SCA tool is skipped at once (no process starts)."""

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


def make_run(runs, target, mode=state.MODE_TOOLS_ONLY):
    return init_run(str(target), runs_dir=runs, mode=mode)


# ---------------------------------------------------------------------------------------------
# drive_steps


def test_tools_only_drive_reaches_done(runs, target, fast_engine):
    ctx = make_run(runs, target)
    said: list[str] = []
    action = drive.drive_steps(ctx, allowed=None, say=said.append)
    assert action["kind"] == "done"
    assert said[0] == "phase deterministic"
    assert "phase sca" in said and "phase merge" in said and "phase report" in said
    assert any(line.startswith("  scan:trivy: skipped (") for line in said)
    trivy = next(line for line in said if "scan:trivy" in line)
    assert "skipped: skipped" not in trivy  # the status is not repeated in the detail
    assert ctx.reload()["phase"] == "done" and ctx.state["tasks"] == {}


def test_agent_mode_drive_stops_before_recon(runs, target, fast_engine):
    ctx = make_run(runs, target, mode=state.MODE_AGENTS)
    said: list[str] = []
    action = drive.drive_steps(ctx, allowed=drive.DETERMINISTIC_PHASES, say=said.append)
    current = ctx.reload()
    assert current["phase"] == "recon"
    assert current["phases"]["deterministic"]["status"] == "done"
    assert current["phases"]["sca"]["status"] == "done"
    assert action["kind"] == "wait" and "agent tasks" in action["reason"]
    # No task was leased: the agent rounds claim them.
    assert {task["status"] for task in current["tasks"].values()} == {"pending"}
    assert "phase recon" not in said


def test_a_step_of_another_process_waits(runs, target, monkeypatch):
    ctx = make_run(runs, target)
    actions = iter(
        [
            {"kind": "wait", "retry_after_seconds": 60, "reason": "an engine step runs in another"},
            {"kind": "done", "report": "x"},
        ]
    )
    monkeypatch.setattr(phases, "next_action", lambda ctx, owner, limit: next(actions))
    slept: list[float] = []
    said: list[str] = []
    action = drive.drive_steps(ctx, allowed=None, say=said.append, sleep=slept.append)
    assert action["kind"] == "done" and slept == [drive.WAIT_SECONDS]
    assert said == ["waiting: an engine step runs in another"]


def test_the_drive_never_claims_a_task(runs, target, monkeypatch):
    ctx = make_run(runs, target)
    limits = []

    def next_action(ctx, owner, limit):
        limits.append((owner, limit))
        return {"kind": "done", "report": "x"}

    monkeypatch.setattr(phases, "next_action", next_action)
    drive.drive_steps(ctx, allowed=None, say=lambda _m: None)
    assert limits == [(drive.OWNER, 0)]


# ---------------------------------------------------------------------------------------------
# RunWatcher


def set_tasks(ctx, statuses):
    with state.transaction(ctx) as tx:
        tx.state["tasks"] = {}
        for seq, status in enumerate(statuses, 1):
            task_id = f"T{seq:04d}-recon"
            tx.state["tasks"][task_id] = {
                "seq": seq,
                "type": "recon",
                "phase": "recon",
                "status": status,
                "priority": 50,
                "attempts": 0,
                "max_attempts": 3,
                "lease": {"owner": "o", "expires_at": "2099-01-01T00:00:00Z"}
                if status == "leased"
                else None,
                "created_at": "2026-10-25T10:00:00Z",
                "updated_at": "2026-10-25T10:00:00Z",
                "completed_at": None,
                "result_sha256": None,
                "error": None,
                "depends_on": [],
                "counts_against_budget": True,
                "dedupe_key": None,
                "completing": None,
                "meta": {},
            }
        tx.state["next_task_seq"] = len(statuses) + 1
        tx.state["phase"] = "recon"


def test_the_watcher_prints_phases_and_paced_task_counts(runs, target):
    ctx = make_run(runs, target, mode=state.MODE_AGENTS)
    now = [0.0]
    said: list[str] = []
    watcher = drive.RunWatcher(ctx.run_dir, said.append, task_interval=120, clock=lambda: now[0])
    assert watcher.poll() == "phase deterministic"
    assert watcher.poll() is None  # nothing changed
    set_tasks(ctx, ["leased", "leased", "pending", "pending"])
    now[0] = 10.0
    assert watcher.poll() == (
        "phase recon: 0 of 4 agent tasks finished, 2 running; budget 0 of 150 used"
    )
    set_tasks(ctx, ["done", "leased", "leased", "pending"])
    now[0] = 60.0
    assert watcher.poll() is None  # the last line is younger than the task interval
    now[0] = 131.0
    assert watcher.poll() == (
        "phase recon: 1 of 4 agent tasks finished, 2 running; budget 0 of 150 used"
    )
    assert said == [
        "phase deterministic",
        "phase recon: 0 of 4 agent tasks finished, 2 running; budget 0 of 150 used",
        "phase recon: 1 of 4 agent tasks finished, 2 running; budget 0 of 150 used",
    ]


def test_the_watcher_ignores_a_state_that_cannot_be_read(tmp_path):
    said: list[str] = []
    watcher = drive.RunWatcher(tmp_path / "missing", said.append)
    assert watcher.poll() is None and said == []


def test_the_watcher_thread_starts_and_stops(runs, target):
    ctx = make_run(runs, target)
    said: list[str] = []
    with drive.RunWatcher(ctx.run_dir, said.append, interval=0.01):
        pass
    assert said[0] == "phase deterministic"


# ---------------------------------------------------------------------------------------------
# Deliverables and the end summary


def test_deliverables_in_order_with_every_sbom(tmp_path):
    report = tmp_path / "report"
    report.mkdir()
    for name in ("summary.json", "REPORT.md", "EXECUTIVE.html", "findings.sarif", "REPORT.html"):
        (report / name).write_text("x", encoding="utf-8")
    (report / "sbom.spdx.json").write_text("{}", encoding="utf-8")
    (report / "sbom.cdx.json").write_text("{}", encoding="utf-8")
    (tmp_path / "sca").mkdir()
    (tmp_path / "sca" / "sbom.cdx.json").write_text("{}", encoding="utf-8")
    labels = [item["label"] for item in summary.deliverables(tmp_path)]
    assert labels == [
        "EXECUTIVE.html",
        "REPORT.html",
        "REPORT.md",
        "findings.sarif",
        "summary.json",
        "SBOM (CycloneDX)",
        "SBOM (SPDX)",
    ]
    (report / "sbom.cdx.json").unlink()
    found = summary.deliverables(tmp_path)
    assert found[-1] == {
        "label": "SBOM (CycloneDX)",
        "path": (tmp_path / "sca" / "sbom.cdx.json").absolute().as_posix(),
    }


def test_the_summary_of_a_tools_only_run(runs, target, fast_engine):
    ctx = make_run(runs, target)
    drive.drive_steps(ctx, allowed=None, say=lambda _m: None)
    # Two tool results of different severity, as a scanner would leave them.
    candidates = {
        "schema_version": 1,
        "candidates": [
            candidate("CAND-0000000000000001", "low", "app/routes.py", 3, "Weak thing"),
            candidate("CAND-0000000000000002", "high", "app/routes.py", 14, "SQL built from input"),
        ],
        "warnings": [],
    }
    (ctx.run_dir / "candidates.json").write_text(json.dumps(candidates), encoding="utf-8")
    data = summary.build_summary(ctx.run_dir)
    assert data["mode"] == "tools-only" and data["posture"] == "unknown"
    assert data["phase"] == "done" and data["complete"] is True
    assert data["tool_results"]["total"] == 2
    assert data["tool_results"]["by_severity"]["high"] == 1
    assert data["top"][0] == {
        "kind": "tool_result",
        "severity": "high",
        "title": "SQL built from input",
        "engine": "opengrep",
        "location": "app/routes.py:14",
        "id": "CAND-0000000000000002",
    }
    assert data["partial_reasons"][0]["code"] == "tools_only"
    assert data["open_first"].endswith("/report/EXECUTIVE.html")
    text = summary.format_summary(data, elapsed="12 s")
    lines = text.splitlines()
    assert lines[0] == f"Tools-only audit done: run {ctx.run_id} (12 s)"
    assert lines[1] == "Posture: not assessed (tools-only mode: no agent validation)"
    assert lines[2] == "Unverified tool results: 2 (critical 0, high 1, medium 0, low 1, info 0)"
    assert "  1. [high] opengrep: SQL built from input" in lines
    assert "Partial pass: tools-only" not in text  # the posture line says it
    assert lines[-1] == f"Open the executive summary: {data['open_first']}"
    assert json.loads(json.dumps(data)) == data


def candidate(cid, severity, file, line, title):
    return {
        "id": cid,
        "engine": "opengrep",
        "rule_id": "rule",
        "class": None,
        "cwe": [],
        "title": title,
        "message": title,
        "file": file,
        "start_line": line,
        "end_line": line,
        "snippet": "",
        "severity": severity,
        "tool_severity": "",
        "confidence": None,
        "tags": [],
        "fingerprints": {},
        "sca": None,
        "raw": {"sarif_file": "scans/opengrep.sarif", "run_index": 0, "result_index": 0},
    }


def test_the_summary_of_an_agents_run_lists_the_top_findings(runs, target, fast_engine):
    ctx = make_run(runs, target, mode=state.MODE_AGENTS)
    model = build_model(ctx.run_dir)
    model.findings_available = True
    model.confirmed = [confirmed(n, severity) for n, severity in enumerate(SEVERITIES, 1)]
    data = summary.build_summary(ctx.run_dir, model=model)
    assert data["mode"] == "agents" and data["posture"] == "critical"
    assert data["posture_label"] == "Critical"
    assert [item["severity"] for item in data["top"]] == ["critical", "high", "medium"]
    assert data["top"][0]["location"] == "app/routes.py:14"
    text = summary.format_summary(data)
    assert "Posture: Critical" in text
    assert "Confirmed findings: 4 (critical 1, high 1, medium 1, low 1, info 0)" in text
    assert f"Audit stopped in phase deterministic: run {ctx.run_id}" in text


SEVERITIES = ("low", "critical", "medium", "high")


def confirmed(number, severity):
    return {
        "id": f"KF-{number:016X}",
        "verdict": "confirmed",
        "title": f"Finding {number} ({severity})",
        "severity": {
            "likelihood": {"score": "medium"},
            "impact": {"score": severity},
            "overall_severity": severity,
        },
        "trace": [{"kind": "sink", "file": "app/routes.py", "line": 14}],
        "evidence": [{"file": "app/routes.py", "line": 14}],
    }
