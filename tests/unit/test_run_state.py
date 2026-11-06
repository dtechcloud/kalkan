# SPDX-License-Identifier: MIT
"""Tests for kalkan.run.state and kalkan.run.events: state checks, atomic save, transactions,
the run context and the event log."""

from __future__ import annotations

import copy
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from kalkan.errors import StateError
from kalkan.run import events, ids, state
from kalkan.run.lock import LOCK_NAME
from kalkan.schema.loader import shared_schema
from kalkan.schema.validator import check_schema

MOMENT = datetime(2026, 10, 15, 22, 43, 5, tzinfo=UTC)
TS = "2026-10-15T22:43:05Z"


def base_state(run_id: str = "20261015T224305Z-app-abcd") -> dict:
    return {
        "schema_version": 1,
        "run_id": run_id,
        "created_at": TS,
        "updated_at": TS,
        "target": {"source": "C:/work/app", "kind": "path", "git_ref": None, "copy": "target"},
        "options": {
            "profile": "standard",
            "lang": "tr",
            "max_parallel": 6,
            "allow_build_network": False,
            "docker": "auto",
        },
        "budget": {
            "max_agent_tasks": 150,
            "used_agent_tasks": 0,
            "reserve_critic": 2,
            "reserve_validation_ratio": 0.3,
        },
        "phase": "deterministic",
        "phases": state.new_phases(),
        "tasks": {},
        "next_task_seq": 1,
        "incomplete_reason": None,
    }


def task_record(seq: int, task_type: str = "recon", **changes) -> dict:
    record = {
        "seq": seq,
        "type": task_type,
        "phase": "recon",
        "status": "pending",
        "priority": 50,
        "attempts": 0,
        "max_attempts": 3,
        "lease": None,
        "created_at": TS,
        "updated_at": TS,
        "completed_at": None,
        "result_sha256": None,
        "error": None,
        "depends_on": [],
        "counts_against_budget": True,
        "dedupe_key": None,
        "completing": None,
        "meta": {},
    }
    record.update(changes)
    return record


def with_tasks(*records: dict) -> dict:
    doc = base_state()
    for record in records:
        doc["tasks"][state.task_id_for(record["seq"], record["type"])] = record
    doc["next_task_seq"] = max((r["seq"] for r in records), default=0) + 1
    return doc


def make_run(tmp_path: Path, doc: dict | None = None) -> state.RunContext:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    state.save_state(run_dir, doc or base_state(), now=MOMENT)
    return state.RunContext.load(run_dir)


# ---------------------------------------------------------------------------------------------
# Schema and checks


def test_state_schema_uses_supported_keywords_only():
    assert check_schema(shared_schema("state")) == []


def test_the_phase_order():
    assert state.PHASES == (
        "prep",
        "deterministic",
        "sca",
        "recon",
        "plan",
        "hunt",
        "validate",
        "poc",
        "merge",
        "report",
        "done",
    )
    assert shared_schema("state")["properties"]["phase"]["enum"] == list(state.PHASES)


def test_a_valid_state_passes():
    doc = with_tasks(
        task_record(1),
        task_record(2, "hunt", depends_on=["T0001-recon"]),
        task_record(
            3,
            "verify",
            status="leased",
            lease={"owner": "orchestrator", "expires_at": TS},
        ),
    )
    assert state.check_state(doc) == []


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda d: d.pop("phase"), "missing required field"),
        (lambda d: d.update(extra=1), "unexpected field"),
        (lambda d: d["phases"].pop("poc"), "exactly the phases"),
        (lambda d: d["phases"]["prep"].update(status="finished"), "phases.prep.status"),
        (lambda d: d["phases"]["prep"]["steps"].update(copy={"status": "done"}), "detail"),
        (lambda d: d["phases"]["prep"]["steps"].update({"Bad Name": {}}), "invalid step name"),
        (lambda d: d["options"].update(max_parallel=99), "at most 32"),
        (lambda d: d["budget"].update(reserve_validation_ratio=1.5), "at most 1"),
        (lambda d: d.update(created_at="2026-02-30T10:00:00Z"), "valid date"),
        (lambda d: d["target"].update(git_ref="abc"), "git_ref"),
        (lambda d: d.update(phase="later"), "invalid value"),
    ],
)
def test_invalid_states_are_reported(change, message):
    doc = base_state()
    change(doc)
    errors = state.check_state(doc)
    assert errors
    assert any(message in error for error in errors), errors


@pytest.mark.parametrize(
    ("record", "message"),
    [
        (task_record(1, status="leased"), "a leased task needs"),
        (task_record(1, lease={"owner": "x", "expires_at": TS}), "must be null"),
        (task_record(1, depends_on=["T0009-recon"]), "unknown task"),
        (task_record(1, depends_on=["T0001-recon"]), "not an older task"),
        (task_record(1, priority=500), "priority"),
        (task_record(1, phase="done"), "phase other than done"),
        (task_record(1, extra=True), "unexpected field"),
        (task_record(1, result_sha256="ABC"), "result_sha256"),
        (task_record(1, error={"kind": "x", "message": "y", "details": [], "at": "no"}), "at"),
        (task_record(1, completing={"pid": "1"}), "completing"),
        (task_record(1, meta=[]), "meta"),
    ],
)
def test_invalid_tasks_are_reported(record, message):
    errors = state.check_state(with_tasks(record))
    assert any(message in error for error in errors), errors


def test_task_ids_must_match_their_records():
    doc = with_tasks(task_record(1))
    doc["tasks"]["T0001-hunt"] = doc["tasks"].pop("T0001-recon")
    assert any("type" in error for error in state.check_state(doc))
    doc = with_tasks(task_record(1))
    doc["tasks"]["bad"] = task_record(2)
    assert any("invalid task ID" in error for error in state.check_state(doc))
    doc = with_tasks(task_record(1))
    doc["next_task_seq"] = 1
    assert any("next_task_seq" in error for error in state.check_state(doc))


def test_task_ids():
    assert state.task_id_for(7, "sca_reach") == "T0007-sca_reach"
    assert state.task_id_for(12345, "hunt") == "T12345-hunt"
    assert state.parse_task_id("T0007-sca_reach") == (7, "sca_reach")
    assert state.parse_task_id("T007-recon") is None
    assert state.parse_task_id("T0007-unknown") is None
    assert state.parse_task_id("T0007-recon/..") is None
    with pytest.raises(ValueError):
        state.task_id_for(0, "recon")
    with pytest.raises(ValueError):
        state.task_id_for(1, "other")


# ---------------------------------------------------------------------------------------------
# Load and save


def test_save_and_load_round_trip(tmp_path):
    later = datetime(2026, 10, 15, 23, 0, 0, tzinfo=UTC)
    doc = base_state()
    state.save_state(tmp_path, doc, now=later)
    assert doc["updated_at"] == "2026-10-15T23:00:00Z"
    loaded = state.load_state(tmp_path)
    assert loaded == doc
    text = (tmp_path / state.STATE_NAME).read_bytes()
    assert b"\r\n" not in text
    assert text.endswith(b"}\n")


def test_save_refuses_an_invalid_state(tmp_path):
    doc = base_state()
    state.save_state(tmp_path, doc)
    before = (tmp_path / state.STATE_NAME).read_text(encoding="utf-8")
    broken = copy.deepcopy(doc)
    broken["phase"] = "nowhere"
    with pytest.raises(StateError, match="refusing to save"):
        state.save_state(tmp_path, broken)
    assert (tmp_path / state.STATE_NAME).read_text(encoding="utf-8") == before


def test_load_reports_missing_and_corrupt_states(tmp_path):
    with pytest.raises(StateError, match="missing"):
        state.load_state(tmp_path)
    (tmp_path / state.STATE_NAME).write_text("{not json", encoding="utf-8")
    with pytest.raises(StateError, match="not valid JSON"):
        state.load_state(tmp_path)
    (tmp_path / state.STATE_NAME).write_text(json.dumps({"schema_version": 1}), encoding="utf-8")
    with pytest.raises(StateError, match="invalid"):
        state.load_state(tmp_path)


# ---------------------------------------------------------------------------------------------
# Context and transactions


def test_context_properties(tmp_path):
    ctx = make_run(tmp_path)
    assert ctx.run_id == "20261015T224305Z-app-abcd"
    assert ctx.phase == "deterministic"
    assert ctx.target_dir == ctx.run_dir / "target"
    assert ctx.source_dir == ctx.run_dir / "source"  # never the original folder
    assert ctx.lang == "tr"
    assert ctx.options["max_parallel"] == 6
    assert ctx.task_dir("T0001-recon") == ctx.run_dir / "tasks" / "T0001-recon"
    with pytest.raises(StateError):
        ctx.task_dir("../x")


def test_git_targets_use_the_clone_as_source(tmp_path):
    doc = base_state()
    doc["target"].update(kind="git", source="https://example.com/org/app.git")
    ctx = make_run(tmp_path, doc)
    assert ctx.source_dir == ctx.run_dir / "source"


def test_load_context_follows_latest(tmp_path):
    root = tmp_path / "runs"
    run_id = "20261015T224305Z-app-abcd"
    (root / run_id).mkdir(parents=True)
    state.save_state(root / run_id, base_state(run_id))
    ids.write_latest(run_id, root)
    ctx = state.load_context(root=root)
    assert ctx.run_dir == root / run_id


def test_transaction_saves_changes_and_appends_events(tmp_path):
    ctx = make_run(tmp_path)
    with state.transaction(ctx, now=MOMENT) as tx:
        tx.state["incomplete_reason"] = "budget"
        tx.event("note", value=1)
    assert ctx.state["incomplete_reason"] == "budget"
    assert state.load_state(ctx.run_dir)["incomplete_reason"] == "budget"
    recorded = events.read_events(ctx.run_dir)
    assert [(e["kind"], e["value"]) for e in recorded] == [("note", 1)]
    assert not (ctx.run_dir / LOCK_NAME).exists()


def test_transaction_without_changes_does_not_save(tmp_path):
    ctx = make_run(tmp_path)
    path = ctx.run_dir / state.STATE_NAME
    before = path.read_bytes()
    with state.transaction(ctx, now=datetime(2030, 1, 1, tzinfo=UTC)):
        pass
    assert path.read_bytes() == before


def test_transaction_discards_changes_on_error(tmp_path):
    ctx = make_run(tmp_path)
    with pytest.raises(RuntimeError), state.transaction(ctx) as tx:
        tx.state["incomplete_reason"] = "lost"
        tx.event("lost")
        raise RuntimeError("boom")
    assert state.load_state(ctx.run_dir)["incomplete_reason"] is None
    assert events.read_events(ctx.run_dir) == []
    assert not (ctx.run_dir / LOCK_NAME).exists()


def test_transaction_refuses_to_save_an_invalid_change(tmp_path):
    ctx = make_run(tmp_path)
    with pytest.raises(StateError), state.transaction(ctx) as tx:
        tx.state["next_task_seq"] = 0
    assert state.load_state(ctx.run_dir)["next_task_seq"] == 1


# ---------------------------------------------------------------------------------------------
# Events


def test_append_event_writes_one_json_line(tmp_path):
    record = events.append_event(tmp_path, "task_created", task="T0001-recon", note="ğüşıöç")
    assert record["kind"] == "task_created"
    events.append_event(tmp_path, "task_leased", task="T0001-recon", text="\ud800")
    lines = (tmp_path / events.EVENTS_NAME).read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    assert list(first)[:2] == ["ts", "kind"]
    assert first["note"] == "ğüşıöç"
    assert ids.TIMESTAMP_PATTERN.fullmatch(first["ts"])
    assert json.loads(lines[1])["text"] == "\ud800"


def test_append_event_rejects_bad_input(tmp_path):
    with pytest.raises(ValueError):
        events.append_event(tmp_path, "Bad Kind")
    with pytest.raises(ValueError):
        events.append_event(tmp_path, "ok", ts="x")


def test_read_events_skips_malformed_lines(tmp_path):
    (tmp_path / events.EVENTS_NAME).write_text(
        '{"ts":"x","kind":"a"}\nnot json\n[1]\n\n{"ts":"y","kind":"b"}\n', encoding="utf-8"
    )
    assert [e["kind"] for e in events.read_events(tmp_path)] == ["a", "b"]
    assert events.read_events(tmp_path / "missing") == []
