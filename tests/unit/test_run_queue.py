# SPDX-License-Identifier: MIT
"""Tests for kalkan.run.queue, kalkan.run.budget and the handler registry
kalkan.run.handlers."""

from __future__ import annotations

import json
import os
import sys
import types
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from kalkan.errors import StateError, ValidationError
from kalkan.run import budget, events, handlers, ids, lock, queue, state
from kalkan.run import init as init_mod
from kalkan.schema.loader import shared_schema
from kalkan.schema.validator import validate

SAMPLES = Path(__file__).resolve().parents[1] / "fixtures" / "task-results"
T0 = datetime(2026, 10, 15, 22, 0, 0, tzinfo=UTC)
ORIGINAL_GET_HANDLER = handlers.get_handler


@pytest.fixture(autouse=True)
def plain_handlers(monkeypatch):
    """Use the default handler, so that type handlers added later do not change these tests."""
    monkeypatch.setattr(handlers, "get_handler", lambda task_type: handlers.default_handler)


@pytest.fixture
def ctx(tmp_path, monkeypatch):
    monkeypatch.setattr(init_mod, "git_head", lambda directory: None)
    target = tmp_path / "app"
    target.mkdir()
    (target / "main.py").write_text("print('sample')\n", encoding="utf-8")
    run = init_mod.init_run(str(target), runs_dir=tmp_path / "runs")
    set_phase(run, "recon")
    return run


def set_phase(ctx, phase):
    with state.transaction(ctx) as tx:
        tx.state["phase"] = phase


def set_status(ctx, task_id, status):
    with state.transaction(ctx) as tx:
        tx.state["tasks"][task_id]["status"] = status


def sample(task_type: str, task_id: str) -> dict:
    data = json.loads((SAMPLES / f"{task_type}.json").read_text(encoding="utf-8"))
    data["task_id"] = task_id
    return data


def write_result(ctx, task_id, data) -> Path:
    path = ctx.task_dir(task_id) / queue.RESULT_NAME
    text = data if isinstance(data, str) else json.dumps(data)
    path.write_text(text, encoding="utf-8")
    return path


def kinds(ctx, kind):
    return [event for event in events.read_events(ctx.run_dir) if event["kind"] == kind]


def recon(ctx, **options) -> str:
    return queue.create_task(ctx, "recon", "recon", {"kind": "surfaces"}, **options)


# ---------------------------------------------------------------------------------------------
# create_task


def test_create_task_writes_files_and_counts_the_budget(ctx):
    task_id = queue.create_task(
        ctx, "recon", "recon", {"kind": "product"}, prompt_text="# Prompt\n", now=T0
    )
    assert task_id == "T0001-recon"
    directory = ctx.task_dir(task_id)
    assert json.loads((directory / "input.json").read_text(encoding="utf-8")) == {"kind": "product"}
    assert (directory / "prompt.md").read_text(encoding="utf-8") == "# Prompt\n"
    task = ctx.state["tasks"][task_id]
    assert task["status"] == "pending"
    assert task["created_at"] == "2026-10-15T22:00:00Z"
    assert ctx.state["next_task_seq"] == 2
    assert ctx.state["budget"]["used_agent_tasks"] == 1
    assert [e["task"] for e in kinds(ctx, "task_created")] == [task_id]


def test_create_task_outside_the_budget(ctx):
    queue.create_task(ctx, "translate", "report", {}, counts_against_budget=False)
    assert ctx.state["budget"]["used_agent_tasks"] == 0


def test_create_task_refuses_when_the_budget_is_used_up(ctx):
    with state.transaction(ctx) as tx:
        tx.state["budget"]["used_agent_tasks"] = tx.state["budget"]["max_agent_tasks"]
    with pytest.raises(StateError, match="budget is used up"):
        recon(ctx)
    assert queue.create_task(ctx, "translate", "report", {}, counts_against_budget=False)


def test_create_task_with_a_dedupe_key_is_idempotent(ctx):
    first = recon(ctx, dedupe_key="hunt:T0003:candidate:0")
    second = recon(ctx, dedupe_key="hunt:T0003:candidate:0")
    assert first == second
    assert len(ctx.state["tasks"]) == 1
    assert ctx.state["budget"]["used_agent_tasks"] == 1


def test_create_task_checks_its_arguments(ctx):
    with pytest.raises(ValueError):
        queue.create_task(ctx, "other", "recon", {})
    with pytest.raises(ValueError):
        queue.create_task(ctx, "recon", "done", {})
    with pytest.raises(ValueError):
        queue.create_task(ctx, "recon", "recon", [])
    with pytest.raises(ValueError):
        recon(ctx, priority=101)
    with pytest.raises(ValueError):
        recon(ctx, max_attempts=0)
    with pytest.raises(StateError, match="invalid task ID"):
        recon(ctx, depends_on=["../x"])
    with pytest.raises(StateError, match="unknown task"):
        recon(ctx, depends_on=["T0009-recon"])
    assert ctx.state["tasks"] == {}


def test_task_ids_grow_past_four_digits(ctx):
    with state.transaction(ctx) as tx:
        tx.state["next_task_seq"] = 10_000
    task_id = recon(ctx)
    assert task_id == "T10000-recon"
    assert validate(sample("recon", task_id), shared_schema("task-recon")) == []


def test_create_task_removes_files_of_an_unsaved_task(ctx):
    directory = ctx.task_dir("T0001-recon")
    directory.mkdir(parents=True)
    (directory / "result.json").write_text("{}", encoding="utf-8")
    (directory / "prompt.md").write_text("old", encoding="utf-8")
    recon(ctx)
    assert not (directory / "result.json").exists()
    assert not (directory / "prompt.md").exists()


# ---------------------------------------------------------------------------------------------
# claim and leases


def test_claim_orders_by_priority_then_sequence(ctx):
    low = recon(ctx, priority=10)
    high_old = recon(ctx, priority=90)
    mid = recon(ctx)
    high_new = recon(ctx, priority=90)
    items = queue.claim(ctx, "orchestrator", 3, now=T0)
    assert [item["id"] for item in items] == [high_old, high_new, mid]
    assert ctx.state["tasks"][low]["status"] == "pending"
    assert queue.claim(ctx, "orchestrator", 0, now=T0) == []


def test_claim_items_name_the_agent_and_absolute_files(ctx):
    expected = {
        "recon": "kalkan-recon",
        "hunt": "kalkan-hunter",
        "critic": "kalkan-critic",
        "verify": "kalkan-verifier",
        "review": "kalkan-reviewer",
        "consolidate": "kalkan-consolidator",
        "polish": "kalkan-polisher",
        "sca_reach": "kalkan-sca-reach",
        "poc_build": "kalkan-poc-builder",
        "translate": "kalkan-translator",
    }
    for task_type in expected:
        queue.create_task(ctx, task_type, "recon", {})
    items = queue.claim(ctx, "worker-1", 10, now=T0)
    assert {item["type"]: item["agent"] for item in items} == expected
    item = items[0]
    assert set(item) == {"id", "type", "agent", "prompt_file", "result_file"}
    assert Path(item["prompt_file"]).is_absolute()
    assert item["prompt_file"].endswith(f"tasks/{item['id']}/prompt.md")
    assert item["result_file"].endswith(f"tasks/{item['id']}/result.json")
    assert "\\" not in item["result_file"]
    lease = ctx.state["tasks"][item["id"]]["lease"]
    assert lease == {"owner": "worker-1", "expires_at": "2026-10-15T22:45:00Z"}


def test_claim_leases_only_the_current_phase_by_default(ctx):
    current = recon(ctx)
    later = queue.create_task(ctx, "sca_reach", "validate", {})
    assert [item["id"] for item in queue.claim(ctx, "o", 10)] == [current]
    assert queue.claim(ctx, "o", 10) == []
    assert [item["id"] for item in queue.claim(ctx, "o", 10, phases={"validate"})] == [later]


def test_claim_filters_by_type(ctx):
    recon(ctx)
    hunt = queue.create_task(ctx, "hunt", "recon", {})
    assert [item["id"] for item in queue.claim(ctx, "o", 10, types=["hunt"])] == [hunt]


@pytest.mark.parametrize("settled", ["done", "dead", "skipped"])
def test_claim_waits_for_dependencies(ctx, settled):
    first = recon(ctx)
    second = recon(ctx, depends_on=[first], priority=100)
    assert [item["id"] for item in queue.claim(ctx, "o", 10)] == [first]
    set_status_with_lease_cleared(ctx, first, settled)
    assert [item["id"] for item in queue.claim(ctx, "o", 10)] == [second]


def set_status_with_lease_cleared(ctx, task_id, status):
    with state.transaction(ctx) as tx:
        tx.state["tasks"][task_id].update(status=status, lease=None)


def test_expired_leases_return_to_pending(ctx):
    task_id = recon(ctx)
    assert queue.claim(ctx, "first", 1, now=T0)
    assert queue.claim(ctx, "second", 1, now=T0 + timedelta(minutes=44)) == []
    items = queue.claim(ctx, "second", 1, now=T0 + timedelta(minutes=46))
    assert [item["id"] for item in items] == [task_id]
    assert ctx.state["tasks"][task_id]["lease"]["owner"] == "second"
    assert [e["owner"] for e in kinds(ctx, "lease_expired")] == ["first"]
    assert ctx.state["tasks"][task_id]["attempts"] == 0


def test_lease_ttl_can_be_configured(ctx):
    task_id = recon(ctx)
    queue.claim(ctx, "o", 1, now=T0, ttl_seconds=60)
    assert ctx.state["tasks"][task_id]["lease"]["expires_at"] == "2026-10-15T22:01:00Z"
    assert queue.expire_leases(ctx, now=T0 + timedelta(seconds=59)) == []
    assert queue.expire_leases(ctx, now=T0 + timedelta(seconds=60)) == [task_id]
    with state.transaction(ctx) as tx:
        tx.state["options"]["lease_ttl_seconds"] = 600
    queue.claim(ctx, "o", 1, now=T0)
    assert ctx.state["tasks"][task_id]["lease"]["expires_at"] == "2026-10-15T22:10:00Z"


def test_claim_checks_its_arguments(ctx):
    with pytest.raises(ValueError):
        queue.claim(ctx, "bad owner", 1)
    with pytest.raises(ValueError):
        queue.claim(ctx, "o", -1)
    with pytest.raises(ValueError):
        queue.claim(ctx, "o", 1, types=["other"])
    with pytest.raises(ValueError):
        queue.claim(ctx, "o", 1, phases=["later"])


def test_release_and_release_owner(ctx):
    one, two, three = recon(ctx), recon(ctx), recon(ctx)
    queue.claim(ctx, "a", 2)
    queue.claim(ctx, "b", 1)
    assert queue.release(ctx, one)
    assert not queue.release(ctx, one)
    assert queue.release_owner(ctx, "a") == [two]
    assert ctx.state["tasks"][three]["status"] == "leased"
    assert all(ctx.state["tasks"][t]["status"] == "pending" for t in (one, two))
    assert all(ctx.state["tasks"][t]["attempts"] == 0 for t in (one, two))


# ---------------------------------------------------------------------------------------------
# complete


def test_complete_marks_done_and_is_idempotent(ctx):
    task_id = recon(ctx)
    queue.claim(ctx, "o", 1)
    write_result(ctx, task_id, sample("recon", task_id))
    outcome = queue.complete(ctx, task_id)
    assert outcome["status"] == "done"
    task = ctx.state["tasks"][task_id]
    assert task["status"] == "done"
    assert task["lease"] is None and task["completing"] is None
    assert task["result_sha256"] == outcome["result_sha256"]
    assert task["completed_at"] is not None
    state_file = (ctx.run_dir / state.STATE_NAME).read_bytes()
    again = queue.complete(ctx, task_id)
    assert again == {**outcome, "status": "unchanged"}
    assert (ctx.run_dir / state.STATE_NAME).read_bytes() == state_file
    assert len(kinds(ctx, "task_completed")) == 1


def test_complete_runs_the_handler_with_the_parsed_result(ctx, monkeypatch):
    seen = []

    def handle(run, task, result):
        seen.append((run.run_id, task["id"], task["type"], result["kind"]))

    monkeypatch.setattr(handlers, "get_handler", lambda task_type: handle)
    task_id = recon(ctx)
    write_result(ctx, task_id, sample("recon", task_id))
    queue.complete(ctx, task_id)
    assert seen == [(ctx.run_id, task_id, "recon", "surfaces")]


def test_complete_accepts_a_pending_task_with_a_late_result(ctx):
    task_id = recon(ctx)
    write_result(ctx, task_id, sample("recon", task_id))
    assert queue.complete(ctx, task_id)["status"] == "done"


def test_a_changed_result_after_done_is_refused(ctx):
    task_id = recon(ctx)
    data = sample("recon", task_id)
    write_result(ctx, task_id, data)
    queue.complete(ctx, task_id)
    data["summary_md"] = "Changed."
    write_result(ctx, task_id, data)
    with pytest.raises(StateError, match="different result"):
        queue.complete(ctx, task_id)


def test_a_missing_result_of_a_leased_task_counts_an_attempt(ctx):
    task_id = recon(ctx)
    queue.claim(ctx, "o", 1)
    with pytest.raises(ValidationError, match="cannot be used"):
        queue.complete(ctx, task_id)
    task = ctx.reload()["tasks"][task_id]
    assert task["status"] == "pending"
    assert task["attempts"] == 1
    assert task["completing"] is None
    assert "result file not found" in task["error"]["details"][0]


def test_a_missing_result_of_an_unclaimed_task_is_a_state_error(ctx):
    task_id = recon(ctx)
    with pytest.raises(StateError, match="result file not found"):
        queue.complete(ctx, task_id)
    task = ctx.reload()["tasks"][task_id]
    assert task["status"] == "pending"
    assert task["attempts"] == 0


def test_invalid_results_count_attempts_until_the_task_is_dead(ctx):
    task_id = recon(ctx)
    for attempt in (1, 2, 3):
        queue.claim(ctx, "o", 1)
        bad = sample("recon", task_id)
        del bad["facts"]
        write_result(ctx, task_id, bad)
        with pytest.raises(ValidationError) as caught:
            queue.complete(ctx, task_id)
        assert "missing required field" in " ".join(caught.value.errors)
        assert f"attempt {attempt} of 3" in str(caught.value)
        task = ctx.state["tasks"][task_id]
        assert task["attempts"] == attempt
        assert task["error"]["kind"] == "invalid_result"
        assert task["error"]["details"]
        assert task["lease"] is None and task["completing"] is None
        directory = ctx.task_dir(task_id)
        assert not (directory / "result.json").exists()
        assert (directory / f"result.rejected-{attempt}.json").exists()
    assert task["status"] == "dead"
    write_result(ctx, task_id, sample("recon", task_id))
    with pytest.raises(StateError, match="dead"):
        queue.complete(ctx, task_id)
    assert queue.fail(ctx, task_id, "late")["status"] == "dead"
    assert ctx.state["tasks"][task_id]["attempts"] == 3
    assert queue.claim(ctx, "o", 5) == []


def test_error_details_are_capped(ctx):
    task_id = recon(ctx)
    write_result(ctx, task_id, {"task_id": task_id, **{f"x{i}": i for i in range(40)}})
    with pytest.raises(ValidationError) as caught:
        queue.complete(ctx, task_id)
    assert len(caught.value.errors) > queue.ERROR_DETAILS_MAX
    assert len(ctx.state["tasks"][task_id]["error"]["details"]) == queue.ERROR_DETAILS_MAX


def test_a_result_for_another_task_is_rejected(ctx):
    task_id = recon(ctx)
    write_result(ctx, task_id, sample("recon", "T0099-recon"))
    with pytest.raises(ValidationError, match="names another task"):
        queue.complete(ctx, task_id)
    assert ctx.state["tasks"][task_id]["attempts"] == 1


@pytest.mark.parametrize(
    "content",
    [b"{not json", b"\xff\xfe invalid utf-8", b" " * (queue.RESULT_MAX_BYTES + 1)],
    ids=["syntax", "encoding", "too-large"],
)
def test_unusable_result_files_count_an_attempt(ctx, content):
    task_id = recon(ctx)
    (ctx.task_dir(task_id) / "result.json").write_bytes(content)
    with pytest.raises(ValidationError):
        queue.complete(ctx, task_id)
    assert ctx.state["tasks"][task_id]["attempts"] == 1
    assert ctx.state["tasks"][task_id]["status"] == "pending"


def test_a_handler_validation_error_counts_an_attempt(ctx, monkeypatch):
    def handle(run, task, result):
        raise ValidationError("quotes do not match", ["evidence[0]: quote not found"])

    monkeypatch.setattr(handlers, "get_handler", lambda task_type: handle)
    task_id = recon(ctx)
    write_result(ctx, task_id, sample("recon", task_id))
    with pytest.raises(ValidationError, match="quotes do not match"):
        queue.complete(ctx, task_id)
    task = ctx.state["tasks"][task_id]
    assert task["attempts"] == 1
    assert task["error"]["details"] == ["evidence[0]: quote not found"]


def test_a_handler_crash_clears_the_marker_and_counts_nothing(ctx, monkeypatch):
    def handle(run, task, result):
        raise RuntimeError("bug")

    monkeypatch.setattr(handlers, "get_handler", lambda task_type: handle)
    task_id = recon(ctx)
    queue.claim(ctx, "o", 1)
    write_result(ctx, task_id, sample("recon", task_id))
    with pytest.raises(RuntimeError):
        queue.complete(ctx, task_id)
    task = ctx.reload()["tasks"][task_id]
    assert task["status"] == "leased"
    assert task["attempts"] == 0
    assert task["completing"] is None
    assert (ctx.task_dir(task_id) / "result.json").exists()


def test_a_second_complete_during_the_handler_is_refused(ctx, monkeypatch):
    task_id = recon(ctx)
    other = recon(ctx)
    queue.claim(ctx, "o", 1)
    write_result(ctx, task_id, sample("recon", task_id))
    checks = []

    def handle(run, task, result):
        second = state.RunContext.load(run.run_dir)
        with pytest.raises(StateError, match="being completed"):
            queue.complete(second, task_id)
        with pytest.raises(StateError, match="being completed"):
            queue.fail(second, task_id, "no")
        with pytest.raises(StateError, match="being completed"):
            queue.release(second, task_id)
        assert queue.expire_leases(second, now=T0 + timedelta(days=1)) == []
        assert [item["id"] for item in queue.claim(second, "x", 5)] == [other]
        checks.append("done")

    monkeypatch.setattr(handlers, "get_handler", lambda task_type: handle)
    assert queue.complete(ctx, task_id)["status"] == "done"
    assert checks == ["done"]
    assert ctx.state["tasks"][task_id]["completing"] is None


def marker(pid, host, age_seconds):
    started = datetime.now(UTC) - timedelta(seconds=age_seconds)
    return {"pid": pid, "host": host, "token": "old", "started_at": ids.format_ts(started)}


def test_a_stale_marker_of_a_dead_process_is_replaced(ctx, monkeypatch):
    task_id = recon(ctx)
    with state.transaction(ctx) as tx:
        tx.state["tasks"][task_id]["completing"] = marker(999_999, lock.hostname(), 5)
    monkeypatch.setattr(lock, "pid_alive", lambda pid: pid == os.getpid())
    write_result(ctx, task_id, sample("recon", task_id))
    assert queue.complete(ctx, task_id)["status"] == "done"
    assert [e["pid"] for e in kinds(ctx, "completion_marker_replaced")] == [999_999]


def test_markers_of_other_hosts_expire_after_30_minutes(ctx):
    task_id = recon(ctx)
    with state.transaction(ctx) as tx:
        tx.state["tasks"][task_id]["completing"] = marker(1, "other-host.example", 60)
    write_result(ctx, task_id, sample("recon", task_id))
    with pytest.raises(StateError, match="being completed"):
        queue.complete(ctx, task_id)
    assert queue.claim(ctx, "o", 5) == []
    with state.transaction(ctx) as tx:
        tx.state["tasks"][task_id]["completing"] = marker(1, "other-host.example", 31 * 60)
    assert queue.complete(ctx, task_id)["status"] == "done"


def test_completion_taken_over_by_another_process(ctx, monkeypatch):
    task_id = recon(ctx)

    def handle(run, task, result):
        with state.transaction(run) as tx:
            tx.state["tasks"][task_id]["completing"]["token"] = "someone-else"

    monkeypatch.setattr(handlers, "get_handler", lambda task_type: handle)
    write_result(ctx, task_id, sample("recon", task_id))
    with pytest.raises(StateError, match="took over"):
        queue.complete(ctx, task_id)


# ---------------------------------------------------------------------------------------------
# fail and resume


def test_fail_counts_attempts(ctx):
    task_id = recon(ctx, max_attempts=2)
    queue.claim(ctx, "o", 1)
    write_result(ctx, task_id, "partial")
    outcome = queue.fail(ctx, task_id, "  the target has no source files  ")
    assert outcome == {"id": task_id, "status": "pending", "attempts": 1, "max_attempts": 2}
    task = ctx.state["tasks"][task_id]
    assert task["error"]["message"] == "the target has no source files"
    assert task["lease"] is None
    assert (ctx.task_dir(task_id) / "result.rejected-1.json").exists()
    assert queue.fail(ctx, task_id, "again")["status"] == "dead"
    with pytest.raises(ValueError):
        queue.fail(ctx, task_id, " ")


def test_fail_refuses_done_tasks(ctx):
    task_id = recon(ctx)
    write_result(ctx, task_id, sample("recon", task_id))
    queue.complete(ctx, task_id)
    with pytest.raises(StateError, match="done"):
        queue.fail(ctx, task_id, "late")


def test_unknown_tasks(ctx):
    with pytest.raises(StateError, match="unknown task"):
        queue.complete(ctx, "T0042-recon")
    with pytest.raises(StateError, match="invalid task ID"):
        queue.complete(ctx, "T42-recon")


def test_resume_completes_releases_and_reports(ctx):
    done, rejected, released = recon(ctx), recon(ctx), recon(ctx)
    pending = recon(ctx)
    queue.claim(ctx, "o", 3)
    write_result(ctx, done, sample("recon", done))
    write_result(ctx, rejected, {"task_id": rejected})
    report = queue.resume(ctx)
    assert report["completed"] == [done]
    assert report["released"] == [released]
    assert [item["id"] for item in report["rejected"]] == [rejected]
    assert report["rejected"][0]["status"] == "pending"
    assert report["busy"] == [] and report["expired"] == [] and report["unchanged"] == []
    statuses = {t: ctx.state["tasks"][t]["status"] for t in (done, rejected, released, pending)}
    assert statuses == {done: "done", rejected: "pending", released: "pending", pending: "pending"}
    assert queue.resume(ctx) == {key: [] for key in report}


def test_task_counts_and_get_task(ctx):
    first = recon(ctx)
    queue.create_task(ctx, "hunt", "hunt", {})
    queue.claim(ctx, "o", 1)
    counts = queue.task_counts(ctx.state)
    assert counts["total"] == 2
    assert counts["by_status"]["leased"] == 1 and counts["by_status"]["pending"] == 1
    assert list(counts["by_type"]) == ["recon", "hunt"]
    assert counts["by_type"]["recon"]["leased"] == 1
    view = queue.get_task(ctx, first)
    assert view["id"] == first and view["type"] == "recon"


# ---------------------------------------------------------------------------------------------
# budget


def budget_state(profile="standard", used=0, tasks=()):
    doc = {
        "options": {"profile": profile},
        "budget": {**budget.initial_budget(profile), "used_agent_tasks": used},
        "tasks": {},
    }
    for index, (task_type, counts) in enumerate(tasks, start=1):
        doc["tasks"][f"T{index:04d}-{task_type}"] = {
            "type": task_type,
            "counts_against_budget": counts,
        }
    return doc


@pytest.mark.parametrize(
    ("name", "canonical", "maximum", "waves"),
    [
        ("fast", "fast", 40, 1),
        ("fast", "fast", 40, 1),
        ("hızlı", "fast", 40, 1),
        ("quick", "fast", 40, 1),
        ("standard", "standard", 150, 2),
        ("STANDARD", "standard", 150, 2),
        ("deep", "deep", 400, 3),
        ("deep", "deep", 400, 3),
    ],
)
def test_profiles(name, canonical, maximum, waves):
    assert budget.canonical_profile(name) == canonical
    initial = budget.initial_budget(name)
    assert initial == {
        "max_agent_tasks": maximum,
        "used_agent_tasks": 0,
        "reserve_critic": waves,
        "reserve_validation_ratio": 0.45,
    }
    assert budget.critic_waves(budget_state(canonical)) == waves
    assert budget.batch_size(budget_state(canonical)) == {1: 6, 2: 4, 3: 3}[waves]


def test_unknown_profile():
    with pytest.raises(ValueError):
        budget.canonical_profile("turbo")


def test_remaining_and_reserves():
    doc = budget_state("fast", used=10, tasks=[("hunt", True)] * 10)
    assert budget.remaining(doc) == 30
    assert budget.validation_reserve(doc) == 18
    assert budget.critic_reserve_left(doc) == 1
    assert budget.validation_reserve_left(doc) == 18
    assert budget.available(doc, "hunt") == 11
    assert budget.available(doc, "critic") == 12
    assert budget.available(doc, "verify") == 29
    assert budget.can_create(doc, 30)
    assert not budget.can_create(doc, 31)
    assert budget.can_create(doc, 11, "hunt")
    assert not budget.can_create(doc, 12, "hunt")
    assert budget.can_create(doc, 0, "hunt")
    # Shares inside the validation reserve and the hunt wave cap.
    assert budget.sca_reach_cap(doc) == 4
    assert budget.deterministic_verify_cap(doc) == 4
    assert budget.hunt_wave_cap(doc) == 9  # (30 - 1) // 3, below available(hunt) = 11


def test_hunt_wave_cap_never_exceeds_the_hunt_budget():
    doc = budget_state("standard", used=80)
    # remaining 70, critic reserve 2, validation reserve 68: no hunt budget is left.
    assert budget.available(doc, "hunt") == 0
    assert budget.hunt_wave_cap(doc) == 0
    fresh = budget_state("standard")
    # Room after the critic reserve (2) and the review reserve (68 // 4 = 17).
    assert budget.hunt_wave_cap(fresh) == (150 - 2 - 17) // 3
    fast = budget_state("fast")
    assert budget.hunt_wave_cap(fast) == (40 - 1) // 3  # no review in the fast profile


def test_reserves_shrink_as_their_tasks_are_created():
    tasks = [("critic", True), ("verify", True), ("sca_reach", True), ("translate", False)]
    doc = budget_state("fast", used=3, tasks=tasks)
    assert budget.counted_tasks(doc, ["translate"]) == 0
    assert budget.critic_reserve_left(doc) == 0
    assert budget.validation_reserve_left(doc) == 16
    assert budget.available(doc, "hunt") == 21


def test_available_never_exceeds_remaining():
    doc = budget_state("fast", used=39)
    assert budget.remaining(doc) == 1
    assert budget.available(doc, "hunt") == 0
    assert budget.available(doc, "verify") == 1
    assert budget.available(doc, "critic") == 1
    doc = budget_state("fast", used=45)
    assert budget.remaining(doc) == 0
    assert budget.available(doc, "verify") == 0


def test_review_reserve_in_standard_and_deep():
    standard = budget_state("standard")
    assert budget.reviews_enabled(standard)
    assert budget.review_reserve(standard) == 17  # 68 // 4
    assert budget.review_reserve_left(standard) == 17
    # Only review tasks can use the review reserve.
    assert budget.available(standard, "review") == 150 - 2
    assert budget.available(standard, "verify") == 150 - 2 - 17
    assert budget.available(standard, "sca_reach") == 150 - 2 - 17
    assert budget.available(standard, "hunt") == 150 - 2 - 68
    assert budget.review_reserve(budget_state("deep")) == 45  # 180 // 4


def test_fast_has_no_review_reserve():
    fast = budget_state("fast")
    assert not budget.reviews_enabled(fast)
    assert budget.review_reserve(fast) == 0
    assert budget.available(fast, "verify") == budget.available(fast, "review") == 39


def test_review_reserve_shrinks_and_is_released_after_the_review_step():
    tasks = [("verify", True)] * 50 + [("review", True)] * 3
    doc = budget_state("standard", used=140, tasks=tasks)
    # remaining 10; validation reserve left 68 - 53 = 15; review reserve left 17 - 3 = 14.
    assert budget.review_reserve_left(doc) == 14
    assert budget.available(doc, "review") == 10
    assert budget.available(doc, "verify") == 1
    doc["phases"] = {"validate": {"status": "running", "steps": {budget.REVIEW_STEP: {}}}}
    assert budget.review_reserve_left(doc) == 14
    doc["phases"]["validate"]["steps"][budget.REVIEW_STEP]["status"] = "done"
    assert budget.review_reserve_left(doc) == 0
    assert budget.available(doc, "poc_build") == 10
    doc["phases"] = {"validate": {"status": "done", "steps": {}}}  # a run without the step
    assert budget.review_reserve_left(doc) == 0


# ---------------------------------------------------------------------------------------------
# handler registry


def test_registry_falls_back_to_the_default_handler(monkeypatch):
    original = handlers.importlib.import_module

    def missing(name, *args, **kwargs):
        if name == "kalkan.run.handlers.critic":
            raise ModuleNotFoundError(f"No module named {name!r}", name=name)
        return original(name, *args, **kwargs)

    monkeypatch.setattr(handlers.importlib, "import_module", missing)
    assert ORIGINAL_GET_HANDLER("critic") is handlers.default_handler
    assert handlers.default_handler(None, {}, {}) is None


def test_registry_returns_the_module_handler(monkeypatch):
    module = types.ModuleType("kalkan.run.handlers.translate")

    def handle(ctx, task, result):
        return None

    module.handle = handle
    monkeypatch.setitem(sys.modules, "kalkan.run.handlers.translate", module)
    assert ORIGINAL_GET_HANDLER("translate") is handle


def test_registry_rejects_a_module_without_handle(monkeypatch):
    monkeypatch.setitem(
        sys.modules, "kalkan.run.handlers.translate", types.ModuleType("kalkan.run.handlers.t")
    )
    with pytest.raises(StateError, match="no handle"):
        ORIGINAL_GET_HANDLER("translate")


def test_registry_reraises_other_import_errors(monkeypatch):
    original = handlers.importlib.import_module

    def broken(name, *args, **kwargs):
        if name == "kalkan.run.handlers.verify":
            raise ModuleNotFoundError("No module named 'yaml'", name="yaml")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(handlers.importlib, "import_module", broken)
    with pytest.raises(ModuleNotFoundError):
        ORIGINAL_GET_HANDLER("verify")


def test_registry_rejects_unknown_types():
    with pytest.raises(ValueError):
        ORIGINAL_GET_HANDLER("os")


def poc_state(profile="fast", used=0, tasks=(), poc_phase=None):
    doc = budget_state(profile, used, tasks)
    doc["budget"] = {**budget.initial_budget(profile, poc=True), "used_agent_tasks": used}
    if poc_phase:
        doc["phases"] = {"poc": {"status": poc_phase}}
    return doc


def test_the_poc_reserve_exists_only_when_the_sandbox_will_run():
    assert "reserve_poc" not in budget.initial_budget("fast")
    assert budget.initial_budget("fast", poc=True)["reserve_poc"] == 4
    assert budget.initial_budget("standard", poc=True)["reserve_poc"] == 15
    assert budget.initial_budget("deep", poc=True)["reserve_poc"] == 40


def test_verify_tasks_never_take_the_poc_reserve():
    # fast: 40 tasks, 18 validation reserve, 4 of it for PoC. 36 used: 4 left, all for PoC.
    tasks = [("verify", True)] * 14
    state = poc_state(used=36, tasks=tasks)
    assert budget.available(state, "verify") == 0
    assert budget.available(state, "poc_build") == 4
    without = budget_state("fast", 36, tasks)
    assert budget.available(without, "verify") == 4


def test_the_poc_reserve_shrinks_with_poc_tasks_and_ends_with_the_poc_phase():
    state = poc_state(used=10, tasks=[("poc_build", True)] * 3)
    assert budget.poc_reserve_left(state) == 1
    assert budget.poc_reserve_left(poc_state(used=10, poc_phase="done")) == 0
