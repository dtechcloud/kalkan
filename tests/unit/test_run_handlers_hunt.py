# SPDX-License-Identifier: MIT
"""Tests for the hunt and critic handlers (kalkan.run.handlers.hunt, .critic)."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from kalkan.errors import ValidationError
from kalkan.findings.ledger import validate_ledger_file
from kalkan.run import ids, plan, queue, state, validation
from kalkan.run import init as init_mod
from kalkan.run.init import init_run
from kalkan.run.ledger_store import load_ledger
from kalkan.run.runfiles import write_json, write_text

TARGETS = Path(__file__).resolve().parents[1] / "fixtures" / "targets"
SINK = 'conn.execute("SELECT name FROM users WHERE id = ?"'
SURFACE = {
    "id": "S001",
    "kind": "http",
    "name": "GET /users",
    "file": "app/routes.py",
    "line": 10,
    "auth": "none",
    "trust_boundary": "internet to application",
    "subsystem": "api",
    "notes": "",
}


@pytest.fixture
def ctx(tmp_path, monkeypatch):
    monkeypatch.setenv(ids.RUNS_DIR_ENV, str(tmp_path / "runs"))
    monkeypatch.setattr(init_mod, "git_head", lambda directory: None)
    target = tmp_path / "webapp"
    shutil.copytree(TARGETS / "webapp", target)
    return init_run(str(target), runs_dir=tmp_path / "runs")


def seed(ctx, classes=("sqli", "idor"), surfaces=(SURFACE,)):
    write_json(ctx.run_dir / "recon" / "surfaces.json", {"surfaces": list(surfaces)})
    write_json(ctx.run_dir / "recon" / "classes.json", {"classes": list(classes)})
    write_text(ctx.run_dir / "recon" / "architecture.md", "# Architecture summary\n")


def move_to(ctx, phase):
    with state.transaction(ctx) as tx:
        tx.state["phase"] = phase
        tx.state["phases"][phase]["status"] = "running"


def planned_hunt(ctx, **kwargs):
    seed(ctx, **kwargs)
    move_to(ctx, "plan")
    plan.plan_ledger(ctx)
    plan.create_hunt_wave(ctx, 1)
    move_to(ctx, "hunt")
    items = queue.claim(ctx, "tester", 10)
    assert items
    return items


def read_input(ctx, task_id):
    return json.loads((ctx.task_dir(task_id) / "input.json").read_text(encoding="utf-8"))


def candidate(coverage_id, slug="sqli", scope="users", quote=SINK, line=14):
    return {
        "coverage_id": coverage_id,
        "title": f"{slug} in the user lookup",
        "class": slug,
        "cwe": [],
        "description": "The id parameter reaches the query.",
        "claimed_root_cause": "No ownership check.",
        "trace": [
            {
                "kind": "entrypoint",
                "file": "app/routes.py",
                "line": 12,
                "scope": "users",
                "description": "Reads id.",
            },
            {
                "kind": "sink",
                "file": "app/routes.py",
                "line": line,
                "scope": scope,
                "description": "Runs the query.",
            },
        ],
        "evidence": [{"file": "app/routes.py", "line": line, "quote": quote}],
        "suggested_severity": {"likelihood": "high", "impact": "critical"},
        "dynamic_test": "",
        "related_candidates": [],
    }


def unit_result(coverage_id, status="covered", unresolved=()):
    return {
        "coverage_id": coverage_id,
        "status": status,
        "checks": [
            {
                "reviewed_paths": ["app/routes.py", "/etc/passwd"],
                "invariant": " Every lookup binds the id. ",
                "result": "The handler binds the id.",
            }
        ],
        "notes": "",
        "unresolved": list(unresolved),
    }


def write_result(ctx, task_id, result):
    result = {"task_id": task_id, "hardening": [], "uncovered": [], **result}
    (ctx.task_dir(task_id) / "result.json").write_text(json.dumps(result), encoding="utf-8")


def ids_by_class(ctx, task_id):
    return {unit["class"]: unit["coverage_id"] for unit in read_input(ctx, task_id)["units"]}


def read_candidates(ctx, task_id):
    data = json.loads((ctx.task_dir(task_id) / "candidates.json").read_text(encoding="utf-8"))
    return data["candidates"]


def test_hunt_updates_the_ledger_and_the_wave_end_creates_verify_tasks(ctx):
    [item] = planned_hunt(ctx)
    hunt_id = item["id"]
    by_class = ids_by_class(ctx, hunt_id)
    write_result(
        ctx,
        hunt_id,
        {
            "units": [
                unit_result(by_class["sqli"], "candidate"),
                unit_result(by_class["idor"], "covered"),
            ],
            "candidates": [
                candidate(by_class["sqli"]),
                candidate(by_class["sqli"]),  # an exact duplicate in the same result
                candidate(by_class["sqli"], scope="users-alt", quote="no such text", line=15),
                candidate(by_class["sqli"], scope="users-again"),  # same root cause as #0
            ],
            "uncovered": [
                {
                    "surface_id": "S001",
                    "class": "ssrf",
                    "reason": "Outbound call.",
                    "starting_paths": ["app/routes.py"],
                }
            ],
        },
    )
    assert queue.complete(ctx, hunt_id)["status"] == "done"
    assert validate_ledger_file(ctx.run_dir / "coverage-ledger.json") == []
    ledger = {unit["coverage_id"]: unit for unit in load_ledger(ctx)}
    sqli = ledger[by_class["sqli"]]
    assert sqli["status"] == "candidate"
    assert sqli["agent_id"] == hunt_id.lower()
    assert sqli["reviewed_paths"] == ["app/routes.py"]
    assert sqli["local_checks"][0] == {
        "agent_id": hunt_id.lower(),
        "reviewed_paths": ["app/routes.py"],
        "invariant": "Every lookup binds the id.",
        "method": "source",
        "result": "The handler binds the id.",
        "artifact": None,
    }
    assert sqli["result_fingerprints"] == [
        "sqli:app/routes.py:users",
        "sqli:app/routes.py:users-alt",
        "sqli:app/routes.py:users-again",
    ]
    assert ledger[by_class["idor"]]["status"] == "covered"
    planned = [unit for unit in ledger.values() if unit["status"] == "planned"]
    assert [unit["attack_class"] for unit in planned] == ["ssrf"]
    assert planned[0]["wave"] == 2

    # The handler creates no verify task; the wave end allocates them.
    candidates = read_candidates(ctx, hunt_id)
    assert {item["status"] for item in candidates} == {"pending"}
    assert candidates[0]["suggested_severity"] == {"likelihood": "high", "impact": "critical"}
    assert candidates[0]["normalized"] == []
    assert not [t for t in ctx.reload()["tasks"].values() if t["type"] == "verify"]
    summary = validation.allocate_hunter_verifies(ctx)
    assert summary == {
        "fingerprints": 3,
        "groups": 2,
        "created": 2,
        "reused": 0,
        "unvalidated": 0,
    }
    candidates = read_candidates(ctx, hunt_id)
    assert [item["status"] for item in candidates] == [
        "queued",
        "duplicate",
        "queued",
        "duplicate",
    ]
    assert candidates[3]["duplicate_of"] == f"{hunt_id}#0"
    assert candidates[0]["quotes"][0]["quote_status"] == "verified"
    assert candidates[2]["quotes"][0]["quote_status"] == "unverified"
    verify_ids = [c["verify_task"] for c in candidates]
    assert verify_ids[0] == verify_ids[1] == verify_ids[3] != verify_ids[2]
    assert validation.allocate_hunter_verifies(ctx)["reused"] == 2  # idempotent
    tasks = ctx.reload()["tasks"]
    assert tasks[verify_ids[0]]["priority"] == 30 + 6 * (4 + 3)
    assert tasks[verify_ids[2]]["priority"] == 10
    verify_input = read_input(ctx, verify_ids[0])
    assert verify_input["subject"] == {"kind": "hunter", "ref": f"{hunt_id}#0"}
    assert verify_input["claim"]["evidence"][0]["quote_status"] == "verified"
    assert (ctx.task_dir(verify_ids[0]) / "prompt.md").is_file()

    # A repeated handler run (stale completion marker) changes nothing.
    before = (ctx.run_dir / "coverage-ledger.json").read_bytes()
    allocated = (ctx.task_dir(hunt_id) / "candidates.json").read_bytes()
    count = len(ctx.reload()["tasks"])
    task = queue.get_task(ctx, hunt_id)
    from kalkan.run.handlers import hunt

    hunt.handle(ctx, task, json.loads((ctx.task_dir(hunt_id) / "result.json").read_text()))
    assert (ctx.run_dir / "coverage-ledger.json").read_bytes() == before
    assert (ctx.task_dir(hunt_id) / "candidates.json").read_bytes() == allocated
    assert len(ctx.reload()["tasks"]) == count


def test_hunt_candidate_traces_are_normalized(ctx):
    [item] = planned_hunt(ctx)
    by_class = ids_by_class(ctx, item["id"])
    mislabeled = candidate(by_class["sqli"])
    entry, sink = mislabeled["trace"]
    mislabeled["trace"] = [entry, sink, {**sink, "kind": "propagation", "scope": "render"}]
    write_result(
        ctx,
        item["id"],
        {
            "units": [unit_result(by_class["sqli"], "candidate"), unit_result(by_class["idor"])],
            "candidates": [mislabeled],
        },
    )
    queue.complete(ctx, item["id"])
    [recorded] = read_candidates(ctx, item["id"])
    assert recorded["fingerprint"] == "sqli:app/routes.py:render"  # the last step is the sink
    assert recorded["normalized"] == [
        "trace[1].kind: sink -> propagation",
        "trace[2].kind: propagation -> sink",
    ]
    validation.allocate_hunter_verifies(ctx)
    verify_input = read_input(ctx, read_candidates(ctx, item["id"])[0]["verify_task"])
    kinds = [step["kind"] for step in verify_input["claim"]["trace"]]
    assert kinds == ["entrypoint", "propagation", "sink"]


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda ids_, r: r["units"].pop(), "is missing"),
        (lambda ids_, r: r["units"].append(unit_result("other-id")), "not assigned"),
        (lambda ids_, r: r["units"].append(dict(r["units"][0])), "appears 2 times"),
        (lambda ids_, r: r["units"][0].update(status="candidate"), "needs at least one candidate"),
        (lambda ids_, r: r["units"][0].update(unresolved=["x"]), "covered unit has no"),
        (lambda ids_, r: r["units"][0].update(status="blocked"), "blocked unit needs"),
        (lambda ids_, r: r["candidates"].append(candidate(ids_["idor"])), "must not have"),
        (lambda ids_, r: r["candidates"].append(candidate("zzz")), "not an assigned unit"),
        (
            lambda ids_, r: r["units"][0]["checks"][0].update(reviewed_paths=["../x"]),
            "no safe relative path",
        ),
    ],
)
def test_hunt_semantic_errors(ctx, mutate, message):
    [item] = planned_hunt(ctx)
    by_class = ids_by_class(ctx, item["id"])
    result = {
        "task_id": item["id"],
        "units": [unit_result(by_class["idor"]), unit_result(by_class["sqli"])],
        "candidates": [],
        "hardening": [],
        "uncovered": [],
    }
    mutate(by_class, result)
    from kalkan.run.handlers import hunt

    with pytest.raises(ValidationError) as caught:
        hunt.handle(ctx, queue.get_task(ctx, item["id"]), result)
    assert any(message in line for line in caught.value.errors), caught.value.errors
    assert all(unit["status"] == "in_progress" for unit in load_ledger(ctx))


def test_hunt_without_validation_budget_marks_the_run_incomplete(ctx):
    [item] = planned_hunt(ctx)
    by_class = ids_by_class(ctx, item["id"])
    with state.transaction(ctx) as tx:
        tx.state["budget"]["max_agent_tasks"] = tx.state["budget"]["used_agent_tasks"]
    write_result(
        ctx,
        item["id"],
        {
            "units": [
                unit_result(by_class["sqli"], "candidate"),
                unit_result(by_class["idor"]),
            ],
            "candidates": [candidate(by_class["sqli"])],
        },
    )
    queue.complete(ctx, item["id"])
    assert not ctx.reload().get("incomplete_pending")
    assert validation.allocate_hunter_verifies(ctx)["unvalidated"] == 1
    current = ctx.reload()
    assert current["incomplete_pending"] == "validation_budget_exhausted"
    assert not [task for task in current["tasks"].values() if task["type"] == "verify"]
    sqli = next(u for u in load_ledger(ctx) if u["coverage_id"] == by_class["sqli"])
    assert sqli["unresolved"] == ["validation_budget_exhausted: sqli:app/routes.py:users"]
    assert validate_ledger_file(ctx.run_dir / "coverage-ledger.json") == []
    data = json.loads((ctx.task_dir(item["id"]) / "candidates.json").read_text())
    assert data["candidates"][0]["status"] == "unvalidated"


def test_duplicate_fingerprint_across_hunts(ctx):
    second = {**SURFACE, "id": "S002", "name": "GET /users/v2", "file": "app/v2.py"}
    surfaces = (SURFACE, {**second, "subsystem": "v2"})
    items = planned_hunt(ctx, classes=("sqli",), surfaces=surfaces)
    assert len(items) == 2
    created = []
    for item in items:
        [coverage_id] = [u["coverage_id"] for u in read_input(ctx, item["id"])["units"]]
        write_result(
            ctx,
            item["id"],
            {
                "units": [unit_result(coverage_id, "candidate")],
                "candidates": [candidate(coverage_id)],
            },
        )
        queue.complete(ctx, item["id"])
    validation.allocate_hunter_verifies(ctx)
    for item in items:
        created.append(read_candidates(ctx, item["id"])[0])
    assert created[0]["status"] == "queued"
    assert created[1]["status"] == "duplicate"
    assert created[1]["duplicate_of"] == f"{items[0]['id']}#0"
    assert created[1]["verify_task"] == created[0]["verify_task"]


def finish_wave(ctx, items, status="covered"):
    for item in items:
        units = read_input(ctx, item["id"])["units"]
        write_result(
            ctx,
            item["id"],
            {"units": [unit_result(u["coverage_id"], status) for u in units], "candidates": []},
        )
        queue.complete(ctx, item["id"])


def critic_result(task_id, missing=(), reassign=(), covered=None):
    result = {
        "task_id": task_id,
        "missing_units": list(missing),
        "reassign_ids": list(reassign),
        "stop": not missing and not reassign,
        "notes": "",
    }
    if covered is not None:
        result["covered_ids"] = list(covered)
    return result


UNRESOLVED = "Which middleware binds the id before the lookup?"


def finish_by_class(ctx, items, statuses):
    """Finish a hunt wave with one status per class (blocked units get ``UNRESOLVED``)."""
    for item in items:
        units = read_input(ctx, item["id"])["units"]
        results = []
        for unit in units:
            status = statuses[unit["class"]]
            unresolved = [UNRESOLVED] if status == "blocked" else []
            results.append(unit_result(unit["coverage_id"], status, unresolved))
        write_result(ctx, item["id"], {"units": results, "candidates": []})
        queue.complete(ctx, item["id"])


def run_critic(ctx, result):
    task_id = result["task_id"]
    (ctx.task_dir(task_id) / "result.json").write_text(json.dumps(result), encoding="utf-8")
    queue.claim(ctx, "tester", 5)
    queue.complete(ctx, task_id)
    assert ctx.reload()["tasks"][task_id]["status"] == "done"
    return json.loads((ctx.task_dir(task_id) / "critic.json").read_text())


def closure(coverage_id, covered_by, file="app/routes.py", line=14, quote=SINK):
    return {
        "coverage_id": coverage_id,
        "covered_by": list(covered_by),
        "reason": "The sqli unit read the lookup: it binds the id as a parameter.",
        "evidence": [{"file": file, "line": line, "quote": quote}],
    }


def critic_task(ctx):
    return next(t for t, task in ctx.state["tasks"].items() if task["type"] == "critic")


def unit_ids(ctx):
    return {unit["attack_class"]: unit["coverage_id"] for unit in load_ledger(ctx)}


def ledger_unit(ctx, coverage_id):
    return next(unit for unit in load_ledger(ctx) if unit["coverage_id"] == coverage_id)


def test_critic_adds_units_reassigns_and_schedules_the_next_wave(ctx):
    items = planned_hunt(ctx)
    finish_wave(ctx, items)
    assert plan.hunt_idle(ctx) is True
    critic = [t for t, task in ctx.state["tasks"].items() if task["type"] == "critic"]
    assert len(critic) == 1
    critic_id = critic[0]
    assert read_input(ctx, critic_id)["wave"] == 1
    sqli_id = ids_by_class(ctx, items[0]["id"])["sqli"]
    result = critic_result(
        critic_id,
        missing=[
            {
                "surface_id": "S001",
                "class": "ssrf",
                "reason": "Outbound URL.",
                "starting_paths": ["app/routes.py"],
            },
            {"surface_id": "x", "class": "ssrf", "reason": "No path.", "starting_paths": ["/x"]},
        ],
        reassign=[
            {"coverage_id": sqli_id, "reason": "The check missed the admin route."},
            {"coverage_id": "unknown", "reason": "Ignored."},
        ],
    )
    (ctx.task_dir(critic_id) / "result.json").write_text(json.dumps(result), encoding="utf-8")
    queue.claim(ctx, "tester", 5)
    queue.complete(ctx, critic_id)
    assert validate_ledger_file(ctx.run_dir / "coverage-ledger.json") == []
    ledger = {unit["coverage_id"]: unit for unit in load_ledger(ctx)}
    sqli = ledger[sqli_id]
    assert sqli["status"] == "in_progress" and sqli["wave"] == 2
    assert sqli["attempts"][0]["agent_id"] == items[0]["id"].lower()
    assert sqli["attempts"][0]["reassignment_reason"] == "The check missed the admin route."
    wave2 = [
        task_id
        for task_id, task in ctx.reload()["tasks"].items()
        if task["type"] == "hunt" and task["meta"]["wave"] == 2
    ]
    assert len(wave2) == 1
    assert sqli["agent_id"] == wave2[0].lower()
    summary = json.loads((ctx.task_dir(critic_id) / "critic.json").read_text())
    assert summary["outcome"] == "next_wave" and len(summary["added_units"]) == 1

    # Repeating the handler archives nothing twice and creates no new task.
    count = len(ctx.state["tasks"])
    from kalkan.run.handlers import critic

    critic.handle(ctx, queue.get_task(ctx, critic_id), result)
    assert len(ctx.reload()["tasks"]) == count
    assert len(next(u for u in load_ledger(ctx) if u["coverage_id"] == sqli_id)["attempts"]) == 1


def test_critic_closes_a_blocked_unit_that_a_sibling_covered(ctx):
    items = planned_hunt(ctx)
    finish_by_class(ctx, items, {"sqli": "covered", "idor": "blocked"})
    assert plan.hunt_idle(ctx) is True
    critic_id = critic_task(ctx)
    found = unit_ids(ctx)
    sqli_id, idor_id = found["sqli"], found["idor"]
    hunter = ledger_unit(ctx, idor_id)["agent_id"]
    entry = closure(idor_id, [sqli_id], file="./app/routes.py")
    result = critic_result(critic_id, covered=[entry])
    summary = run_critic(ctx, result)
    assert summary["closed_units"] == [idor_id]
    [record] = summary["closures"]
    assert record["accepted"] is True and record["dropped"] is None
    assert record["evidence"][0]["file"] == "app/routes.py"
    assert record["evidence"][0]["quote_status"] == "verified"
    assert validate_ledger_file(ctx.run_dir / "coverage-ledger.json") == []
    idor = ledger_unit(ctx, idor_id)
    assert idor["status"] == "covered" and idor["unresolved"] == []
    assert idor["agent_id"] == hunter  # the hunter stays the owner
    assert [check["agent_id"] for check in idor["local_checks"]] == [hunter, critic_id.lower()]
    critic_check = idor["local_checks"][1]
    assert critic_check["reviewed_paths"] == ["app/routes.py"]
    assert sqli_id in critic_check["invariant"] and UNRESOLVED in critic_check["invariant"]
    assert idor["kalkan"]["closure"] == {
        "task": critic_id,
        "covered_by": [sqli_id],
        "unresolved": [UNRESOLVED],
        "reason": entry["reason"],
        "evidence": [{"file": "app/routes.py", "line": 14, "quote": SINK}],
    }
    # No open unit is left, so no wave 2 hunt task exists.
    assert not any(t["meta"].get("wave") == 2 for t in ctx.reload()["tasks"].values())

    # A repeated handler run keeps the closure and adds no second check.
    from kalkan.run.handlers import critic

    critic.handle(ctx, queue.get_task(ctx, critic_id), result)
    again = json.loads((ctx.task_dir(critic_id) / "critic.json").read_text())
    assert again["closed_units"] == [idor_id]
    assert len(ledger_unit(ctx, idor_id)["local_checks"]) == 2
    assert validate_ledger_file(ctx.run_dir / "coverage-ledger.json") == []


def test_critic_closure_drops_every_entry_the_engine_cannot_check(ctx):
    classes = ("sqli", "idor", "xss", "ssrf", "csrf", "xxe")
    items = planned_hunt(ctx, classes=classes)
    statuses = dict.fromkeys(classes, "blocked")
    statuses["sqli"] = "covered"
    finish_by_class(ctx, items, statuses)
    assert plan.hunt_idle(ctx) is True
    critic_id = critic_task(ctx)
    found = unit_ids(ctx)
    sqli = [found["sqli"]]
    result = critic_result(
        critic_id,
        reassign=[{"coverage_id": found["xxe"], "reason": "The parser was not read."}],
        covered=[
            closure(found["idor"], sqli),
            closure(found["idor"], sqli),
            closure("unknown", sqli),
            closure(found["sqli"], [found["idor"]]),
            closure(found["xss"], [found["idor"]]),  # idor closes in this same result
            closure(found["ssrf"], sqli, file="Dockerfile", line=1, quote="FROM python"),
            closure(found["csrf"], sqli, quote='conn.execute("DROP TABLE users")'),
            closure(found["xxe"], sqli),
        ],
    )
    summary = run_critic(ctx, result)
    from kalkan.run.handlers import critic

    assert [record["dropped"] for record in summary["closures"]] == [
        None,
        critic.DROPPED_DUPLICATE,
        critic.DROPPED_UNKNOWN,
        critic.DROPPED_NOT_BLOCKED,
        critic.DROPPED_SIBLING,
        critic.DROPPED_OUTSIDE_SIBLINGS,
        critic.DROPPED_UNVERIFIED,
        critic.DROPPED_REASSIGNED,
    ]
    assert summary["closed_units"] == [found["idor"]]
    assert summary["reassigned_units"] == [found["xxe"]]
    outside = summary["closures"][5]["evidence"][0]
    assert outside["quote_status"] == "verified" and outside["in_sibling_paths"] is False
    assert summary["closures"][6]["evidence"][0]["quote_status"] == "unverified"
    ledger = {unit["attack_class"]: unit for unit in load_ledger(ctx)}
    assert [ledger[slug]["status"] for slug in ("xss", "ssrf", "csrf")] == ["blocked"] * 3
    assert ledger["xxe"]["status"] == "in_progress" and ledger["xxe"]["wave"] == 2
    assert "closure" not in ledger["xxe"]["kalkan"]
    assert validate_ledger_file(ctx.run_dir / "coverage-ledger.json") == []


def test_a_reassigned_closed_unit_loses_its_closure(ctx):
    items = planned_hunt(ctx)
    finish_by_class(ctx, items, {"sqli": "covered", "idor": "blocked"})
    assert plan.hunt_idle(ctx) is True
    critic_id = critic_task(ctx)
    found = unit_ids(ctx)
    run_critic(ctx, critic_result(critic_id, covered=[closure(found["idor"], [found["sqli"]])]))
    from kalkan.run.ledger_store import archive_attempt, ledger_transaction

    with ledger_transaction(ctx) as (_, units):
        idor = next(unit for unit in units if unit["coverage_id"] == found["idor"])
        assert archive_attempt(idor, "The role check needs a second look.", 2)
    idor = ledger_unit(ctx, found["idor"])
    assert idor["status"] == "planned" and "closure" not in idor["kalkan"]
    attempt = idor["attempts"][0]
    assert attempt["status"] == "covered"
    assert attempt["local_checks"][1]["agent_id"] == critic_id.lower()
    assert validate_ledger_file(ctx.run_dir / "coverage-ledger.json") == []


def test_closures_never_chain_across_critics(ctx):
    items = planned_hunt(ctx, classes=("sqli", "idor", "xss"))
    finish_by_class(ctx, items, {"sqli": "covered", "idor": "blocked", "xss": "blocked"})
    assert plan.hunt_idle(ctx) is True
    found = unit_ids(ctx)
    entry = closure(found["idor"], [found["sqli"]])
    run_critic(ctx, critic_result(critic_task(ctx), covered=[entry]))
    from kalkan.run.handlers import critic
    from kalkan.run.inputs import critic_input
    from kalkan.run.ledger_store import ledger_transaction

    flags = {
        unit["class"]: unit["closed_from_siblings"]
        for unit in critic_input(ctx, load_ledger(ctx), 2)["ledger"]
    }
    assert flags == {"sqli": False, "idor": True, "xss": False}
    with ledger_transaction(ctx) as (_, units):
        [record] = critic.close_units(
            ctx, "T0099-critic", units, [closure(found["xss"], [found["idor"]])], set()
        )
    assert record["dropped"] == critic.DROPPED_SIBLING
    assert ledger_unit(ctx, found["xss"])["status"] == "blocked"


def test_a_reapplied_hunt_result_replaces_the_closure(ctx):
    items = planned_hunt(ctx)
    finish_by_class(ctx, items, {"sqli": "covered", "idor": "blocked"})
    assert plan.hunt_idle(ctx) is True
    critic_id = critic_task(ctx)
    found = unit_ids(ctx)
    result = critic_result(critic_id, covered=[closure(found["idor"], [found["sqli"]])])
    run_critic(ctx, result)
    owner = ledger_unit(ctx, found["idor"])["agent_id"]
    hunt_id = next(item["id"] for item in items if item["id"].lower() == owner)
    from kalkan.run.handlers import critic, hunt

    hunt_result = json.loads((ctx.task_dir(hunt_id) / "result.json").read_text(encoding="utf-8"))
    hunt.handle(ctx, queue.get_task(ctx, hunt_id), hunt_result)
    idor = ledger_unit(ctx, found["idor"])
    assert idor["status"] == "blocked" and "closure" not in idor["kalkan"]
    assert [check["agent_id"] for check in idor["local_checks"]] == [owner]
    # The same critic closes the unit again from its checks, not from the stale record.
    critic.handle(ctx, queue.get_task(ctx, critic_id), result)
    idor = ledger_unit(ctx, found["idor"])
    assert idor["status"] == "covered" and len(idor["local_checks"]) == 2
    assert validate_ledger_file(ctx.run_dir / "coverage-ledger.json") == []


def test_fast_profile_closes_blocked_units_in_the_final_critic(tmp_path, monkeypatch):
    monkeypatch.setenv(ids.RUNS_DIR_ENV, str(tmp_path / "runs"))
    monkeypatch.setattr(init_mod, "git_head", lambda directory: None)
    target = tmp_path / "webapp"
    shutil.copytree(TARGETS / "webapp", target)
    ctx = init_run(str(target), profile="fast", runs_dir=tmp_path / "runs")
    items = planned_hunt(ctx)
    finish_by_class(ctx, items, {"sqli": "covered", "idor": "blocked"})
    assert plan.hunt_idle(ctx) is True
    found = unit_ids(ctx)
    entry = closure(found["idor"], [found["sqli"]])
    summary = run_critic(ctx, critic_result(critic_task(ctx), covered=[entry]))
    assert summary["closed_units"] == [found["idor"]]
    assert summary["outcome"] == "deferred:fast_profile_final_critic"
    assert {unit["status"] for unit in load_ledger(ctx)} == {"covered"}
    assert validate_ledger_file(ctx.run_dir / "coverage-ledger.json") == []


def test_fast_profile_defers_the_final_critic_work(tmp_path, monkeypatch):
    monkeypatch.setenv(ids.RUNS_DIR_ENV, str(tmp_path / "runs"))
    monkeypatch.setattr(init_mod, "git_head", lambda directory: None)
    target = tmp_path / "webapp"
    shutil.copytree(TARGETS / "webapp", target)
    ctx = init_run(str(target), profile="fast", runs_dir=tmp_path / "runs")
    items = planned_hunt(ctx)
    units = load_ledger(ctx)
    assert {unit["subsystem"] for unit in units} == {"profile/quick/all-in-scope-subsystems"}
    finish_wave(ctx, items)
    assert plan.hunt_idle(ctx) is True
    critic_id = next(t for t, task in ctx.state["tasks"].items() if task["type"] == "critic")
    covered = units[0]["coverage_id"]
    result = critic_result(
        critic_id,
        missing=[
            {"surface_id": "S001", "class": "xss", "reason": "Template.", "starting_paths": ["app"]}
        ],
        reassign=[{"coverage_id": covered, "reason": "Too shallow."}],
    )
    (ctx.task_dir(critic_id) / "result.json").write_text(json.dumps(result), encoding="utf-8")
    queue.claim(ctx, "tester", 5)
    queue.complete(ctx, critic_id)
    ledger = {unit["coverage_id"]: unit for unit in load_ledger(ctx)}
    assert ledger[covered]["status"] == "deferred"
    assert ledger[covered]["unresolved"] == ["fast_profile_final_critic"]
    assert len(ledger[covered]["attempts"]) == 1
    assert [u["status"] for u in ledger.values() if u["attack_class"] == "xss"] == ["deferred"]
    assert not any(t["meta"].get("wave") == 2 for t in ctx.reload()["tasks"].values())
    assert plan.hunt_idle(ctx) is False
    assert validate_ledger_file(ctx.run_dir / "coverage-ledger.json") == []


def test_dead_hunt_units_return_to_planned_and_then_deferred(ctx):
    items = planned_hunt(ctx)
    for item in items:
        for _ in range(3):
            queue.fail(ctx, item["id"], "agent crashed")
            queue.claim(ctx, "tester", 5)
    assert all(ctx.reload()["tasks"][i["id"]]["status"] == "dead" for i in items)
    with state.transaction(ctx) as tx:
        tx.state["budget"]["max_agent_tasks"] = tx.state["budget"]["used_agent_tasks"]
    assert plan.hunt_idle(ctx) is False
    statuses = {unit["status"] for unit in load_ledger(ctx)}
    assert statuses == {"deferred"}
    assert {u["unresolved"][0] for u in load_ledger(ctx)} == {"critic_budget_exhausted"}
    assert ctx.reload()["incomplete_pending"] == "critic_budget_exhausted"
