# SPDX-License-Identifier: MIT
"""Tests for the final review: the review handler (kalkan.run.handlers.review), the rules of
kalkan.findings.review (apply_review, lower_severity), the step ``review:tasks``
(kalkan.run.review), the phase flow and the merge of review outcomes."""

from __future__ import annotations

import copy
import json
import shutil
from pathlib import Path

import pytest

from kalkan.errors import ValidationError
from kalkan.findings.merge import merge_run
from kalkan.findings.review import CHECKLISTS, apply_review, lower_severity, review_record
from kalkan.findings.validate import validate_findings
from kalkan.run import budget, ids, phases, queue, state, steps
from kalkan.run import init as init_mod
from kalkan.run.handlers import review, verify
from kalkan.run.init import init_run
from kalkan.run.review import REASON_REVIEW, create_review_tasks, rejected_verify_tasks

TARGETS = Path(__file__).resolve().parents[1] / "fixtures" / "targets"
SAMPLES = Path(__file__).resolve().parents[1] / "fixtures" / "task-results"
ROUTES = "app/routes.py"
QUOTES = {
    "attacker_control": (12, 'user_id = request.args.get("id")'),
    "privilege_boundary": (10, '@app.route("/users")'),
    "unmitigated": (14, 'conn.execute("SELECT name FROM users WHERE id = ?"'),
}
BINDING = (14, "(user_id,)")
PLAN = "Request /users?id=2 as user 1 with a test database."


@pytest.fixture
def ctx(tmp_path, monkeypatch):
    monkeypatch.setenv(ids.RUNS_DIR_ENV, str(tmp_path / "runs"))
    monkeypatch.setattr(init_mod, "git_head", lambda directory: None)
    target = tmp_path / "webapp"
    shutil.copytree(TARGETS / "webapp", target)
    run = init_run(str(target), runs_dir=tmp_path / "runs", profile="standard")
    with state.transaction(run) as tx:
        tx.state["phase"] = "validate"
    return run


def answers(second="established"):
    result = {}
    for question, (line, quote) in QUOTES.items():
        status = second if question == "privilege_boundary" else "established"
        evidence = [] if status == "unknown" else [{"file": ROUTES, "line": line, "quote": quote}]
        result[question] = {"status": status, "reason": f"{question}.", "evidence": evidence}
    return result


def verify_finding(confirmed=True, scope="users", line=14):
    finding = {
        "title": "SQL injection in user lookup",
        "description": "The id parameter reaches the query.",
        "class": "sqli",
        "cwe": ["CWE-89"],
        "root_cause": "The handler builds the query from the parameter.",
        "trace": [
            {"kind": "entrypoint", "file": ROUTES, "line": 12, "scope": scope, "description": "x"},
            {"kind": "sink", "file": ROUTES, "line": line, "scope": scope, "description": "y"},
        ],
        "evidence": [{"file": ROUTES, "line": 14, "description": "The query call."}],
        "blockers": ["Whether a gateway checks the id is not visible."],
        "validation_plan": {"local": PLAN},
        "reason": "Answered from the quoted lines.",
    }
    if confirmed:
        finding.update(
            intended_behavior="Only bound parameters reach the query.",
            conditions=[{"kind": "network_routing", "description": "The route is public."}],
            execution={
                "attacker_perspective": "An anonymous client.",
                "payloads": ["1 OR 1=1"],
                "instructions": ["Send the request."],
                "observed_result": "The payload reaches the query.",
            },
            remediation={"strategy": "Bind the parameter."},
            severity={
                "likelihood": {"score": "high", "reason": "Public route."},
                "impact": {"score": "high", "reason": "Reads every user."},
                "overall_severity": "high",
            },
            confidence={"score": "high", "reason": "Clear."},
        )
    return finding


def make_verified(
    ctx, confirmed=True, ref="T0001-hunt#0", scope="users", line=14, impact="high", refuted=False
):
    """Create a done verify task with its finding and return the task ID."""
    subject = {"kind": "hunter", "ref": ref}
    task_id = queue.create_task(
        ctx,
        "verify",
        "validate",
        {"subject": subject, "claim": {"class": "sqli", "trace": [], "evidence": []}},
        meta={"subject": ref},
    )
    result = {
        "task_id": task_id,
        "subject": subject,
        "audit_answers": answers(
            "refuted" if refuted else "established" if confirmed else "unknown"
        ),
        "finding": verify_finding(confirmed, scope, line),
        "duplicate_of": None,
    }
    if confirmed:
        result["finding"]["severity"]["impact"]["score"] = impact
        result["finding"]["severity"]["overall_severity"] = impact
    (ctx.task_dir(task_id) / "result.json").write_text(json.dumps(result), encoding="utf-8")
    verify.handle(ctx, queue.get_task(ctx, task_id), result)
    with state.transaction(ctx) as tx:
        tx.state["tasks"][task_id]["status"] = "done"
    return task_id


def review_task(ctx, confirmed=True):
    make_verified(ctx, confirmed)
    assert create_review_tasks(ctx)["created"] == 1
    task_id = next(t for t, task in ctx.reload()["tasks"].items() if task["type"] == "review")
    return task_id, queue.get_task(ctx, task_id)


def record_of(ctx, task_id):
    data = json.loads((ctx.task_dir(task_id) / "input.json").read_text(encoding="utf-8"))
    return data["finding"]


def result_for(task, decision="verified", failed=(), evidence=(), **extra):
    verdict = task["meta"]["verdict"]
    result = {
        "task_id": task["id"],
        "finding_id": task["meta"]["finding"],
        "decision": decision,
        "reason": "The review found the decisive fact.",
        "checks": [
            {"item": item, "ok": item not in failed, "note": f"Read {ROUTES} for {item}."}
            for item in CHECKLISTS[verdict]
        ],
        "evidence": [{"file": ROUTES, "line": line, "quote": quote} for line, quote in evidence],
    }
    result.update(extra)
    return result


def run_review(ctx, task, result):
    review.handle(ctx, task, result)
    outcome = json.loads((ctx.task_dir(task["id"]) / "review.json").read_text(encoding="utf-8"))
    reviewed = apply_review(record_of(ctx, task["id"]), outcome)
    assert validate_findings([reviewed]) == []
    return outcome, reviewed


LOWER = {
    "likelihood": {"score": "high", "reason": "Public route."},
    "impact": {"score": "medium", "reason": "Only names leak."},
    "overall_severity": "high",
}
HIGHER = {
    "likelihood": {"score": "critical", "reason": "Trivial."},
    "impact": {"score": "critical", "reason": "Everything."},
    "overall_severity": "critical",
}


# ---------------------------------------------------------------------------------------------
# The input


def test_the_reviewer_sees_only_the_canonical_record(ctx):
    task_id, task = review_task(ctx)
    data = json.loads((ctx.task_dir(task_id) / "input.json").read_text(encoding="utf-8"))
    assert data["subject"]["verdict"] == "confirmed"
    assert data["checklist"] == list(CHECKLISTS["confirmed"])
    record = data["finding"]
    for hidden in ("audit_answers", "engines", "candidates", "owasp"):
        assert hidden not in record
    assert record["id"] == task["meta"]["finding"]
    prompt = (ctx.task_dir(task_id) / "prompt.md").read_text(encoding="utf-8")
    assert "## Task: final review of one record" in prompt
    assert "audit_answers" not in prompt.split("### Result schema")[0]
    assert "conn.execute" in prompt  # the source excerpt
    assert "#### Methodology" in prompt and "#### Class: sqli" in prompt
    assert "Answered from the quoted lines." not in prompt  # no verifier reasoning


# ---------------------------------------------------------------------------------------------
# Decisions on a confirmed record


def test_verified_adds_the_reviewer_and_keeps_confidence_medium(ctx):
    _, task = review_task(ctx)
    outcome, reviewed = run_review(ctx, task, result_for(task, evidence=[QUOTES["unmitigated"]]))
    assert outcome["decision"] == outcome["requested"] == "verified"
    assert outcome["verdict_after"] == "confirmed"
    assert outcome["verified_quotes"] == 1
    assert reviewed["verdict"] == "confirmed"
    assert "reviewer" in reviewed["engines"]
    assert reviewed["confidence"]["score"] == "medium"
    assert reviewed["review"] == {"decision": "verified", "reason": outcome["reason"]}


def test_verified_with_a_failed_check_fails_the_attempt(ctx):
    _, task = review_task(ctx)
    with pytest.raises(ValidationError, match="says verified") as caught:
        review.handle(ctx, task, result_for(task, failed=("impact",)))
    assert "impact is not ok" in caught.value.errors[0]
    # A failed severity check needs the corrected severity.
    with pytest.raises(ValidationError):
        review.handle(ctx, task, result_for(task, failed=("severity",)))
    outcome, reviewed = run_review(
        ctx, task, result_for(task, failed=("severity",), severity=copy.deepcopy(LOWER))
    )
    assert outcome["decision"] == "verified"
    assert reviewed["severity"]["impact"]["score"] == "medium"
    assert reviewed["severity"]["overall_severity"] == "medium"  # never above the impact


def test_downgrade_with_a_lower_severity_keeps_the_record_confirmed(ctx):
    _, task = review_task(ctx)
    remediation = {
        "strategy": "Bind the parameter and validate the id as an integer.",
        "code_changes": [
            {"file_name": "./app/routes.py", "fixed_code": "x"},
            {"file_name": "../escape.py", "fixed_code": "y"},
        ],
    }
    outcome, reviewed = run_review(
        ctx,
        task,
        result_for(
            task,
            "downgrade",
            failed=("severity",),
            severity=copy.deepcopy(LOWER),
            remediation=remediation,
        ),
    )
    assert outcome["verdict_after"] == "confirmed"
    assert reviewed["severity"]["likelihood"]["score"] == "high"
    assert reviewed["severity"]["impact"] == LOWER["impact"]
    assert reviewed["severity"]["overall_severity"] == "medium"
    assert reviewed["remediation"]["code_changes"] == [{"file_name": ROUTES, "fixed_code": "x"}]
    assert "remediation code change without a safe file name dropped" in outcome["normalized"]
    assert "reviewer" not in reviewed.get("engines", [])
    assert reviewed["review"]["decision"] == "downgrade"


def test_downgrade_never_raises_the_severity(ctx):
    _, task = review_task(ctx)
    outcome, reviewed = run_review(
        ctx, task, result_for(task, "downgrade", severity=copy.deepcopy(HIGHER))
    )
    # The higher severity lowers nothing: the record becomes needs_validation instead.
    assert outcome["severity"] is None
    assert reviewed["verdict"] == "needs_validation"
    assert "severity" not in reviewed


def test_downgrade_without_severity_makes_needs_validation(ctx):
    _, task = review_task(ctx)
    outcome, reviewed = run_review(ctx, task, result_for(task, "downgrade"))
    assert outcome["verdict_after"] == "needs_validation"
    assert reviewed["blockers"] == [outcome["reason"]]
    assert reviewed["validation_plan"] == {"local": PLAN}  # the verifier's plan
    assert reviewed["claimed_root_cause"] == "The handler builds the query from the parameter."
    for gone in ("root_cause", "severity", "confidence", "execution", "remediation"):
        assert gone not in reviewed


def test_reject_with_a_verified_quote_rejects_the_record(ctx):
    _, task = review_task(ctx)
    outcome, reviewed = run_review(ctx, task, result_for(task, "reject", evidence=[BINDING]))
    assert outcome["decision"] == "reject" and outcome["verdict_after"] == "rejected"
    assert reviewed["verdict"] == "rejected"
    assert reviewed["reason"] == outcome["reason"]
    assert reviewed["claimed_root_cause"]
    assert outcome["evidence"][0]["quote_status"] == "verified"


def test_reject_without_a_verified_quote_is_a_downgrade(ctx):
    _, task = review_task(ctx)
    outcome, reviewed = run_review(
        ctx, task, result_for(task, "reject", evidence=[(14, "parameterized query helper")])
    )
    assert outcome["requested"] == "reject"
    assert outcome["decision"] == "downgrade"
    assert outcome["evidence"][0]["quote_status"] == "unverified"
    assert reviewed["verdict"] == "needs_validation"
    assert reviewed["blockers"] == [outcome["reason"], review.UNGROUNDED_REJECTION]


# ---------------------------------------------------------------------------------------------
# Decisions on a needs_validation record


def test_needs_validation_downgrade_adds_a_blocker(ctx):
    _, task = review_task(ctx, confirmed=False)
    assert task["meta"]["verdict"] == "needs_validation"
    outcome, reviewed = run_review(
        ctx,
        task,
        result_for(task, "downgrade", failed=("blockers",), severity=copy.deepcopy(LOWER)),
    )
    assert reviewed["verdict"] == "needs_validation"
    assert reviewed["blockers"][-1] == outcome["reason"]
    assert len(reviewed["blockers"]) >= 2
    assert "severity" not in reviewed
    assert any("takes no severity" in note for note in outcome["normalized"])


def test_needs_validation_verified_and_reject(ctx):
    _, task = review_task(ctx, confirmed=False)
    _, reviewed = run_review(ctx, task, result_for(task))
    assert reviewed["verdict"] == "needs_validation" and "reviewer" in reviewed["engines"]
    _, rejected = run_review(ctx, task, result_for(task, "reject", evidence=[BINDING]))
    assert rejected["verdict"] == "rejected"
    assert "blockers" not in rejected and "validation_plan" not in rejected


# ---------------------------------------------------------------------------------------------
# Semantic checks


def test_the_result_must_review_the_subject(ctx):
    _, task = review_task(ctx)
    result = result_for(task)
    result["finding_id"] = "KF-0000000000000000"
    with pytest.raises(ValidationError, match="another finding"):
        review.handle(ctx, task, result)


def test_the_checks_must_follow_the_checklist(ctx):
    _, task = review_task(ctx)
    result = result_for(task)
    result["checks"] = result["checks"][1:] + [
        {"item": "blockers", "ok": True, "note": "Wrong list."},
        {"item": "impact", "ok": True, "note": "Twice."},
    ]
    with pytest.raises(ValidationError, match="checklist") as caught:
        review.handle(ctx, task, result)
    assert set(caught.value.errors) == {
        "$result.checks: missing trace_and_evidence",
        "$result.checks: impact appears 2 times",
        "$result.checks: blockers is not on the confirmed checklist",
    }


def test_a_malformed_review_counts_an_attempt(ctx):
    task_id, task = review_task(ctx)
    claimed = queue.claim(ctx, "tester", 5, types=["review"])
    assert [item["id"] for item in claimed] == [task_id]
    result = result_for(task, failed=("impact",))
    (ctx.task_dir(task_id) / "result.json").write_text(json.dumps(result), encoding="utf-8")
    with pytest.raises(ValidationError, match="says verified"):
        queue.complete(ctx, task_id)
    record = ctx.reload()["tasks"][task_id]
    assert record["attempts"] == 1 and record["status"] == "pending"
    assert record["error"]["details"] == [
        "$result.checks: impact is not ok; decide downgrade or reject"
    ]
    assert not (ctx.task_dir(task_id) / "review.json").exists()


# ---------------------------------------------------------------------------------------------
# kalkan.findings.review


def test_lower_severity_never_raises():
    current = {
        "likelihood": {"score": "medium", "reason": "a"},
        "impact": {"score": "high", "reason": "b"},
        "overall_severity": "high",
    }
    assert lower_severity(current, HIGHER) is None
    assert lower_severity(current, current) is None
    mixed = {
        "likelihood": {"score": "critical", "reason": "c"},
        "impact": {"score": "low", "reason": "d"},
        "overall_severity": "critical",
    }
    lowered = lower_severity(current, mixed)
    assert lowered == {
        "likelihood": current["likelihood"],
        "impact": mixed["impact"],
        "overall_severity": "low",
    }
    only_overall = {**current, "overall_severity": "medium"}
    assert lower_severity(current, only_overall)["overall_severity"] == "medium"


def test_apply_review_never_promotes_and_checks_the_verdict():
    record = review_record(
        {
            "verdict": "rejected",
            "fingerprint": "sqli:a.py:f",
            "title": "t",
            "description": "d",
            "claimed_root_cause": "c",
            "trace": [
                {"kind": "sink", "file": "a.py", "line": 1, "scope": "f", "description": "x"}
            ],
            "evidence": [{"file": "a.py", "line": 1, "description": "x"}],
            "reason": "r",
        }
    )
    outcome = {"verdict_before": "rejected", "decision": "verified", "reason": "ok"}
    with pytest.raises(ValueError):
        apply_review(record, outcome)
    with pytest.raises(ValueError, match="cannot apply"):
        apply_review({**record, "verdict": "confirmed"}, {**outcome, "verdict_before": "x"})


# ---------------------------------------------------------------------------------------------
# The step review:tasks and the phase flow


def review_tasks(ctx):
    return [
        (task_id, queue.get_task(ctx, task_id))
        for task_id, task in ctx.reload()["tasks"].items()
        if task["type"] == "review"
    ]


def test_standard_runs_the_review_step_and_its_tasks(ctx):
    make_verified(ctx)
    action = phases.next_action(ctx, "orchestrator")
    assert action == {"kind": "engine_step", "phase": "validate", "step": budget.REVIEW_STEP}
    outcome = steps.run_step(ctx)
    assert outcome["status"] == "done"
    assert outcome["detail"] == "1 review tasks for 1 records"
    action = phases.next_action(ctx, "orchestrator")
    assert action["kind"] == "agent_tasks" and action["phase"] == "validate"
    [item] = action["tasks"]
    assert item["type"] == "review" and item["agent"] == "kalkan-reviewer"
    task = queue.get_task(ctx, item["id"])
    Path(item["result_file"]).write_text(json.dumps(result_for(task)), encoding="utf-8")
    assert queue.complete(ctx, item["id"])["status"] == "done"
    action = phases.next_action(ctx, "orchestrator")
    assert action == {"kind": "engine_step", "phase": "validate", "step": "consolidate"}
    assert steps.run_step(ctx)["detail"] == "no candidate group (1 records)"
    run_polish_step(ctx)
    action = phases.next_action(ctx, "orchestrator")
    assert action == {"kind": "engine_step", "phase": "poc", "step": "poc:skip"}
    # The unused review reserve is free again for the PoC phase.
    assert budget.review_reserve_left(ctx.reload()) == 0


def run_polish_step(ctx):
    """Run the last validate step (Turkish letters) and settle its tasks without an agent: the
    English sample texts have no Turkish letters, so the step selects them."""
    action = phases.next_action(ctx, "orchestrator")
    assert action == {"kind": "engine_step", "phase": "validate", "step": budget.POLISH_STEP}
    assert steps.run_step(ctx)["status"] == "done"
    with state.transaction(ctx) as tx:
        for task in tx.state["tasks"].values():
            if task["type"] == "polish":
                task["status"] = "skipped"


def test_quick_skips_the_review(tmp_path, monkeypatch):
    monkeypatch.setenv(ids.RUNS_DIR_ENV, str(tmp_path / "runs"))
    monkeypatch.setattr(init_mod, "git_head", lambda directory: None)
    target = tmp_path / "webapp"
    shutil.copytree(TARGETS / "webapp", target)
    run = init_run(str(target), runs_dir=tmp_path / "runs", profile="fast")
    with state.transaction(run) as tx:
        tx.state["phase"] = "validate"
    make_verified(run)
    action = phases.next_action(run, "orchestrator")
    # Quick has no review step: the consolidate step follows the verify tasks directly.
    assert action == {"kind": "engine_step", "phase": "validate", "step": "consolidate"}
    assert steps.run_step(run)["status"] == "done"
    run_polish_step(run)
    action = phases.next_action(run, "orchestrator")
    assert action == {"kind": "engine_step", "phase": "poc", "step": "poc:skip"}
    record = run.reload()["phases"]["validate"]["steps"][budget.REVIEW_STEP]
    assert record["status"] == "skipped"
    assert record["detail"].startswith("fast profile")
    assert review_tasks(run) == []


def test_review_tasks_follow_verdict_and_severity_within_the_budget(ctx):
    low = make_verified(ctx, ref="T0001-hunt#0", scope="a", line=13, impact="low")
    high = make_verified(ctx, ref="T0001-hunt#1", scope="b", line=14, impact="high")
    pending = make_verified(ctx, confirmed=False, ref="T0001-hunt#2", scope="c", line=15)
    make_verified(ctx, confirmed=False, refuted=True, ref="T0001-hunt#3", scope="d", line=12)
    with state.transaction(ctx) as tx:
        tx.state["budget"]["used_agent_tasks"] = tx.state["budget"]["max_agent_tasks"] - 1
    summary = create_review_tasks(ctx)
    assert summary == {
        "records": 3,  # the rejected record gets no review
        "created": 1,
        "reused": 0,
        "unfunded_confirmed": 1,
        "unfunded_needs_validation": 1,
    }
    [(_, task)] = review_tasks(ctx)
    assert task["meta"]["verify_tasks"] == [high]
    assert task["priority"] == 70
    assert ctx.reload()["incomplete_pending"] == REASON_REVIEW
    with state.transaction(ctx) as tx:
        tx.state["budget"]["used_agent_tasks"] = 0
    again = create_review_tasks(ctx)
    assert (again["created"], again["reused"]) == (2, 1)
    order = [task["meta"]["verify_tasks"] for _, task in review_tasks(ctx)]
    assert order == [[high], [low], [pending]]
    assert [task["priority"] for _, task in review_tasks(ctx)] == [70, 70, 50]


def test_one_review_task_per_final_record(ctx):
    first = make_verified(ctx, ref="T0001-hunt#0")
    second = make_verified(ctx, ref="T0001-hunt#1")  # the same fingerprint and ID
    assert create_review_tasks(ctx)["created"] == 1
    [(_, task)] = review_tasks(ctx)
    assert task["meta"]["verify_tasks"] == [first, second]
    again = create_review_tasks(ctx)
    assert (again["created"], again["reused"]) == (0, 1)


def test_merge_applies_reviews_and_the_poc_skips_rejected_records(ctx):
    kept = make_verified(ctx, ref="T0001-hunt#0", scope="a", line=13)
    gone = make_verified(ctx, ref="T0001-hunt#1", scope="b", line=14)
    create_review_tasks(ctx)
    for task_id, task in review_tasks(ctx):
        decision = "verified" if task["meta"]["verify_tasks"] == [kept] else "reject"
        evidence = [BINDING] if decision == "reject" else []
        result = result_for(task, decision, evidence=evidence)
        (ctx.task_dir(task_id) / "result.json").write_text(json.dumps(result), encoding="utf-8")
        assert queue.complete(ctx, task_id)["status"] == "done"
    assert rejected_verify_tasks(ctx) == {gone}
    assert [task_id for task_id, _ in steps.code_findings(ctx)] == [kept]
    summary = merge_run(ctx.run_dir)
    assert summary["reviews"] == {"applied": 2, "verified": 1, "downgrade": 0, "reject": 1}
    assert summary["warnings"] == []
    findings = json.loads((ctx.run_dir / "findings.json").read_text(encoding="utf-8"))
    by_verdict = {finding["verdict"]: finding for finding in findings}
    assert set(by_verdict) == {"confirmed", "rejected"}
    assert "reviewer" in by_verdict["confirmed"]["engines"]
    assert by_verdict["confirmed"]["review"]["decision"] == "verified"
    assert by_verdict["rejected"]["review"]["decision"] == "reject"
    assert by_verdict["rejected"]["reason"] == by_verdict["rejected"]["review"]["reason"]
    assert by_verdict["rejected"]["audit_answers"]  # merge keeps the extensions


def test_merge_skips_an_outcome_whose_record_changed(ctx):
    task_id, task = review_task(ctx)
    result = result_for(task, "reject", evidence=[BINDING])
    (ctx.task_dir(task_id) / "result.json").write_text(json.dumps(result), encoding="utf-8")
    queue.complete(ctx, task_id)
    path = ctx.task_dir(task_id) / "review.json"
    outcome = json.loads(path.read_text(encoding="utf-8"))
    outcome["verdict_before"] = "needs_validation"
    path.write_text(json.dumps(outcome), encoding="utf-8")
    summary = merge_run(ctx.run_dir, write=False)
    assert summary["reviews"]["applied"] == 0
    assert any("review not applied" in warning for warning in summary["warnings"])


def test_merge_takes_the_most_conservative_of_several_outcomes(ctx):
    task_id, task = review_task(ctx)
    reject = result_for(task, "reject", evidence=[BINDING])
    (ctx.task_dir(task_id) / "result.json").write_text(json.dumps(reject), encoding="utf-8")
    queue.complete(ctx, task_id)
    # A second (later) review of the same record says verified: the reject still wins.
    second = queue.create_task(ctx, "review", "validate", {}, meta=dict(task["meta"]))
    outcome = json.loads((ctx.task_dir(task_id) / "review.json").read_text(encoding="utf-8"))
    outcome.update(
        task_id=second, requested="verified", decision="verified", verdict_after="confirmed"
    )
    (ctx.task_dir(second) / "review.json").write_text(json.dumps(outcome), encoding="utf-8")
    with state.transaction(ctx) as tx:
        tx.state["tasks"][second]["status"] = "done"
    summary = merge_run(ctx.run_dir, write=False)
    assert summary["reviews"] == {"applied": 1, "verified": 0, "downgrade": 0, "reject": 1}
    assert summary["inputs"]["review_files"] == 2
