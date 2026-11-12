# SPDX-License-Identifier: MIT
"""Tests for the verify handler (kalkan.run.handlers.verify)."""

from __future__ import annotations

import copy
import json
import shutil
from pathlib import Path

import pytest

from kalkan.errors import ValidationError
from kalkan.findings.validate import validate_findings
from kalkan.run import ids, queue, state
from kalkan.run import init as init_mod
from kalkan.run.handlers import verify
from kalkan.run.init import init_run

TARGETS = Path(__file__).resolve().parents[1] / "fixtures" / "targets"
QUOTES = {
    "attacker_control": (12, 'user_id = request.args.get("id")'),
    "privilege_boundary": (10, '@app.route("/users")'),
    "unmitigated": (14, 'conn.execute("SELECT name FROM users WHERE id = ?"'),
}
SUBJECT = {"kind": "hunter", "ref": "T0001-hunt#0"}


@pytest.fixture
def ctx(tmp_path, monkeypatch):
    monkeypatch.setenv(ids.RUNS_DIR_ENV, str(tmp_path / "runs"))
    monkeypatch.setattr(init_mod, "git_head", lambda directory: None)
    target = tmp_path / "webapp"
    shutil.copytree(TARGETS / "webapp", target)
    run = init_run(str(target), runs_dir=tmp_path / "runs", lang="tr")
    with state.transaction(run) as tx:
        tx.state["phase"] = "validate"
    return run


def make_task(ctx, subject=SUBJECT, claim=None, meta=None):
    data = {"subject": subject, "claim": claim or {"class": "sqli", "trace": [], "evidence": []}}
    return queue.create_task(
        ctx, "verify", "validate", data, meta=meta or {"subject": subject["ref"]}
    )


def answers(**statuses):
    result = {}
    for question, (line, quote) in QUOTES.items():
        status = statuses.get(question, "established")
        evidence = (
            [] if status == "unknown" else [{"file": "app/routes.py", "line": line, "quote": quote}]
        )
        result[question] = {
            "status": status,
            "reason": f"{question} {status}.",
            "evidence": evidence,
        }
    return result


def base_finding(**extra):
    finding = {
        "title": "SQL injection in user lookup",
        "description": "The id parameter reaches the query.",
        "class": "sqli",
        "cwe": [],
        "root_cause": "The handler builds the query from the parameter.",
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
                "line": 14,
                "scope": "users",
                "description": "Runs the query.",
            },
        ],
        "evidence": [{"file": "app/routes.py", "line": 14, "description": "The query call."}],
        "blockers": [],
        "validation_plan": {"local": "Run the query with a test database."},
        "reason": "Answered from the quoted lines.",
    }
    finding.update(extra)
    return finding


CONFIRMED_EXTRA = {
    "intended_behavior": "Only bound parameters reach the query.",
    "conditions": [],
    "execution": {
        "attacker_perspective": "An anonymous client.",
        "payloads": ["1 OR 1=1"],
        "instructions": ["Send the request."],
        "observed_result": "The payload reaches the query.",
    },
    "remediation": {"strategy": "Bind the parameter."},
    "severity": {
        "likelihood": {"score": "high", "reason": "Public route."},
        "impact": {"score": "low", "reason": "Reads names."},
        "overall_severity": "critical",
    },
    "confidence": {"score": "high", "reason": "Clear."},
}


def result_for(task_id, audit, finding, subject=SUBJECT, duplicate_of=None):
    return {
        "task_id": task_id,
        "subject": subject,
        "audit_answers": audit,
        "finding": finding,
        "duplicate_of": duplicate_of,
    }


def run_handler(ctx, task_id, result):
    verify.handle(ctx, queue.get_task(ctx, task_id), result)
    directory = ctx.task_dir(task_id)
    finding = json.loads((directory / "finding.json").read_text(encoding="utf-8"))
    record = json.loads((directory / "verdict.json").read_text(encoding="utf-8"))
    assert validate_findings([finding]) == []
    return finding, record


def test_confirmed_finding(ctx):
    task_id = make_task(ctx)
    finding, record = run_handler(
        ctx, task_id, result_for(task_id, answers(), base_finding(**CONFIRMED_EXTRA))
    )
    assert finding["verdict"] == "confirmed" and record["verdict"] == "confirmed"
    assert finding["fingerprint"] == "sqli:app/routes.py:users"
    assert finding["id"].startswith("KF-")
    assert finding["confidence"]["score"] == "medium"
    assert finding["severity"]["overall_severity"] == "low"
    assert finding["execution"]["observed_result"].startswith("Yalnızca statik analiz")
    assert finding["engines"] == ["hunter", "verifier"]
    assert finding["cwe"] == ["CWE-89"] and finding["owasp"] == ["A03:2021"]
    assert "candidates" not in finding
    for name in ("blockers", "validation_plan", "reason", "claimed_root_cause"):
        assert name not in finding
    assert finding["audit_answers"]["unmitigated"]["evidence"][0]["line"] == 14
    # The ID is stable for the same source.
    again, _ = run_handler(
        ctx, task_id, result_for(task_id, answers(), base_finding(**CONFIRMED_EXTRA))
    )
    assert again == finding


def test_established_claims_need_the_confirmed_fields(ctx):
    task_id = make_task(ctx)
    extra = dict(CONFIRMED_EXTRA)
    del extra["severity"]
    with pytest.raises(ValidationError) as caught:
        verify.handle(
            ctx, queue.get_task(ctx, task_id), result_for(task_id, answers(), base_finding(**extra))
        )
    assert caught.value.errors == ["$result.finding: missing severity"]


def test_unverified_quote_gives_needs_validation(ctx):
    task_id = make_task(ctx)
    audit = answers()
    audit["unmitigated"]["evidence"][0]["quote"] = "this text is not in the file"
    finding, record = run_handler(
        ctx, task_id, result_for(task_id, audit, base_finding(**CONFIRMED_EXTRA))
    )
    assert finding["verdict"] == "needs_validation"
    assert finding["blockers"] == ["unverified_evidence"]
    assert finding["claimed_root_cause"].startswith("The handler")
    assert finding["audit_answers"]["unmitigated"]["status"] == "unknown"
    assert record["reasons"] == {"unmitigated": "unverified_evidence"}
    for name in ("root_cause", "severity", "execution", "remediation", "reason"):
        assert name not in finding


def test_unknown_answer_uses_agent_blockers(ctx):
    task_id = make_task(ctx)
    finding, _ = run_handler(
        ctx,
        task_id,
        result_for(
            task_id,
            answers(privilege_boundary="unknown"),
            base_finding(blockers=["Gateway policy is not in the repository."]),
        ),
    )
    assert finding["verdict"] == "needs_validation"
    assert finding["blockers"] == ["Gateway policy is not in the repository."]
    assert finding["validation_plan"] == {"local": "Run the query with a test database."}


def test_unknown_without_blockers_names_the_questions(ctx):
    task_id = make_task(ctx)
    finding, _ = run_handler(
        ctx, task_id, result_for(task_id, answers(privilege_boundary="unknown"), base_finding())
    )
    assert finding["blockers"] == ["unknown:privilege_boundary"]


def test_refuted_and_ungrounded_refutation(ctx):
    task_id = make_task(ctx)
    finding, _ = run_handler(
        ctx, task_id, result_for(task_id, answers(unmitigated="refuted"), base_finding())
    )
    assert finding["verdict"] == "rejected"
    assert finding["reason"] == "Answered from the quoted lines."
    assert "blockers" not in finding and "validation_plan" not in finding

    audit = answers(unmitigated="refuted")
    audit["unmitigated"]["evidence"] = []
    finding, record = run_handler(ctx, task_id, result_for(task_id, audit, base_finding()))
    assert finding["verdict"] == "needs_validation"
    assert "ungrounded_refutation" in finding["blockers"]


def test_subject_mismatch(ctx):
    task_id = make_task(ctx)
    other = {"kind": "hunter", "ref": "T0009-hunt#3"}
    with pytest.raises(ValidationError, match="another subject"):
        verify.handle(
            ctx,
            queue.get_task(ctx, task_id),
            result_for(task_id, answers(), base_finding(), subject=other),
        )


def test_trace_kinds_are_normalized_in_the_agents_order(ctx):
    task_id = make_task(ctx)
    finding = base_finding()
    entry, sink = finding["trace"]
    # T0034: the agent labels the sink in the middle and a later step "propagation".
    finding["trace"] = [
        entry,
        dict(sink),
        {**sink, "kind": "propagation", "line": 15, "description": "Returns the rows."},
    ]
    result, record = run_handler(
        ctx, task_id, result_for(task_id, answers(privilege_boundary="unknown"), finding)
    )
    assert [step["kind"] for step in result["trace"]] == ["entrypoint", "propagation", "sink"]
    assert [step["line"] for step in result["trace"]] == [12, 14, 15]
    assert record["normalized"] == [
        "trace[1].kind: sink -> propagation",
        "trace[2].kind: propagation -> sink",
    ]
    assert result["fingerprint"] == record["computed_fingerprint"] == "sqli:app/routes.py:users"


def test_trace_normalization_keeps_one_step_traces_and_removes_new_duplicates(ctx):
    task_id = make_task(ctx)
    finding = base_finding()
    sink = finding["trace"][1]
    finding["trace"] = [{**sink, "kind": "propagation"}]
    result, record = run_handler(
        ctx, task_id, result_for(task_id, answers(privilege_boundary="unknown"), finding)
    )
    assert [step["kind"] for step in result["trace"]] == ["sink"]
    assert record["normalized"] == ["trace[0].kind: propagation -> sink"]

    # T0032: two sinks; after the new kinds two middle steps are equal and one goes.
    finding = base_finding()
    entry, sink = finding["trace"]
    middle = {**sink, "line": 13, "description": "Builds the query."}
    finding["trace"] = [entry, {**middle, "kind": "sink"}, {**middle, "kind": "propagation"}, sink]
    result, record = run_handler(
        ctx, task_id, result_for(task_id, answers(privilege_boundary="unknown"), finding)
    )
    assert [step["kind"] for step in result["trace"]] == ["entrypoint", "propagation", "sink"]
    assert "1 duplicate trace step(s) removed" in record["normalized"]


def test_a_clean_result_has_no_normalization_notes(ctx):
    task_id = make_task(ctx)
    _, record = run_handler(
        ctx, task_id, result_for(task_id, answers(privilege_boundary="unknown"), base_finding())
    )
    assert record["normalized"] == []


def test_cosmetic_slips_are_repaired_and_recorded(ctx):
    task_id = make_task(ctx)
    audit = answers()
    audit["unmitigated"]["evidence"][0]["file"] = "./app/routes.py"
    extra = copy.deepcopy(CONFIRMED_EXTRA)
    extra["execution"]["payloads"] = ["1 OR 1=1", "1 OR 1=1"]
    extra["conditions"] = [{"kind": "network_routing", "description": "Reachable."}] * 2
    extra["remediation"]["code_changes"] = [
        {"file_name": "./app/routes.py", "fixed_code": "bind(id)"},
        {"file_name": "/etc/passwd", "fixed_code": "x"},
    ]
    finding = base_finding(**extra)
    finding["trace"][0]["file"] = "./app/routes.py"
    finding["evidence"] = [dict(finding["evidence"][0]), dict(finding["evidence"][0])]
    result, record = run_handler(ctx, task_id, result_for(task_id, audit, finding))
    assert result["verdict"] == "confirmed"
    assert result["trace"][0]["file"] == "app/routes.py"
    assert result["audit_answers"]["unmitigated"]["evidence"][0]["file"] == "app/routes.py"
    assert result["execution"]["payloads"] == ["1 OR 1=1"]
    assert len(result["conditions"]) == 1 and len(result["evidence"]) == 1
    assert result["remediation"]["code_changes"] == [
        {"file_name": "app/routes.py", "fixed_code": "bind(id)"}
    ]
    notes = " | ".join(record["normalized"])
    for part in ("audit_answers.unmitigated path", "trace path", "execution.payloads"):
        assert part in notes
    assert "remediation code change without a safe file name dropped" in notes


def test_missing_validation_plan_gets_an_engine_plan(ctx):
    task_id = make_task(ctx)
    result, record = run_handler(
        ctx,
        task_id,
        result_for(
            task_id, answers(privilege_boundary="unknown"), base_finding(validation_plan={})
        ),
    )
    assert result["verdict"] == "needs_validation"
    assert "unknown:privilege_boundary" in result["validation_plan"]["local"]
    assert any("validation_plan" in note for note in record["normalized"])


def test_downgraded_claims_need_no_confirmed_fields(ctx):
    task_id = make_task(ctx)
    audit = answers()
    audit["unmitigated"]["evidence"][0]["quote"] = "this text is not in the file"
    result, _ = run_handler(ctx, task_id, result_for(task_id, audit, base_finding()))
    assert result["verdict"] == "needs_validation"
    assert result["blockers"] == ["unverified_evidence"]


def test_unsafe_trace_paths_are_still_rejected(ctx):
    task_id = make_task(ctx)
    finding = base_finding()
    finding["trace"][1]["file"] = "/srv/app/routes.py"
    with pytest.raises(ValidationError) as caught:
        verify.handle(
            ctx,
            queue.get_task(ctx, task_id),
            result_for(task_id, answers(privilege_boundary="unknown"), finding),
        )
    assert any("trace[1].file" in line for line in caught.value.errors)


def test_deterministic_subject(ctx):
    subject = {"kind": "deterministic", "ref": "CAND-0123456789ABCDEF"}
    claim = {"class": "sqli", "engine": "opengrep", "trace": [], "evidence": []}
    task_id = make_task(ctx, subject=subject, claim=claim)
    finding, _ = run_handler(
        ctx,
        task_id,
        result_for(task_id, answers(privilege_boundary="unknown"), base_finding(), subject=subject),
    )
    assert finding["engines"] == ["opengrep", "verifier"]
    assert finding["candidates"] == ["CAND-0123456789ABCDEF"]


def test_duplicate_of_takes_the_primary_fingerprint(ctx):
    primary = make_task(ctx)
    run_handler(ctx, primary, result_for(primary, answers(), base_finding(**CONFIRMED_EXTRA)))
    subject = {"kind": "hunter", "ref": "T0001-hunt#1"}
    second = make_task(ctx, subject=subject)
    finding = copy.deepcopy(base_finding())
    finding["trace"][1]["scope"] = "other_scope"
    duplicate, record = run_handler(
        ctx,
        second,
        result_for(
            second,
            answers(privilege_boundary="unknown"),
            finding,
            subject=subject,
            duplicate_of="T0001-hunt#0",
        ),
    )
    assert record["duplicate_honored"] is True
    assert duplicate["fingerprint"] == "sqli:app/routes.py:users"
    assert record["computed_fingerprint"] == "sqli:app/routes.py:other_scope"
    # A rejected record never takes another fingerprint.
    rejected, record = run_handler(
        ctx,
        second,
        result_for(
            second,
            answers(unmitigated="refuted"),
            finding,
            subject=subject,
            duplicate_of="T0001-hunt#0",
        ),
    )
    assert rejected["fingerprint"] == "sqli:app/routes.py:other_scope"
    assert record["duplicate_honored"] is False
