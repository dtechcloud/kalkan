# SPDX-License-Identifier: MIT
"""Tests for kalkan.findings.merge and the ``merge`` command (ENGINE-SPEC 15)."""

from __future__ import annotations

import copy
import json
import shutil
from pathlib import Path

import pytest

from kalkan.cli import main
from kalkan.errors import StateError
from kalkan.findings.merge import (
    BLOCKER_CONFIRMED_FIELDS_MISSING,
    BLOCKER_SANDBOX_INFEASIBLE,
    BLOCKER_SANDBOX_UNAVAILABLE,
    link_candidates,
    merge_findings,
    merge_run,
    sca_records,
    severity_of,
    target_get_lines,
)
from kalkan.findings.validate import validate_findings, validate_findings_file
from kalkan.run.state import check_state, new_phases, parse_task_id
from kalkan.util.text import utf16_key

GOLDEN_RUN = Path(__file__).resolve().parents[1] / "golden" / "report" / "run"
GOLDEN_RUN = GOLDEN_RUN / "20261015T120000Z-shop-a1b2"
RUN_ID = "20261015T120000Z-test-0001"
TS = "2026-10-15T12:00:00Z"


# ---------------------------------------------------------------------------------------------
# Builders


def trace(file="app/db.py", line=8, scope="find_user"):
    return [
        {
            "kind": "entrypoint",
            "file": "app/routes.py",
            "line": 12,
            "scope": "get_user",
            "description": "Reads id from the query string.",
        },
        {
            "kind": "sink",
            "file": file,
            "line": line,
            "scope": scope,
            "description": "Executes the formatted SQL text.",
        },
    ]


def evidence(line=8, text="The f-string puts user_id into the SQL text."):
    return [{"file": "app/db.py", "line": line, "description": text}]


CONFIRMED_EXTRA = {
    "intended_behavior": "The query binds user_id.",
    "conditions": [],
    "execution": {
        "attacker_perspective": "A logged-in user.",
        "payloads": ["1 OR 1=1"],
        "instructions": ["Send GET /users?id=1%20OR%201=1."],
        "observed_result": "Static analysis only.",
    },
    "remediation": {"strategy": "Use a bound parameter."},
    "severity": {
        "likelihood": {"score": "high", "reason": "Any user can send it."},
        "impact": {"score": "high", "reason": "Reads every row."},
        "overall_severity": "high",
    },
    "confidence": {"score": "medium", "reason": "No PoC ran yet."},
}


def confirmed(**extra):
    finding = {
        "verdict": "confirmed",
        "fingerprint": "sqli:app/db.py:find_user",
        "title": "SQL injection in user lookup",
        "description": "GET /users formats id into SQL.",
        "root_cause": "find_user builds SQL with an f-string.",
        "trace": trace(),
        "evidence": evidence(),
        **copy.deepcopy(CONFIRMED_EXTRA),
        "id": "KF-0000000000000001",
        "class": "sqli",
        "cwe": ["CWE-89"],
        "engines": ["hunter", "verifier"],
    }
    finding.update(extra)
    return finding


def needs_validation(**extra):
    finding = {
        "verdict": "needs_validation",
        "fingerprint": "sqli:app/db.py:find_user",
        "title": "Formatted SQL in find_user",
        "description": "A SQL string is built with an f-string.",
        "claimed_root_cause": "find_user builds SQL with an f-string.",
        "trace": trace(),
        "evidence": evidence(),
        "blockers": ["unverified_evidence"],
        "validation_plan": {"local": "Send the payload to a test database."},
        "id": "KF-0000000000000001",
        "class": "sqli",
        "cwe": ["CWE-89"],
        "engines": ["opengrep", "verifier"],
    }
    finding.update(extra)
    return finding


def rejected(**extra):
    finding = {
        "verdict": "rejected",
        "fingerprint": "sqli:app/db.py:find_user",
        "title": "Claimed SQL injection",
        "description": "The candidate claimed SQL injection.",
        "claimed_root_cause": "find_user was claimed to format SQL.",
        "trace": trace(),
        "evidence": evidence(),
        "reason": "The value is cast to int first.",
        "id": "KF-0000000000000001",
        "class": "sqli",
        "engines": ["critic"],
    }
    finding.update(extra)
    return finding


def candidate(cid="CAND-00000000000000A1", **extra):
    record = {
        "id": cid,
        "engine": "opengrep",
        "rule_id": "kalkan.python.sqli",
        "class": "sqli",
        "cwe": ["CWE-89"],
        "title": "SQL built with an f-string",
        "message": "f-string reaches execute",
        "file": "app/db.py",
        "start_line": 8,
        "end_line": 8,
        "snippet": "",
        "severity": "high",
        "tool_severity": "ERROR",
        "confidence": None,
        "tags": [],
        "fingerprints": {},
        "sca": None,
        "raw": {"sarif_file": "scans/opengrep.sarif", "run_index": 0, "result_index": 0},
    }
    record.update(extra)
    return record


def task_record(seq, task_type, status):
    return {
        "seq": seq,
        "type": task_type,
        "phase": {"verify": "validate", "poc_build": "poc", "translate": "report"}.get(
            task_type, task_type
        ),
        "status": status,
        "priority": 50,
        "attempts": 1,
        "max_attempts": 3,
        "lease": None,
        "created_at": TS,
        "updated_at": TS,
        "completed_at": TS if status == "done" else None,
        "result_sha256": None,
        "error": None,
        "depends_on": [],
        "counts_against_budget": True,
        "dedupe_key": None,
        "completing": None,
        "meta": {},
    }


def make_state(tasks, *, lang="tr"):
    records = {}
    for task_id, status in tasks.items():
        seq, task_type = parse_task_id(task_id)
        records[task_id] = task_record(seq, task_type, status)
    state = {
        "schema_version": 1,
        "run_id": RUN_ID,
        "created_at": TS,
        "updated_at": TS,
        "target": {"source": "C:/projects/shop", "kind": "path", "git_ref": None, "copy": "target"},
        "options": {
            "profile": "standard",
            "lang": lang,
            "max_parallel": 6,
            "allow_build_network": False,
            "docker": "auto",
        },
        "budget": {
            "max_agent_tasks": 150,
            "used_agent_tasks": len(tasks),
            "reserve_critic": 2,
            "reserve_validation_ratio": 0.3,
        },
        "phase": "merge",
        "phases": new_phases(),
        "tasks": records,
        "next_task_seq": max((parse_task_id(t)[0] for t in tasks), default=0) + 1,
        "incomplete_reason": None,
    }
    assert check_state(state) == []
    return state


def write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def make_run(root: Path, tasks: dict, *, lang="tr", candidates=None, vulns=None) -> Path:
    """``tasks`` maps a task ID to ``(status, {file name: JSON data})``."""
    run = root / RUN_ID
    shutil.copytree(GOLDEN_RUN / "target", run / "target")
    write_json(run / "state.json", make_state({k: v[0] for k, v in tasks.items()}, lang=lang))
    for task_id, (_, files) in tasks.items():
        for name, data in files.items():
            write_json(run / "tasks" / task_id / name, data)
    if candidates is not None:
        write_json(run / "candidates.json", {"schema_version": 1, "candidates": candidates})
    if vulns is not None:
        write_json(run / "sca" / "vulns.json", vulns)
    return run


def read_findings(run: Path) -> list[dict]:
    return json.loads((run / "findings.json").read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------------------------
# Merge by ID and fingerprint


def test_same_fingerprint_merges_and_keeps_the_strongest_verdict(tmp_path):
    run = make_run(
        tmp_path,
        {
            "T0001-verify": ("done", {"finding.json": needs_validation(id="KF-0000000000000002")}),
            "T0002-verify": ("done", {"finding.json": confirmed()}),
            "T0003-verify": ("done", {"finding.json": rejected(id="KF-0000000000000003")}),
        },
    )
    summary = merge_run(run)
    findings = read_findings(run)
    assert len(findings) == 1
    merged = findings[0]
    assert merged["verdict"] == "confirmed"
    assert merged["id"] == "KF-0000000000000001"
    assert merged["engines"] == ["hunter", "verifier", "opengrep", "critic"]
    assert summary["merged_duplicates"] == 2
    assert summary["by_verdict"] == {"confirmed": 1, "needs_validation": 0, "rejected": 0}
    assert summary["by_severity"]["high"] == 1


@pytest.mark.parametrize(
    ("first", "second", "winner"),
    [
        (needs_validation, rejected, "needs_validation"),
        (rejected, needs_validation, "needs_validation"),
        (rejected, confirmed, "confirmed"),
        (confirmed, needs_validation, "confirmed"),
    ],
)
def test_verdict_strength(first, second, winner):
    merged, duplicates = merge_findings([("T0001-verify", first()), ("T0002-verify", second())])
    assert duplicates == 1
    assert [item["verdict"] for item in merged] == [winner]
    assert validate_findings(merged) == []


def test_same_id_merges_even_with_different_fingerprints():
    one = needs_validation(fingerprint="sqli:a", candidates=["CAND-00000000000000A1"])
    two = needs_validation(fingerprint="sqli:b", candidates=["CAND-00000000000000B2"])
    merged, duplicates = merge_findings([("T0001-verify", one), ("T0002-verify", two)])
    assert duplicates == 1
    assert len(merged) == 1
    assert merged[0]["candidates"] == ["CAND-00000000000000A1", "CAND-00000000000000B2"]


def test_grouping_is_transitive():
    a = needs_validation(id="KF-00000000000000A1", fingerprint="fp:x")
    b = needs_validation(id="KF-00000000000000B2", fingerprint="fp:x")
    c = needs_validation(id="KF-00000000000000B2", fingerprint="fp:y")
    d = needs_validation(id="KF-00000000000000D4", fingerprint="fp:z")
    merged, duplicates = merge_findings([("T1", a), ("T2", b), ("T3", c), ("T4", d)])
    assert duplicates == 2
    assert sorted(item["fingerprint"] for item in merged) == ["fp:x", "fp:z"]


def test_richest_evidence_wins_a_tie_and_evidence_is_united():
    poor = needs_validation(engines=["hunter"])
    rich = needs_validation(
        evidence=[*evidence(), *evidence(9, "The result is returned unchanged.")],
        engines=["opengrep"],
    )
    merged, _ = merge_findings([("T0001-verify", poor), ("T0002-verify", rich)])
    record = merged[0]
    assert record["engines"] == ["opengrep", "hunter"]
    assert len(record["evidence"]) == 2


def test_evidence_of_another_verdict_is_not_added():
    base = confirmed()
    other = rejected(evidence=evidence(9, "A rejected claim."))
    merged, _ = merge_findings([("T1", base), ("T2", other)])
    assert merged[0]["evidence"] == base["evidence"]


# ---------------------------------------------------------------------------------------------
# Candidate linking


def test_link_candidates_rules():
    finding = confirmed()
    candidates = [
        candidate("CAND-00000000000000A1"),  # same class, same line
        candidate("CAND-00000000000000A2", **{"class": None}),  # null class matches
        candidate("CAND-00000000000000A3", **{"class": "xss"}),  # other class
        candidate("CAND-00000000000000A4", file="app/other.py"),  # other file
        candidate("CAND-00000000000000A5", start_line=20, end_line=25),  # no overlap
        candidate("CAND-00000000000000A6", start_line=5, end_line=9),  # range overlap
        candidate("CAND-00000000000000A7", start_line=None, end_line=None),  # no line
        candidate("CAND-00000000000000A8", engine="bandit", file="app/routes.py", start_line=12),
    ]
    linked = link_candidates([finding], candidates)
    assert linked == {
        "CAND-00000000000000A1",
        "CAND-00000000000000A2",
        "CAND-00000000000000A6",
        "CAND-00000000000000A8",
    }
    assert finding["candidates"] == sorted(linked)
    assert finding["engines"] == ["hunter", "verifier", "opengrep", "bandit"]


def test_link_uses_the_line_range_of_the_finding_in_one_file():
    finding = confirmed(
        trace=[
            {
                "kind": "entrypoint",
                "file": "app/db.py",
                "line": 4,
                "scope": "find_user",
                "description": "Entry.",
            },
            {
                "kind": "sink",
                "file": "app/db.py",
                "line": 8,
                "scope": "find_user",
                "description": "Sink.",
            },
        ]
    )
    linked = link_candidates([finding], [candidate(start_line=6, end_line=6)])
    assert linked == {"CAND-00000000000000A1"}


def test_finding_without_class_links_any_candidate_class():
    finding = confirmed()
    del finding["class"]
    assert link_candidates([finding], [candidate(**{"class": "xss"})]) == {"CAND-00000000000000A1"}


def test_merge_run_links_candidates_and_counts_unlinked(tmp_path):
    run = make_run(
        tmp_path,
        {"T0001-verify": ("done", {"finding.json": confirmed()})},
        candidates=[
            candidate("CAND-00000000000000A1"),
            candidate("CAND-00000000000000B1", file="app/config.py", start_line=3, end_line=3),
        ],
    )
    summary = merge_run(run)
    assert summary["candidates"] == {"available": True, "total": 2, "linked": 1, "unlinked": 1}
    assert read_findings(run)[0]["candidates"] == ["CAND-00000000000000A1"]


# ---------------------------------------------------------------------------------------------
# PoC results


def poc(finding_id="KF-0000000000000001", status="passed", **extra):
    record = {
        "finding_id": finding_id,
        "level": "unit",
        "status": status,
        "observed_result": "The harness printed every row.",
        "artifacts": ["poc/KF-0000000000000001/out/stdout.txt"],
    }
    record.update(extra)
    return record


def test_passed_poc_raises_confidence_of_a_confirmed_finding(tmp_path):
    run = make_run(
        tmp_path,
        {
            "T0001-verify": ("done", {"finding.json": confirmed()}),
            "T0002-poc_build": ("done", {"poc.json": poc()}),
        },
    )
    summary = merge_run(run)
    finding = read_findings(run)[0]
    assert finding["confidence"]["score"] == "high"
    assert finding["execution"]["observed_result"] == "The harness printed every row."
    assert finding["poc"] == {
        "level": "unit",
        "status": "passed",
        "observed_result": "The harness printed every row.",
        "artifacts": ["poc/KF-0000000000000001/out/stdout.txt"],
    }
    assert "poc-builder" in finding["engines"]
    assert summary["poc"] == {"applied": 1, "promoted": 0, "promotion_refused": 0}


def verify_result(finding_fields):
    return {"task_id": "T0001-verify", "finding": finding_fields}


def test_passed_poc_promotes_needs_validation_with_confirmed_fields(tmp_path):
    fields = {"root_cause": "find_user formats SQL.", **copy.deepcopy(CONFIRMED_EXTRA)}
    run = make_run(
        tmp_path,
        {
            "T0001-verify": (
                "done",
                {"finding.json": needs_validation(), "result.json": verify_result(fields)},
            ),
            "T0002-poc_build": ("done", {"poc.json": poc()}),
        },
        lang="en",
    )
    summary = merge_run(run)
    finding = read_findings(run)[0]
    assert finding["verdict"] == "confirmed"
    assert finding["root_cause"] == "find_user formats SQL."
    assert finding["confidence"] == {
        "score": "high",
        "reason": "The sandbox PoC demonstrated the vulnerability.",
    }
    assert finding["execution"]["observed_result"] == "The harness printed every row."
    for key in ("claimed_root_cause", "blockers", "validation_plan"):
        assert key not in finding
    assert summary["poc"]["promoted"] == 1
    assert summary["by_verdict"]["confirmed"] == 1


def test_passed_poc_without_confirmed_fields_keeps_needs_validation(tmp_path):
    partial = {"root_cause": "x", "intended_behavior": "y"}
    run = make_run(
        tmp_path,
        {
            "T0001-verify": (
                "done",
                {"finding.json": needs_validation(), "result.json": verify_result(partial)},
            ),
            "T0002-poc_build": ("done", {"poc.json": poc()}),
        },
    )
    summary = merge_run(run)
    finding = read_findings(run)[0]
    assert finding["verdict"] == "needs_validation"
    assert finding["poc"]["status"] == "passed"
    assert BLOCKER_CONFIRMED_FIELDS_MISSING in finding["blockers"]
    assert summary["poc"]["promotion_refused"] == 1


def test_invalid_promotion_keeps_needs_validation(tmp_path):
    fields = copy.deepcopy(CONFIRMED_EXTRA)
    fields["severity"]["impact"]["score"] = "low"  # overall would exceed impact
    run = make_run(
        tmp_path,
        {
            "T0001-verify": (
                "done",
                {"finding.json": needs_validation(), "result.json": verify_result(fields)},
            ),
            "T0002-poc_build": ("done", {"poc.json": poc()}),
        },
    )
    merge_run(run)
    finding = read_findings(run)[0]
    assert finding["verdict"] == "needs_validation"
    assert BLOCKER_CONFIRMED_FIELDS_MISSING in finding["blockers"]


@pytest.mark.parametrize(
    ("status", "extra", "blocker"),
    [
        ("blocked", {}, BLOCKER_SANDBOX_INFEASIBLE),
        ("not_run", {}, BLOCKER_SANDBOX_UNAVAILABLE),
        ("not_run", {"blocker": "budget_exhausted"}, "budget_exhausted"),
    ],
)
def test_blocked_and_not_run_record_the_reason(tmp_path, status, extra, blocker):
    run = make_run(
        tmp_path,
        {
            "T0001-verify": ("done", {"finding.json": needs_validation()}),
            "T0002-poc_build": (
                "done",
                {"poc.json": poc(status=status, observed_result="Docker is missing.", **extra)},
            ),
        },
    )
    merge_run(run)
    finding = read_findings(run)[0]
    assert finding["verdict"] == "needs_validation"
    assert finding["poc"]["status"] == status
    assert finding["poc"]["observed_result"] == "Docker is missing."
    assert finding["blockers"] == ["unverified_evidence", blocker]


def test_the_poc_keeps_its_blocker_and_its_run_facts(tmp_path):
    facts = {
        "started_at": "2026-11-02T10:00:00Z",
        "duration_ms": 1520,
        "exit_code": 137,
        "output_truncated": False,
    }
    record = poc(status="blocked", blocker="sandbox_timeout", **facts)
    record["duration_ms_bad"] = 1  # unknown keys never reach the finding
    run = make_run(
        tmp_path,
        {
            "T0001-verify": ("done", {"finding.json": confirmed()}),
            "T0002-poc_build": ("done", {"poc.json": record}),
        },
    )
    merge_run(run)
    finding = read_findings(run)[0]
    assert finding["poc"]["blocker"] == "sandbox_timeout"
    assert {key: finding["poc"][key] for key in facts} == facts
    assert "duration_ms_bad" not in finding["poc"]


def test_a_dead_poc_task_gives_its_blocked_record_to_the_finding(tmp_path):
    record = poc(status="blocked", blocker="agent_failed", observed_result="no result (3 attempts)")
    run = make_run(
        tmp_path,
        {
            "T0001-verify": ("done", {"finding.json": confirmed()}),
            "T0002-poc_build": ("dead", {"poc.json": record}),
        },
    )
    merge_run(run)
    findings = read_findings(run)
    assert findings[0]["poc"]["status"] == "blocked"
    assert findings[0]["poc"]["blocker"] == "agent_failed"


def test_failed_poc_keeps_the_verdict(tmp_path):
    run = make_run(
        tmp_path,
        {
            "T0001-verify": ("done", {"finding.json": confirmed()}),
            "T0002-poc_build": ("done", {"poc.json": poc(status="failed", observed_result="")}),
        },
    )
    merge_run(run)
    finding = read_findings(run)[0]
    assert finding["verdict"] == "confirmed"
    assert finding["confidence"]["score"] == "medium"
    assert finding["poc"]["status"] == "failed"
    assert finding["poc"]["observed_result"] == "PoC zafiyeti göstermedi."  # run language tr


def test_strongest_poc_wins(tmp_path):
    run = make_run(
        tmp_path,
        {
            "T0001-verify": ("done", {"finding.json": confirmed()}),
            "T0002-poc_build": ("done", {"poc.json": poc()}),
            "T0003-poc_build": ("done", {"poc.json": poc(status="blocked")}),
        },
    )
    merge_run(run)
    assert read_findings(run)[0]["poc"]["status"] == "passed"


def test_poc_for_unknown_finding_and_unsafe_artifacts_give_warnings(tmp_path):
    run = make_run(
        tmp_path,
        {
            "T0001-verify": ("done", {"finding.json": confirmed()}),
            "T0002-poc_build": ("done", {"poc.json": poc(finding_id="KF-FFFFFFFFFFFFFFFF")}),
            "T0003-poc_build": ("done", {"poc.json": poc(artifacts=["../escape.txt"])}),
        },
    )
    summary = merge_run(run)
    assert any("unknown finding" in warning for warning in summary["warnings"])
    assert any("artifact" in warning for warning in summary["warnings"])
    assert read_findings(run)[0]["poc"]["artifacts"] == []


# ---------------------------------------------------------------------------------------------
# Translations


def test_translations_set_i18n_en_and_later_tasks_win(tmp_path):
    first = {
        "translations": [
            {
                "id": "KF-0000000000000001",
                "title": "Old",
                "description": "Old",
                "remediation_strategy": "Old",
            }
        ]
    }
    second = {
        "translations": [
            {
                "id": "KF-0000000000000001",
                "title": "SQL injection",
                "description": "id reaches SQL.",
                "remediation_strategy": "Bind it.",
            },
            {
                "id": "KF-9999999999999999",
                "title": "x",
                "description": "y",
                "remediation_strategy": "z",
            },
        ]
    }
    run = make_run(
        tmp_path,
        {
            "T0001-verify": ("done", {"finding.json": confirmed()}),
            "T0002-translate": ("done", {"translations.json": first}),
            "T0003-translate": ("done", {"translations.json": second}),
        },
    )
    summary = merge_run(run)
    finding = read_findings(run)[0]
    assert finding["i18n"] == {
        "en": {
            "title": "SQL injection",
            "description": "id reaches SQL.",
            "remediation_strategy": "Bind it.",
        }
    }
    assert summary["translations_applied"] == 1
    assert any("unknown finding" in warning for warning in summary["warnings"])


# ---------------------------------------------------------------------------------------------
# Inputs, output and errors


def test_only_done_tasks_are_read_and_invalid_findings_are_skipped(tmp_path):
    broken = confirmed(fingerprint="broken")
    del broken["remediation"]
    run = make_run(
        tmp_path,
        {
            "T0001-verify": ("done", {"finding.json": confirmed()}),
            "T0002-verify": ("failed", {"finding.json": rejected(fingerprint="other")}),
            "T0003-verify": ("done", {"finding.json": broken}),
            "T0004-verify": ("pending", {"finding.json": needs_validation(fingerprint="later")}),
        },
    )
    summary = merge_run(run)
    assert [item["fingerprint"] for item in read_findings(run)] == ["sqli:app/db.py:find_user"]
    assert summary["inputs"]["done_tasks"] == 2
    assert any("invalid finding skipped" in warning for warning in summary["warnings"])


def test_output_is_sorted_validated_and_ids_are_assigned(tmp_path):
    no_id = rejected(fingerprint="a-first")
    del no_id["id"]
    items = {
        "T0001-verify": ("done", {"finding.json": confirmed(fingerprint="z-last")}),
        "T0002-verify": ("done", {"finding.json": no_id}),
        "T0003-verify": (
            "done",
            {"finding.json": needs_validation(fingerprint="M-mid", id="KF-0000000000000005")},
        ),
    }
    run = make_run(tmp_path, items)
    merge_run(run)
    findings = read_findings(run)
    fingerprints = [item["fingerprint"] for item in findings]
    assert fingerprints == sorted(fingerprints, key=utf16_key)
    assert all(item["id"].startswith("KF-") for item in findings)
    assert validate_findings_file(run / "findings.json") == []
    assert list(findings[0])[:2] == ["verdict", "fingerprint"]


def test_write_false_writes_nothing(tmp_path):
    run = make_run(tmp_path, {"T0001-verify": ("done", {"finding.json": confirmed()})})
    summary = merge_run(run, write=False)
    assert summary["findings"] == 1
    assert not (run / "findings.json").exists()


def test_empty_run_writes_an_empty_document(tmp_path):
    run = make_run(tmp_path, {}, vulns={"records": [{"package": "a"}, {"package": "b"}]})
    summary = merge_run(run)
    assert read_findings(run) == []
    assert summary["sca_records"] == 2
    assert summary["candidates"]["available"] is False


def test_missing_state_raises(tmp_path):
    (tmp_path / RUN_ID).mkdir()
    with pytest.raises(StateError):
        merge_run(tmp_path / RUN_ID)


def test_unreadable_candidates_give_a_warning(tmp_path):
    run = make_run(tmp_path, {"T0001-verify": ("done", {"finding.json": confirmed()})})
    (run / "candidates.json").write_text("{not json", encoding="utf-8")
    summary = merge_run(run)
    assert any("candidates.json" in warning for warning in summary["warnings"])


def test_helpers():
    assert severity_of(confirmed()) == "high"
    informational = confirmed()
    informational["severity"]["overall_severity"] = "informational"
    assert severity_of(informational) == "info"
    assert severity_of(needs_validation()) is None
    assert sca_records([{"a": 1}, "x"]) == [{"a": 1}]
    assert sca_records({"vulns": [{"a": 1}]}) == [{"a": 1}]
    assert sca_records({"other": []}) is None
    get_lines = target_get_lines(GOLDEN_RUN / "target")
    assert get_lines("app/db.py")[7].startswith("    cur.execute(")
    assert get_lines("../state.json") is None
    assert get_lines("missing.py") is None


# ---------------------------------------------------------------------------------------------
# CLI


def test_merge_command_json(tmp_path, monkeypatch, capsys):
    make_run(tmp_path, {"T0001-verify": ("done", {"finding.json": confirmed()})})
    monkeypatch.setenv("KALKAN_RUNS_DIR", str(tmp_path))
    assert main(["merge", "--run", RUN_ID, "--json"]) == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["findings"] == 1
    assert not (tmp_path / RUN_ID / "run.lock").exists()


def test_merge_command_uses_latest(tmp_path, monkeypatch, capsys):
    make_run(tmp_path, {"T0001-verify": ("done", {"finding.json": confirmed()})})
    (tmp_path / "LATEST").write_text(RUN_ID + "\n", encoding="utf-8")
    monkeypatch.setenv("KALKAN_RUNS_DIR", str(tmp_path))
    assert main(["merge"]) == 0
    assert "merged 1 findings" in capsys.readouterr().err


def test_merge_command_unknown_run(tmp_path, monkeypatch):
    monkeypatch.setenv("KALKAN_RUNS_DIR", str(tmp_path))
    assert main(["merge", "--run", "20261015T120000Z-none-0000"]) == 1
