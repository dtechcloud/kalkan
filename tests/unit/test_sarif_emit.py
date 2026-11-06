# SPDX-License-Identifier: MIT
"""Tests for kalkan.sarif.emit (ENGINE-SPEC 8.2)."""

from __future__ import annotations

import copy
import errno
import json
import os
import random
import re

import pytest

from kalkan.findings.fingerprint import FINGERPRINT_KEY, assign_finding_ids, finding_hash
from kalkan.sarif import emit as emit_module
from kalkan.sarif.emit import SARIF_SCHEMA, emit, write_sarif
from kalkan.sarif.ingest import ingest_document

HEX64 = re.compile(r"[0-9a-f]{64}")


def severity(overall):
    return {
        "likelihood": {"score": "high", "reason": "Reachable without authentication."},
        "impact": {"score": overall, "reason": "Reads every user record."},
        "overall_severity": overall,
    }


def confirmed(**extra):
    finding = {
        "verdict": "confirmed",
        "fingerprint": "app-db-sqli",
        "title": "SQL injection in the user lookup",
        "description": "The id parameter reaches a raw SQL string.",
        "root_cause": "String concatenation builds the query.",
        "intended_behavior": "The query binds the id as a parameter.",
        "trace": [
            {
                "kind": "entrypoint",
                "file": "app/routes.py",
                "line": 10,
                "scope": "get_user",
                "description": "Reads id from the query string.",
            },
            {
                "kind": "propagation",
                "file": "app/service.py",
                "line": 22,
                "scope": "find_user",
                "description": "Passes id to the query builder.",
            },
            {
                "kind": "sink",
                "file": "app/db.py",
                "line": 14,
                "scope": "run_query",
                "description": "Concatenates id into SQL.",
            },
        ],
        "evidence": [{"file": "app/db.py", "line": 14, "description": "String concatenation."}],
        "conditions": [],
        "execution": {
            "attacker_perspective": "Unauthenticated client.",
            "payloads": ["1 OR 1=1"],
            "instructions": ["GET /users?id=1%20OR%201=1"],
            "observed_result": "All rows returned.",
        },
        "remediation": {"strategy": "Use bound parameters."},
        "severity": severity("high"),
        "confidence": {"score": "high", "reason": "The PoC passed."},
        "class": "sqli",
        "cwe": ["CWE-89"],
        "engines": ["opengrep", "hunter"],
    }
    finding.update(extra)
    return finding


def needs_validation(**extra):
    finding = {
        "verdict": "needs_validation",
        "fingerprint": "app-fetch-ssrf",
        "title": "SSRF in the avatar fetcher",
        "description": "A user URL reaches requests.get.",
        "claimed_root_cause": "No host allow-list.",
        "trace": [
            {
                "kind": "sink",
                "file": "app/avatar.py",
                "line": 31,
                "scope": "fetch_avatar",
                "description": "requests.get(url).",
            }
        ],
        "evidence": [{"file": "app/avatar.py", "line": 31, "description": "Outbound call."}],
        "blockers": ["sandbox_unavailable"],
        "validation_plan": {"local": "Run the PoC in the sandbox."},
        "class": "ssrf",
        "cwe": ["CWE-918"],
        "engines": ["hunter"],
    }
    finding.update(extra)
    return finding


def rejected(**extra):
    finding = {
        "verdict": "rejected",
        "fingerprint": "app-view-xss",
        "title": "XSS in the profile view",
        "description": "The name reaches the template.",
        "claimed_root_cause": "Unescaped output.",
        # No sink element: the location falls back to the first evidence element.
        "trace": [
            {
                "kind": "entrypoint",
                "file": "app/views.py",
                "line": 5,
                "scope": "profile",
                "description": "Reads the name.",
            }
        ],
        "evidence": [
            {"file": "templates/profile.html", "line": 12, "description": "Auto-escaped."},
            {"file": "app/views.py", "line": 5, "description": "Render call."},
        ],
        "reason": "Jinja2 auto-escaping covers this context.",
        "class": "xss",
        "cwe": ["CWE-79"],
        "engines": ["critic"],
    }
    finding.update(extra)
    return finding


def findings_with_ids(*findings, get_lines=None):
    items = [copy.deepcopy(item) for item in findings]
    assign_finding_ids(items, get_lines=get_lines)
    return items


def run_of(document):
    assert len(document["runs"]) == 1
    return document["runs"][0]


def result_for(document, title):
    for item in run_of(document)["results"]:
        if item["message"]["text"].startswith(title):
            return item
    raise AssertionError(title)


def doc_of(*findings, **kwargs):
    return emit(list(findings), tool_version="0.1.0", run_id="R1", **kwargs)


# --- document structure ---------------------------------------------------------------------------


def test_document_structure():
    document = doc_of(*findings_with_ids(confirmed(), needs_validation(), rejected()))
    assert list(document) == ["$schema", "version", "runs"]
    assert document["$schema"] == SARIF_SCHEMA
    assert document["version"] == "2.1.0"
    run = run_of(document)
    assert run["tool"]["driver"]["name"] == "kalkan"
    assert run["tool"]["driver"]["version"] == "0.1.0"
    assert run["automationDetails"] == {"id": "kalkan/R1"}
    assert len(run["results"]) == 3
    json.dumps(document, allow_nan=False)


def test_empty_findings_give_an_empty_run():
    run = run_of(doc_of())
    assert run["tool"]["driver"]["rules"] == []
    assert run["results"] == []


# --- rules ----------------------------------------------------------------------------------------


def test_one_rule_per_class_in_taxonomy_order():
    items = findings_with_ids(
        rejected(),
        needs_validation(),
        confirmed(),
        confirmed(fingerprint="second", trace=[], evidence=[{"file": "b.py", "line": 1}]),
    )
    rules = run_of(doc_of(*items))["tool"]["driver"]["rules"]
    assert [rule["id"] for rule in rules] == ["sqli", "xss", "ssrf"]
    assert rules[0] == {
        "id": "sqli",
        "shortDescription": {"text": "SQL injection"},
        "properties": {"tags": ["security", "external/cwe/cwe-89"]},
    }
    assert rules[2]["shortDescription"] == {"text": "Server-side request forgery"}


def test_rule_tags_add_the_cwes_of_the_findings():
    item = confirmed(cwe=["CWE-564", "CWE-89"])
    rules = run_of(doc_of(*findings_with_ids(item)))["tool"]["driver"]["rules"]
    assert rules[0]["properties"]["tags"] == [
        "security",
        "external/cwe/cwe-89",
        "external/cwe/cwe-564",
    ]


def test_fallback_rules_per_cwe_then_unclassified():
    no_class = confirmed(fingerprint="cookie", cwe=["CWE-1004", "CWE-614"])
    del no_class["class"]
    nothing = confirmed(fingerprint="nothing", cwe=[])
    del nothing["class"]
    other = confirmed(fingerprint="other", cwe=["CWE-89"])
    del other["class"]
    items = findings_with_ids(nothing, no_class, other, confirmed())
    run = run_of(doc_of(*items))
    rules = run["tool"]["driver"]["rules"]
    assert [rule["id"] for rule in rules] == ["sqli", "CWE-89", "CWE-1004", "unclassified"]
    assert rules[2] == {
        "id": "CWE-1004",
        "shortDescription": {"text": "CWE-1004"},
        "properties": {"tags": ["security", "external/cwe/cwe-1004", "external/cwe/cwe-614"]},
    }
    assert rules[3] == {
        "id": "unclassified",
        "shortDescription": {"text": "Unclassified finding"},
        "properties": {"tags": ["security"]},
    }
    for result in run["results"]:
        assert rules[result["ruleIndex"]]["id"] == result["ruleId"]


def test_unknown_class_slug_gets_its_own_rule():
    item = confirmed(**{"class": "future-class"})
    rules = run_of(doc_of(*findings_with_ids(item)))["tool"]["driver"]["rules"]
    assert rules[0]["id"] == "future-class"
    assert rules[0]["shortDescription"] == {"text": "future-class"}


def test_code_quality_rule_has_no_security_tag():
    item = confirmed(**{"class": "code-quality", "cwe": []})
    rules = run_of(doc_of(*findings_with_ids(item)))["tool"]["driver"]["rules"]
    assert rules[0]["properties"]["tags"] == []


# --- results --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("overall", "level", "score"),
    [
        ("critical", "error", "9.5"),
        ("high", "error", "8.0"),
        ("medium", "warning", "5.5"),
        ("low", "note", "2.0"),
        ("informational", "note", "0.0"),
    ],
)
def test_level_and_security_severity_follow_the_overall_severity(overall, level, score):
    result = run_of(doc_of(*findings_with_ids(confirmed(severity=severity(overall)))))["results"][0]
    assert result["level"] == level
    assert result["properties"]["security-severity"] == score
    assert result["properties"]["severity"] == ("info" if overall == "informational" else overall)


def test_needs_validation_gives_warning_without_severity():
    result = result_for(doc_of(*findings_with_ids(needs_validation())), "SSRF")
    assert result["level"] == "warning"
    assert "severity" not in result["properties"]
    assert "security-severity" not in result["properties"]


def test_rejected_findings_are_suppressed_with_the_reason():
    document = doc_of(*findings_with_ids(confirmed(), rejected()))
    result = result_for(document, "XSS")
    assert result["suppressions"] == [
        {
            "kind": "external",
            "status": "accepted",
            "justification": "Jinja2 auto-escaping covers this context.",
        }
    ]
    assert result["level"] == "note"
    assert "suppressions" not in result_for(document, "SQL injection")


def test_rejected_without_a_reason_has_no_justification():
    item = rejected()
    del item["reason"]
    result = run_of(doc_of(*findings_with_ids(item)))["results"][0]
    assert result["suppressions"] == [{"kind": "external", "status": "accepted"}]


def test_location_is_the_sink_element_of_the_trace():
    result = result_for(doc_of(*findings_with_ids(confirmed())), "SQL injection")
    assert result["locations"] == [
        {
            "physicalLocation": {
                "artifactLocation": {"uri": "app/db.py", "uriBaseId": "%SRCROOT%"},
                "region": {"startLine": 14},
            }
        }
    ]


def test_location_falls_back_to_the_first_evidence_element():
    result = result_for(doc_of(*findings_with_ids(rejected())), "XSS")
    location = result["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "templates/profile.html"
    assert location["region"] == {"startLine": 12}


def test_result_without_a_location():
    item = confirmed(trace=[], evidence=[])
    result = run_of(doc_of(*findings_with_ids(item)))["results"][0]
    assert "locations" not in result
    assert "codeFlows" not in result


def test_location_uri_is_percent_encoded():
    item = confirmed(trace=[], evidence=[{"file": "src/my file/çıktı.py", "line": 3}])
    result = run_of(doc_of(*findings_with_ids(item)))["results"][0]
    uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "src/my%20file/%C3%A7%C4%B1kt%C4%B1.py"


def test_code_flows_follow_the_trace_in_order():
    result = result_for(doc_of(*findings_with_ids(confirmed())), "SQL injection")
    assert result["codeFlows"] == [
        {
            "threadFlows": [
                {
                    "locations": [
                        {
                            "location": {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": "app/routes.py",
                                        "uriBaseId": "%SRCROOT%",
                                    },
                                    "region": {"startLine": 10},
                                },
                                "message": {"text": "Reads id from the query string."},
                            },
                            "properties": {"kind": "entrypoint", "scope": "get_user"},
                        },
                        {
                            "location": {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": "app/service.py",
                                        "uriBaseId": "%SRCROOT%",
                                    },
                                    "region": {"startLine": 22},
                                },
                                "message": {"text": "Passes id to the query builder."},
                            },
                            "properties": {"kind": "propagation", "scope": "find_user"},
                        },
                        {
                            "location": {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": "app/db.py",
                                        "uriBaseId": "%SRCROOT%",
                                    },
                                    "region": {"startLine": 14},
                                },
                                "message": {"text": "Concatenates id into SQL."},
                            },
                            "properties": {"kind": "sink", "scope": "run_query"},
                        },
                    ]
                }
            ]
        }
    ]


def test_message_joins_title_and_description():
    result = run_of(doc_of(*findings_with_ids(confirmed())))["results"][0]
    assert result["message"] == {
        "text": "SQL injection in the user lookup\n\nThe id parameter reaches a raw SQL string."
    }
    item = confirmed(title="", description="")
    result = run_of(doc_of(*findings_with_ids(item)))["results"][0]
    assert result["message"] == {"text": "SQL injection"}


def test_properties_in_spec_order():
    [item] = findings_with_ids(confirmed())
    result = run_of(doc_of(item))["results"][0]
    assert result["properties"] == {
        "findingId": item["id"],
        "verdict": "confirmed",
        "severity": "high",
        "confidence": "high",
        "engines": ["opengrep", "hunter"],
        "class": "sqli",
        "cwe": ["CWE-89"],
        "security-severity": "8.0",
    }
    assert list(result["properties"]) == [
        "findingId",
        "verdict",
        "severity",
        "confidence",
        "engines",
        "class",
        "cwe",
        "security-severity",
    ]


def test_result_key_order():
    result = result_for(doc_of(*findings_with_ids(rejected())), "XSS")
    assert list(result) == [
        "ruleId",
        "ruleIndex",
        "level",
        "message",
        "locations",
        "codeFlows",
        "partialFingerprints",
        "suppressions",
        "properties",
    ]


# --- partialFingerprints --------------------------------------------------------------------------


def test_partial_fingerprint_is_the_full_hash_of_the_finding_id():
    items = findings_with_ids(confirmed(), needs_validation(), rejected())
    document = doc_of(*items)
    by_id = {item["id"]: item for item in items}
    for result in run_of(document)["results"]:
        value = result["partialFingerprints"][FINGERPRINT_KEY]
        assert list(result["partialFingerprints"]) == ["kalkanFinding/v1"]
        assert HEX64.fullmatch(value)
        finding_id = result["properties"]["findingId"]
        assert value[:16].upper() == finding_id[3:]
        assert finding_id in by_id


def test_partial_fingerprint_follows_the_collision_counter():
    # Two findings with the same class, file and line: the second ID uses counter 1.
    first = confirmed(fingerprint="first", description="first")
    second = confirmed(fingerprint="second", description="second")
    items = findings_with_ids(first, second)
    assert items[0]["id"] != items[1]["id"]
    document = doc_of(*items)
    values = {}
    for result in run_of(document)["results"]:
        value = result["partialFingerprints"][FINGERPRINT_KEY]
        values[result["properties"]["findingId"]] = value
        assert value[:16].upper() == result["properties"]["findingId"][3:]
    assert len(set(values.values())) == 2
    inputs = {
        "cwe": ["CWE-89"],
        "class_slug": "sqli",
        "rule_id": None,
        "uri": "app/db.py",
        "snippet": None,
        "start_line": 14,
    }
    assert values[items[1]["id"]] == finding_hash(**inputs, counter=1)


def test_partial_fingerprint_uses_get_lines_like_the_finding_id():
    source = {"app/db.py": ["line"] * 13 + ['    cursor.execute("SELECT " + uid)']}

    def get_lines(path):
        return source.get(path)

    items = findings_with_ids(confirmed(), get_lines=get_lines)
    with_lines = run_of(doc_of(*items, get_lines=get_lines))["results"][0]
    value = with_lines["partialFingerprints"][FINGERPRINT_KEY]
    assert value[:16].upper() == items[0]["id"][3:]
    # Without get_lines the anchor differs, so the hash cannot reproduce the ID.
    without = run_of(doc_of(*items))["results"][0]["partialFingerprints"][FINGERPRINT_KEY]
    assert without != value
    assert HEX64.fullmatch(without)


def test_partial_fingerprints_stay_unique_when_ids_are_missing_or_shared():
    plain = confirmed()
    twin = confirmed(description="twin")
    same_id = confirmed(description="same id", id="KF-0000000000000000")
    other_same_id = confirmed(description="other", id="KF-0000000000000000")
    document = doc_of(plain, twin, same_id, other_same_id)
    values = [r["partialFingerprints"][FINGERPRINT_KEY] for r in run_of(document)["results"]]
    assert len(values) == len(set(values)) == 4
    assert all(HEX64.fullmatch(value) for value in values)
    without_id = [r for r in run_of(document)["results"] if "findingId" not in r["properties"]]
    assert len(without_id) == 2


# --- determinism ----------------------------------------------------------------------------------


def test_output_does_not_depend_on_the_input_order():
    items = findings_with_ids(
        confirmed(),
        needs_validation(),
        rejected(),
        confirmed(fingerprint="b", trace=[], evidence=[{"file": "a.py", "line": 2}]),
        confirmed(fingerprint="c", description="same place"),
    )
    expected = doc_of(*items)
    generator = random.Random(7)
    for _ in range(5):
        shuffled = items[:]
        generator.shuffle(shuffled)
        assert doc_of(*shuffled) == expected
    assert json.dumps(doc_of(*reversed(items))) == json.dumps(expected)


def test_results_are_sorted_by_file_and_line():
    items = findings_with_ids(confirmed(), needs_validation(), rejected())
    results = run_of(doc_of(*items))["results"]
    uris = [
        (
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            r["locations"][0]["physicalLocation"]["region"]["startLine"],
        )
        for r in results
    ]
    assert uris == sorted(uris)


def test_emit_does_not_change_the_findings():
    items = findings_with_ids(confirmed(), rejected())
    before = copy.deepcopy(items)
    doc_of(*items)
    assert items == before


# --- write_sarif and round trip -------------------------------------------------------------------


def test_write_sarif_writes_utf8_json_with_lf(tmp_path):
    document = doc_of(*findings_with_ids(confirmed(title="Türkçe başlık: çıktı")))
    path = tmp_path / "findings.sarif"
    write_sarif(path, document)
    data = path.read_bytes()
    assert data.endswith(b"}\n")
    assert b"\r\n" not in data
    assert "Türkçe başlık: çıktı".encode() in data
    assert json.loads(data.decode("utf-8")) == document
    assert [p.name for p in tmp_path.iterdir()] == ["findings.sarif"]


def test_write_sarif_replaces_an_existing_file(tmp_path):
    path = tmp_path / "findings.sarif"
    path.write_text("old", encoding="utf-8")
    write_sarif(str(path), {"version": "2.1.0", "runs": []})
    assert json.loads(path.read_text(encoding="utf-8")) == {"version": "2.1.0", "runs": []}
    assert [p.name for p in tmp_path.iterdir()] == ["findings.sarif"]


def test_write_sarif_needs_the_parent_directory(tmp_path):
    with pytest.raises(FileNotFoundError):
        write_sarif(tmp_path / "missing" / "findings.sarif", {"version": "2.1.0", "runs": []})


def test_write_sarif_does_not_create_a_file_for_unserializable_data(tmp_path):
    with pytest.raises(TypeError):
        write_sarif(tmp_path / "findings.sarif", {"bad": object()})
    assert list(tmp_path.iterdir()) == []


def test_write_sarif_removes_the_temporary_file_when_the_replace_fails(tmp_path, monkeypatch):
    path = tmp_path / "findings.sarif"
    path.write_text("old", encoding="utf-8")

    def failing_replace(source, destination):
        # Not a PermissionError: safe_io retries that one on Windows.
        raise OSError(errno.EIO, "input/output error")

    monkeypatch.setattr(os, "replace", failing_replace)
    with pytest.raises(OSError, match="input/output error"):
        write_sarif(path, {"version": "2.1.0", "runs": []})
    assert [p.name for p in tmp_path.iterdir()] == ["findings.sarif"]
    assert path.read_text(encoding="utf-8") == "old"


def test_write_sarif_rejects_nan(tmp_path):
    with pytest.raises(ValueError):
        write_sarif(tmp_path / "findings.sarif", {"version": "2.1.0", "x": float("nan")})
    assert list(tmp_path.iterdir()) == []


def test_write_sarif_uses_the_shared_atomic_writer(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(emit_module, "atomic_write_json", lambda p, o: calls.append((p, o)))
    document = {"version": "2.1.0", "runs": []}
    write_sarif(tmp_path / "x.sarif", document)
    assert calls == [(tmp_path / "x.sarif", document)]


def test_emitted_sarif_can_be_ingested_again():
    # The candidate engine name does not matter here. "matcher" is a valid engine.
    items = findings_with_ids(
        confirmed(), needs_validation(), confirmed(severity=severity("informational"))
    )
    document = doc_of(*items)
    outcome = ingest_document(document, "matcher", "C:/runs/R1/target", "findings.sarif")
    assert outcome.warnings == []
    seen = {
        (c["rule_id"], c["file"], c["start_line"], c["severity"], c["class"], tuple(c["cwe"]))
        for c in outcome.candidates
    }
    assert seen == {
        ("sqli", "app/db.py", 14, "high", "sqli", ("CWE-89",)),
        ("ssrf", "app/avatar.py", 31, "medium", "ssrf", ("CWE-918",)),
        ("sqli", "app/db.py", 14, "info", "sqli", ("CWE-89",)),
    }
