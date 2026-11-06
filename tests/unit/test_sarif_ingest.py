# SPDX-License-Identifier: MIT
"""Tests for kalkan.sarif.ingest (ENGINE-SPEC 4 and 8.1)."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from kalkan.errors import UnsafeInputError, ValidationError
from kalkan.findings.fingerprint import candidate_id
from kalkan.findings.validate import validate_candidate
from kalkan.sarif import ingest as ingest_module
from kalkan.sarif.ingest import (
    ENGINES,
    IngestResult,
    _manifest_ecosystem,
    _parse_purl,
    default_class,
    ingest_document,
    ingest_file,
)

ROOT = "C:\\work\\runs\\R1\\target"

REQUIRED_FIELDS = [
    "id",
    "engine",
    "rule_id",
    "class",
    "cwe",
    "title",
    "message",
    "file",
    "start_line",
    "end_line",
    "snippet",
    "severity",
    "tool_severity",
    "confidence",
    "tags",
    "fingerprints",
    "sca",
    "raw",
]
SCA_FIELDS = [
    "ecosystem",
    "package",
    "version",
    "vuln_ids",
    "fixed_versions",
    "cvss_score",
    "cvss_vector",
]


def sarif(*runs):
    return {"version": "2.1.0", "runs": list(runs)}


def run(results, rules=None, **extra):
    driver = {"name": "tool"}
    if rules is not None:
        driver["rules"] = rules
    return {"tool": {"driver": driver}, "results": results, **extra}


def result(rule_id="R1", uri="app/a.py", line=3, **extra):
    item = {"ruleId": rule_id, "message": {"text": "message text"}}
    if uri is not None:
        location = {"artifactLocation": {"uri": uri}}
        if line is not None:
            location["region"] = {"startLine": line}
        item["locations"] = [{"physicalLocation": location}]
    item.update(extra)
    return item


def ingest(doc, engine="opengrep", root=ROOT):
    return ingest_document(doc, engine, root, "scans/tool.sarif")


def only(outcome: IngestResult) -> dict:
    assert outcome.warnings == []
    assert len(outcome.candidates) == 1
    return outcome.candidates[0]


# --- the candidate record -------------------------------------------------------------------------


def test_candidate_has_every_field_of_engine_spec_4():
    candidate = only(ingest(sarif(run([result()], rules=[{"id": "R1"}]))))
    assert list(candidate) == REQUIRED_FIELDS
    assert candidate["engine"] == "opengrep"
    assert candidate["rule_id"] == "R1"
    assert candidate["class"] is None
    assert candidate["cwe"] == []
    assert candidate["title"] == "R1"
    assert candidate["message"] == "message text"
    assert candidate["file"] == "app/a.py"
    assert candidate["start_line"] == 3
    assert candidate["end_line"] == 3
    assert candidate["snippet"] == ""
    assert candidate["severity"] == "medium"
    assert candidate["tool_severity"] == ""
    assert candidate["confidence"] is None
    assert candidate["tags"] == []
    assert candidate["fingerprints"] == {}
    assert candidate["sca"] is None
    assert candidate["raw"] == {"sarif_file": "scans/tool.sarif", "run_index": 0, "result_index": 0}


def test_candidate_id_comes_from_the_fingerprint_module():
    item = result(line=7)
    item["locations"][0]["physicalLocation"]["region"]["snippet"] = {"text": "  eval(x)\n"}
    candidate = only(ingest(sarif(run([item]))))
    assert re.fullmatch(r"CAND-[0-9A-F]{16}", candidate["id"])
    assert candidate["id"] == candidate_id("opengrep", "R1", "app/a.py", 7, "  eval(x)\n")


def test_raw_provenance_counts_runs_and_results():
    doc = sarif(run([result("A"), result("B")]), run([result("C")]))
    outcome = ingest(doc)
    assert [c["raw"] for c in outcome.candidates] == [
        {"sarif_file": "scans/tool.sarif", "run_index": 0, "result_index": 0},
        {"sarif_file": "scans/tool.sarif", "run_index": 0, "result_index": 1},
        {"sarif_file": "scans/tool.sarif", "run_index": 1, "result_index": 0},
    ]


def test_sarif_file_name_uses_forward_slashes():
    doc = sarif(run([result()]))
    outcome = ingest_document(doc, "bandit", ROOT, "scans\\bandit.sarif")
    assert outcome.candidates[0]["raw"]["sarif_file"] == "scans/bandit.sarif"
    outcome = ingest_document(doc, "bandit", ROOT, Path("scans") / "bandit.sarif")
    assert outcome.candidates[0]["raw"]["sarif_file"] == "scans/bandit.sarif"


# --- rules ----------------------------------------------------------------------------------------


def test_rule_found_through_rule_index():
    rules = [{"id": "R0", "name": "zero"}, {"id": "R1", "name": "one"}]
    candidate = only(ingest(sarif(run([result("R1", ruleIndex=1)], rules=rules))))
    assert candidate["title"] == "one"


def test_rule_index_alone_gives_the_rule_id():
    item = result()
    del item["ruleId"]
    item["ruleIndex"] = 0
    candidate = only(ingest(sarif(run([item], rules=[{"id": "R9", "name": "nine"}]))))
    assert candidate["rule_id"] == "R9"
    assert candidate["title"] == "nine"


def test_rule_found_through_rule_id():
    rules = [{"id": "R0", "name": "zero"}, {"id": "R1", "name": "one"}]
    assert only(ingest(sarif(run([result("R1")], rules=rules))))["title"] == "one"


def test_rule_found_in_tool_extensions():
    doc = sarif(run([result("EXT1")], rules=[{"id": "R0"}]))
    doc["runs"][0]["tool"]["extensions"] = [
        {"name": "pack", "rules": [{"id": "EXT1", "shortDescription": {"text": "From pack"}}]}
    ]
    assert only(ingest(doc))["title"] == "From pack"


def test_rule_id_wins_over_a_rule_index_that_disagrees():
    # Old Checkov versions computed ruleIndex from an unordered set.
    rules = [{"id": "CKV_1", "name": "first"}, {"id": "CKV_2", "name": "second"}]
    candidate = only(ingest(sarif(run([result("CKV_2", ruleIndex=0)], rules=rules))))
    assert candidate["title"] == "second"


def test_rule_index_out_of_range_falls_back_to_rule_id():
    rules = [{"id": "R1", "name": "one"}]
    assert only(ingest(sarif(run([result("R1", ruleIndex=5)], rules=rules))))["title"] == "one"


def test_rule_reference_object():
    item = result()
    del item["ruleId"]
    item["rule"] = {"id": "R2", "index": 1}
    rules = [{"id": "R1"}, {"id": "R2", "name": "two"}]
    candidate = only(ingest(sarif(run([item], rules=rules))))
    assert (candidate["rule_id"], candidate["title"]) == ("R2", "two")


def test_result_without_a_rule_id_is_skipped_with_a_warning():
    item = result()
    del item["ruleId"]
    outcome = ingest(sarif(run([item, result("OK")])))
    assert [c["rule_id"] for c in outcome.candidates] == ["OK"]
    assert outcome.warnings == [
        "scans/tool.sarif: run 0, result 0: the result has no rule ID; skipped"
    ]


def test_result_without_a_rule_definition():
    # Hadolint writes no rules.
    candidate = only(ingest(sarif(run([result("DL3008")]))))
    assert candidate["title"] == "DL3008"
    assert candidate["message"] == "message text"


# --- title and message ----------------------------------------------------------------------------


def test_title_prefers_short_description_then_name_then_rule_id():
    rule = {"id": "R1", "name": "rule name", "shortDescription": {"text": " Short "}}
    assert only(ingest(sarif(run([result()], rules=[rule]))))["title"] == "Short"
    rule = {"id": "R1", "name": "rule name", "shortDescription": {"text": "  "}}
    assert only(ingest(sarif(run([result()], rules=[rule]))))["title"] == "rule name"
    rule = {"id": "R1", "shortDescription": {"markdown": "only markdown"}}
    assert only(ingest(sarif(run([result()], rules=[rule]))))["title"] == "R1"
    rule = {"id": "R1", "name": " padded name\n"}
    assert only(ingest(sarif(run([result()], rules=[rule]))))["title"] == "padded name"
    rule = {"id": "R1", "name": "   "}
    assert only(ingest(sarif(run([result()], rules=[rule]))))["title"] == "R1"


def test_message_falls_back_to_the_full_description():
    rule = {"id": "R1", "fullDescription": {"text": "Full description."}}
    item = result(message={"id": "default", "arguments": []})
    assert only(ingest(sarif(run([item], rules=[rule]))))["message"] == "Full description."
    item = result(message={})
    assert only(ingest(sarif(run([item], rules=[{"id": "R1"}]))))["message"] == ""


def test_message_text_stays_verbatim():
    item = result(message={"text": "Line one\nLine two\n"})
    assert only(ingest(sarif(run([item]))))["message"] == "Line one\nLine two\n"


# --- CWE and class --------------------------------------------------------------------------------


def test_cwe_forms_and_order():
    item = result(properties={"tags": ["CWE-918: SSRF", "security"], "cwe": ["cwe-22", 79]})
    rule = {
        "id": "R1",
        "properties": {
            "tags": ["external/cwe/cwe-89", "OWASP-A03:2021 - Injection", "2021"],
            "cwe": "CWE-918",
        },
        "relationships": [
            {"target": {"id": "CWE-94", "toolComponent": {"name": "CWE"}}},
            {"target": {"id": "1333", "toolComponent": {"name": "cwe"}}},
            {"target": {"id": "SEC-1", "toolComponent": {"name": "OWASP"}}},
            {"target": {"id": 77}},
            "bad",
        ],
    }
    candidate = only(ingest(sarif(run([item], rules=[rule]))))
    assert candidate["cwe"] == ["CWE-918", "CWE-22", "CWE-79", "CWE-89", "CWE-94", "CWE-1333"]
    assert candidate["class"] == "ssrf"


def test_gosec_relationship_gives_the_cwe():
    rule = {
        "id": "G304",
        "relationships": [
            {"target": {"id": "22", "guid": "x", "toolComponent": {"name": "CWE"}}, "kinds": []}
        ],
    }
    candidate = only(ingest(sarif(run([result("G304")], rules=[rule])), engine="gosec"))
    assert candidate["cwe"] == ["CWE-22"]
    assert candidate["class"] == "path-traversal"


def test_class_comes_from_the_first_cwe_only():
    rule = {"id": "R1", "properties": {"tags": ["CWE-703", "CWE-89"]}}
    candidate = only(ingest(sarif(run([result()], rules=[rule]))))
    assert candidate["cwe"] == ["CWE-703", "CWE-89"]
    assert candidate["class"] is None


def test_class_uses_the_extended_map():
    rule = {"id": "R1", "properties": {"tags": ["CWE-77: Command Injection"]}}
    assert only(ingest(sarif(run([result()], rules=[rule]))))["class"] == "os-command-injection"


# --- default class --------------------------------------------------------------------------------

TRIVY_VULNERABILITY = {
    "name": "LanguageSpecificPackageVulnerability",
    "properties": {"tags": ["vulnerability", "security", "MEDIUM"]},
}
TRIVY_OS_VULNERABILITY = {
    "name": "OsPackageVulnerability",
    "properties": {"tags": ["vulnerability", "security", "HIGH"]},
}
TRIVY_MISCONFIGURATION = {
    "name": "Misconfiguration",
    "properties": {"tags": ["misconfiguration", "security", "HIGH"]},
}
TRIVY_SECRET = {"name": "Secret", "properties": {"tags": ["secret", "security", "CRITICAL"]}}
TRIVY_LICENSE = {"name": "License", "properties": {"tags": ["license", "security", "HIGH"]}}


@pytest.mark.parametrize(
    ("engine", "rule_id", "rule", "expected"),
    [
        ("gitleaks", "aws-access-token", None, "hardcoded-secrets"),
        ("gitleaks-history", "private-key", None, "hardcoded-secrets"),
        ("kingfisher", "betterleaks.private-key", None, "hardcoded-secrets"),
        ("kingfisher-history", "kingfisher.aws.1", None, "hardcoded-secrets"),
        ("shellcheck", "SC2086", None, None),
        ("flawfinder", "FF1033", None, None),
        ("gixy", "ssrf", None, None),
        ("hadolint", "DL3008", None, "iac-cloud-container"),
        ("osv-scanner", "CVE-2021-23337", None, "vulnerable-dependency"),
        ("grype", "GHSA-35jh-r3h4-6jhm-lodash", None, "vulnerable-dependency"),
        ("govulncheck", "GO-2023-2102", None, "vulnerable-dependency"),
        # Trivy: the rule tags and the rule name.
        ("trivy", "CVE-2023-32681", TRIVY_VULNERABILITY, "vulnerable-dependency"),
        ("trivy", "DLA-3482-1", TRIVY_OS_VULNERABILITY, "vulnerable-dependency"),
        ("trivy", "TEMP-0841856-B18BAF", TRIVY_OS_VULNERABILITY, "vulnerable-dependency"),
        ("trivy", "DS002", TRIVY_MISCONFIGURATION, "iac-cloud-container"),
        ("trivy", "AVD-AWS-0107", TRIVY_MISCONFIGURATION, "iac-cloud-container"),
        ("trivy", "aws-access-key-id", TRIVY_SECRET, "hardcoded-secrets"),
        ("trivy", "GPL-3.0", TRIVY_LICENSE, None),
        ("trivy", "custom-rule", {"name": "Secret"}, "hardcoded-secrets"),
        ("trivy", "custom-check", {"name": "Misconfiguration"}, "iac-cloud-container"),
        # Trivy without tags and name: the rule ID shape.
        ("trivy", "CVE-2024-1234", None, "vulnerable-dependency"),
        ("trivy", "GHSA-j8r2-6x86-q33q", {}, "vulnerable-dependency"),
        ("trivy", "DS026", None, "iac-cloud-container"),
        ("trivy", "KSV001", None, "iac-cloud-container"),
        ("trivy", "AVD-KSV-0012", None, "iac-cloud-container"),
        ("trivy", "AWS-0086", None, "iac-cloud-container"),
        ("trivy", "github-pat", None, "hardcoded-secrets"),
        ("trivy", "Something", None, None),
        # Checkov: the rule ID prefix.
        ("checkov", "CKV_SECRET_2", None, "hardcoded-secrets"),
        ("checkov", "CKV_GHA_2", None, "supply-chain-cicd"),
        ("checkov", "CKV2_GHA_1", None, "supply-chain-cicd"),
        ("checkov", "CKV_GITLABCI_1", None, "supply-chain-cicd"),
        ("checkov", "CKV_BITBUCKETPIPELINES_1", None, "supply-chain-cicd"),
        ("checkov", "CKV_AZUREPIPELINES_1", None, "supply-chain-cicd"),
        ("checkov", "CKV_CIRCLECIPIPELINES_2", None, "supply-chain-cicd"),
        ("checkov", "CKV_GITHUB_1", None, "supply-chain-cicd"),
        ("checkov", "CKV_GITLAB_1", None, "supply-chain-cicd"),
        ("checkov", "CKV_AWS_24", None, "iac-cloud-container"),
        ("checkov", "CKV2_AWS_6", None, "iac-cloud-container"),
        ("checkov", "CKV_DOCKER_2", None, "iac-cloud-container"),
        ("checkov", "CKV_K8S_8", None, "iac-cloud-container"),
        ("checkov", "CKV_GHAX_1", None, "iac-cloud-container"),
        ("checkov", "CVE-2021-23337", None, "vulnerable-dependency"),
        # Engines without a default class.
        ("bandit", "B608", None, None),
        ("gosec", "G104", None, None),
        ("opengrep", "python.lang.security.audit.x", None, None),
        ("matcher", "go-command-injection", None, None),
        ("syft", "x", None, None),
        ("semgrep", "x", None, None),
    ],
)
def test_default_class(engine, rule_id, rule, expected):
    assert default_class(engine, rule_id, rule) == expected


def test_default_class_is_used_when_no_cwe_gives_a_class():
    rule = {"id": "DS002", **TRIVY_MISCONFIGURATION}
    candidate = only(ingest(sarif(run([result("DS002")], rules=[rule])), engine="trivy"))
    assert candidate["cwe"] == []
    assert candidate["class"] == "iac-cloud-container"


def test_default_class_is_used_when_the_first_cwe_is_unmapped():
    item = result("generic-api-key", properties={"cwe": "CWE-703"})
    candidate = only(ingest(sarif(run([item])), engine="gitleaks-history"))
    assert (candidate["cwe"], candidate["class"]) == (["CWE-703"], "hardcoded-secrets")


def test_cwe_class_wins_over_the_default_class():
    rule = {"id": "CKV_AWS_1", "properties": {"tags": ["CWE-798"]}}
    candidate = only(ingest(sarif(run([result("CKV_AWS_1")], rules=[rule])), engine="checkov"))
    assert candidate["class"] == "hardcoded-secrets"


def test_engines_without_a_default_keep_a_null_class():
    rule = {"id": "G104", "properties": {"cwe": "CWE-703"}}
    candidate = only(ingest(sarif(run([result("G104")], rules=[rule])), engine="gosec"))
    assert candidate["class"] is None


# --- location -------------------------------------------------------------------------------------


def test_region_end_line_defaults_to_start_line_and_snippet_is_read():
    item = result(line=None)
    item["locations"][0]["physicalLocation"]["region"] = {
        "startLine": 4,
        "endLine": 6,
        "snippet": {"text": "x = 1\n"},
    }
    candidate = only(ingest(sarif(run([item]))))
    assert (candidate["start_line"], candidate["end_line"], candidate["snippet"]) == (
        4,
        6,
        "x = 1\n",
    )


def test_missing_region_gives_null_lines():
    candidate = only(ingest(sarif(run([result(line=None)]))))
    assert (candidate["start_line"], candidate["end_line"], candidate["snippet"]) == (
        None,
        None,
        "",
    )


def test_invalid_line_numbers_are_ignored_with_a_warning():
    item = result(line=None)
    item["locations"][0]["physicalLocation"]["region"] = {"startLine": 0, "endLine": 2}
    outcome = ingest(sarif(run([item])))
    candidate = outcome.candidates[0]
    assert (candidate["start_line"], candidate["end_line"]) == (None, None)
    assert outcome.warnings == [
        "scans/tool.sarif: run 0, result 0: region.startLine 0 is not a line number; ignored"
    ]


def test_end_line_before_start_line_is_replaced():
    item = result(line=None)
    item["locations"][0]["physicalLocation"]["region"] = {"startLine": 9, "endLine": 2}
    outcome = ingest(sarif(run([item])))
    assert (outcome.candidates[0]["start_line"], outcome.candidates[0]["end_line"]) == (9, 9)
    assert len(outcome.warnings) == 1
    assert "endLine 2 is before startLine 9" in outcome.warnings[0]


def test_first_location_with_a_physical_location_is_used():
    item = result(uri=None)
    item["locations"] = [
        {"logicalLocations": [{"name": "pkg"}]},
        {"physicalLocation": {"artifactLocation": {"uri": "second.py"}}},
        {"physicalLocation": {"artifactLocation": {"uri": "third.py"}}},
    ]
    assert only(ingest(sarif(run([item]))))["file"] == "second.py"


def test_result_without_locations_has_an_empty_file():
    candidate = only(ingest(sarif(run([result(uri=None)]))))
    assert (candidate["file"], candidate["start_line"]) == ("", None)


def test_artifact_index_gives_the_uri():
    item = result(uri=None)
    item["locations"] = [{"physicalLocation": {"artifactLocation": {"index": 1}}}]
    artifacts = [{"location": {"uri": "a.py"}}, {"location": {"uri": "lib/b.py"}}]
    assert only(ingest(sarif(run([item], artifacts=artifacts))))["file"] == "lib/b.py"


def test_location_uri_is_normalized_against_the_root_and_base_ids():
    items = [
        result(uri="file:///C:/work/runs/R1/target/app/x.py"),
        result(uri="C:\\work\\runs\\R1\\target\\app\\y.py"),
        result(uri=".\\app\\z.py"),
    ]
    based = result(uri="w.py")
    based["locations"][0]["physicalLocation"]["artifactLocation"]["uriBaseId"] = "SRC"
    items.append(based)
    doc = sarif(
        run(items, originalUriBaseIds={"SRC": {"uri": "file:///C:/work/runs/R1/target/src/"}})
    )
    outcome = ingest(doc)
    assert outcome.warnings == []
    assert [c["file"] for c in outcome.candidates] == [
        "app/x.py",
        "app/y.py",
        "app/z.py",
        "src/w.py",
    ]


def test_file_outside_the_target_root_is_kept_with_a_warning():
    outcome = ingest(sarif(run([result(uri="D:\\elsewhere\\x.py"), result(uri="../up.py")])))
    assert [c["file"] for c in outcome.candidates] == ["D:/elsewhere/x.py", "../up.py"]
    assert outcome.warnings == [
        "scans/tool.sarif: run 0, result 0: the file 'D:/elsewhere/x.py' is not inside the "
        "target root",
        "scans/tool.sarif: run 0, result 1: the file '../up.py' is not inside the target root",
    ]


def test_grype_leading_slash_is_relative_to_the_scan_root():
    outcome = ingest(sarif(run([result(uri="/package-lock.json")])), engine="grype")
    assert outcome.warnings == []
    assert outcome.candidates[0]["file"] == "package-lock.json"


# --- runs and bad results -------------------------------------------------------------------------


def test_runs_without_results_are_ignored():
    doc = sarif({"tool": {"driver": {"name": "x"}}}, run([]), run([result()]))
    outcome = ingest(doc)
    assert outcome.warnings == []
    assert [c["raw"]["run_index"] for c in outcome.candidates] == [2]


def test_bad_runs_are_skipped_with_warnings():
    doc = sarif("not a run", {"tool": {}, "results": {"x": 1}}, run([result()]))
    outcome = ingest(doc)
    assert len(outcome.candidates) == 1
    assert outcome.warnings == [
        "scans/tool.sarif: run 0: the run is not an object; skipped",
        "scans/tool.sarif: run 1: 'results' is not an array; skipped",
    ]


def test_a_bad_result_does_not_stop_the_ingest():
    outcome = ingest(sarif(run(["text", None, result("GOOD")])))
    assert [c["rule_id"] for c in outcome.candidates] == ["GOOD"]
    assert outcome.warnings == [
        "scans/tool.sarif: run 0, result 0: the result is not an object; skipped",
        "scans/tool.sarif: run 0, result 1: the result is not an object; skipped",
    ]


def test_an_unexpected_error_in_one_result_becomes_a_warning(monkeypatch):
    real = ingest_module.for_sarif_result

    def failing(item, rule):
        if item.get("ruleId") == "BOOM":
            raise RuntimeError("broken")
        return real(item, rule)

    monkeypatch.setattr(ingest_module, "for_sarif_result", failing)
    outcome = ingest(sarif(run([result("BOOM"), result("OK")])))
    assert [c["rule_id"] for c in outcome.candidates] == ["OK"]
    assert outcome.warnings == ["scans/tool.sarif: run 0, result 0: RuntimeError: broken; skipped"]


def test_malformed_fields_do_not_raise():
    item = {
        "ruleId": "R1",
        "message": "not an object",
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": 5}, "region": []}}],
        "properties": ["x"],
        "partialFingerprints": ["x"],
    }
    rule = {"id": "R1", "properties": {"tags": "CWE-89"}, "relationships": {"x": 1}}
    candidate = only(ingest(sarif(run([item], rules=[rule, "bad"]))))
    assert candidate["file"] == ""
    assert candidate["cwe"] == []
    assert candidate["fingerprints"] == {}


@pytest.mark.parametrize("kind", ["pass", "notApplicable"])
def test_results_that_report_no_problem_are_skipped(kind):
    outcome = ingest(sarif(run([result(kind=kind), result("OK", kind="fail")])))
    assert outcome.warnings == []
    assert [c["rule_id"] for c in outcome.candidates] == ["OK"]


def test_empty_runs_list():
    assert ingest(sarif()) == IngestResult(candidates=[], warnings=[])


@pytest.mark.parametrize(
    ("doc", "text"),
    [
        ([], "not a JSON object"),
        ({"runs": []}, "SARIF version None is not supported"),
        ({"version": "2.0.0", "runs": []}, "SARIF version '2.0.0' is not supported"),
        ({"version": "2.1.0"}, "'runs' is not an array"),
        ({"version": "2.1.0", "runs": {}}, "'runs' is not an array"),
    ],
)
def test_document_errors_raise_validation_error(doc, text):
    with pytest.raises(ValidationError) as error:
        ingest(doc)
    assert text in str(error.value)
    assert error.value.errors == [str(error.value)]


def test_unknown_engine_raises_validation_error():
    with pytest.raises(ValidationError, match="unknown engine 'semgrep'"):
        ingest(sarif(), engine="semgrep")


def test_engine_list_matches_engine_spec_4():
    assert ENGINES == (
        "trivy",
        "checkov",
        "hadolint",
        "gitleaks",
        "gitleaks-history",
        "opengrep",
        "bandit",
        "gosec",
        "osv-scanner",
        "grype",
        "govulncheck",
        "syft",
        "matcher",
        "zizmor",
        "actionlint",
        "poutine",
        "scorecard",
        "kingfisher",
        "kingfisher-history",
        "shellcheck",
        "flawfinder",
        "gixy",
        "helm-checkov",
        "vacuum",
        "opengrep-packs",
    )


# --- fingerprints, tags, severity, confidence -----------------------------------------------------


def test_fingerprints_merge_both_sarif_objects():
    item = result(
        fingerprints={"matchBasedId/v1": "abc", "shared": "from-fingerprints"},
        partialFingerprints={"shared": "from-partial", "commitSha": "", "count": 3},
    )
    assert only(ingest(sarif(run([item]))))["fingerprints"] == {
        "matchBasedId/v1": "abc",
        "shared": "from-partial",
    }


def test_tags_merge_result_then_rule_without_duplicates():
    item = result(properties={"tags": ["security", "result-tag", 5]})
    rule = {"id": "R1", "properties": {"tags": ["rule-tag", "security"]}}
    candidate = only(ingest(sarif(run([item], rules=[rule]))))
    assert candidate["tags"] == ["security", "result-tag", "rule-tag"]


def test_severity_and_tool_severity_follow_engine_spec_7():
    item = result(level="warning", properties={"issue_severity": "HIGH"})
    candidate = only(ingest(sarif(run([item]))))
    assert (candidate["severity"], candidate["tool_severity"]) == ("high", "HIGH")


@pytest.mark.parametrize(
    ("result_props", "rule_props", "expected"),
    [
        ({"issue_confidence": "MEDIUM"}, {"precision": "high"}, "medium"),
        ({"confidence": "Low"}, {}, "low"),
        ({}, {"confidence": "high"}, "high"),
        ({}, {"tags": ["security", "HIGH CONFIDENCE"], "precision": "very-high"}, "high"),
        ({}, {"tags": ["LOW CONFIDENCE"], "precision": "very-high"}, "low"),
        ({}, {"precision": "very-high"}, "high"),
        ({}, {"precision": "medium"}, "medium"),
        ({"confidence": "certain"}, {"precision": "unknown"}, None),
        ({}, {}, None),
    ],
)
def test_confidence_sources(result_props, rule_props, expected):
    item = result(properties=result_props)
    rule = {"id": "R1", "properties": rule_props}
    assert only(ingest(sarif(run([item], rules=[rule]))))["confidence"] == expected


# --- software composition analysis ----------------------------------------------------------------


def test_sca_is_null_for_code_scanners():
    rule = {"id": "R1", "properties": {"tags": ["vulnerability"]}}
    assert only(ingest(sarif(run([result()], rules=[rule])), engine="bandit"))["sca"] is None


def test_sca_is_null_for_trivy_results_that_are_not_vulnerabilities():
    rule = {"id": "DS002", "properties": {"tags": ["misconfiguration", "security", "HIGH"]}}
    candidate = only(ingest(sarif(run([result("DS002")], rules=[rule])), engine="trivy"))
    assert candidate["sca"] is None


def test_sca_from_trivy_message():
    rule = {
        "id": "CVE-2023-32681",
        "name": "LanguageSpecificPackageVulnerability",
        "properties": {
            "security-severity": "6.1",
            "tags": ["vulnerability", "security", "MEDIUM"],
            "cvssv3_baseScore": 6.1,
            "cvssv3_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N",
        },
    }
    message = (
        "Package: requests\nInstalled Version: 2.25.1\nVulnerability CVE-2023-32681\n"
        "Severity: MEDIUM\nFixed Version: 2.31.0, 3.0.1\nLink: [CVE-2023-32681](https://x)"
    )
    item = result("CVE-2023-32681", uri="requirements.txt", message={"text": message})
    candidate = only(ingest(sarif(run([item], rules=[rule])), engine="trivy"))
    assert candidate["sca"] == {
        "ecosystem": "PyPI",
        "package": "requests",
        "version": "2.25.1",
        "vuln_ids": ["CVE-2023-32681"],
        "fixed_versions": ["2.31.0", "3.0.1"],
        "cvss_score": 6.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N",
    }


def test_sca_from_osv_scanner_message_and_rule():
    rule = {
        "id": "CVE-2023-45133",
        "deprecatedIds": ["CVE-2023-45133", "GHSA-67hx-6x53-jw92"],
        "properties": {"security-severity": "9.3"},
    }
    message = (
        "Package '@babel/traverse@7.22.5' is vulnerable to 'CVE-2023-45133' "
        "(also known as 'GHSA-67hx-6x53-jw92')."
    )
    item = result("CVE-2023-45133", uri="web/package-lock.json", line=None)
    item["message"] = {"text": message}
    candidate = only(ingest(sarif(run([item], rules=[rule])), engine="osv-scanner"))
    assert candidate["sca"] == {
        "ecosystem": "npm",
        "package": "@babel/traverse",
        "version": "7.22.5",
        "vuln_ids": ["CVE-2023-45133", "GHSA-67hx-6x53-jw92"],
        "fixed_versions": [],
        "cvss_score": 9.3,
        "cvss_vector": None,
    }


def test_sca_from_grype_purl_and_help_text():
    rule = {
        "id": "GHSA-35jh-r3h4-6jhm-lodash",
        "help": {
            "text": "Vulnerability GHSA-35jh-r3h4-6jhm\nSeverity: high\nPackage: lodash\n"
            "Version: 4.17.20\nFix Version: 4.17.21\nType: npm\nLocation: /package-lock.json\n"
            "Data Namespace: github:language:javascript\nLink: x"
        },
        "properties": {"security-severity": "7.2", "purls": ["pkg:npm/lodash@4.17.20"]},
    }
    item = result("GHSA-35jh-r3h4-6jhm-lodash", uri="/package-lock.json")
    candidate = only(ingest(sarif(run([item], rules=[rule])), engine="grype"))
    assert candidate["sca"] == {
        "ecosystem": "npm",
        "package": "lodash",
        "version": "4.17.20",
        "vuln_ids": ["GHSA-35jh-r3h4-6jhm"],
        "fixed_versions": ["4.17.21"],
        "cvss_score": None,
        "cvss_vector": None,
    }


def test_sca_from_grype_without_help_text_uses_the_rule_id():
    rule = {"id": "CVE-2021-23337-lodash", "properties": {"purls": ["pkg:npm/lodash@4.17.20"]}}
    item = result("CVE-2021-23337-lodash", uri="/package-lock.json")
    sca = only(ingest(sarif(run([item], rules=[rule])), engine="grype"))["sca"]
    assert sca["vuln_ids"] == ["CVE-2021-23337"]
    assert sca["fixed_versions"] == []


def test_sca_from_grype_type_when_there_is_no_purl():
    rule = {
        "id": "CVE-2021-1-requests",
        "help": {"text": "Vulnerability CVE-2021-1\nPackage: requests\nVersion: 1.0\nType: python"},
    }
    item = result("CVE-2021-1-requests", uri="/setup.cfg")
    sca = only(ingest(sarif(run([item], rules=[rule])), engine="grype"))["sca"]
    assert (sca["ecosystem"], sca["package"], sca["version"]) == ("PyPI", "requests", "1.0")


def test_sca_from_govulncheck_tags():
    rule = {
        "id": "GO-2023-2102",
        "properties": {"tags": ["CVE-2023-39325", "GHSA-4374-p667-p6c8", "not-an-id"]},
    }
    item = result("GO-2023-2102", uri="go.mod", line=1)
    sca = only(ingest(sarif(run([item], rules=[rule])), engine="govulncheck"))["sca"]
    assert sca["ecosystem"] == "Go"
    assert (sca["package"], sca["version"]) == ("", "")
    assert sca["vuln_ids"] == ["GO-2023-2102", "CVE-2023-39325", "GHSA-4374-p667-p6c8"]


def test_sca_from_generic_properties():
    item = result(
        "VULN-1",
        uri="Cargo.lock",
        properties={
            "packageName": "openssl",
            "packageVersion": "0.10.40",
            "fixedVersions": ["0.10.55", " 0.10.55 ", ""],
            "aliases": ["RUSTSEC-2023-0044", "CVE-2023-0001"],
            "cvss_score": "7.5",
        },
    )
    sca = only(ingest(sarif(run([item])), engine="osv-scanner"))["sca"]
    assert sca == {
        "ecosystem": "crates.io",
        "package": "openssl",
        "version": "0.10.40",
        "vuln_ids": ["RUSTSEC-2023-0044", "CVE-2023-0001", "VULN-1"],
        "fixed_versions": ["0.10.55"],
        "cvss_score": 7.5,
        "cvss_vector": None,
    }


def test_sca_record_has_the_spec_fields_even_when_nothing_is_known():
    candidate = only(ingest(sarif(run([result("X-1", uri=None)])), engine="osv-scanner"))
    sca = candidate["sca"]
    assert list(sca) == SCA_FIELDS
    assert sca == {
        "ecosystem": "",
        "package": "",
        "version": "",
        "vuln_ids": ["X-1"],
        "fixed_versions": [],
        "cvss_score": None,
        "cvss_vector": None,
    }
    # The candidate schema wants strings for ecosystem, package and version.
    assert validate_candidate(candidate) == []


@pytest.mark.parametrize("score", ["NaN", "inf", "-1", float("nan"), True, "high"])
def test_sca_cvss_score_must_be_a_finite_number(score):
    # JSON has no NaN: the candidate must stay serializable with allow_nan=False.
    rule = {"id": "X-1", "properties": {"security-severity": score, "cvss_score": score}}
    candidate = only(ingest(sarif(run([result("X-1")], rules=[rule])), engine="osv-scanner"))
    assert candidate["sca"]["cvss_score"] is None
    json.dumps(candidate, allow_nan=False)


@pytest.mark.parametrize(
    ("purl", "expected"),
    [
        ("pkg:npm/lodash@4.17.20", ("npm", "lodash", "4.17.20")),
        ("pkg:npm/%40babel/traverse@7.22.5", ("npm", "@babel/traverse", "7.22.5")),
        ("pkg:npm/@babel/traverse@7.22.5", ("npm", "@babel/traverse", "7.22.5")),
        ("pkg:npm/@babel/traverse", ("npm", "@babel/traverse", None)),
        ("pkg:pypi/requests@2.25.1", ("PyPI", "requests", "2.25.1")),
        (
            "pkg:golang/github.com/gin-gonic/gin@v1.9.0",
            ("Go", "github.com/gin-gonic/gin", "v1.9.0"),
        ),
        (
            "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
            ("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1"),
        ),
        (
            "pkg:deb/debian/openssl@3.0.11-1~deb12u2?arch=amd64&distro=debian-12",
            ("Debian", "openssl", "3.0.11-1~deb12u2"),
        ),
        ("pkg:rpm/redhat/curl@7.76.1", ("rpm", "curl", "7.76.1")),
        ("pkg:cargo/openssl@0.10.40#sub/path", ("crates.io", "openssl", "0.10.40")),
        ("pkg:composer/laravel/framework@8.0.0", ("Packagist", "laravel/framework", "8.0.0")),
    ],
)
def test_parse_purl(purl, expected):
    assert _parse_purl(purl) == expected


@pytest.mark.parametrize("purl", ["", "npm/lodash@1", "pkg:", "pkg:npm", "pkg:npm/"])
def test_parse_purl_rejects_other_text(purl):
    assert _parse_purl(purl) is None


@pytest.mark.parametrize(
    ("file", "ecosystem"),
    [
        ("package-lock.json", "npm"),
        ("web/yarn.lock", "npm"),
        ("requirements.txt", "PyPI"),
        ("requirements-dev.txt", "PyPI"),
        ("Pipfile.lock", "PyPI"),
        ("go.mod", "Go"),
        ("Cargo.lock", "crates.io"),
        ("Gemfile.lock", "RubyGems"),
        ("composer.lock", "Packagist"),
        ("pom.xml", "Maven"),
        ("src/App/App.csproj", "NuGet"),
        ("Dockerfile", None),
        ("", None),
    ],
)
def test_manifest_ecosystem(file, ecosystem):
    assert _manifest_ecosystem(file) == ecosystem


# --- ingest_file ----------------------------------------------------------------------------------


def write_doc(path: Path, doc, encoding="utf-8", bom=b""):
    path.write_bytes(bom + json.dumps(doc).encode(encoding))
    return path


def test_ingest_file_reads_a_sarif_file(tmp_path):
    path = write_doc(tmp_path / "bandit.sarif", sarif(run([result("B602")])))
    outcome = ingest_file(path, "bandit", ROOT)
    assert outcome.warnings == []
    assert outcome.candidates[0]["rule_id"] == "B602"
    assert outcome.candidates[0]["raw"]["sarif_file"] == path.as_posix()


def test_ingest_file_accepts_a_string_path(tmp_path):
    path = write_doc(tmp_path / "x.sarif", sarif(run([result()])))
    assert len(ingest_file(str(path), "opengrep", ROOT).candidates) == 1


def test_ingest_file_accepts_a_utf8_bom(tmp_path):
    path = write_doc(tmp_path / "bom.sarif", sarif(run([result()])), bom=b"\xef\xbb\xbf")
    assert len(ingest_file(path, "opengrep", ROOT).candidates) == 1


def test_ingest_file_accepts_utf16_from_windows_powershell(tmp_path):
    path = write_doc(tmp_path / "u16.sarif", sarif(run([result()])), "utf-16")
    assert len(ingest_file(path, "opengrep", ROOT).candidates) == 1


def test_ingest_file_rejects_invalid_json(tmp_path):
    path = tmp_path / "broken.sarif"
    path.write_text('{"version": "2.1.0", "runs": [', encoding="utf-8")
    with pytest.raises(ValidationError, match="not a JSON document"):
        ingest_file(path, "opengrep", ROOT)


def test_ingest_file_rejects_a_large_file(tmp_path, monkeypatch):
    path = write_doc(tmp_path / "big.sarif", sarif(run([result()])))
    monkeypatch.setattr(ingest_module, "MAX_SARIF_BYTES", 16)
    with pytest.raises(UnsafeInputError, match="exceeds 16 byte limit"):
        ingest_file(path, "opengrep", ROOT)


def test_ingest_file_limit_is_50_mib(tmp_path, monkeypatch):
    assert ingest_module.MAX_SARIF_BYTES == 50 * 1024 * 1024
    calls = []
    real = ingest_module.read_bounded

    def spy(path, max_bytes):
        calls.append(max_bytes)
        return real(path, max_bytes)

    monkeypatch.setattr(ingest_module, "read_bounded", spy)
    ingest_file(write_doc(tmp_path / "x.sarif", sarif(run([]))), "opengrep", ROOT)
    assert calls == [50 * 1024 * 1024]


def test_ingest_file_missing_file_raises_unsafe_input_error(tmp_path):
    with pytest.raises(UnsafeInputError):
        ingest_file(tmp_path / "missing.sarif", "opengrep", ROOT)


def test_ingest_file_rejects_a_directory(tmp_path):
    with pytest.raises(UnsafeInputError):
        ingest_file(tmp_path, "opengrep", ROOT)
