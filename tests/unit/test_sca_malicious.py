# SPDX-License-Identifier: MIT
"""Malicious packages in SCA (ADR-0005, K.2; ENGINE-SPEC 17).

``tests/fixtures/sca/malicious`` holds trimmed copies of the real outputs of OSV-Scanner 2.6.0
and Grype 0.119.0 on 2026-10-25 (local databases of 2026-10-16) for two PyPI packages that the
OpenSSF malicious-packages data lists: ``sample-module`` 0.0.1 (MAL-2025-41758) and
``test-async`` (MAL-2022-7428). OSV-Scanner reports the ``MAL-`` records. Grype reports the GitHub
malware advisories (GHSA IDs): the first one links its ``MAL-`` record, the second one does not.
Nothing installs or runs these packages.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kalkan.findings.validate import validate_candidate
from kalkan.sca.merge import (
    MALICIOUS_REMEDIATION,
    build_candidates,
    carry_over,
    merge_records,
    read_vulns,
    set_reachability,
    validate_vulns,
    write_vulns,
)
from kalkan.sca.normalize import (
    MALICIOUS_CLASS,
    MALICIOUS_REACHABILITY_REASON,
    GovulncheckResult,
    is_malicious,
    is_malicious_id,
    malicious_ids,
    malware_title,
    new_record,
    parse_grype,
    parse_osv_scanner,
    primary_id,
)
from kalkan.sca.reach import apply_govulncheck, select_for_agents

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "sca" / "malicious"
APP = FIXTURES / "app"
LINK = (
    "https://github.com/ossf/malicious-packages/blob/49d0cfba3689ed9b195d101d3a2a964c6a77f767/"
    "osv/malicious/pypi/sample-module/MAL-2025-41758.json"
)


def osv_records() -> list[dict]:
    text = (FIXTURES / "osv.json").read_text(encoding="utf-8")
    doc = json.loads(text.replace("@TARGET@", APP.resolve().as_posix()))
    return parse_osv_scanner(doc, APP).records


def grype_records() -> list[dict]:
    doc = json.loads((FIXTURES / "grype.json").read_text(encoding="utf-8"))
    return parse_grype(doc, APP).records


def by_package(records: list[dict]) -> dict[str, dict]:
    return {record["package"]: record for record in records}


def go_record(**overrides) -> dict:
    values = {
        "ecosystem": "Go",
        "package": "github.com/example/evil",
        "version": "1.0.0",
        "ids": ["MAL-2024-0001"],
        "engine": "osv-scanner",
        "locations": ["go.mod"],
    }
    values.update(overrides)
    return new_record(**values)


# --- detection ---------------------------------------------------------------------------------


def test_helpers_recognize_the_malware_signals():
    assert is_malicious_id("MAL-2025-41758")
    assert is_malicious_id(" mal-2025-41758 ")
    assert not is_malicious_id("GHSA-2g5x-c76j-3h73")
    assert not is_malicious_id("MAL-25-1")
    assert malicious_ids([LINK, "https://github.com/advisories/GHSA-2g5x-c76j-3h73", LINK]) == [
        "MAL-2025-41758"
    ]
    assert malicious_ids(["https://example.com/MAL-2025-41758.json", None, 7]) == []
    assert malware_title("Malicious code in sample-module (PyPI)")
    assert malware_title("Malicious code in @scope/pkg (npm)")
    assert not malware_title("test-async malicious PyPI package")
    assert not malware_title("Malicious code injection in the template engine")


def test_primary_id_prefers_the_mal_id():
    assert primary_id(["GHSA-cg89-rrrm-gf58", "MAL-2022-7428"]) == "MAL-2022-7428"
    assert primary_id(["MAL-2025-41758", "GHSA-2g5x-c76j-3h73", "CVE-2025-1"]) == "MAL-2025-41758"


def test_osv_scanner_mal_records_become_malicious():
    records = by_package(osv_records())
    sample = records["sample-module"]
    assert sample["ref"] == "PyPI/sample-module@0.0.1/MAL-2025-41758"
    assert sample["class"] == MALICIOUS_CLASS
    assert sample["severity"] == "critical"
    assert sample["tool_severity"] == "malicious package"
    assert sample["fixed_versions"] == []
    assert sample["reachability"] == "unknown"
    assert sample["reachability_reason"] == MALICIOUS_REACHABILITY_REASON
    # The GHSA alias does not win: the MAL- ID names the malicious version.
    assert records["test-async"]["vuln_id"] == "MAL-2022-7428"
    assert records["test-async"]["aliases"] == ["GHSA-cg89-rrrm-gf58"]


def test_grype_malware_advisory_link_adds_the_mal_id():
    records = by_package(grype_records())
    sample = records["sample-module"]
    assert sample["vuln_id"] == "MAL-2025-41758"
    assert sample["aliases"] == ["GHSA-2g5x-c76j-3h73"]
    assert sample["class"] == MALICIOUS_CLASS
    assert sample["severity"] == "critical"
    # Without a link and without the GitHub malware title Grype alone cannot tell.
    assert "class" not in records["test-async"]
    assert records["test-async"]["severity"] == "high"


def test_grype_malware_title_alone_marks_the_record():
    doc = json.loads((FIXTURES / "grype.json").read_text(encoding="utf-8"))
    match = doc["matches"][0]
    match["vulnerability"]["urls"] = []
    match["vulnerability"]["severity"] = "Medium"
    record = parse_grype({"matches": [match]}, APP).records[0]
    assert record["vuln_id"] == "GHSA-2g5x-c76j-3h73"
    assert record["class"] == MALICIOUS_CLASS
    assert record["severity"] == "critical"


def test_an_ordinary_record_stays_a_vulnerable_dependency():
    record = new_record(
        ecosystem="npm",
        package="lodash",
        version="4.17.20",
        ids=["GHSA-35jh-r3h4-6jhm"],
        label="High",
        engine="grype",
    )
    assert "class" not in record
    assert not is_malicious(record)
    assert record["reachability_reason"] == ""


# --- merge -------------------------------------------------------------------------------------


def test_osv_and_grype_join_into_one_malicious_record():
    merged = by_package(merge_records([*osv_records(), *grype_records()]))
    assert len(merged) == 2
    sample = merged["sample-module"]
    assert sample["ref"] == "PyPI/sample-module@0.0.1/MAL-2025-41758"
    assert sample["engines"] == ["osv-scanner", "grype"]
    assert sample["aliases"] == ["GHSA-2g5x-c76j-3h73"]
    # test-async: the GHSA alias of the OSV record joins the Grype record (severity high).
    other = merged["test-async"]
    assert other["engines"] == ["osv-scanner", "grype"]
    assert other["class"] == MALICIOUS_CLASS
    assert other["severity"] == "critical"
    assert other["tool_severity"] == "malicious package"
    assert (
        validate_vulns({"schema_version": 1, "records": list(merged.values()), "warnings": []})
        == []
    )


def test_a_mal_id_of_one_input_makes_the_merged_record_malicious():
    grype = new_record(
        ecosystem="PyPI",
        package="test-async",
        version="1.0.0",
        ids=["GHSA-cg89-rrrm-gf58"],
        label="Low",
        engine="grype",
    )
    osv = new_record(
        ecosystem="PyPI",
        package="test-async",
        version="1.0.0",
        ids=["GHSA-cg89-rrrm-gf58"],
        engine="osv-scanner",
    )
    osv["aliases"].append("MAL-2022-7428")  # an old record without the class field
    [merged] = merge_records([grype, osv])
    assert merged["vuln_id"] == "MAL-2022-7428"
    assert merged["class"] == MALICIOUS_CLASS
    assert merged["severity"] == "critical"


# --- reachability ------------------------------------------------------------------------------


def test_malicious_records_get_no_reach_task():
    records = merge_records([*osv_records(), *grype_records()])
    ordinary = new_record(
        ecosystem="PyPI",
        package="pyyaml",
        version="5.3",
        ids=["GHSA-6757-jp84-gxfx"],
        cvss_score=9.8,
        engine="osv-scanner",
    )
    selected = select_for_agents([*records, ordinary], remaining_budget=10, max_tasks=10)
    assert [record["ref"] for record in selected] == [ordinary["ref"]]


def test_set_reachability_never_lowers_a_malicious_record():
    [record] = [r for r in osv_records() if r["package"] == "sample-module"]
    set_reachability(
        record,
        "not_reachable",
        reason="the only import is in a test",
        source="sca_reach",
        searched=["import sample_module"],
    )
    assert record["reachability"] == "unknown"
    assert record["severity"] == "critical"
    assert record["severity_original"] is None
    assert record["reachability_reason"] == (
        f"{MALICIOUS_REACHABILITY_REASON}: the only import is in a test"
    )
    assert validate_vulns({"schema_version": 1, "records": [record], "warnings": []}) == []


def test_carry_over_leaves_malicious_records_alone():
    [old] = [r for r in osv_records() if r["package"] == "sample-module"]
    old.pop("class")
    old["aliases"] = []
    old["vuln_id"] = "GHSA-2g5x-c76j-3h73"  # a run before K.2 with a lowered GHSA record
    old["ref"] = "PyPI/sample-module@0.0.1/GHSA-2g5x-c76j-3h73"
    old.update(severity="high", severity_original="critical", reachability="not_reachable")
    new = merge_records([*osv_records(), *grype_records()])
    assert carry_over(new, [old]) == 0
    sample = by_package(new)["sample-module"]
    assert (sample["severity"], sample["reachability"]) == ("critical", "unknown")


def test_govulncheck_leaves_malicious_go_records_alone():
    record = go_record()
    result = GovulncheckResult(levels={("github.com/example/evil", "MAL-2024-0001"): "module"})
    counts = apply_govulncheck([record], result)
    assert counts == {"reachable": 0, "not_reachable": 0, "unchanged": 1}
    assert record["reachability"] == "unknown"
    assert record["severity"] == "critical"


def test_validate_vulns_rejects_a_lowered_malicious_record():
    record = go_record()
    record.update(severity="high", severity_original="critical", reachability="not_reachable")
    errors = validate_vulns({"schema_version": 1, "records": [record], "warnings": []})
    assert errors == ["$.records[0]: a malicious-dependency record stays critical"]


# --- vulns.json and candidates -----------------------------------------------------------------


def test_vulns_json_keeps_the_class(tmp_path):
    records = merge_records([*osv_records(), *grype_records()])
    write_vulns(tmp_path, records, [])
    doc = read_vulns(tmp_path)
    assert {record["class"] for record in doc["records"]} == {MALICIOUS_CLASS}


def test_malicious_candidates():
    records = merge_records([*osv_records(), *grype_records()])
    candidates = {c["sca"]["package"]: c for c in build_candidates(records, APP)}
    sample = candidates["sample-module"]
    assert validate_candidate(sample) == []
    assert sample["class"] == MALICIOUS_CLASS
    assert sample["cwe"] == ["CWE-506"]
    assert sample["severity"] == "critical"
    assert sample["rule_id"] == "MAL-2025-41758"
    assert sample["title"] == "Malicious code in sample-module (PyPI)"
    assert "malicious" in sample["tags"]
    assert sample["file"] == "requirements.txt"
    assert sample["start_line"] == 1
    assert sample["message"].startswith(
        "sample-module 0.0.1 (PyPI) is a known malicious package version: MAL-2025-41758 "
        "(also known as GHSA-2g5x-c76j-3h73). Remove the package"
    )
    assert MALICIOUS_REMEDIATION in sample["message"]
    assert "Fixed in" not in sample["message"] and "No fixed version" not in sample["message"]
    # test-async has the CWE-506 of its OSV record once.
    assert candidates["test-async"]["cwe"] == ["CWE-506"]


@pytest.mark.parametrize("summary", ["", "  "])
def test_a_malicious_candidate_without_a_summary_names_the_package(summary):
    record = go_record(summary=summary)
    [candidate] = build_candidates([record], None)
    assert candidate["title"] == "Malicious package: github.com/example/evil 1.0.0"
