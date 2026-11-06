# SPDX-License-Identifier: MIT
"""Tests for kalkan.sca.normalize: OSV-Scanner, Grype and govulncheck outputs (ENGINE-SPEC 17).

The fixtures in tests/fixtures/sca are trimmed copies of real outputs of OSV-Scanner 2.6.0
and Grype 0.119.0 on tests/fixtures/sca/depapp. The govulncheck stream follows the govulncheck
JSON protocol v1.0.0 (crafted: Go is not installed on the development machine).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kalkan.errors import ValidationError
from kalkan.sca.normalize import (
    cvss3_base_score,
    new_record,
    parse_govulncheck,
    parse_govulncheck_text,
    parse_grype,
    parse_osv_scanner,
    primary_id,
    severity_for,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "sca"
DEPAPP = FIXTURES / "depapp"


def osv_doc(root: Path = DEPAPP) -> dict:
    text = (FIXTURES / "osv.json").read_text(encoding="utf-8")
    return json.loads(text.replace("@TARGET@", root.resolve().as_posix()))


def grype_doc() -> dict:
    return json.loads((FIXTURES / "grype.json").read_text(encoding="utf-8"))


def by_ref(records):
    return {record["ref"]: record for record in records}


# --- OSV-Scanner -------------------------------------------------------------------------------


def test_osv_scanner_one_record_per_group():
    result = parse_osv_scanner(osv_doc(), DEPAPP)
    assert result.warnings == []
    refs = by_ref(result.records)
    # The lodash group joins GHSA-35jh-r3h4-6jhm and GHSA-r5fr-rjxr-66jc.
    lodash = refs["npm/lodash@4.17.20/GHSA-35jh-r3h4-6jhm"]
    assert lodash["aliases"] == ["CVE-2021-23337", "CVE-2026-4800", "GHSA-r5fr-rjxr-66jc"]
    assert lodash["engines"] == ["osv-scanner"]
    assert lodash["locations"] == ["package-lock.json"]
    assert lodash["fixed_versions"] == ["4.17.21", "4.18.0"]
    assert lodash["cwe"] == ["CWE-77", "CWE-94"]
    # max_severity 8.1 comes from the CVSS 3.1 vector of GHSA-r5fr (the 3.x score wins).
    assert lodash["cvss_score"] == 8.1
    assert lodash["cvss_vector"].startswith("CVSS:3.1/")
    assert lodash["severity"] == "high"
    assert lodash["tool_severity"] == "8.1"
    assert lodash["reachability"] == "unknown"
    assert lodash["severity_original"] is None


def test_osv_scanner_primary_id_prefers_ghsa_then_cve_then_osv():
    refs = by_ref(parse_osv_scanner(osv_doc(), DEPAPP).records)
    assert "PyPI/pyyaml@5.3/GHSA-6757-jp84-gxfx" in refs
    assert refs["PyPI/pyyaml@5.3/GHSA-6757-jp84-gxfx"]["aliases"] == [
        "CVE-2020-1747",
        "PYSEC-2020-96",
    ]
    # GO-2026-5970 has only a CVE alias: the CVE becomes the primary ID.
    assert "Go/golang.org/x/text@0.3.5/CVE-2026-56852" in refs
    # Go versions lose the "v" prefix; the location is relative to the target.
    jwt = refs["Go/github.com/dgrijalva/jwt-go@3.2.0+incompatible/GHSA-w73w-5m7g-f7qc"]
    assert jwt["locations"] == ["go.mod"]
    assert jwt["fixed_versions"] == []
    assert jwt["affected_symbols"] == [
        {"package": "github.com/dgrijalva/jwt-go", "symbols": ["MapClaims.VerifyAudience"]}
    ]


def test_osv_scanner_label_and_default_severity():
    refs = by_ref(parse_osv_scanner(osv_doc(), DEPAPP).records)
    # GO-2026-5970: no CVSS vector, no database label: medium.
    unscored = refs["Go/golang.org/x/text@0.3.5/CVE-2026-56852"]
    assert unscored["cvss_score"] is None
    assert unscored["severity"] == "medium"
    assert unscored["tool_severity"] == ""


def test_osv_scanner_go_imports_and_ranges():
    refs = by_ref(parse_osv_scanner(osv_doc(), DEPAPP).records)
    text = refs["Go/golang.org/x/text@0.3.5/GHSA-ppp9-7jff-5vj2"]
    assert text["affected_symbols"] == [
        {
            "package": "golang.org/x/text/language",
            "symbols": ["MatchStrings", "MustParse", "Parse", "ParseAcceptLanguage"],
        }
    ]
    assert text["fixed_versions"] == ["0.3.7"]
    assert text["vulnerable_ranges"] == ["<0.3.7"]


def test_osv_scanner_transitive_source_keeps_its_version():
    records = parse_osv_scanner(osv_doc(), DEPAPP).records
    versions = {r["version"] for r in records if r["package"] == "pyyaml"}
    # OSV-Scanner writes 5.3 for the lockfile source and 5.3.0 for the resolved source.
    assert versions == {"5.3", "5.3.0"}
    urllib3 = [r for r in records if r["package"] == "urllib3"]
    assert urllib3 and urllib3[0]["locations"] == ["requirements.txt"]


def test_osv_scanner_source_outside_the_target_warns(tmp_path):
    other = tmp_path / "other"
    other.mkdir()
    result = parse_osv_scanner(osv_doc(), other)
    assert any("not inside the target" in w for w in result.warnings)
    assert all(record["locations"] == [] for record in result.records)


def test_osv_scanner_bad_input():
    with pytest.raises(ValidationError):
        parse_osv_scanner({"matches": []}, DEPAPP)
    doc = {
        "results": [
            "not an object",
            {"source": {"path": "go.mod"}, "packages": [{"package": {"name": "x"}}, 7]},
        ]
    }
    result = parse_osv_scanner(doc, DEPAPP)
    assert result.records == []
    assert len(result.warnings) == 3


def test_osv_scanner_without_groups_uses_one_group_per_entry():
    doc = {
        "results": [
            {
                "source": {"path": "requirements.txt"},
                "packages": [
                    {
                        "package": {"name": "Flask", "version": "0.12", "ecosystem": "PyPI"},
                        "vulnerabilities": [
                            {
                                "id": "PYSEC-2018-66",
                                "aliases": ["CVE-2018-1000656"],
                                "summary": "Flask DoS",
                                "database_specific": {"severity": "HIGH"},
                            }
                        ],
                    }
                ],
            }
        ]
    }
    records = parse_osv_scanner(doc, DEPAPP).records
    assert [r["ref"] for r in records] == ["PyPI/flask@0.12/CVE-2018-1000656"]
    assert records[0]["severity"] == "high"
    assert records[0]["tool_severity"] == "HIGH"


# --- Grype -------------------------------------------------------------------------------------


def test_grype_one_record_per_match():
    result = parse_grype(grype_doc(), DEPAPP)
    assert result.warnings == []
    refs = by_ref(result.records)
    assert len(result.records) == 11
    pyyaml = refs["PyPI/pyyaml@5.3/GHSA-8q59-q68h-6hv4"]
    assert pyyaml["aliases"] == ["CVE-2020-14343"]
    assert pyyaml["engines"] == ["grype"]
    assert pyyaml["locations"] == ["requirements.txt"]
    assert pyyaml["fixed_versions"] == ["5.4"]
    assert pyyaml["vulnerable_ranges"] == ["<5.4"]
    assert pyyaml["cvss_score"] == 9.8
    assert pyyaml["severity"] == "critical"
    assert pyyaml["cwe"] == ["CWE-20"]
    assert pyyaml["summary"] == "Improper Input Validation in PyYAML"


def test_grype_go_versions_and_not_fixed_state():
    refs = by_ref(parse_grype(grype_doc(), DEPAPP).records)
    jwt = refs["Go/github.com/dgrijalva/jwt-go@3.2.0+incompatible/GHSA-w73w-5m7g-f7qc"]
    assert jwt["fixed_versions"] == []
    assert jwt["locations"] == ["go.mod"]
    # GO-2026-5970 has a CVE as the related vulnerability: the CVE is the primary ID.
    assert "Go/golang.org/x/text@0.3.5/CVE-2026-56852" in refs


def test_grype_bad_input():
    with pytest.raises(ValidationError):
        parse_grype({"results": []}, DEPAPP)
    doc = {"matches": [1, {"vulnerability": {"id": "CVE-1"}, "artifact": {"name": "x"}}]}
    result = parse_grype(doc, DEPAPP)
    assert result.records == []
    assert len(result.warnings) == 2


def test_grype_label_without_cvss_and_unknown_label():
    doc = {
        "matches": [
            {
                "vulnerability": {"id": "GHSA-aaaa-bbbb-cccc", "severity": "Low", "cvss": []},
                "artifact": {"name": "a", "version": "1.0.0", "type": "npm"},
            },
            {
                "vulnerability": {"id": "CVE-2026-0001", "severity": "Unknown"},
                "artifact": {"name": "b", "version": "1.0.0", "purl": "pkg:npm/b@1.0.0"},
            },
        ]
    }
    records = parse_grype(doc, DEPAPP).records
    assert [r["severity"] for r in records] == ["low", "medium"]
    assert [r["tool_severity"] for r in records] == ["Low", ""]


# --- govulncheck -------------------------------------------------------------------------------


def test_govulncheck_stream_records_levels_and_traces():
    text = (FIXTURES / "govulncheck.json").read_text(encoding="utf-8")
    result = parse_govulncheck_text(text, "")
    assert result.warnings == []
    assert result.config["scan_level"] == "symbol"
    refs = by_ref(result.records)
    assert set(refs) == {
        "Go/github.com/dgrijalva/jwt-go@3.2.0+incompatible/GHSA-w73w-5m7g-f7qc",
        "Go/golang.org/x/text@0.3.5/GHSA-ppp9-7jff-5vj2",
        "Go/golang.org/x/text@0.3.5/GHSA-69ch-w2m2-3vjp",
    }
    text_record = refs["Go/golang.org/x/text@0.3.5/GHSA-ppp9-7jff-5vj2"]
    assert text_record["engines"] == ["govulncheck"]
    assert text_record["fixed_versions"] == ["0.3.7"]
    assert text_record["locations"] == ["go.mod"]
    assert text_record["severity"] == "medium"
    assert result.levels == {
        ("github.com/dgrijalva/jwt-go", "GO-2020-0017"): "module",
        ("golang.org/x/text", "GO-2021-0113"): "symbol",
        ("golang.org/x/text", "GO-2022-1059"): "package",
    }
    trace = result.traces[("golang.org/x/text", "GO-2021-0113")][0]
    assert trace[0]["function"] == "Parse"
    assert trace[0]["file"] == ""  # a dependency position is not a target file
    assert trace[1]["file"] == "main.go"
    assert trace[1]["line"] == 12


def test_govulncheck_module_dir_prefixes_paths():
    text = (FIXTURES / "govulncheck.json").read_text(encoding="utf-8")
    result = parse_govulncheck_text(text, "services/api")
    assert all(r["locations"] == ["services/api/go.mod"] for r in result.records)
    trace = result.traces[("golang.org/x/text", "GO-2021-0113")][0]
    assert trace[1]["file"] == "services/api/main.go"


def test_govulncheck_broken_stream_and_bad_messages():
    result = parse_govulncheck_text('{"config": {}}\n{"finding": ', "")
    assert result.records == []
    assert any("broken" in w for w in result.warnings)
    result = parse_govulncheck([1, {"finding": {"osv": "GO-1"}}], "")
    assert len(result.warnings) == 2


# --- severity and IDs --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("vector", "score"),
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", 7.2),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
        ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8),
        ("CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:N/I:N/A:L", 2.6),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ],
)
def test_cvss3_base_score(vector, score):
    assert cvss3_base_score(vector) == score


def test_cvss3_base_score_rejects_other_text():
    assert (
        cvss3_base_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N") is None
    )
    assert cvss3_base_score("AV:N/AC:L/Au:N/C:P/I:P/A:P") is None
    assert cvss3_base_score("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") is None
    assert cvss3_base_score(None) is None


def test_severity_for_precedence():
    assert severity_for(9.8, "LOW") == ("critical", "9.8")
    assert severity_for(7.0, "") == ("high", "7.0")
    assert severity_for(None, "MODERATE") == ("medium", "MODERATE")
    assert severity_for(0.0, "Negligible") == ("info", "Negligible")
    assert severity_for(None, "Unknown") == ("medium", "")
    assert severity_for(None, "") == ("medium", "")


def test_primary_id():
    assert primary_id(["PYSEC-2020-96", "CVE-2020-1747", "GHSA-6757-jp84-gxfx"]) == (
        "GHSA-6757-jp84-gxfx"
    )
    assert primary_id(["GO-2026-5970", "CVE-2026-56852"]) == "CVE-2026-56852"
    assert primary_id(["GO-2020-0017"], "GO-2020-0017") == "GO-2020-0017"
    assert primary_id(["GHSA-r5fr-rjxr-66jc", "GHSA-35jh-r3h4-6jhm"]) == "GHSA-35jh-r3h4-6jhm"
    assert primary_id([]) == ""


def test_new_record_shape():
    record = new_record(
        ecosystem="PyPI",
        package="PyYAML",
        version="5.3",
        ids=["PYSEC-2021-142", "GHSA-8q59-q68h-6hv4", "CVE-2020-14343", "GHSA-8q59-q68h-6hv4"],
        cvss_score=9.8,
        engine="osv-scanner",
        cwe=["cwe-020", "NVD-CWE-noinfo"],
        locations=["requirements.txt", "requirements.txt"],
    )
    assert record["ref"] == "PyPI/pyyaml@5.3/GHSA-8q59-q68h-6hv4"
    assert record["aliases"] == ["CVE-2020-14343", "PYSEC-2021-142"]
    assert record["cwe"] == ["CWE-20"]
    assert record["locations"] == ["requirements.txt"]
    assert record["severity"] == "critical"


def test_govulncheck_invocation_markers_split_modules():
    fixture = (FIXTURES / "govulncheck.json").read_text(encoding="utf-8")
    second = {
        "finding": {
            "osv": "GO-2020-0017",
            "trace": [
                {
                    "module": "github.com/dgrijalva/jwt-go",
                    "version": "v3.2.0+incompatible",
                    "package": "github.com/dgrijalva/jwt-go",
                    "function": "VerifyAudience",
                    "receiver": "MapClaims",
                },
                {
                    "module": "example.com/svc",
                    "package": "example.com/svc",
                    "function": "check",
                    "position": {"filename": "auth.go", "offset": 10, "line": 7, "column": 2},
                },
            ],
        }
    }
    stream = "\n".join(
        [
            json.dumps({"kalkan_invocation": {"index": 0, "label": ".", "dir": None}}),
            fixture,
            json.dumps({"kalkan_invocation": {"index": 1, "label": "svc", "dir": "svc"}}),
            json.dumps({"SBOM": {"roots": ["example.com/svc"]}}),
            json.dumps(second, indent=2),
        ]
    )
    result = parse_govulncheck_text(stream, "")
    assert result.warnings == []
    key = ("github.com/dgrijalva/jwt-go", "GO-2020-0017")
    assert result.levels[key] == "symbol"
    assert result.traces[key][0][1]["file"] == "svc/auth.go"
    jwt = next(r for r in result.records if r["package"] == "github.com/dgrijalva/jwt-go")
    assert jwt["locations"] == ["go.mod", "svc/go.mod"]
    # The first module keeps its paths at the target root.
    assert result.traces[("golang.org/x/text", "GO-2021-0113")][0][1]["file"] == "main.go"
