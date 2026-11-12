# SPDX-License-Identifier: MIT
"""Tests for the ``report`` command, the SARIF output and summary.json."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from kalkan.cli import main
from kalkan.findings.fingerprint import FINGERPRINT_KEY
from kalkan.findings.merge import merge_run
from kalkan.report.commands import parse_formats, write_report
from kalkan.report.model import build_model
from kalkan.report.summary import (
    CANDIDATE_FINGERPRINT_KEY,
    SCA_FINGERPRINT_KEY,
    build_sarif,
    build_summary,
)

GOLDEN = Path(__file__).resolve().parents[1] / "golden" / "report"
RUN_ID = "20261015T120000Z-shop-a1b2"


@pytest.fixture
def runs(tmp_path, monkeypatch) -> Path:
    shutil.copytree(GOLDEN / "run" / RUN_ID, tmp_path / RUN_ID)
    monkeypatch.setenv("KALKAN_RUNS_DIR", str(tmp_path))
    return tmp_path


def model_of(run: Path):
    return build_model(
        run, generated_at="2026-10-15T12:30:00Z", installed_tools=GOLDEN / "installed.json"
    )


def check_sarif(document: dict) -> None:
    assert document["version"] == "2.1.0"
    assert document["$schema"].endswith("sarif-schema-2.1.0.json")
    assert len(document["runs"]) == 1
    run = document["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    ids = [rule["id"] for rule in rules]
    assert len(ids) == len(set(ids))
    for result in run["results"]:
        assert rules[result["ruleIndex"]]["id"] == result["ruleId"]
        assert result["level"] in ("error", "warning", "note", "none")
        assert result["message"]["text"]
        for location in result.get("locations", []):
            artifact = location["physicalLocation"]["artifactLocation"]
            assert artifact["uriBaseId"] == "%SRCROOT%"
            assert not artifact["uri"].startswith(("/", "..")) and "\\" not in artifact["uri"]


def test_cli_merge_then_report_tr_and_en(runs, capsys):
    assert main(["merge", "--run", RUN_ID]) == 0
    assert main(["report", "--run", RUN_ID, "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    names = [item["path"] for item in result["files"]]
    assert names == [
        "report/REPORT.md",
        "report/REPORT.html",
        "report/EXECUTIVE.html",
        "report/findings.sarif",
        "report/sbom.cdx.json",
        "report/sbom.spdx.json",
        "report/findings.json",
        "report/summary.json",
    ]
    assert result["findings"] == {"confirmed": 2, "needs_validation": 1, "rejected": 1}
    assert all(item["bytes"] > 0 for item in result["files"])
    assert main(["report", "--run", RUN_ID, "--lang", "en"]) == 0
    report = runs / RUN_ID / "report"
    assert (report / "REPORT.en.md").is_file() and (report / "REPORT.en.html").is_file()
    assert (report / "EXECUTIVE.en.html").is_file()
    summary = json.loads((report / "summary.json").read_text(encoding="utf-8"))
    assert summary["lang"] == "en"
    assert summary["paths"]["report_en_md"] == "report/REPORT.en.md"
    assert summary["paths"]["report_md"] == "report/REPORT.md"
    assert summary["paths"]["executive_html"] == "report/EXECUTIVE.html"
    assert summary["paths"]["executive_en_html"] == "report/EXECUTIVE.en.html"
    assert summary["paths"]["sbom_cyclonedx"] == "report/sbom.cdx.json"
    assert summary["paths"]["sbom_spdx"] == "report/sbom.spdx.json"
    copied = json.loads((report / "findings.json").read_text(encoding="utf-8"))
    original = json.loads((runs / RUN_ID / "findings.json").read_text(encoding="utf-8"))
    assert copied == original


def test_formats_option(runs, capsys):
    assert main(["report", "--run", RUN_ID, "--formats", "md"]) == 0
    assert sorted(path.name for path in (runs / RUN_ID / "report").iterdir()) == ["REPORT.md"]
    assert "wrote report/REPORT.md" in capsys.readouterr().err
    assert main(["report", "--run", RUN_ID, "--formats", "pdf"]) == 2
    assert "unknown format" in capsys.readouterr().err


def test_parse_formats():
    assert parse_formats("json, MD") == ["md", "json"]
    assert parse_formats("exec,html") == ["html", "exec"]
    with pytest.raises(ValueError):
        parse_formats(" , ")


def test_report_on_a_run_without_findings_still_works(runs):
    # No merge: findings.json is missing; the report renders what exists.
    assert main(["report", "--run", RUN_ID]) == 0
    text = (runs / RUN_ID / "report" / "REPORT.md").read_text(encoding="utf-8")
    assert "`findings.json` yok" in text
    summary = json.loads((runs / RUN_ID / "report" / "summary.json").read_text(encoding="utf-8"))
    assert "findings.json" in summary["missing_inputs"]


def test_sarif_has_findings_and_sca_results(runs):
    run = runs / RUN_ID
    merge_run(run)
    model = model_of(run)
    document = build_sarif(model)
    check_sarif(document)
    results = document["runs"][0]["results"]
    assert len(results) == len(model.findings) + len(model.sca)
    findings = [r for r in results if "findingId" in r["properties"]]
    for result in findings:
        digest = result["partialFingerprints"][FINGERPRINT_KEY]
        assert "KF-" + digest[:16].upper() == result["properties"]["findingId"]
    sca = [r for r in results if r["properties"].get("kind") == "sca"]
    assert [r["properties"]["package"] for r in sca] == [
        "sample-module",
        "pyyaml",
        "lodash",
        "jquery",
        "requests",
    ]
    malicious, sca = sca[0], sca[1:]
    assert malicious["ruleId"] == "MAL-2025-41758"
    assert malicious["level"] == "error"
    assert malicious["properties"]["class"] == "malicious-dependency"
    assert malicious["properties"]["malicious"] is True
    assert malicious["message"]["text"].startswith(
        "sample-module 0.0.1 (PyPI) is a known malicious package version: MAL-2025-41758. "
        "Remove the package and this version"
    )
    rule = document["runs"][0]["tool"]["driver"]["rules"][malicious["ruleIndex"]]
    assert rule["properties"]["tags"] == ["security", "sca", "malicious", "external/cwe/cwe-506"]
    assert sca[1]["properties"]["pinSource"] == "manifest"
    assert "pinSource" not in sca[0]["properties"]
    assert sca[2]["properties"]["pinSource"] == "vendored"
    assert sca[2]["properties"]["vendoredFiles"] == ["web/static/js/jquery.min.js"]
    assert sca[2]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == (
        "web/static/js/jquery.min.js"
    )
    pyyaml = sca[0]
    assert pyyaml["ruleId"] == "GHSA-8q59-q68h-6hv4"
    assert pyyaml["level"] == "error"
    assert pyyaml["properties"]["reachability"] == "reachable"
    assert pyyaml["properties"]["vulnIds"] == ["GHSA-8q59-q68h-6hv4", "CVE-2020-14343"]
    assert pyyaml["properties"]["security-severity"] == "9.5"
    assert len(pyyaml["partialFingerprints"][SCA_FINGERPRINT_KEY]) == 64
    assert pyyaml["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == (
        "requirements.txt"
    )
    assert sca[3]["level"] == "note"
    rejected = [r for r in results if r["properties"].get("verdict") == "rejected"]
    assert rejected and rejected[0]["suppressions"][0]["kind"] == "external"
    assert not any(r["properties"].get("kind") == "candidate" for r in results)


def test_sarif_with_candidates(runs):
    run = runs / RUN_ID
    merge_run(run)
    model = model_of(run)
    document = build_sarif(model, include_candidates=True)
    check_sarif(document)
    results = document["runs"][0]["results"]
    candidates = [r for r in results if r["properties"].get("kind") == "candidate"]
    assert len(candidates) == len(model.tool_results) == 2
    assert {r["ruleId"] for r in candidates} == {"bandit/B506", "gitleaks/generic-api-key"}
    for result in candidates:
        assert result["properties"]["verdict"] == "unverified"
        assert result["partialFingerprints"][CANDIDATE_FINGERPRINT_KEY].startswith("CAND-")
    assert len(results) == len(model.findings) + len(model.sca) + 2


def test_cli_include_candidates(runs):
    assert main(["merge", "--run", RUN_ID]) == 0
    assert main(["report", "--run", RUN_ID, "--formats", "sarif", "--include-candidates"]) == 0
    document = json.loads((runs / RUN_ID / "report" / "findings.sarif").read_text("utf-8"))
    check_sarif(document)
    assert len(document["runs"][0]["results"]) == 4 + 5 + 2


def test_summary_document(runs):
    run = runs / RUN_ID
    merge_run(run)
    model = model_of(run)
    summary = build_summary(model, lang="tr", paths={"report_md": "report/REPORT.md"})
    assert summary["schema_version"] == 1
    assert summary["counts"]["by_verdict"] == {
        "confirmed": 2,
        "needs_validation": 1,
        "rejected": 1,
    }
    assert summary["counts"]["tool_results_by_engine"] == {
        "bandit": {"medium": 1},
        "gitleaks": {"high": 1},
    }
    assert summary["counts"]["sca_by_reachability"] == {
        "reachable": 1,
        "not_reachable": 1,
        "unknown": 3,
    }
    assert summary["counts"]["sca"] == 5
    assert summary["counts"]["sca_malicious"] == 1
    assert summary["malicious_dependencies"] == [
        {
            "ecosystem": "PyPI",
            "package": "sample-module",
            "version": "0.0.1",
            "vuln_ids": ["MAL-2025-41758", "GHSA-2g5x-c76j-3h73"],
            "locations": ["requirements.txt"],
        }
    ]
    gaps = summary["coverage_gaps"]
    assert [item["file"] for item in gaps["unchecked_manifests"]] == ["web/package.json"]
    assert gaps["engines"] == {
        "opengrep": {"partial_files": 1, "skipped_files": 1, "partial_packages": 0}
    }
    assert gaps["long_paths"] == 1 and gaps["sca_from_manifest_pins"] == 1
    assert gaps["sca_from_vendored_files"] == 1
    assert summary["sbom"] == {
        "components": 5,
        "by_source": {"syft": 3, "manifest-pin": 1, "vendored": 1},
    }
    assert summary["coverage"] == {
        "units": 5,
        "open": 1,
        "by_status": {"candidate": 2, "covered": 1, "deferred": 1, "not_applicable": 1},
        "closed_by_siblings": 0,
    }
    assert summary["partial"] is True
    assert summary["partial_reasons"] == [
        {"code": "ledger_open", "n": 1},
        {"code": "unchecked_manifests", "n": 1},
    ]
    assert summary["paths"] == {"report_md": "report/REPORT.md"}
    assert [engine["engine"] for engine in summary["engines"]][:3] == [
        "bandit",
        "gitleaks",
        "opengrep",
    ]


def test_write_report_returns_paths(runs):
    run = runs / RUN_ID
    merge_run(run)
    written = write_report(run, model_of(run), lang="en", formats=["md", "html"])
    assert [path.name for path in written] == ["REPORT.en.md", "REPORT.en.html"]


def test_the_run_language_gets_the_plain_file_names(runs):
    run = runs / RUN_ID
    merge_run(run)
    state_path = run / "state.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    state["options"]["lang"] = "en"
    state_path.write_text(json.dumps(state), encoding="utf-8")
    written = write_report(run, model_of(run), formats=["md", "html", "exec"])
    assert [path.name for path in written] == ["REPORT.md", "REPORT.html", "EXECUTIVE.html"]
    other = write_report(run, model_of(run), lang="tr", formats=["md", "html", "exec"])
    assert [path.name for path in other] == ["REPORT.tr.md", "REPORT.tr.html", "EXECUTIVE.tr.html"]
    page = (run / "report" / "EXECUTIVE.tr.html").read_text(encoding="utf-8")
    assert 'href="REPORT.tr.html#' in page and 'href="REPORT.html#' not in page
