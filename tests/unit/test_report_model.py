# SPDX-License-Identifier: MIT
"""Tests for kalkan.report.model: the report data model built from a run folder."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from kalkan.findings.merge import merge_run
from kalkan.report.model import build_model, class_title, clean, fmt_ts, localized, location_of
from kalkan.report.render_html import render_html
from kalkan.report.render_md import render_markdown

GOLDEN = Path(__file__).resolve().parents[1] / "golden" / "report"
RUN_ID = "20261015T120000Z-shop-a1b2"


@pytest.fixture
def run(tmp_path) -> Path:
    target = tmp_path / RUN_ID
    shutil.copytree(GOLDEN / "run" / RUN_ID, target)
    merge_run(target)
    return target


def model_of(path: Path, **kwargs):
    kwargs.setdefault("generated_at", "2026-10-15T12:30:00Z")
    kwargs.setdefault("installed_tools", GOLDEN / "installed.json")
    return build_model(path, **kwargs)


def edit_json(path: Path, change) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    data = change(data) or data
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def test_model_of_the_sample_run(run):
    model = model_of(run)
    assert model.run_id == RUN_ID
    assert model.state_available and model.complete
    assert model.profile == "standard" and model.run_lang == "tr"
    assert model.tech == ["docker", "flask", "python"]
    assert model.verdict_counts() == {"confirmed": 2, "needs_validation": 1, "rejected": 1}
    assert model.severity_counts()["high"] == 1
    assert model.highest_severity() == "high"
    # The linked opengrep candidate and the SCA candidate are not tool results.
    assert sorted(item["engine"] for item in model.tool_results) == ["bandit", "gitleaks"]
    assert model.candidates_total == 4
    assert model.sca_source == "vulns"
    # The known malicious package version comes first (ENGINE-SPEC 16).
    assert [record.package for record in model.sca] == [
        "sample-module",
        "pyyaml",
        "lodash",
        "jquery",
        "requests",
    ]
    [malicious] = model.sca_malicious()
    assert (malicious.package, malicious.severity, malicious.malicious) == (
        "sample-module",
        "critical",
        True,
    )
    assert malicious.ids == ("MAL-2025-41758", "GHSA-2g5x-c76j-3h73")
    assert [record.package for record in model.sca_vulnerable()] == [
        "pyyaml",
        "lodash",
        "jquery",
        "requests",
    ]
    assert model.sca_reachable() == 1
    assert model.sca_from_pins() == 1
    assert [record.pin_source for record in model.sca] == [None, None, "manifest", "vendored", None]
    [vendored] = model.sca_vendored()
    assert vendored.vendored_files == ("web/static/js/jquery.min.js",)
    assert model.sbom is not None and len(model.sbom.components) == 5
    assert model.sbom.by_source() == {"syft": 3, "manifest-pin": 1, "vendored": 1}
    assert model.outputs == ()  # write_report fills it
    assert [(m.file, m.ecosystem, m.exact_pins, m.ranges) for m in model.unchecked_manifests] == [
        ("web/package.json", "npm", 1, 2)
    ]
    [gap] = model.scan_gaps
    assert (gap.engine, gap.partial_count, gap.skipped_count) == ("opengrep", 1, 1)
    assert gap.partial_paths == ("app/helpers.py",)
    assert gap.skipped_reasons == (("files larger than 1.0 MB", 1),)
    assert model.long_paths is not None and model.long_paths["count"] == 1
    assert model.long_paths["long_paths_enabled"] is True
    assert len(model.hardening) == 2
    assert model.ledger == {"candidate": 2, "covered": 1, "deferred": 1, "not_applicable": 1}
    assert model.ledger_total == 5 and model.ledger_open == 1
    assert [engine.engine for engine in model.engines] == [
        "bandit",
        "gitleaks",
        "opengrep",
        "trivy",
        "grype",
        "osv-scanner",
        "retirejs",
        "syft",
    ]
    assert model.budget == {"max": 150, "used": 13}
    assert model.review_counts() == {
        "reviewed": 2,
        "verified": 1,
        "downgrade": 1,
        "reject": 0,
        "not_reviewed": 1,
    }
    assert model.partial_reasons == [
        ("partial_ledger_open", {"n": 1}),
        ("partial_unchecked_manifests", {"n": 1}),
    ]
    assert model.missing == []
    [warning] = model.warnings
    assert "absolute path of 260 or more characters: 1" in warning
    assert "Opengrep may skip them" in warning
    assert model.tool_versions[0] == ("bandit", "1.9.4", "pip")


def test_empty_run_folder_reports_every_missing_input(tmp_path):
    folder = tmp_path / RUN_ID
    folder.mkdir()
    model = model_of(folder, installed_tools=tmp_path / "none.json")
    assert model.missing == [
        "state.json",
        "target-manifest.json",
        "findings.json",
        "candidates.json",
        "sca/vulns.json",
        "scans/*.status.json",
        "coverage-ledger.json",
        ".tools/installed.json",
    ]
    assert model.partial_reasons == [("partial_no_state", {})]
    assert not model.complete
    markdown = render_markdown(model, "tr")
    assert "`findings.json` yok" in markdown
    assert "`state.json` yok" in markdown
    assert "`candidates.json` yok" in markdown
    assert "`sca/vulns.json` yok" in markdown
    page = render_html(model, "en")
    assert "<code>findings.json</code> is missing" in page


def test_partial_reasons_for_quick_budget_incomplete_and_dead_tasks(run):
    def change(state):
        state["options"]["profile"] = "fast"
        state["budget"]["max_agent_tasks"] = 40
        state["budget"]["used_agent_tasks"] = 40
        state["phase"] = "hunt"
        state["incomplete_reason"] = "usage limit"
        state["tasks"]["T0001-recon"]["status"] = "dead"

    edit_json(run / "state.json", change)
    model = model_of(run)
    codes = [code for code, _ in model.partial_reasons]
    assert codes == [
        "partial_fast",
        "partial_budget",
        "partial_not_done",
        "partial_reason",
        "partial_ledger_open",
        "partial_dead_tasks",
        "partial_unchecked_manifests",
    ]
    markdown = render_markdown(model, "tr")
    assert "Kısmi geçiş (partial pass)" in markdown
    assert "`fast` profili kullanıldı. Bu profil en çok 40 ajan görevi" in markdown
    assert "Ajan görevi bütçesi doldu: 40 / 40." in markdown
    assert "Son aşama: Avlanma (hunt)." in markdown


def test_sibling_closures_are_counted_and_noted(run):
    def change(units):
        check = {"agent_id": "t0009-critic", "reviewed_paths": ["app/routes.py"]}
        closure = {"task": "T0009-critic", "covered_by": ["unit-1"]}
        units[3].update(status="covered", local_checks=[check], kalkan={"closure": closure})
        # A stale closure: the live checks no longer hold the critic check.
        units[0].update(local_checks=[], kalkan={"closure": closure})

    edit_json(run / "coverage-ledger.json", change)
    model = model_of(run)
    assert model.ledger == {"candidate": 2, "covered": 2, "not_applicable": 1}
    assert model.ledger_open == 0 and model.ledger_sibling_closed == 1
    assert "partial_ledger_open" not in [code for code, _ in model.partial_reasons]
    markdown = render_markdown(model, "tr")
    assert "1 birim önce Engellendi (blocked) durumundaydı. Critic bu birimleri kapattı" in markdown
    assert "closed from sibling coverage: 1." in render_markdown(model, "en")
    assert "Engine her alıntıyı kaynak kodla karşılaştırdı." in render_html(model, "tr")


def test_no_sibling_note_without_closures(run):
    model = model_of(run)
    assert model.ledger_sibling_closed == 0
    assert "Engellendi (blocked) durumundaydı" not in render_markdown(model, "tr")


def test_invalid_state_is_still_read_with_a_warning(run):
    edit_json(run / "state.json", lambda state: state.update(unknown_field=1))
    model = model_of(run)
    assert model.state_available
    assert model.profile == "standard"
    assert model.warnings and model.warnings[0].startswith("state.json:")


def test_invalid_findings_records_are_dropped(run):
    def change(findings):
        del findings[0]["reason"]

    edit_json(run / "findings.json", change)
    model = model_of(run)
    assert len(model.findings) == 3
    assert any("invalid records are not shown" in warning for warning in model.warnings)


def test_unreadable_inputs_become_warnings(run):
    (run / "candidates.json").write_text("{broken", encoding="utf-8")
    (run / "coverage-ledger.json").write_text('{"units": 3}', encoding="utf-8")
    model = model_of(run)
    assert not model.candidates_available
    assert any(warning.startswith("candidates.json") for warning in model.warnings)
    assert any(warning.startswith("coverage-ledger.json") for warning in model.warnings)


def test_sca_falls_back_to_candidates(run):
    (run / "sca" / "vulns.json").unlink()
    model = model_of(run)
    assert model.sca_source == "candidates"
    assert "sca/vulns.json" in model.missing
    assert [record.vuln_id for record in model.sca] == ["GHSA-8q59-q68h-6hv4"]
    assert model.sca[0].reachability == "unknown"
    assert "SCA adaylarından" in render_markdown(model, "tr")


def test_tool_results_are_unlinked_when_findings_are_missing(run):
    (run / "findings.json").unlink()
    model = model_of(run)
    assert not model.findings_available
    assert len(model.tool_results) == 3  # SCA candidates stay out of the tool results


def test_localized_text():
    finding = {
        "title": "Başlık",
        "description": "Açıklama",
        "remediation": {"strategy": "Düzelt"},
        "i18n": {"en": {"title": "Title", "description": "Description"}},
    }
    assert localized(finding, "title", "tr", "tr") == ("Başlık", False)
    assert localized(finding, "title", "en", "tr") == ("Title", False)
    assert localized(finding, "remediation_strategy", "en", "tr") == ("Düzelt", True)
    assert localized(finding, "remediation_strategy", "en", "en") == ("Düzelt", False)
    assert localized({"title": "Only"}, "title", "tr", "en") == ("Only", True)


def test_clean_removes_controls_bidi_and_surrogates():
    assert clean("a\r\nb\rc") == "a\nb\nc"
    assert clean("x\x1b[31my\x00") == "x�[31my�"
    assert clean("abc‮def") == "abc[U+202E]def"
    assert clean("lone\ud800") == "lone�"
    assert clean(None) == "" and clean(True) == "" and clean(3) == "3" and clean({}) == ""


def test_small_helpers():
    assert fmt_ts("2026-10-15T12:30:45Z") == "2026-10-15 12:30 UTC"
    assert fmt_ts("2026-10-15T12:30:45.123Z") == "2026-10-15 12:30 UTC"
    assert fmt_ts("yesterday") == "yesterday"
    assert class_title("sqli", "tr") == "SQL injection"
    assert class_title("file-upload", "tr").startswith("Güvensiz dosya")
    assert class_title("file-upload", "en") == "Unsafe file upload"
    assert class_title("no-such-class", "en") == "no-such-class"
    finding = {"trace": [{"kind": "sink", "file": "a.py", "line": 3}], "evidence": []}
    assert location_of(finding) == "a.py:3"
    assert location_of({"trace": [], "evidence": []}) == ""


def test_unchecked_manifests_count_without_a_state_too(tmp_path):
    folder = tmp_path / RUN_ID
    (folder / "sca").mkdir(parents=True)
    vulns = {
        "schema_version": 1,
        "records": [],
        "warnings": [],
        "unchecked_manifests": [
            {"file": "Gemfile", "ecosystem": "RubyGems", "reason": "the manifest cannot be read"},
            {"file": "a/package.json", "ecosystem": "npm", "reason": "something new"},
        ],
    }
    (folder / "sca" / "vulns.json").write_text(json.dumps(vulns), encoding="utf-8")
    model = model_of(folder, installed_tools=None)
    assert model.partial_reasons == [
        ("partial_no_state", {}),
        ("partial_unchecked_manifests", {"n": 2}),
    ]
    assert [m.file for m in model.unchecked_manifests] == ["a/package.json", "Gemfile"]
    markdown = render_markdown(model, "en")
    assert "### 2.6 Scan gaps" in markdown
    assert "| `Gemfile` | RubyGems |" in markdown and "The file cannot be read" in markdown
    assert "something new" in markdown  # an unknown reason stays as written
    assert "> Manifests without a lockfile: 2." in markdown
    page = render_html(model, "tr")
    assert "Tarama boşlukları" in page and "Dosya okunamadı" in page


def test_no_gap_section_without_gaps(run):
    (run / "sca" / "vulns.json").unlink()
    edit_json(run / "scans" / "opengrep.status.json", _drop_gap_keys)
    edit_json(run / "target-manifest.json", _drop_long_paths)
    model = model_of(run)
    assert not model.has_coverage_gaps
    assert "### 2.6" not in render_markdown(model, "tr")


def _drop_gap_keys(doc):
    for key in ("partial_files", "skipped_files", "files_scanned"):
        doc.pop(key)


def _drop_long_paths(doc):
    doc.pop("long_paths")


def test_database_gaps_are_a_partial_reason_and_a_scan_gap(tmp_path):
    folder = tmp_path / RUN_ID
    (folder / "sca").mkdir(parents=True)
    vulns = {
        "schema_version": 1,
        "records": [],
        "warnings": [],
        "database_gaps": [
            {"engine": "grype", "ecosystem": None, "reason": "no local Grype database"},
            {"engine": "osv-scanner", "ecosystem": "PyPI", "reason": "no local OSV database"},
        ],
    }
    (folder / "sca" / "vulns.json").write_text(json.dumps(vulns), encoding="utf-8")
    model = model_of(folder, installed_tools=None)
    assert ("partial_database_gaps", {"n": 2}) in model.partial_reasons
    assert [(gap.engine, gap.ecosystem) for gap in model.database_gaps] == [
        ("grype", None),
        ("osv-scanner", "PyPI"),
    ]
    markdown = render_markdown(model, "en")
    assert "| `grype` | all ecosystems | no local Grype database |" in markdown
    assert "kalkan sca update-db" in markdown
    turkish = render_markdown(model, "tr")
    assert "tüm ekosistemler" in turkish
    assert "no local OSV database" in render_html(model, "en")
