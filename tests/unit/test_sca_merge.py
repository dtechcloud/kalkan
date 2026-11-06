# SPDX-License-Identifier: MIT
"""Tests for kalkan.sca.merge: merge rules, vulns.json, candidates and line lookup."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kalkan.errors import ValidationError
from kalkan.findings.fingerprint import candidate_id
from kalkan.findings.validate import validate_candidate
from kalkan.sca.merge import (
    build_candidates,
    carry_over,
    empty_doc,
    find_package_line,
    lower_severity,
    merge_records,
    read_vulns,
    set_reachability,
    validate_vulns,
    vulns_path,
    write_vulns,
)
from kalkan.sca.normalize import new_record, parse_grype, parse_osv_scanner
from kalkan.schema.loader import load_schema

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "sca"
DEPAPP = FIXTURES / "depapp"


def osv_records() -> list[dict]:
    text = (FIXTURES / "osv.json").read_text(encoding="utf-8")
    doc = json.loads(text.replace("@TARGET@", DEPAPP.resolve().as_posix()))
    return parse_osv_scanner(doc, DEPAPP).records


def grype_records() -> list[dict]:
    doc = json.loads((FIXTURES / "grype.json").read_text(encoding="utf-8"))
    return parse_grype(doc, DEPAPP).records


def record(**overrides) -> dict:
    values = {
        "ecosystem": "npm",
        "package": "lodash",
        "version": "4.17.20",
        "ids": ["GHSA-35jh-r3h4-6jhm", "CVE-2021-23337"],
        "engine": "osv-scanner",
        "locations": ["package-lock.json"],
    }
    values.update(overrides)
    return new_record(**values)


def merged_fixture() -> list[dict]:
    return merge_records(osv_records() + grype_records())


# --- merge rules -------------------------------------------------------------------------------


def test_alias_intersection_merges_records():
    osv = record(ids=["GHSA-35jh-r3h4-6jhm", "CVE-2021-23337"], summary="Command Injection")
    grype = record(
        ids=["CVE-2021-23337"],
        engine="grype",
        cvss_score=9.8,
        summary="lodash versions prior to 4.17.21 are vulnerable to Command Injection.",
        fixed_versions=["4.17.21"],
        locations=["web/package-lock.json"],
    )
    merged = merge_records([grype, osv])
    assert len(merged) == 1
    item = merged[0]
    assert item["ref"] == "npm/lodash@4.17.20/GHSA-35jh-r3h4-6jhm"
    assert item["aliases"] == ["CVE-2021-23337"]
    assert item["engines"] == ["osv-scanner", "grype"]
    assert item["severity"] == "critical"
    assert item["cvss_score"] == 9.8
    assert item["summary"].startswith("lodash versions prior")
    assert item["fixed_versions"] == ["4.17.21"]
    assert item["locations"] == ["package-lock.json", "web/package-lock.json"]


def test_version_mismatch_keeps_records_apart():
    left = record(version="4.17.20")
    right = record(version="4.17.19", engine="grype")
    assert len(merge_records([left, right])) == 2


def test_disjoint_ids_keep_records_apart():
    left = record(ids=["GHSA-35jh-r3h4-6jhm", "CVE-2021-23337"])
    right = record(ids=["GHSA-29mw-wpgm-hmr9", "CVE-2020-28500"], engine="grype")
    assert len(merge_records([left, right])) == 2


def test_other_ecosystem_or_package_keeps_records_apart():
    npm = record()
    gem = record(ecosystem="RubyGems", package="lodash-rails", engine="grype")
    assert len(merge_records([npm, gem])) == 2


def test_merge_is_transitive_inside_one_key():
    group = record(ids=["GHSA-35jh-r3h4-6jhm", "GHSA-r5fr-rjxr-66jc", "CVE-2021-23337"])
    first = record(ids=["GHSA-35jh-r3h4-6jhm"], engine="grype")
    second = record(ids=["GHSA-r5fr-rjxr-66jc", "CVE-2026-4800"], engine="grype")
    merged = merge_records([first, second, group])
    assert len(merged) == 1
    assert merged[0]["aliases"] == ["CVE-2021-23337", "CVE-2026-4800", "GHSA-r5fr-rjxr-66jc"]


def test_pypi_names_and_versions_compare_normalized():
    left = record(ecosystem="PyPI", package="PyYAML", version="5.3", ids=["GHSA-8q59-q68h-6hv4"])
    right = record(
        ecosystem="PyPI",
        package="pyyaml",
        version="5.3.0",
        ids=["GHSA-8q59-q68h-6hv4"],
        engine="grype",
    )
    merged = merge_records([right, left])
    assert len(merged) == 1
    # The osv-scanner record gives the display version.
    assert merged[0]["ref"] == "PyPI/pyyaml@5.3/GHSA-8q59-q68h-6hv4"


def test_go_versions_with_and_without_v_merge():
    osv = record(ecosystem="Go", package="golang.org/x/text", version="0.3.5", ids=["GO-2021-0113"])
    grype = record(
        ecosystem="Go",
        package="golang.org/x/text",
        version="v0.3.5",
        ids=["GHSA-ppp9-7jff-5vj2", "GO-2021-0113"],
        engine="grype",
    )
    merged = merge_records([osv, grype])
    assert [m["ref"] for m in merged] == ["Go/golang.org/x/text@0.3.5/GHSA-ppp9-7jff-5vj2"]


def test_equal_severity_keeps_the_higher_score():
    left = record(cvss_score=7.2, cvss_vector="A")
    right = record(cvss_score=8.1, cvss_vector="B", engine="grype")
    merged = merge_records([left, right])[0]
    assert (merged["cvss_score"], merged["cvss_vector"], merged["severity"]) == (8.1, "B", "high")


def test_affected_symbols_and_cwes_join():
    left = record(cwe=["CWE-94"], affected_symbols=[{"package": "lodash", "symbols": ["template"]}])
    right = record(
        cwe=["CWE-77", "CWE-94"],
        engine="grype",
        affected_symbols=[{"package": "lodash", "symbols": ["template", "templateSettings"]}],
    )
    merged = merge_records([left, right])[0]
    assert merged["cwe"] == ["CWE-94", "CWE-77"]
    assert merged["affected_symbols"] == [
        {"package": "lodash", "symbols": ["template", "templateSettings"]}
    ]


def test_merge_does_not_change_inputs():
    left = record()
    right = record(engine="grype", locations=["other.json"])
    before = json.dumps([left, right], sort_keys=True)
    merge_records([left, right])
    assert json.dumps([left, right], sort_keys=True) == before


def test_fixture_merge_counts_and_order():
    osv, grype = osv_records(), grype_records()
    merged = merge_records(osv + grype)
    assert (len(osv), len(grype), len(merged)) == (17, 11, 14)
    refs = [m["ref"] for m in merged]
    assert refs[0] == "PyPI/pyyaml@5.3/GHSA-6757-jp84-gxfx"
    severities = [m["severity"] for m in merged]
    order = ["critical", "high", "medium", "low", "info"]
    assert severities == sorted(severities, key=order.index)
    lodash = next(m for m in merged if m["ref"] == "npm/lodash@4.17.20/GHSA-35jh-r3h4-6jhm")
    # Grype reports GHSA-r5fr-rjxr-66jc separately with CVSS 9.8; the OSV group joins both.
    assert lodash["engines"] == ["osv-scanner", "grype"]
    assert lodash["severity"] == "critical"
    pyyaml = [m for m in merged if m["package"] == "pyyaml"]
    assert len(pyyaml) == 2  # 5.3 and 5.3.0 from two OSV sources and Grype, per advisory
    assert len(refs) == len(set(refs))


# --- reachability state ------------------------------------------------------------------------


def test_lower_severity():
    assert [lower_severity(s) for s in ("critical", "high", "medium", "low", "info")] == [
        "high",
        "medium",
        "low",
        "info",
        "info",
    ]


def test_set_reachability_keeps_the_severity_rule():
    item = record(cvss_score=9.8)
    set_reachability(item, "not_reachable", reason="r", source="sca_reach", searched=["a"])
    assert (item["severity"], item["severity_original"]) == ("high", "critical")
    set_reachability(item, "not_reachable", reason="again", source="sca_reach", searched=["a"])
    assert (item["severity"], item["severity_original"]) == ("high", "critical")
    set_reachability(item, "reachable", reason="r", source="sca_reach")
    assert (item["severity"], item["severity_original"]) == ("critical", None)
    with pytest.raises(ValueError):
        set_reachability(item, "maybe", reason="", source=None)


def test_carry_over_keeps_decisions_across_runs():
    old = record(cvss_score=9.8)
    set_reachability(
        old,
        "not_reachable",
        reason="only a test dependency",
        source="sca_reach",
        searched=['require("lodash")'],
        task_id="T0007-sca_reach",
    )
    fresh = record(cvss_score=9.8, engine="grype")
    other = record(package="minimist", ids=["GHSA-xvch-5gv4-984h"])
    assert carry_over([fresh, other], [old]) == 1
    assert fresh["reachability"] == "not_reachable"
    assert fresh["severity"] == "high"
    assert fresh["severity_original"] == "critical"
    assert fresh["reach_task_id"] == "T0007-sca_reach"
    assert other["reachability"] == "unknown"


# --- vulns.json --------------------------------------------------------------------------------


def test_vulns_schema_loads_with_the_restricted_validator():
    schema = load_schema("vulns")
    assert schema["properties"]["schema_version"] == {"const": 1}


def test_fixture_records_validate():
    doc = {"schema_version": 1, "records": merged_fixture(), "warnings": ["w"]}
    assert validate_vulns(doc) == []
    assert validate_vulns(empty_doc()) == []


def test_validate_vulns_finds_errors():
    item = record()
    bad = dict(item, severity="severe")
    assert any("severity" in e for e in validate_vulns({**empty_doc(), "records": [bad]}))
    wrong_ref = dict(item, ref="npm/lodash@1/GHSA-x")
    assert any("ref" in e for e in validate_vulns({**empty_doc(), "records": [wrong_ref]}))
    duplicate = {**empty_doc(), "records": [item, dict(item)]}
    assert any("duplicate" in e for e in validate_vulns(duplicate))
    lowered = dict(item, severity_original="critical")
    assert any(
        "severity_original" in e for e in validate_vulns({**empty_doc(), "records": [lowered]})
    )
    assert validate_vulns({"schema_version": 2, "records": [], "warnings": []})
    assert validate_vulns([]) == ["$: expected an object"]
    extra = dict(item, extra=1)
    assert validate_vulns({**empty_doc(), "records": [extra]})


def test_validate_vulns_has_no_1000_record_cap():
    records = []
    for index in range(1001):
        records.append(record(package=f"pkg{index}", ids=[f"GHSA-{index}"]))
    assert validate_vulns({**empty_doc(), "records": records}) == []


def test_write_and_read_vulns(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    assert read_vulns(run_dir) == empty_doc()
    records = merged_fixture()
    path = write_vulns(run_dir, records, ["one", "one", "two"])
    assert path == vulns_path(run_dir)
    text = path.read_text(encoding="utf-8")
    assert text.endswith("}\n")
    doc = read_vulns(run_dir)
    assert doc["records"] == records
    assert doc["warnings"] == ["one", "two"]
    with pytest.raises(ValidationError):
        write_vulns(run_dir, [dict(records[0], severity="bad")], [])
    path.write_text('{"schema_version": 1}', encoding="utf-8")
    with pytest.raises(ValidationError):
        read_vulns(run_dir)
    path.write_text("{", encoding="utf-8")
    with pytest.raises(ValidationError):
        read_vulns(run_dir)


# --- candidates --------------------------------------------------------------------------------


def test_candidates_follow_the_candidate_schema():
    records = merged_fixture()
    candidates = build_candidates(records, DEPAPP)
    assert len(candidates) == len(records)
    for candidate in candidates:
        assert validate_candidate(candidate) == [], candidate


def test_candidate_fields():
    records = merged_fixture()
    candidates = build_candidates(records, DEPAPP)
    first = candidates[0]
    assert first["engine"] == "osv-scanner"
    assert first["rule_id"] == "GHSA-6757-jp84-gxfx"
    assert first["class"] == "vulnerable-dependency"
    assert first["cwe"] == ["CWE-1395", "CWE-20"]
    assert first["file"] == "requirements.txt"
    assert first["start_line"] == first["end_line"] == 2
    assert first["snippet"] == "PyYAML==5.3"
    assert first["severity"] == "critical"
    assert first["tool_severity"] == "9.8"
    assert "sca" in first["tags"] and "engines:osv-scanner,grype" in first["tags"]
    assert "reachability:unknown" in first["tags"]
    assert first["fingerprints"] == {"kalkanSca/v1": "PyPI/pyyaml@5.3/GHSA-6757-jp84-gxfx"}
    assert first["sca"]["vuln_ids"] == ["GHSA-6757-jp84-gxfx", "CVE-2020-1747", "PYSEC-2020-96"]
    assert first["raw"] == {"sarif_file": "sca/vulns.json", "run_index": 0, "result_index": 0}
    assert first["id"] == candidate_id(
        "osv-scanner", "GHSA-6757-jp84-gxfx", "requirements.txt", 2, "PyYAML==5.3"
    )
    lock = next(c for c in candidates if c["sca"]["package"] == "minimist")
    assert (lock["file"], lock["start_line"]) == ("package-lock.json", 22)
    assert lock["snippet"] == '"node_modules/minimist": {'
    go = next(c for c in candidates if c["sca"]["package"] == "golang.org/x/text")
    assert (go["file"], go["start_line"], go["snippet"]) == (
        "go.mod",
        8,
        "golang.org/x/text v0.3.5",
    )


def test_candidate_without_a_line_or_target():
    records = merged_fixture()
    urllib3 = next(r for r in records if r["package"] == "urllib3")
    candidate = build_candidates([urllib3], DEPAPP)[0]
    # urllib3 is a resolved transitive dependency: requirements.txt does not name it.
    assert (candidate["file"], candidate["start_line"], candidate["snippet"]) == (
        "requirements.txt",
        None,
        "",
    )
    assert validate_candidate(candidate) == []
    no_target = build_candidates(records[:1], None)[0]
    assert no_target["start_line"] is None
    no_location = build_candidates([dict(records[0], locations=[])], DEPAPP)[0]
    assert no_location["file"] == ""
    assert validate_candidate(no_location) == []


def test_candidate_ids_are_stable_across_reachability_changes():
    records = merged_fixture()
    before = [c["id"] for c in build_candidates(records, DEPAPP)]
    set_reachability(records[0], "not_reachable", reason="r", source="sca_reach", searched=["x"])
    after = build_candidates(records, DEPAPP)
    assert [c["id"] for c in after] == before
    assert after[0]["severity"] == "high"
    assert "reachability:not_reachable" in after[0]["tags"]


# --- line lookup -------------------------------------------------------------------------------


def lines_of(text: str) -> list[str]:
    return text.split("\n")


def test_line_lookup_requirements():
    text = "# PyYAML==5.3 is pinned below\nflask==2.0\npyyaml == 5.3.0 ; python_version>'3'\n"
    assert find_package_line(lines_of(text), "requirements.txt", "PyPI", "pyyaml", "5.3") == 3
    text = "Foo_Bar==1.0\n"
    assert find_package_line(lines_of(text), "requirements-dev.txt", "PyPI", "foo-bar", "1.0") == 1
    assert (
        find_package_line(lines_of("flask==2.0\n"), "requirements.txt", "PyPI", "yaml", "1") is None
    )


def test_line_lookup_package_lock_prefers_the_entry_with_the_version():
    text = """{
  "packages": {
    "": {"dependencies": {"lodash": "^4.17.0"}},
    "node_modules/lodash": {
      "version": "4.17.21"
    },
    "node_modules/a/node_modules/lodash": {
      "version": "4.17.20"
    },
    "node_modules/lodash.template": {
      "version": "4.17.20"
    }
  }
}"""
    assert find_package_line(lines_of(text), "package-lock.json", "npm", "lodash", "4.17.20") == 7


def test_line_lookup_go_mod_and_others():
    gomod = "module x\n\n// golang.org/x/text v0.3.5 is old\nrequire golang.org/x/text v0.3.5\n"
    assert find_package_line(lines_of(gomod), "go.mod", "Go", "golang.org/x/text", "0.3.5") == 4
    pom = "<dependency>\n  <groupId>org.x</groupId>\n  <artifactId>core</artifactId>\n"
    assert find_package_line(lines_of(pom), "pom.xml", "Maven", "org.x:core", "1.0") == 3
    yarn = 'lodash-es@^4:\n  version "4.17.20"\nlodash@^4.17.0:\n  version "4.17.20"\n'
    assert find_package_line(lines_of(yarn), "yarn.lock", "npm", "lodash", "4.17.20") == 3
    gemfile = "GEM\n  specs:\n    rails (6.0.0)\n    rails-html (1.0)\n"
    assert find_package_line(lines_of(gemfile), "Gemfile.lock", "RubyGems", "rails", "6.0.0") == 3


def test_line_lookup_on_the_depapp_files():
    package_json = (DEPAPP / "package.json").read_text(encoding="utf-8").split("\n")
    assert find_package_line(package_json, "package.json", "npm", "node-fetch", "2.6.0") == 11
    requirements = (DEPAPP / "requirements.txt").read_text(encoding="utf-8").split("\n")
    assert find_package_line(requirements, "requirements.txt", "PyPI", "jinja2", "2.10.1") == 3


@pytest.mark.parametrize(
    ("package", "lockfile", "resolved"),
    [("Flask", "0.12", "0.12.0"), ("Django", "3.2.0", "3.2"), ("PyYAML", "5.3", "5.3.0")],
)
def test_osv_scanner_double_pypi_spellings_merge(package, lockfile, resolved):
    # OSV-Scanner 2.6 reports a requirements.txt package twice: from the lockfile extractor
    # (the written version) and from transitive resolution (a normalized version).
    ids = ["PYSEC-2026-1", "GHSA-c3x2-p9qv-hm4w"]
    first = record(ecosystem="PyPI", package=package, version=lockfile, ids=ids)
    second = record(ecosystem="PyPI", package=package.lower(), version=resolved, ids=ids)
    grype = record(
        ecosystem="PyPI", package=package.lower(), version=lockfile, ids=ids[1:], engine="grype"
    )
    merged = merge_records([first, second, grype])
    assert len(merged) == 1
    assert merged[0]["version"] == lockfile
    assert merged[0]["engines"] == ["osv-scanner", "grype"]
    assert merged[0]["ref"] == f"PyPI/{package.lower()}@{lockfile}/GHSA-c3x2-p9qv-hm4w"


def test_pypi_versions_that_differ_stay_apart():
    ids = ["GHSA-c3x2-p9qv-hm4w"]
    left = record(ecosystem="PyPI", package="flask", version="0.12", ids=ids)
    right = record(ecosystem="PyPI", package="flask", version="0.12.1", ids=ids)
    rc = record(ecosystem="PyPI", package="flask", version="0.12rc1", ids=ids)
    assert len(merge_records([left, right, rc])) == 3


# --- manifest pins and unchecked manifests -----------------------------------------------------


def _pin_record(engine: str, *, pin: bool) -> dict:
    record = new_record(
        ecosystem="npm",
        package="lodash",
        version="4.17.15",
        ids=["GHSA-p6mc-m468-83gw", "CVE-2020-8203"],
        cvss_score=7.4,
        engine=engine,
        locations=["web/package.json" if pin else "package-lock.json"],
    )
    if pin:
        record["pin_source"] = "manifest"
    return record


def test_pin_source_survives_only_when_every_input_has_it():
    [both] = merge_records([_pin_record("osv-scanner", pin=True), _pin_record("grype", pin=True)])
    assert both["pin_source"] == "manifest" and both["engines"] == ["osv-scanner", "grype"]
    [mixed] = merge_records([_pin_record("grype", pin=True), _pin_record("osv-scanner", pin=False)])
    assert "pin_source" not in mixed
    assert mixed["locations"] == ["package-lock.json", "web/package.json"]


def test_vulns_schema_accepts_pins_and_unchecked_manifests(tmp_path):
    record = _pin_record("osv-scanner", pin=True)
    unchecked = [{"file": "web/package.json", "ecosystem": "npm", "reason": "r", "ranges": 2}]
    write_vulns(tmp_path, [record], [], unchecked)
    doc = read_vulns(tmp_path)
    assert doc["unchecked_manifests"] == unchecked
    assert doc["records"][0]["pin_source"] == "manifest"
    write_vulns(tmp_path, [record], [])
    assert "unchecked_manifests" not in read_vulns(tmp_path)
    bad = dict(record, pin_source="lockfile")
    assert any("pin_source" in e for e in validate_vulns({**empty_doc(), "records": [bad]}))
    missing = {**empty_doc(), "unchecked_manifests": [{"ecosystem": "npm", "reason": "r"}]}
    assert validate_vulns(missing)


def test_pin_candidates_carry_a_tag(tmp_path):
    (tmp_path / "web").mkdir()
    (tmp_path / "web" / "package.json").write_text(
        '{\n  "dependencies": {\n    "lodash": "4.17.15"\n  }\n}\n', encoding="utf-8"
    )
    [candidate] = build_candidates([_pin_record("osv-scanner", pin=True)], tmp_path)
    assert candidate["file"] == "web/package.json" and candidate["start_line"] == 3
    assert "pin-source:manifest" in candidate["tags"]
    assert validate_candidate(candidate) == []


def test_line_lookup_gemfile():
    lines = ["source 'https://rubygems.org'", "# gem 'rack', '2.2.3'", 'gem "rack", "2.2.3"']
    assert find_package_line(lines, "ruby/Gemfile", "RubyGems", "rack", "2.2.3") == 3


def _vendored_record(engine: str, file: str, line: int | None = 1) -> dict:
    record = new_record(
        ecosystem="npm",
        package="jquery",
        version="1.12.4",
        ids=["GHSA-jpcq-cgw6-v4j6", "CVE-2020-11023"],
        engine=engine,
        locations=[file],
        label="medium",
    )
    record["pin_source"] = "vendored"
    record["vendored"] = [
        {
            "file": file,
            "line": line,
            "library": "jquery",
            "version": "1.12.4",
            "extractor": "filecontent" if line else "filename",
        }
    ]
    if engine == "retirejs":
        record["references"] = ["https://blog.jquery.com/2020/04/10/jquery-3-5-0-released/"]
    return record


def test_vendored_records_merge_by_ids_and_keep_their_files():
    [merged] = merge_records(
        [
            _vendored_record("retirejs", "lib/jquery.js"),
            _vendored_record("osv-scanner", "lib/jquery.min.js"),
            _vendored_record("grype", "lib/jquery.js"),
        ]
    )
    assert merged["engines"] == ["osv-scanner", "grype", "retirejs"]
    assert merged["pin_source"] == "vendored"
    assert merged["locations"] == ["lib/jquery.min.js", "lib/jquery.js"]
    assert [entry["file"] for entry in merged["vendored"]] == ["lib/jquery.min.js", "lib/jquery.js"]
    assert merged["references"] == ["https://blog.jquery.com/2020/04/10/jquery-3-5-0-released/"]
    assert validate_vulns({**empty_doc(), "records": [merged]}) == []


def test_mixed_pin_sources_drop_the_field_but_keep_the_vendored_files():
    manifest = _vendored_record("osv-scanner", "lib/jquery.js")
    manifest.update(pin_source="manifest", locations=["web/package.json"])
    del manifest["vendored"]
    [mixed] = merge_records([manifest, _vendored_record("retirejs", "lib/jquery.js")])
    assert "pin_source" not in mixed and mixed["vendored"][0]["file"] == "lib/jquery.js"
    lockfile = _vendored_record("grype", "package-lock.json")
    del lockfile["pin_source"], lockfile["vendored"]
    [with_lockfile] = merge_records([lockfile, _vendored_record("retirejs", "lib/jquery.js")])
    assert "pin_source" not in with_lockfile
    [candidate] = build_candidates([with_lockfile], None)
    assert "vendored" in candidate["tags"] and not any(
        tag.startswith("pin-source") for tag in candidate["tags"]
    )


def test_vendored_candidates_use_the_detection_line_and_a_short_window(tmp_path):
    minified = "!function(){" + "x" * 3000 + 'jquery:"1.12.4",' + "y" * 3000 + "}();"
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "jquery.js").write_text("/*! header */\n" + minified, encoding="utf-8")
    record = _vendored_record("retirejs", "lib/jquery.js", line=2)
    [candidate] = build_candidates([record], tmp_path)
    assert (candidate["file"], candidate["start_line"]) == ("lib/jquery.js", 2)
    assert 'jquery:"1.12.4"' in candidate["snippet"] and len(candidate["snippet"]) <= 240
    assert "pin-source:vendored" in candidate["tags"] and validate_candidate(candidate) == []
    by_name = _vendored_record("retirejs", "lib/jquery-1.12.4.js", line=None)
    [named] = build_candidates([by_name], tmp_path)
    assert (named["file"], named["start_line"], named["snippet"]) == (
        "lib/jquery-1.12.4.js",
        None,
        "",
    )


def test_vulns_schema_checks_the_vendored_fields():
    good = _vendored_record("retirejs", "lib/jquery.js")
    assert validate_vulns({**empty_doc(), "records": [good]}) == []
    for bad in (
        dict(good, pin_source="bundled"),
        dict(good, engines=["retire"]),
        dict(good, vendored=[{"file": "lib/jquery.js"}]),
        dict(good, vendored=[{**good["vendored"][0], "extractor": "func"}]),
        dict(good, references=[""]),
    ):
        assert validate_vulns({**empty_doc(), "records": [bad]}), bad
