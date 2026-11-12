# SPDX-License-Identifier: MIT
"""Tests for kalkan.sca.reach: govulncheck, agent task selection, task input and results."""

from __future__ import annotations

import json
import shutil
import sys
import types
from pathlib import Path

import pytest

import kalkan.scanners as scanners_package
from kalkan.errors import ValidationError
from kalkan.findings.quote_verify import Evidence, verify_evidence
from kalkan.sca.merge import merge_records, read_vulns, set_reachability, write_vulns
from kalkan.sca.normalize import (
    new_record,
    parse_govulncheck_text,
    parse_grype,
    parse_osv_scanner,
)
from kalkan.sca.reach import (
    apply_govulncheck,
    apply_reach_result,
    build_reach_input,
    decide_reachability,
    import_patterns,
    mark_reach_tasks,
    python_import_names,
    select_for_agents,
)
from kalkan.schema.loader import shared_schema
from kalkan.schema.validator import validate

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "sca"
DEPAPP = FIXTURES / "depapp"
EXAMPLE = Path(__file__).resolve().parents[1] / "fixtures" / "task-results" / "sca_reach.json"
PYYAML_REF = "PyPI/pyyaml@5.3/GHSA-8q59-q68h-6hv4"
MATCH_WARNING = "grype: failed: database does not exist"


def fixture_records(root: Path = DEPAPP) -> list[dict]:
    text = (FIXTURES / "osv.json").read_text(encoding="utf-8")
    osv = parse_osv_scanner(json.loads(text.replace("@TARGET@", root.resolve().as_posix())), root)
    grype = parse_grype(json.loads((FIXTURES / "grype.json").read_text(encoding="utf-8")), root)
    return merge_records(osv.records + grype.records)


def govulncheck_result(module_dir: str = ""):
    return parse_govulncheck_text((FIXTURES / "govulncheck.json").read_text("utf-8"), module_dir)


def find(records: list[dict], ref: str) -> dict:
    return next(r for r in records if r["ref"] == ref)


@pytest.fixture
def merge_calls(monkeypatch):
    """Replace kalkan.scanners.candidates with a recorder of merge_candidates calls."""
    calls: list[tuple] = []
    module = types.ModuleType("kalkan.scanners.candidates")

    def merge_candidates(run_dir, source, candidates, warnings):
        calls.append((Path(run_dir), source, candidates, list(warnings)))
        return len(candidates)

    module.merge_candidates = merge_candidates
    monkeypatch.setitem(sys.modules, "kalkan.scanners.candidates", module)
    monkeypatch.setattr(scanners_package, "candidates", module, raising=False)
    return calls


@pytest.fixture
def run_dir(tmp_path):
    directory = tmp_path / "run"
    shutil.copytree(DEPAPP, directory / "target")
    write_vulns(directory, fixture_records(directory / "target"), [MATCH_WARNING])
    return directory


def target_lines(run: Path):
    def get_lines(path: str):
        file = run / "target" / path
        return file.read_text(encoding="utf-8").split("\n") if file.is_file() else None

    return get_lines


# --- govulncheck -------------------------------------------------------------------------------


def test_apply_govulncheck_marks_reachable_and_not_reachable():
    records = fixture_records()
    counts = apply_govulncheck(records, govulncheck_result(), DEPAPP)
    assert counts == {"reachable": 1, "not_reachable": 2, "unchanged": 1}
    called = find(records, "Go/golang.org/x/text@0.3.5/GHSA-ppp9-7jff-5vj2")
    assert called["reachability"] == "reachable"
    assert called["reachability_source"] == "govulncheck"
    assert called["reach_evidence"] == [
        {
            "file": "main.go",
            "line": 12,
            "quote": 'tag, err := language.Parse(os.Getenv("LANG_TAG"))',
        }
    ]
    assert "golang.org/x/text/language.Parse" in called["reachability_reason"]
    assert called["severity_original"] is None
    imported = find(records, "Go/golang.org/x/text@0.3.5/GHSA-69ch-w2m2-3vjp")
    assert imported["reachability"] == "not_reachable"
    assert (imported["severity"], imported["severity_original"]) == ("medium", "high")
    assert "package-level" in imported["reachability_reason"]
    required = find(
        records, "Go/github.com/dgrijalva/jwt-go@3.2.0+incompatible/GHSA-w73w-5m7g-f7qc"
    )
    assert required["reachability"] == "not_reachable"
    assert "module-level" in required["reachability_reason"]
    # govulncheck did not report GO-2026-5970: the record keeps its state.
    assert find(records, "Go/golang.org/x/text@0.3.5/CVE-2026-56852")["reachability"] == "unknown"
    # Other ecosystems stay unknown.
    assert find(records, PYYAML_REF)["reachability"] == "unknown"


def test_apply_govulncheck_respects_agent_decisions_and_versions():
    records = fixture_records()
    decided = find(records, "Go/golang.org/x/text@0.3.5/GHSA-69ch-w2m2-3vjp")
    set_reachability(decided, "reachable", reason="agent", source="sca_reach")
    other_version = new_record(
        ecosystem="Go",
        package="github.com/dgrijalva/jwt-go",
        version="3.1.0",
        ids=["GO-2020-0017"],
        engine="osv-scanner",
    )
    records.append(other_version)
    apply_govulncheck(records, govulncheck_result(), DEPAPP)
    assert decided["reachability"] == "reachable"
    assert decided["reachability_source"] == "sca_reach"
    assert other_version["reachability"] == "unknown"


def test_apply_govulncheck_without_target_uses_the_symbol_as_quote():
    records = fixture_records()
    apply_govulncheck(records, govulncheck_result(), None)
    called = find(records, "Go/golang.org/x/text@0.3.5/GHSA-ppp9-7jff-5vj2")
    assert called["reach_evidence"][0]["quote"] == "golang.org/x/text/language.Parse"


# --- selection ---------------------------------------------------------------------------------


def test_select_for_agents_orders_packages_first_then_severity_and_ref():
    records = fixture_records()
    selected = select_for_agents(records, remaining_budget=100, max_tasks=100)
    refs = [r["ref"] for r in selected]
    assert all(r["severity"] in ("critical", "high") for r in selected)
    # One record per package first: the second pyyaml record waits for the other packages.
    assert refs[:3] == [
        "PyPI/pyyaml@5.3/GHSA-6757-jp84-gxfx",
        "npm/lodash@4.17.20/GHSA-35jh-r3h4-6jhm",
        "npm/minimist@1.2.5/GHSA-xvch-5gv4-984h",
    ]
    packages = [(r["ecosystem"], r["package"]) for r in selected]
    first_round = len(set(packages))
    assert len(set(packages[:first_round])) == first_round
    assert refs[first_round] == "PyPI/pyyaml@5.3/GHSA-8q59-q68h-6hv4"
    high = [r["ref"] for r in selected[:first_round] if r["severity"] == "high"]
    assert high == sorted(high)
    assert len(selected) == sum(1 for r in records if r["severity"] in ("critical", "high"))


def test_select_for_agents_budget_and_cap():
    records = fixture_records()
    assert len(select_for_agents(records, remaining_budget=3, max_tasks=10)) == 3
    assert len(select_for_agents(records, remaining_budget=10, max_tasks=2)) == 2
    assert select_for_agents(records, remaining_budget=0, max_tasks=10) == []
    assert select_for_agents(records, remaining_budget=-5, max_tasks=10) == []


def test_select_for_agents_skips_decided_and_assigned_records():
    records = fixture_records()
    apply_govulncheck(records, govulncheck_result(), DEPAPP)
    first = find(records, "PyPI/pyyaml@5.3/GHSA-6757-jp84-gxfx")
    first["reach_task_id"] = "T0001-sca_reach"
    agent_unknown = find(records, PYYAML_REF)
    set_reachability(agent_unknown, "unknown", reason="dynamic import", source="sca_reach")
    refs = [r["ref"] for r in select_for_agents(records, remaining_budget=99, max_tasks=99)]
    assert "PyPI/pyyaml@5.3/GHSA-6757-jp84-gxfx" not in refs
    assert PYYAML_REF not in refs
    assert not any(ref.startswith("Go/") and "GHSA-ppp9" in ref for ref in refs)


# --- task input --------------------------------------------------------------------------------


def test_build_reach_input_for_pypi():
    record = find(fixture_records(), PYYAML_REF)
    data = build_reach_input(record, DEPAPP)
    assert data["vuln_ref"] == PYYAML_REF
    assert data["package"] == "pyyaml"
    assert data["version"] == "5.3"
    assert data["vuln_id"] == "GHSA-8q59-q68h-6hv4"
    assert "CVE-2020-14343" in data["aliases"]
    assert data["fixed_versions"] == ["5.4"]
    assert data["locations"] == [{"file": "requirements.txt", "line": 2}]
    assert "import yaml" in data["import_patterns"]
    assert "from yaml import" in data["import_patterns"]
    assert data["engines"] == ["osv-scanner", "grype"]
    json.dumps(data)  # JSON-ready


def test_build_reach_input_for_go_names_the_symbols():
    record = find(fixture_records(), "Go/golang.org/x/text@0.3.5/GHSA-69ch-w2m2-3vjp")
    data = build_reach_input(record, DEPAPP)
    assert data["affected_symbols"] == [
        {
            "package": "golang.org/x/text/language",
            "symbols": ["MatchStrings", "ParseAcceptLanguage"],
        }
    ]
    assert data["locations"] == [{"file": "go.mod", "line": 8}]
    assert '"golang.org/x/text"' in data["import_patterns"]
    assert '"golang.org/x/text/language"' in data["import_patterns"]


def test_build_reach_input_without_target_has_null_lines():
    record = find(fixture_records(), PYYAML_REF)
    assert build_reach_input(record, None)["locations"] == [
        {"file": "requirements.txt", "line": None}
    ]


def test_import_patterns_per_ecosystem():
    assert 'require("lodash")' in import_patterns("npm", "lodash")
    assert 'from "lodash/' in import_patterns("npm", "lodash")
    maven = import_patterns("Maven", "org.apache.logging.log4j:log4j-core")
    assert "import org.apache.logging.log4j." in maven
    assert "<artifactId>log4j-core</artifactId>" in maven
    assert "use serde_json::" in import_patterns("crates.io", "serde-json")
    assert "require 'rails'" in import_patterns("RubyGems", "rails")
    assert import_patterns("Hex", "plug") == ["plug"]
    assert python_import_names("PyYAML") == ["yaml", "pyyaml"]
    assert python_import_names("python-dateutil") == ["dateutil", "python_dateutil"]
    assert python_import_names("requests") == ["requests"]


# --- results -----------------------------------------------------------------------------------


def result(**overrides) -> dict:
    data = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    data.update(overrides)
    return data


def test_example_result_is_valid_and_verified_on_the_depapp(run_dir):
    data = result()
    assert validate(data, shared_schema("task-sca_reach")) == []
    evidence = [Evidence(e["file"], e["line"], e["quote"]) for e in data["evidence"]]
    verified = verify_evidence(evidence, target_lines(run_dir))
    assert [e.line for e in verified] == [3, 15]


def test_apply_reachable_with_verified_quotes(run_dir, merge_calls):
    data = result()
    evidence = [Evidence(e["file"], e["line"], e["quote"]) for e in data["evidence"]]
    verified = verify_evidence(evidence, target_lines(run_dir))
    apply_reach_result(run_dir, data, verified)
    record = find(read_vulns(run_dir)["records"], PYYAML_REF)
    assert record["reachability"] == "reachable"
    assert record["reachability_source"] == "sca_reach"
    assert record["reach_task_id"] == "T0031-sca_reach"
    assert record["reach_evidence"] == [
        {"file": "app/config.py", "line": 3, "quote": "import yaml"},
        {"file": "app/config.py", "line": 15, "quote": "return yaml.load(stream)"},
    ]
    assert record["reach_searched"] == ["import yaml", "yaml.load(", "yaml.full_load("]
    assert record["severity"] == "critical"
    # The SCA candidates were rewritten once, with the new state.
    assert len(merge_calls) == 1
    _, source, candidates, warnings = merge_calls[0]
    assert source == "sca"
    # merge_candidates replaces the warnings of the source, so the match warnings go along.
    assert warnings == [MATCH_WARNING]
    candidate = next(c for c in candidates if c["fingerprints"]["kalkanSca/v1"] == PYYAML_REF)
    assert "reachability:reachable" in candidate["tags"]


def test_apply_reachable_without_verified_quotes_becomes_unknown(run_dir, merge_calls):
    apply_reach_result(run_dir, result(), [])
    record = find(read_vulns(run_dir)["records"], PYYAML_REF)
    assert record["reachability"] == "unknown"
    assert record["reachability_reason"].startswith("unverified_evidence: ")
    assert record["reach_evidence"] == []
    assert record["severity"] == "critical"


def test_apply_not_reachable_lowers_the_severity(run_dir, merge_calls):
    before = len(read_vulns(run_dir)["records"])
    data = result(
        reachability="not_reachable",
        reason="yaml is imported only by a build script.",
        evidence=[],
        searched=["import yaml", "from yaml", "yaml.load"],
    )
    apply_reach_result(run_dir, data, [])
    records = read_vulns(run_dir)["records"]
    assert len(records) == before  # never deleted
    record = find(records, PYYAML_REF)
    assert record["reachability"] == "not_reachable"
    assert (record["severity"], record["severity_original"]) == ("high", "critical")
    candidate = next(
        c for c in merge_calls[-1][2] if c["fingerprints"]["kalkanSca/v1"] == PYYAML_REF
    )
    assert candidate["severity"] == "high"
    # A second identical result does not lower the severity again.
    apply_reach_result(run_dir, data, [])
    record = find(read_vulns(run_dir)["records"], PYYAML_REF)
    assert (record["severity"], record["severity_original"]) == ("high", "critical")


def test_apply_not_reachable_needs_a_search_list(run_dir, merge_calls):
    data = result(reachability="not_reachable", evidence=[], searched=[" "])
    apply_reach_result(run_dir, data, [])
    record = find(read_vulns(run_dir)["records"], PYYAML_REF)
    assert record["reachability"] == "unknown"
    assert record["reachability_reason"].startswith("ungrounded_not_reachable")
    assert (record["severity"], record["severity_original"]) == ("critical", None)


def test_apply_not_reachable_with_failed_quotes_becomes_unknown(run_dir, merge_calls):
    data = result(reachability="not_reachable", searched=["import yaml"])
    apply_reach_result(run_dir, data, [])
    record = find(read_vulns(run_dir)["records"], PYYAML_REF)
    assert record["reachability"] == "unknown"
    assert record["reachability_reason"].startswith("unverified_evidence")


def test_apply_unknown_and_then_reachable_restores_the_severity(run_dir, merge_calls):
    lowered = result(reachability="not_reachable", evidence=[], searched=["import yaml"])
    apply_reach_result(run_dir, lowered, [])
    apply_reach_result(run_dir, result(reachability="unknown", evidence=[]), [])
    record = find(read_vulns(run_dir)["records"], PYYAML_REF)
    assert record["reachability"] == "unknown"
    assert (record["severity"], record["severity_original"]) == ("critical", None)


def test_apply_unknown_ref_raises(run_dir, merge_calls):
    with pytest.raises(ValidationError):
        apply_reach_result(run_dir, result(vuln_ref="npm/nothing@1.0.0/GHSA-x"), [])
    with pytest.raises(ValidationError):
        apply_reach_result(run_dir, result(reachability="maybe"), [])
    with pytest.raises(ValidationError):
        apply_reach_result(run_dir, ["not", "an", "object"], [])  # type: ignore[arg-type]
    assert merge_calls == []


def test_apply_accepts_verified_dicts_and_skips_bad_items(run_dir, merge_calls):
    verified = [
        {"file": "app/config.py", "line": 15, "quote": "return yaml.load(stream)"},
        {"file": "app/config.py", "line": 0, "quote": "bad line"},
        {"file": "", "line": 3, "quote": "no file"},
        "junk",
    ]
    apply_reach_result(run_dir, result(), verified)
    record = find(read_vulns(run_dir)["records"], PYYAML_REF)
    assert record["reachability"] == "reachable"
    assert len(record["reach_evidence"]) == 1


def test_decide_reachability_rules():
    verified = [{"file": "a.py", "line": 1, "quote": "import yaml"}]
    assert decide_reachability(result(), verified)[0] == "reachable"
    assert decide_reachability(result(), [])[0] == "unknown"
    lowered = result(reachability="not_reachable", evidence=[], searched=["x"])
    assert decide_reachability(lowered, [])[0] == "not_reachable"
    assert decide_reachability(result(reachability="unknown", reason=""), [])[1] == ""


def test_mark_reach_tasks(run_dir):
    assert mark_reach_tasks(run_dir, {}) == 0
    assert mark_reach_tasks(run_dir, {PYYAML_REF: "T0005-sca_reach", "missing": "T0006-x"}) == 1
    records = read_vulns(run_dir)["records"]
    assert find(records, PYYAML_REF)["reach_task_id"] == "T0005-sca_reach"
    refs = [r["ref"] for r in select_for_agents(records, remaining_budget=50, max_tasks=50)]
    assert PYYAML_REF not in refs


def _go_record(package: str, version: str, vuln_id: str, location: str = "go/go.mod") -> dict:
    return new_record(
        ecosystem="Go",
        package=package,
        version=version,
        ids=[vuln_id],
        label="high",
        locations=[location],
        engine="osv-scanner",
    )


def _stream(*messages: dict) -> str:
    return "\n".join(json.dumps(message) for message in messages)


#: govulncheck 1.8.0 on the vulnapp fixture: x/text is required in go.mod but no package of it
#: is imported. The SBOM lists only the main module and stdlib, and no finding follows.
NOT_IMPORTED_STREAM = _stream(
    {"kalkan_invocation": {"index": 0, "label": "go", "dir": "go"}},
    {"config": {"scanner_version": "v1.8.0", "go_version": "go1.26.9", "scan_level": "symbol"}},
    {
        "SBOM": {
            "go_version": "go1.26.9",
            "modules": [{"path": "vulnapp.internal/inventory"}, {"path": "stdlib"}],
            "roots": ["vulnapp.internal/inventory"],
        }
    },
)


def test_govulncheck_sbom_lists_the_analyzed_modules_per_go_mod():
    result = parse_govulncheck_text(NOT_IMPORTED_STREAM)
    assert result.analyzed == {"go/go.mod": ["stdlib", "vulnapp.internal/inventory"]}
    assert result.records == [] and result.levels == {}
    assert govulncheck_result().analyzed["go.mod"] == [
        "example.com/depapp",
        "github.com/dgrijalva/jwt-go",
        "golang.org/x/text",
        "stdlib",
    ]


def test_module_outside_the_build_is_not_reachable():
    records = [_go_record("golang.org/x/text", "0.3.7", "GHSA-69ch-w2m2-3vjp")]
    counts = apply_govulncheck(records, parse_govulncheck_text(NOT_IMPORTED_STREAM), None)
    assert counts == {"reachable": 0, "not_reachable": 1, "unchanged": 0}
    record = records[0]
    assert record["reachability"] == "not_reachable"
    assert record["reachability_source"] == "govulncheck"
    assert (record["severity"], record["severity_original"]) == ("medium", "high")
    assert (
        "no package of golang.org/x/text is in the build of go/" in (record["reachability_reason"])
    )
    assert record["reach_searched"] == [
        "govulncheck SBOM of go/go.mod: stdlib, vulnapp.internal/inventory"
    ]


def test_module_of_an_unscanned_go_mod_keeps_its_state():
    records = [
        _go_record("golang.org/x/text", "0.3.7", "GHSA-69ch-w2m2-3vjp", "tools/go.mod"),
        _go_record("vulnapp.internal/inventory", "1.0.0", "GO-2099-0001"),
    ]
    counts = apply_govulncheck(records, parse_govulncheck_text(NOT_IMPORTED_STREAM), None)
    assert counts == {"reachable": 0, "not_reachable": 0, "unchanged": 2}
    assert [record["reachability"] for record in records] == ["unknown", "unknown"]
