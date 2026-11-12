# SPDX-License-Identifier: MIT
"""Tests for kalkan.sca.commands: the sca sbom, match and reach steps and the CLI.

The scanner layer is replaced by fakes that write the recorded tool outputs of
tests/fixtures/sca, so these tests never run a tool and never use the network. The test at the
end that runs the real Syft carries ``@pytest.mark.tools``.
"""

from __future__ import annotations

import json
import shutil
import sys
import types
from dataclasses import dataclass
from pathlib import Path

import pytest

import kalkan.scanners as scanners_package
from kalkan import cli
from kalkan.errors import StateError, ToolError
from kalkan.sca import commands
from kalkan.sca.merge import read_vulns, set_reachability, validate_vulns, write_vulns
from kalkan.sca.normalize import new_record

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "sca"
DEPAPP = FIXTURES / "depapp"
RUN_ID = "20261015T120000Z-depapp-ab12"
#: A small RetireJS repository in the format of jsrepository-v5.json (kalkan.sca.retirejs).
RETIRE_REPOSITORY = FIXTURES / "retire" / "jsrepository-v5.json"


@dataclass(frozen=True)
class FakeContext:
    run_dir: Path
    target_dir: Path
    source_dir: Path | None
    tech: frozenset[str]
    offline: bool = False
    allow_path_tools: bool = False


@dataclass
class FakeResult:
    engine: str
    status: str
    output_path: Path | None
    message: str
    duration_seconds: float = 0.0
    exit_code: int | None = 0
    tool_version: str | None = None


def write_output(ctx, name: str, fixture: str, *, replace_target: bool = False) -> Path:
    text = (FIXTURES / fixture).read_text(encoding="utf-8")
    if replace_target:
        text = text.replace("@TARGET@", Path(ctx.target_dir).resolve().as_posix())
    out = Path(ctx.run_dir) / "sca" / name
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text, encoding="utf-8")
    return out


def ok(name: str, fixture: str, *, replace_target: bool = False):
    def behave(ctx):
        out = write_output(ctx, name, fixture, replace_target=replace_target)
        return FakeResult(Path(name).stem, "ok", out, "")

    return behave


def failing(status: str, message: str):
    def behave(_ctx):
        return FakeResult("x", status, None, message, exit_code=None)

    return behave


DEFAULT_BEHAVIOR = {
    "syft": ok("sbom.cdx.json", "syft.cdx.json"),
    "trivy-sbom": ok("sbom.trivy.cdx.json", "trivy.cdx.json"),
    "osv-scanner": ok("osv.json", "osv.json", replace_target=True),
    "grype": ok("grype.json", "grype.json"),
    "govulncheck": ok("govulncheck.json", "govulncheck.json"),
}


class FakeScanners:
    def __init__(self) -> None:
        self.behavior = dict(DEFAULT_BEHAVIOR)
        self.calls: list[tuple[str, FakeContext, int | None]] = []
        self.merged: list[tuple[Path, str, list[dict], list[str]]] = []

    def run_adapter(self, adapter, ctx, *, timeout_seconds=None):
        self.calls.append((adapter.name, ctx, timeout_seconds))
        return self.behavior[adapter.name](ctx)

    def merge_candidates(self, run_dir, source, candidates, warnings):
        self.merged.append((Path(run_dir), source, candidates, list(warnings)))
        return len(candidates)

    def names(self) -> list[str]:
        return [name for name, _, _ in self.calls]


@pytest.fixture
def fake(monkeypatch) -> FakeScanners:
    scanners = FakeScanners()
    base = types.ModuleType("kalkan.scanners.base")
    base.ScanContext = FakeContext
    base.run_adapter = scanners.run_adapter
    registry = types.ModuleType("kalkan.scanners.registry")
    registry.get = lambda name: types.SimpleNamespace(name=name)
    candidates = types.ModuleType("kalkan.scanners.candidates")
    candidates.merge_candidates = scanners.merge_candidates
    for name, module in (("base", base), ("registry", registry), ("candidates", candidates)):
        monkeypatch.setitem(sys.modules, f"kalkan.scanners.{name}", module)
        monkeypatch.setattr(scanners_package, name, module, raising=False)
    return scanners


@pytest.fixture
def kalkan_home(tmp_path, monkeypatch) -> Path:
    """A kalkan home with the test RetireJS repository: ``sca match`` never reads the local
    databases of the developer, and the vendored JavaScript check runs on the test data."""
    home = tmp_path / "home"
    folder = home / ".tools" / "vulndb" / "retire"
    folder.mkdir(parents=True)
    shutil.copyfile(RETIRE_REPOSITORY, folder / "jsrepository-v5.json")
    monkeypatch.setenv("KALKAN_HOME", str(home))
    return home


@pytest.fixture
def run_dir(tmp_path, monkeypatch, kalkan_home) -> Path:
    root = tmp_path / "runs"
    directory = root / RUN_ID
    shutil.copytree(DEPAPP, directory / "target")
    monkeypatch.setenv("KALKAN_RUNS_DIR", str(root))
    return directory


# --- CLI ---------------------------------------------------------------------------------------


def test_sca_group_without_step_prints_help(capsys):
    assert cli.main(["sca"]) == 2
    assert "sbom" in capsys.readouterr().err


def test_cli_match_json(fake, run_dir, capsys):
    assert cli.main(["sca", "match", "--run", RUN_ID, "--json", "--offline"]) == 0
    captured = capsys.readouterr()
    summary = json.loads(captured.out)
    assert summary["merged"] == 14
    assert "sca match: 28 records, 14 after merge" in captured.err
    assert all(ctx.offline for _, ctx, _ in fake.calls)


def test_cli_sbom_and_reach(fake, run_dir, capsys):
    assert cli.main(["sca", "sbom", "--run", RUN_ID, "--timeout", "60"]) == 0
    assert "syft ok, 9 components" in capsys.readouterr().err
    assert fake.calls[0][2] == 60
    assert cli.main(["sca", "match", "--run", RUN_ID]) == 0
    assert cli.main(["sca", "reach", "--run", RUN_ID, "--json", "--max-tasks", "3"]) == 0
    summary = json.loads(capsys.readouterr().out)
    assert len(summary["selected_for_agents"]) == 3


def test_cli_without_scanner_layer_reports_a_tool_error(run_dir, monkeypatch, capsys):
    monkeypatch.setitem(sys.modules, "kalkan.scanners.base", None)
    monkeypatch.delattr(scanners_package, "base", raising=False)
    assert cli.main(["sca", "sbom", "--run", RUN_ID]) == 5
    assert "kalkan.scanners is not available" in capsys.readouterr().err


def test_cli_without_run_reports_an_error(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("KALKAN_RUNS_DIR", str(tmp_path / "empty"))
    assert cli.main(["sca", "match"]) == 1
    assert "no run found" in capsys.readouterr().err


# --- sca sbom ----------------------------------------------------------------------------------


def test_run_sbom_with_syft(fake, run_dir):
    summary = commands.run_sbom(run_dir, offline=True)
    assert summary["engine"] == "syft"
    assert summary["components"] == 9
    assert summary["by_ecosystem"] == {"Go": 2, "PyPI": 3, "npm": 4}
    assert summary["sbom"] == "sca/sbom.cdx.json"
    assert (run_dir / "sca" / "sbom.cdx.json").is_file()
    assert fake.names() == ["syft"]
    ctx = fake.calls[0][1]
    assert ctx.offline is True
    assert Path(ctx.target_dir) == run_dir / "target"


def test_run_sbom_falls_back_to_trivy(fake, run_dir):
    fake.behavior["syft"] = failing("failed", "exit code 1")
    summary = commands.run_sbom(run_dir)
    assert summary["engine"] == "trivy-sbom"
    assert summary["components"] == 8
    assert fake.names() == ["syft", "trivy-sbom"]
    assert summary["warnings"][0] == "syft: failed: exit code 1"
    copied = json.loads((run_dir / "sca" / "sbom.cdx.json").read_text(encoding="utf-8"))
    assert copied["metadata"]["tools"]["components"][0]["name"] == "trivy"


def test_run_sbom_rejects_a_broken_sbom_and_falls_back(fake, run_dir):
    def broken(ctx):
        out = Path(ctx.run_dir) / "sca" / "sbom.cdx.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text('{"spdxVersion": "SPDX-2.3"}', encoding="utf-8")
        return FakeResult("syft", "ok", out, "")

    fake.behavior["syft"] = broken
    summary = commands.run_sbom(run_dir)
    assert summary["engine"] == "trivy-sbom"
    assert "not a CycloneDX" in summary["warnings"][0]


def test_run_sbom_without_tools_raises(fake, run_dir):
    fake.behavior["syft"] = failing("skipped", "syft is not installed")
    fake.behavior["trivy-sbom"] = failing("skipped", "trivy is not installed")
    with pytest.raises(ToolError, match="syft is not installed"):
        commands.run_sbom(run_dir)


def test_scan_context_prefers_load_scan_context(fake, run_dir):
    seen = []

    def load_scan_context(directory, *, offline=False):
        seen.append((Path(directory), offline))
        return FakeContext(Path(directory), Path(directory) / "target", None, frozenset(), offline)

    sys.modules["kalkan.scanners.base"].load_scan_context = load_scan_context
    (run_dir / "target-manifest.json").write_text('{"tech": ["go"]}', encoding="utf-8")
    ctx = commands.scan_context(run_dir, offline=True)
    assert seen == [(run_dir, True)]
    assert ctx.offline is True


def test_scan_context_reads_tech_from_the_manifest_or_detects_it(fake, run_dir):
    ctx = commands.scan_context(run_dir)
    assert {"go", "node", "python"} <= set(ctx.tech)


# --- sca match ---------------------------------------------------------------------------------


def test_run_match_writes_vulns_and_candidates(fake, run_dir):
    summary = commands.run_match(run_dir)
    assert summary["records"] == 28
    assert summary["merged"] == 14
    assert summary["candidates"] == 14
    assert summary["engines"]["osv-scanner"]["records"] == 17
    assert summary["engines"]["grype"]["records"] == 11
    assert summary["engines"]["osv-scanner"]["output"] == "sca/osv.json"
    assert summary["by_severity"]["critical"] == 4
    assert summary["examples"][0] == "PyPI/pyyaml@5.3/GHSA-6757-jp84-gxfx"
    assert summary["warnings"] == []
    doc = read_vulns(run_dir)
    assert validate_vulns(doc) == []
    assert len(doc["records"]) == 14
    (path, source, candidates, warnings) = fake.merged[-1]
    assert (path, source, warnings) == (run_dir, "sca", [])
    assert {c["file"] for c in candidates} == {"requirements.txt", "package-lock.json", "go.mod"}


def test_run_match_offline_with_a_missing_database_continues(fake, run_dir):
    fake.behavior["grype"] = failing("failed", "database does not exist")
    summary = commands.run_match(run_dir, offline=True)
    assert summary["engines"]["grype"]["status"] == "failed"
    assert summary["engines"]["osv-scanner"]["status"] == "ok"
    assert summary["warnings"] == ["grype: failed: database does not exist"]
    assert summary["merged"] == 14
    assert all(ctx.offline for _, ctx, _ in fake.calls)
    assert read_vulns(run_dir)["warnings"] == ["grype: failed: database does not exist"]
    assert fake.merged[-1][3] == ["grype: failed: database does not exist"]


def test_run_match_without_any_result_keeps_the_old_vulns(fake, run_dir):
    write_vulns(run_dir, [], ["old"])
    fake.behavior["osv-scanner"] = failing("failed", "offline database missing")
    fake.behavior["grype"] = failing("skipped", "grype is not installed")
    with pytest.raises(ToolError, match="no vulnerability matcher"):
        commands.run_match(run_dir)
    assert read_vulns(run_dir)["warnings"] == ["old"]


def test_run_match_with_unparsable_output_warns(fake, run_dir):
    def garbage(ctx):
        out = Path(ctx.run_dir) / "sca" / "grype.json"
        out.write_text("not json", encoding="utf-8")
        return FakeResult("grype", "ok", out, "")

    fake.behavior["grype"] = garbage
    summary = commands.run_match(run_dir)
    assert summary["engines"]["grype"]["status"] == "failed"
    assert summary["warnings"] and summary["warnings"][0].startswith("grype: ")


def test_run_match_carries_over_reachability(fake, run_dir):
    commands.run_match(run_dir)
    doc = read_vulns(run_dir)
    record = next(r for r in doc["records"] if r["ref"] == "PyPI/pyyaml@5.3/GHSA-8q59-q68h-6hv4")
    set_reachability(
        record, "not_reachable", reason="build only", source="sca_reach", searched=["import yaml"]
    )
    write_vulns(run_dir, doc["records"], [])
    summary = commands.run_match(run_dir)
    assert summary["carried_over"] == 1
    record = next(
        r
        for r in read_vulns(run_dir)["records"]
        if r["ref"] == "PyPI/pyyaml@5.3/GHSA-8q59-q68h-6hv4"
    )
    assert (record["reachability"], record["severity"], record["severity_original"]) == (
        "not_reachable",
        "high",
        "critical",
    )


def test_run_match_marks_malicious_packages_and_reach_skips_them(fake, run_dir, capsys):
    # Recorded outputs of OSV-Scanner and Grype for two PyPI packages with MAL- records
    # (tests/fixtures/sca/malicious; nothing is installed).
    shutil.rmtree(run_dir / "target")
    shutil.copytree(FIXTURES / "malicious" / "app", run_dir / "target")
    fake.behavior["osv-scanner"] = ok("osv.json", "malicious/osv.json", replace_target=True)
    fake.behavior["grype"] = ok("grype.json", "malicious/grype.json")
    assert cli.main(["sca", "match", "--run", RUN_ID]) == 0
    err = capsys.readouterr().err
    assert "sca match: 4 records, 2 after merge, 2 candidates" in err
    assert "malicious packages: 2 (class malicious-dependency, critical" in err
    summary = commands.run_match(run_dir)
    assert summary["malicious"] == [
        "PyPI/sample-module@0.0.1/MAL-2025-41758",
        "PyPI/test-async@1.0.0/MAL-2022-7428",
    ]
    assert summary["by_severity"]["critical"] == 2
    records = read_vulns(run_dir)["records"]
    assert {(r["class"], r["severity"], r["reachability"]) for r in records} == {
        ("malicious-dependency", "critical", "unknown")
    }
    candidates = fake.merged[-1][2]
    assert {(c["class"], c["severity"], c["file"]) for c in candidates} == {
        ("malicious-dependency", "critical", "requirements.txt")
    }
    reach = commands.run_reach(run_dir, max_tasks=10)
    assert reach["selected_for_agents"] == []
    assert {r["severity"] for r in read_vulns(run_dir)["records"]} == {"critical"}


# --- sca reach ---------------------------------------------------------------------------------


def test_run_reach_applies_govulncheck_and_selects(fake, run_dir):
    commands.run_match(run_dir)
    summary = commands.run_reach(run_dir, max_tasks=50)
    assert summary["govulncheck"]["status"] == "ok"
    assert summary["govulncheck"]["counts"] == {"reachable": 1, "not_reachable": 2, "unchanged": 1}
    assert summary["reachability"] == {"reachable": 1, "not_reachable": 2, "unknown": 11}
    selected = summary["selected_for_agents"]
    assert "Go/golang.org/x/text@0.3.5/GHSA-ppp9-7jff-5vj2" not in selected
    assert selected[0] == "PyPI/pyyaml@5.3/GHSA-6757-jp84-gxfx"
    assert summary["remaining_budget"] == 50
    records = read_vulns(run_dir)["records"]
    reachable = next(r for r in records if r["reachability"] == "reachable")
    assert reachable["reach_evidence"][0]["file"] == "main.go"
    tags = {c["fingerprints"]["kalkanSca/v1"]: c["tags"] for c in fake.merged[-1][2]}
    assert "reachability:reachable" in tags["Go/golang.org/x/text@0.3.5/GHSA-ppp9-7jff-5vj2"]


def test_run_reach_when_govulncheck_is_unavailable(fake, run_dir):
    commands.run_match(run_dir)
    fake.behavior["govulncheck"] = failing("skipped", "Go 1.26 or later is not on PATH")
    summary = commands.run_reach(run_dir, max_tasks=5)
    assert summary["govulncheck"]["status"] == "skipped"
    assert summary["reachability"]["unknown"] == 14
    assert len(summary["selected_for_agents"]) == 5
    assert "govulncheck: skipped: Go 1.26 or later is not on PATH" in summary["warnings"]


def test_run_reach_records_the_missing_go_database_as_a_gap(fake, run_dir):
    commands.run_match(run_dir)
    fake.behavior["govulncheck"] = failing("skipped", vulndb.GO_DB_MISSING)
    summary = commands.run_reach(run_dir)
    assert summary["govulncheck"]["message"] == vulndb.GO_DB_MISSING
    gaps = read_vulns(run_dir)["database_gaps"]
    [gap] = [item for item in gaps if item["engine"] == "govulncheck"]
    assert gap["ecosystem"] == "Go" and "kalkan sca update-db" in gap["reason"]
    validate_vulns(read_vulns(run_dir))
    # A later run with the database removes the gap.
    fake.behavior["govulncheck"] = DEFAULT_BEHAVIOR["govulncheck"]
    commands.run_reach(run_dir)
    after = read_vulns(run_dir).get("database_gaps") or []
    assert [item for item in after if item["engine"] == "govulncheck"] == []


def test_run_reach_names_the_go_packages_that_did_not_load(fake, run_dir):
    commands.run_match(run_dir)
    status = {
        "engine": "govulncheck",
        "status": "failed",
        "partial_packages": {
            "count": 1,
            "packages": [
                {
                    "package": ".",
                    "files": ["main.go"],
                    "missing_imports": ["example.com/dep"],
                    "errors": ["main.go:6:2: could not import example.com/dep"],
                    "reason": "the module of example.com/dep is not in the local module cache",
                }
            ],
            "truncated": False,
            "mode": "local",
            "hint": "kalkan sca reach --online or a vendor/ folder",
        },
    }
    (run_dir / "sca" / "govulncheck.status.json").write_text(json.dumps(status), encoding="utf-8")
    fake.behavior["govulncheck"] = failing("failed", "exit code 1 (expected 0): For details")
    summary = commands.run_reach(run_dir)
    gv = summary["govulncheck"]
    assert gv["status"] == "failed" and gv["partial_packages"] == 1
    assert gv["message"].startswith("1 Go packages could not load: the module of example.com/dep")
    assert "kalkan sca reach --online" in gv["message"]
    assert any(w.startswith("govulncheck: failed: 1 Go packages") for w in summary["warnings"])


def test_run_reach_without_go_records_skips_govulncheck(fake, run_dir):
    record = new_record(
        ecosystem="npm",
        package="minimist",
        version="1.2.5",
        ids=["GHSA-xvch-5gv4-984h"],
        cvss_score=9.8,
        engine="osv-scanner",
        locations=["package-lock.json"],
    )
    write_vulns(run_dir, [record], [])
    summary = commands.run_reach(run_dir)
    assert summary["govulncheck"]["status"] == "skipped"
    assert fake.names() == []
    assert summary["selected_for_agents"] == ["npm/minimist@1.2.5/GHSA-xvch-5gv4-984h"]


def test_run_reach_requires_vulns(fake, run_dir):
    with pytest.raises(StateError, match="sca match"):
        commands.run_reach(run_dir)


# --- integration with the real candidate store -------------------------------------------------


def test_write_candidates_with_the_real_merge_candidates(tmp_path):
    candidates_module = pytest.importorskip("kalkan.scanners.candidates")
    from kalkan.sca.merge import write_candidates
    from kalkan.sca.normalize import parse_grype

    run = tmp_path / "run"
    shutil.copytree(DEPAPP, run / "target")
    doc = json.loads((FIXTURES / "grype.json").read_text(encoding="utf-8"))
    records = parse_grype(doc, run / "target").records
    assert write_candidates(run, records, ["w"]) == len(records)
    stored = candidates_module.load_candidates(run)
    assert stored["sources"]["sca"]["count"] == len(records)
    assert "sca: w" in stored["warnings"]


# --- real tools ---------------------------------------------------------------------------------


@pytest.mark.tools
def test_real_syft_sbom_on_the_depapp(tmp_path, monkeypatch):
    pytest.importorskip("kalkan.scanners.registry")
    from kalkan.tools.resolve import resolve

    if resolve("syft") is None:
        pytest.skip("syft is not installed")
    root = tmp_path / "runs"
    run = root / RUN_ID
    shutil.copytree(DEPAPP, run / "target")
    monkeypatch.setenv("KALKAN_RUNS_DIR", str(root))
    summary = commands.run_sbom(run)
    assert summary["engine"] == "syft"
    assert summary["by_ecosystem"].get("PyPI") == 3
    assert summary["by_ecosystem"].get("Go") == 2


# --- manifests without a lockfile --------------------------------------------------------------


def _pins_osv(ctx):
    pins = Path(ctx.run_dir) / "sca" / "manifest-pins.cdx.json"
    entry = {
        "id": "GHSA-p6mc-m468-83gw",
        "aliases": ["CVE-2020-8203"],
        "summary": "Prototype pollution in lodash",
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "lodash"},
                "ranges": [
                    {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.19"}]}
                ],
            }
        ],
        "database_specific": {"severity": "HIGH"},
    }
    doc = {
        "results": [
            {
                "source": {"path": str(pins), "type": "sbom"},
                "packages": [
                    {
                        "package": {"name": "lodash", "version": "4.17.15", "ecosystem": "npm"},
                        "vulnerabilities": [entry],
                        "groups": [
                            {
                                "ids": ["GHSA-p6mc-m468-83gw"],
                                "aliases": ["CVE-2020-8203", "GHSA-p6mc-m468-83gw"],
                                "max_severity": "7.4",
                            }
                        ],
                    }
                ],
            }
        ]
    }
    out = Path(ctx.run_dir) / "sca" / "osv-pins.json"
    out.write_text(json.dumps(doc), encoding="utf-8")
    return FakeResult("osv-scanner-pins", "ok", out, "")


def _pins_grype(ctx):
    doc = {
        "matches": [
            {
                "vulnerability": {
                    "id": "GHSA-p6mc-m468-83gw",
                    "severity": "High",
                    "fix": {"versions": ["4.17.19"]},
                },
                "relatedVulnerabilities": [{"id": "CVE-2020-8203"}],
                "artifact": {
                    "name": "lodash",
                    "version": "4.17.15",
                    "type": "npm",
                    "purl": "pkg:npm/lodash@4.17.15",
                },
            },
            {
                "vulnerability": {"id": "GHSA-xxxx-xxxx-xxxx", "severity": "Low"},
                "artifact": {"name": "other", "version": "1.0.0", "purl": "pkg:npm/other@1.0.0"},
            },
        ]
    }
    out = Path(ctx.run_dir) / "sca" / "grype-pins.json"
    out.write_text(json.dumps(doc), encoding="utf-8")
    return FakeResult("grype-pins", "ok", out, "")


@pytest.fixture
def unlocked(fake, run_dir) -> Path:
    web = run_dir / "target" / "web"
    web.mkdir()
    (web / "package.json").write_text(
        json.dumps({"dependencies": {"lodash": "4.17.15", "express": "^4.18.2"}}, indent=2),
        encoding="utf-8",
    )
    fake.behavior["osv-scanner-pins"] = _pins_osv
    fake.behavior["grype-pins"] = _pins_grype
    return run_dir


def test_run_match_checks_the_exact_pins_of_unlocked_manifests(fake, unlocked):
    run_dir = unlocked
    summary = commands.run_match(run_dir)
    assert fake.names() == ["osv-scanner", "grype", "osv-scanner-pins", "grype-pins"]
    assert summary["unchecked_manifests"] == [
        {
            "file": "web/package.json",
            "ecosystem": "npm",
            "reason": "version ranges without a lockfile",
            "exact_pins": 1,
            "ranges": 1,
        }
    ]
    assert summary["manifest_pins"] == 1
    assert summary["pin_records"] == 1
    assert summary["engines"]["osv-scanner-pins"]["records"] == 1
    assert summary["engines"]["grype-pins"]["records"] == 1
    assert summary["merged"] == 15
    assert summary["warnings"][0].startswith("web/package.json: npm manifest without a lockfile")
    assert "grype-pins: npm/other@1.0.0/GHSA-xxxx-xxxx-xxxx matches no manifest pin" in (
        " ".join(summary["warnings"])
    )
    pins = json.loads((run_dir / "sca" / "manifest-pins.cdx.json").read_text("utf-8"))
    assert [c["purl"] for c in pins["components"]] == ["pkg:npm/lodash@4.17.15"]
    doc = read_vulns(run_dir)
    assert validate_vulns(doc) == []
    assert doc["unchecked_manifests"] == summary["unchecked_manifests"]
    [record] = [r for r in doc["records"] if r.get("pin_source")]
    assert record["ref"] == "npm/lodash@4.17.15/GHSA-p6mc-m468-83gw"
    assert record["engines"] == ["osv-scanner", "grype"]
    assert record["locations"] == ["web/package.json"]
    assert record["severity"] == "high"
    [candidate] = [c for c in fake.merged[-1][2] if c["file"] == "web/package.json"]
    assert candidate["start_line"] == 3 and "pin-source:manifest" in candidate["tags"]


NUGET_VULN = {
    "id": "GHSA-5crp-9r3c-p9vr",
    "aliases": ["CVE-2024-21907"],
    "summary": "Improper handling of exceptional conditions in Newtonsoft.Json",
    "affected": [
        {
            "package": {"ecosystem": "NuGet", "name": "Newtonsoft.Json"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "13.0.1"}]}],
        }
    ],
    "database_specific": {"severity": "HIGH"},
}


def _nuget_pins_osv(ctx):
    pins = Path(ctx.run_dir) / "sca" / "manifest-pins.cdx.json"
    package = {"name": "Newtonsoft.Json", "version": "12.0.3", "ecosystem": "NuGet"}
    doc = {
        "results": [
            {
                "source": {"path": str(pins), "type": "sbom"},
                "packages": [
                    {
                        "package": package,
                        "vulnerabilities": [NUGET_VULN],
                        "groups": [
                            {
                                "ids": ["GHSA-5crp-9r3c-p9vr"],
                                "aliases": ["CVE-2024-21907", "GHSA-5crp-9r3c-p9vr"],
                                "max_severity": "7.5",
                            }
                        ],
                    }
                ],
            }
        ]
    }
    out = Path(ctx.run_dir) / "sca" / "osv-pins.json"
    out.write_text(json.dumps(doc), encoding="utf-8")
    return FakeResult("osv-scanner-pins", "ok", out, "")


def _nuget_pins_grype(ctx):
    doc = {
        "matches": [
            {
                "vulnerability": {
                    "id": "GHSA-5crp-9r3c-p9vr",
                    "severity": "High",
                    "fix": {"versions": ["13.0.1"]},
                },
                "relatedVulnerabilities": [{"id": "CVE-2024-21907"}],
                "artifact": {
                    "name": "Newtonsoft.Json",
                    "version": "12.0.3",
                    "type": "dotnet",
                    "purl": "pkg:nuget/Newtonsoft.Json@12.0.3",
                },
            }
        ]
    }
    out = Path(ctx.run_dir) / "sca" / "grype-pins.json"
    out.write_text(json.dumps(doc), encoding="utf-8")
    return FakeResult("grype-pins", "ok", out, "")


def test_run_match_checks_the_central_nuget_pins(fake, run_dir):
    target = run_dir / "target"
    (target / "Directory.Packages.props").write_text(
        "\n".join(
            [
                "<Project>",
                "  <PropertyGroup>",
                "    <ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally>",
                "    <CentralPackageTransitivePinningEnabled>true"
                "</CentralPackageTransitivePinningEnabled>",
                "  </PropertyGroup>",
                "  <ItemGroup>",
                '    <PackageVersion Include="Newtonsoft.Json" Version="12.0.3" />',
                '    <PackageVersion Include="System.Text.Json" Version="8.0.4" />',
                "  </ItemGroup>",
                "</Project>",
            ]
        ),
        encoding="utf-8",
    )
    api = target / "src" / "Api"
    api.mkdir(parents=True)
    (api / "Api.csproj").write_text(
        "\n".join(
            [
                '<Project Sdk="Microsoft.NET.Sdk.Web">',
                "  <ItemGroup>",
                '    <PackageReference Include="Newtonsoft.Json" />',
                "  </ItemGroup>",
                "</Project>",
            ]
        ),
        encoding="utf-8",
    )
    fake.behavior["osv-scanner-pins"] = _nuget_pins_osv
    fake.behavior["grype-pins"] = _nuget_pins_grype
    summary = commands.run_match(run_dir)
    assert fake.names() == ["osv-scanner", "grype", "osv-scanner-pins", "grype-pins"]
    assert summary["unchecked_manifests"] == [
        {
            "file": "src/Api/Api.csproj",
            "ecosystem": "NuGet",
            "reason": "no lockfile: the exact pins were checked, transitive dependencies were not",
            "exact_pins": 1,
            "ranges": 0,
        }
    ]
    assert summary["manifest_pins"] == 2  # the direct pin and the transitive pin
    assert summary["pin_records"] == 1
    assert summary["warnings"][0].startswith(
        "src/Api/Api.csproj: NuGet manifest without a lockfile"
    )
    pins = json.loads((run_dir / "sca" / "manifest-pins.cdx.json").read_text("utf-8"))
    assert [(c["purl"], c["properties"]) for c in pins["components"]] == [
        (
            "pkg:nuget/Newtonsoft.Json@12.0.3",
            [{"name": "kalkan:manifest:path", "value": "src/Api/Api.csproj"}],
        ),
        (
            "pkg:nuget/System.Text.Json@8.0.4",
            [
                {"name": "kalkan:manifest:path", "value": "Directory.Packages.props"},
                {"name": "kalkan:manifest:transitive-pin", "value": "true"},
            ],
        ),
    ]
    doc = read_vulns(run_dir)
    assert validate_vulns(doc) == []
    assert doc["unchecked_manifests"] == summary["unchecked_manifests"]
    [record] = [r for r in doc["records"] if r.get("pin_source")]
    assert record["ref"] == "NuGet/Newtonsoft.Json@12.0.3/GHSA-5crp-9r3c-p9vr"
    assert record["engines"] == ["osv-scanner", "grype"]
    assert record["locations"] == ["src/Api/Api.csproj"]
    assert record["pin_source"] == "manifest"
    [candidate] = [c for c in fake.merged[-1][2] if c["file"] == "src/Api/Api.csproj"]
    assert candidate["start_line"] == 3 and "pin-source:manifest" in candidate["tags"]


def test_run_reach_keeps_the_unchecked_manifests(fake, unlocked):
    commands.run_match(unlocked)
    fake.behavior["govulncheck"] = failing("skipped", "no Go")
    commands.run_reach(unlocked, max_tasks=1)
    assert read_vulns(unlocked)["unchecked_manifests"][0]["file"] == "web/package.json"


def test_failed_pin_matchers_only_warn(fake, unlocked):
    fake.behavior["osv-scanner-pins"] = failing("failed", "exit code 2")
    fake.behavior["grype-pins"] = failing("timeout", "timed out after 5 s")
    summary = commands.run_match(unlocked)
    assert summary["engines"]["osv-scanner-pins"]["status"] == "failed"
    assert summary["engines"]["grype-pins"]["status"] == "timeout"
    assert summary["pin_records"] == 0
    assert "osv-scanner-pins: failed: exit code 2" in summary["warnings"]


def test_without_pins_the_old_pin_files_go_away(fake, run_dir):
    sca = run_dir / "sca"
    sca.mkdir()
    for name in ("manifest-pins.cdx.json", "osv-scanner-pins.status.json"):
        (sca / name).write_text("{}", encoding="utf-8")
    summary = commands.run_match(run_dir)
    assert fake.names() == ["osv-scanner", "grype"]
    assert summary["unchecked_manifests"] == [] and summary["pin_records"] == 0
    assert not (sca / "manifest-pins.cdx.json").exists()
    assert not (sca / "osv-scanner-pins.status.json").exists()
    assert read_vulns(run_dir)["unchecked_manifests"] == []


# --- vendored JavaScript libraries ---------------------------------------------------------------

VULNAPP_LIB = FIXTURES.parent / "vulnapp" / "csharp" / "wwwroot" / "lib"
VENDORED = "wwwroot/lib/bootstrap/js/bootstrap.min.js"
VENDORED_TWIN = "wwwroot/lib/bootstrap-current/js/bootstrap.bundle.min.js"
BOOTSTRAP_VULN = {
    "id": "GHSA-9v3m-8fp8-mj99",
    "aliases": ["CVE-2019-8331"],
    "summary": "Bootstrap vulnerable to Cross-Site Scripting",
    "affected": [
        {
            "package": {"ecosystem": "npm", "name": "bootstrap"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "3.0.0"}, {"fixed": "3.4.1"}]}],
        }
    ],
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"}],
}


def _vendored_osv(ctx):
    pins = json.loads((Path(ctx.run_dir) / "sca" / "manifest-pins.cdx.json").read_text("utf-8"))
    assert {c["purl"] for c in pins["components"]} == {
        "pkg:npm/bootstrap@3.3.7",
        "pkg:npm/bootstrap@5.3.8",
    }
    doc = {
        "results": [
            {
                "source": {"path": "manifest-pins.cdx.json", "type": "sbom"},
                "packages": [
                    {
                        "package": {"name": "bootstrap", "version": "3.3.7", "ecosystem": "npm"},
                        "vulnerabilities": [BOOTSTRAP_VULN],
                        "groups": [
                            {
                                "ids": ["GHSA-9v3m-8fp8-mj99"],
                                "aliases": ["CVE-2019-8331", "GHSA-9v3m-8fp8-mj99"],
                                "max_severity": "6.1",
                            }
                        ],
                    }
                ],
            }
        ]
    }
    out = Path(ctx.run_dir) / "sca" / "osv-pins.json"
    out.write_text(json.dumps(doc), encoding="utf-8")
    return FakeResult("osv-scanner-pins", "ok", out, "")


def _vendored_grype(ctx):
    doc = {
        "matches": [
            {
                "vulnerability": {
                    "id": "GHSA-9v3m-8fp8-mj99",
                    "severity": "Medium",
                    "fix": {"versions": ["3.4.1"]},
                },
                "relatedVulnerabilities": [{"id": "CVE-2019-8331"}],
                "artifact": {
                    "name": "bootstrap",
                    "version": "3.3.7",
                    "type": "npm",
                    "purl": "pkg:npm/bootstrap@3.3.7",
                },
            }
        ]
    }
    out = Path(ctx.run_dir) / "sca" / "grype-pins.json"
    out.write_text(json.dumps(doc), encoding="utf-8")
    return FakeResult("grype-pins", "ok", out, "")


@pytest.fixture
def vendored_run(fake, run_dir) -> Path:
    shutil.copytree(VULNAPP_LIB, run_dir / "target" / "wwwroot" / "lib")
    fake.behavior["osv-scanner-pins"] = _vendored_osv
    fake.behavior["grype-pins"] = _vendored_grype
    return run_dir


def test_run_match_checks_vendored_javascript_end_to_end(fake, vendored_run):
    run_dir = vendored_run
    summary = commands.run_match(run_dir)
    assert fake.names() == ["osv-scanner", "grype", "osv-scanner-pins", "grype-pins"]
    assert summary["engines"]["retirejs"]["status"] == "ok"
    assert summary["engines"]["retirejs"]["records"] == 3
    assert [(item["path"], item["version"]) for item in summary["vendored_libraries"]] == [
        (VENDORED_TWIN, "5.3.8"),
        (VENDORED, "3.3.7"),
    ]
    assert summary["vendored_records"] == 3
    assert "  vendored JavaScript libraries: 2 in 2 files (3 records)" in commands._match_lines(
        summary
    )
    doc = read_vulns(run_dir)
    assert validate_vulns(doc) == []
    vendored = [r for r in doc["records"] if r.get("vendored")]
    assert sorted(r["ref"] for r in vendored) == [
        "npm/bootstrap@3.3.7/GHSA-3wqf-4x89-9g79",
        "npm/bootstrap@3.3.7/GHSA-9v3m-8fp8-mj99",
        "npm/bootstrap@3.3.7/RETIRE-bootstrap-retid-72",
    ]
    merged = next(r for r in vendored if r["vuln_id"] == "GHSA-9v3m-8fp8-mj99")
    assert merged["engines"] == ["osv-scanner", "grype", "retirejs"]
    assert merged["pin_source"] == "vendored" and merged["locations"] == [VENDORED]
    assert merged["aliases"] == ["CVE-2019-8331"] and merged["fixed_versions"] == ["3.4.1"]
    assert merged["cvss_score"] == 6.1
    assert merged["vendored"] == [
        {
            "file": VENDORED,
            "line": 2,
            "library": "bootstrap",
            "version": "3.3.7",
            "extractor": "filecontent",
        }
    ]
    assert merged["references"] == ["https://github.com/advisories/GHSA-9v3m-8fp8-mj99"]
    assert not any(r["version"] == "5.3.8" for r in doc["records"])  # the secure twin
    status = json.loads((run_dir / "sca" / "retirejs.status.json").read_text("utf-8"))
    assert status["status"] == "ok" and status["libraries"] == 2
    found = json.loads((run_dir / "sca" / "vendored.json").read_text("utf-8"))
    assert found["libraries"][1]["purl"] == "pkg:npm/bootstrap@3.3.7"
    pins = json.loads((run_dir / "sca" / "manifest-pins.cdx.json").read_text("utf-8"))
    component = next(c for c in pins["components"] if c["version"] == "3.3.7")
    assert {"name": "kalkan:vendored:path", "value": VENDORED} in component["properties"]
    [candidate] = [
        c for c in fake.merged[-1][2] if c["fingerprints"]["kalkanSca/v1"] == merged["ref"]
    ]
    assert (candidate["file"], candidate["start_line"]) == (VENDORED, 2)
    assert candidate["snippet"] == "* Bootstrap v3.3.7 (http://getbootstrap.com)"
    assert "pin-source:vendored" in candidate["tags"] and candidate["engine"] == "osv-scanner"
    assert f"Vendored copy without a package manager: {VENDORED}." in candidate["message"]
    retire_only = next(c for c in fake.merged[-1][2] if c["rule_id"].startswith("RETIRE-"))
    assert retire_only["engine"] == "retirejs"


def test_vendored_records_keep_their_reachability_and_reach_input(fake, vendored_run):
    from kalkan.sca.reach import build_reach_input

    commands.run_match(vendored_run)
    record = next(
        r for r in read_vulns(vendored_run)["records"] if r["vuln_id"] == "GHSA-9v3m-8fp8-mj99"
    )
    task = build_reach_input(record, vendored_run / "target")
    assert task["vendored"] == [
        {"file": VENDORED, "line": 2, "library": "bootstrap", "version": "3.3.7"}
    ]
    assert task["locations"] == [{"file": VENDORED, "line": 2}]
    assert "bootstrap.min.js" in task["import_patterns"]
    assert "bootstrap.js" in task["import_patterns"]
    assert 'require("bootstrap")' in task["import_patterns"]


def test_a_missing_retire_repository_is_a_database_gap(fake, run_dir, kalkan_home):
    shutil.rmtree(kalkan_home / ".tools" / "vulndb" / "retire")
    summary = commands.run_match(run_dir)
    [gap] = summary["database_gaps"]
    assert (gap["engine"], gap["ecosystem"]) == ("retirejs", None)
    assert gap["reason"].startswith("no local RetireJS repository (run: kalkan sca update-db)")
    assert summary["engines"]["retirejs"]["status"] == "skipped"
    assert any(w.startswith("retirejs: skipped: no local RetireJS") for w in summary["warnings"])
    assert read_vulns(run_dir)["database_gaps"] == [gap]


def test_match_lines_mention_the_unchecked_manifests():
    lines = commands._match_lines(
        {
            "records": 1,
            "merged": 1,
            "candidates": 1,
            "engines": {},
            "by_severity": {"high": 1},
            "unchecked_manifests": [{"file": "a"}],
            "manifest_pins": 2,
        }
    )
    assert lines[-1] == (
        "  manifests without a lockfile: 1 (2 exact pins checked, version ranges not checked)"
    )


# --- promise 3: local databases only -----------------------------------------------------------


def test_sca_commands_are_local_by_default_and_online_is_opt_in(fake, run_dir):
    assert cli.main(["sca", "match", "--run", RUN_ID]) == 0
    assert all(ctx.offline for _, ctx, _ in fake.calls)
    fake.calls.clear()
    assert cli.main(["sca", "match", "--run", RUN_ID, "--online"]) == 0
    assert not any(ctx.offline for _, ctx, _ in fake.calls)
    assert commands.run_match.__kwdefaults__["offline"] is True
    assert commands.run_sbom.__kwdefaults__["offline"] is True
    assert commands.run_reach.__kwdefaults__["offline"] is True


def write_status(run_dir: Path, name: str, data: dict) -> None:
    path = run_dir / "sca" / f"{name}.status.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


def test_missing_databases_become_gaps_not_online_queries(fake, run_dir):
    def osv_missing(ctx):
        write_status(run_dir, "osv-scanner", {"missing_databases": ["PyPI"]})
        return FakeResult("osv-scanner", "failed", None, "exit code 127 (expected 0, 1)")

    fake.behavior["osv-scanner"] = osv_missing
    summary = commands.run_match(run_dir)
    assert summary["engines"]["grype"]["status"] == "ok"
    [gap] = summary["database_gaps"]
    assert gap["engine"] == "osv-scanner" and gap["ecosystem"] == "PyPI"
    assert "kalkan sca update-db --ecosystems" in gap["reason"]
    assert read_vulns(run_dir)["database_gaps"] == [gap]
    assert any("database gap" in line for line in commands._match_lines(summary))


def test_no_local_database_at_all_records_gaps_and_keeps_going(fake, run_dir):
    fake.behavior["osv-scanner"] = failing(
        "skipped", "no local OSV database (run: kalkan sca update-db)"
    )
    fake.behavior["grype"] = failing(
        "skipped", "no local Grype database (run: kalkan sca update-db)"
    )
    summary = commands.run_match(run_dir)
    assert summary["merged"] == 0
    assert [(gap["engine"], gap["ecosystem"]) for gap in summary["database_gaps"]] == [
        ("osv-scanner", None),
        ("grype", None),
    ]
    doc = read_vulns(run_dir)
    assert doc["records"] == [] and len(doc["database_gaps"]) == 2
    assert any("no package was checked" in warning for warning in doc["warnings"])


def test_run_reach_keeps_the_database_gaps(fake, run_dir):
    fake.behavior["grype"] = failing(
        "skipped", "no local Grype database (run: kalkan sca update-db)"
    )
    commands.run_match(run_dir)
    commands.run_reach(run_dir, max_tasks=0)
    assert read_vulns(run_dir)["database_gaps"][0]["engine"] == "grype"


# --- sca update-db -----------------------------------------------------------------------------


class FakeTool:
    def __init__(self, name: str) -> None:
        self.argv = [f"/opt/{name}"]


def update_runner(root: Path, calls: list, *, osv_ok=True, grype_ok=True):
    from kalkan.scanners.base import ProcessOutcome

    def run(argv, *, cwd, env, timeout, stdout, stderr):
        calls.append((list(argv), dict(env)))
        if argv[0].endswith("osv-scanner"):
            probe = json.loads(Path(argv[argv.index("-L") + 1]).read_text(encoding="utf-8"))
            assert all("probe" in c["purl"].lower() for c in probe["components"])
            if osv_ok:
                cache = Path(env["OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"]) / "osv-scalibr"
                for item in probe["components"]:
                    eco = next(k for k, v in vulndb.PROBE_PURLS.items() if v == item["purl"])
                    (cache / eco).mkdir(parents=True, exist_ok=True)
                    (cache / eco / "all.zip").write_bytes(b"zip")
                return ProcessOutcome(0)
            stderr.write(b"could not load db for npm ecosystem: 404\n")
            return ProcessOutcome(127)
        if argv[1:3] == ["db", "update"]:
            assert "GRYPE_DB_AUTO_UPDATE" not in env
            if grype_ok:
                db = Path(env["GRYPE_DB_CACHE_DIR"]) / "6" / "vulnerability.db"
                db.parent.mkdir(parents=True, exist_ok=True)
                db.write_bytes(b"db")
                return ProcessOutcome(0)
            stderr.write(b"failed to download\n")
            return ProcessOutcome(1)
        if argv[1:3] == ["db", "status"]:
            stdout.write(b'{"built": "2026-10-16T00:00:00Z", "valid": true}')
            return ProcessOutcome(0)
        raise AssertionError(argv)

    return run


from kalkan.sca import vulndb  # noqa: E402


def test_update_db_downloads_the_databases_into_the_kalkan_home(tmp_path):
    calls: list = []
    root = tmp_path / "vulndb"
    summary = vulndb.update(
        root,
        go=False,
        retire=False,
        runner=update_runner(root, calls),
        resolver=lambda name: FakeTool(name),
    )
    assert summary["osv"]["status"] == "ok" and summary["grype"]["status"] == "ok"
    assert vulndb.osv_ecosystems(root) == sorted(vulndb.DEFAULT_ECOSYSTEMS)
    assert vulndb.grype_ready(root)
    osv_argv, osv_env = calls[0]
    assert "--download-offline-databases" in osv_argv and "--no-resolve" in osv_argv
    assert osv_env["OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"] == str(root / "osv")
    assert vulndb.read_status(root)["grype"]["built"] == "2026-10-16T00:00:00Z"


def test_update_db_reports_failures_and_unknown_ecosystems(tmp_path):
    calls: list = []
    root = tmp_path / "vulndb"
    summary = vulndb.update(
        root,
        ecosystems=["npm"],
        go=False,
        retire=False,
        runner=update_runner(root, calls, osv_ok=False, grype_ok=False),
        resolver=lambda name: FakeTool(name),
    )
    assert summary["osv"]["status"] == "failed" and summary["osv"]["missing"] == ["npm"]
    assert "could not load db for npm" in summary["osv"]["message"]
    assert summary["grype"]["status"] == "failed"
    with pytest.raises(ValueError, match="unknown ecosystem"):
        vulndb.update(root, ecosystems=["Debian"])
    missing = vulndb.update(
        root, go=False, retire=False, resolver=lambda name: None, runner=update_runner(root, [])
    )
    assert missing["osv"]["status"] == "skipped" and missing["grype"]["status"] == "skipped"


def test_cli_update_db(monkeypatch, capsys):
    seen = {}

    def fake_update(**kwargs):
        seen.update(kwargs)
        return {
            "root": "/home/.tools/vulndb",
            "osv": {"status": "ok", "message": "", "ecosystems": ["npm"]},
            "grype": {"status": "ok", "message": ""},
            "go": {"status": "ok", "message": "", "source": "official"},
            "retire": {
                "status": "ok",
                "message": "",
                "libraries": 74,
                "vulnerabilities": 767,
                "sha256": "c213444cbf88" + "0" * 52,
            },
        }

    monkeypatch.setattr(vulndb, "update", fake_update)
    assert cli.main(["sca", "update-db", "--ecosystems", "npm, PyPI", "--no-grype", "--json"]) == 0
    assert seen["ecosystems"] == ["npm", "PyPI"] and seen["grype"] is False
    assert (seen["go"], seen["go_source"], seen["retire"]) == (True, "auto", True)
    captured = capsys.readouterr()
    assert json.loads(captured.out)["root"] == "/home/.tools/vulndb"
    assert "retire: ok 74 libraries, 767 vulnerabilities, sha256 c213444cbf88" in captured.err


def test_cli_update_db_go_options(monkeypatch, capsys):
    seen = {}

    def fake_update(**kwargs):
        seen.update(kwargs)
        return {
            "root": "/home/.tools/vulndb",
            "osv": None,
            "grype": None,
            "go": {
                "status": "ok",
                "source": "osv",
                "modified": "2026-10-16T10:42:06Z",
                "entries": 4632,
                "message": "built from the OSV Go database (official archive: HTTP 404)",
            },
        }

    monkeypatch.setattr(vulndb, "update", fake_update)
    argv = ["sca", "update-db", "--no-osv", "--no-grype", "--no-retire", "--go-source", "osv"]
    assert cli.main(argv) == 0
    assert (seen["osv"], seen["grype"], seen["go"], seen["retire"], seen["go_source"]) == (
        False,
        False,
        True,
        False,
        "osv",
    )
    err = capsys.readouterr().err
    assert "go: ok source osv, modified 2026-10-16T10:42:06Z, 4632 entries" in err
    assert cli.main(["sca", "update-db", "--no-go", "--no-osv"]) == 1  # grype: None
    assert seen["go"] is False


def test_missing_from_stderr():
    lines = [
        "x",
        "could not load db for GitHub Actions ecosystem: 404",
        "could not load db for npm",
    ]
    text = chr(10).join(lines) + " ecosystem"
    assert vulndb.missing_from_stderr(text) == ["GitHub Actions", "npm"]
