# SPDX-License-Identifier: MIT
"""Run the real scanners on the vulnapp fixture (ENGINE-SPEC 13).

The fixture is copied into a temporary run folder (``target/`` plus ``target-manifest.json``,
built by hand as ``run init`` would). ``README.md``, ``EXPECTED.json`` and ``INJECTION-NOTE.md``
at the fixture root hold the answers, not target code, so they are left out of the copy.
Every scanner of :data:`kalkan.scanners.registry.SCANNERS` runs, plus the two SBOM tools that
need no network (``syft``, ``trivy-sbom``). The context is offline: Trivy uses its cached or
embedded checks, Checkov downloads nothing, so the test needs no network. OSV-Scanner and
Grype need vulnerability databases and are left to the SCA tests.

Run with ``pytest -m tools -s tests/integration/test_scan_vulnapp.py`` to see the per-engine
table.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from kalkan.findings.validate import validate_candidate
from kalkan.run import tech
from kalkan.scanners import registry
from kalkan.scanners.base import ScanResult, load_scan_context, run_adapter
from kalkan.scanners.candidates import load_candidates
from kalkan.schema.loader import shared_schema
from kalkan.schema.validator import validate
from kalkan.tools.golang import resolve_go
from kalkan.tools.resolve import resolve

pytestmark = pytest.mark.tools

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "vulnapp"
EXPECTED = FIXTURE / "EXPECTED.json"
#: Engines that must end ``ok`` when their tool is installed.
REQUIRED_OK = (
    "trivy",
    "checkov",
    "hadolint",
    "gitleaks",
    "kingfisher",
    "opengrep",
    "opengrep-packs",
    "bandit",
    "shellcheck",
    "flawfinder",
    "gixy",
    "matcher",
)
LOCAL_SCA = ("syft", "trivy-sbom")
#: Fixture root files that describe the answers; they are not part of the target.
ANSWER_FILES = frozenset({"README.md", "EXPECTED.json", "INJECTION-NOTE.md"})
#: A candidate matches an expected issue when the expected line lies in its line range, give or
#: take this many lines (tools report a statement, a block or a resource).
LINE_SLACK = 3


def _tool_of(engine: str) -> str | None:
    return registry.get(engine).tool


def _available(engine: str) -> bool:
    tool = _tool_of(engine)
    return tool is None or resolve(tool) is not None


def _skip_answer_files(folder: str, names: list[str]) -> set[str]:
    if Path(folder).resolve() == FIXTURE:
        return {name for name in names if name in ANSWER_FILES}
    return set()


@pytest.fixture(scope="module")
def scan(tmp_path_factory) -> dict:
    if not any(_available(engine) for engine in REQUIRED_OK if _tool_of(engine)):
        pytest.skip("no scanner tool is installed (run: kalkan tools install --all)")
    run = tmp_path_factory.mktemp("scan-vulnapp") / "run"
    shutil.copytree(FIXTURE, run / "target", ignore=_skip_answer_files)
    manifest = {
        "copy": "target",
        "source_dir": FIXTURE.as_posix(),  # no .git there: gitleaks-history is skipped
        "tech": tech.detect(run / "target"),
    }
    (run / "target-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    ctx = load_scan_context(run, offline=True)
    adapters = [*registry.SCANNERS, *(registry.get(name) for name in LOCAL_SCA)]
    results: dict[str, ScanResult] = {}
    for adapter in adapters:
        results[adapter.name] = run_adapter(adapter, ctx)
    print("\nengine             status    seconds  candidates  message")
    for result in results.values():
        count = "-" if result.candidates is None else str(result.candidates)
        print(
            f"{result.engine:18} {result.status:8} {result.duration_seconds:8.1f}  "
            f"{count:>10}  {result.message}"
        )
    return {"ctx": ctx, "results": results}


@pytest.mark.parametrize("engine", REQUIRED_OK)
def test_required_engine_ran_ok(scan, engine):
    if not _available(engine):
        pytest.skip(f"{_tool_of(engine)} is not installed")
    result = scan["results"][engine]
    assert result.status == "ok", f"{engine}: {result.status}: {result.message}"
    assert result.candidates and result.candidates > 0, f"{engine} found nothing"


def test_other_engines_did_not_fail(scan):
    results = scan["results"]
    assert results["gitleaks-history"].status == "skipped"
    assert results["kingfisher-history"].status == "skipped"
    if _available("gosec") and resolve_go() is not None:
        # kalkan installs the Go toolchain itself: gosec must run, not skip.
        assert results["gosec"].status == "ok", results["gosec"].message
    else:
        assert results["gosec"].status == "skipped", results["gosec"].message
    for engine in LOCAL_SCA:
        if _available(engine):
            assert results[engine].status == "ok", results[engine].message


def test_status_files_match_results(scan):
    ctx = scan["ctx"]
    for engine, result in scan["results"].items():
        adapter = registry.get(engine)
        status = json.loads(
            (ctx.run_dir / adapter.output_dir / f"{engine}.status.json").read_text(encoding="utf-8")
        )
        assert status["status"] == result.status
        assert status["engine"] == engine


def test_candidates_validate_against_the_schema(scan):
    doc = load_candidates(scan["ctx"].run_dir)
    schema = shared_schema("candidate")
    assert doc["candidates"], "no candidates at all"
    errors = []
    for candidate in doc["candidates"]:
        errors += [f"{candidate['id']}: {e}" for e in validate(candidate, schema)]
        errors += [f"{candidate['id']}: {e}" for e in validate_candidate(candidate)]
    assert errors == []
    ids = [candidate["id"] for candidate in doc["candidates"]]
    assert len(ids) == len(set(ids))
    for engine, result in scan["results"].items():
        if result.candidates is not None:
            assert doc["sources"][engine]["count"] == result.candidates
    for candidate in doc["candidates"]:
        assert not candidate["file"].startswith(("/", "../")) and ":" not in candidate["file"]


def _matches(candidate: dict, entry: dict, engine: str) -> bool:
    if candidate["engine"] != engine or candidate["file"] != entry["file"]:
        return False
    rules = entry.get("rules", {}).get(engine)
    if rules and candidate["rule_id"] not in rules:
        return False
    line = entry.get("line")
    start = candidate["start_line"]
    if line is None or start is None:
        return True
    end = candidate["end_line"] or start
    return start - LINE_SLACK <= line <= end + LINE_SLACK


def test_expected_issues_are_found(scan):
    candidates = load_candidates(scan["ctx"].run_dir)["candidates"]
    results = scan["results"]
    if not EXPECTED.is_file():
        _fallback_checks(candidates, results)
        return
    entries = json.loads(EXPECTED.read_text(encoding="utf-8"))
    checked = 0
    missing = []
    for entry in entries:
        if entry.get("kind") != "vulnerable":
            continue
        for engine in entry.get("expected_engines", []):
            result = results.get(engine)
            if result is None or result.status != "ok":
                continue  # SCA engines, the hunter, or a tool that is not installed
            checked += 1
            if not any(_matches(c, entry, engine) for c in candidates):
                missing.append(f"{engine}: {entry['id']} ({entry['file']}:{entry.get('line')})")
    assert checked > 0
    assert missing == [], f"{len(missing)} of {checked} expected results missing"


def _fallback_checks(candidates: list[dict], results: dict) -> None:
    def found(engine: str, file: str) -> bool:
        return any(c["engine"] == engine and c["file"] == file for c in candidates)

    if results["bandit"].status == "ok":
        assert found("bandit", "python/shop/accounts.py")
    if results["opengrep"].status == "ok":
        assert found("opengrep", "python/shop/app.py")
    assert found("matcher", "python/shop/app.py")


def test_sbom_is_cyclonedx(scan):
    ctx = scan["ctx"]
    for engine in LOCAL_SCA:
        result = scan["results"][engine]
        if result.status != "ok":
            continue
        assert result.output_path == ctx.run_dir / "sca" / "sbom.cdx.json"
    sbom = ctx.run_dir / "sca" / "sbom.cdx.json"
    if sbom.is_file():
        doc = json.loads(sbom.read_text(encoding="utf-8"))
        assert doc["bomFormat"] == "CycloneDX"
        assert doc.get("components")


# --------------------------------------------------------------------------------------------
# ADR-0003: a target that tries to hide its results

SUPPRESSION_ENGINES = ("gitleaks", "bandit", "hadolint", "opengrep", "checkov")


def _hostile_target(folder: Path, marker: Path) -> None:
    evil = f"open({str(marker)!r}, 'w').write('target code ran')\n"
    files = {
        "app.py": (
            "import hashlib\n\n\ndef h(x):\n    return hashlib.md5(x)  # nosec\n\n\n"
            "def g(x):\n    return hashlib.md5(x)  # nosemgrep\n"
        ),
        ".bandit": "[bandit]\nskips = B324\n",
        "Dockerfile": "# hadolint ignore=DL3007\nFROM ubuntu:latest\nUSER root\n",
        ".checkov.yaml": "skip-check:\n  - CKV_DOCKER_7\nexternal-checks-dir:\n  - evil\n",
        "evil/__init__.py": evil,
        "evil/check.py": evil,
        "creds.ini": 'aws_access_key_id = "AKIAIOSFODNN7EXAMPLA"\n',
        "more.ini": 'k = "AKIAIOSFODNN7EXAMPLB"  # gitleaks:allow\n',
        ".gitleaks.toml": '[allowlist]\npaths = ["creds.ini"]\n',
    }
    for name, text in files.items():
        path = folder / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


@pytest.fixture(scope="module")
def suppression_scans(tmp_path_factory) -> dict:
    if not any(_available(engine) for engine in SUPPRESSION_ENGINES):
        pytest.skip("no scanner tool is installed")
    scans = {}
    for honor in (False, True):
        root = tmp_path_factory.mktemp("honor" if honor else "ignore")
        marker = root / "MARKER"
        run = root / "run"
        _hostile_target(run / "target", marker)
        manifest = {"copy": "target", "source_dir": None, "tech": tech.detect(run / "target")}
        (run / "target-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        ctx = load_scan_context(run, offline=True, honor_suppressions=honor)
        results = {
            name: run_adapter(registry.get(name), ctx)
            for name in SUPPRESSION_ENGINES
            if _available(name)
        }
        candidates = load_candidates(run)["candidates"]
        scans[honor] = {"ctx": ctx, "results": results, "candidates": candidates, "marker": marker}
    return scans


def _found(scan: dict, engine: str, rule: str, file: str, line: int | None = None) -> list[dict]:
    return [
        c
        for c in scan["candidates"]
        if c["engine"] == engine
        and c["rule_id"].endswith(rule)
        and c["file"] == file
        and (line is None or c["start_line"] == line)
    ]


def _require(scan: dict, engine: str) -> None:
    result = scan["results"].get(engine)
    if result is None:
        pytest.skip(f"{engine} is not installed")
    assert result.status == "ok", f"{engine}: {result.message}"


def test_default_mode_ignores_target_suppressions(suppression_scans):
    scan = suppression_scans[False]
    for engine in scan["results"]:
        _require(scan, engine)
    results = scan["results"]
    if "bandit" in results:
        assert len(_found(scan, "bandit", "B324", "app.py")) == 2
    if "opengrep" in results:
        [nosem] = _found(scan, "opengrep", "weak-hash-algorithm", "app.py", 9)
        assert "suppressed-in-source" in nosem["tags"]
    if "hadolint" in results:
        assert _found(scan, "hadolint", "DL3007", "Dockerfile")
    if "checkov" in results:
        assert _found(scan, "checkov", "CKV_DOCKER_7", "Dockerfile")
    if "gitleaks" in results:
        assert _found(scan, "gitleaks", "aws-access-token", "creds.ini")
        assert _found(scan, "gitleaks", "aws-access-token", "more.ini")
    assert not scan["marker"].exists(), "Checkov ran Python code from the target"
    status = json.loads(
        (scan["ctx"].run_dir / "scans" / "bandit.status.json").read_text(encoding="utf-8")
    )
    assert status["suppressions"]["mode"] == "ignore"


def test_honor_mode_restores_tool_suppressions(suppression_scans):
    scan = suppression_scans[True]
    for engine in scan["results"]:
        _require(scan, engine)
    results = scan["results"]
    if "bandit" in results:
        assert _found(scan, "bandit", "B324", "app.py") == []
    if "opengrep" in results:
        assert _found(scan, "opengrep", "weak-hash-algorithm", "app.py", 9) == []
        assert _found(scan, "opengrep", "weak-hash-algorithm", "app.py", 5)
    if "hadolint" in results:
        assert _found(scan, "hadolint", "DL3007", "Dockerfile") == []
    if "checkov" in results:
        # The target .checkov.yaml is never loaded: it can make Checkov run target code.
        assert _found(scan, "checkov", "CKV_DOCKER_7", "Dockerfile")
    if "gitleaks" in results:
        assert _found(scan, "gitleaks", "aws-access-token", "creds.ini") == []
        assert _found(scan, "gitleaks", "aws-access-token", "more.ini") == []
    assert not scan["marker"].exists(), "Checkov ran Python code from the target"
