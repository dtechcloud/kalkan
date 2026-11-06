# SPDX-License-Identifier: MIT
"""zizmor, actionlint, poutine and OpenSSF Scorecard on the vulnapp fixture, in local mode
(ENGINE-SPEC 13; docs/SECURITY.md, promise 3; ADR-0003).

The tests run the installed tools (``kalkan tools install zizmor actionlint poutine scorecard``)
and skip when a tool is missing. Each adapter runs with every proxy variable pointing at the trap
of ``conftest.py``: zero connections. A control step per tool shows that the trap sees the
network feature that kalkan turns off: zizmor with a GitHub token and without ``--offline``,
poutine without ``--disable-version-check``, and the Scorecard check ``Pinned-Dependencies``
(registry lookups). actionlint has no network feature, so it has no control step.

poutine 1.1.6 and Scorecard 5.5.0 cannot read the GitHub workflows on Windows (they match paths
with ``/``); the tests check the recorded ``platform_gap`` there and the workflow results on
Linux and macOS.

Run with ``pytest -m tools tests/integration/test_cicd_tools.py``.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from kalkan.findings.validate import validate_candidate
from kalkan.run import tech
from kalkan.scanners import registry
from kalkan.scanners.base import load_scan_context, minimal_env, run_adapter
from kalkan.scanners.candidates import load_candidates
from kalkan.schema.loader import shared_schema
from kalkan.schema.validator import validate
from kalkan.tools.manifest import load_manifest
from kalkan.tools.resolve import resolve

pytestmark = pytest.mark.tools

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "vulnapp"
EXPECTED = FIXTURE / "EXPECTED.json"
#: Fixture root files that describe the answers; they are not part of the target.
ANSWER_FILES = frozenset({"README.md", "EXPECTED.json", "INJECTION-NOTE.md"})
#: Build output that an IDE can leave in the C# folders; not fixture data.
BUILD_FOLDERS = frozenset({"obj", "bin"})
LINE_SLACK = 2
WINDOWS = os.name == "nt"
WORKFLOWS = [
    ".github/workflows/issue-labels.yml",
    ".github/workflows/issue-triage.yml",
    ".github/workflows/pr-checks.yml",
    ".github/workflows/pr-preview.yml",
]


def _ignore(folder: str, names: list[str]) -> set[str]:
    skipped = {name for name in names if name in BUILD_FOLDERS}
    if Path(folder).resolve() == FIXTURE:
        skipped |= {name for name in names if name in ANSWER_FILES}
    return skipped


def _require(engine: str):
    tool = resolve(registry.get(engine).tool)
    if tool is None:
        pytest.skip(f"{engine} is not installed (run: kalkan tools install {engine})")
    return tool


def _make_run(root: Path) -> Path:
    run = root / "run"
    shutil.copytree(FIXTURE, run / "target", ignore=_ignore)
    manifest = {"copy": "target", "source_dir": None, "tech": tech.detect(run / "target")}
    (run / "target-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return run


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def _status(run: Path, engine: str) -> dict:
    return json.loads((run / "scans" / f"{engine}.status.json").read_text(encoding="utf-8"))


def _candidates(run: Path, engine: str) -> list[dict]:
    """Return the candidates of one engine; each one is schema-clean (ENGINE-SPEC 4)."""
    found = [c for c in load_candidates(run)["candidates"] if c["engine"] == engine]
    schema = shared_schema("candidate")
    for candidate in found:
        assert validate(candidate, schema) == [], candidate["id"]
        assert validate_candidate(candidate) == [], candidate["id"]
    return found


def _items() -> dict[str, dict]:
    return {item["id"]: item for item in json.loads(EXPECTED.read_text(encoding="utf-8"))}


def _matches(candidate: dict, item: dict, engine: str) -> bool:
    if candidate["file"] != item["file"]:
        return False
    rules = item.get("rules", {}).get(engine)
    if rules and candidate["rule_id"] not in rules:
        return False
    start = candidate["start_line"]
    end = candidate["end_line"] or start
    return start is not None and start - LINE_SLACK <= item["line"] <= end + LINE_SLACK


def _check_expected_items(candidates: list[dict], engine: str) -> None:
    """Every item that expects the engine is found; no twin gets a result of the same rule."""
    items = _items()
    vulnerable = [i for i in items.values() if engine in i.get("expected_engines", [])]
    assert vulnerable, engine
    missing = [i["id"] for i in vulnerable if not any(_matches(c, i, engine) for c in candidates)]
    assert missing == []
    for item in vulnerable:
        twin = items[item["twin"]]
        hits = [c for c in candidates if _matches(c, {**twin, "rules": item["rules"]}, engine)]
        assert hits == [], twin["id"]


def _run_with_trap(engine: str, run: Path, monkeypatch, trap_proxy, **context):
    proxy = trap_proxy()
    for name, value in proxy.env().items():
        monkeypatch.setenv(name, value)
    result = run_adapter(registry.get(engine), load_scan_context(run, offline=True, **context))
    assert proxy.connections == [], proxy.connections
    return result


def _control(argv: list[str], cwd: Path, trap_proxy, extra: dict[str, str] | None = None) -> list:
    """Run a tool with its network feature on, against a second trap; return the connections."""
    control = trap_proxy()
    env = minimal_env({**control.env(), **(extra or {})})
    subprocess.run(
        argv,
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=300,
        check=False,
    )
    control.close()
    return control.connections


# --------------------------------------------------------------------------------------------
# zizmor


def test_zizmor_local_mode_finds_the_workflow_items(tmp_path, monkeypatch, trap_proxy):
    tool = _require("zizmor")
    run = _make_run(tmp_path)
    result = _run_with_trap("zizmor", run, monkeypatch, trap_proxy)
    assert result.status == "ok", result.message
    assert result.tool_version == load_manifest().get("zizmor").version
    candidates = _candidates(run, "zizmor")
    _check_expected_items(candidates, "zizmor")
    assert {c["rule_id"] for c in candidates} == {
        "zizmor/excessive-permissions",
        "zizmor/template-injection",
        "zizmor/dangerous-triggers",
        "zizmor/unpinned-uses",
    }
    status = _status(run, "zizmor")
    assert status["command"][1:4] == ["--offline", "--no-config", "--no-ignores"]
    # Control: with a GitHub token and without --offline, zizmor calls the GitHub API.
    argv = [*tool.argv, "--gh-token", "ghp_" + "0" * 36, "--no-config", "--format=sarif"]
    connections = _control([*argv, str(run / "target")], run / "scans", trap_proxy)
    assert connections, "the trap proxy did not see the online zizmor run"


def test_zizmor_ignores_the_target_suppressions_by_default(tmp_path, monkeypatch, trap_proxy):
    _require("zizmor")
    run = _make_run(tmp_path)
    workflow = run / "target" / ".github" / "workflows" / "issue-triage.yml"
    text = workflow.read_text(encoding="utf-8")
    # An ignore comment must be a YAML comment, so it goes on the "run: |" line.
    workflow.write_text(
        text.replace("run: |", "run: | # zizmor: ignore[template-injection]", 1), encoding="utf-8"
    )
    _write(run / "target" / "zizmor.yml", "rules:\n  excessive-permissions:\n    disable: true\n")
    default = _run_with_trap("zizmor", run, monkeypatch, trap_proxy)
    assert default.status == "ok", default.message
    rules = {c["rule_id"] for c in _candidates(run, "zizmor")}
    assert {"zizmor/template-injection", "zizmor/excessive-permissions"} <= rules
    honor = _run_with_trap("zizmor", run, monkeypatch, trap_proxy, honor_suppressions=True)
    assert honor.status == "ok", honor.message
    rules = {c["rule_id"] for c in _candidates(run, "zizmor")}
    assert not {"zizmor/template-injection", "zizmor/excessive-permissions"} & rules
    assert _status(run, "zizmor")["command"][1:4] == [
        "--offline",
        "--config",
        str(run.resolve() / "target" / "zizmor.yml"),
    ]


# --------------------------------------------------------------------------------------------
# actionlint


def test_actionlint_finds_the_untrusted_input(tmp_path, monkeypatch, trap_proxy):
    _require("actionlint")
    run = _make_run(tmp_path)
    result = _run_with_trap("actionlint", run, monkeypatch, trap_proxy)
    assert result.status == "ok", result.message
    assert result.exit_code == 1  # actionlint found errors
    candidates = _candidates(run, "actionlint")
    _check_expected_items(candidates, "actionlint")
    assert [(c["rule_id"], c["class"]) for c in candidates] == [
        ("expression/untrusted-input", "code-injection")
    ]
    status = _status(run, "actionlint")
    assert "-pyflakes=" in status["command"]
    # No shellcheck of the system: none, or the pinned kalkan copy when it is installed.
    [shellcheck] = [arg for arg in status["command"] if arg.startswith("-shellcheck=")]
    value = shellcheck.removeprefix("-shellcheck=")
    assert value == "" or "/.tools/shellcheck/" in value.replace("\\", "/"), shellcheck
    assert not (run / "scans" / ".work").exists()


def test_actionlint_ignores_the_target_configuration_by_default(tmp_path, monkeypatch, trap_proxy):
    _require("actionlint")
    run = _make_run(tmp_path)
    config = "paths:\n  .github/workflows/**/*.yml:\n    ignore:\n      - 'potentially untrusted'\n"
    _write(run / "target" / ".github" / "actionlint.yaml", config)
    default = _run_with_trap("actionlint", run, monkeypatch, trap_proxy)
    assert default.status == "ok", default.message
    assert len(_candidates(run, "actionlint")) == 1
    honor = _run_with_trap("actionlint", run, monkeypatch, trap_proxy, honor_suppressions=True)
    assert honor.status == "ok", honor.message
    assert _candidates(run, "actionlint") == []


# --------------------------------------------------------------------------------------------
# poutine


def test_poutine_local_mode_makes_no_connection(tmp_path, monkeypatch, trap_proxy):
    tool = _require("poutine")
    run = _make_run(tmp_path)
    result = _run_with_trap("poutine", run, monkeypatch, trap_proxy)
    assert result.status == "ok", result.message
    candidates = _candidates(run, "poutine")
    _check_expected_items(candidates, "poutine")
    status = _status(run, "poutine")
    assert "--disable-version-check" in status["command"]
    found = {(c["rule_id"], c["file"], c["start_line"]) for c in candidates}
    if WINDOWS:
        assert status["platform_gap"]["files"] == WORKFLOWS
        assert found == {("injection", "azure-pipelines.yml", 14)}
    else:
        # The Linux and macOS builds read the workflows (measured with a development build
        # that uses '/' paths on 2026-10-25).
        assert "platform_gap" not in status
        assert ("injection", ".github/workflows/issue-triage.yml", 18) in found
        assert ("untrusted_checkout_exec", ".github/workflows/pr-preview.yml", 21) in found
    # Control: without --disable-version-check poutine calls version-check.cicd.fun.
    state = tmp_path / "poutine-state"
    connections = _control(
        [*tool.argv, "version"], run / "scans", trap_proxy, {"POUTINE_CONFIG_DIR": str(state)}
    )
    assert connections, "the trap proxy did not see the poutine version check"


# --------------------------------------------------------------------------------------------
# OpenSSF Scorecard


def test_scorecard_local_checks_make_no_connection(tmp_path, monkeypatch, trap_proxy):
    tool = _require("scorecard")
    run = _make_run(tmp_path)
    result = _run_with_trap("scorecard", run, monkeypatch, trap_proxy)
    assert result.status == "ok", result.message
    assert result.tool_version == load_manifest().get("scorecard").version
    status = _status(run, "scorecard")
    scores = {item["name"]: item["score"] for item in status["scores"]}
    assert set(scores) == {
        "Binary-Artifacts",
        "Dangerous-Workflow",
        "Dependency-Update-Tool",
        "License",
        "Security-Policy",
        "Token-Permissions",
    }
    assert (scores["Security-Policy"], scores["License"]) == (0, 0)
    # The header-only ELF files of the committed-binary item and its twin (ADR-0005, K.12):
    # Scorecard has no folder exclusions, so it reports both (score below 10).
    assert scores["Binary-Artifacts"] < 10
    assert "Pinned-Dependencies" in status["checks_not_run"]
    candidates = _candidates(run, "scorecard")
    roots = {c["rule_id"] for c in candidates if c["file"] == ""}
    assert roots == {"Dependency-Update-Tool", "License", "Security-Policy"}
    binaries = {c["file"] for c in candidates if c["rule_id"] == "Binary-Artifacts"}
    assert binaries <= {"native/bin/labelprint", "native/testdata/labelprint.elf"}
    located = {
        (c["rule_id"], c["file"], c["start_line"])
        for c in candidates
        if c["file"] and c["rule_id"] != "Binary-Artifacts"
    }
    if WINDOWS:
        assert (scores["Dangerous-Workflow"], scores["Token-Permissions"]) == (-1, -1)
        assert status["platform_gap"]["files"] == WORKFLOWS
        assert located == set()
    else:
        assert "platform_gap" not in status
        assert located == {
            ("Dangerous-Workflow", ".github/workflows/issue-triage.yml", 18),
            ("Dangerous-Workflow", ".github/workflows/pr-preview.yml", 16),
            ("Token-Permissions", ".github/workflows/issue-triage.yml", 7),
        }
    # Control: Pinned-Dependencies asks the container registry for image digests.
    argv = [*tool.argv, "--local", str(run / "target"), "--checks", "Pinned-Dependencies"]
    connections = _control([*argv, "--format", "json"], run / "scans", trap_proxy)
    assert connections, "the trap proxy did not see the registry lookups of Pinned-Dependencies"
