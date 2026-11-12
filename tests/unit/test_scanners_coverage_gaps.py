# SPDX-License-Identifier: MIT
"""Tests for the SCA pin adapters, the Opengrep coverage details and the ``status_details``
hook of :func:`kalkan.scanners.base.run_adapter`."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from kalkan.scanners import registry
from kalkan.scanners.adapters import opengrep
from kalkan.scanners.adapters.grype import GrypePinsAdapter
from kalkan.scanners.adapters.opengrep import (
    LONG_PATH_REASON,
    OpengrepAdapter,
    notification_paths,
    parse_summary,
    target_relative,
)
from kalkan.scanners.adapters.osv_scanner import OsvScannerPinsAdapter
from kalkan.scanners.base import ProcessOutcome, ScanContext, run_adapter
from kalkan.tools.resolve import ResolvedTool

TOOL = Path("/opt/tool")

OPENGREP_STDERR = """\
[00.17][WARNING]: !!! You're using one or more options starting with '--x-'.
\x1b[1m┌──────────────┐\x1b[0m
│ Scan Summary │
└──────────────┘
Some files were skipped or only partially analyzed.
  Partially scanned: 31 files only partially analyzed due to parsing or internal Opengrep errors
  Scan skipped: 2 files larger than 1.0 MB, 3 files matching .semgrepignore patterns
  For a full list of skipped files, run opengrep with the --verbose flag.

Ran 35 rules on 1464 files: 33 findings.
"""


def make_ctx(tmp_path: Path, *, offline: bool = False) -> ScanContext:
    run = (tmp_path / "run").resolve()
    target = run / "target"
    target.mkdir(parents=True, exist_ok=True)
    return ScanContext(
        run_dir=run, target_dir=target, source_dir=None, tech=frozenset(), offline=offline
    )


def resolver(name, *, allow_path=False):
    return ResolvedTool(name, Path("/opt") / name, "9.9.9", "kalkan")


def sarif_with_notes(target: Path, files: list[str]) -> dict:
    notes = [
        {
            "descriptor": {"id": "Syntax error"},
            "level": "warning",
            "message": {"text": f"Syntax error at line {target / name}:11:\n `}}` was unexpected"},
        }
        for name in files
    ]
    notes.append(
        {
            "descriptor": {"id": "Timeout"},
            "level": "warning",
            "message": {"text": "Timeout"},
            "locations": [
                {"physicalLocation": {"artifactLocation": {"uri": (target / "big.js").as_uri()}}}
            ],
        }
    )
    notes.append({"descriptor": {"id": "Other"}, "message": {"text": "at line /elsewhere/x:1:"}})
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "Opengrep"}},
                "invocations": [{"executionSuccessful": True, "toolExecutionNotifications": notes}],
                "results": [],
            }
        ],
    }


# --- registry and pin adapters -----------------------------------------------------------------


def test_pin_adapters_are_registered_apart_from_the_sca_tools():
    assert [a.name for a in registry.SCA_PIN_TOOLS] == ["osv-scanner-pins", "grype-pins"]
    assert registry.get("grype-pins").output_name == "grype-pins.json"
    assert registry.get("osv-scanner-pins").output_name == "osv-pins.json"
    assert registry.names()[-2:] == ["osv-scanner-pins", "grype-pins"]
    for adapter in registry.SCA_PIN_TOOLS:
        assert adapter.output == "json-file" and adapter.output_dir == "sca"


def test_osv_scanner_pins_command(tmp_path):
    ctx = make_ctx(tmp_path)
    adapter = OsvScannerPinsAdapter()
    applies, reason = adapter.applies(ctx)
    assert applies is False and "manifest-pins.cdx.json" in reason
    pins = ctx.run_dir / "sca" / "manifest-pins.cdx.json"
    pins.parent.mkdir(parents=True)
    pins.write_text("{}", encoding="utf-8")
    assert adapter.applies(ctx) == (True, "")
    out = ctx.run_dir / "sca" / ".work" / "osv-scanner-pins" / "osv-pins.json"
    assert adapter.command(ctx, TOOL, out) == [
        str(TOOL),
        "scan",
        "source",
        "-L",
        str(pins),
        "--no-ignore",
        "--format",
        "json",
        "--output-file",
        str(out),
        "--config",
        str(out.parent / "osv-scanner.toml"),
    ]
    offline = adapter.command(make_ctx(tmp_path, offline=True), TOOL, out)
    assert offline[-1] == "--offline"
    assert adapter.ok_exit_codes == (0, 1)


def test_grype_pins_command(tmp_path):
    ctx = make_ctx(tmp_path)
    adapter = GrypePinsAdapter()
    assert adapter.applies(ctx)[0] is False
    (ctx.run_dir / "sca").mkdir(parents=True)
    (ctx.run_dir / "sca" / "sbom.cdx.json").write_text("{}", encoding="utf-8")
    assert adapter.applies(ctx)[0] is False  # the lockfile SBOM is not the pins SBOM
    pins = ctx.run_dir / "sca" / "manifest-pins.cdx.json"
    pins.write_text("{}", encoding="utf-8")
    assert adapter.applies(ctx) == (True, "")
    out = ctx.run_dir / "sca" / "grype-pins.json"
    assert adapter.command(ctx, TOOL, out) == [
        str(TOOL),
        f"sbom:{pins}",
        "-o",
        "json",
        "--file",
        str(out),
    ]


def test_pin_adapter_runs_through_run_adapter(tmp_path):
    ctx = make_ctx(tmp_path)
    pins = ctx.run_dir / "sca" / "manifest-pins.cdx.json"
    pins.parent.mkdir(parents=True)
    pins.write_text("{}", encoding="utf-8")

    def runner(argv, *, cwd, env, timeout, stdout, stderr):
        Path(argv[argv.index("--file") + 1]).write_text('{"matches": []}', encoding="utf-8")
        return ProcessOutcome(0)

    result = run_adapter(GrypePinsAdapter(), ctx, runner=runner, resolver=resolver)
    assert result.status == "ok", result.message
    assert result.output_path == ctx.run_dir / "sca" / "grype-pins.json"
    status = json.loads((ctx.run_dir / "sca" / "grype-pins.status.json").read_text("utf-8"))
    assert status["engine"] == "grype-pins"


# --- Opengrep coverage details -----------------------------------------------------------------


def test_parse_summary():
    summary = parse_summary(OPENGREP_STDERR)
    assert summary == {
        "files_scanned": 1464,
        "partial": 31,
        "skipped": {
            "files larger than 1.0 MB": 2,
            "files matching .semgrepignore patterns": 3,
        },
    }
    assert parse_summary("") == {"files_scanned": None, "partial": 0, "skipped": {}}


def test_notification_paths(tmp_path):
    target = tmp_path.resolve()
    doc = sarif_with_notes(target, ["data/a.ts", "src/b.ts", "data/a.ts"])
    kinds, paths = notification_paths(doc, target)
    assert kinds == {"Syntax error": 3, "Timeout": 1, "Other": 1}
    assert paths == ["data/a.ts", "src/b.ts", "big.js"]
    assert notification_paths({"runs": "x"}, target) == ({}, [])
    assert notification_paths(None, target) == ({}, [])


def test_target_relative(tmp_path):
    root = tmp_path.resolve()
    assert target_relative(str(root / "a" / "b.ts"), root) == "a/b.ts"
    assert target_relative("a\\b.ts", root) == "a/b.ts"
    assert target_relative("../outside", root) is None
    assert target_relative("/elsewhere/x", root) is None
    assert target_relative((root / "c.py").as_uri(), root) == "c.py"


def test_status_details_records_partial_and_skipped_files(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    (ctx.target_dir / "big.bin").write_bytes(b"x" * 1_000_001)
    (ctx.target_dir / "small.js").write_text("x", encoding="utf-8")
    stderr = tmp_path / "stderr.txt"
    stderr.write_text(OPENGREP_STDERR, encoding="utf-8")
    sarif = tmp_path / "out.sarif"
    sarif.write_text(json.dumps(sarif_with_notes(ctx.target_dir, ["a.ts"])), encoding="utf-8")
    monkeypatch.setattr(opengrep, "find_long_paths", lambda root: ["deep/long/file.ts"])
    details = OpengrepAdapter().status_details(ctx, tmp_path / "none", stderr, [sarif])
    assert details["files_scanned"] == 1464
    assert details["partial_files"] == {
        "count": 31,
        "paths": ["a.ts", "big.js"],
        "truncated": False,
        "kinds": {"Other": 1, "Syntax error": 1, "Timeout": 1},
    }
    assert details["skipped_files"] == {
        "count": 6,
        "reasons": {
            "files larger than 1.0 MB": 2,
            "files matching .semgrepignore patterns": 3,
            LONG_PATH_REASON: 1,
        },
        "paths": ["big.bin", "deep/long/file.ts"],
        "truncated": False,
    }


def test_status_details_caps_the_path_lists(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    sarif = tmp_path / "out.sarif"
    names = [f"f{index:03d}.ts" for index in range(60)]
    sarif.write_text(json.dumps(sarif_with_notes(ctx.target_dir, names)), encoding="utf-8")
    monkeypatch.setattr(opengrep, "find_long_paths", lambda root: [])
    details = OpengrepAdapter().status_details(ctx, tmp_path / "a", tmp_path / "b", [sarif])
    partial = details["partial_files"]
    assert partial["count"] == 61 and len(partial["paths"]) == 50 and partial["truncated"]
    assert details["skipped_files"]["count"] == 0
    assert "files_scanned" not in details


def test_run_adapter_writes_the_details_into_the_status_file(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "r.yaml").write_text("rules: []\n", encoding="utf-8")
    monkeypatch.setattr(opengrep, "find_long_paths", lambda root: [])

    def runner(argv, *, cwd, env, timeout, stdout, stderr):
        stderr.write(OPENGREP_STDERR.encode("utf-8"))
        doc = sarif_with_notes(ctx.target_dir, ["x.ts"])
        Path(argv[argv.index("--output") + 1]).write_text(json.dumps(doc), encoding="utf-8")
        return ProcessOutcome(0)

    result = run_adapter(OpengrepAdapter(rules), ctx, runner=runner, resolver=resolver)
    assert result.status == "ok", result.message
    status = json.loads((ctx.run_dir / "scans" / "opengrep.status.json").read_text("utf-8"))
    assert status["files_scanned"] == 1464
    assert status["partial_files"]["count"] == 31
    assert status["partial_files"]["paths"] == ["big.js", "x.ts"]
    assert status["skipped_files"]["count"] == 5


def test_a_failing_details_hook_never_fails_the_run(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "r.yaml").write_text("rules: []\n", encoding="utf-8")

    def broken(*_args, **_kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(OpengrepAdapter, "status_details", broken)

    def runner(argv, *, cwd, env, timeout, stdout, stderr):
        doc = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "x"}}, "results": []}]}
        Path(argv[argv.index("--output") + 1]).write_text(json.dumps(doc), encoding="utf-8")
        return ProcessOutcome(0)

    result = run_adapter(OpengrepAdapter(rules), ctx, runner=runner, resolver=resolver)
    assert result.status == "ok"
    status = json.loads((ctx.run_dir / "scans" / "opengrep.status.json").read_text("utf-8"))
    assert status["details_error"] == "RuntimeError: boom"


def _create(path: Path) -> None:
    text = str(path)
    if os.name == "nt":  # works without LongPathsEnabled
        text = "\\\\?\\" + text
    with open(text, "wb"):
        pass


@pytest.mark.parametrize("windows", [True, False])
def test_long_paths_use_the_measured_limit(tmp_path, windows):
    from kalkan.util.winpath import find_long_paths

    root = tmp_path.resolve()
    sub = root / ("d" * 40)
    sub.mkdir()
    prefix = len(str(sub)) + 1  # the folder and the separator before the file name
    under, at = "a" * (259 - prefix), "b" * (260 - prefix)
    _create(sub / under)
    _create(sub / at)
    found = find_long_paths(root, windows=windows)
    assert found == ([f"{sub.name}/{at}"] if windows else [])
