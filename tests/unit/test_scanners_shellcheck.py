# SPDX-License-Identifier: MIT
"""Tests for the ShellCheck adapter (kalkan.scanners.adapters.shellcheck): script discovery,
the command line, the curated codes and their context filter, and the SARIF conversion of a
recorded ShellCheck 0.11.0 report."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kalkan.sarif.ingest import ingest_document
from kalkan.scanners.adapters import _sources
from kalkan.scanners.adapters.shellcheck import (
    RULES,
    SPLITTING,
    ShellcheckAdapter,
    expansion_context,
    included_codes,
    is_shell_script,
    json_to_sarif,
    shell_scripts,
    splitting_rule,
)
from kalkan.scanners.base import ProcessOutcome, ScanContext, run_adapter
from kalkan.tools.resolve import ResolvedTool

TOOL = Path("/opt/shellcheck")
OUTPUTS = Path(__file__).resolve().parents[1] / "fixtures" / "scanner-outputs"
FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "vulnapp"


def make_ctx(tmp_path: Path, *, honor: bool = False) -> ScanContext:
    run = (tmp_path / "run").resolve()
    target = run / "target"
    target.mkdir(parents=True, exist_ok=True)
    return ScanContext(
        run_dir=run, target_dir=target, source_dir=None, tech=frozenset(), honor_suppressions=honor
    )


def write(path: Path, data: str | bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, bytes):
        path.write_bytes(data)
    else:
        path.write_text(data, encoding="utf-8", newline="\n")
    return path


# --------------------------------------------------------------------------------------------
# discovery


@pytest.mark.parametrize(
    ("name", "head", "expected"),
    [
        ("a.sh", b"echo hi\n", True),
        ("A.BASH", b"", True),
        ("b.ksh", b"", True),
        ("deploy", b"#!/bin/sh\n", True),
        ("deploy", b"#!/usr/bin/env bash\n", True),
        ("deploy", b"#!/usr/bin/env -S bash -e\n", True),
        ("deploy", b"#! /bin/dash\r\n", True),
        ("deploy.cgi", b"#!/bin/ksh -p\n", True),
        ("deploy", b"#!/bin/zsh\n", False),
        ("deploy", b"#!/usr/bin/env python3\n", False),
        ("deploy", b"echo no shebang\n", False),
        ("gradlew", b"#!/bin/sh\n", False),
        ("mvnw", b"#!/bin/sh\n", False),
    ],
)
def test_is_shell_script(tmp_path, name, head, expected):
    write(tmp_path / name, head)
    assert is_shell_script(tmp_path, name) is expected


def test_vendored_and_skipped_folders_are_left_out(tmp_path):
    for rel in ("ops/run.sh", "vendor/x/run.sh", "third_party/run.sh", "node_modules/a/run.sh"):
        write(tmp_path / rel, "#!/bin/sh\n")
    assert shell_scripts(tmp_path) == ["ops/run.sh"]
    assert _sources.is_vendored("Vendor/run.sh") and not _sources.is_vendored("vendor.sh")


# --------------------------------------------------------------------------------------------
# context of an unquoted expansion


@pytest.mark.parametrize(
    ("line", "column", "expected"),
    [
        ("  rm -rf $DIR/", 10, ("rm", False)),
        ("eval $1", 6, ("eval", False)),
        ("sudo $1", 6, (None, True)),
        ("sudo -u root $1", 14, (None, True)),
        ("X=1 env -i /bin/rm $f", 20, ("rm", False)),
        ("if [ -z $x ]; then", 9, ("[", False)),
        ("cd /tmp && rm $f", 15, ("rm", False)),
        ("out=$(curl $u)", 12, ("curl", False)),
        ("for f in $(ls); do ssh host $f; done", 29, ("ssh", False)),
        ("echo $x | sh", 6, ("echo", False)),
    ],
)
def test_expansion_context(line, column, expected):
    assert expansion_context(line, column) == expected


@pytest.mark.parametrize(
    ("line", "column", "expected"),
    [
        ("eval $1", 6, ("code-injection", ("CWE-95",), "medium", "eval")),
        ("source $f", 8, ("code-injection", ("CWE-94",), "medium", "source")),
        ("bash -c $1", 9, ("os-command-injection", ("CWE-78",), "medium", "bash")),
        ("ssh web $cmd", 9, ("os-command-injection", ("CWE-78",), "medium", "ssh")),
        ("python3 -c $c", 12, ("code-injection", ("CWE-94",), "medium", "python3")),
        ("sudo $1", 6, ("os-command-injection", ("CWE-78",), "medium", "command word")),
        ("rm -rf $DIR/", 8, ("os-command-injection", ("CWE-88",), "low", "rm")),
        ("chmod 777 $f", 11, ("os-command-injection", ("CWE-88",), "low", "chmod")),
        ("echo $x", 6, None),
        ("[ -n $x ]", 6, None),
    ],
)
def test_splitting_rule(line, column, expected):
    assert splitting_rule(line, column) == expected


def test_curated_codes_have_classes_and_cwes():
    assert set(included_codes().split(",")) == {f"SC{c}" for c in (*RULES, *SPLITTING)}
    for vuln_class, cwes, severity, title in RULES.values():
        assert vuln_class in ("os-command-injection", "code-injection", "path-traversal")
        assert cwes and all(cwe.startswith("CWE-") for cwe in cwes)
        assert severity in ("medium", "low") and title
    assert 2148 not in RULES and 2164 not in RULES  # style and robustness codes are dropped


# --------------------------------------------------------------------------------------------
# command line


def test_command_line_and_batches(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx.target_dir / "a.sh", "#!/bin/sh\n")
    write(ctx.target_dir / ".shellcheckrc", "disable=SC2115\n")
    adapter = ShellcheckAdapter()
    assert adapter.applies(ctx) == (True, "")
    out = ctx.run_dir / "scans" / ".work" / "shellcheck" / "shellcheck.sarif"
    [item] = adapter.invocations(ctx, TOOL, out)
    assert list(item.argv) == [
        str(TOOL),
        "--format=json1",
        "--norc",
        f"--include={included_codes()}",
        str(ctx.target_dir / "a.sh"),
    ]
    assert item.cwd == ctx.run_dir / "scans" and item.output == out
    assert adapter.ok_exit_codes == (0, 1)
    for index in range(150):
        write(ctx.target_dir / "many" / f"s{index:03d}.sh", "#!/bin/sh\n")
    items = adapter.invocations(ctx, TOOL, out)
    assert [len(i.argv) - 4 for i in items] == [100, 51]
    assert items[0].output != items[1].output


def test_honor_mode_reads_only_the_rc_file_of_the_target_root(tmp_path):
    ctx = make_ctx(tmp_path, honor=True)
    write(ctx.target_dir / "a.sh", "#!/bin/sh\n")
    adapter = ShellcheckAdapter()
    argv = adapter.arguments(ctx, Path("out"))
    assert "--norc" in argv  # no rc file in the target root: none above it either
    rc = write(ctx.target_dir / ".shellcheckrc", "disable=SC2115\n")
    argv = adapter.arguments(ctx, Path("out"))
    assert f"--rcfile={rc}" in argv and "--norc" not in argv
    ignored, honored = adapter.suppression_sources(ctx)
    assert ignored == [] and any(".shellcheckrc" in item for item in honored)


def test_no_scripts_skips(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx.target_dir / "README.md", "# x\n")
    assert ShellcheckAdapter().applies(ctx) == (False, "no shell script found in the target")


def test_inline_directives_are_recorded_as_honored(tmp_path):
    ignored, honored = ShellcheckAdapter().suppression_sources(make_ctx(tmp_path))
    assert any("--norc" in item for item in ignored)
    assert any("SHELLCHECK_OPTS" in item for item in ignored)
    assert honored and "no option to turn them off" in honored[0]


# --------------------------------------------------------------------------------------------
# conversion of the recorded report (vulnapp infra/scripts/release.sh)


def copy_release_script(ctx: ScanContext) -> None:
    rel = "infra/scripts/release.sh"
    write(ctx.target_dir / rel, (FIXTURE / rel).read_text(encoding="utf-8"))


def recorded(ctx: ScanContext) -> dict:
    text = (OUTPUTS / "shellcheck.json1.json").read_text(encoding="utf-8")
    return json.loads(text.replace("@TARGET@", ctx.target_dir.as_posix()))


def test_recorded_report_becomes_classified_sarif(tmp_path):
    ctx = make_ctx(tmp_path)
    copy_release_script(ctx)
    doc, dropped = json_to_sarif(recorded(ctx), target=ctx.target_dir)
    assert dropped == 0
    results = doc["runs"][0]["results"]
    assert [(r["ruleId"], r["level"]) for r in results] == [
        ("SC2115", "warning"),
        ("SC2086", "note"),
        ("SC2029", "warning"),
    ]
    place = results[1]["locations"][0]["physicalLocation"]
    assert place["artifactLocation"]["uri"] == "infra/scripts/release.sh"
    assert place["region"]["snippet"]["text"] == "  rm -rf $STAGE_DIR/"
    assert results[1]["properties"]["command"] == "rm"
    candidates = ingest_document(doc, "shellcheck", ctx.target_dir, "scans/s.sarif").candidates
    assert [(c["rule_id"], c["class"], c["cwe"], c["start_line"]) for c in candidates] == [
        ("SC2115", "path-traversal", ["CWE-73"], 19),
        ("SC2086", "os-command-injection", ["CWE-88"], 19),
        ("SC2029", "os-command-injection", ["CWE-78"], 27),
    ]
    assert [c["severity"] for c in candidates] == ["medium", "low", "medium"]


def test_expansions_outside_a_sensitive_command_and_other_codes_are_dropped(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx.target_dir / "s.sh", "#!/bin/sh\necho $1\neval $1\n")
    path = (ctx.target_dir / "s.sh").as_posix()
    report = {
        "comments": [
            {"file": path, "line": 2, "column": 6, "level": "info", "code": 2086, "message": "q"},
            {"file": path, "line": 3, "column": 6, "level": "info", "code": 2086, "message": "q"},
            {"file": path, "line": 1, "column": 1, "level": "error", "code": 2148, "message": "s"},
            {"file": "/elsewhere/x.sh", "line": 1, "column": 1, "code": 2115, "message": "m"},
        ]
    }
    doc, dropped = json_to_sarif(report, target=ctx.target_dir)
    [result] = doc["runs"][0]["results"]
    assert (result["ruleId"], result["properties"]["command"]) == ("SC2086", "eval")
    assert result["properties"]["tags"] == ["security", "external/cwe/cwe-95"]
    assert dropped == 3


def test_run_adapter_converts_stdout(tmp_path):
    ctx = make_ctx(tmp_path)
    copy_release_script(ctx)
    payload = json.dumps(recorded(ctx)).encode()

    def runner(argv, *, cwd, env, timeout, stdout, stderr):
        stdout.write(payload)
        return ProcessOutcome(1)

    def resolver(name, *, allow_path=False):
        return ResolvedTool(name, TOOL, "0.11.0", "kalkan")

    result = run_adapter(ShellcheckAdapter(), ctx, runner=runner, resolver=resolver)
    assert result.status == "ok", result.message
    assert result.candidates == 3
    status = json.loads((ctx.run_dir / "scans" / "shellcheck.status.json").read_text("utf-8"))
    assert status["dropped_comments"] == 0 and "SC2086" in status["kept_codes"]
