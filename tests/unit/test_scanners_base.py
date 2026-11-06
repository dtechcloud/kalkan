# SPDX-License-Identifier: MIT
"""Tests for kalkan.scanners.base: run_adapter, process handling, caps and status files."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from kalkan.errors import ValidationError
from kalkan.scanners import base
from kalkan.scanners.base import (
    BuiltinOutcome,
    Invocation,
    ProcessOutcome,
    ScanContext,
    ToolAdapter,
    cap_file,
    load_scan_context,
    minimal_env,
    part_path,
    run_adapter,
    run_process,
    status_path,
)
from kalkan.scanners.candidates import load_candidates
from kalkan.tools.resolve import ResolvedTool

# --------------------------------------------------------------------------------------------
# helpers

RULE = {"id": "R1", "shortDescription": {"text": "Rule one"}}


def sarif(results: list[dict], rules: list[dict] | None = None) -> dict:
    return {
        "version": "2.1.0",
        "runs": [
            {"tool": {"driver": {"name": "fake", "rules": rules or [RULE]}}, "results": results}
        ],
    }


def result(uri: str = "app.py", line: int = 3, snippet: str = "x = 1", rule: str = "R1") -> dict:
    return {
        "ruleId": rule,
        "level": "error",
        "message": {"text": "bad thing"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": line, "snippet": {"text": snippet}},
                }
            }
        ],
    }


def make_ctx(tmp_path: Path, **kwargs) -> ScanContext:
    run = tmp_path / "run"
    target = run / "target"
    target.mkdir(parents=True, exist_ok=True)
    (target / "app.py").write_text("a\nb\nx = 1\n", encoding="utf-8")
    return ScanContext(run_dir=run, target_dir=target, source_dir=None, tech=frozenset(), **kwargs)


def resolver(version: str = "1.2.3", command: tuple[str, ...] = ()):
    calls: list[tuple[str, bool]] = []

    def resolve(name: str, *, allow_path: bool = False):
        calls.append((name, allow_path))
        return ResolvedTool(name, Path("/opt/tools") / name, version, "kalkan", command)

    resolve.calls = calls  # type: ignore[attr-defined]
    return resolve


def missing(name: str, *, allow_path: bool = False):
    return None


class FakeRunner:
    """Records calls; ``action(index, argv, cwd, stdout, stderr)`` returns the outcome."""

    def __init__(self, action):
        self.action = action
        self.calls: list[dict] = []

    def __call__(self, argv, *, cwd, env, timeout, stdout, stderr):
        self.calls.append(
            {"argv": list(argv), "cwd": Path(cwd), "env": dict(env), "timeout": timeout}
        )
        return self.action(len(self.calls) - 1, list(argv), Path(cwd), stdout, stderr)


def write_after(flag: str, payload: object | bytes, code: int = 0):
    """A runner action that writes ``payload`` to the path after ``flag`` in argv."""

    def action(index, argv, cwd, stdout, stderr):
        path = Path(argv[argv.index(flag) + 1])
        data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        path.write_bytes(data)
        stderr.write(b"some log line\n")
        return ProcessOutcome(code)

    return action


class FakeSarifAdapter(ToolAdapter):
    name = "opengrep"
    tool = "opengrep"
    output = "sarif-file"
    output_name = "opengrep.sarif"
    ok_exit_codes = (0,)
    timeout_seconds = 77

    def arguments(self, ctx, out):
        return ["scan", "--out", str(out), str(ctx.target_dir)]


class FakeJsonAdapter(ToolAdapter):
    name = "syft"
    tool = "syft"
    output = "json-file"
    output_dir = "sca"
    output_name = "sbom.cdx.json"

    def arguments(self, ctx, out):
        return ["--out", str(out)]


def read_status(ctx: ScanContext, adapter) -> dict:
    return json.loads(status_path(ctx.run_dir.resolve(), adapter).read_text(encoding="utf-8"))


# --------------------------------------------------------------------------------------------
# minimal_env, cap_file, part_path


def test_minimal_env_keeps_only_allowed_names():
    environ = {
        "PATH": "/bin",
        "HOME": "/home/u",
        "LANG": "C.UTF-8",
        "GITHUB_TOKEN": "secret",
        "AWS_SECRET_ACCESS_KEY": "secret",
        "BC_API_KEY": "secret",
        "HTTPS_PROXY": "http://proxy:3128",
    }
    env = minimal_env({"EXTRA": "1"}, environ=environ)
    assert env["PATH"] == "/bin"
    assert env["EXTRA"] == "1"
    assert env["HTTPS_PROXY"] == "http://proxy:3128"
    assert "GITHUB_TOKEN" not in env
    assert "AWS_SECRET_ACCESS_KEY" not in env
    assert "BC_API_KEY" not in env


def test_minimal_env_adapter_values_win():
    env = minimal_env({"PATH": "/custom"}, environ={"PATH": "/bin"})
    assert env["PATH"] == "/custom"


def test_cap_file_keeps_head_and_adds_note(tmp_path):
    path = tmp_path / "log.txt"
    path.write_bytes(b"HEAD" + b"x" * 3000)
    assert cap_file(path, limit=1000) is True
    data = path.read_bytes()
    assert len(data) <= 1000
    assert data.startswith(b"HEAD")
    assert b"output cut to the first 1000 bytes of 3004" in data


def test_cap_file_small_file_unchanged(tmp_path):
    path = tmp_path / "log.txt"
    path.write_bytes(b"short")
    assert cap_file(path, limit=1000) is False
    assert path.read_bytes() == b"short"


def test_cap_file_does_not_split_utf8(tmp_path):
    path = tmp_path / "log.txt"
    path.write_bytes(("ü" * 2000).encode("utf-8"))
    cap_file(path, limit=1001)
    path.read_bytes().decode("utf-8")  # no UnicodeDecodeError


def test_part_path(tmp_path):
    assert part_path(tmp_path / "gosec.sarif", 2) == tmp_path / "gosec.sarif.parts" / "002.sarif"


# --------------------------------------------------------------------------------------------
# run_adapter: status handling


def test_ok_sarif_is_ingested_and_status_written(tmp_path):
    ctx = make_ctx(tmp_path)
    runner = FakeRunner(write_after("--out", sarif([result()])))
    res = run_adapter(FakeSarifAdapter(), ctx, runner=runner, resolver=resolver())
    assert res.status == "ok", res.message
    assert res.candidates == 1
    assert res.message == "1 candidate"
    assert res.tool_version == "1.2.3"
    assert res.exit_code == 0
    run = ctx.run_dir.resolve()
    assert res.output_path == run / "scans" / "opengrep.sarif"
    assert res.output_path.is_file()
    doc = load_candidates(run)
    assert len(doc["candidates"]) == 1
    candidate = doc["candidates"][0]
    assert candidate["file"] == "app.py"
    assert candidate["raw"]["sarif_file"] == "scans/opengrep.sarif"
    status = read_status(ctx, FakeSarifAdapter())
    assert status["status"] == "ok"
    assert status["candidates"] == 1
    assert status["output"] == "scans/opengrep.sarif"
    assert status["command"][0] == str(Path("/opt/tools/opengrep"))
    for key in ("engine", "message", "duration_seconds", "exit_code", "tool_version"):
        assert key in status
    assert status["started_at"].endswith("Z") and status["finished_at"].endswith("Z")
    assert not (run / "scans" / ".work").exists()


def test_default_timeout_and_cwd(tmp_path):
    ctx = make_ctx(tmp_path)
    runner = FakeRunner(write_after("--out", sarif([])))
    run_adapter(FakeSarifAdapter(), ctx, runner=runner, resolver=resolver())
    call = runner.calls[0]
    assert 0 < call["timeout"] <= 77
    assert call["cwd"] == ctx.run_dir.resolve() / "scans"


def test_timeout_zero_means_no_limit(tmp_path):
    ctx = make_ctx(tmp_path)
    runner = FakeRunner(write_after("--out", sarif([])))
    run_adapter(FakeSarifAdapter(), ctx, runner=runner, resolver=resolver(), timeout_seconds=0)
    assert runner.calls[0]["timeout"] is None


def test_negative_timeout_is_rejected(tmp_path):
    with pytest.raises(ValueError):
        run_adapter(FakeSarifAdapter(), make_ctx(tmp_path), timeout_seconds=-1)


def test_not_applicable_gives_skipped(tmp_path):
    class Never(FakeSarifAdapter):
        def applies(self, ctx):
            return False, "no Python code"

    ctx = make_ctx(tmp_path)
    runner = FakeRunner(write_after("--out", sarif([])))
    res = run_adapter(Never(), ctx, runner=runner, resolver=resolver())
    assert (res.status, res.message) == ("skipped", "no Python code")
    assert runner.calls == []
    assert read_status(ctx, Never())["status"] == "skipped"


def test_missing_tool_gives_skipped(tmp_path):
    ctx = make_ctx(tmp_path)
    runner = FakeRunner(write_after("--out", sarif([])))
    res = run_adapter(FakeSarifAdapter(), ctx, runner=runner, resolver=missing)
    assert res.status == "skipped"
    assert res.message.startswith("tool not found: opengrep")
    assert "kalkan tools install opengrep" in res.message
    assert runner.calls == []


def test_allow_path_tools_reaches_the_resolver(tmp_path):
    ctx = make_ctx(tmp_path, allow_path_tools=True)
    resolve = resolver()
    run_adapter(
        FakeSarifAdapter(),
        ctx,
        runner=FakeRunner(write_after("--out", sarif([]))),
        resolver=resolve,
    )
    assert resolve.calls == [("opengrep", True)]


def test_unexpected_exit_code_gives_failed_with_stderr(tmp_path):
    def action(index, argv, cwd, stdout, stderr):
        stderr.write(b"\x1b[31mFATAL\x1b[0m boom happened\n")
        return ProcessOutcome(3)

    ctx = make_ctx(tmp_path)
    res = run_adapter(FakeSarifAdapter(), ctx, runner=FakeRunner(action), resolver=resolver())
    assert res.status == "failed"
    assert res.exit_code == 3
    assert "exit code 3 (expected 0)" in res.message
    assert "FATAL boom happened" in res.message
    assert res.output_path is None


def test_ok_exit_code_list_is_respected(tmp_path):
    class FindingsExitOne(FakeSarifAdapter):
        ok_exit_codes = (0, 1)

    ctx = make_ctx(tmp_path)
    runner = FakeRunner(write_after("--out", sarif([result()]), code=1))
    res = run_adapter(FindingsExitOne(), ctx, runner=runner, resolver=resolver())
    assert res.status == "ok"
    assert res.exit_code == 1


def test_missing_output_gives_failed(tmp_path):
    ctx = make_ctx(tmp_path)
    res = run_adapter(
        FakeSarifAdapter(),
        ctx,
        runner=FakeRunner(lambda *a: ProcessOutcome(0)),
        resolver=resolver(),
    )
    assert res.status == "failed"
    assert "no output file opengrep.sarif" in res.message


def test_empty_sarif_gives_failed(tmp_path):
    ctx = make_ctx(tmp_path)
    res = run_adapter(
        FakeSarifAdapter(), ctx, runner=FakeRunner(write_after("--out", b"")), resolver=resolver()
    )
    assert res.status == "failed"
    assert "empty output file" in res.message


def test_malformed_sarif_gives_failed_not_exception(tmp_path):
    ctx = make_ctx(tmp_path)
    runner = FakeRunner(write_after("--out", b"{not json"))
    res = run_adapter(FakeSarifAdapter(), ctx, runner=runner, resolver=resolver())
    assert res.status == "failed"
    assert "not valid JSON" in res.message


def test_wrong_sarif_version_gives_failed(tmp_path):
    ctx = make_ctx(tmp_path)
    runner = FakeRunner(write_after("--out", {"version": "2.0.0", "runs": []}))
    res = run_adapter(FakeSarifAdapter(), ctx, runner=runner, resolver=resolver())
    assert res.status == "failed"
    assert "not a SARIF 2.1.0 document" in res.message


def test_timeout_outcome_gives_timeout(tmp_path):
    ctx = make_ctx(tmp_path)
    runner = FakeRunner(lambda *a: ProcessOutcome(None, timed_out=True))
    res = run_adapter(
        FakeSarifAdapter(), ctx, runner=runner, resolver=resolver(), timeout_seconds=5
    )
    assert res.status == "timeout"
    assert res.message == "timed out after 5 s"
    assert read_status(ctx, FakeSarifAdapter())["status"] == "timeout"


def test_start_error_gives_failed(tmp_path):
    ctx = make_ctx(tmp_path)
    runner = FakeRunner(lambda *a: ProcessOutcome(None, error="cannot start opengrep: denied"))
    res = run_adapter(FakeSarifAdapter(), ctx, runner=runner, resolver=resolver())
    assert res.status == "failed"
    assert "cannot start opengrep" in res.message


def test_exception_inside_adapter_gives_failed(tmp_path):
    class Broken(FakeSarifAdapter):
        def arguments(self, ctx, out):
            raise RuntimeError("bug")

    res = run_adapter(Broken(), make_ctx(tmp_path), runner=FakeRunner(None), resolver=resolver())
    assert res.status == "failed"
    assert res.message == "internal error: RuntimeError: bug"


def test_ingest_false_skips_candidates(tmp_path):
    ctx = make_ctx(tmp_path)
    runner = FakeRunner(write_after("--out", sarif([result()])))
    res = run_adapter(FakeSarifAdapter(), ctx, runner=runner, resolver=resolver(), ingest=False)
    assert res.status == "ok"
    assert res.candidates is None
    assert not (ctx.run_dir / "candidates.json").exists()


def test_rerun_replaces_candidates_of_the_engine(tmp_path):
    ctx = make_ctx(tmp_path)
    first = FakeRunner(write_after("--out", sarif([result(line=1), result(line=2)])))
    run_adapter(FakeSarifAdapter(), ctx, runner=first, resolver=resolver())
    assert len(load_candidates(ctx.run_dir)["candidates"]) == 2
    second = FakeRunner(write_after("--out", sarif([result(line=3)])))
    res = run_adapter(FakeSarifAdapter(), ctx, runner=second, resolver=resolver())
    assert res.candidates == 1
    assert [c["start_line"] for c in load_candidates(ctx.run_dir)["candidates"]] == [3]


# --------------------------------------------------------------------------------------------
# argv, environment, logs


def test_argv0_is_replaced_by_resolved_argv(tmp_path):
    ctx = make_ctx(tmp_path)
    runner = FakeRunner(write_after("--out", sarif([])))
    resolve = resolver(command=("/venv/python", "/venv/Scripts/checkov"))
    res = run_adapter(FakeSarifAdapter(), ctx, runner=runner, resolver=resolve)
    assert res.status == "ok"
    assert runner.calls[0]["argv"][:3] == ["/venv/python", "/venv/Scripts/checkov", "scan"]


def test_environment_is_minimal_plus_adapter_env(tmp_path, monkeypatch):
    class WithEnv(FakeSarifAdapter):
        def env(self, ctx):
            return {"TOOL_FLAG": "yes"}

    monkeypatch.setenv("GITHUB_TOKEN", "do-not-leak")
    ctx = make_ctx(tmp_path)
    runner = FakeRunner(write_after("--out", sarif([])))
    run_adapter(WithEnv(), ctx, runner=runner, resolver=resolver())
    env = runner.calls[0]["env"]
    assert env["TOOL_FLAG"] == "yes"
    assert "GITHUB_TOKEN" not in env
    assert "PATH" in env


def test_logs_are_written_and_capped(tmp_path):
    def action(index, argv, cwd, stdout, stderr):
        stdout.write(b"o" * (3 * 1024 * 1024))
        stderr.write(b"e" * (2 * 1024 * 1024))
        Path(argv[argv.index("--out") + 1]).write_text(json.dumps(sarif([])), encoding="utf-8")
        return ProcessOutcome(0)

    ctx = make_ctx(tmp_path)
    res = run_adapter(FakeSarifAdapter(), ctx, runner=FakeRunner(action), resolver=resolver())
    assert res.status == "ok"
    scans = ctx.run_dir / "scans"
    for name in ("opengrep.stdout.txt", "opengrep.stderr.txt"):
        size = (scans / name).stat().st_size
        assert 0 < size <= base.MAX_LOG_BYTES
        assert b"output cut" in (scans / name).read_bytes()[-200:]


# --------------------------------------------------------------------------------------------
# outputs: staging, stdout, parts


def test_failed_run_keeps_the_last_good_output(tmp_path):
    ctx = make_ctx(tmp_path)
    good = FakeRunner(write_after("--out", {"bomFormat": "CycloneDX"}))
    assert run_adapter(FakeJsonAdapter(), ctx, runner=good, resolver=resolver()).status == "ok"
    out = ctx.run_dir / "sca" / "sbom.cdx.json"
    before = out.read_bytes()
    bad = FakeRunner(lambda *a: ProcessOutcome(2))
    res = run_adapter(FakeJsonAdapter(), ctx, runner=bad, resolver=resolver())
    assert res.status == "failed"
    assert res.output_path is None
    assert out.read_bytes() == before


def test_invalid_json_output_gives_failed_and_keeps_old(tmp_path):
    ctx = make_ctx(tmp_path)
    run_adapter(
        FakeJsonAdapter(),
        ctx,
        runner=FakeRunner(write_after("--out", {"a": 1})),
        resolver=resolver(),
    )
    res = run_adapter(
        FakeJsonAdapter(), ctx, runner=FakeRunner(write_after("--out", b"[1,")), resolver=resolver()
    )
    assert res.status == "failed"
    assert "not valid JSON" in res.message
    assert json.loads((ctx.run_dir / "sca" / "sbom.cdx.json").read_text(encoding="utf-8")) == {
        "a": 1
    }


def test_json_file_ok_message(tmp_path):
    ctx = make_ctx(tmp_path)
    res = run_adapter(
        FakeJsonAdapter(),
        ctx,
        runner=FakeRunner(write_after("--out", {"a": 1})),
        resolver=resolver(),
    )
    assert res.status == "ok"
    assert res.candidates is None
    assert res.message.startswith("output written: sca/sbom.cdx.json")


class StdoutAdapter(ToolAdapter):
    name = "hadolint"
    tool = "hadolint"
    output = "sarif-stdout"
    output_name = "hadolint.sarif"

    def arguments(self, ctx, out):
        return ["-f", "sarif"]


def test_sarif_stdout_becomes_the_output(tmp_path):
    def action(index, argv, cwd, stdout, stderr):
        stdout.write(json.dumps(sarif([result()])).encode())
        return ProcessOutcome(0)

    ctx = make_ctx(tmp_path)
    res = run_adapter(StdoutAdapter(), ctx, runner=FakeRunner(action), resolver=resolver())
    assert res.status == "ok", res.message
    assert res.candidates == 1
    log = (ctx.run_dir / "scans" / "hadolint.stdout.txt").read_text(encoding="utf-8")
    assert "stdout is the output file" in log


def test_sarif_stdout_in_ansi_code_page_is_repaired(tmp_path, monkeypatch):
    monkeypatch.setattr(base.locale, "getpreferredencoding", lambda do_setlocale=True: "cp1252")
    doc = sarif([result(snippet="café = 1")])

    def action(index, argv, cwd, stdout, stderr):
        stdout.write(json.dumps(doc, ensure_ascii=False).encode("cp1252"))
        return ProcessOutcome(0)

    ctx = make_ctx(tmp_path)
    res = run_adapter(StdoutAdapter(), ctx, runner=FakeRunner(action), resolver=resolver())
    assert res.status == "ok", res.message
    assert load_candidates(ctx.run_dir)["candidates"][0]["snippet"] == "café = 1"


class ModuleAdapter(ToolAdapter):
    """Two runs with module-relative URIs, like gosec."""

    name = "gosec"
    tool = "gosec"
    output = "sarif-file"
    output_name = "gosec.sarif"

    def arguments(self, ctx, out):
        return ["-out", str(out)]

    def invocations(self, ctx, tool_path, out):
        items = []
        for index, module in enumerate(["svc/a", "svc/b"]):
            part = part_path(out, index)
            items.append(
                Invocation(
                    (str(tool_path), *self.arguments(ctx, part)),
                    ctx.target_dir,
                    part,
                    base=module,
                    label=module,
                )
            )
        return items


def test_parts_are_merged_and_uris_rebased(tmp_path):
    def action(index, argv, cwd, stdout, stderr):
        path = Path(argv[argv.index("-out") + 1])
        path.write_text(json.dumps(sarif([result(uri="main.go")])), encoding="utf-8")
        return ProcessOutcome(0)

    ctx = make_ctx(tmp_path)
    runner = FakeRunner(action)
    res = run_adapter(ModuleAdapter(), ctx, runner=runner, resolver=resolver())
    assert res.status == "ok", res.message
    assert len(runner.calls) == 2
    merged = json.loads((ctx.run_dir / "scans" / "gosec.sarif").read_text(encoding="utf-8"))
    uris = [
        run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        for run in merged["runs"]
    ]
    assert uris == ["svc/a/main.go", "svc/b/main.go"]
    files = sorted(c["file"] for c in load_candidates(ctx.run_dir)["candidates"])
    assert files == ["svc/a/main.go", "svc/b/main.go"]
    status = read_status(ctx, ModuleAdapter())
    assert len(status["commands"]) == 2


def test_partial_failure_still_ingests_good_parts(tmp_path):
    def action(index, argv, cwd, stdout, stderr):
        if index == 1:
            stderr.write(b"package load failed\n")
            return ProcessOutcome(1)
        path = Path(argv[argv.index("-out") + 1])
        path.write_text(json.dumps(sarif([result(uri="main.go")])), encoding="utf-8")
        return ProcessOutcome(0)

    ctx = make_ctx(tmp_path)
    res = run_adapter(ModuleAdapter(), ctx, runner=FakeRunner(action), resolver=resolver())
    assert res.status == "failed"
    assert res.message.startswith("1 of 2 runs succeeded")
    assert "(svc/b)" in res.message
    assert res.candidates == 1
    assert res.exit_code == 1


def test_rebase_keeps_absolute_and_known_base_uris():
    run = {
        "originalUriBaseIds": {"ROOT": {"uri": "file:///src/"}},
        "results": [
            {"locations": [{"physicalLocation": {"artifactLocation": {"uri": "/abs/x.go"}}}]},
            {"locations": [{"physicalLocation": {"artifactLocation": {"uri": "file:///c/x.go"}}}]},
            {
                "locations": [
                    {"physicalLocation": {"artifactLocation": {"uri": "x.go", "uriBaseId": "ROOT"}}}
                ]
            },
            {"locations": [{"physicalLocation": {"artifactLocation": {"uri": "./sub\\y.go"}}}]},
        ],
    }
    base._rebase_uris(run, "mod dir")
    uris = [
        r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in run["results"]
    ]
    assert uris == ["/abs/x.go", "file:///c/x.go", "x.go", "mod%20dir/sub/y.go"]


class StreamAdapter(ToolAdapter):
    name = "govulncheck"
    tool = "govulncheck"
    output = "json-stdout"
    output_dir = "sca"
    output_name = "govulncheck.json"

    def arguments(self, ctx, out):
        return ["-json", "./..."]

    def invocations(self, ctx, tool_path, out):
        return [
            Invocation(
                (str(tool_path), "-json"), ctx.target_dir, part_path(out, i), base=m, label=m
            )
            for i, m in enumerate(["a", "b"])
        ]


def test_json_stream_parts_get_markers(tmp_path):
    def action(index, argv, cwd, stdout, stderr):
        stdout.write(b'{"config": {"n": %d}}\n{"finding": {}}\n' % index)
        return ProcessOutcome(0)

    ctx = make_ctx(tmp_path)
    res = run_adapter(StreamAdapter(), ctx, runner=FakeRunner(action), resolver=resolver())
    assert res.status == "ok", res.message
    lines = (ctx.run_dir / "sca" / "govulncheck.json").read_text(encoding="utf-8").splitlines()
    objects = [json.loads(line) for line in lines]
    assert objects[0] == {"kalkan_invocation": {"index": 0, "label": "a", "dir": "a"}}
    assert objects[1] == {"config": {"n": 0}}
    assert objects[3]["kalkan_invocation"]["dir"] == "b"


# --------------------------------------------------------------------------------------------
# built-in adapters


class Builtin:
    name = "matcher"
    tool = None
    output = "candidates"
    output_dir = "scans"
    output_name = ""
    ok_exit_codes = (0,)
    timeout_seconds = 10

    def __init__(self, outcome=None, error=None):
        self.outcome = outcome
        self.error = error

    def applies(self, ctx):
        return True, ""

    def command(self, ctx, tool_path, out):
        raise NotImplementedError

    def env(self, ctx):
        return {}

    def collect(self, ctx):
        if self.error:
            raise self.error
        return self.outcome


def candidate(line: int) -> dict:
    from kalkan.findings.fingerprint import candidate_id

    return {
        "id": candidate_id("matcher", "m1", "app.py", line, "x"),
        "engine": "matcher",
        "rule_id": "m1",
        "class": None,
        "cwe": [],
        "title": "t",
        "message": "m",
        "file": "app.py",
        "start_line": line,
        "end_line": line,
        "snippet": "x",
        "severity": "info",
        "tool_severity": "noisy",
        "confidence": "low",
        "tags": [],
        "fingerprints": {},
        "sca": None,
        "raw": {"sarif_file": "", "run_index": 0, "result_index": 0},
    }


def test_builtin_adapter_merges_candidates_and_details(tmp_path):
    outcome = BuiltinOutcome(
        candidates=[candidate(1), candidate(2)],
        warnings=["w1"],
        message="2 of 3 matchers applied",
        details={"stats": {"files_scanned": 4}, "skipped": {"x": "tech"}, "warnings": ["w1"]},
    )
    ctx = make_ctx(tmp_path)
    res = run_adapter(Builtin(outcome), ctx)
    assert res.status == "ok"
    assert res.candidates == 2
    assert res.message == "2 candidates; 2 of 3 matchers applied"
    status = read_status(ctx, Builtin())
    assert status["stats"] == {"files_scanned": 4}
    assert status["skipped"] == {"x": "tech"}
    assert status["warnings"] == ["w1"]
    assert load_candidates(ctx.run_dir)["warnings"] == ["matcher: w1"]


def test_builtin_adapter_error_gives_failed(tmp_path):
    error = ValidationError("2 matcher spec error(s)", ["a.json: bad regex"])
    res = run_adapter(Builtin(error=error), make_ctx(tmp_path))
    assert res.status == "failed"
    assert res.message == "2 matcher spec error(s): a.json: bad regex"


# --------------------------------------------------------------------------------------------
# load_scan_context


def write_manifest(run: Path, data: dict) -> None:
    run.mkdir(parents=True, exist_ok=True)
    (run / "target-manifest.json").write_text(json.dumps(data), encoding="utf-8")


def test_load_scan_context_reads_manifest(tmp_path):
    run = tmp_path / "run"
    (run / "target").mkdir(parents=True)
    source = run / "source"
    source.mkdir()
    write_manifest(
        run, {"copy": "target", "source_dir": source.as_posix(), "tech": ["Python", "go"]}
    )
    ctx = load_scan_context(run, offline=True)
    assert ctx.run_dir == run.resolve()
    assert ctx.target_dir == (run / "target").resolve()
    assert ctx.source_dir == source.resolve()
    assert ctx.tech == frozenset({"python", "go"})
    assert ctx.offline is True
    assert ctx.allow_path_tools is False


def test_load_scan_context_never_gives_a_folder_outside_the_run(tmp_path):
    """Promise 1: an older manifest named the original folder; no scanner may get it."""
    run = tmp_path / "run"
    (run / "target").mkdir(parents=True)
    original = tmp_path / "original"
    original.mkdir()
    write_manifest(run, {"copy": "target", "source_dir": original.as_posix(), "tech": []})
    assert load_scan_context(run).source_dir is None
    write_manifest(run, {"copy": "target", "source_dir": run.as_posix(), "tech": []})
    assert load_scan_context(run).source_dir is None
    write_manifest(run, {"copy": "target", "source_dir": None, "tech": []})
    assert load_scan_context(run).source_dir is None


def test_load_scan_context_drops_missing_source(tmp_path):
    run = tmp_path / "run"
    (run / "target").mkdir(parents=True)
    write_manifest(
        run, {"copy": "target", "source_dir": (tmp_path / "gone").as_posix(), "tech": []}
    )
    assert load_scan_context(run).source_dir is None


@pytest.mark.parametrize(
    "data",
    [{"copy": "../outside", "tech": []}, {"copy": "missing", "tech": []}, ["not", "an", "object"]],
)
def test_load_scan_context_rejects_bad_manifest(tmp_path, data):
    from kalkan.errors import StateError

    run = tmp_path / "run"
    (run / "target").mkdir(parents=True)
    run.joinpath("target-manifest.json").write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(StateError):
        load_scan_context(run)


def test_load_scan_context_without_manifest(tmp_path):
    from kalkan.errors import StateError

    (tmp_path / "run").mkdir()
    with pytest.raises(StateError, match="target-manifest.json"):
        load_scan_context(tmp_path / "run")


# --------------------------------------------------------------------------------------------
# run_process with real processes (no network)


def test_run_process_writes_files_and_exit_code(tmp_path):
    out = tmp_path / "out.txt"
    err = tmp_path / "err.txt"
    code = "import sys; print('hello'); print('oops', file=sys.stderr); sys.exit(3)"
    with open(out, "wb") as stdout, open(err, "wb") as stderr:
        outcome = run_process(
            [sys.executable, "-c", code],
            cwd=tmp_path,
            env=minimal_env(),
            timeout=60,
            stdout=stdout,
            stderr=stderr,
        )
    assert outcome == ProcessOutcome(3)
    assert out.read_text().strip() == "hello"
    assert err.read_text().strip() == "oops"


def test_run_process_start_error(tmp_path):
    with open(tmp_path / "o", "wb") as stdout, open(tmp_path / "e", "wb") as stderr:
        outcome = run_process(
            [str(tmp_path / "no-such-tool")],
            cwd=tmp_path,
            env=minimal_env(),
            timeout=5,
            stdout=stdout,
            stderr=stderr,
        )
    assert outcome.exit_code is None
    assert outcome.error and outcome.error.startswith("cannot start no-such-tool")


def test_run_process_timeout_kills_the_process_tree(tmp_path):
    from kalkan.run.lock import pid_alive

    pid_file = tmp_path / "child.pid"
    parent = (
        "import subprocess, sys, time\n"
        "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)'])\n"
        f"open({str(pid_file)!r}, 'w').write(str(child.pid))\n"
        "time.sleep(120)\n"
    )
    started = time.monotonic()
    with open(tmp_path / "o", "wb") as stdout, open(tmp_path / "e", "wb") as stderr:
        outcome = run_process(
            [sys.executable, "-c", parent],
            cwd=tmp_path,
            env=minimal_env(),
            timeout=8,
            stdout=stdout,
            stderr=stderr,
        )
    assert outcome.timed_out is True
    assert time.monotonic() - started < 60
    child = int(pid_file.read_text())
    deadline = time.monotonic() + 10
    while pid_alive(child) and time.monotonic() < deadline:
        time.sleep(0.2)
    assert not pid_alive(child)


@pytest.mark.skipif(os.name != "nt", reason="Windows taskkill path")
def test_kill_uses_absolute_taskkill(monkeypatch):
    seen: list[list[str]] = []

    def fake_run(argv, **kwargs):
        seen.append(argv)
        return subprocess.CompletedProcess(argv, 0)

    class FakeProcess:
        pid = 4242

        def kill(self):
            pass

        def wait(self, timeout=None):
            return 0

    monkeypatch.setattr(base.subprocess, "run", fake_run)
    base.kill_process_tree(FakeProcess())  # type: ignore[arg-type]
    assert seen[0][0].lower().endswith(os.path.join("system32", "taskkill.exe"))
    assert seen[0][1:] == ["/T", "/F", "/PID", "4242"]


# --------------------------------------------------------------------------------------------
# suppressions (ADR-0003)


def suppressed(result_item: dict, status: str | None = None) -> dict:
    entry = {"kind": "inSource", "justification": "target says so"}
    if status is not None:
        entry["status"] = status
    return {**result_item, "suppressions": [entry]}


class SourcesAdapter(FakeSarifAdapter):
    def __init__(self):
        self.prepared: list[Path] = []

    def prepare(self, ctx, stage):
        self.prepared.append(stage)
        (stage.parent / "helper.cfg").write_text("x", encoding="utf-8")

    def suppression_sources(self, ctx):
        if ctx.honor_suppressions:
            return [], ["inline comments"]
        return ["inline comments (--flag)"], ["config file (no option)"]


def test_suppressed_results_are_kept_and_tagged_by_default(tmp_path):
    ctx = make_ctx(tmp_path)
    doc = sarif(
        [
            result(line=1),
            suppressed(result(line=2)),
            suppressed(result(line=3), status="rejected"),
        ]
    )
    adapter = SourcesAdapter()
    res = run_adapter(
        adapter, ctx, runner=FakeRunner(write_after("--out", doc)), resolver=resolver()
    )
    assert res.status == "ok", res.message
    assert res.candidates == 3
    assert "1 suppressed by the target: kept, tagged suppressed-in-source" in res.message
    tagged = {
        c["start_line"]: base.SUPPRESSED_TAG in c["tags"]
        for c in load_candidates(ctx.run_dir)["candidates"]
    }
    assert tagged == {1: False, 2: True, 3: False}
    status = read_status(ctx, adapter)
    assert status["suppressions"]["mode"] == "ignore"
    assert status["suppressions"]["ignored"][0] == "inline comments (--flag)"
    assert status["suppressions"]["ignored"][-1].startswith("results that the tool marks")
    assert status["suppressions"]["honored"] == ["config file (no option)"]
    assert status["suppressed_results"] == {
        "count": 1,
        "action": "kept, tagged suppressed-in-source",
    }


def test_honor_mode_drops_suppressed_results(tmp_path):
    ctx = make_ctx(tmp_path, honor_suppressions=True)
    doc = sarif([result(line=1), suppressed(result(line=2))])
    adapter = SourcesAdapter()
    res = run_adapter(
        adapter, ctx, runner=FakeRunner(write_after("--out", doc)), resolver=resolver()
    )
    assert res.status == "ok"
    assert res.candidates == 1
    assert [c["start_line"] for c in load_candidates(ctx.run_dir)["candidates"]] == [1]
    status = read_status(ctx, adapter)
    assert status["suppressions"]["mode"] == "honor"
    assert status["suppressions"]["honored"][0] == "inline comments"
    assert status["suppressed_results"]["action"] == "dropped"


def test_prepare_runs_in_the_work_folder_before_the_tool(tmp_path):
    ctx = make_ctx(tmp_path)
    adapter = SourcesAdapter()
    seen: list[bool] = []

    def action(index, argv, cwd, stdout, stderr):
        seen.append((adapter.prepared[0].parent / "helper.cfg").is_file())
        return write_after("--out", sarif([]))(index, argv, cwd, stdout, stderr)

    run_adapter(adapter, ctx, runner=FakeRunner(action), resolver=resolver())
    run = ctx.run_dir.resolve()
    assert adapter.prepared == [run / "scans" / ".work" / "opengrep" / "opengrep.sarif"]
    assert seen == [True]
    assert not (run / "scans" / ".work").exists()


def test_json_adapter_records_suppressions_without_sarif_note(tmp_path):
    ctx = make_ctx(tmp_path)
    run_adapter(
        FakeJsonAdapter(),
        ctx,
        runner=FakeRunner(write_after("--out", {"a": 1})),
        resolver=resolver(),
    )
    status = read_status(ctx, FakeJsonAdapter())
    assert status["suppressions"] == {"mode": "ignore", "ignored": [], "honored": []}


def test_load_scan_context_honor_flag(tmp_path):
    run = tmp_path / "run"
    (run / "target").mkdir(parents=True)
    write_manifest(run, {"copy": "target", "tech": []})
    assert load_scan_context(run).honor_suppressions is False
    assert load_scan_context(run, honor_suppressions=True).honor_suppressions is True


def test_checkov_launcher_turns_config_discovery_off(tmp_path):
    from kalkan.scanners.adapters.checkov import LAUNCHER, CheckovAdapter

    venv = tmp_path / "venv" / "Scripts"
    venv.mkdir(parents=True)
    python = venv / ("python.exe" if os.name == "nt" else "python")
    python.write_text("", encoding="utf-8")
    entry = venv / "checkov"
    ctx = make_ctx(tmp_path)
    out = tmp_path / "work" / "checkov.sarif"
    adapter = CheckovAdapter()
    [item] = adapter.invocations(ctx, entry, out)
    assert list(item.argv[:6]) == [str(python), "-I", "-X", "utf8", "-c", LAUNCHER]
    assert item.argv[6:8] == ("-d", str(ctx.target_dir))
    assert "m.get_default_config_paths = lambda argv: []" in LAUNCHER
    ignored, honored = adapter.suppression_sources(ctx)
    assert any("config discovery turned off" in item for item in ignored)
    assert honored == []
    honor = make_ctx(tmp_path, honor_suppressions=True)
    ignored, honored = adapter.suppression_sources(honor)
    assert any(".checkov.yaml" in item for item in ignored)
    assert any("checkov:skip" in item for item in honored)
    python.unlink()
    [item] = adapter.invocations(ctx, entry, out)
    assert item.argv[0] == str(entry)
    ignored, honored = adapter.suppression_sources(ctx)
    assert any("could not be turned off" in item for item in honored)
