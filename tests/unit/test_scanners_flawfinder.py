# SPDX-License-Identifier: MIT
"""Tests for the flawfinder adapter (kalkan.scanners.adapters.flawfinder): file discovery, the
command line, the minimum level, the UTF-8 copies of other encodings and the rewrite of a
recorded flawfinder 2.0.20 SARIF document."""

from __future__ import annotations

import json
from pathlib import Path

from kalkan.sarif.ingest import ingest_document
from kalkan.scanners.adapters.flawfinder import (
    MIN_LEVEL,
    FlawfinderAdapter,
    c_sources,
    file_argument,
    flawfinder_level,
    is_c_source,
    needs_transcoding,
    rewrite_sarif,
)
from kalkan.scanners.base import ProcessOutcome, ScanContext, run_adapter, work_dir
from kalkan.tools.resolve import ResolvedTool

TOOL = Path("/opt/flawfinder")
OUTPUTS = Path(__file__).resolve().parents[1] / "fixtures" / "scanner-outputs"
FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "vulnapp"
COPY = "void f(char *s) { char b[8]; strcpy(b, s); }\n"


def make_ctx(tmp_path: Path, tech=("c",), *, honor: bool = False) -> ScanContext:
    run = (tmp_path / "run").resolve()
    target = run / "target"
    target.mkdir(parents=True, exist_ok=True)
    return ScanContext(
        run_dir=run,
        target_dir=target,
        source_dir=None,
        tech=frozenset(tech),
        honor_suppressions=honor,
    )


def write(path: Path, data: str | bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, bytes):
        path.write_bytes(data)
    else:
        path.write_text(data, encoding="utf-8", newline="\n")
    return path


def test_is_c_source():
    for name in ("a.c", "A.C", "b.h", "x.cpp", "y.cxx", "z.c++", "w.hpp", "v.hh", "q.pgc"):
        assert is_c_source(f"src/{name}"), name
    for name in ("a.cs", "b.m", "c.go", "Makefile", "d.cpp.txt"):
        assert not is_c_source(f"src/{name}"), name


def test_applies_needs_the_tech_tag_and_files_outside_vendored_folders(tmp_path):
    ctx = make_ctx(tmp_path, tech=())
    assert FlawfinderAdapter().applies(ctx)[0] is False
    ctx = make_ctx(tmp_path, tech=("cpp",))
    write(ctx.target_dir / "third_party" / "zlib" / "inflate.c", COPY)
    ok, reason = FlawfinderAdapter().applies(ctx)
    assert ok is False and "vendored" in reason
    write(ctx.target_dir / ".hidden" / "h.c", COPY)  # flawfinder skips dot folders it walks
    assert FlawfinderAdapter().applies(ctx) == (True, "")
    assert c_sources(ctx.target_dir) == [".hidden/h.c"]


def test_command_line(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx.target_dir / "src" / "a.c", COPY)
    out = ctx.run_dir / "scans" / ".work" / "flawfinder" / "flawfinder.sarif"
    [item] = FlawfinderAdapter().invocations(ctx, TOOL, out)
    assert list(item.argv) == [
        str(TOOL),
        "--sarif",
        "--neverignore",
        "--",
        file_argument(ctx.target_dir / "src" / "a.c"),
    ]
    assert item.output == out and item.cwd == ctx.run_dir / "scans"
    honor = FlawfinderAdapter().arguments(make_ctx(tmp_path, honor=True), out)
    assert "--neverignore" not in honor
    assert FlawfinderAdapter().env(ctx)["PYTHONUTF8"] == "1"


def test_file_arguments_escape_glob_characters_on_windows():
    path = Path("C:/t/src/[id]/a?.c")
    assert file_argument(path, windows=True) == str(path).replace("[id]", "[[]id]").replace(
        "a?", "a[?]"
    )
    assert file_argument(path, windows=False) == str(path)


def test_files_that_are_not_utf8_are_scanned_as_utf8_copies(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx.target_dir / "ok.c", COPY)
    latin = write(ctx.target_dir / "src" / "old.c", b"/* caf\xe9 */\r\n" + COPY.encode())
    assert needs_transcoding(latin) and not needs_transcoding(ctx.target_dir / "ok.c")
    adapter = FlawfinderAdapter()
    stage = work_dir(ctx.run_dir, adapter) / adapter.output_name
    stage.parent.mkdir(parents=True)
    adapter.prepare(ctx, stage)
    copy = adapter.transcoded_dir(ctx) / "src" / "old.c"
    assert copy.read_bytes() == "/* café */\r\n".encode() + COPY.encode()  # lines kept
    [item] = adapter.invocations(ctx, TOOL, stage)
    assert file_argument(copy) in item.argv and file_argument(ctx.target_dir / "ok.c") in item.argv
    assert not any("old.c" in arg and "transcoded" not in arg for arg in item.argv[1:])


def test_flawfinder_level_from_rank():
    assert [flawfinder_level({"rank": r}) for r in (0.0, 0.4, 0.6, 0.8, 1.0)] == [0, 2, 3, 4, 5]
    assert flawfinder_level({}) is None and flawfinder_level({"rank": True}) is None


def recorded(ctx: ScanContext) -> dict:
    text = (OUTPUTS / "flawfinder.sarif.json").read_text(encoding="utf-8")
    return json.loads(text.replace("@TARGET@", ctx.target_dir.as_posix()))


def test_recorded_sarif_keeps_level_three_and_higher(tmp_path):
    ctx = make_ctx(tmp_path)
    rel = "native/labels.c"
    write(ctx.target_dir / rel, (FIXTURE / rel).read_text(encoding="utf-8"))
    doc, below = rewrite_sarif(recorded(ctx), target=ctx.target_dir, transcoded=tmp_path / "t")
    assert MIN_LEVEL == 3 and below == 8  # char arrays (2) and constant-format snprintf (1)
    results = doc["runs"][0]["results"]
    assert [r["ruleId"] for r in results] == ["FF1001", "FF1015", "FF1014"]
    place = results[0]["locations"][0]["physicalLocation"]["artifactLocation"]
    assert place == {"uri": "native/labels.c"}  # no uriBaseId, no absolute path
    assert [r["properties"]["flawfinder_level"] for r in results] == [4, 4, 5]
    candidates = ingest_document(doc, "flawfinder", ctx.target_dir, "scans/f.sarif").candidates
    assert [(c["start_line"], c["class"], c["cwe"][0], c["severity"]) for c in candidates] == [
        (8, "memory-safety", "CWE-120", "high"),
        (22, "memory-safety", "CWE-120", "high"),
        (36, "memory-safety", "CWE-120", "high"),
    ]


def test_copies_map_back_to_the_target_path(tmp_path):
    ctx = make_ctx(tmp_path)
    copies = tmp_path / "work" / "transcoded"
    doc = recorded(ctx)
    for result in doc["runs"][0]["results"]:
        artifact = result["locations"][0]["physicalLocation"]["artifactLocation"]
        artifact["uri"] = (copies / "native" / "labels.c").as_posix()
    doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = (
        "/somewhere/else.c"
    )
    rewritten, _below = rewrite_sarif(doc, target=ctx.target_dir, transcoded=copies)
    uris = {
        r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        for r in rewritten["runs"][0]["results"]
    }
    assert uris == {"native/labels.c"}  # the result outside both folders was dropped


def test_run_adapter_records_the_level_and_the_copies(tmp_path):
    ctx = make_ctx(tmp_path)
    rel = "native/labels.c"
    write(ctx.target_dir / rel, (FIXTURE / rel).read_text(encoding="utf-8"))
    write(ctx.target_dir / "src" / "old.c", b"/* caf\xe9 */\n" + COPY.encode())
    payload = json.dumps(recorded(ctx)).encode()

    def runner(argv, *, cwd, env, timeout, stdout, stderr):
        stdout.write(payload)
        return ProcessOutcome(0)

    def resolver(name, *, allow_path=False):
        return ResolvedTool(name, TOOL, "2.0.20", "kalkan")

    result = run_adapter(FlawfinderAdapter(), ctx, runner=runner, resolver=resolver)
    assert result.status == "ok", result.message
    assert result.candidates == 3
    status = json.loads((ctx.run_dir / "scans" / "flawfinder.status.json").read_text("utf-8"))
    assert status["min_level"] == 3 and status["below_min_level"] == 8
    assert status["transcoded_files"] == {"count": 1, "paths": ["src/old.c"]}
    assert not (ctx.run_dir / "scans" / ".work").exists()  # the copies are gone
    ignored, honored = FlawfinderAdapter().suppression_sources(ctx)
    assert "--neverignore" in ignored[0] and honored == []
