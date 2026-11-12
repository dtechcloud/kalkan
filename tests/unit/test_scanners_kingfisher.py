# SPDX-License-Identifier: MIT
"""Tests for the Kingfisher adapters (kalkan.scanners.adapters.kingfisher): command lines, the
history copy gate, the SARIF conversion of recorded Kingfisher 2.11.1 reports and the redaction
guarantees (no secret value, no Kingfisher fingerprint, no author in any kalkan file)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kalkan.errors import ToolError
from kalkan.sarif.ingest import ingest_document
from kalkan.scanners.adapters import _common
from kalkan.scanners.adapters.kingfisher import (
    REDACTED,
    KingfisherAdapter,
    KingfisherHistoryAdapter,
    json_to_sarif,
)
from kalkan.scanners.base import Invocation, ProcessOutcome, ScanContext, run_adapter
from kalkan.scanners.candidates import load_candidates
from kalkan.tools.resolve import ResolvedTool

TOOL = Path("/opt/kingfisher")
OUTPUTS = Path(__file__).resolve().parents[1] / "fixtures" / "scanner-outputs"
#: A made-up value that a broken Kingfisher could leave in its report.
FAKE_SECRET = "postgres://report:Zq9" + "Kw2Lm7Pt4Xb8Vn3@db.example.invalid/x"


def make_ctx(tmp_path: Path, *, source: Path | None = None, honor: bool = False) -> ScanContext:
    run = (tmp_path / "run").resolve()
    target = run / "target"
    target.mkdir(parents=True, exist_ok=True)
    return ScanContext(
        run_dir=run,
        target_dir=target,
        source_dir=source,
        tech=frozenset(),
        honor_suppressions=honor,
    )


def recorded(name: str, ctx: ScanContext) -> dict:
    """Return a recorded report with ``@TARGET@`` and ``@SOURCE@`` set to this run."""
    text = (OUTPUTS / name).read_text(encoding="utf-8")
    text = text.replace("@TARGET@", ctx.target_dir.as_posix())
    if ctx.source_dir is not None:
        text = text.replace("@SOURCE@", ctx.source_dir.as_posix())
    return json.loads(text)


def bare_mirror(run: Path) -> Path:
    source = run / "source"
    (source / "objects").mkdir(parents=True)
    (source / "refs").mkdir()
    (source / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    return source


def resolver(name, *, allow_path=False):
    return ResolvedTool(name, TOOL, "2.11.1", "kalkan")


# --------------------------------------------------------------------------------------------
# command lines


def test_tree_command_is_offline_redacted_and_ignores_inline_directives(tmp_path):
    ctx = make_ctx(tmp_path)
    out = ctx.run_dir / "scans" / ".work" / "kingfisher" / "kingfisher.sarif"
    argv = KingfisherAdapter().command(ctx, TOOL, out)
    assert argv == [
        str(TOOL),
        "scan",
        str(ctx.target_dir),
        "--no-update-check",
        "--quiet",
        "--no-validate",
        "--redact",
        "--no-ignore",
        "--confidence",
        "medium",
        "--no-rule-cache",
        "--git-history",
        "none",
        "--no-dedup",
        "--format",
        "json",
        "--output",
        str(out.with_suffix(".json")),
    ]
    honor = KingfisherAdapter().command(make_ctx(tmp_path, honor=True), TOOL, out)
    assert "--no-ignore" not in honor
    assert {"--no-validate", "--no-update-check", "--redact"} <= set(honor)
    assert KingfisherAdapter().ok_exit_codes == (0, 200)  # 205 (validated) fails the run


def test_history_command_reads_the_git_folder_of_the_copy(tmp_path):
    run = (tmp_path / "run").resolve()
    source = bare_mirror(run)
    ctx = make_ctx(tmp_path, source=source)
    out = ctx.run_dir / "scans" / ".work" / "kingfisher-history" / "kingfisher-history.sarif"
    adapter = KingfisherHistoryAdapter()
    assert adapter.applies(ctx) == (True, "")
    argv = adapter.command(ctx, TOOL, out)
    assert argv[:3] == [str(TOOL), "scan", str(source)]
    assert "--git-history" not in argv and "--no-dedup" not in argv
    assert {"--no-validate", "--no-update-check", "--redact", "--no-ignore"} <= set(argv)
    assert "--commit-metadata" not in argv  # without metadata Kingfisher names object files
    # A URL clone: the git folder of the work tree.
    clone = run / "clone"
    (clone / ".git").mkdir(parents=True)
    ctx = make_ctx(tmp_path, source=clone)
    assert adapter.scan_root(ctx) == clone / ".git"


def test_history_needs_no_git_on_path(tmp_path, monkeypatch):
    monkeypatch.setattr(_common, "executable_finder", lambda name: None)
    run = (tmp_path / "run").resolve()
    ctx = make_ctx(tmp_path, source=bare_mirror(run))
    assert KingfisherHistoryAdapter().applies(ctx) == (True, "")


def test_history_gates(tmp_path):
    adapter = KingfisherHistoryAdapter()
    ctx = make_ctx(tmp_path)
    manifest = {"history": {"status": "failed", "detail": "dubious ownership"}}
    (ctx.run_dir / "target-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    ok, reason = adapter.applies(ctx)
    assert ok is False and "dubious ownership" in reason
    outside = tmp_path / "elsewhere"
    (outside / ".git").mkdir(parents=True)
    assert adapter.applies(make_ctx(tmp_path, source=outside))[0] is False
    empty = (tmp_path / "run" / "source").resolve()
    empty.mkdir(parents=True)
    ok, reason = adapter.applies(make_ctx(tmp_path, source=empty))
    assert ok is False and "no git folder" in reason


def test_suppression_sources(tmp_path):
    ignored, honored = KingfisherAdapter().suppression_sources(make_ctx(tmp_path))
    assert any("--no-ignore" in item for item in ignored) and honored == []
    ignored, honored = KingfisherAdapter().suppression_sources(make_ctx(tmp_path, honor=True))
    assert ignored == [] and honored == ["kingfisher:ignore inline directives"]


# --------------------------------------------------------------------------------------------
# SARIF conversion of recorded reports


def test_tree_report_becomes_target_relative_redacted_sarif(tmp_path):
    ctx = make_ctx(tmp_path)
    report = recorded("kingfisher.json", ctx)
    doc = json_to_sarif(report, target=ctx.target_dir, history=False, version="2.11.1")
    run = doc["runs"][0]
    results = run["results"]
    assert [r["ruleId"] for r in results] == [
        "betterleaks.private-key",
        "betterleaks.generic-credential-uri",
    ]
    places = [r["locations"][0]["physicalLocation"] for r in results]
    assert [p["artifactLocation"]["uri"] for p in places] == [
        "config/deploy_key.pem",
        "config/settings.ini",
    ]
    assert [p["region"]["startLine"] for p in places] == [1, 24]
    assert places[1]["region"]["startColumn"] == 25  # 0-based 24 in the report
    assert {p["region"]["snippet"]["text"] for p in places} == {REDACTED}
    assert [r["level"] for r in results] == ["error", "warning"]  # high, medium confidence
    assert run["properties"]["update_check_status"] == "disabled"
    text = json.dumps(doc)
    assert "fingerprint" not in text and "[REDACTED:" not in text
    rules = {rule["id"]: rule for rule in run["tool"]["driver"]["rules"]}
    assert rules["betterleaks.generic-credential-uri"]["shortDescription"]["text"] == (
        "Generic credential URI"
    )
    candidates = ingest_document(doc, "kingfisher", ctx.target_dir, "scans/k.sarif").candidates
    assert [(c["class"], c["cwe"], c["file"]) for c in candidates] == [
        ("hardcoded-secrets", ["CWE-798"], "config/deploy_key.pem"),
        ("hardcoded-secrets", ["CWE-798"], "config/settings.ini"),
    ]
    assert [c["confidence"] for c in candidates] == ["high", "medium"]


def test_history_report_names_the_commit_but_no_author(tmp_path):
    run = (tmp_path / "run").resolve()
    ctx = make_ctx(tmp_path, source=bare_mirror(run))
    report = recorded("kingfisher-history.json", ctx)
    assert "test@example.com" in json.dumps(report)  # the raw report has the author
    doc = json_to_sarif(report, target=ctx.target_dir, history=True)
    [result] = doc["runs"][0]["results"]
    place = result["locations"][0]["physicalLocation"]
    assert place["artifactLocation"]["uri"] == "db.env"
    assert place["region"]["snippet"]["text"] == f"{REDACTED} (commit 708aef8b8ba9)"
    assert result["properties"]["commit"] == "708aef8b8ba92131a85c2cbd29389e9171102bda"
    text = json.dumps(doc)
    assert "test@example.com" not in text and "kalkan test" not in text


def test_an_unredacted_value_fails_the_conversion(tmp_path):
    ctx = make_ctx(tmp_path)
    report = recorded("kingfisher.json", ctx)
    report["findings"][1]["finding"]["snippet"] = FAKE_SECRET
    with pytest.raises(ToolError, match="not redacted"):
        json_to_sarif(report, target=ctx.target_dir, history=False)
    report = recorded("kingfisher.json", ctx)
    report["findings"][0]["finding"]["validation"]["response"] = "200 OK: {user: admin}"
    with pytest.raises(ToolError, match="not redacted"):
        json_to_sarif(report, target=ctx.target_dir, history=False)


def test_findings_outside_the_target_or_with_unsafe_paths_are_skipped(tmp_path):
    ctx = make_ctx(tmp_path)
    report = recorded("kingfisher.json", ctx)
    report["findings"][0]["finding"]["path"] = str(tmp_path / "other" / "x.pem")
    doc = json_to_sarif(report, target=ctx.target_dir, history=False)
    assert len(doc["runs"][0]["results"]) == 1
    assert doc["runs"][0]["properties"]["skipped_findings"] == 1
    history = recorded("kingfisher.json", ctx)
    history["findings"][0]["finding"]["path"] = "../escape.env"
    history["findings"][1]["finding"]["path"] = "C:/abs.env"
    doc = json_to_sarif(history, target=ctx.target_dir, history=True)
    assert doc["runs"][0]["results"] == []


def test_not_a_kingfisher_report_raises():
    with pytest.raises(ToolError):
        json_to_sarif({"results": []}, target=Path("."), history=False)


# --------------------------------------------------------------------------------------------
# run_adapter: the report is deleted, no value reaches a kalkan file


def _runner(report: dict, exit_code: int = 200):
    def runner(argv, *, cwd, env, timeout, stdout, stderr):
        Path(argv[argv.index("--output") + 1]).write_text(json.dumps(report), encoding="utf-8")
        return ProcessOutcome(exit_code)

    return runner


def _files_text(folder: Path) -> str:
    return "\n".join(
        path.read_text(encoding="utf-8", errors="replace")
        for path in folder.rglob("*")
        if path.is_file()
    )


def test_run_writes_candidates_and_deletes_the_report(tmp_path):
    ctx = make_ctx(tmp_path)
    report = recorded("kingfisher.json", ctx)
    result = run_adapter(KingfisherAdapter(), ctx, runner=_runner(report), resolver=resolver)
    assert result.status == "ok", result.message
    assert result.candidates == 2
    assert not (ctx.run_dir / "scans" / ".work").exists()
    status = json.loads((ctx.run_dir / "scans" / "kingfisher.status.json").read_text("utf-8"))
    assert status["update_check"] == "disabled"
    assert status["scan_summary"]["rules_applied"] == 488
    assert status["redaction"].startswith("values redacted")
    candidates = load_candidates(ctx.run_dir)["candidates"]
    assert {c["snippet"] for c in candidates} == {REDACTED}


def test_an_unredacted_report_fails_and_leaves_no_value_behind(tmp_path):
    ctx = make_ctx(tmp_path)
    report = recorded("kingfisher.json", ctx)
    report["findings"][1]["finding"]["snippet"] = FAKE_SECRET
    result = run_adapter(KingfisherAdapter(), ctx, runner=_runner(report), resolver=resolver)
    assert result.status == "failed" and "not redacted" in result.message
    assert FAKE_SECRET not in _files_text(ctx.run_dir)  # the report was deleted


def test_a_failed_run_deletes_the_report(tmp_path):
    ctx = make_ctx(tmp_path)
    report = recorded("kingfisher.json", ctx)
    report["findings"][1]["finding"]["snippet"] = FAKE_SECRET
    result = run_adapter(
        KingfisherAdapter(), ctx, runner=_runner(report, exit_code=1), resolver=resolver
    )
    assert result.status == "failed" and "exit code 1" in result.message
    assert list((ctx.run_dir / "scans" / ".work" / "kingfisher").glob("*.json")) == []
    assert FAKE_SECRET not in _files_text(ctx.run_dir)


def test_after_run_needs_the_report(tmp_path):
    ctx = make_ctx(tmp_path)
    out = ctx.run_dir / "scans" / ".work" / "kingfisher" / "kingfisher.sarif"
    out.parent.mkdir(parents=True)
    item = Invocation(("kingfisher",), ctx.run_dir / "scans", out)
    with pytest.raises(ToolError, match="no Kingfisher report"):
        KingfisherAdapter().after_run(ctx, item)
