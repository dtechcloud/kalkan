# SPDX-License-Identifier: MIT
"""Tests for ``kalkan run clean <run-id>`` (kalkan.run.clean)."""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

from kalkan.cli import main
from kalkan.run import events, ids, state
from kalkan.run import init as init_mod
from kalkan.run.clean import CLEANED_NAME, clean_run, read_cleaned

TARGETS = Path(__file__).resolve().parents[1] / "fixtures" / "targets"


@pytest.fixture
def runs(tmp_path, monkeypatch):
    root = tmp_path / "runs"
    monkeypatch.setenv(ids.RUNS_DIR_ENV, str(root))
    monkeypatch.setattr(init_mod, "git_head", lambda directory: None)
    return root


def cli(capsys, *argv):
    code = main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def make_run(tmp_path: Path, runs: Path, *, phase: str = "done") -> Path:
    """A run made by ``run init`` with the parts of a finished run."""
    target = tmp_path / "webapp"
    if not target.exists():
        shutil.copytree(TARGETS / "webapp", target)
    ctx = init_mod.init_run(str(target), runs_dir=runs, update_latest=False)
    run = ctx.run_dir
    with state.transaction(ctx) as tx:
        tx.state["phase"] = phase
    for name, text in {
        "source/HEAD": "ref: refs/heads/main\n",
        "source/objects/pack/pack-1.pack": "P" * 4000,
        "scans/.work/opengrep/tmp/semgrep-x.rules": "rules",
        "scans/.work/opengrep/opengrep.log": "/target/app.py:3 os.system(cmd)",
        "scans/opengrep.sarif": '{"version": "2.1.0", "runs": []}',
        "scans/opengrep.status.json": "{}",
        "sca/.work/govulncheck/go-cache/ab/abcdef-d": "C" * 3000,
        "sca/vulns.json": "{}",
        "candidates.json": "{}",
        "tasks/T0001-recon/result.json": "{}",
        "findings.json": "[]",
        "report/REPORT.md": "# Rapor\n",
        "report/REPORT.html": "<html></html>",
    }.items():
        path = run / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return run


KEPT = (
    "state.json",
    "events.jsonl",
    "target-manifest.json",
    "scans/opengrep.sarif",
    "scans/opengrep.status.json",
    "sca/vulns.json",
    "candidates.json",
    "tasks/T0001-recon/result.json",
    "findings.json",
    "report/REPORT.md",
    "report/REPORT.html",
)


def test_a_finished_run_loses_its_bulky_parts_and_keeps_the_deliverables(tmp_path, runs, capsys):
    run = make_run(tmp_path, runs)
    target_files = sum(1 for path in (run / "target").rglob("*") if path.is_file())
    code, out, err = cli(capsys, "run", "clean", run.name, "--json")
    assert code == 0, err
    result = json.loads(out)
    assert result["finished"] is True and result["dry_run"] is False
    parts = {part["path"]: part for part in result["parts"]}
    assert set(parts) == {"target", "source", "scans/.work", "sca/.work"}
    assert parts["target"]["files"] == target_files and parts["source"]["files"] == 2
    assert parts["sca/.work"]["bytes"] == 3000
    assert result["total"]["files"] == target_files + 5 and result["errors"] == []
    for name in ("target", "source", "scans/.work", "sca/.work"):
        assert not (run / name).exists(), name
    for name in KEPT:
        assert (run / name).is_file(), name
    record = read_cleaned(run)
    assert record["files"] == target_files + 5 and record["forced"] is False
    assert [part["path"] for part in record["parts"]] == list(parts)
    [event] = [item for item in events.read_events(run) if item["kind"] == "run_cleaned"]
    assert event["files"] == target_files + 5
    # A second clean finds nothing more to delete and keeps the record of the first one.
    again = clean_run(run)
    assert again.total.files == 0 and all(not part.present for part in again.parts)
    assert read_cleaned(run) == record


def test_the_dry_run_measures_and_deletes_nothing(tmp_path, runs, capsys):
    run = make_run(tmp_path, runs)
    before = sorted(path.relative_to(run).as_posix() for path in run.rglob("*"))
    code, out, err = cli(capsys, "run", "clean", run.name, "--dry-run")
    assert code == 0, err
    assert out.startswith(f"Run {run.name} (phase done): would delete ")
    assert "target/" in out and "source/" in out and "scans/.work/" in out
    assert "Kept: report/" in out
    assert sorted(path.relative_to(run).as_posix() for path in run.rglob("*")) == before
    assert not (run / CLEANED_NAME).exists()


def test_a_run_that_is_not_finished_needs_force(tmp_path, runs, capsys):
    run = make_run(tmp_path, runs, phase="hunt")
    code, out, err = cli(capsys, "run", "clean", run.name)
    assert code == 1 and "not finished (in the phase hunt)" in err and "--force" in err
    assert (run / "target").is_dir()
    code, out, err = cli(capsys, "run", "clean", run.name, "--force", "--json")
    assert code == 0, err
    assert json.loads(out)["forced"] is True and not (run / "target").exists()
    assert read_cleaned(run)["forced"] is True


def test_a_cleaned_run_cannot_run_again(tmp_path, runs, capsys):
    run = make_run(tmp_path, runs)
    assert cli(capsys, "run", "clean", run.name)[0] == 0
    for argv in (
        ("run", "next"),
        ("run", "step"),
        ("run", "resume"),
        ("run", "reopen", "--step", "polish"),
        ("run", "answer", "english_report", "yes"),
    ):
        code, out, err = cli(capsys, *argv, "--run", run.name)
        assert code == 1, argv
        assert "the run was cleaned at" in err and argv[1] in err, argv
    code, out, err = cli(capsys, "run", "status", "--run", run.name, "--json")
    assert code == 0 and json.loads(out)["phase"] == "done"


def make_junction(link: Path, target: Path) -> None:
    if os.name == "nt":
        import _winapi

        _winapi.CreateJunction(str(target), str(link))
    else:
        os.symlink(target, link, target_is_directory=True)


def test_links_inside_the_target_copy_are_removed_as_links(tmp_path, runs):
    run = make_run(tmp_path, runs)
    outside = tmp_path / "outside"
    (outside / "deep").mkdir(parents=True)
    (outside / "deep" / "keep.txt").write_text("keep me", encoding="utf-8")
    make_junction(run / "target" / "escape", outside)
    if os.name != "nt":
        os.symlink(outside / "deep" / "keep.txt", run / "target" / "file-link")
    result = clean_run(run)
    assert result.errors == []
    assert not (run / "target").exists()
    assert (outside / "deep" / "keep.txt").read_text(encoding="utf-8") == "keep me"
    target = next(part for part in result.parts if part.path == "target")
    assert target.stats.links >= 1


def test_a_parent_folder_that_links_out_of_the_run_is_skipped(tmp_path, runs):
    run = make_run(tmp_path, runs)
    elsewhere = tmp_path / "elsewhere"
    shutil.move(str(run / "scans"), str(elsewhere))
    make_junction(run / "scans", elsewhere)
    result = clean_run(run)
    part = next(part for part in result.parts if part.path == "scans/.work")
    assert part.skipped == "its parent folder is a link out of the run"
    assert (elsewhere / ".work" / "opengrep" / "opengrep.log").is_file()
    assert not (run / "target").exists()


def test_read_only_files_long_paths_and_unicode_names_are_removed(tmp_path, runs):
    run = make_run(tmp_path, runs)
    deep = run / "target" / "çalışma-ğüşİö"
    while len(str(deep)) < 280:
        deep = deep / ("klasör-" + "x" * 30)
    long_file = deep / "dosya-ı.txt"
    if os.name == "nt":
        os.makedirs("\\\\?\\" + str(deep))
        with open("\\\\?\\" + str(long_file), "w", encoding="utf-8") as handle:
            handle.write("uzun")
    else:
        deep.mkdir(parents=True)
        long_file.write_text("uzun", encoding="utf-8")
    locked = run / "source" / "objects" / "pack" / "pack-1.pack"
    os.chmod(locked, stat.S_IREAD)  # git marks its pack files read-only on Windows
    result = clean_run(run)
    assert result.errors == []
    assert not (run / "target").exists() and not (run / "source").exists()


def test_an_invalid_run_id_is_refused(runs, capsys):
    code, out, err = cli(capsys, "run", "clean", "../escape")
    assert code == 1 and "invalid run ID" in err


@pytest.mark.skipif(os.name != "nt", reason="junctions are a Windows feature")
def test_a_junction_made_by_mklink_survives_with_its_target(tmp_path, runs):
    run = make_run(tmp_path, runs)
    outside = tmp_path / "outside2"
    outside.mkdir()
    (outside / "keep.txt").write_text("keep", encoding="utf-8")
    link = run / "target" / "mklink-junction"
    subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(link), str(outside)],
        check=True,
        capture_output=True,
    )
    clean_run(run)
    assert (outside / "keep.txt").is_file() and not link.exists()
