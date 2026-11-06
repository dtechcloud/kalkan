# SPDX-License-Identifier: MIT
"""Tests for kalkan.scanners.candidates: merge_candidates and load_candidates."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kalkan.errors import StateError
from kalkan.findings.fingerprint import candidate_id
from kalkan.scanners import candidates as mod
from kalkan.scanners.candidates import load_candidates, merge_candidates


def cand(
    engine: str, line: int, *, file: str = "app.py", rule: str = "R1", title: str = "t"
) -> dict:
    return {
        "id": candidate_id(engine, rule, file, line, "x"),
        "engine": engine,
        "rule_id": rule,
        "class": None,
        "cwe": [],
        "title": title,
        "message": "m",
        "file": file,
        "start_line": line,
        "end_line": line,
        "snippet": "x",
        "severity": "low",
        "tool_severity": "",
        "confidence": None,
        "tags": [],
        "fingerprints": {},
        "sca": None,
        "raw": {"sarif_file": "", "run_index": 0, "result_index": 0},
    }


@pytest.fixture
def run(tmp_path: Path) -> Path:
    folder = tmp_path / "run"
    folder.mkdir()
    return folder


def test_load_missing_file_gives_empty_document(run):
    assert load_candidates(run) == {
        "schema_version": 1,
        "candidates": [],
        "warnings": [],
        "sources": {},
    }


def test_merge_writes_document_and_returns_count(run):
    count = merge_candidates(run, "trivy", [cand("trivy", 1), cand("trivy", 2)], ["note"])
    assert count == 2
    doc = json.loads((run / "candidates.json").read_text(encoding="utf-8"))
    assert doc["schema_version"] == 1
    assert len(doc["candidates"]) == 2
    assert doc["warnings"] == ["trivy: note"]
    assert doc["sources"]["trivy"]["count"] == 2
    assert doc["sources"]["trivy"]["updated_at"].endswith("Z")
    assert all("source" not in item for item in doc["candidates"])
    assert not (run / "run.lock").exists()


def test_merge_replaces_earlier_results_of_the_same_source(run):
    merge_candidates(run, "trivy", [cand("trivy", 1), cand("trivy", 2)], ["old"])
    merge_candidates(run, "bandit", [cand("bandit", 5)], [])
    merge_candidates(run, "trivy", [cand("trivy", 3)], ["new"])
    doc = load_candidates(run)
    lines = sorted((c["engine"], c["start_line"]) for c in doc["candidates"])
    assert lines == [("bandit", 5), ("trivy", 3)]
    assert doc["warnings"] == ["trivy: new"]
    assert doc["sources"]["trivy"]["count"] == 1


def test_merge_deduplicates_by_id(run):
    first = cand("trivy", 1)
    count = merge_candidates(run, "trivy", [first, dict(first), cand("trivy", 2)], [])
    assert count == 2
    assert len(load_candidates(run)["candidates"]) == 2


def test_shared_id_stays_while_another_source_reports_it(run):
    shared = cand("matcher", 1)
    merge_candidates(run, "matcher", [shared], [])
    merge_candidates(run, "sca", [shared, cand("matcher", 9)], [])
    merge_candidates(run, "matcher", [], [])
    ids = {c["id"] for c in load_candidates(run)["candidates"]}
    assert shared["id"] in ids
    merge_candidates(run, "sca", [], [])
    assert load_candidates(run)["candidates"] == []


def test_newest_record_of_an_id_wins(run):
    merge_candidates(run, "trivy", [cand("trivy", 1, title="old")], [])
    merge_candidates(run, "trivy", [cand("trivy", 1, title="new")], [])
    assert load_candidates(run)["candidates"][0]["title"] == "new"


def test_candidates_are_sorted(run):
    merge_candidates(
        run,
        "trivy",
        [
            cand("trivy", 9, file="b.py"),
            cand("trivy", 2, file="b.py"),
            cand("trivy", 7, file="a.py"),
        ],
        [],
    )
    merge_candidates(run, "bandit", [cand("bandit", 1, file="z.py")], [])
    order = [(c["engine"], c["file"], c["start_line"]) for c in load_candidates(run)["candidates"]]
    assert order == [
        ("bandit", "z.py", 1),
        ("trivy", "a.py", 7),
        ("trivy", "b.py", 2),
        ("trivy", "b.py", 9),
    ]


def test_record_without_valid_id_is_skipped_with_warning(run):
    bad = cand("trivy", 1)
    bad["id"] = "CAND-lowercase"
    count = merge_candidates(run, "trivy", [bad, "nope", cand("trivy", 2)], [])  # type: ignore[list-item]
    assert count == 1
    assert load_candidates(run)["warnings"] == [
        "trivy: 2 record(s) without a valid candidate ID skipped"
    ]


def test_warnings_are_capped_per_source(run, monkeypatch):
    monkeypatch.setattr(mod, "MAX_WARNINGS_PER_SOURCE", 3)
    merge_candidates(run, "trivy", [], [f"w{i}" for i in range(10)])
    assert load_candidates(run)["warnings"] == [
        "trivy: w0",
        "trivy: w1",
        "trivy: 8 more warning(s) not recorded",
    ]


def test_invalid_source_name_is_rejected(run):
    with pytest.raises(ValueError):
        merge_candidates(run, "Bad Name", [], [])


def test_missing_run_folder_is_rejected(tmp_path):
    with pytest.raises(StateError):
        merge_candidates(tmp_path / "missing", "trivy", [], [])


def test_corrupt_file_raises_state_error(run):
    (run / "candidates.json").write_text("{broken", encoding="utf-8")
    with pytest.raises(StateError, match="not valid JSON"):
        merge_candidates(run, "trivy", [cand("trivy", 1)], [])
    (run / "candidates.json").write_text('{"candidates": 5}', encoding="utf-8")
    with pytest.raises(StateError, match="not a candidates document"):
        load_candidates(run)


def test_unowned_candidates_are_kept(run):
    legacy = cand("checkov", 4)
    (run / "candidates.json").write_text(
        json.dumps({"schema_version": 1, "candidates": [legacy], "warnings": []}), encoding="utf-8"
    )
    merge_candidates(run, "trivy", [cand("trivy", 1)], [])
    ids = {c["id"] for c in load_candidates(run)["candidates"]}
    assert legacy["id"] in ids


def test_merge_holds_the_run_lock_while_writing(run, monkeypatch):
    import contextlib

    import kalkan.run.lock as lock

    events: list[str] = []
    real_write = mod.atomic_write_json

    @contextlib.contextmanager
    def recording_lock(run_dir, timeout_seconds=30.0):
        events.append("lock")
        yield
        events.append("unlock")

    def recording_write(path, obj):
        events.append("write")
        real_write(path, obj)

    monkeypatch.setattr(lock, "run_lock", recording_lock)
    monkeypatch.setattr(mod, "atomic_write_json", recording_write)
    merge_candidates(run, "trivy", [cand("trivy", 1)], [])
    assert events == ["lock", "write", "unlock"]


def test_busy_lock_gives_state_error(run, monkeypatch):
    import contextlib

    import kalkan.run.lock as lock

    @contextlib.contextmanager
    def busy(run_dir, timeout_seconds=30.0):
        raise StateError("the run is locked by another kalkan process")
        yield  # pragma: no cover

    monkeypatch.setattr(lock, "run_lock", busy)
    with pytest.raises(StateError, match="locked"):
        merge_candidates(run, "trivy", [cand("trivy", 1)], [])
    assert not (run / "candidates.json").exists()
