# SPDX-License-Identifier: MIT
"""Tests for `kalkan verify`, `kalkan ledger validate` and the safe source reader."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest

from kalkan.cli import EXIT_USAGE, EXIT_VALIDATION, main
from kalkan.run.source import make_get_lines

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"

DB_PY = (
    "import sqlite3\n\n\n"
    "def find_user(cur, user_id):\n"
    "    # look up one user\n\n\n"
    '    cur.execute(f"SELECT * FROM users WHERE id = {user_id}")\n'
)
ROUTES_PY = (
    "from flask import request\n\n\n\n\n\n\n\n\n"
    "@login_required\n"
    "def get_user():\n"
    '    user_id = request.args.get("id")\n'
)


@pytest.fixture
def target(tmp_path: Path) -> Path:
    root = tmp_path / "target"
    (root / "app").mkdir(parents=True)
    (root / "app" / "db.py").write_text(DB_PY, encoding="utf-8", newline="\n")
    (root / "app" / "routes.py").write_text(ROUTES_PY, encoding="utf-8", newline="\n")
    return root


def _write(path: Path, data: object) -> Path:
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_get_lines_reads_safe_paths(target: Path):
    get_lines = make_get_lines(target)
    lines = get_lines("app/db.py")
    assert lines is not None and lines[7].startswith("    cur.execute")
    assert get_lines("./app/db.py") == lines


@pytest.mark.parametrize("bad", ["../outside.py", "/etc/passwd", "C:/x.py", "app/../app/db.py", ""])
def test_get_lines_rejects_unsafe_paths(target: Path, bad: str):
    (target.parent / "outside.py").write_text("x = 1\n", encoding="utf-8")
    assert make_get_lines(target)(bad) is None


def test_get_lines_missing_file(target: Path):
    assert make_get_lines(target)("app/none.py") is None


def test_get_lines_refuses_symlink(target: Path):
    link = target / "app" / "link.py"
    try:
        os.symlink(target / "app" / "db.py", link)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available")
    assert make_get_lines(target)("app/link.py") is None


def test_verify_task_result_confirmed(target: Path, tmp_path: Path, capsys):
    sample = json.loads((FIXTURES / "task-results" / "verify.json").read_text(encoding="utf-8"))
    result = _write(tmp_path / "result.json", sample)
    assert main(["verify", str(result), "--target", str(target), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["verdict"] == "confirmed"
    assert payload["downgrades"] == {}


def test_verify_task_result_with_bad_quote_needs_validation(target: Path, tmp_path: Path, capsys):
    sample = json.loads((FIXTURES / "task-results" / "verify.json").read_text(encoding="utf-8"))
    sample["audit_answers"]["unmitigated"]["evidence"][0]["quote"] = "cur.execute(safe_query)"
    result = _write(tmp_path / "result.json", sample)
    assert main(["verify", str(result), "--target", str(target), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["verdict"] == "needs_validation"
    assert payload["downgrades"] == {"unmitigated": "unverified_evidence"}


def test_verify_task_result_schema_error(target: Path, tmp_path: Path, capsys):
    sample = json.loads((FIXTURES / "task-results" / "verify.json").read_text(encoding="utf-8"))
    del sample["finding"]
    result = _write(tmp_path / "result.json", sample)
    assert main(["verify", str(result), "--target", str(target)]) == EXIT_VALIDATION
    err = capsys.readouterr().err
    assert "ERROR:" in err and "FAIL: " in err


def test_verify_findings_document(tmp_path: Path, capsys):
    findings = [
        json.loads((FIXTURES / "findings" / name).read_text(encoding="utf-8"))
        for name in ("confirmed.json", "needs_validation.json", "rejected.json")
    ]
    flat = [item for doc in findings for item in (doc if isinstance(doc, list) else [doc])]
    path = _write(tmp_path / "findings.json", flat)
    assert main(["verify", str(path)]) == 0
    assert "PASS" in capsys.readouterr().err


def test_verify_findings_document_invalid(tmp_path: Path, capsys):
    path = _write(tmp_path / "findings.json", [{"verdict": "confirmed"}])
    assert main(["verify", str(path), "--json"]) == EXIT_VALIDATION
    payload = json.loads(capsys.readouterr().out)
    assert payload["valid"] is False and payload["errors"]


def test_verify_unknown_document(tmp_path: Path):
    path = _write(tmp_path / "other.json", {"hello": 1})
    assert main(["verify", str(path)]) == EXIT_VALIDATION


def test_ledger_validate_file(tmp_path: Path, capsys):
    unit = json.loads((FIXTURES / "ledger" / "unit.json").read_text(encoding="utf-8"))
    ledger = unit if isinstance(unit, list) else [unit]
    path = _write(tmp_path / "coverage-ledger.json", ledger)
    assert main(["ledger", "validate", str(path)]) == 0
    assert "PASS" in capsys.readouterr().err


def test_ledger_validate_invalid(tmp_path: Path, capsys):
    path = _write(tmp_path / "coverage-ledger.json", [{"coverage_id": "x"}])
    assert main(["ledger", "validate", str(path), "--json"]) == EXIT_VALIDATION
    assert json.loads(capsys.readouterr().out)["valid"] is False


def test_ledger_group_without_subcommand():
    assert main(["ledger"]) == EXIT_USAGE


def test_ledger_validate_run_default(tmp_path: Path, monkeypatch, capsys):
    pytest.importorskip("kalkan.run.ids")
    from kalkan.run.ids import new_run_id, write_latest

    runs = tmp_path / "runs"
    monkeypatch.setenv("KALKAN_RUNS_DIR", str(runs))
    run_id = new_run_id("demo")
    run_dir = runs / run_id
    run_dir.mkdir(parents=True)
    unit = json.loads((FIXTURES / "ledger" / "unit.json").read_text(encoding="utf-8"))
    _write(run_dir / "coverage-ledger.json", unit if isinstance(unit, list) else [unit])
    write_latest(run_id, runs)
    shutil.rmtree(tmp_path / "unused", ignore_errors=True)
    assert main(["ledger", "validate"]) == 0
