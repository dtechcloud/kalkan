# SPDX-License-Identifier: MIT
"""Unit tests for the comparison of runs (kalkan.report.compare, ``kalkan run compare``)."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from kalkan.cli import main
from kalkan.findings.merge import merge_run
from kalkan.report.compare import compare_models, format_comparison
from kalkan.report.model import ReportModel

GOLDEN = Path(__file__).resolve().parents[1] / "golden" / "report"
RUN_ID = "20261015T120000Z-shop-a1b2"


def finding(
    number, *, verdict="confirmed", severity="high", cls="sqli", file="app/db.py", line=10, fp=None
):
    record = {
        "verdict": verdict,
        "id": f"KF-{number:016X}",
        "fingerprint": fp or f"fp-{number}",
        "title": f"Finding {number}",
        "class": cls,
        "trace": [{"kind": "sink", "file": file, "line": line}],
        "evidence": [],
        "severity": {
            "likelihood": {"score": "medium", "reason": "r"},
            "impact": {"score": severity, "reason": "r"},
            "overall_severity": severity,
        },
    }
    return record


def model(run_id, *findings):
    m = ReportModel(
        run_id=run_id, run_lang="en", generated_at="x", kalkan_version="t", findings_available=True
    )
    for item in findings:
        {"confirmed": m.confirmed, "needs_validation": m.needs_validation, "rejected": m.rejected}[
            item["verdict"]
        ].append(item)
    m.profile = "fast"
    return m


def test_matching_by_fingerprint_and_by_nearby_line():
    a = model("A", finding(1, fp="same"), finding(2, cls="xss", file="web/x.js", line=40))
    b = model(
        "B",
        finding(9, fp="same", line=99),  # same fingerprint, other line
        finding(8, cls="xss", file="web/x.js", line=47),  # 7 lines apart: same issue
        finding(7, cls="ssrf", file="net.py", line=1),  # only in B
    )
    result = compare_models([a, b])
    assert result["open_issues"] == 3 and result["open_in_all_runs"] == 2
    assert result["stability"] == round(2 / 3, 3)
    assert result["verdict_changes"] == 0


def test_far_lines_and_other_classes_are_different_issues():
    a = model("A", finding(1, line=10))
    b = model("B", finding(2, line=40), finding(3, cls="xss", line=10))
    result = compare_models([a, b])
    assert result["open_issues"] == 3 and result["open_in_all_runs"] == 0


def test_verdict_and_severity_changes_are_counted():
    a = model("A", finding(1, fp="f", severity="high"), finding(2, fp="g"))
    b = model(
        "B",
        finding(3, fp="f", severity="medium"),
        finding(4, fp="g", verdict="rejected"),
    )
    c = model("C", finding(5, fp="f", severity="high"))
    result = compare_models([a, b, c])
    assert result["severity_changes"] == 1 and result["verdict_changes"] == 1
    text = format_comparison(result)
    assert "C:high | C:medium | C:high" in text and "*" in text


def test_run_compare_on_the_command_line(tmp_path, monkeypatch, capsys):
    runs = tmp_path / "runs"
    for suffix in ("a1b2", "c3d4"):
        target = runs / f"20261015T120000Z-shop-{suffix}"
        shutil.copytree(GOLDEN / "run" / RUN_ID, target)
        state = json.loads((target / "state.json").read_text(encoding="utf-8"))
        state["run_id"] = target.name
        (target / "state.json").write_text(json.dumps(state), encoding="utf-8")
        merge_run(target)
    monkeypatch.setenv("KALKAN_RUNS_DIR", str(runs))
    code = main(
        ["run", "compare", "20261015T120000Z-shop-a1b2", "20261015T120000Z-shop-c3d4", "--json"]
    )
    assert code == 0
    result = json.loads(capsys.readouterr().out)
    assert result["stability"] == 1.0 and len(result["runs"]) == 2
    assert main(["run", "compare", "20261015T120000Z-shop-a1b2"]) != 0
    capsys.readouterr()
