# SPDX-License-Identifier: MIT
"""Tests for task inputs (kalkan.run.inputs) and the recon merge (kalkan.run.recon_merge)."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from kalkan.run import ids, inputs, queue, state
from kalkan.run import init as init_mod
from kalkan.run.init import init_run
from kalkan.run.recon_merge import merge_recon
from kalkan.run.runfiles import load_classes, load_surfaces, write_json

TARGETS = Path(__file__).resolve().parents[1] / "fixtures" / "targets"
SAMPLES = Path(__file__).resolve().parents[1] / "fixtures" / "task-results"


@pytest.fixture
def ctx(tmp_path, monkeypatch):
    monkeypatch.setenv(ids.RUNS_DIR_ENV, str(tmp_path / "runs"))
    monkeypatch.setattr(init_mod, "git_head", lambda directory: None)
    target = tmp_path / "webapp"
    shutil.copytree(TARGETS / "webapp", target)
    (target / ".github" / "workflows").mkdir(parents=True)
    (target / ".github" / "workflows" / "ci.yml").write_text("on: push\n", encoding="utf-8")
    return init_run(str(target), runs_dir=tmp_path / "runs")


def test_file_inventory(ctx):
    inventory = inputs.file_inventory(ctx.target_dir)
    assert inventory["total_files"] == 6
    names = {item["name"]: item for item in inventory["top_level"]}
    assert names["app"] == {"name": "app", "kind": "dir", "files": 2}
    assert names["Dockerfile"]["kind"] == "file"
    assert inventory["extensions"][".py"] == 2
    assert inventory["manifests"] == [".github/workflows/ci.yml", "Dockerfile", "requirements.txt"]
    assert inventory["truncated"] is False


def test_summaries_and_hints():
    candidates = [
        {
            "id": "C1",
            "engine": "bandit",
            "class": "sqli",
            "severity": "high",
            "file": "a/x.py",
            "start_line": 3,
            "title": "t",
            "rule_id": "B608",
        },
        {
            "id": "C2",
            "engine": "matcher",
            "class": None,
            "severity": "info",
            "file": "a/y.py",
            "start_line": 1,
            "title": "t",
            "rule_id": "m",
        },
        {
            "id": "C3",
            "engine": "osv-scanner",
            "class": "vulnerable-dependency",
            "severity": "critical",
            "file": "a/requirements.txt",
            "start_line": 1,
            "title": "t",
            "rule_id": "GHSA",
        },
    ]
    summary = inputs.deterministic_summary(candidates)
    assert summary["total"] == 3
    assert summary["by_severity"] == {"critical": 1, "high": 1, "info": 1}
    assert summary["by_class"]["unclassified"] == 1
    hints = inputs.tool_hints(candidates, ["a"])
    assert [hint["engine"] for hint in hints] == ["bandit", "matcher"]
    assert inputs.tool_hints(candidates, ["a/x.py"])[0]["line"] == 3
    assert inputs.tool_hints(candidates, []) == []
    sca = inputs.sca_summary([{"severity": "high", "package": "p"}, {"severity": "low"}])
    assert sca["by_severity"] == {"high": 1, "low": 1}
    assert sca["top"][0]["package"] == "p"


def test_translate_input():
    findings = [
        {
            "id": "KF-1",
            "verdict": "confirmed",
            "title": "t",
            "description": "d",
            "remediation": {"strategy": "s"},
        },
        {
            "id": "KF-2",
            "verdict": "needs_validation",
            "title": "t",
            "description": "d",
            "validation_plan": {"deployment": "p"},
        },
        {"id": "KF-3", "verdict": "rejected", "title": "t", "description": "d", "reason": "r"},
    ]
    items = inputs.translate_input(findings)["findings"]
    assert [item["remediation_strategy"] for item in items] == ["s", "p", "r"]


def test_recon_input(ctx):
    data = inputs.recon_input(ctx, "surfaces")
    assert data["kind"] == "surfaces"
    assert data["tech"] == ["docker", "flask", "github-actions", "python"]
    assert data["deterministic"]["total"] == 0 and data["sca"]["total"] == 0
    assert len(json.dumps(data, indent=2).splitlines()) < 400


def recon_result(task_id, kind, surfaces, classes):
    data = json.loads((SAMPLES / "recon.json").read_text(encoding="utf-8"))
    data.update(task_id=task_id, kind=kind, surfaces=surfaces, classes_of_interest=classes)
    return data


def test_merge_recon(ctx):
    with state.transaction(ctx) as tx:
        tx.state["phase"] = "recon"
    base = json.loads((SAMPLES / "recon.json").read_text(encoding="utf-8"))["surfaces"]
    unsafe = dict(base[0], id="bad", file="../outside.py")
    pipe = dict(base[0], id="pipe", name="GET | /a", line=11)
    results = {
        "surfaces": (base + [unsafe, pipe], ["sqli", "idor"]),
        "product": ([dict(base[0], id="again")], ["ssrf"]),
        "principals": ([], []),
    }
    for kind, (surfaces, classes) in results.items():
        task_id = queue.create_task(ctx, "recon", "recon", {"kind": kind})
        (ctx.task_dir(task_id) / "result.json").write_text(
            json.dumps(recon_result(task_id, kind, surfaces, classes)), encoding="utf-8"
        )
        queue.claim(ctx, "t", 5)
        queue.complete(ctx, task_id)
    write_json(
        ctx.run_dir / "candidates.json",
        {
            "candidates": [
                {"id": "CAND-1", "class": "crypto", "severity": "medium", "file": "a"},
                {"id": "CAND-2", "class": "xss", "severity": "low", "file": "a"},
                {"id": "CAND-3", "class": "vulnerable-dependency", "severity": "high", "file": "a"},
            ]
        },
    )
    summary = merge_recon(ctx.reload() and ctx)
    assert summary == {"results": 3, "surfaces": 3, "dropped": 1, "classes": 4}
    surfaces = load_surfaces(ctx)
    assert [surface["id"] for surface in surfaces] == ["S001", "S002", "S003"]
    assert surfaces[0]["sources"] == ["T0002-recon:again", "T0001-recon:http-users"]
    document = json.loads((ctx.run_dir / "recon" / "surfaces.json").read_text("utf-8"))
    assert document["id_map"]["T0001-recon:http-users"] == "S001"
    assert load_classes(ctx) == ["crypto", "idor", "sqli", "ssrf"]
    architecture = (ctx.run_dir / "recon" / "architecture.md").read_text("utf-8")
    assert architecture.index("## Product") < architecture.index("## Principals")
    assert "(No result for this part of the reconnaissance.)" in architecture  # execution
    assert "GET \\| /a" in architecture
    assert len(architecture.split()) < 1600
    # The same results give the same files.
    before = (ctx.run_dir / "recon" / "surfaces.json").read_bytes()
    merge_recon(ctx)
    assert (ctx.run_dir / "recon" / "surfaces.json").read_bytes() == before
