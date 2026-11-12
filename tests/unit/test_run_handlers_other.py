# SPDX-License-Identifier: MIT
"""Tests for the recon, translate, sca_reach and poc_build handlers."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from kalkan.errors import ValidationError
from kalkan.run import handlers, ids, queue, state
from kalkan.run import init as init_mod
from kalkan.run.handlers import poc_build, recon, sca_reach, translate
from kalkan.run.init import init_run

TARGETS = Path(__file__).resolve().parents[1] / "fixtures" / "targets"
SAMPLES = Path(__file__).resolve().parents[1] / "fixtures" / "task-results"
FINDING_ID = "KF-2CC44B27C1508C41"


@pytest.fixture
def ctx(tmp_path, monkeypatch):
    monkeypatch.setenv(ids.RUNS_DIR_ENV, str(tmp_path / "runs"))
    monkeypatch.setattr(init_mod, "git_head", lambda directory: None)
    target = tmp_path / "webapp"
    shutil.copytree(TARGETS / "webapp", target)
    return init_run(str(target), runs_dir=tmp_path / "runs")


def sample(name, task_id):
    data = json.loads((SAMPLES / f"{name}.json").read_text(encoding="utf-8"))
    data["task_id"] = task_id
    return data


def test_every_task_type_has_a_handler_module():
    for task_type in state.TASK_TYPES:
        assert handlers.get_handler(task_type) is not handlers.default_handler


def test_recon_checks_the_kind(ctx):
    task_id = queue.create_task(ctx, "recon", "recon", {"kind": "surfaces"})
    recon.handle(ctx, queue.get_task(ctx, task_id), sample("recon", task_id))
    other = queue.create_task(ctx, "recon", "recon", {"kind": "product"})
    with pytest.raises(ValidationError, match="another recon kind"):
        recon.handle(ctx, queue.get_task(ctx, other), sample("recon", other))


def test_translate_writes_translations(ctx):
    data = {"findings": [{"id": FINDING_ID, "title": "x", "description": "y"}]}
    task_id = queue.create_task(ctx, "translate", "report", data)
    result = sample("translate", task_id)
    translate.handle(ctx, queue.get_task(ctx, task_id), result)
    written = json.loads((ctx.task_dir(task_id) / "translations.json").read_text("utf-8"))
    assert written == {"translations": result["translations"]}
    result["translations"][0]["id"] = "KF-0000000000000000"
    with pytest.raises(ValidationError) as caught:
        translate.handle(ctx, queue.get_task(ctx, task_id), result)
    assert len(caught.value.errors) == 2  # one missing, one unknown


def write_vuln(ctx):
    from kalkan.sca.merge import write_vulns
    from kalkan.sca.normalize import new_record

    record = new_record(
        ecosystem="PyPI",
        package="flask",
        version="3.0.3",
        ids=["GHSA-m2qf-hxjv-5gpq"],
        summary="Cookie disclosure.",
        cvss_score=7.5,
        locations=["requirements.txt"],
        engine="osv-scanner",
    )
    write_vulns(ctx.run_dir, [record], [])
    return record["ref"]


def reach_result(task_id, ref, reachability, quote="from flask import Flask, request"):
    return {
        "task_id": task_id,
        "vuln_ref": ref,
        "reachability": reachability,
        "reason": "Checked the imports.",
        "evidence": [{"file": "app/routes.py", "line": 4, "quote": quote}],
        "searched": ["from flask import"],
    }


def test_sca_reach_applies_verified_results(ctx):
    from kalkan.sca.merge import read_vulns

    ref = write_vuln(ctx)
    task_id = queue.create_task(ctx, "sca_reach", "validate", {"vuln_ref": ref})
    sca_reach.handle(ctx, queue.get_task(ctx, task_id), reach_result(task_id, ref, "reachable"))
    record = read_vulns(ctx.run_dir)["records"][0]
    assert record["reachability"] == "reachable"
    assert record["reach_task_id"] == task_id
    reach = json.loads((ctx.task_dir(task_id) / "reach.json").read_text("utf-8"))
    assert reach["applied"] is True and reach["evidence"][0]["quote_status"] == "verified"

    # A quote that is not in the file never proves reachability.
    bad = reach_result(task_id, ref, "reachable", quote="import nothing at all")
    sca_reach.handle(ctx, queue.get_task(ctx, task_id), bad)
    assert read_vulns(ctx.run_dir)["records"][0]["reachability"] == "unknown"

    with pytest.raises(ValidationError, match="another vulnerability record"):
        sca_reach.handle(
            ctx, queue.get_task(ctx, task_id), reach_result(task_id, "PyPI/x@1/GHSA", "unknown")
        )


def test_poc_build_infeasible(ctx):
    data = {"finding_id": FINDING_ID, "finding": {"id": FINDING_ID, "class": "sqli"}}
    task_id = queue.create_task(ctx, "poc_build", "poc", data)
    result = {
        "task_id": task_id,
        "finding_id": FINDING_ID,
        "feasible": False,
        "reason": "The framework cannot be stubbed.",
    }
    poc_build.handle(ctx, queue.get_task(ctx, task_id), result)
    poc = json.loads((ctx.task_dir(task_id) / "poc.json").read_text("utf-8"))
    assert poc["status"] == "blocked" and poc["blocker"] == "sandbox_infeasible"


def test_poc_build_feasible_keeps_the_harness_for_the_run_step(ctx):
    task_id = queue.create_task(ctx, "poc_build", "poc", {"finding_id": FINDING_ID})
    feasible = sample("poc_build", task_id)
    poc_build.handle(ctx, queue.get_task(ctx, task_id), feasible)
    # The sandbox module provides run_poc, so the handler only stores the harness; the poc:run
    # step produces poc.json.
    assert (ctx.task_dir(task_id) / "harness.json").is_file()
    assert not (ctx.task_dir(task_id) / "poc.json").is_file()


def test_poc_build_feasible_without_a_sandbox_runner(ctx, monkeypatch):
    task_id = queue.create_task(ctx, "poc_build", "poc", {"finding_id": FINDING_ID})
    feasible = sample("poc_build", task_id)
    monkeypatch.setattr(poc_build, "sandbox_runner", lambda: None)
    poc_build.handle(ctx, queue.get_task(ctx, task_id), feasible)
    assert (ctx.task_dir(task_id) / "harness.json").is_file()
    poc = json.loads((ctx.task_dir(task_id) / "poc.json").read_text("utf-8"))
    assert poc["status"] == "not_run" and poc["blocker"] == "sandbox_unavailable"


def test_poc_build_rejects_an_unusable_harness(ctx):
    task_id = queue.create_task(ctx, "poc_build", "poc", {"finding_id": FINDING_ID})
    feasible = sample("poc_build", task_id)
    feasible["files"].append(dict(feasible["files"][0]))
    with pytest.raises(ValidationError, match="not usable"):
        poc_build.handle(ctx, queue.get_task(ctx, task_id), feasible)
    feasible["files"].pop()
    feasible["finding_id"] = "KF-0000000000000000"
    with pytest.raises(ValidationError):
        poc_build.handle(ctx, queue.get_task(ctx, task_id), feasible)


def test_a_dead_poc_task_is_recorded_as_blocked(ctx, monkeypatch):
    from kalkan.run import steps  # noqa: PLC0415

    task_id = queue.create_task(
        ctx, "poc_build", "poc", {"finding_id": FINDING_ID}, meta={"finding": FINDING_ID}
    )
    for _ in range(3):
        queue.fail(ctx, task_id, "a safety classifier stopped the agent")
    monkeypatch.setattr(steps, "_need", lambda module, name: lambda *a, **k: {})
    outcome = steps._poc_run(ctx, "poc:run", None)
    assert "1 PoC tasks without a result" in outcome.detail
    poc = json.loads((ctx.task_dir(task_id) / "poc.json").read_text("utf-8"))
    assert poc["status"] == "blocked" and poc["blocker"] == "agent_failed"
    assert poc["finding_id"] == FINDING_ID and "(3 attempts)" in poc["observed_result"]
    # A second run of the step keeps the record and counts nothing new.
    assert steps._poc_run(ctx, "poc:run", None).detail == "0 PoC harnesses ran"
