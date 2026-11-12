# SPDX-License-Identifier: MIT
"""Tests for coverage planning (kalkan.run.plan), the ledger store and the text helpers."""

from __future__ import annotations

import json
import shutil
from collections import Counter
from pathlib import Path

import pytest

from kalkan.findings.ledger import canonical_coverage_id, validate_ledger, validate_ledger_file
from kalkan.run import budget, ids, plan, state, validation
from kalkan.run import init as init_mod
from kalkan.run.cleaning import (
    clean_text,
    dedupe_key,
    fingerprint_for,
    normalize_path,
    normalize_trace,
    reduce_fingerprint,
    safe_paths,
    sink_of,
)
from kalkan.run.init import init_run
from kalkan.run.ledger_store import (
    FAST_SUBSYSTEM,
    archive_attempt,
    assign,
    defer,
    load_ledger,
    make_unit,
)
from kalkan.run.runfiles import write_json

TARGETS = Path(__file__).resolve().parents[1] / "fixtures" / "targets"


def surface(sid, name, file="app/routes.py", kind="http", auth="user", subsystem="api"):
    return {
        "id": sid,
        "kind": kind,
        "name": name,
        "file": file,
        "line": 1,
        "auth": auth,
        "trust_boundary": "internet to application",
        "subsystem": subsystem,
        "notes": "",
    }


def cand(cid, slug, file, line=3, severity="high", engine="opengrep"):
    return {
        "id": cid,
        "engine": engine,
        "rule_id": "r",
        "class": slug,
        "cwe": [],
        "title": f"{slug} hint",
        "message": "m",
        "file": file,
        "start_line": line,
        "end_line": line,
        "snippet": "code()",
        "severity": severity,
        "tool_severity": "",
        "confidence": None,
        "tags": [],
        "fingerprints": {},
        "sca": None,
        "raw": {"sarif_file": "", "run_index": 0, "result_index": 0},
    }


def make_ctx(tmp_path, monkeypatch, profile="standard"):
    monkeypatch.setenv(ids.RUNS_DIR_ENV, str(tmp_path / "runs"))
    monkeypatch.setattr(init_mod, "git_head", lambda directory: None)
    target = tmp_path / "webapp"
    shutil.copytree(TARGETS / "webapp", target)
    return init_run(str(target), profile=profile, runs_dir=tmp_path / "runs")


@pytest.fixture
def ctx(tmp_path, monkeypatch):
    return make_ctx(tmp_path, monkeypatch)


def seed(ctx, surfaces, classes, candidates=()):
    write_json(ctx.run_dir / "recon" / "surfaces.json", {"surfaces": list(surfaces)})
    write_json(ctx.run_dir / "recon" / "classes.json", {"classes": list(classes)})
    write_json(ctx.run_dir / "candidates.json", {"candidates": list(candidates)})


# ---------------------------------------------------------------------------------------------
# Text helpers


def test_clean_text_and_paths():
    assert clean_text("  a\u200bb\n\tc\x00 ") == "a b c"
    assert clean_text("e\u0301") == "\u00e9"
    assert clean_text(" \u200b ") == ""
    assert clean_text(None) == ""
    assert len(clean_text("x" * 5000, 100)) == 100
    assert safe_paths(["./a.py", "a.py", "../b", "/etc", "C:/x", "c\\d", 3]) == ["a.py"]


def test_fingerprints():
    trace = [
        {"kind": "entrypoint", "file": "a.py", "line": 1, "scope": "f"},
        {"kind": "sink", "file": "app/db.py", "line": 8, "scope": "Users.find(id) "},
    ]
    assert sink_of(trace)["file"] == "app/db.py"
    assert fingerprint_for("sqli", trace) == "sqli:app/db.py:Users.find-id-"
    assert fingerprint_for(
        "xss", [{"kind": "entrypoint", "file": "v.js", "line": 4, "scope": ""}]
    ) == ("xss:v.js:line-4")
    assert reduce_fingerprint("__ ünïcode ::") == "n-code-::"
    assert reduce_fingerprint("") == "unknown"
    assert len(dedupe_key("x", "y" * 600)) < 120


def test_normalize_path_and_trace():
    assert normalize_path("./app/x.py") == "app/x.py"
    assert normalize_path("app\\x.py") == "app/x.py"
    assert normalize_path(".\\app\\x.py") == "app/x.py"
    assert normalize_path("../x.py") == "../x.py"  # unsafe stays; the validator reports it
    assert normalize_path(7) == 7

    def step(kind, line):
        return {"kind": kind, "file": "a.py", "line": line, "scope": "f", "description": "d"}

    trace, notes = normalize_trace([step("entrypoint", 1), step("sink", 2), step("sink", 3)])
    assert [s["kind"] for s in trace] == ["entrypoint", "propagation", "sink"]
    assert notes == ["trace[1].kind: sink -> propagation"]
    trace, notes = normalize_trace([step("entrypoint", 4)])
    assert trace == [step("entrypoint", 4)] and notes == []
    assert normalize_trace(None) == ([], [])


# ---------------------------------------------------------------------------------------------
# Ledger store


def test_unit_state_changes_keep_the_ledger_valid():
    unit = make_unit(
        surface="app/routes.py#GET /users",
        boundary="internet to application",
        subsystem="api",
        class_slug="sqli",
        starting_paths=["app/routes.py", "../x"],
        companion_blocks=plan.companion_blocks("sqli"),
        wave=1,
        bookkeeping={"group": "api"},
    )
    assert unit["coverage_id"] == canonical_coverage_id(unit["canonical_refs"])
    assert unit["starting_paths"] == ["app/routes.py"]
    assert validate_ledger([unit]) == []
    assign(unit, "t0001-hunt", 1)
    assert unit["status"] == "in_progress" and validate_ledger([unit]) == []
    unit.update(
        status="covered",
        reviewed_paths=["app/routes.py"],
        local_checks=[
            {
                "agent_id": "t0001-hunt",
                "reviewed_paths": ["app/routes.py"],
                "invariant": "i",
                "method": "source",
                "result": "r",
                "artifact": None,
            }
        ],
    )
    assert validate_ledger([unit]) == []
    assert archive_attempt(unit, "missed a route", 1) is False  # the wave must grow
    assert archive_attempt(unit, "missed a route", 2) is True
    assert unit["status"] == "planned" and unit["wave"] == 2
    assert validate_ledger([unit]) == []
    assign(unit, "t0005-hunt", 2)
    assert validate_ledger([unit]) == []
    defer(unit, "budget")
    assert unit["unresolved"] == ["budget"] and validate_ledger([unit]) == []
    assert (
        make_unit(
            surface="",
            boundary="b",
            subsystem="s",
            class_slug="sqli",
            starting_paths=["a"],
            companion_blocks=[],
            wave=1,
            bookkeeping={},
        )
        is None
    )


# ---------------------------------------------------------------------------------------------
# Units


def test_classes_for_surface():
    hints = {"app/routes.py": Counter({"crypto": 1})}
    http = surface("S1", "GET /", kind="http")
    assert plan.classes_for_surface(http, ["sqli", "crypto", "vulnerable-dependency"], hints) == [
        "sqli",
        "crypto",
    ]
    cli = surface("S2", "tool", kind="cli", file="cli.py")
    assert plan.classes_for_surface(cli, ["sqli", "path-traversal"], {}) == ["path-traversal"]
    other = surface("S3", "x", kind="other", file="x.py")
    assert plan.classes_for_surface(other, ["xss", "code-quality"], {}) == ["xss"]


def test_build_units_standard_and_priority(ctx):
    seed(
        ctx,
        [
            surface("S001", "GET /users", auth="user"),
            surface("S002", "GET /users", auth="none"),  # same refs: merged into S001's units
            surface("S003", "POST /login", file="app/auth.py", auth="none"),
            surface("S004", "settings", file="Dockerfile", kind="file", subsystem="deploy"),
        ],
        ["sqli", "idor", "authn"],
        [cand("CAND-0000000000000001", "xss", "app/routes.py", severity="medium")],
    )
    units = plan.build_units(ctx)
    assert validate_ledger(sorted(units, key=lambda u: u["coverage_id"])) == []
    by_class = Counter(unit["attack_class"] for unit in units)
    assert by_class == Counter({"sqli": 2, "idor": 2, "authn": 2, "xss": 1})
    merged = next(
        u
        for u in units
        if u["attack_class"] == "sqli" and u["surface"] == "app/routes.py#GET /users"
    )
    assert merged["kalkan"]["surface_ids"] == ["S001", "S002"]
    assert merged["kalkan"]["auth"] == "none"
    ordered = plan.order_units(units)
    assert ordered[0]["kalkan"]["auth"] == "none"
    hinted = [u for u in ordered if u["kalkan"]["hints"]]
    assert [u["attack_class"] for u in hinted] == ["xss"]


def test_subsystem_groups_join_labels_of_one_file():
    surfaces = [
        surface("S1", "GET /a", file="shop/accounts.py", subsystem="shop/accounts"),
        surface("S2", "GET /b", file="shop/accounts.py", subsystem="shop/accounts"),
        surface("S3", "/api/*", file="shop/accounts.py", subsystem="accounts"),
        surface("S4", "env", file="shop/storage.py", kind="other", subsystem="config"),
        surface("S5", "env", file="shop/storage.py", kind="other", subsystem="configuration"),
        surface("S6", "env", file="shop/settings.py", kind="other", subsystem="configuration"),
        surface("S7", "Dockerfile", file="Dockerfile", kind="file", subsystem=""),
        surface("S8", "job", file="jobs/run.py", kind="queue", subsystem="unknown subsystem"),
    ]
    groups = plan.subsystem_groups(surfaces)
    assert groups == {
        "shop/accounts.py": "shop/accounts",
        "shop/storage.py": "configuration",
        "shop/settings.py": "configuration",
        "Dockerfile": "(root)",
        "jobs/run.py": "jobs",
    }
    assert plan.folder_of("src/main/java/A.java") == "src/main"
    assert plan.folder_of("shop/app.py") == "shop"
    assert plan.folder_of("Dockerfile") == "(root)"


def test_units_coarsen_until_the_hunt_batches_fit(ctx):
    surfaces = [
        surface(f"S{n:03d}", f"GET /r{n}", file=f"app/r{n % 4}.py", subsystem=f"s{n % 4}")
        for n in range(12)
    ]
    seed(ctx, surfaces, ["sqli", "idor", "authn", "xss", "ssrf"])
    by_level = {level: plan.build_units(ctx, level) for level in plan.LEVELS}
    assert [len(by_level[level]) for level in plan.LEVELS] == [60, 20, 20, 5, 5]
    level, units = plan.choose_units(ctx)
    assert level == "surface"  # 60 units in 4 groups: 16 batches fit the cap of 49
    assert {unit["kalkan"]["level"] for unit in units} == {"surface"}
    with state.transaction(ctx) as tx:
        # remaining 82: critic reserve 2, validation reserve 68 -> 12 hunt tasks at most
        tx.state["budget"]["used_agent_tasks"] = 68
    level, units = plan.choose_units(ctx)
    assert level == "file" and len(units) == 20
    file_unit = units[0]
    assert file_unit["surface"].endswith("#all-entry-surfaces")
    assert file_unit["boundary"].endswith("#all-trust-boundaries")
    assert file_unit["subsystem"] == file_unit["kalkan"]["group"]
    assert len(file_unit["kalkan"]["surface_ids"]) == 3
    with state.transaction(ctx) as tx:
        tx.state["budget"]["used_agent_tasks"] = 77  # 3 hunt tasks
    level, units = plan.choose_units(ctx)
    assert level == "folder" and len(units) == 5
    assert units[0]["surface"] == "app#all-entry-surfaces"
    assert validate_ledger(sorted(units, key=lambda u: u["coverage_id"])) == []


def test_build_units_quick(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path, monkeypatch, profile="fast")
    seed(
        ctx,
        [
            surface("S001", "GET /users"),
            surface("S002", "POST /users", auth="none"),
            surface("S003", "job", file="jobs/run.py", kind="queue", subsystem="worker"),
        ],
        ["sqli", "idor"],
    )
    units = plan.build_units(ctx)
    assert {unit["subsystem"] for unit in units} == {FAST_SUBSYSTEM}
    assert sorted((u["kalkan"]["group"], u["attack_class"]) for u in units) == [
        ("api", "idor"),
        ("api", "sqli"),
        ("worker", "sqli"),
    ]
    api_sqli = next(
        u for u in units if u["kalkan"]["group"] == "api" and u["attack_class"] == "sqli"
    )
    assert api_sqli["kalkan"]["surface_ids"] == ["S001", "S002"]
    assert api_sqli["kalkan"]["auth"] == "none"


def test_form_batches():
    units = [
        {"coverage_id": str(n), "kalkan": {"group": group}}
        for n, group in enumerate(["a", "a", "b", "a", "a", "b", "c"])
    ]
    batches, left = plan.form_batches(units)
    assert [[u["coverage_id"] for u in b] for b in batches] == [
        ["0", "1", "3"],
        ["2", "5"],
        ["4"],
        ["6"],
    ]
    assert left == []
    batches, left = plan.form_batches(units, max_batches=2)
    assert [u["coverage_id"] for u in left] == ["4", "6"]


def test_plan_ledger_defers_what_the_budget_cannot_fund(ctx):
    surfaces = [surface(f"S{n:03d}", f"GET /r{n}", file=f"app/r{n}.py") for n in range(6)]
    seed(ctx, surfaces, ["sqli", "idor", "authn", "xss", "ssrf", "csrf"])
    with state.transaction(ctx) as tx:
        # remaining 71: critic reserve 2, validation reserve 68 -> 1 hunt task
        tx.state["budget"]["used_agent_tasks"] = 79
    summary = plan.plan_ledger(ctx)
    # Even the coarsest level needs two batches of four: one batch fits.
    assert summary == {
        "units": 6,
        "planned": 4,
        "deferred": 2,
        "hunt_budget": 1,
        "level": "all",
    }
    ledger = load_ledger(ctx)
    assert validate_ledger_file(ctx.run_dir / "coverage-ledger.json") == []
    deferred = [u for u in ledger if u["status"] == "deferred"]
    assert {u["unresolved"][0] for u in deferred} == {plan.REASON_BUDGET}
    with state.transaction(ctx) as tx:
        tx.state["phase"] = "plan"
    result = plan.create_hunt_wave(ctx, 1)
    assert result == {"tasks": 1, "units": 4, "deferred": 0}
    assert plan.create_hunt_wave(ctx, 1) == {"tasks": 0, "units": 0, "deferred": 0}
    assert budget.available(ctx.reload(), "hunt") == 0


def test_plan_ledger_without_surfaces_writes_an_empty_ledger(ctx):
    seed(ctx, [], [])
    assert plan.plan_ledger(ctx)["units"] == 0
    assert json.loads((ctx.run_dir / "coverage-ledger.json").read_text("utf-8")) == []


def test_deterministic_verifies(ctx):
    candidates = [
        cand(f"CAND-{n:016X}", "sqli", "app/routes.py", line=n, severity="critical")
        for n in range(1, 30)
    ]
    candidates += [
        cand("CAND-1000000000000001", "iac-cloud-container", "Dockerfile"),
        cand("CAND-1000000000000002", "vulnerable-dependency", "requirements.txt"),
        cand("CAND-1000000000000003", "xss", "app/routes.py", severity="medium"),
        cand("CAND-1000000000000004", "sqli", "app/routes.py", line=1, engine="bandit"),
    ]
    seed(ctx, [], [], candidates)
    cap = budget.deterministic_verify_cap(ctx.state)
    assert cap == budget.validation_reserve(ctx.state) // 4
    first = validation.create_deterministic_verifies(ctx)
    assert first == {"tasks": cap, "skipped": 29 - cap, "covered": 0, "cap": cap}
    tasks = [t for t in ctx.reload()["tasks"].values() if t["type"] == "verify"]
    assert len(tasks) == cap
    assert {t["phase"] for t in tasks} == {"validate"}
    assert validation.create_deterministic_verifies(ctx)["tasks"] == cap
    assert len([t for t in ctx.reload()["tasks"].values() if t["type"] == "verify"]) == cap


def test_gap_unit(ctx):
    seed(ctx, [surface("S001", "GET /users")], ["sqli"])
    surfaces = {"S001": surface("S001", "GET /users")}
    known = plan.gap_unit(
        ctx,
        {"surface_id": "S001", "class": "ssrf", "starting_paths": ["app/x.py"]},
        surfaces,
        wave=2,
        origin="critic:T1",
    )
    assert known["surface"] == "app/routes.py#GET /users"
    assert known["starting_paths"] == ["app/routes.py", "app/x.py"]
    assert known["wave"] == 2
    free = plan.gap_unit(
        ctx,
        {"surface_id": "GET /admin", "class": "missing-authz", "starting_paths": ["admin/v.py"]},
        surfaces,
        wave=2,
        origin="hunt:T2",
    )
    assert free["surface"] == "admin/v.py#GET /admin" and free["subsystem"] == "admin"
    assert (
        plan.gap_unit(
            ctx,
            {"surface_id": "x", "class": "vulnerable-dependency", "starting_paths": ["a"]},
            surfaces,
            wave=2,
            origin="o",
        )
        is None
    )
    assert (
        plan.gap_unit(
            ctx,
            {"surface_id": "x", "class": "xss", "starting_paths": ["/a"]},
            surfaces,
            wave=2,
            origin="o",
        )
        is None
    )
