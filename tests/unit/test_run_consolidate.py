# SPDX-License-Identifier: MIT
"""Tests for root-cause consolidation: the link rules and the candidate groups
(kalkan.findings.consolidate), the step ``consolidate`` (kalkan.run.consolidate), the handler
(kalkan.run.handlers.consolidate), the merge fields, the report counts, SARIF suppressions,
``run reopen`` and the compatibility with run states of older versions."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from kalkan.cli import main
from kalkan.errors import StateError, ValidationError
from kalkan.findings.consolidate import (
    CHUNK_SIZE,
    candidate_groups,
    eligible,
    fold_groups,
    link_reasons,
    link_strength,
    pick_primary,
)
from kalkan.findings.merge import merge_run, merged_records
from kalkan.findings.validate import validate_findings
from kalkan.report.model import build_model
from kalkan.report.render_exec import render_executive
from kalkan.report.render_html import render_html
from kalkan.report.render_md import render_markdown
from kalkan.report.summary import build_sarif, build_summary
from kalkan.run import budget, events, ids, phases, queue, state, steps
from kalkan.run import init as init_mod
from kalkan.run.consolidate import GROUPS_NAME, create_consolidate_tasks
from kalkan.run.handlers import consolidate as handler
from kalkan.run.init import init_run

CAPTCHA = """# Sample captcha service for kalkan consolidation tests. Not a real application.
import hmac


def _unused():
    return None
CAPTCHA_HMAC_KEY = "test-only-placeholder"


def sign(value):
    return hmac.new(CAPTCHA_HMAC_KEY.encode(), value.encode(), "sha256").hexdigest()
"""
REGISTER = """# Sample register controller for kalkan consolidation tests.
from app.captcha import CAPTCHA_HMAC_KEY, sign


def register(form):
    token = sign(form["email"])
    return {"token": token, "key_id": CAPTCHA_HMAC_KEY[:4]}
"""
BACKUP = """# Sample backup job for kalkan consolidation tests.
import os
import shutil

SHARED = "/mnt/shared"


def walk(source):
    return os.walk(source, followlinks=True)


def run_backup(source):
    for root, _, files in walk(source):
        for name in files:
            shutil.copy(os.path.join(root, name), SHARED)
"""
KEY_QUOTE = 'CAPTCHA_HMAC_KEY = "test-only-placeholder"'


@pytest.fixture
def ctx(tmp_path, monkeypatch):
    monkeypatch.setenv(ids.RUNS_DIR_ENV, str(tmp_path / "runs"))
    monkeypatch.setattr(init_mod, "git_head", lambda directory: None)
    target = tmp_path / "shop"
    (target / "app").mkdir(parents=True)
    (target / "ops").mkdir()
    (target / "app" / "captcha.py").write_text(CAPTCHA, encoding="utf-8")
    (target / "app" / "register.py").write_text(REGISTER, encoding="utf-8")
    (target / "ops" / "backup.py").write_text(BACKUP, encoding="utf-8")
    run = init_run(str(target), runs_dir=tmp_path / "runs", profile="standard")
    with state.transaction(run) as tx:
        tx.state["phase"] = "validate"
    return run


def fid(number: int) -> str:
    return f"KF-{number:016X}"


def record(
    number,
    slug,
    file,
    line,
    *,
    verdict="confirmed",
    overall="high",
    evidence=(),
    quotes=(),
    title=None,
):
    """Return a valid canonical finding; ``evidence`` adds (file, line) items and ``quotes``
    adds audit-answer quotes (file, line, quote)."""
    finding = {
        "verdict": verdict,
        "fingerprint": f"{slug}:{file}:line-{line}-{number}",
        "title": title or f"{slug} at {file}:{line}",
        "description": f"Record {number}.",
        "trace": [
            {"kind": "sink", "file": file, "line": line, "scope": "main", "description": "x"}
        ],
        "evidence": [
            {"file": file, "line": line, "description": "The cited line."},
            *({"file": f, "line": n, "description": "More."} for f, n in evidence),
        ],
        "id": fid(number),
        "class": slug,
        "cwe": [],
        "engines": ["hunter", "verifier"],
    }
    if quotes:
        answer = {
            "status": "established",
            "reason": "Quoted.",
            "evidence": [{"file": f, "line": n, "quote": q} for f, n, q in quotes],
        }
        finding["audit_answers"] = {
            key: copy.deepcopy(answer)
            for key in ("attacker_control", "privilege_boundary", "unmitigated")
        }
    if verdict == "confirmed":
        finding.update(
            root_cause=f"Root cause {number}.",
            intended_behavior="The safe behavior.",
            conditions=[{"kind": "network_routing", "description": "Reachable."}],
            execution={
                "attacker_perspective": "A client.",
                "payloads": ["x"],
                "instructions": ["Send it."],
                "observed_result": "Static analysis only.",
            },
            remediation={"strategy": f"Fix {number}."},
            severity={
                "likelihood": {"score": "high", "reason": "Easy."},
                "impact": {"score": overall, "reason": "Impact."},
                "overall_severity": overall,
            },
            confidence={"score": "medium", "reason": "Clear."},
        )
    elif verdict == "needs_validation":
        finding.update(
            claimed_root_cause=f"Claimed {number}.",
            blockers=["A deployment fact."],
            validation_plan={"local": "Run a local test."},
        )
    else:
        finding.update(claimed_root_cause=f"Claimed {number}.", reason="Refuted.")
    assert validate_findings([finding]) == [], validate_findings([finding])
    return finding


def add_verified(ctx, finding) -> str:
    """Create a done verify task that holds ``finding`` and return its ID."""
    task_id = queue.create_task(ctx, "verify", "validate", {})
    (ctx.task_dir(task_id) / "finding.json").write_text(json.dumps(finding), encoding="utf-8")
    with state.transaction(ctx) as tx:
        tx.state["tasks"][task_id]["status"] = "done"
    return task_id


def consolidate_tasks(ctx):
    return [
        (task_id, queue.get_task(ctx, task_id))
        for task_id, task in ctx.reload()["tasks"].items()
        if task["type"] == "consolidate"
    ]


def task_input(ctx, task_id):
    return json.loads((ctx.task_dir(task_id) / "input.json").read_text(encoding="utf-8"))


def complete(ctx, task_id, groups=(), distinct=()):
    result = {"task_id": task_id, "groups": list(groups), "distinct": list(distinct)}
    (ctx.task_dir(task_id) / "result.json").write_text(json.dumps(result), encoding="utf-8")
    return queue.complete(ctx, task_id)


def findings_by_id(ctx):
    data = json.loads((ctx.run_dir / "findings.json").read_text(encoding="utf-8"))
    return {item["id"]: item for item in data}


def secret_pair(ctx):
    """The committed captcha key, filed at the service and at the controller (one root cause)."""
    service = record(
        1,
        "hardcoded-secrets",
        "app/captcha.py",
        7,
        overall="medium",
        quotes=[("app/captcha.py", 7, KEY_QUOTE)],
    )
    controller = record(
        2,
        "hardcoded-secrets",
        "app/register.py",
        7,
        overall="high",
        evidence=[("app/captcha.py", 7)],
    )
    add_verified(ctx, service)
    add_verified(ctx, controller)
    return service, controller


# ---------------------------------------------------------------------------------------------
# Link rules and candidate groups


def test_shared_location_links_within_three_lines():
    a = record(1, "authn", "app/a.py", 10)
    b = record(2, "path-traversal", "app/b.py", 40, evidence=[("app/a.py", 13)])
    c = record(3, "path-traversal", "app/c.py", 40, evidence=[("app/a.py", 14)])
    assert link_reasons(a, b) == ["shared_location: app/a.py:10 and app/a.py:13"]
    assert link_reasons(a, c) == []  # four lines apart, other class, other first file


def test_shared_location_counts_the_audit_answer_quotes():
    a = record(1, "rate-limit-bruteforce", "app/a.py", 10, quotes=[("app/proxy.py", 5, "xff")])
    b = record(2, "dos-redos", "app/b.py", 80, quotes=[("app/proxy.py", 7, "xff header")])
    assert link_reasons(a, b) == ["shared_location: app/proxy.py:5 and app/proxy.py:7"]


def test_nearby_anchor_links_first_evidence_within_fifteen_lines():
    a = record(1, "race-condition", "app/wallet.py", 10)
    b = record(2, "business-logic", "app/wallet.py", 25)
    c = record(3, "business-logic", "app/wallet.py", 26)
    assert link_reasons(a, b) == ["nearby_anchor: first evidence app/wallet.py:10 and line 25"]
    assert link_reasons(a, c) == []


def test_same_class_and_a_shared_cited_file_link():
    a = record(1, "race-condition", "app/wallet.py", 10)
    b = record(2, "race-condition", "app/wallet.py", 90)
    c = record(3, "business-logic", "app/wallet.py", 90)
    assert link_reasons(a, b) == ["same_class_file: race-condition in app/wallet.py"]
    assert link_reasons(a, c) == []


def test_candidate_groups_are_components_without_rejected_records():
    a = record(1, "authn", "app/a.py", 10)
    b = record(2, "security-misconfig", "app/b.py", 40, evidence=[("app/a.py", 11)])
    c = record(3, "path-traversal", "app/c.py", 70, evidence=[("app/b.py", 41)])  # via b
    lone = record(4, "xss", "web/x.js", 3)
    gone = record(5, "authn", "app/a.py", 10, verdict="rejected")
    reviewed = record(6, "authn", "app/a.py", 12, verdict="needs_validation")
    reviewed["review"] = {"decision": "reject", "reason": "Refuted."}
    assert not eligible(gone) and not eligible(reviewed)
    [group] = candidate_groups([lone, c, gone, b, reviewed, a])
    assert [item["id"] for item in group.records] == [fid(1), fid(2), fid(3)]
    assert (group.component_size, group.chunk, group.chunks) == (3, 1, 1)
    assert [link["ids"] for link in group.links] == [[fid(1), fid(2)], [fid(2), fid(3)]]


def test_a_large_component_is_split_without_a_lone_record():
    records = [record(n, "authn", "app/a.py", 10 + n) for n in range(1, 14)]
    groups = candidate_groups(records)
    # Twelve fill the first chunk; the 13th pairs with its strongest neighbor (record 10).
    assert [len(group.records) for group in groups] == [11, 2]
    assert [item["id"] for item in groups[1].records] == [fid(10), fid(13)]
    assert {group.component_size for group in groups} == {13}
    assert [group.chunk for group in groups] == [1, 2]
    seen = [item["id"] for group in groups for item in group.records]
    assert sorted(seen) == sorted(item["id"] for item in records)
    many = [record(n, "authn", "app/a.py", 10 + n) for n in range(1, 26)]
    sizes = [len(group.records) for group in candidate_groups(many)]
    assert sizes == [12, 11, 2] and sum(sizes) == 25
    assert all(len(group.records) <= CHUNK_SIZE for group in candidate_groups(many))


def test_the_split_keeps_records_with_shared_locations_together():
    # Two true duplicates (a shared location) sit far apart in location order, and a chain of
    # weak same-class links connects 14 records. A split in walk order would separate the pair.
    filler = [
        record(n, "idor", f"svc/f{n:02}.py", 1, evidence=[("svc/hub.py", 100 + 50 * n)])
        for n in range(1, 13)
    ]
    first = record(20, "idor", "app/a.py", 5, evidence=[("svc/hub.py", 2000)])
    second = record(99, "authn", "web/z.py", 9, evidence=[("app/a.py", 6)])
    groups = candidate_groups([*filler, first, second])
    assert sum(len(group.records) for group in groups) == 14
    assert max(len(group.records) for group in groups) <= CHUNK_SIZE
    together = [group for group in groups if fid(20) in {item["id"] for item in group.records}]
    assert fid(99) in {item["id"] for item in together[0].records}


def test_link_strength_orders_shared_locations_first():
    a = record(1, "authn", "app/a.py", 10, evidence=[("app/b.py", 4)])
    b = record(2, "authn", "app/a.py", 12, evidence=[("app/b.py", 5)])
    c = record(3, "authn", "app/a.py", 40)
    assert link_strength(a, b) == (2, 1, 1)
    assert link_strength(a, c) == (0, 0, 1)
    assert link_strength(c, record(4, "xss", "web/x.js", 3)) == (0, 0, 0)


# ---------------------------------------------------------------------------------------------
# Primary selection


def test_primary_order_verdict_severity_evidence_id():
    weak = record(1, "authn", "app/a.py", 10, verdict="needs_validation")
    medium = record(2, "authn", "app/a.py", 10, overall="medium")
    high = record(9, "authn", "app/a.py", 10, overall="high")
    assert pick_primary([weak, medium, high]) is high
    assert pick_primary([weak, medium]) is medium  # confirmed beats needs_validation
    richer = record(8, "authn", "app/a.py", 10, overall="high", evidence=[("app/b.py", 1)])
    assert pick_primary([high, richer]) is richer  # more evidence items
    twin = record(3, "authn", "app/a.py", 10, overall="high")
    assert pick_primary([high, twin]) is twin  # the smallest id


# ---------------------------------------------------------------------------------------------
# The step


def test_the_step_creates_one_task_per_group_with_the_record_views(ctx):
    service, controller = secret_pair(ctx)
    add_verified(ctx, record(3, "xss", "web/x.js", 3))  # alone: no task
    summary = create_consolidate_tasks(ctx)
    assert summary == {"records": 3, "groups": 1, "created": 1, "reused": 0, "unfunded": 0}
    [(task_id, task)] = consolidate_tasks(ctx)
    assert task["phase"] == "validate" and task["priority"] == 60
    assert task["dedupe_key"] == f"consolidate:{service['fingerprint']} {controller['fingerprint']}"
    assert task["meta"] == {"findings": [fid(1), fid(2)], "chunk": 1, "chunks": 1}
    data = task_input(ctx, task_id)
    assert data["component"] == {"size": 2, "chunk": 1, "chunks": 1, "note": None}
    assert data["links"][0]["reasons"][0].startswith("shared_location: app/captcha.py:7")
    view = data["records"][0]
    assert view["id"] == fid(1) and view["root_cause"] == "Root cause 1."
    assert view["overall_severity"] == "medium" and view["remediation"] == "Fix 1."
    assert view["quotes"] == [{"file": "app/captcha.py", "line": 7, "quote": KEY_QUOTE}]
    assert view["trace"] == ["sink app/captcha.py:7"] and view["review"] is None
    prompt = (ctx.task_dir(task_id) / "prompt.md").read_text(encoding="utf-8")
    assert "## Task: find the records that share one root cause" in prompt
    assert KEY_QUOTE in prompt  # the source excerpt
    groups = json.loads((ctx.run_dir / GROUPS_NAME).read_text(encoding="utf-8"))
    assert groups["groups"][0]["task"] == task_id and groups["unfunded"] == 0
    # Idempotent: a second run reuses the task.
    again = create_consolidate_tasks(ctx)
    assert (again["created"], again["reused"]) == (0, 1)


def test_a_split_component_says_so_in_the_input(ctx):
    for number in range(1, 14):
        add_verified(ctx, record(number, "authn", "app/captcha.py", number))
    summary = create_consolidate_tasks(ctx)
    assert (summary["groups"], summary["created"]) == (2, 2)
    notes = [task_input(ctx, task_id)["component"] for task_id, _ in consolidate_tasks(ctx)]
    assert [(note["chunk"], note["chunks"], note["size"]) for note in notes] == [
        (1, 2, 13),
        (2, 2, 13),
    ]
    assert "split 13 linked records into 2 chunks" in notes[0]["note"]


def test_a_run_without_a_group_creates_no_task(ctx):
    add_verified(ctx, record(1, "xss", "web/x.js", 3))
    action = phases.next_action(ctx, "orchestrator")
    assert action == {"kind": "engine_step", "phase": "validate", "step": budget.REVIEW_STEP}
    steps.run_step(ctx)  # one review task
    for task_id, task in ctx.reload()["tasks"].items():
        if task["type"] == "review":
            with state.transaction(ctx) as tx:
                tx.state["tasks"][task_id]["status"] = "skipped"
    action = phases.next_action(ctx, "orchestrator")
    assert action == {"kind": "engine_step", "phase": "validate", "step": "consolidate"}
    outcome = steps.run_step(ctx)
    assert outcome["status"] == "done"
    assert outcome["detail"] == "no candidate group (1 records)"
    assert consolidate_tasks(ctx) == []
    # The Turkish letter step follows; the short English sample texts need no letters.
    action = phases.next_action(ctx, "orchestrator")
    assert action == {"kind": "engine_step", "phase": "validate", "step": "polish"}
    assert steps.run_step(ctx)["detail"] == "no record needs the Turkish letters (1 records)"
    assert phases.next_action(ctx, "orchestrator")["phase"] == "poc"


def test_without_budget_the_records_stay_separate_and_the_report_says_so(ctx):
    secret_pair(ctx)
    with state.transaction(ctx) as tx:
        tx.state["budget"]["used_agent_tasks"] = tx.state["budget"]["max_agent_tasks"]
    summary = create_consolidate_tasks(ctx)
    assert (summary["created"], summary["unfunded"]) == (0, 1)
    assert consolidate_tasks(ctx) == []
    assert ctx.reload().get("incomplete_pending") is None  # never blocks the report
    groups = json.loads((ctx.run_dir / GROUPS_NAME).read_text(encoding="utf-8"))
    assert groups["unfunded"] == 1 and groups["groups"][0]["task"] is None
    assert any(e["kind"] == "consolidate_unfunded" for e in events.read_events(ctx.run_dir))
    merge_run(ctx.run_dir)
    model = build_model(ctx.run_dir, installed_tools=None)
    assert model.verdict_counts()["confirmed"] == 2 and model.duplicates == []
    assert any("not checked for 1 candidate groups" in item for item in model.warnings)


# ---------------------------------------------------------------------------------------------
# The handler


def test_the_handler_needs_every_id_exactly_once(ctx):
    secret_pair(ctx)
    add_verified(ctx, record(3, "hardcoded-secrets", "app/captcha.py", 11))
    create_consolidate_tasks(ctx)
    [(task_id, task)] = consolidate_tasks(ctx)
    quote = [{"file": "app/captcha.py", "line": 7, "quote": KEY_QUOTE}]

    def result(groups, distinct):
        return {"task_id": task_id, "groups": groups, "distinct": distinct}

    missing = result([{"ids": [fid(1), fid(2)], "reason": "One key.", "evidence": quote}], [])
    with pytest.raises(ValidationError) as caught:
        handler.handle(ctx, task, missing)
    assert caught.value.errors == [
        f"$result: {fid(3)} is missing; put it in a group or in distinct"
    ]
    unknown = result(
        [{"ids": [fid(1), fid(2)], "reason": "One key.", "evidence": quote}],
        [{"id": fid(3), "reason": "Other."}, {"id": fid(77), "reason": "Unknown."}],
    )
    with pytest.raises(ValidationError) as caught:
        handler.handle(ctx, task, unknown)
    assert caught.value.errors == [f"$result: {fid(77)} is not a record of this task"]
    twice = result(
        [{"ids": [fid(1), fid(2)], "reason": "One key.", "evidence": quote}],
        [{"id": fid(3), "reason": "Other."}, {"id": fid(2), "reason": "Again."}],
    )
    with pytest.raises(ValidationError) as caught:
        handler.handle(ctx, task, twice)
    assert caught.value.errors == [f"$result: {fid(2)} appears 2 times; name each record once"]
    assert not (ctx.task_dir(task_id) / handler.OUTCOME_NAME).exists()


def test_a_wrong_result_counts_a_failed_attempt(ctx):
    secret_pair(ctx)
    create_consolidate_tasks(ctx)
    [(task_id, _)] = consolidate_tasks(ctx)
    with pytest.raises(ValidationError, match="does not name every record once"):
        complete(ctx, task_id, distinct=[{"id": fid(1), "reason": "Alone."}])
    task = ctx.reload()["tasks"][task_id]
    assert task["attempts"] == 1 and task["status"] == "pending"


def test_a_group_with_a_failing_quote_is_dropped(ctx):
    secret_pair(ctx)
    create_consolidate_tasks(ctx)
    [(task_id, _)] = consolidate_tasks(ctx)
    bad = {"file": "app/captcha.py", "line": 7, "quote": "SECRET_TOKEN = load()"}
    good = {"file": "app/captcha.py", "line": 7, "quote": KEY_QUOTE}
    group = {"ids": [fid(1), fid(2)], "reason": "One key.", "evidence": [good, bad]}
    assert complete(ctx, task_id, groups=[group])["status"] == "done"
    outcome = json.loads((ctx.task_dir(task_id) / handler.OUTCOME_NAME).read_text("utf-8"))
    [entry] = outcome["groups"]
    assert entry["accepted"] is False and entry["dropped"] == handler.DROPPED_UNVERIFIED
    assert [item["quote_status"] for item in entry["evidence"]] == ["verified", "unverified"]
    assert outcome["dropped"] == 1 and outcome["normalized"]
    summary = merge_run(ctx.run_dir)
    assert summary["consolidation"] == {"groups": 0, "duplicates": 0, "skipped": 0}
    assert all("duplicate_of" not in item for item in findings_by_id(ctx).values())
    model = build_model(ctx.run_dir, installed_tools=None)
    assert any("groups were dropped" in item for item in model.warnings)


# ---------------------------------------------------------------------------------------------
# Merge fields and the report


def folded_run(ctx):
    """One accepted group: the committed key (primary: the high controller record)."""
    secret_pair(ctx)
    pending = record(3, "hardcoded-secrets", "app/captcha.py", 11, verdict="needs_validation")
    add_verified(ctx, pending)
    create_consolidate_tasks(ctx)
    [(task_id, _)] = consolidate_tasks(ctx)
    group = {
        "ids": [fid(1), fid(2), fid(3)],
        "reason": "One committed HMAC key; removing and rotating it fixes all three records.",
        "evidence": [{"file": "app/captcha.py", "line": 7, "quote": KEY_QUOTE}],
    }
    complete(ctx, task_id, groups=[group])
    outcome = json.loads((ctx.task_dir(task_id) / handler.OUTCOME_NAME).read_text("utf-8"))
    assert outcome["groups"][0]["primary"] == fid(2)  # confirmed high beats confirmed medium
    return merge_run(ctx.run_dir)


def test_merge_keeps_every_record_and_marks_the_duplicates(ctx):
    summary = folded_run(ctx)
    assert summary["consolidation"] == {"groups": 1, "duplicates": 2, "skipped": 0}
    assert summary["duplicates_folded"] == 2
    assert summary["findings"] == 3
    assert summary["by_verdict"] == {"confirmed": 1, "needs_validation": 0, "rejected": 0}
    assert summary["by_severity"]["high"] == 1 and summary["by_severity"]["medium"] == 0
    assert summary["inputs"]["consolidate_files"] == 1
    found = findings_by_id(ctx)
    assert set(found) == {fid(1), fid(2), fid(3)}
    primary = found[fid(2)]
    assert primary["severity"]["overall_severity"] == "high"  # the primary keeps its fields
    assert [item["id"] for item in primary["related"]] == [fid(1), fid(3)]
    assert primary["related"][0] == {
        "id": fid(1),
        "title": "hardcoded-secrets at app/captcha.py:7",
        "class": "hardcoded-secrets",
        "reason": "One committed HMAC key; removing and rotating it fixes all three records.",
    }
    for duplicate in (found[fid(1)], found[fid(3)]):
        assert duplicate["duplicate_of"] == fid(2)
        assert duplicate["duplicate_reason"].startswith("One committed HMAC key")
    assert validate_findings(list(found.values())) == []
    # merged_records without fold gives the records before consolidation (the step input).
    plain = merged_records(ctx.run_dir)
    assert all("duplicate_of" not in item and "related" not in item for item in plain)


def test_fold_skips_overlapping_and_short_groups():
    a = record(1, "authn", "app/a.py", 10)
    b = record(2, "authn", "app/a.py", 11)
    c = record(3, "authn", "app/a.py", 12)
    findings = [a, b, c]
    stats = fold_groups(
        findings,
        [
            ("first", {"ids": [fid(1), fid(2)], "reason": "One."}),
            ("second", {"ids": [fid(2), fid(3)], "reason": "Two."}),
            ("third", {"ids": [fid(3), fid(99)], "reason": "Three."}),
        ],
    )
    assert (stats.applied, stats.duplicates, stats.skipped) == (1, 1, 2)
    assert "already belong to another consolidation group" in stats.warnings[0]
    assert "fewer than two eligible records" in stats.warnings[1]
    assert b["duplicate_of"] == fid(1) and "duplicate_of" not in c


def test_a_distinct_answer_keeps_the_counter_example_separate(ctx):
    dos = record(1, "dos-redos", "ops/backup.py", 15, title="Backup fills the shared disk")
    traversal = record(
        2, "path-traversal", "ops/backup.py", 13, title="Backup follows symlinks as root"
    )
    add_verified(ctx, dos)
    add_verified(ctx, traversal)
    assert link_reasons(dos, traversal)  # the evidence overlaps: the engine links them
    create_consolidate_tasks(ctx)
    [(task_id, _)] = consolidate_tasks(ctx)
    distinct = [
        {"id": fid(1), "reason": "Unbounded copy: needs a quota."},
        {"id": fid(2), "reason": "Symlink following: needs followlinks=False."},
    ]
    complete(ctx, task_id, distinct=distinct)
    summary = merge_run(ctx.run_dir)
    assert summary["duplicates_folded"] == 0
    assert summary["by_verdict"]["confirmed"] == 2
    assert all(
        "duplicate_of" not in item and "related" not in item
        for item in findings_by_id(ctx).values()
    )


def test_the_report_counts_leave_the_duplicates_out(ctx):
    folded_run(ctx)
    model = build_model(ctx.run_dir, installed_tools=None)
    assert model.verdict_counts() == {"confirmed": 1, "needs_validation": 0, "rejected": 0}
    assert model.severity_counts()["high"] == 1 and model.severity_counts()["medium"] == 0
    # By primary, then by title (":11" sorts before ":7").
    assert [item["id"] for item in model.duplicates] == [fid(3), fid(1)]
    assert model.review_counts()["not_reviewed"] == 1
    summary = build_summary(model, lang="tr")
    assert summary["counts"]["findings"] == 1
    assert summary["counts"]["duplicates_folded"] == 2
    assert summary["counts"]["by_verdict"]["needs_validation"] == 0

    markdown = render_markdown(model, "tr")
    assert "2 kayıt başka bir bulguyla aynı kök nedeni paylaşıyor." in markdown
    assert "| Doğrulanan bulgu | 1 |" in markdown
    assert "| Doğrulama bekleyen | 0 |" in markdown
    assert f"| Aynı kök neden | `{fid(1)}` hardcoded-secrets at app/captcha.py:7; `{fid(3)}`" in (
        markdown
    )
    appendix = markdown.split("### A.4 Birleştirilen tekrar kayıtlar", 1)[1]
    assert f"| `{fid(1)}` |" in appendix and f"`{fid(2)}` hardcoded-secrets" in appendix
    listing = markdown.split("### 1.1", 1)[1].split("## 2.", 1)[0]
    assert fid(2) in listing and fid(1) not in listing and fid(3) not in listing
    english = render_markdown(model, "en")
    assert "Records that share the root cause of another finding: 2." in english
    assert "### A.4 Folded duplicate records" in english

    page = render_html(model, "tr")
    assert f'<a class="id" href="#f-{fid(1)}">{fid(1)}</a>' in page
    assert f'<span class="id" id="f-{fid(1)}">{fid(1)}</span>' in page
    assert f'<a class="id" href="#f-{fid(2)}">{fid(2)}</a>' in page  # the primary link
    executive = render_executive(model, "tr")
    assert "Doğrulanan bulgular: 1" in executive
    assert "2 tekrar kayıt, birincil bulgunun altına alındı." in executive


def test_sarif_suppresses_the_duplicates(ctx):
    folded_run(ctx)
    model = build_model(ctx.run_dir, installed_tools=None)
    results = {
        item["properties"]["findingId"]: item for item in build_sarif(model)["runs"][0]["results"]
    }
    assert len(results) == 3  # duplicates stay results
    assert "suppressions" not in results[fid(2)]
    for duplicate in (fid(1), fid(3)):
        assert results[duplicate]["suppressions"] == [
            {"kind": "external", "status": "accepted", "justification": f"duplicate of {fid(2)}"}
        ]
        assert results[duplicate]["properties"]["duplicateOf"] == fid(2)


def test_the_validator_checks_the_duplicate_fields():
    finding = record(1, "authn", "app/a.py", 10)
    assert validate_findings([{**finding, "duplicate_of": fid(1), "duplicate_reason": "x"}])
    assert validate_findings([{**finding, "duplicate_of": fid(2)}])  # no reason
    assert validate_findings([{**finding, "duplicate_reason": "x"}])  # no duplicate_of
    related = [{"id": fid(3), "title": "t", "reason": "r"}]
    both = {**finding, "duplicate_of": fid(2), "duplicate_reason": "x", "related": related}
    assert validate_findings([both])
    assert validate_findings([{**finding, "related": related}]) == []
    rejected = record(4, "authn", "app/a.py", 10, verdict="rejected")
    assert validate_findings([{**rejected, "duplicate_of": fid(2), "duplicate_reason": "x"}])


# ---------------------------------------------------------------------------------------------
# run reopen and older run states


def finish(ctx):
    with state.transaction(ctx) as tx:
        tx.state["phase"] = "done"
        for name in ("validate", "poc", "merge", "report", "done"):
            tx.state["phases"][name].update(
                status="done", started_at=ids.format_ts(), finished_at=ids.format_ts()
            )
        tx.state["phases"]["validate"]["steps"] = {
            budget.REVIEW_STEP: {"status": "done", "detail": ""},
        }
        tx.state["phases"]["merge"]["steps"] = {"merge": {"status": "done", "detail": ""}}
        tx.state["phases"]["report"]["steps"] = {"report:tr": {"status": "done", "detail": ""}}
        tx.state["answers"] = {"english_report": "no"}


def test_reopen_refuses_while_a_task_is_leased(ctx):
    finish(ctx)
    task_id = queue.create_task(ctx, "verify", "validate", {})
    queue.claim(ctx, "worker", 1, phases=["validate"])
    with pytest.raises(StateError, match="tasks are leased"):
        phases.reopen(ctx, "consolidate")
    assert ctx.reload()["phase"] == "done"
    queue.release(ctx, task_id)
    assert phases.reopen(ctx, "consolidate")["reopened"] is True


def test_reopen_moves_a_finished_run_back_and_is_idempotent(ctx):
    finish(ctx)
    outcome = phases.reopen(ctx, "consolidate")
    assert outcome == {
        "run_id": ctx.run_id,
        "step": "consolidate",
        "previous_phase": "done",
        "phase": "validate",
        "reopened": True,
    }
    current = ctx.reload()
    validate = current["phases"]["validate"]
    assert validate["status"] == "running" and validate["finished_at"] is None
    # Polish follows consolidate, so it is pending again too.
    assert list(validate["steps"]) == [budget.REVIEW_STEP, "consolidate", "polish"]
    assert validate["steps"]["consolidate"] == {"status": "pending", "detail": ""}
    assert validate["steps"]["polish"] == {"status": "pending", "detail": ""}
    for later in ("poc", "merge", "report", "done"):
        assert current["phases"][later] == {
            "status": "pending",
            "started_at": None,
            "finished_at": None,
            "steps": {},
        }
    assert current["answers"] == {"english_report": "no"}
    again = phases.reopen(ctx, "consolidate")
    assert again["reopened"] is False and again["previous_phase"] == "validate"
    assert ctx.reload() == current  # nothing saved
    kinds = [event["kind"] for event in events.read_events(ctx.run_dir)]
    assert kinds.count("run_reopened") == 1
    # The run flows on: the step runs, then poc, merge and report again.
    assert phases.next_action(ctx, "orchestrator") == {
        "kind": "engine_step",
        "phase": "validate",
        "step": "consolidate",
    }


def test_reopen_before_validate_changes_nothing_and_rejects_other_steps(ctx):
    with state.transaction(ctx) as tx:
        tx.state["phase"] = "hunt"
    assert phases.reopen(ctx, "consolidate")["reopened"] is False
    assert ctx.reload()["phase"] == "hunt"
    with pytest.raises(ValidationError):
        phases.reopen(ctx, "merge")


def test_run_reopen_command(ctx, capsys):
    finish(ctx)
    code = main(["run", "reopen", "--run", ctx.run_id, "--step", "consolidate", "--json"])
    output = json.loads(capsys.readouterr().out)
    assert code == 0 and output["reopened"] is True and output["phase"] == "validate"
    code = main(["run", "reopen", "--run", ctx.run_id, "--step", "consolidate"])
    assert code == 0 and "Nothing to reopen" in capsys.readouterr().err
    with pytest.raises(SystemExit):
        main(["run", "reopen", "--run", ctx.run_id, "--step", "review:tasks"])


def test_an_older_run_in_validate_gets_the_step(ctx):
    with state.transaction(ctx) as tx:
        record_ = tx.state["phases"]["validate"]
        record_["status"] = "running"
        record_["steps"] = {budget.REVIEW_STEP: {"status": "done", "detail": ""}}
    action = phases.next_action(ctx, "orchestrator")
    assert action == {"kind": "engine_step", "phase": "validate", "step": "consolidate"}
    added = [e for e in events.read_events(ctx.run_dir) if e["kind"] == "step_added"]
    assert [(e["phase"], e["step"]) for e in added] == [
        ("validate", "consolidate"),
        ("validate", "polish"),
    ]
    steps_now = ctx.reload()["phases"]["validate"]["steps"]
    assert list(steps_now) == [budget.REVIEW_STEP, "consolidate", "polish"]


def test_an_older_run_after_validate_is_not_changed(ctx):
    with state.transaction(ctx) as tx:
        tx.state["phase"] = "poc"
        tx.state["phases"]["validate"].update(status="done")
        tx.state["phases"]["validate"]["steps"] = {
            budget.REVIEW_STEP: {"status": "done", "detail": ""}
        }
    action = phases.next_action(ctx, "orchestrator")
    assert action == {"kind": "engine_step", "phase": "poc", "step": "poc:skip"}
    assert "consolidate" not in ctx.reload()["phases"]["validate"]["steps"]


def test_the_consolidator_agent_files_exist():
    root = Path(__file__).resolve().parents[2]
    for folder in (".claude/agents", "plugins/kalkan/agents"):
        text = (root / folder / "kalkan-consolidator.md").read_text(encoding="utf-8")
        assert "tools: Read, Grep, Glob, Write" in text
    assert (root / ".codex" / "agents" / "kalkan-consolidator.toml").is_file()
    assert queue.AGENTS["consolidate"] == "kalkan-consolidator"


def test_a_passed_poc_of_a_folded_record_stays_visible_on_the_primary():
    from kalkan.report import i18n  # noqa: PLC0415

    primary = record(1, "authn", "app/a.py", 10, overall="high")
    folded = record(2, "authn", "app/a.py", 11, overall="medium")
    folded["poc"] = {"level": "unit", "status": "passed", "observed_result": "x", "artifacts": []}
    stats = fold_groups([primary, folded], [("g", {"ids": [fid(1), fid(2)], "reason": "Same."})])
    assert stats.applied == 1 and folded["duplicate_of"] == fid(1)
    assert primary["related"][0]["poc_status"] == "passed"
    assert "poc" not in primary  # the primary keeps its own fields
    assert validate_findings([primary]) == []
    text = i18n.runtime_validation("en", primary.get("poc"), primary["related"])
    assert text.startswith("Not performed")
    assert f"The PoC of {fid(2)}, a record with the same root cause" in text
    # A record without a PoC adds no poc_status.
    other = record(3, "sqli", "app/b.py", 1)
    other2 = record(4, "sqli", "app/b.py", 2)
    fold_groups([other, other2], [("h", {"ids": [fid(3), fid(4)], "reason": "Same."})])
    assert "poc_status" not in other["related"][0]
