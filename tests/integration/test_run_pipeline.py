# SPDX-License-Identifier: MIT
"""End-to-end run of the phase engine on a copy of tests/fixtures/targets/webapp.

The loop is driven through ``kalkan.cli.main`` exactly as the ``/kalkan`` skill drives it:
``run init``, then ``run next`` → ``run step`` or fake agents + ``task complete`` → ... →
``ask_user`` → ``run answer english_report no`` → ``done``. A fake agent writes a schema-valid
result for every claimed task; its quotes come from the real fixture lines, so quote
verification passes where the fake agent intends it to. The fake reviewer verifies the
confirmed record, downgrades the IDOR record and rejects every other record with a quote of
the bound parameter. The fake verifier writes the description and the root cause in Turkish
without the Turkish letters; the fake polisher restores the description and, in the root cause,
also changes a code token, which the engine rejects.

External tools are replaced: every scanner except the built-in matcher returns ``skipped``; the
SBOM step fails (no tool); the match step writes one high vulnerability record with the real
``kalkan.sca.merge`` writers. Merge and report are the real modules.

A crash in the middle (dropped objects, a stale run lock, a dead completion marker and a dead
running step) followed by ``run resume`` must neither lose nor repeat a task.
"""

from __future__ import annotations

import gc
import json
import re
import shutil
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from kalkan.cli import main
from kalkan.errors import ToolError
from kalkan.findings.ledger import validate_ledger_file
from kalkan.findings.merge import merge_run
from kalkan.findings.validate import validate_findings_file
from kalkan.run import events, ids, lock, state

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
DEAD_PID = 999_999
QUOTE_ROUTE = '@app.route("/users")'
QUOTE_INPUT = 'user_id = request.args.get("id")'
QUOTE_SINK = 'conn.execute("SELECT name FROM users WHERE id = ?"'
QUOTE_IMPORT = "from flask import Flask, request"
QUOTE_BINDING = "(user_id,)"
# Turkish prose without the Turkish letters (as a careless agent writes it) and its repair.
PLAIN_DESCRIPTION = "Kiraci kimligi dogrulanmadan `user_id` degeri sorguya ulasir."
POLISHED_DESCRIPTION = "Kiracı kimliği doğrulanmadan `user_id` değeri sorguya ulaşır."
PLAIN_ROOT_CAUSE = "Handler `user_id` degerini sahiplik kontrolu olmadan kullanir."
TURKISH_WORDS = {
    "Kiraci": "Kiracı",
    "kimligi": "kimliği",
    "dogrulanmadan": "doğrulanmadan",
    "degeri": "değeri",
    "ulasir": "ulaşır",
    "degerini": "değerini",
    "kontrolu": "kontrolü",
    "kullanir": "kullanır",
}
CHECKLISTS = {
    "confirmed": (
        "trace_and_evidence",
        "entry_interface",
        "conditions_and_controls",
        "impact",
        "severity",
        "remediation",
    ),
    "needs_validation": (
        "source_path",
        "blockers",
        "boundary_and_result",
        "validation_plan",
        "fingerprint",
    ),
}


# ---------------------------------------------------------------------------------------------
# CLI helpers


def cli(capsys, *argv: str) -> tuple[int, str, str]:
    code = main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def cli_json(capsys, *argv: str) -> Any:
    code, out, err = cli(capsys, *argv, "--json")
    assert code == 0, err
    return json.loads(out)


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------------------------
# Fake agent


def _recon(task_id: str, data: dict[str, Any]) -> dict[str, Any]:
    kind = data["kind"]
    surfaces = []
    classes: list[str] = []
    if kind == "surfaces":
        surfaces = [
            {
                "id": "http-users",
                "kind": "http",
                "name": "GET /users",
                "file": "app/routes.py",
                "line": 10,
                "auth": "none",
                "trust_boundary": "internet to application",
                "subsystem": "api",
                "notes": "",
            },
            {
                "id": "cfg-docker",
                "kind": "file",
                "name": "Dockerfile",
                "file": "Dockerfile",
                "line": None,
                "auth": "unknown",
                "trust_boundary": "build to runtime",
                "subsystem": "deployment",
                "notes": "",
            },
        ]
        classes = ["sqli", "idor"]
    elif kind == "product":
        surfaces = [  # the same route again: recon:merge removes the duplicate
            {
                "id": "users",
                "kind": "http",
                "name": "GET /users",
                "file": "app/routes.py",
                "line": 10,
                "auth": "none",
                "trust_boundary": "internet to application",
                "subsystem": "api",
                "notes": "",
            }
        ]
    return {
        "task_id": task_id,
        "kind": kind,
        "summary_md": f"Flask sample application ({kind}).",
        "facts": [
            {
                "statement": "The user lookup reads the id query parameter.",
                "evidence": [{"file": "app/routes.py", "line": 12, "quote": QUOTE_INPUT}],
            }
        ],
        "surfaces": surfaces,
        "classes_of_interest": classes,
        "sensitive_data": ["user names"],
        "uncertainties": [],
    }


def _candidate(coverage_id: str, slug: str) -> dict[str, Any]:
    titles = {"sqli": "SQL query built from the id parameter", "idor": "User lookup without owner"}
    return {
        "coverage_id": coverage_id,
        "title": titles[slug],
        "class": slug,
        "cwe": ["CWE-89"] if slug == "sqli" else ["CWE-639"],
        "description": f"Candidate {slug} in the user lookup.",
        "claimed_root_cause": "The handler trusts the id query parameter.",
        "trace": [
            {
                "kind": "entrypoint",
                "file": "app/routes.py",
                "line": 12,
                "scope": "users",
                "description": "Reads id from the query string.",
            },
            {
                "kind": "sink",
                "file": "app/routes.py",
                "line": 14,
                "scope": "users" if slug == "sqli" else "users-lookup",
                "description": "Runs the query with the value.",
            },
        ],
        "evidence": [{"file": "app/routes.py", "line": 14, "quote": QUOTE_SINK}],
        "suggested_severity": {"likelihood": "high", "impact": "high"},
        "dynamic_test": "",
        "related_candidates": [],
    }


def _hunt(task_id: str, data: dict[str, Any]) -> dict[str, Any]:
    units, candidates = [], []
    for unit in data["units"]:
        slug = unit["class"]
        status = "candidate" if slug in ("sqli", "idor") else "covered"
        units.append(
            {
                "coverage_id": unit["coverage_id"],
                "status": status,
                "checks": [
                    {
                        "reviewed_paths": ["app/routes.py", "./app/__init__.py"],
                        "invariant": f"The {slug} invariant holds for GET /users.",
                        "result": "Checked the handler and the query call.",
                    }
                ],
                "notes": "",
                "unresolved": [],
            }
        )
        if status == "candidate":
            candidates.append(_candidate(unit["coverage_id"], slug))
    return {
        "task_id": task_id,
        "units": units,
        "candidates": candidates,
        "hardening": [
            {"title": "Container runs as root", "file": "Dockerfile", "line": None, "note": "x"}
        ],
        "uncovered": [],
    }


def _critic(task_id: str, data: dict[str, Any]) -> dict[str, Any]:
    first = data["wave"] == 1
    return {
        "task_id": task_id,
        "missing_units": [
            {
                "surface_id": "S001",
                "class": "ssrf",
                "reason": "The handler module also builds outbound URLs.",
                "starting_paths": ["app/routes.py"],
            }
        ]
        if first
        else [],
        "reassign_ids": [{"coverage_id": "unknown-id", "reason": "Not a real unit."}],
        "stop": not first,
        "notes": "",
    }


def _answer(status: str, file: str, line: int, quote: str) -> dict[str, Any]:
    evidence = [{"file": file, "line": line, "quote": quote}] if status != "unknown" else []
    return {"status": status, "reason": f"Answer {status}.", "evidence": evidence}


def _verify(task_id: str, data: dict[str, Any]) -> dict[str, Any]:
    claim = data["claim"]
    slug = claim.get("class") or "code-injection"
    confirmed = slug == "sqli" and data["subject"]["kind"] == "hunter"
    trace = claim.get("trace") or [
        {
            "kind": "sink",
            "file": claim.get("file") or "app/routes.py",
            "line": claim.get("start_line") or 14,
            "scope": "users",
            "description": "The flagged line.",
        }
    ]
    finding: dict[str, Any] = {
        "title": claim.get("title") or "Claim",
        "description": PLAIN_DESCRIPTION,
        "class": slug,
        "cwe": claim.get("cwe") or [],
        "root_cause": PLAIN_ROOT_CAUSE,
        "trace": trace,
        "evidence": [
            {"file": "app/routes.py", "line": 14, "description": "The query runs with user_id."}
        ],
        "blockers": ["Whether a gateway enforces ownership is not visible in source."],
        "validation_plan": {"local": "Request /users?id=2 as user 1 with a test database."},
        "reason": "Answers follow the quoted lines.",
    }
    if confirmed:
        finding.update(
            intended_behavior="Only bound parameters reach the query.",
            conditions=[{"kind": "network_routing", "description": "The route is reachable."}],
            execution={
                "attacker_perspective": "An anonymous client.",
                "payloads": ["1 OR 1=1"],
                "instructions": ["Request GET /users?id=1%20OR%201=1."],
                "observed_result": "The payload reaches conn.execute.",
            },
            remediation={"strategy": "Keep the bound parameter and validate the id."},
            severity={
                "likelihood": {"score": "high", "reason": "Anyone can call the route."},
                "impact": {"score": "medium", "reason": "Reads user names."},
                "overall_severity": "high",
            },
            confidence={"score": "high", "reason": "Clear in source."},
        )
    second = "established" if confirmed else "unknown"
    return {
        "task_id": task_id,
        "subject": data["subject"],
        "audit_answers": {
            "attacker_control": _answer("established", "app/routes.py", 12, QUOTE_INPUT),
            "privilege_boundary": _answer(second, "app/routes.py", 10, QUOTE_ROUTE),
            "unmitigated": _answer("established", "app/routes.py", 14, QUOTE_SINK),
        },
        "finding": finding,
        "duplicate_of": None,
    }


def _sca_reach(task_id: str, data: dict[str, Any]) -> dict[str, Any]:
    return {
        "task_id": task_id,
        "vuln_ref": data["vuln_ref"],
        "reachability": "reachable",
        "reason": "The application imports flask and serves sessions.",
        "evidence": [{"file": "app/routes.py", "line": 4, "quote": QUOTE_IMPORT}],
        "searched": ["from flask import"],
    }


def _review(task_id: str, data: dict[str, Any]) -> dict[str, Any]:
    verdict = data["subject"]["verdict"]
    record = data["finding"]
    assert "audit_answers" not in record and "engines" not in record
    assert data["checklist"] == list(CHECKLISTS[verdict])
    if verdict == "confirmed":
        decision, quote = "verified", (14, QUOTE_SINK)
    elif record["class"] == "idor":
        decision, quote = "downgrade", (14, QUOTE_SINK)
    else:
        decision, quote = "reject", (14, QUOTE_BINDING)
    return {
        "task_id": task_id,
        "finding_id": data["subject"]["finding_id"],
        "decision": decision,
        "reason": f"Fresh review: {decision}.",
        "checks": [
            {"item": item, "ok": decision == "verified", "note": "Read app/routes.py."}
            for item in data["checklist"]
        ],
        "evidence": [{"file": "app/routes.py", "line": quote[0], "quote": quote[1]}],
    }


def _consolidate(task_id: str, data: dict[str, Any]) -> dict[str, Any]:
    """Fold the IDOR record into the SQL injection record (one quoted query call); keep every
    other record distinct."""
    records = data["records"]
    assert len(records) >= 2 and data["links"]
    by_class = {record["class"]: record["id"] for record in records}
    groups = []
    if "sqli" in by_class and "idor" in by_class:
        groups.append(
            {
                "ids": [by_class["idor"], by_class["sqli"]],
                "reason": "Both records describe the one query call that trusts the id value.",
                "evidence": [{"file": "app/routes.py", "line": 14, "quote": QUOTE_SINK}],
            }
        )
    grouped = {item for group in groups for item in group["ids"]}
    distinct = [
        {"id": record["id"], "reason": "A different flaw with its own fix."}
        for record in records
        if record["id"] not in grouped
    ]
    return {"task_id": task_id, "groups": groups, "distinct": distinct}


def _polish(task_id: str, data: dict[str, Any]) -> dict[str, Any]:
    """Restore the known Turkish words; English fields have nothing to restore and stay out. In
    a root cause the fake agent also changes the code token `user_id` (a slip)."""
    records = []
    for record in data["records"]:
        fields = []
        for item in record["fields"]:
            text = re.sub(
                r"[A-Za-z]+", lambda m: TURKISH_WORDS.get(m.group(), m.group()), item["text"]
            )
            if item["path"].endswith("root_cause"):
                text = text.replace("user_id", "user_ıd")
            if text != item["text"]:
                fields.append({"path": item["path"], "text": text})
        if fields:
            records.append({"id": record["id"], "fields": fields})
    return {"task_id": task_id, "records": records}


def _translate(task_id: str, data: dict[str, Any]) -> dict[str, Any]:
    return {
        "task_id": task_id,
        "translations": [
            {
                "id": item["id"],
                "title": f"EN: {item['title']}",
                "description": f"EN: {item['description']}",
                "remediation_strategy": "EN: fix it.",
            }
            for item in data["findings"]
        ],
    }


FAKE_AGENTS = {
    "recon": _recon,
    "hunt": _hunt,
    "critic": _critic,
    "verify": _verify,
    "review": _review,
    "consolidate": _consolidate,
    "polish": _polish,
    "sca_reach": _sca_reach,
    "translate": _translate,
}


def fake_agent(item: dict[str, str]) -> None:
    """Read the task input next to the result file and write a valid result."""
    result_file = Path(item["result_file"])
    assert Path(item["prompt_file"]).is_file()
    data = read_json(result_file.with_name("input.json"))
    result = FAKE_AGENTS[item["type"]](item["id"], data)
    result_file.write_text(json.dumps(result, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------------------------
# Environment


@pytest.fixture
def environment(tmp_path, monkeypatch):
    from kalkan.run import init as init_mod
    from kalkan.sca import commands as sca_commands
    from kalkan.sca.merge import write_candidates, write_vulns
    from kalkan.sca.normalize import new_record
    from kalkan.scanners import base

    monkeypatch.setenv(ids.RUNS_DIR_ENV, str(tmp_path / "runs"))
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
    monkeypatch.setattr(init_mod, "git_head", lambda directory: None)
    real_pid_alive = lock.pid_alive
    monkeypatch.setattr(lock, "pid_alive", lambda pid: pid != DEAD_PID and real_pid_alive(pid))
    real_run_adapter = base.run_adapter

    def run_adapter(adapter, ctx, *, timeout_seconds=None, **kwargs):
        if adapter.name == "matcher":
            return real_run_adapter(adapter, ctx, timeout_seconds=timeout_seconds)
        return base.ScanResult(
            engine=adapter.name,
            status="skipped",
            output_path=None,
            message="tool not installed (test)",
            duration_seconds=0.0,
            exit_code=None,
            tool_version=None,
        )

    def run_sbom(run_dir, *, offline=False, timeout_seconds=None):
        raise ToolError("no SBOM tool produced a CycloneDX SBOM (test)")

    def run_match(run_dir, *, offline=False, timeout_seconds=None):
        record = new_record(
            ecosystem="PyPI",
            package="flask",
            version="3.0.3",
            ids=["GHSA-m2qf-hxjv-5gpq", "CVE-2023-30861"],
            summary="Session cookie disclosure without a Vary: Cookie header.",
            cvss_score=7.5,
            locations=["requirements.txt"],
            engine="osv-scanner",
            fixed_versions=["3.0.4"],
        )
        write_vulns(run_dir, [record], [])
        write_candidates(run_dir, [record], [])
        return {"merged": 1, "by_severity": {"high": 1}}

    monkeypatch.setattr(base, "run_adapter", run_adapter)
    monkeypatch.setattr(sca_commands, "run_sbom", run_sbom)
    monkeypatch.setattr(sca_commands, "run_match", run_match)
    target = tmp_path / "webapp"
    shutil.copytree(FIXTURES / "targets" / "webapp", target)
    return target


class Driver:
    """Drive the run like the /kalkan skill and record what happened."""

    def __init__(self, capsys, run_dir: Path) -> None:
        self.capsys = capsys
        self.run_dir = run_dir
        self.phases: list[str] = []
        self.kinds: Counter[str] = Counter()
        self.completed: list[str] = []

    def ledger_ok(self) -> None:
        path = self.run_dir / "coverage-ledger.json"
        if path.exists():
            assert validate_ledger_file(path) == []

    def note_phase(self) -> None:
        phase = state.load_state(self.run_dir)["phase"]
        if not self.phases or self.phases[-1] != phase:
            self.phases.append(phase)

    def complete(self, task_id: str) -> None:
        output = cli_json(self.capsys, "task", "complete", task_id)
        assert output["status"] in ("done", "unchanged")
        self.completed.append(task_id)
        self.ledger_ok()

    def run(self, *, stop_after_claim: bool = False, rounds: int = 300) -> dict[str, Any]:
        for _ in range(rounds):
            action = cli_json(self.capsys, "run", "next", "--owner", "orchestrator")
            self.kinds[action["kind"]] += 1
            self.note_phase()
            kind = action["kind"]
            if kind == "engine_step":
                outcome = cli_json(self.capsys, "run", "step", "--max-seconds", "120")
                assert outcome["step"] == action["step"]
                assert outcome["status"] in ("done", "skipped", "failed"), outcome
            elif kind == "agent_tasks":
                if stop_after_claim:
                    return action
                for item in action["tasks"]:
                    fake_agent(item)
                for item in action["tasks"]:
                    self.complete(item["id"])
            elif kind == "wait":
                cli_json(self.capsys, "run", "resume")
            else:
                return action
        raise AssertionError("the run did not finish")


# ---------------------------------------------------------------------------------------------
# The test


def test_full_pipeline_with_crash_and_resume(environment, capsys):
    init = cli_json(
        capsys, "run", "init", str(environment), "--profile", "standard", "--lang", "tr"
    )
    run_dir = Path(init["run_dir"])
    driver = Driver(capsys, run_dir)

    # Run until the validation tasks are handed out, then crash in the middle.
    action = None
    while True:
        action = driver.run(stop_after_claim=True)
        assert action["kind"] == "agent_tasks"
        if action["phase"] == "validate":
            break
        for item in action["tasks"]:
            fake_agent(item)
        for item in action["tasks"]:
            driver.complete(item["id"])
    claimed = [item["id"] for item in action["tasks"]]
    assert len(claimed) >= 3  # two verify tasks and one sca_reach task
    fake_agent(action["tasks"][0])
    first = claimed[0]
    ctx = state.load_context()
    with state.transaction(ctx) as tx:
        tx.state["tasks"][first]["completing"] = {
            "pid": DEAD_PID,
            "host": lock.hostname(),
            "token": "crashed",
            "started_at": ids.format_ts(),
        }
    stale = datetime.now(UTC) - timedelta(seconds=lock.STALE_AFTER_SECONDS + 60)
    (run_dir / lock.LOCK_NAME).write_text(
        json.dumps({"pid": DEAD_PID, "host": lock.hostname(), "created_at": ids.format_ts(stale)}),
        encoding="utf-8",
    )
    del ctx, action
    gc.collect()

    resumed = cli_json(capsys, "run", "resume")
    assert resumed["resume"]["completed"] == [first]
    assert sorted(resumed["resume"]["released"]) == sorted(claimed[1:])
    driver.completed.append(first)

    # The run continues after the crash: validation, poc, merge, report, then the question.
    finished = driver.run()
    assert finished == {"kind": "ask_user", "question": "english_report"}
    cli_json(capsys, "run", "answer", "english_report", "no")
    done = driver.run()
    assert done["kind"] == "done"
    assert done["report"].endswith("report/REPORT.md")

    # Phases advanced in order.
    order = [phase for phase in driver.phases if phase in state.PHASES]
    assert order == sorted(order, key=state.PHASES.index)
    assert order[0] == "deterministic" and order[-1] == "done"
    assert {"recon", "hunt", "validate", "poc", "merge", "report"} <= set(order)

    final = state.load_state(run_dir)
    assert final["incomplete_reason"] is None
    statuses = Counter(task["status"] for task in final["tasks"].values())
    assert statuses == Counter({"done": len(final["tasks"])})
    # No task lost, none repeated: every task completed exactly once.
    completed_events = Counter(
        event["task"] for event in events.read_events(run_dir) if event["kind"] == "task_completed"
    )
    assert set(completed_events) == set(final["tasks"])
    assert all(count == 1 for count in completed_events.values())
    assert sorted(driver.completed) == sorted(final["tasks"])
    by_type = Counter(task["type"] for task in final["tasks"].values())
    assert by_type["recon"] == 4
    waves = Counter(
        task["meta"]["wave"] for task in final["tasks"].values() if task["type"] == "hunt"
    )
    assert waves[1] >= 1 and waves[2] == 1  # the critic of wave 1 scheduled wave 2
    assert by_type["critic"] == 2
    assert by_type["sca_reach"] == 1
    assert by_type["review"] >= 2  # one per final confirmed and needs_validation record
    reviewed = {
        task["meta"]["fingerprint"] for task in final["tasks"].values() if task["type"] == "review"
    }
    assert len(reviewed) == by_type["review"]

    # Steps: the failed SBOM step is recorded and the run continued.
    steps = {
        name: record["status"]
        for phase in final["phases"].values()
        for name, record in phase["steps"].items()
    }
    assert steps["sca:sbom"] == "failed"
    assert steps["sca:match"] == "done"
    assert steps["scan:matcher"] == "done"
    assert steps["review:tasks"] == "done"
    assert steps["poc:skip"] == "done"
    assert steps["merge"] == "done"
    assert steps["report:tr"] == "done"

    # Ledger stays valid; findings exist with both verdicts.
    driver.ledger_ok()
    ledger = read_json(run_dir / "coverage-ledger.json")
    assert {unit["status"] for unit in ledger} <= {"covered", "candidate", "deferred"}
    assert validate_findings_file(run_dir / "findings.json") == []
    findings = read_json(run_dir / "findings.json")
    verdicts = Counter(finding["verdict"] for finding in findings)
    assert verdicts["confirmed"] >= 1
    assert verdicts["needs_validation"] >= 1
    confirmed = next(finding for finding in findings if finding["verdict"] == "confirmed")
    assert confirmed["confidence"]["score"] == "medium"
    assert confirmed["severity"]["overall_severity"] == "medium"  # capped at the impact
    assert confirmed["poc"]["status"] == "blocked"
    assert confirmed["review"] == {"decision": "verified", "reason": "Fresh review: verified."}
    assert "reviewer" in confirmed["engines"]
    pending = next(finding for finding in findings if finding["verdict"] == "needs_validation")
    assert "sandbox_unavailable" in pending["blockers"]
    assert pending["class"] == "idor"
    assert pending["review"]["decision"] == "downgrade"
    assert "Fresh review: downgrade." in pending["blockers"]
    for finding in findings:
        if finding["verdict"] == "rejected" and "review" in finding:
            assert finding["reason"] == "Fresh review: reject."
            assert "poc" not in finding  # the PoC phase skips rejected records
    report = (run_dir / "report" / "REPORT.md").read_text(encoding="utf-8")
    assert "**Son inceleme.**" in report
    assert "| Son inceleme | Doğrulandı: Fresh review: verified. |" in report
    vulns = read_json(run_dir / "sca" / "vulns.json")
    assert vulns["records"][0]["reachability"] == "reachable"
    assert (run_dir / "report" / "REPORT.md").is_file()
    assert (run_dir / "recon" / "architecture.md").is_file()

    # Consolidation: the step ran after the reviews; the IDOR record (same query call) is a
    # duplicate of the confirmed SQL injection record, kept in findings.json and not counted.
    assert steps["consolidate"] == "done"
    consolidate_tasks = [t for t in final["tasks"].values() if t["type"] == "consolidate"]
    assert len(consolidate_tasks) == 1
    assert pending["duplicate_of"] == confirmed["id"]
    assert pending["duplicate_reason"].startswith("Both records describe")
    assert confirmed["related"] == [
        {
            "id": pending["id"],
            "title": pending["title"],
            "class": "idor",
            "reason": pending["duplicate_reason"],
            # The folded record's PoC status stays visible on the primary.
            "poc_status": pending["poc"]["status"],
        }
    ]
    summary = read_json(run_dir / "report" / "summary.json")
    assert summary["counts"]["duplicates_folded"] == 1
    assert summary["counts"]["by_verdict"]["confirmed"] == 1
    assert summary["counts"]["by_verdict"]["needs_validation"] == 0
    assert "Birleştirilen tekrar kayıtlar" in report
    assert f"| Aynı kök neden | `{pending['id']}`" in report
    sarif = read_json(run_dir / "report" / "findings.sarif")
    folded = next(
        result
        for result in sarif["runs"][0]["results"]
        if result["properties"].get("findingId") == pending["id"]
    )
    assert folded["suppressions"][0]["justification"] == f"duplicate of {confirmed['id']}"

    # Turkish letters: the polish step ran last in validate (one batch: the confirmed record
    # and its folded duplicate). The restored description is in findings.json and the report;
    # the root cause keeps its text because the agent also changed the code token `user_id`.
    assert list(final["phases"]["validate"]["steps"])[-1] == "polish"
    assert steps["polish"] == "done"
    polish_ids = [task_id for task_id, t in final["tasks"].items() if t["type"] == "polish"]
    assert len(polish_ids) == 1
    outcome = read_json(run_dir / "tasks" / polish_ids[0] / "polish.json")
    applied = {(item["id"], item["path"]) for item in outcome["applied"]}
    assert applied == {(confirmed["id"], "/description"), (pending["id"], "/description")}
    assert {(item["path"], item["reason"]) for item in outcome["rejected"]} == {
        ("/root_cause", "code_token_changed"),
        ("/claimed_root_cause", "code_token_changed"),
    }
    assert confirmed["description"] == POLISHED_DESCRIPTION
    assert pending["description"] == POLISHED_DESCRIPTION
    assert confirmed["root_cause"] == PLAIN_ROOT_CAUSE
    assert confirmed["id"] in {finding["id"] for finding in findings}  # ids never change
    for finding in findings:
        if finding["verdict"] == "rejected":  # rejected records are never polished
            assert finding["description"] == PLAIN_DESCRIPTION
    assert "Kiracı kimliği doğrulanmadan" in report  # the report escapes the backticks
    assert "Kiraci kimligi" not in report
    assert merge_run(run_dir, write=False)["polish_applied"] == 2

    # english_report yes after done reopens the report phase: translate, report:en, done.
    answered = cli_json(capsys, "run", "answer", "english_report", "yes")
    assert answered["reopened"] is True
    again = driver.run()
    assert again["kind"] == "done"
    final = state.load_state(run_dir)
    assert final["phases"]["report"]["steps"]["report:en"]["status"] == "done"
    assert any(task["type"] == "translate" for task in final["tasks"].values())
    assert (run_dir / "report" / "REPORT.en.md").is_file()
    english = read_json(run_dir / "findings.json")
    assert all(finding["i18n"]["en"]["title"].startswith("EN: ") for finding in english)

    # run reopen --step consolidate puts the finished run back into validate; run next runs the
    # step again (the existing task is reused), then merge, report and done follow again.
    tasks_before = set(final["tasks"])
    reopened = cli_json(capsys, "run", "reopen", "--step", "consolidate")
    assert reopened["reopened"] is True and reopened["previous_phase"] == "done"
    assert reopened["phase"] == "validate"
    again = cli_json(capsys, "run", "reopen", "--step", "consolidate")
    assert again["reopened"] is False  # idempotent
    assert driver.run()["kind"] == "done"
    final = state.load_state(run_dir)
    assert set(final["tasks"]) == tasks_before
    assert final["phases"]["validate"]["steps"]["consolidate"]["status"] == "done"
    # Polish follows consolidate, so it ran again; it asked no field twice (no new task).
    assert final["phases"]["validate"]["steps"]["polish"]["status"] == "done"
    assert final["phases"]["report"]["steps"]["report:en"]["status"] == "done"
    assert [e["kind"] for e in events.read_events(run_dir)].count("run_reopened") == 1
    refolded = {finding["id"]: finding for finding in read_json(run_dir / "findings.json")}
    assert refolded[pending["id"]]["duplicate_of"] == confirmed["id"]
    assert refolded[confirmed["id"]]["description"] == POLISHED_DESCRIPTION

    # run reopen --step polish runs only the polish step again, then merge, report and done.
    reopened = cli_json(capsys, "run", "reopen", "--step", "polish")
    assert reopened["reopened"] is True and reopened["step"] == "polish"
    validate = state.load_state(run_dir)["phases"]["validate"]["steps"]
    assert validate["consolidate"]["status"] == "done"
    assert validate["polish"]["status"] == "pending"
    assert cli_json(capsys, "run", "reopen", "--step", "polish")["reopened"] is False
    assert driver.run()["kind"] == "done"
    final = state.load_state(run_dir)
    assert set(final["tasks"]) == tasks_before
    assert final["phases"]["validate"]["steps"]["polish"]["status"] == "done"
    repolished = {finding["id"]: finding for finding in read_json(run_dir / "findings.json")}
    assert repolished[confirmed["id"]]["description"] == POLISHED_DESCRIPTION


def test_crashed_engine_step_runs_again(environment, capsys):
    init = cli_json(capsys, "run", "init", str(environment), "--profile", "fast", "--lang", "tr")
    run_dir = Path(init["run_dir"])
    action = cli_json(capsys, "run", "next", "--owner", "orchestrator")
    assert action["kind"] == "engine_step"
    ctx = state.load_context()
    with state.transaction(ctx) as tx:
        record = tx.state["phases"][action["phase"]]["steps"][action["step"]]
        record.update(
            status="running",
            pid=DEAD_PID,
            host=lock.hostname(),
            started_at=ids.format_ts(),
            timeout_seconds=480,
            attempts=1,
        )
    again = cli_json(capsys, "run", "next", "--owner", "orchestrator")
    assert again == action
    outcome = cli_json(capsys, "run", "step")
    assert outcome["step"] == action["step"]
    record = state.load_state(run_dir)["phases"][action["phase"]]["steps"][action["step"]]
    assert record["attempts"] == 2
    assert record["status"] == outcome["status"]
    assert "pid" not in record


def test_fast_run_skips_the_final_review(environment, capsys):
    init = cli_json(capsys, "run", "init", str(environment), "--profile", "fast", "--lang", "tr")
    run_dir = Path(init["run_dir"])
    driver = Driver(capsys, run_dir)
    assert driver.run() == {"kind": "ask_user", "question": "english_report"}
    cli_json(capsys, "run", "answer", "english_report", "no")
    assert driver.run()["kind"] == "done"
    final = state.load_state(run_dir)
    assert not [task for task in final["tasks"].values() if task["type"] == "review"]
    step = final["phases"]["validate"]["steps"]["review:tasks"]
    assert step["status"] == "skipped" and step["detail"].startswith("fast profile")
    # Quick has no review step: consolidation follows the verify and sca_reach tasks.
    assert final["phases"]["validate"]["steps"]["consolidate"]["status"] == "done"
    assert any(task["type"] == "consolidate" for task in final["tasks"].values())
    # Polish follows the last validation step of fast too.
    assert list(final["phases"]["validate"]["steps"])[-1] == "polish"
    assert final["phases"]["validate"]["steps"]["polish"]["status"] == "done"
    findings = read_json(run_dir / "findings.json")
    assert findings and all("review" not in finding for finding in findings)
    kept = [finding for finding in findings if finding["verdict"] != "rejected"]
    assert kept and all(finding["description"] == POLISHED_DESCRIPTION for finding in kept)
    report = (run_dir / "report" / "REPORT.md").read_text(encoding="utf-8")
    assert "`fast` profilinde ayrı bir son inceleme yok." in report
