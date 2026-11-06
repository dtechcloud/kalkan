# SPDX-License-Identifier: MIT
"""Budget simulation of the first live ``/kalkan`` audit (run 20261016T062010Z-shop-c47c).

The live run audited a 403-line Flask shop with about 19 planted vulnerabilities on the fast
profile (40 agent tasks). Four recon agents named the same subsystems in different ways
(``shop/accounts`` and ``accounts``, ``config`` and ``configuration``), the planner built 210
ledger units, 23 hunt tasks ran, the hunters reported 22 unique fingerprints, and only 4 of
them got a verify task: the run ended ``incomplete: validation_budget_exhausted``.

This test rebuilds that situation on a synthetic shop with the same files and fingerprints:

- fake recon agents return about 12 distinct surfaces with inconsistent subsystem names;
- the deterministic scan reports 14 critical or high tool results, the SCA match reports 8
  critical or high records of two packages;
- a fake hunter reports every planted vulnerability whose class and file fit its unit (22
  unique fingerprints, more candidates when two units cover the same file);
- fake verifiers sometimes label the trace in the wrong order (as in T0032 and T0034).

The engine runs exactly as ``run next`` / ``run step`` / ``task complete`` drive it.

Measured before the fix (same simulation): 209 units (140 deferred), 23 hunt tasks, 35
candidates with 19 unique fingerprints, 4 of them with a verify task (21 %), 4 sca_reach tasks
for one package, 39 of 40 tasks used. After the fix: 31 units at the ``folder`` level (none
deferred), 6 hunt tasks, 22 unique fingerprints, all 22 with a verify task, 4 sca_reach tasks
for two packages, 38 of 40 tasks used.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

from kalkan.errors import ToolError
from kalkan.findings.ledger import validate_ledger_file
from kalkan.findings.validate import validate_findings_file
from kalkan.run import ids, phases, queue, state, steps
from kalkan.run.init import init_run

# (class, file, scope, sink line, likelihood, impact)
PLANTED: tuple[tuple[str, str, str, int, str, str], ...] = (
    ("jwt", "shop/accounts.py", "profile", 20, "high", "high"),
    ("nosqli", "shop/accounts.py", "find_users", 26, "high", "high"),
    ("crypto", "shop/accounts.py", "register", 32, "medium", "medium"),
    ("authn", "shop/accounts.py", "change_password", 38, "high", "high"),
    ("business-logic", "shop/accounts.py", "change_password", 40, "medium", "medium"),
    ("idor", "shop/accounts.py", "get_order", 46, "high", "medium"),
    ("missing-authz", "shop/accounts.py", "delete_user", 52, "high", "high"),
    ("path-traversal", "shop/files.py", "invoice", 20, "high", "high"),
    ("path-traversal", "shop/files.py", "note", 26, "high", "high"),
    ("authn", "shop/files.py", "receipt", 32, "medium", "medium"),
    ("sqli", "shop/app.py", "search_products", 20, "high", "critical"),
    ("ssti", "shop/app.py", "greeting", 26, "high", "critical"),
    ("xss", "shop/app.py", "search_page", 32, "high", "medium"),
    ("open-redirect", "shop/app.py", "continue_login", 38, "medium", "low"),
    ("cors", "shop/app.py", "cart", 44, "low", "low"),
    ("os-command-injection", "shop/tools.py", "ping", 20, "critical", "critical"),
    ("code-injection", "shop/tools.py", "calc", 26, "critical", "critical"),
    ("deserialization", "shop/tools.py", "restore_session", 32, "high", "critical"),
    ("deserialization", "shop/tools.py", "import_config", 38, "high", "critical"),
    ("ssrf", "shop/tools.py", "fetch", 44, "high", "high"),
    ("xxe", "shop/tools.py", "import_xml", 50, "high", "high"),
    ("authn", "shop/tools.py", "restore_session", 34, "medium", "high"),
)
ROUTES: dict[str, list[tuple[str, int, str]]] = {
    "shop/app.py": [
        ("GET /products/search", 18, "search_products"),
        ("GET /greeting", 24, "greeting"),
        ("GET /search", 30, "search_page"),
        ("GET /login/continue", 36, "continue_login"),
        ("GET /api/cart", 42, "cart"),
    ],
    "shop/accounts.py": [
        ("GET /api/profile", 18, "profile"),
        ("POST /api/users/find", 24, "find_users"),
        ("POST /api/register", 30, "register"),
        ("POST /api/password", 36, "change_password"),
        ("GET /api/orders/<id>", 44, "get_order"),
        ("DELETE /api/admin/users/<id>", 50, "delete_user"),
    ],
    "shop/files.py": [
        ("GET /files/invoice", 18, "invoice"),
        ("GET /files/note", 24, "note"),
        ("GET /files/receipt", 30, "receipt"),
    ],
    "shop/tools.py": [
        ("GET /tools/ping", 18, "ping"),
        ("GET /tools/calc", 24, "calc"),
        ("POST /tools/session/restore", 30, "restore_session"),
        ("POST /tools/import/config", 36, "import_config"),
        ("GET /tools/fetch", 42, "fetch"),
        ("POST /tools/import/xml", 48, "import_xml"),
    ],
}
RUN_CLASSES = [
    "authn",
    "business-logic",
    "code-injection",
    "cors",
    "crypto",
    "csrf",
    "deserialization",
    "iac-cloud-container",
    "idor",
    "jwt",
    "missing-authz",
    "nosqli",
    "open-redirect",
    "os-command-injection",
    "path-traversal",
    "rate-limit-bruteforce",
    "security-misconfig",
    "sqli",
    "ssrf",
    "ssti",
    "supply-chain-cicd",
    "vulnerable-dependency",
    "xss",
    "xxe",
]


def sink_code(slug: str, scope: str) -> str:
    return f"sink_{scope}_{slug.replace('-', '_')}(request.args)"


def build_target(root: Path) -> Path:
    """Write the synthetic shop: route lines, sink lines and filler lines."""
    target = root / "shop-target"
    files: dict[str, list[str]] = {}
    for path in ("shop/app.py", "shop/accounts.py", "shop/files.py", "shop/tools.py"):
        files[path] = [f"# {path} line {number}" for number in range(1, 61)]
    files["shop/storage.py"] = [f"# storage line {number}" for number in range(1, 21)]
    files["shop/storage.py"][7] = 'DB_PATH = os.environ.get("SHOP_DB", "shop.db")'
    for path, routes in ROUTES.items():
        for name, line, scope in routes:
            method, url = name.split(" ", 1)
            files[path][line - 1] = f'@app.route("{url}", methods=["{method}"])'
            files[path][line] = f"def {scope}(request):"
    for slug, path, scope, line, _, _ in PLANTED:
        files[path][line - 1] = f"    {sink_code(slug, scope)}"
    for path, lines in files.items():
        file = target / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    (target / "shop" / "__init__.py").write_text("", encoding="utf-8")
    (target / "Dockerfile").write_text(
        "FROM python:3.12\nCOPY . /app\nRUN pip install -r requirements.txt\n", encoding="utf-8"
    )
    (target / "requirements.txt").write_text("django==3.2.0\nflask==1.0\n", encoding="utf-8")
    return target


# ---------------------------------------------------------------------------------------------
# Fake agents


def _surface(sid, kind, name, file, line, auth, subsystem, boundary="internet to application"):
    return {
        "id": sid,
        "kind": kind,
        "name": name,
        "file": file,
        "line": line,
        "auth": auth,
        "trust_boundary": boundary,
        "subsystem": subsystem,
        "notes": "",
    }


def recon_surfaces(kind: str) -> list[dict[str, Any]]:
    """Return the surfaces of one recon kind; the kinds name the subsystems differently."""
    if kind == "surfaces":
        found = []
        for path, routes in ROUTES.items():
            label = path.removesuffix(".py")  # shop/app, shop/accounts, ...
            for name, line, scope in routes[:3]:
                found.append(_surface(f"s-{scope}", "http", name, path, line, "none", label))
        return found
    if kind == "product":
        return [
            _surface(
                "p-front", "http", "/, /search, /greeting", "shop/app.py", 18, "none", "frontend"
            ),
            _surface(
                "p-acc", "http", "/api/* accounts", "shop/accounts.py", 18, "none", "accounts"
            ),
            _surface("p-files", "http", "/files/*", "shop/files.py", 18, "none", "files"),
            _surface("p-tools", "http", "/tools/*", "shop/tools.py", 18, "none", "tools"),
        ]
    if kind == "execution":
        return [
            _surface(
                "e-env", "other", "environment variables", "shop/storage.py", 8, "unknown", "config"
            ),
            _surface(
                "e-docker",
                "file",
                "Dockerfile",
                "Dockerfile",
                1,
                "unknown",
                "deployment",
                "build to runtime",
            ),
        ]
    return [  # principals
        _surface(
            "r-env",
            "other",
            "environment secrets",
            "shop/storage.py",
            8,
            "privileged",
            "configuration",
        ),
    ]


def fake_recon(task_id: str, data: dict[str, Any]) -> dict[str, Any]:
    kind = data["kind"]
    return {
        "task_id": task_id,
        "kind": kind,
        "summary_md": f"Synthetic Flask shop ({kind}).",
        "facts": [],
        "surfaces": recon_surfaces(kind),
        "classes_of_interest": RUN_CLASSES,
        "sensitive_data": [],
        "uncertainties": [],
    }


def planted_for(unit: dict[str, Any]) -> list[tuple[str, str, str, int, str, str]]:
    paths = set(unit["starting_paths"])
    return [item for item in PLANTED if item[0] == unit["class"] and item[1] in paths]


def fake_hunt(task_id: str, data: dict[str, Any]) -> dict[str, Any]:
    units, candidates = [], []
    for unit in data["units"]:
        found = planted_for(unit)
        units.append(
            {
                "coverage_id": unit["coverage_id"],
                "status": "candidate" if found else "covered",
                "checks": [
                    {
                        "reviewed_paths": list(unit["starting_paths"]),
                        "invariant": f"No {unit['class']} sink takes request data.",
                        "result": f"Checked {len(unit['starting_paths'])} files.",
                    }
                ],
                "notes": "",
                "unresolved": [],
            }
        )
        for slug, path, scope, line, likelihood, impact in found:
            code = sink_code(slug, scope)
            candidates.append(
                {
                    "coverage_id": unit["coverage_id"],
                    "title": f"{slug} in {scope}",
                    "class": slug,
                    "cwe": [],
                    "description": f"Request data reaches the {slug} sink in {scope}.",
                    "claimed_root_cause": "The handler passes request data to the sink.",
                    "trace": [
                        {
                            "kind": "entrypoint",
                            "file": path,
                            "line": line - 2 if line > 2 else 1,
                            "scope": scope,
                            "description": "The route reads request data.",
                        },
                        {
                            "kind": "sink",
                            "file": path,
                            "line": line,
                            "scope": scope,
                            "description": "The sink uses the data.",
                        },
                    ],
                    "evidence": [{"file": path, "line": line, "quote": code}],
                    "suggested_severity": {"likelihood": likelihood, "impact": impact},
                    "dynamic_test": "",
                    "related_candidates": [],
                }
            )
    return {
        "task_id": task_id,
        "units": units,
        "candidates": candidates,
        "hardening": [],
        "uncovered": [],
    }


def fake_critic(task_id: str, data: dict[str, Any]) -> dict[str, Any]:
    return {
        "task_id": task_id,
        "missing_units": [],
        "reassign_ids": [],
        "stop": True,
        "notes": "",
    }


def fake_verify(task_id: str, data: dict[str, Any]) -> dict[str, Any]:
    claim = data["claim"]
    trace = claim.get("trace") or [
        {
            "kind": "sink",
            "file": claim["file"],
            "line": claim["start_line"],
            "scope": "tool-result",
            "description": "The flagged line.",
        }
    ]
    evidence = [
        {"file": item["file"], "line": item["line"], "quote": item["quote"]}
        for item in claim.get("evidence", [])
    ]
    if len(trace) >= 2 and int(task_id[1:5]) % 2 == 0:
        # T0032/T0034: the agent labels the sink in the middle and a later step propagation.
        trace = [
            trace[0],
            {**trace[-1], "kind": "sink"},
            {**trace[-1], "kind": "propagation", "description": "The result goes back."},
        ]
    first = evidence[0] if evidence else None
    return {
        "task_id": task_id,
        "subject": data["subject"],
        "audit_answers": {
            "attacker_control": {
                "status": "established" if first else "unknown",
                "reason": "The route passes request data.",
                "evidence": [first] if first else [],
            },
            "privilege_boundary": {
                "status": "unknown",
                "reason": "The deployment is not visible.",
                "evidence": [],
            },
            "unmitigated": {
                "status": "established" if first else "unknown",
                "reason": "No check before the sink.",
                "evidence": [first] if first else [],
            },
        },
        "finding": {
            "title": claim.get("title") or "Claim",
            "description": "Request data reaches a sink.",
            "class": claim.get("class") or "code-injection",
            "cwe": [],
            "root_cause": "The handler trusts request data.",
            "trace": trace,
            "evidence": [
                {"file": item["file"], "line": item["line"], "description": "The sink."}
                for item in evidence
            ]
            or [{"file": trace[-1]["file"], "line": trace[-1]["line"], "description": "Sink."}],
            "validation_plan": {"local": "Call the route with a test payload."},
            "reason": "Answers follow the quoted lines.",
        },
        "duplicate_of": None,
    }


def fake_sca_reach(task_id: str, data: dict[str, Any]) -> dict[str, Any]:
    return {
        "task_id": task_id,
        "vuln_ref": data["vuln_ref"],
        "reachability": "unknown",
        "reason": "The vulnerable function is not visible.",
        "evidence": [],
        "searched": ["import"],
    }


def fake_consolidate(task_id: str, data: dict[str, Any]) -> dict[str, Any]:
    """Keep every record of the group distinct (the planted sinks are different flaws)."""
    return {
        "task_id": task_id,
        "groups": [],
        "distinct": [
            {"id": record["id"], "reason": "A different sink with its own fix."}
            for record in data["records"]
        ],
    }


def fake_polish(task_id: str, data: dict[str, Any]) -> dict[str, Any]:
    """Restore nothing (the sample texts are English)."""
    return {"task_id": task_id, "records": []}


AGENTS = {
    "recon": fake_recon,
    "hunt": fake_hunt,
    "critic": fake_critic,
    "verify": fake_verify,
    "consolidate": fake_consolidate,
    "polish": fake_polish,
    "sca_reach": fake_sca_reach,
}


def run_agent(item: dict[str, Any]) -> None:
    result_file = Path(item["result_file"])
    data = json.loads(result_file.with_name("input.json").read_text(encoding="utf-8"))
    result = AGENTS[item["type"]](item["id"], data)
    result_file.write_text(json.dumps(result, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------------------------
# Environment


def tool_candidates() -> list[dict[str, Any]]:
    """14 critical or high tool results, most of them on the planted sinks."""
    picks = [
        ("crypto", "shop/accounts.py", "register", 32, "bandit"),
        ("jwt", "shop/accounts.py", "profile", 20, "opengrep"),
        ("nosqli", "shop/accounts.py", "find_users", 26, "opengrep"),
        ("os-command-injection", "shop/tools.py", "ping", 20, "bandit"),
        ("os-command-injection", "shop/tools.py", "ping", 20, "opengrep"),
        ("code-injection", "shop/tools.py", "calc", 26, "bandit"),
        ("deserialization", "shop/tools.py", "restore_session", 32, "bandit"),
        ("deserialization", "shop/tools.py", "import_config", 38, "opengrep"),
        ("xxe", "shop/tools.py", "import_xml", 50, "bandit"),
        ("ssrf", "shop/tools.py", "fetch", 44, "opengrep"),
        ("sqli", "shop/app.py", "search_products", 20, "opengrep"),
        ("ssti", "shop/app.py", "greeting", 26, "opengrep"),
        ("path-traversal", "shop/files.py", "invoice", 20, "opengrep"),
        ("hardcoded-secrets", "shop/storage.py", "config", 8, "opengrep"),
    ]
    records = []
    for number, (slug, path, scope, line, engine) in enumerate(picks, start=1):
        records.append(
            {
                "id": f"CAND-{number:016X}",
                "engine": engine,
                "rule_id": f"{engine}.{slug}",
                "class": slug,
                "cwe": [],
                "title": f"{engine} {slug}",
                "message": f"{slug} pattern",
                "file": path,
                "start_line": line,
                "end_line": line,
                "snippet": sink_code(slug, scope) if slug != "hardcoded-secrets" else "DB_PATH",
                "severity": "critical" if number % 3 == 0 else "high",
                "tool_severity": "",
                "confidence": None,
                "tags": [],
                "fingerprints": {},
                "sca": None,
                "raw": {"sarif_file": "", "run_index": 0, "result_index": 0},
            }
        )
    return records


@pytest.fixture
def environment(tmp_path, monkeypatch):
    from kalkan.run import init as init_mod
    from kalkan.sca import commands as sca_commands
    from kalkan.sca.merge import write_candidates, write_vulns
    from kalkan.sca.normalize import new_record
    from kalkan.scanners import base
    from kalkan.scanners.candidates import merge_candidates

    monkeypatch.setenv(ids.RUNS_DIR_ENV, str(tmp_path / "runs"))
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
    monkeypatch.setattr(init_mod, "git_head", lambda directory: None)

    def run_adapter(adapter, ctx, *, timeout_seconds=None, **kwargs):
        if adapter.name == "opengrep":
            count = merge_candidates(ctx.run_dir, "opengrep", tool_candidates(), [])
            return base.ScanResult("opengrep", "ok", None, "test", 0.0, 0, "1", count)
        return base.ScanResult(adapter.name, "skipped", None, "test", 0.0, None, None)

    def run_sbom(run_dir, *, offline=False, timeout_seconds=None):
        raise ToolError("no SBOM tool (test)")

    def run_match(run_dir, *, offline=False, timeout_seconds=None):
        records = [
            new_record(
                ecosystem="PyPI",
                package=package,
                version=version,
                ids=[f"GHSA-{package[:4]}-{number:04d}-test"],
                summary=f"{package} issue {number}",
                cvss_score=9.1 if number % 2 else 7.5,
                locations=["requirements.txt"],
                engine="osv-scanner",
                fixed_versions=["9.9.9"],
            )
            for package, version in (("django", "3.2.0"), ("flask", "1.0"))
            for number in range(4)
        ]
        write_vulns(run_dir, records, [])
        write_candidates(run_dir, records, [])
        return {"merged": len(records), "by_severity": {"high": len(records)}}

    monkeypatch.setattr(base, "run_adapter", run_adapter)
    monkeypatch.setattr(sca_commands, "run_sbom", run_sbom)
    monkeypatch.setattr(sca_commands, "run_match", run_match)
    return build_target(tmp_path)


def drive(ctx, *, stop_at_phase: str | None = None, rounds: int = 400) -> dict[str, Any]:
    """Drive the run like the /kalkan skill; stop before ``stop_at_phase`` hands out tasks."""
    for _ in range(rounds):
        action = phases.next_action(ctx, "simulation")
        kind = action["kind"]
        if kind == "engine_step":
            outcome = steps.run_step(ctx, max_seconds=120)
            assert outcome["status"] in ("done", "skipped", "failed"), outcome
        elif kind == "agent_tasks":
            if stop_at_phase is not None and action["phase"] == stop_at_phase:
                for item in action["tasks"]:
                    queue.release(ctx, item["id"])
                return action
            for item in action["tasks"]:
                run_agent(item)
            for item in action["tasks"]:
                queue.complete(ctx, item["id"])
        elif kind == "ask_user":
            phases.answer(ctx, "english_report", "no")
        elif kind == "wait":
            queue.resume(ctx)
        else:
            return action
    raise AssertionError("the run did not finish")


def hunter_coverage(ctx) -> dict[str, Any]:
    """Return the unique hunter fingerprints and those that a verify task covers."""
    ctx.reload()
    fingerprints: set[str] = set()
    covered: set[str] = set()
    candidates = 0
    for task_id, task in ctx.state["tasks"].items():
        if task["type"] != "hunt" or task["status"] != "done":
            continue
        data = json.loads((ctx.task_dir(task_id) / "candidates.json").read_text("utf-8"))
        for item in data["candidates"]:
            candidates += 1
            fingerprints.add(item["fingerprint"])
            if item.get("verify_task"):
                covered.add(item["fingerprint"])
    by_type = Counter(task["type"] for task in ctx.state["tasks"].values())
    ledger = json.loads((ctx.run_dir / "coverage-ledger.json").read_text("utf-8"))
    return {
        "units": len(ledger),
        "deferred_units": sum(1 for unit in ledger if unit["status"] == "deferred"),
        "hunt_tasks": by_type["hunt"],
        "verify_tasks": by_type["verify"],
        "sca_reach_tasks": by_type["sca_reach"],
        "critic_tasks": by_type["critic"],
        "candidates": candidates,
        "unique_fingerprints": len(fingerprints),
        "covered_fingerprints": len(covered),
        "unvalidated": sorted(fingerprints - covered),
        "used": ctx.state["budget"]["used_agent_tasks"],
    }


def start(environment, profile: str = "fast", max_agent_tasks: int | None = None):
    ctx = init_run(str(environment), profile=profile)
    if max_agent_tasks is not None:
        with state.transaction(ctx) as tx:
            tx.state["budget"]["max_agent_tasks"] = max_agent_tasks
    return ctx


# ---------------------------------------------------------------------------------------------
# Tests


def test_quick_run_on_a_small_app_verifies_most_hunter_candidates(environment):
    ctx = start(environment)
    drive(ctx, stop_at_phase="validate")
    numbers = hunter_coverage(ctx)
    print("simulation (fast, 40 tasks):", json.dumps(numbers, sort_keys=True))
    assert numbers["unique_fingerprints"] >= 20
    assert numbers["covered_fingerprints"] >= 0.8 * numbers["unique_fingerprints"], numbers
    assert numbers["units"] <= 60 and numbers["deferred_units"] == 0
    assert numbers["hunt_tasks"] <= 10
    assert numbers["sca_reach_tasks"] <= 4
    reach_packages = {
        task["meta"]["vuln_ref"].split("@")[0]
        for task in ctx.state["tasks"].values()
        if task["type"] == "sca_reach"
    }
    assert reach_packages == {"PyPI/django", "PyPI/flask"}  # one record per package first
    assert validate_ledger_file(ctx.run_dir / "coverage-ledger.json") == []

    final = drive(ctx)
    current = ctx.reload()
    assert current["phase"] == "done"
    assert current["phases"]["report"]["status"] == "done"
    verify = [task for task in current["tasks"].values() if task["type"] == "verify"]
    assert verify and all(task["status"] == "done" for task in verify)  # no trace rejection
    assert validate_findings_file(ctx.run_dir / "findings.json") == []
    normalized = [
        json.loads((ctx.task_dir(task_id) / "verdict.json").read_text("utf-8"))
        for task_id, task in current["tasks"].items()
        if task["type"] == "verify"
    ]
    assert any(record["normalized"] for record in normalized)
    if current["incomplete_reason"]:
        assert final["kind"] == "incomplete"
    else:
        assert final["kind"] == "done"
    assert final["report"].endswith("report/REPORT.md")


def test_validation_overflow_ends_done_with_a_listed_gap(environment):
    ctx = start(environment, max_agent_tasks=26)
    drive(ctx, stop_at_phase="validate")
    numbers = hunter_coverage(ctx)
    print("simulation (fast, 26 tasks):", json.dumps(numbers, sort_keys=True))
    assert numbers["unvalidated"], numbers
    current = ctx.reload()
    assert current["incomplete_pending"] == "validation_budget_exhausted"
    # The most severe candidates got the verify tasks first.
    severity = {
        f"{slug}:{path}:{scope}": ("critical" in (likelihood, impact))
        for slug, path, scope, _, likelihood, impact in PLANTED
    }
    assert not any(severity.get(fingerprint) for fingerprint in numbers["unvalidated"])

    final = drive(ctx)
    current = ctx.reload()
    assert current["phase"] == "done"
    assert current["incomplete_reason"] == "validation_budget_exhausted"
    assert final == {
        "kind": "incomplete",
        "reason": "validation_budget_exhausted",
        "report": final["report"],
    }
    report = (ctx.run_dir / "report" / "REPORT.md").read_text(encoding="utf-8")
    first_section = report.split("\n## 2.", 1)[0]
    for fingerprint in numbers["unvalidated"]:
        assert fingerprint in first_section
    ledger = json.loads((ctx.run_dir / "coverage-ledger.json").read_text("utf-8"))
    notes = {note for unit in ledger for note in unit["unresolved"]}
    for fingerprint in numbers["unvalidated"]:
        assert f"validation_budget_exhausted: {fingerprint}" in notes
    summary = json.loads((ctx.run_dir / "report" / "summary.json").read_text("utf-8"))
    listed = {row["fingerprint"] for row in summary["unvalidated_candidates"]}
    assert listed == set(numbers["unvalidated"])
    assert all(row["units"] for row in summary["unvalidated_candidates"])
