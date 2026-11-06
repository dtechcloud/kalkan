# SPDX-License-Identifier: MIT
"""Validation planning: verify tasks for hunter candidates and deterministic tool results
(docs/PHASES.md sections 3, 4 and 7).

Hunter candidates (:func:`allocate_hunter_verifies`). The hunt handler records every candidate
in ``tasks/<id>/candidates.json`` with status ``pending``. When every hunt task of a wave is
settled, the hunt phase hook allocates verify tasks for all candidates of the run at once,
before the critic of the wave:

1. Claims with the same fingerprint are one claim; its primary is the first by task sequence
   and index. Claims with the same class, sink file and sink line (another scope label for the
   same root cause) join one root-cause group.
2. Groups are ranked by the best member: suggested severity (impact + likelihood) first, then
   the presence of a verified quote, then the fingerprint (Cloudflare "fingerprint order").
3. In that order each group gets one verify task while ``budget.available(state, "verify")``
   allows. A group that already has a task (dedupe key ``verify:fp:<fingerprint>``) keeps it.
4. A group without budget stays unvalidated: its items get status ``unvalidated``, their
   ``candidate`` units get ``validation_budget_exhausted: <fingerprint>`` in ``unresolved``, and
   the run records the pending incomplete reason ``validation_budget_exhausted`` (Cloudflare
   incomplete-run rule). It never becomes a finding.

Item statuses after the allocation: ``queued`` (the primary of a group with a verify task),
``duplicate`` (another claim of the group; ``duplicate_of`` names the primary and
``verify_task`` its task) and ``unvalidated``.

Deterministic tool results (:func:`create_deterministic_verifies`). At the end of the hunt
phase, critical and high tool results in code classes get verify tasks when no hunter
candidate cites the same class and file (the hunters saw the tool results as hints), at most
:func:`kalkan.run.budget.deterministic_verify_cap` and within the budget.

Both functions are idempotent: a repeated call reuses the tasks through their dedupe keys and
writes the same files.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Final

from kalkan.findings import severity as sev
from kalkan.findings.taxonomy import DEPENDENCY_CLASSES
from kalkan.run import budget
from kalkan.run.cleaning import clean_text, dedupe_key, normalize_trace, safe_paths, unique
from kalkan.run.inputs import verify_input_deterministic, verify_input_hunter
from kalkan.run.ledger_store import ledger_transaction, load_ledger
from kalkan.run.runfiles import load_candidates, read_task_json, tasks_of_type, write_json
from kalkan.run.state import RunContext
from kalkan.run.tasks import find_by_dedupe_key, new_task
from kalkan.util.text import utf16_key

__all__ = [
    "NON_CODE_CLASSES",
    "REASON_VALIDATION",
    "allocate_hunter_verifies",
    "create_deterministic_verifies",
    "severity_score",
    "verify_priority",
]

REASON_VALIDATION: Final = "validation_budget_exhausted"
#: Classes that are not code findings (no deterministic verify task, no PoC).
NON_CODE_CLASSES: Final = frozenset({*DEPENDENCY_CLASSES, "iac-cloud-container"})
_SCORES: Final = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_UNVERIFIED_PRIORITY: Final = 10

Entry = tuple[str, dict[str, Any]]


def severity_score(suggested: object) -> int:
    """Return impact + likelihood of a ``suggested_severity`` (informational 0 … critical 4;
    a missing value counts as medium)."""
    data = suggested if isinstance(suggested, Mapping) else {}
    return _SCORES.get(str(data.get("impact")), 2) + _SCORES.get(str(data.get("likelihood")), 2)


def verify_priority(score: int, verified_quotes: int) -> int:
    """Return the priority of a hunter verify task: ``30 + 6 × score``; 10 without a verified
    quote."""
    return 30 + 6 * score if verified_quotes else _UNVERIFIED_PRIORITY


def _hunt_documents(ctx: RunContext) -> dict[str, dict[str, Any]]:
    documents: dict[str, dict[str, Any]] = {}
    for task_id, _ in tasks_of_type(ctx.state, "hunt", statuses=("done",)):
        data = read_task_json(ctx, task_id, "candidates.json")
        if isinstance(data, dict) and isinstance(data.get("candidates"), list):
            documents[task_id] = data
    return documents


def _entries(documents: dict[str, dict[str, Any]]) -> list[Entry]:
    return [
        (task_id, item)
        for task_id, document in documents.items()
        for item in document["candidates"]
        if isinstance(item, dict)
        and isinstance(item.get("fingerprint"), str)
        and isinstance(item.get("ref"), str)
    ]


def _rank(item: Mapping[str, Any]) -> tuple[Any, ...]:
    verified = int(item.get("verified_quotes") or 0) > 0
    return (
        -severity_score(item.get("suggested_severity")),
        0 if verified else 1,
        utf16_key(str(item["fingerprint"])),
    )


def _root_cause_groups(first: dict[str, Entry]) -> list[list[str]]:
    """Return the fingerprints in root-cause groups (same class, sink file and sink line)."""
    parent = {fingerprint: fingerprint for fingerprint in first}

    def find(value: str) -> str:
        while parent[value] != value:
            parent[value] = parent[parent[value]]
            value = parent[value]
        return value

    by_location: dict[tuple[Any, ...], str] = {}
    for fingerprint, (_, item) in first.items():
        file, line = item.get("file"), item.get("line")
        if not isinstance(file, str) or not file or not isinstance(line, int):
            continue
        other = by_location.setdefault((item.get("class"), file, line), fingerprint)
        if other != fingerprint:
            parent[find(fingerprint)] = find(other)
    groups: dict[str, list[str]] = {}
    for fingerprint in first:
        groups.setdefault(find(fingerprint), []).append(fingerprint)
    ordered = [sorted(members, key=lambda fp: _rank(first[fp][1])) for members in groups.values()]
    return sorted(ordered, key=lambda members: _rank(first[members[0]][1]))


def _unit_checks(units: list[dict[str, Any]], coverage_id: object, agent: str) -> list[dict]:
    for unit in units:
        if unit.get("coverage_id") == coverage_id and unit.get("agent_id") == agent:
            return list(unit.get("local_checks") or [])
    return []


def _claim_of(ctx: RunContext, task_id: str, item: dict[str, Any]) -> dict[str, Any]:
    """Return the hunter candidate of ``item`` from the hunt result (trace normalized)."""
    result = read_task_json(ctx, task_id, "result.json")
    candidates = result.get("candidates") if isinstance(result, dict) else None
    index = item.get("index")
    if isinstance(candidates, list) and isinstance(index, int) and 0 <= index < len(candidates):
        candidate = dict(candidates[index])
        candidate["trace"], _ = normalize_trace(candidate.get("trace"))
        return candidate
    # The result file is gone: rebuild a minimal claim from candidates.json.
    return {
        "title": item.get("title"),
        "class": item.get("class"),
        "cwe": list(item.get("cwe") or []),
        "description": item.get("title"),
        "claimed_root_cause": "",
        "trace": [
            {
                "kind": "sink",
                "file": item.get("file"),
                "line": item.get("line"),
                "scope": "unknown",
                "description": item.get("title"),
            }
        ],
        "evidence": [
            {key: quote.get(key) for key in ("file", "line", "quote")}
            for quote in item.get("quotes") or []
            if isinstance(quote, dict)
        ],
        "suggested_severity": item.get("suggested_severity"),
        "dynamic_test": "",
    }


def _create_hunter_verify(
    ctx: RunContext, entry: Entry, units: list[dict[str, Any]], key: str
) -> str:
    task_id, item = entry
    quotes = [q for q in item.get("quotes") or [] if isinstance(q, dict)]
    return new_task(
        ctx,
        "verify",
        "validate",
        verify_input_hunter(
            ctx,
            ref=item["ref"],
            candidate=_claim_of(ctx, task_id, item),
            fingerprint=item["fingerprint"],
            quote_status=[str(quote.get("quote_status")) for quote in quotes],
            checks=_unit_checks(units, item.get("coverage_id"), task_id.lower()),
        ),
        priority=verify_priority(
            severity_score(item.get("suggested_severity")), int(item.get("verified_quotes") or 0)
        ),
        dedupe_key=key,
        meta={
            "subject": item["ref"],
            "fingerprint": item["fingerprint"],
            "file": item.get("file"),
            "title": clean_text(item.get("title"), 120),
        },
    )


def allocate_hunter_verifies(ctx: RunContext) -> dict[str, int]:
    """Create verify tasks for the hunter candidates of the run (module docstring).

    Returns ``{"fingerprints", "groups", "created", "reused", "unvalidated"}``.
    """
    ctx.reload()
    documents = _hunt_documents(ctx)
    entries = _entries(documents)
    first: dict[str, Entry] = {}
    for entry in entries:
        first.setdefault(entry[1]["fingerprint"], entry)
    units = load_ledger(ctx)
    decision: dict[str, tuple[str | None, str]] = {}  # fingerprint -> (task, primary ref)
    created = reused = unvalidated = 0
    groups = _root_cause_groups(first)
    for members in groups:
        task_id = None
        representative = members[0]
        for fingerprint in members:
            task_id = find_by_dedupe_key(ctx.state, dedupe_key("verify:fp", fingerprint))
            if task_id is not None:
                representative = fingerprint
                break
        if task_id is not None:
            reused += 1
        elif budget.available(ctx.state, "verify") >= 1:
            key = dedupe_key("verify:fp", representative)
            task_id = _create_hunter_verify(ctx, first[representative], units, key)
            created += 1
        else:
            unvalidated += 1
        primary = first[representative][1]["ref"]
        for fingerprint in members:
            decision[fingerprint] = (task_id, primary)

    notes: dict[str, list[str]] = {}
    changed: set[str] = set()
    for hunt_id, item in entries:
        task_id, primary = decision[item["fingerprint"]]
        if task_id is None:
            update = {"status": "unvalidated", "verify_task": None}
            note = f"{REASON_VALIDATION}: {item['fingerprint']}"
            notes.setdefault(str(item.get("coverage_id")), []).append(note)
        else:
            update = {"status": "queued" if item["ref"] == primary else "duplicate"}
            update["verify_task"] = task_id
        update["duplicate_of"] = None if item["ref"] == primary else primary
        if any(item.get(name) != value for name, value in update.items()):
            item.update(update)
            changed.add(hunt_id)
    for hunt_id in sorted(changed):
        write_json(ctx.task_dir(hunt_id) / "candidates.json", documents[hunt_id])
    if notes:
        with ledger_transaction(ctx) as (tx, ledger):
            for unit in ledger:
                extra = notes.get(unit["coverage_id"])
                if extra and unit["status"] == "candidate":
                    unit["unresolved"] = unique([*unit["unresolved"], *extra])
            if not tx.state.get("incomplete_pending"):
                tx.state["incomplete_pending"] = REASON_VALIDATION
                tx.event("incomplete_pending", reason=REASON_VALIDATION, unvalidated=unvalidated)
    return {
        "fingerprints": len(first),
        "groups": len(groups),
        "created": created,
        "reused": reused,
        "unvalidated": unvalidated,
    }


def _cited_by_hunters(ctx: RunContext) -> set[tuple[Any, str]]:
    cited: set[tuple[Any, str]] = set()
    for _, item in _entries(_hunt_documents(ctx)):
        quotes = [quote for quote in item.get("quotes") or [] if isinstance(quote, dict)]
        paths = [item.get("file"), *(quote.get("file") for quote in quotes)]
        cited.update((item.get("class"), path) for path in paths if isinstance(path, str))
    return cited


def create_deterministic_verifies(ctx: RunContext) -> dict[str, int]:
    """Create verify tasks for critical and high deterministic tool results in code classes.

    One task per (class, file, start line), only when no hunter candidate cites the same class
    and file; at most :func:`kalkan.run.budget.deterministic_verify_cap` and never beyond
    ``budget.available(state, "verify")``. Order: severity, engine, file, line, ID.
    Returns ``{"tasks", "skipped", "covered", "cap"}``.
    """
    ctx.reload()
    cap = budget.deterministic_verify_cap(ctx.state)
    cited = _cited_by_hunters(ctx)
    candidates = [
        candidate
        for candidate in load_candidates(ctx)
        if candidate.get("severity") in ("critical", "high")
        and candidate.get("class") not in NON_CODE_CLASSES
        and isinstance(candidate.get("file"), str)
        and safe_paths([candidate.get("file")])
        and isinstance(candidate.get("start_line"), int)
    ]
    candidates.sort(
        key=lambda c: (
            -sev.rank(c["severity"]),
            str(c.get("engine")),
            c["file"],
            c["start_line"],
            c["id"],
        )
    )
    seen: set[tuple[Any, ...]] = set()
    created = skipped = covered = 0
    for candidate in candidates:
        location = (candidate.get("class"), candidate["file"], candidate["start_line"])
        if location in seen:
            continue
        seen.add(location)
        if (candidate.get("class"), candidate["file"]) in cited:
            covered += 1
            continue
        key = dedupe_key("verify:deterministic", candidate["id"])
        if find_by_dedupe_key(ctx.state, key) is not None:
            created += 1
            continue
        if created >= cap or budget.available(ctx.state, "verify") < 1:
            skipped += 1
            continue
        new_task(
            ctx,
            "verify",
            "validate",
            verify_input_deterministic(ctx, candidate),
            priority=80 if candidate["severity"] == "critical" else 70,
            dedupe_key=key,
            meta={
                "subject": candidate["id"],
                "file": candidate["file"],
                "title": clean_text(candidate.get("title"), 120),
            },
        )
        created += 1
    return {"tasks": created, "skipped": skipped, "covered": covered, "cap": cap}
