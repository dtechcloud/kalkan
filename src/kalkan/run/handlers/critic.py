# SPDX-License-Identifier: MIT
"""Handler of ``critic`` results (docs/PHASES.md section 3, hunt).

The critic of hunt wave ``n``:

1. adds every accepted ``missing_units`` entry as a ``planned`` unit of wave ``n + 1``
   (deduplicated by ``coverage_id``; an entry with an unknown class or without a usable path is
   dropped);
2. archives every ``reassign_ids`` unit with live ``covered``, ``candidate`` or ``blocked``
   evidence into ``attempts`` (Cloudflare rules) and returns it to ``planned`` with wave
   ``n + 1``; unknown IDs and units without live evidence are ignored;
3. closes every accepted ``covered_ids`` entry: a ``blocked`` unit whose unresolved facts the
   named sibling units already settled (:func:`close_units`); the unit becomes ``covered``
   without another hunt task;
4. creates hunt wave ``n + 1`` for every ``planned`` unit when the profile allows that wave and
   no incomplete reason is pending; otherwise every ``planned`` unit becomes ``deferred``
   (``fast_profile_final_critic`` for fast, else ``hunt_waves_exhausted`` or
   ``validation_budget_exhausted``).

The decision depends on the accepted work, not on ``stop`` alone (Cloudflare: "the parent's loop
condition, not stop alone, decides"). ``tasks/<id>/critic.json`` records what the handler did.
Repeated runs are idempotent: a unit whose wave is already above ``n`` is never archived again,
a unit that this critic closed stays closed, and the hunt tasks are reused through their dedupe
keys.
"""

from __future__ import annotations

from typing import Any, Final

from kalkan.findings.quote_verify import Evidence, verify_evidence
from kalkan.run.cleaning import clean_text, normalize_path, safe_paths, unique
from kalkan.run.ledger_store import (
    CLOSURE_KEY,
    archive_attempt,
    ledger_transaction,
    live_closure,
)
from kalkan.run.plan import (
    REASON_FAST,
    REASON_VALIDATION,
    REASON_WAVES,
    create_hunt_wave,
    defer_planned,
    gap_unit,
    hunt_waves,
)
from kalkan.run.runfiles import load_surfaces, target_get_lines, task_input, write_json
from kalkan.run.state import RunContext

__all__ = [
    "DROPPED_DUPLICATE",
    "DROPPED_NOT_BLOCKED",
    "DROPPED_OUTSIDE_SIBLINGS",
    "DROPPED_REASSIGNED",
    "DROPPED_SIBLING",
    "DROPPED_UNKNOWN",
    "DROPPED_UNVERIFIED",
    "close_units",
    "handle",
]

#: Why a ``covered_ids`` entry was not applied (``critic.json`` ``closures[].dropped``).
DROPPED_DUPLICATE: Final = "duplicate_entry"
DROPPED_UNKNOWN: Final = "unknown_unit"
DROPPED_REASSIGNED: Final = "reassigned"
DROPPED_NOT_BLOCKED: Final = "not_blocked"
DROPPED_SIBLING: Final = "sibling_not_covered"
DROPPED_OUTSIDE_SIBLINGS: Final = "quote_outside_sibling_paths"
DROPPED_UNVERIFIED: Final = "unverified_quote"
#: Sibling statuses that settle facts: a hunter read the unit to the end.
_SETTLED: Final = ("covered", "candidate")


def _closed_by(unit: dict[str, Any], task_id: str) -> bool:
    closure = live_closure(unit)
    return closure is not None and closure.get("task") == task_id


def _quotes(
    get_lines: Any, evidence: list[dict[str, Any]], sibling_paths: set[str]
) -> list[dict[str, Any]]:
    statuses = []
    for item in evidence:
        path = normalize_path(item["file"])
        file = path if isinstance(path, str) else item["file"]
        passed = verify_evidence([Evidence(file, item["line"], item["quote"])], get_lines)
        statuses.append(
            {
                **item,
                "file": file,
                "quote_status": "verified" if passed else "unverified",
                "in_sibling_paths": file in sibling_paths,
            }
        )
    return statuses


def _close(unit: dict[str, Any], task_id: str, item: dict[str, Any], evidence: list) -> None:
    covered_by = unique(item["covered_by"])
    paths = safe_paths([entry["file"] for entry in evidence])
    unresolved = list(unit["unresolved"])
    unit["local_checks"].append(
        {
            "agent_id": task_id.lower(),
            "reviewed_paths": paths,
            "invariant": clean_text(
                f"The covered units {', '.join(covered_by)} settle the unresolved facts: "
                + " | ".join(unresolved)
            ),
            "method": "source",
            "result": clean_text(item["reason"]) or "The sibling units settle every fact.",
            "artifact": None,
        }
    )
    unit["reviewed_paths"] = unique([*unit["reviewed_paths"], *paths])
    unit["unresolved"] = []
    unit["status"] = "covered"
    unit.setdefault("kalkan", {})[CLOSURE_KEY] = {
        "task": task_id,
        "covered_by": covered_by,
        "unresolved": unresolved,
        "reason": item["reason"],
        "evidence": [{key: entry[key] for key in ("file", "line", "quote")} for entry in evidence],
    }


def close_units(
    ctx: RunContext,
    task_id: str,
    units: list[dict[str, Any]],
    entries: list[dict[str, Any]],
    reassigned: set[str],
) -> list[dict[str, Any]]:
    """Close the accepted ``covered_ids`` entries in ``units`` and return one record per entry.

    The critic judges; the engine decides. An entry is accepted only when:

    1. the unit exists, is not in ``reassign_ids`` and is live ``blocked``;
    2. every ``covered_by`` unit exists, is not the unit itself and is ``covered`` or
       ``candidate`` from its own hunt: a unit with a live closure (of any critic, also one that
       this result adds) never settles another unit, so closures never chain;
    3. every ``evidence`` quote names a file in the ``reviewed_paths`` of the ``covered_by``
       units and matches the source (:func:`kalkan.findings.quote_verify.verify_evidence`).

    The first entry of a ``coverage_id`` decides; a later one is ``duplicate_entry``. The engine
    checks that the quotes exist in code that the siblings read; whether that code answers the
    unresolved facts is the critic's judgment (as in consolidate).

    An accepted unit keeps its owner and the hunter's checks. It gets one more check (agent
    ``task_id`` in lower case, the quoted files, ``method: source``), ``status: covered``, empty
    ``unresolved`` and ``kalkan.closure`` = ``{task, covered_by, unresolved, reason,
    evidence}``. A unit that this task closed before counts as accepted again and stays as it is.
    """
    by_id = {unit["coverage_id"]: unit for unit in units}
    settled = {
        unit["coverage_id"]
        for unit in units
        if unit.get("status") in _SETTLED and live_closure(unit) is None
    }
    get_lines = target_get_lines(ctx)
    seen: set[str] = set()
    records: list[dict[str, Any]] = []
    for item in entries:
        coverage_id = item["coverage_id"]
        covered_by = unique(item["covered_by"])
        unit = by_id.get(coverage_id)
        sibling_paths = {
            path
            for sibling in covered_by
            if sibling in settled and sibling != coverage_id
            for path in by_id[sibling].get("reviewed_paths", [])
        }
        evidence = _quotes(get_lines, item["evidence"], sibling_paths)
        if coverage_id in seen:
            dropped = DROPPED_DUPLICATE
        elif unit is None:
            dropped = DROPPED_UNKNOWN
        elif _closed_by(unit, task_id):
            dropped = None
        elif coverage_id in reassigned:
            dropped = DROPPED_REASSIGNED
        elif unit.get("status") != "blocked":
            dropped = DROPPED_NOT_BLOCKED
        elif any(sibling == coverage_id or sibling not in settled for sibling in covered_by):
            dropped = DROPPED_SIBLING
        elif not all(entry["in_sibling_paths"] for entry in evidence):
            dropped = DROPPED_OUTSIDE_SIBLINGS
        elif not all(entry["quote_status"] == "verified" for entry in evidence):
            dropped = DROPPED_UNVERIFIED
        else:
            dropped = None
            _close(unit, task_id, item, evidence)
        seen.add(coverage_id)
        records.append(
            {
                "coverage_id": coverage_id,
                "covered_by": covered_by,
                "reason": item["reason"],
                "evidence": evidence,
                "accepted": dropped is None,
                "dropped": dropped,
            }
        )
    return records


def handle(ctx: RunContext, task: dict[str, Any], result: dict[str, Any]) -> None:
    """Apply a critic result (module docstring)."""
    task_id = task["id"]
    wave = (task.get("meta") or {}).get("wave") or task_input(ctx, task_id).get("wave") or 1
    next_wave = wave + 1
    surfaces = {surface["id"]: surface for surface in load_surfaces(ctx)}
    proposed = [
        unit
        for unit in (
            gap_unit(ctx, item, surfaces, wave=next_wave, origin=f"critic:{task_id}")
            for item in result["missing_units"]
        )
        if unit is not None
    ]
    reasons = {item["coverage_id"]: item["reason"] for item in result["reassign_ids"]}
    added: list[str] = []
    archived: list[str] = []
    with ledger_transaction(ctx) as (tx, units):
        by_id = {unit["coverage_id"]: unit for unit in units}
        for unit in proposed:
            if unit["coverage_id"] not in by_id:
                units.append(unit)
                by_id[unit["coverage_id"]] = unit
                added.append(unit["coverage_id"])
        for coverage_id, reason in reasons.items():
            unit = by_id.get(coverage_id)
            if (
                unit is not None
                and int(unit.get("wave", 1)) <= wave
                and archive_attempt(unit, reason, next_wave)
            ):
                archived.append(coverage_id)
        closures = close_units(ctx, task_id, units, result.get("covered_ids", []), set(reasons))
        state = tx.state
    pending = state.get("incomplete_pending")
    if next_wave <= hunt_waves(state) and not pending:
        scheduled = create_hunt_wave(ctx, next_wave)
        deferred = scheduled["deferred"]
        outcome = "next_wave"
    else:
        if pending:
            reason = REASON_VALIDATION
        elif ctx.options["profile"] == "fast":
            reason = REASON_FAST
        else:
            reason = REASON_WAVES
        scheduled = {"tasks": 0, "units": 0, "deferred": 0}
        deferred = defer_planned(ctx, reason)
        outcome = f"deferred:{reason}"
    write_json(
        ctx.task_dir(task_id) / "critic.json",
        {
            "task_id": task_id,
            "wave": wave,
            "stop": bool(result["stop"]),
            "added_units": added,
            "reassigned_units": archived,
            "closed_units": [entry["coverage_id"] for entry in closures if entry["accepted"]],
            "closures": closures,
            "outcome": outcome,
            "hunt_tasks": scheduled["tasks"],
            "deferred_units": deferred,
        },
    )
