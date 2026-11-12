# SPDX-License-Identifier: MIT
"""Handler of ``hunt`` results (docs/PHASES.md section 4).

1. Semantic checks: ``units`` names every assigned coverage ID exactly once; every candidate
   belongs to an assigned unit; a ``candidate`` unit has a candidate, ``covered`` and
   ``blocked`` units have none; ``covered`` has no unresolved fact, ``blocked`` has one; every
   check keeps at least one safe path and visible text. A failure raises ``ValidationError``.
2. Candidates: the trace is normalized first (:func:`kalkan.run.cleaning.normalize_trace`:
   ``entrypoint`` first, ``sink`` last, ``propagation`` between, in the agent's order of
   steps), then the Cloudflare fingerprint ``<class>:<sink file>:<sink scope>`` and the status
   of every evidence quote (:func:`kalkan.findings.quote_verify.verify_evidence`) are computed.
   Every candidate starts with status ``pending``. The verify tasks come after the wave
   (:func:`kalkan.run.validation.allocate_hunter_verifies`), which also resolves duplicates
   across the run and applies the budget.
3. Ledger: every unit owned by this task gets its status, its ``local_checks`` (``agent_id`` =
   lower-case task ID, ``method: source``, ``artifact: null``), ``reviewed_paths`` (the union of
   the check paths), ``result_fingerprints`` and ``unresolved``; a critic closure of the unit
   (``kalkan.closure``) is removed. ``uncovered`` entries become ``planned`` units of the next
   wave. The ledger is validated before it is written.
4. ``tasks/<id>/candidates.json`` lists every candidate with its fingerprint, quote statuses,
   suggested severity, the trace normalization notes, status and verify task. A repeated
   handler run keeps the allocation of candidates whose fingerprint did not change.
   ``hardening`` stays in ``result.json`` (the report reads it).
"""

from __future__ import annotations

import copy
from collections import Counter
from typing import Any, Final

from kalkan.errors import ValidationError
from kalkan.findings.ledger import validate_ledger
from kalkan.findings.quote_verify import Evidence, verify_evidence
from kalkan.run.cleaning import (
    clean_text,
    fingerprint_for,
    normalize_trace,
    safe_paths,
    sink_of,
    unique,
)
from kalkan.run.ledger_store import (
    drop_closure,
    ledger_transaction,
    load_ledger,
    sort_units,
)
from kalkan.run.plan import gap_unit
from kalkan.run.runfiles import (
    load_surfaces,
    read_task_json,
    target_get_lines,
    task_input,
    write_json,
)
from kalkan.run.state import RunContext

#: Item fields that the verify allocation owns; a repeated handler run keeps them.
_ALLOCATION_FIELDS: Final = ("status", "verify_task", "duplicate_of")
#: The unresolved note of an unvalidated candidate (written by the verify allocation).
_ALLOCATION_NOTE: Final = "validation_budget_exhausted: "


def _checks(unit_result: dict[str, Any], agent: str, where: str, errors: list[str]) -> list[dict]:
    checks = []
    for index, check in enumerate(unit_result["checks"]):
        paths = safe_paths(check["reviewed_paths"])
        invariant = clean_text(check["invariant"])
        outcome = clean_text(check["result"])
        if not paths:
            errors.append(f"{where}.checks[{index}].reviewed_paths: no safe relative path")
        if not invariant or not outcome:
            errors.append(f"{where}.checks[{index}]: invariant and result need visible text")
        checks.append(
            {
                "agent_id": agent,
                "reviewed_paths": paths,
                "invariant": invariant,
                "method": "source",
                "result": outcome,
                "artifact": None,
            }
        )
    return checks


def _check_result(
    assigned: list[str], result: dict[str, Any], agent: str
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    errors: list[str] = []
    counts = Counter(unit["coverage_id"] for unit in result["units"])
    for coverage_id, count in counts.items():
        if count > 1:
            errors.append(f"$result.units: {coverage_id} appears {count} times")
    for coverage_id in assigned:
        if coverage_id not in counts:
            errors.append(f"$result.units: the assigned unit {coverage_id} is missing")
    for coverage_id in counts:
        if coverage_id not in assigned:
            errors.append(f"$result.units: {coverage_id} is not assigned to this task")
    with_candidates = Counter(candidate["coverage_id"] for candidate in result["candidates"])
    for index, candidate in enumerate(result["candidates"]):
        if candidate["coverage_id"] not in assigned:
            errors.append(f"$result.candidates[{index}].coverage_id: not an assigned unit")
    prepared: dict[str, dict[str, Any]] = {}
    for index, unit in enumerate(result["units"]):
        where = f"$result.units[{index}]"
        status = unit["status"]
        unresolved = unique(text for text in map(clean_text, unit["unresolved"]) if text)
        has_candidates = with_candidates.get(unit["coverage_id"], 0) > 0
        if status == "candidate" and not has_candidates:
            errors.append(f"{where}.status: a candidate unit needs at least one candidate")
        if status != "candidate" and has_candidates:
            errors.append(f"{where}.status: a {status} unit must not have candidates")
        if status == "covered" and unresolved:
            errors.append(f"{where}.unresolved: a covered unit has no unresolved facts")
        if status == "blocked" and not unresolved:
            errors.append(f"{where}.unresolved: a blocked unit needs the missing facts")
        checks = _checks(unit, agent, where, errors)
        prepared[unit["coverage_id"]] = {
            "status": status,
            "checks": checks,
            "reviewed_paths": unique(path for check in checks for path in check["reviewed_paths"]),
            "unresolved": unresolved,
        }
    return prepared, errors


def _apply_units(
    units: list[dict[str, Any]],
    prepared: dict[str, dict[str, Any]],
    fingerprints: dict[str, list[str]],
    agent: str,
    wave: int,
    gaps: list[dict[str, Any]],
) -> None:
    by_id = {unit["coverage_id"]: unit for unit in units}
    for coverage_id, data in prepared.items():
        unit = by_id.get(coverage_id)
        if unit is None or unit.get("agent_id") not in (agent, None):
            continue  # reassigned or removed meanwhile: leave the other owner's unit alone
        if unit["status"] not in ("planned", "in_progress") and unit.get("agent_id") != agent:
            continue
        unit["status"] = data["status"]
        unit["agent_id"] = agent
        unit["wave"] = max(int(unit.get("wave", 1)), wave)
        unit["local_checks"] = copy.deepcopy(data["checks"])
        unit["reviewed_paths"] = list(data["reviewed_paths"])
        unit["result_fingerprints"] = (
            list(fingerprints.get(coverage_id, [])) if data["status"] == "candidate" else []
        )
        unresolved = list(data["unresolved"])
        if data["status"] == "candidate":  # keep the notes of an earlier verify allocation
            kept = [text for text in unit["unresolved"] if text.startswith(_ALLOCATION_NOTE)]
            unresolved = unique([*unresolved, *kept])
        unit["unresolved"] = unresolved
        drop_closure(unit)  # the hunter's own result replaces a critic closure
    for gap in gaps:
        if gap["coverage_id"] not in by_id:
            units.append(gap)
            by_id[gap["coverage_id"]] = gap


def _previous_items(ctx: RunContext, task_id: str) -> dict[int, dict[str, Any]]:
    data = read_task_json(ctx, task_id, "candidates.json")
    items = data.get("candidates") if isinstance(data, dict) else None
    if not isinstance(items, list):
        return {}
    return {
        item["index"]: item
        for item in items
        if isinstance(item, dict) and isinstance(item.get("index"), int)
    }


def handle(ctx: RunContext, task: dict[str, Any], result: dict[str, Any]) -> None:
    """Apply a hunt result (module docstring)."""
    task_id = task["id"]
    agent = task_id.lower()
    data = task_input(ctx, task_id)
    assigned = [
        unit["coverage_id"]
        for unit in data.get("units", [])
        if isinstance(unit, dict) and isinstance(unit.get("coverage_id"), str)
    ]
    wave = (task.get("meta") or {}).get("wave") or data.get("wave") or 1
    prepared, errors = _check_result(assigned, result, agent)
    if errors:
        raise ValidationError(f"the result of {task_id} does not fit its assignment", errors)

    get_lines = target_get_lines(ctx)
    previous = _previous_items(ctx, task_id)
    items: list[dict[str, Any]] = []
    fingerprints: dict[str, list[str]] = {}
    for index, candidate in enumerate(result["candidates"]):
        trace, normalized = normalize_trace(candidate["trace"])
        fingerprint = fingerprint_for(candidate["class"], trace)
        statuses = [
            "verified"
            if verify_evidence([Evidence(ev["file"], ev["line"], ev["quote"])], get_lines)
            else "unverified"
            for ev in candidate["evidence"]
        ]
        sink = sink_of(trace) or {}
        item = {
            "index": index,
            "ref": f"{task_id}#{index}",
            "coverage_id": candidate["coverage_id"],
            "fingerprint": fingerprint,
            "title": candidate["title"],
            "class": candidate["class"],
            "cwe": list(candidate["cwe"]),
            "file": sink.get("file"),
            "line": sink.get("line"),
            "quotes": [
                {**ev, "quote_status": status}
                for ev, status in zip(candidate["evidence"], statuses, strict=True)
            ],
            "verified_quotes": statuses.count("verified"),
            "suggested_severity": dict(candidate["suggested_severity"]),
            "normalized": normalized,
            "status": "pending",
            "verify_task": None,
            "duplicate_of": None,
        }
        before = previous.get(index)
        if before is not None and before.get("fingerprint") == fingerprint:
            item.update({name: before.get(name) for name in _ALLOCATION_FIELDS})
        items.append(item)
        fingerprints.setdefault(candidate["coverage_id"], [])
        if fingerprint not in fingerprints[candidate["coverage_id"]]:
            fingerprints[candidate["coverage_id"]].append(fingerprint)

    surfaces = {surface["id"]: surface for surface in load_surfaces(ctx)}
    gaps = [
        unit
        for unit in (
            gap_unit(ctx, item, surfaces, wave=wave + 1, origin=f"hunt:{task_id}")
            for item in result["uncovered"]
        )
        if unit is not None
    ]

    # Dry run: the ledger update must be valid before anything is written.
    trial = load_ledger(ctx)
    _apply_units(trial, prepared, fingerprints, agent, wave, gaps)
    sort_units(trial)
    trial_errors = validate_ledger(trial)
    if trial_errors:
        raise ValidationError(
            f"the result of {task_id} would make the coverage ledger invalid", trial_errors
        )

    with ledger_transaction(ctx) as (_, units):
        _apply_units(units, prepared, fingerprints, agent, wave, gaps)
    write_json(
        ctx.task_dir(task_id) / "candidates.json",
        {"task_id": task_id, "wave": wave, "candidates": items},
    )
