# SPDX-License-Identifier: MIT
"""Handler of ``consolidate`` results: which records of one candidate group share one root cause
(docs/PHASES.md section 4, ENGINE-SPEC section 18). The agent judges; the engine decides.

1. The input must hold the records of the group (``input.records[].id``).
2. Every input id appears exactly once across ``groups[].ids`` and ``distinct[].id``: an unknown
   id, an id that appears twice and a missing id each fail the attempt.
3. Every ``evidence`` quote of a group is checked with
   :func:`kalkan.findings.quote_verify.verify_evidence` (the cited line plus and minus 2 lines,
   the check of verify and review). A group with a quote that does not match is dropped: its
   records stay separate, and ``consolidate.json`` notes the drop (``dropped:
   unverified_quote``).
4. For each accepted group the engine picks the primary with
   :func:`kalkan.findings.consolidate.pick_primary` (highest verdict, then the highest overall
   severity, then the most evidence items, then the smallest id); the other members become its
   duplicates. A severity never goes down: the primary is the strongest record and keeps its
   own fields.
5. ``tasks/<id>/consolidate.json`` = ``{task_id, records, groups: [{ids, reason, evidence (with
   quote_status), verified_quotes, accepted, dropped, primary, duplicates}], distinct, accepted,
   dropped, normalized}``. :mod:`kalkan.findings.merge` folds the accepted groups.
"""

from __future__ import annotations

import copy
from collections import Counter
from typing import Any, Final

from kalkan.errors import ValidationError
from kalkan.findings.consolidate import pick_primary
from kalkan.findings.quote_verify import Evidence, verify_evidence
from kalkan.run.cleaning import normalize_path
from kalkan.run.runfiles import target_get_lines, task_input, write_json
from kalkan.run.state import RunContext

__all__ = ["DROPPED_UNVERIFIED", "OUTCOME_NAME", "build_outcome", "handle"]

OUTCOME_NAME: Final = "consolidate.json"
#: Why a group was dropped: one of its quotes does not match the source.
DROPPED_UNVERIFIED: Final = "unverified_quote"


def _input_records(ctx: RunContext, task_id: str) -> dict[str, dict[str, Any]]:
    data = task_input(ctx, task_id)
    records = data.get("records")
    found: dict[str, dict[str, Any]] = {}
    for record in records if isinstance(records, list) else []:
        if isinstance(record, dict) and isinstance(record.get("id"), str):
            found[record["id"]] = record
    if len(found) < 2:
        raise ValidationError(
            f"the input of {task_id} holds no group of records", ["$input.records: missing"]
        )
    return found


def _check_ids(task_id: str, known: dict[str, dict[str, Any]], result: dict[str, Any]) -> None:
    named = [item for group in result["groups"] for item in group["ids"]]
    named += [item["id"] for item in result["distinct"]]
    counts = Counter(named)
    errors = [
        f"$result: {item} is not a record of this task" for item in counts if item not in known
    ]
    errors += [
        f"$result: {item} appears {count} times; name each record once"
        for item, count in counts.items()
        if count > 1
    ]
    errors += [
        f"$result: {item} is missing; put it in a group or in distinct"
        for item in known
        if item not in counts
    ]
    if errors:
        raise ValidationError(f"the result of {task_id} does not name every record once", errors)


def _quotes(ctx: RunContext, evidence: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    get_lines = target_get_lines(ctx)
    statuses, verified = [], 0
    for item in evidence:
        path = normalize_path(item["file"])
        file = path if isinstance(path, str) else item["file"]
        passed = verify_evidence([Evidence(file, item["line"], item["quote"])], get_lines)
        statuses.append(
            {**item, "file": file, "quote_status": "verified" if passed else "unverified"}
        )
        verified += len(passed)
    return statuses, verified


def build_outcome(ctx: RunContext, task: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    """Return the ``consolidate.json`` document of a result (module docstring)."""
    task_id = task["id"]
    known = _input_records(ctx, task_id)
    _check_ids(task_id, known, result)
    groups: list[dict[str, Any]] = []
    notes: list[str] = []
    for index, group in enumerate(result["groups"]):
        evidence, verified = _quotes(ctx, group["evidence"])
        accepted = verified == len(evidence)
        entry: dict[str, Any] = {
            "ids": list(group["ids"]),
            "reason": group["reason"],
            "evidence": evidence,
            "verified_quotes": verified,
            "accepted": accepted,
            "dropped": None if accepted else DROPPED_UNVERIFIED,
            "primary": None,
            "duplicates": [],
        }
        if accepted:
            primary = pick_primary(known[item] for item in group["ids"])
            entry["primary"] = primary["id"]
            entry["duplicates"] = [item for item in group["ids"] if item != primary["id"]]
        else:
            notes.append(
                f"groups[{index}]: {len(evidence) - verified} of {len(evidence)} quotes do not "
                "match the source; the group is dropped and its records stay separate"
            )
        groups.append(entry)
    return {
        "task_id": task_id,
        "records": list(known),
        "groups": groups,
        "distinct": copy.deepcopy(result["distinct"]),
        "accepted": sum(1 for entry in groups if entry["accepted"]),
        "dropped": sum(1 for entry in groups if not entry["accepted"]),
        "normalized": notes,
    }


def handle(ctx: RunContext, task: dict[str, Any], result: dict[str, Any]) -> None:
    """Check a consolidate result, then write ``tasks/<id>/consolidate.json``."""
    outcome = build_outcome(ctx, task, result)
    write_json(ctx.task_dir(task["id"]) / OUTCOME_NAME, outcome)
