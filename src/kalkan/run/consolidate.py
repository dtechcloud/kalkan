# SPDX-License-Identifier: MIT
"""Consolidation tasks: one judgment per group of final records that may share one root cause
(docs/PHASES.md sections 3 and 4, ENGINE-SPEC sections 15 and 18).

The validate step :data:`kalkan.run.budget.CONSOLIDATE_STEP` follows the review step; only the
step ``polish`` (:mod:`kalkan.run.polish`) comes after it. Like every step it runs when the phase
has no open task: after the review tasks in the profiles ``standard`` and ``deep``, after the
verify and sca_reach tasks in ``fast`` (no review step).
:func:`create_consolidate_tasks`:

1. Reads the final records exactly as merge would write them now
   (:func:`kalkan.findings.merge.merged_records` without folding, so the review outcomes apply)
   and keeps the eligible ones (:func:`kalkan.findings.consolidate.eligible`: ``confirmed`` and
   ``needs_validation`` records; no rejected record and no record that a review rejected).
2. Builds the candidate groups (:func:`kalkan.findings.consolidate.candidate_groups`: linked
   records, components of more than 12 records split into chunks).
3. Orders the groups: the group whose best record ranks highest under the primary rule first,
   then the dedupe key.
4. Creates one ``consolidate`` task per group (phase ``validate``, priority 60, dedupe key
   ``consolidate:<record fingerprints in UTF-16 order, space separated>``, a SHA-256 for a long
   key; ``meta = {findings, chunk, chunks}``) while ``budget.available(state, "consolidate") >=
   1``. A group without budget stays unchecked: its records stay separate. This never blocks the
   report and sets no incomplete reason; the event :data:`EVENT_UNFUNDED`, the step detail and
   ``consolidate/groups.json`` record it, and the report shows a warning.
5. Writes :data:`GROUPS_NAME`: ``{schema_version, records, groups: [{ids, fingerprints,
   component_size, chunk, chunks, task}], unfunded}`` (``task`` is null without budget).

A run without a candidate group creates no task. The function is idempotent through the dedupe
keys: a second run (``run reopen``, a crash) reuses the existing tasks.
"""

from __future__ import annotations

from typing import Any, Final

from kalkan.findings.consolidate import (
    CandidateGroup,
    candidate_groups,
    eligible,
    pick_primary,
    primary_key,
)
from kalkan.findings.merge import merged_records
from kalkan.run import budget
from kalkan.run.cleaning import dedupe_key
from kalkan.run.inputs import consolidate_input
from kalkan.run.runfiles import read_task_json, tasks_of_type, write_json
from kalkan.run.state import RunContext, transaction
from kalkan.run.tasks import find_by_dedupe_key, new_task
from kalkan.util.text import utf16_key

__all__ = [
    "EVENT_UNFUNDED",
    "GROUPS_NAME",
    "OUTCOME_NAME",
    "consolidate_outcomes",
    "create_consolidate_tasks",
    "group_key",
]

GROUPS_NAME: Final = "consolidate/groups.json"
OUTCOME_NAME: Final = "consolidate.json"
EVENT_UNFUNDED: Final = "consolidate_unfunded"
_PRIORITY: Final = 60


def group_key(group: CandidateGroup) -> str:
    """Return the dedupe key of the task of ``group``."""
    return dedupe_key("consolidate", " ".join(group.fingerprints))


def create_consolidate_tasks(ctx: RunContext) -> dict[str, int]:
    """Create the consolidation tasks of the run (module docstring).

    Returns ``{"records", "groups", "created", "reused", "unfunded"}``: the eligible records,
    the candidate groups (chunks count one each), and what happened to the groups.
    """
    ctx.reload()
    records = [item for item in merged_records(ctx.run_dir) if eligible(item)]
    groups = candidate_groups(records)
    ranked = sorted(
        groups,
        key=lambda group: (
            primary_key(pick_primary(group.records)),
            utf16_key(group_key(group)),
        ),
    )
    summary = {
        "records": len(records),
        "groups": len(groups),
        "created": 0,
        "reused": 0,
        "unfunded": 0,
    }
    entries: list[dict[str, Any]] = []
    for group in ranked:
        key = group_key(group)
        ids = [record["id"] for record in group.records]
        task_id = find_by_dedupe_key(ctx.state, key)
        if task_id is not None:
            summary["reused"] += 1
        elif budget.available(ctx.state, "consolidate") < 1:
            summary["unfunded"] += 1
        else:
            task_id = new_task(
                ctx,
                "consolidate",
                "validate",
                consolidate_input(group),
                priority=_PRIORITY,
                dedupe_key=key,
                meta={"findings": ids, "chunk": group.chunk, "chunks": group.chunks},
            )
            summary["created"] += 1
        entries.append(
            {
                "ids": ids,
                "fingerprints": group.fingerprints,
                "component_size": group.component_size,
                "chunk": group.chunk,
                "chunks": group.chunks,
                "task": task_id,
            }
        )
    write_json(
        ctx.run_dir / GROUPS_NAME,
        {
            "schema_version": 1,
            "records": summary["records"],
            "groups": entries,
            "unfunded": summary["unfunded"],
        },
    )
    if summary["unfunded"]:
        with transaction(ctx) as tx:
            tx.event(EVENT_UNFUNDED, groups=summary["unfunded"])
    return summary


def consolidate_outcomes(ctx: RunContext) -> list[tuple[str, dict[str, Any]]]:
    """Return ``(task_id, outcome)`` of every done consolidate task with a ``consolidate.json``."""
    found = []
    for task_id, _ in tasks_of_type(ctx.state, "consolidate", statuses=("done",)):
        outcome = read_task_json(ctx, task_id, OUTCOME_NAME)
        if isinstance(outcome, dict):
            found.append((task_id, outcome))
    return found
