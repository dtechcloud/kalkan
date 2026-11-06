# SPDX-License-Identifier: MIT
"""Polish tasks: an agent restores the Turkish letters of the final records, the engine checks
every change (docs/PHASES.md sections 3 and 4, ENGINE-SPEC sections 15 and 18).

The validate step :data:`kalkan.run.budget.POLISH_STEP` is the last step of the phase. Like every
step it runs when the phase has no open task, so after the consolidate tasks.
:func:`create_polish_tasks`:

1. The step calls it only for a Turkish run (``ctx.lang == "tr"``); it reports any other run
   as done with the detail "not a Turkish run".
2. Reads the final records exactly as merge would write them now
   (:func:`kalkan.findings.merge.merged_records` with folding: the review outcomes, the
   consolidation and the corrections of earlier polish tasks apply), and keeps the
   ``confirmed`` and ``needs_validation`` records with an id, folded duplicates included.
3. Selects the records with prose fields that need the Turkish letters
   (:func:`kalkan.findings.polish.select_records`). A field that the input of a done polish
   task already held with the same text is not selected again (:func:`seen_fields`), so a
   ``run reopen`` never asks twice about a field that the agent left as it was.
4. Cuts the selected records into batches of at most 8 (confirmed first, then by overall
   severity, then by id) and creates one ``polish`` task per batch (phase ``validate``,
   priority 40, dedupe key ``polish:<record ids> <SHA-256 of the selected fields>``, a SHA-256
   for a long key; ``meta = {findings, fields}``) while ``budget.available(state, "polish") >=
   1``. A batch without budget keeps its text. This never blocks the report and sets no
   incomplete reason; the event :data:`EVENT_UNFUNDED`, the step detail and
   :data:`BATCHES_NAME` record it.
5. Writes :data:`BATCHES_NAME`: ``{schema_version, records, selected, fields, batches: [{ids,
   fields, task}], unfunded}`` (``task`` is null without budget).

The function is idempotent through the dedupe keys: a second run (``run reopen``, a crash)
reuses the existing tasks.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Final

from kalkan.findings.merge import merged_records
from kalkan.findings.polish import eligible, make_batches, select_records
from kalkan.run import budget
from kalkan.run.cleaning import dedupe_key
from kalkan.run.inputs import polish_input
from kalkan.run.runfiles import task_input, tasks_of_type, write_json
from kalkan.run.state import RunContext, transaction
from kalkan.run.tasks import find_by_dedupe_key, new_task

__all__ = [
    "BATCHES_NAME",
    "EVENT_UNFUNDED",
    "OUTCOME_NAME",
    "batch_key",
    "create_polish_tasks",
    "seen_fields",
]

BATCHES_NAME: Final = "polish/batches.json"
OUTCOME_NAME: Final = "polish.json"
EVENT_UNFUNDED: Final = "polish_unfunded"
_PRIORITY: Final = 40


def batch_key(batch: list[dict[str, Any]]) -> str:
    """Return the dedupe key of the task of ``batch``: the record ids and a SHA-256 of the
    selected fields (id, path and text of each)."""
    fields = [
        [record["id"], item["path"], item["text"]] for record in batch for item in record["fields"]
    ]
    digest = hashlib.sha256(
        json.dumps(fields, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    ids = " ".join(record["id"] for record in batch)
    return dedupe_key("polish", f"{ids} {digest}")


def seen_fields(ctx: RunContext) -> set[tuple[str, str, str]]:
    """Return the ``(id, path, text)`` triples of the inputs of the done polish tasks."""
    seen: set[tuple[str, str, str]] = set()
    for task_id, _ in tasks_of_type(ctx.state, "polish", statuses=("done",)):
        records = task_input(ctx, task_id).get("records")
        for record in records if isinstance(records, list) else []:
            if not isinstance(record, dict) or not isinstance(record.get("id"), str):
                continue
            fields = record.get("fields")
            for item in fields if isinstance(fields, list) else []:
                if isinstance(item, dict):
                    path, text = item.get("path"), item.get("text")
                    if isinstance(path, str) and isinstance(text, str):
                        seen.add((record["id"], path, text))
    return seen


def create_polish_tasks(ctx: RunContext) -> dict[str, int]:
    """Create the polish tasks of a Turkish run (module docstring).

    Returns ``{"records", "selected", "fields", "batches", "created", "reused", "unfunded"}``:
    the eligible records, the records and fields that need the letters, and what happened to
    the batches.
    """
    ctx.reload()
    records = [item for item in merged_records(ctx.run_dir, fold=True) if eligible(item)]
    selected = select_records(records, seen_fields(ctx))
    batches = make_batches(selected)
    summary = {
        "records": len(records),
        "selected": len(selected),
        "fields": sum(len(record["fields"]) for record in selected),
        "batches": len(batches),
        "created": 0,
        "reused": 0,
        "unfunded": 0,
    }
    entries: list[dict[str, Any]] = []
    for batch in batches:
        key = batch_key(batch)
        ids = [record["id"] for record in batch]
        fields = sum(len(record["fields"]) for record in batch)
        task_id = find_by_dedupe_key(ctx.state, key)
        if task_id is not None:
            summary["reused"] += 1
        elif budget.available(ctx.state, "polish") < 1:
            summary["unfunded"] += 1
        else:
            task_id = new_task(
                ctx,
                "polish",
                "validate",
                polish_input(batch),
                priority=_PRIORITY,
                dedupe_key=key,
                meta={"findings": ids, "fields": fields},
            )
            summary["created"] += 1
        entries.append({"ids": ids, "fields": fields, "task": task_id})
    write_json(
        ctx.run_dir / BATCHES_NAME,
        {
            "schema_version": 1,
            "records": summary["records"],
            "selected": summary["selected"],
            "fields": summary["fields"],
            "batches": entries,
            "unfunded": summary["unfunded"],
        },
    )
    if summary["unfunded"]:
        with transaction(ctx) as tx:
            tx.event(EVENT_UNFUNDED, batches=summary["unfunded"])
    return summary
