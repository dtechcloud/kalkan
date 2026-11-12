# SPDX-License-Identifier: MIT
"""Handler of ``polish`` results: the Turkish letters that an agent restored in the prose fields
of the final records (docs/PHASES.md section 4, ENGINE-SPEC section 18). The agent proposes; the
engine decides, field by field.

1. The input must hold at least one field (``input.records[].fields[]``, each with the record
   ``id``, a ``path`` and the old ``text``).
2. Every returned field is judged on its own, in result order. The engine compares the NFC form
   of the new text (:func:`kalkan.findings.polish.candidate_text`) and rejects the field with a
   reason when:

   - ``(id, path)`` is not a field of the input: ``unknown_field``;
   - the result named the same field before: ``duplicate_field`` (only the first one counts);
   - the new text equals the old one: ``unchanged``;
   - the texts differ in anything but the Turkish letters (:func:`kalkan.findings.polish.fold`
     of both is not equal; so the length and every other character stay): ``fold_mismatch``;
   - a code token (a backtick span, or a token with a code character, a digit next to a letter
     or an inner uppercase letter) is not byte-identical: ``code_token_changed``.

   A rejected field never fails the task; the old text stays.
3. ``tasks/<id>/polish.json`` = ``{task_id, applied: [{id, path, old, new}], rejected: [{id,
   path, reason}]}``. :mod:`kalkan.findings.merge` applies the accepted corrections.
"""

from __future__ import annotations

from typing import Any, Final

from kalkan.errors import ValidationError
from kalkan.findings.polish import (
    DUPLICATE_FIELD,
    UNKNOWN_FIELD,
    candidate_text,
    check_correction,
)
from kalkan.run.runfiles import task_input, write_json
from kalkan.run.state import RunContext

__all__ = ["OUTCOME_NAME", "build_outcome", "handle"]

OUTCOME_NAME: Final = "polish.json"


def _input_fields(ctx: RunContext, task_id: str) -> dict[tuple[str, str], str]:
    records = task_input(ctx, task_id).get("records")
    found: dict[tuple[str, str], str] = {}
    for record in records if isinstance(records, list) else []:
        if not isinstance(record, dict) or not isinstance(record.get("id"), str):
            continue
        fields = record.get("fields")
        for item in fields if isinstance(fields, list) else []:
            if isinstance(item, dict):
                path, text = item.get("path"), item.get("text")
                if isinstance(path, str) and isinstance(text, str):
                    found[(record["id"], path)] = text
    if not found:
        raise ValidationError(
            f"the input of {task_id} holds no field to polish", ["$input.records: missing"]
        )
    return found


def build_outcome(ctx: RunContext, task: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    """Return the ``polish.json`` document of a result (module docstring)."""
    task_id = task["id"]
    known = _input_fields(ctx, task_id)
    applied: list[dict[str, str]] = []
    rejected: list[dict[str, str]] = []
    handled: set[tuple[str, str]] = set()
    for record in result["records"]:
        for item in record["fields"]:
            key = (record["id"], item["path"])
            if key not in known:
                reason: str | None = UNKNOWN_FIELD
            elif key in handled:
                reason = DUPLICATE_FIELD
            else:
                handled.add(key)
                new = candidate_text(item["text"])
                reason = check_correction(known[key], new)
                if reason is None:
                    applied.append({"id": key[0], "path": key[1], "old": known[key], "new": new})
                    continue
            rejected.append({"id": key[0], "path": key[1], "reason": reason})
    return {"task_id": task_id, "applied": applied, "rejected": rejected}


def handle(ctx: RunContext, task: dict[str, Any], result: dict[str, Any]) -> None:
    """Check a polish result field by field, then write ``tasks/<id>/polish.json``."""
    outcome = build_outcome(ctx, task, result)
    write_json(ctx.task_dir(task["id"]) / OUTCOME_NAME, outcome)
