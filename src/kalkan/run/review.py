# SPDX-License-Identifier: MIT
"""Final review tasks: a second, independent check of the final records (docs/PHASES.md
sections 3, 4 and 7; Cloudflare security-audit Phase 5).

The validate step :data:`kalkan.run.budget.REVIEW_STEP` runs after every verify and sca_reach
task of the phase is settled. :func:`create_review_tasks` merges the findings of the done verify
tasks exactly as :mod:`kalkan.findings.merge` does (same ``id`` or ``fingerprint``), so that one
task reviews one final record, and creates one ``review`` task (phase ``validate``) per final
``confirmed`` and ``needs_validation`` record:

1. Order: every ``confirmed`` record first, then the ``needs_validation`` records; inside each
   group the higher severity score first (confirmed: likelihood + impact of the record;
   needs_validation: the suggested severity of the claim, or the tool severity), then the
   fingerprint.
2. Each record gets a task while ``budget.available(state, "review") >= 1`` (dedupe key
   ``review:<fingerprint>``; priority 70 for confirmed, 50 for needs_validation). The input holds
   only the canonical record (:func:`kalkan.findings.review.review_record`) and its checklist.
3. A ``confirmed`` record without budget sets the pending incomplete reason
   :data:`REASON_REVIEW` (Cloudflare: never skip the review of a confirmed record). A
   ``needs_validation`` record without budget stays unreviewed; the report says so.

The profile ``fast`` has no review step (the Cloudflare quick profile merges the record checks
into the validation pass). The function is idempotent through the dedupe keys.
"""

from __future__ import annotations

from typing import Any, Final

from kalkan.findings.merge import merge_with_sources
from kalkan.findings.review import REVIEWED_VERDICTS, SEVERITY_RANK
from kalkan.findings.validate import validate_findings
from kalkan.run import budget
from kalkan.run.cleaning import dedupe_key
from kalkan.run.inputs import review_input
from kalkan.run.runfiles import read_task_json, task_input, tasks_of_type, verify_findings
from kalkan.run.state import RunContext, transaction
from kalkan.run.tasks import find_by_dedupe_key, new_task
from kalkan.run.validation import severity_score
from kalkan.util.text import utf16_key

__all__ = [
    "REASON_REVIEW",
    "REVIEW_OUTCOME",
    "create_review_tasks",
    "final_records",
    "rejected_verify_tasks",
    "review_outcomes",
]

REASON_REVIEW: Final = "review_budget_exhausted"
REVIEW_OUTCOME: Final = "review.json"
_TOOL_SCORES: Final = {"critical": 8, "high": 6, "medium": 4, "low": 2, "info": 0}
_PRIORITY: Final = {"confirmed": 70, "needs_validation": 50}


def final_records(ctx: RunContext) -> list[tuple[dict[str, Any], list[str]]]:
    """Return the merged findings of the done verify tasks with their verify task IDs."""
    sources = [
        (task_id, finding)
        for task_id, finding in verify_findings(ctx)
        if not validate_findings([finding])
    ]
    return merge_with_sources(sources)


def _claim_score(ctx: RunContext, task_id: str) -> int:
    claim = task_input(ctx, task_id).get("claim")
    if not isinstance(claim, dict):
        return 4
    if isinstance(claim.get("suggested_severity"), dict):
        return severity_score(claim["suggested_severity"])
    return _TOOL_SCORES.get(str(claim.get("severity")), 4)


def _record_score(ctx: RunContext, finding: dict[str, Any], tasks: list[str]) -> int:
    severity = finding.get("severity")
    if finding["verdict"] == "confirmed" and isinstance(severity, dict):
        return sum(
            SEVERITY_RANK.get(str((severity.get(part) or {}).get("score")), 2)
            for part in ("likelihood", "impact")
        )
    return max((_claim_score(ctx, task_id) for task_id in tasks), default=4)


def create_review_tasks(ctx: RunContext) -> dict[str, int]:
    """Create the review tasks of the run (module docstring).

    Returns ``{"records", "created", "reused", "unfunded_confirmed",
    "unfunded_needs_validation"}``.
    """
    ctx.reload()
    records = [
        (finding, tasks)
        for finding, tasks in final_records(ctx)
        if finding.get("verdict") in REVIEWED_VERDICTS and isinstance(finding.get("id"), str)
    ]
    ranked = sorted(
        records,
        key=lambda item: (
            0 if item[0]["verdict"] == "confirmed" else 1,
            -_record_score(ctx, item[0], item[1]),
            utf16_key(item[0]["fingerprint"]),
        ),
    )
    summary = {
        "records": len(ranked),
        "created": 0,
        "reused": 0,
        "unfunded_confirmed": 0,
        "unfunded_needs_validation": 0,
    }
    for finding, tasks in ranked:
        verdict = finding["verdict"]
        key = dedupe_key("review", finding["fingerprint"])
        if find_by_dedupe_key(ctx.state, key) is not None:
            summary["reused"] += 1
            continue
        if budget.available(ctx.state, "review") < 1:
            summary[f"unfunded_{verdict}"] += 1
            continue
        new_task(
            ctx,
            "review",
            "validate",
            review_input(finding),
            priority=_PRIORITY[verdict],
            dedupe_key=key,
            meta={
                "finding": finding["id"],
                "fingerprint": finding["fingerprint"],
                "verdict": verdict,
                "verify_tasks": tasks,
            },
        )
        summary["created"] += 1
    if summary["unfunded_confirmed"]:
        with transaction(ctx) as tx:
            if not tx.state.get("incomplete_pending"):
                tx.state["incomplete_pending"] = REASON_REVIEW
                tx.event(
                    "incomplete_pending",
                    reason=REASON_REVIEW,
                    unreviewed=summary["unfunded_confirmed"],
                )
    return summary


def review_outcomes(ctx: RunContext) -> list[tuple[str, dict[str, Any]]]:
    """Return ``(task_id, outcome)`` of every done review task with a ``review.json``."""
    found = []
    for task_id, _ in tasks_of_type(ctx.state, "review", statuses=("done",)):
        outcome = read_task_json(ctx, task_id, REVIEW_OUTCOME)
        if isinstance(outcome, dict):
            found.append((task_id, outcome))
    return found


def rejected_verify_tasks(ctx: RunContext) -> set[str]:
    """Return the verify task IDs whose final record a review rejected."""
    rejected: set[str] = set()
    for _, outcome in review_outcomes(ctx):
        if outcome.get("verdict_after") == "rejected":
            tasks = outcome.get("verify_tasks")
            rejected.update(item for item in tasks or [] if isinstance(item, str))
    return rejected
