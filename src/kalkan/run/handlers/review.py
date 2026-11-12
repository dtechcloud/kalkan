# SPDX-License-Identifier: MIT
"""Handler of ``review`` results: the final independent review of one record (docs/PHASES.md
section 4, ENGINE-SPEC section 18).

1. The result's ``finding_id`` must equal the task's subject.
2. ``checks`` must hold every item of the record's checklist exactly once
   (:data:`kalkan.findings.review.CHECKLISTS`) and nothing else.
3. ``verified`` must not fail a check. Only ``severity`` and ``remediation`` may fail when the
   result gives the corrected field. A contradictory result fails the attempt.
4. Every evidence quote is checked with :func:`kalkan.findings.quote_verify.verify_evidence`.
   ``reject`` needs at least one verified quote; a ``reject`` without one is applied as a
   ``downgrade`` with the reason code :data:`UNGROUNDED_REJECTION`.
5. The applied decision (:func:`kalkan.findings.review.apply_review`): a corrected severity
   counts only when it lowers the record's severity (never raises it; the overall severity
   never exceeds the impact). A ``downgrade`` of a confirmed record without a lower severity
   makes it ``needs_validation`` with the reason as a blocker and a validation plan (the
   verifier's plan, else an engine plan). A corrected remediation counts for a record that stays
   confirmed. ``needs_validation`` records take no severity and no remediation.
6. The reviewed record must be a valid canonical finding; then ``tasks/<id>/review.json`` holds
   the outcome that :mod:`kalkan.findings.merge` applies to the merged record.
"""

from __future__ import annotations

import copy
from typing import Any, Final

from kalkan.errors import ValidationError
from kalkan.findings.quote_verify import Evidence, verify_evidence
from kalkan.findings.review import CHECKLISTS, REVIEWED_VERDICTS, apply_review, lower_severity
from kalkan.findings.validate import validate_findings
from kalkan.run.cleaning import clean_text, normalize_path, unique
from kalkan.run.runfiles import read_task_json, target_get_lines, task_input, write_json
from kalkan.run.state import RunContext, parse_task_id
from kalkan.util.paths import is_safe_relative_path

__all__ = ["UNGROUNDED_REJECTION", "handle"]

UNGROUNDED_REJECTION: Final = "ungrounded_rejection"
OUTCOME_NAME: Final = "review.json"
_CORRECTABLE: Final = ("severity", "remediation")
_ENGINE_PLAN: Final = {
    "tr": "Bağımsız inceleme bu bulguyu doğrulanmış tutmadı. İnceleme notunu kaynakta veya "
    "yerel bir testte kontrol et: {reason}",
    "en": "The independent review did not keep this finding confirmed. Check the review note "
    "in source or in a local test: {reason}",
}


def _check_checklist(task_id: str, verdict: str, checks: list[dict[str, Any]]) -> None:
    wanted = CHECKLISTS[verdict]
    items = [check["item"] for check in checks]
    errors = []
    for item in wanted:
        count = items.count(item)
        if count == 0:
            errors.append(f"$result.checks: missing {item}")
        elif count > 1:
            errors.append(f"$result.checks: {item} appears {count} times")
    errors += [
        f"$result.checks: {item} is not on the {verdict} checklist"
        for item in unique(items)
        if item not in wanted
    ]
    if errors:
        raise ValidationError(
            f"the checks of {task_id} do not follow the {verdict} checklist", errors
        )


def _check_verified(task_id: str, result: dict[str, Any]) -> None:
    allowed = {name for name in _CORRECTABLE if name in result}
    failed = [check["item"] for check in result["checks"] if not check["ok"]]
    bad = [item for item in failed if item not in allowed]
    if bad:
        raise ValidationError(
            f"the result of {task_id} says verified but a check failed",
            [f"$result.checks: {item} is not ok; decide downgrade or reject" for item in bad],
        )


def _quotes(result: dict[str, Any], ctx: RunContext) -> tuple[list[dict[str, Any]], int]:
    get_lines = target_get_lines(ctx)
    statuses, verified = [], 0
    for item in result["evidence"]:
        path = normalize_path(item["file"])
        file = path if isinstance(path, str) else item["file"]
        passed = verify_evidence([Evidence(file, item["line"], item["quote"])], get_lines)
        statuses.append(
            {**item, "file": file, "quote_status": "verified" if passed else "unverified"}
        )
        verified += len(passed)
    return statuses, verified


def _remediation(remediation: dict[str, Any], notes: list[str]) -> dict[str, Any]:
    result = copy.deepcopy(remediation)
    changes = result.get("code_changes")
    if isinstance(changes, list):
        kept = []
        for change in changes:
            name = normalize_path(change.get("file_name"))
            if isinstance(name, str) and is_safe_relative_path(name):
                kept.append({**change, "file_name": name})
            else:
                notes.append("remediation code change without a safe file name dropped")
        result["code_changes"] = kept
    return result


def _validation_plan(ctx: RunContext, verify_tasks: list[str], reason: str) -> dict[str, str]:
    """Return the verifier's validation plan of the record, else an engine plan."""
    for task_id in verify_tasks:
        if not isinstance(task_id, str) or parse_task_id(task_id) is None:
            continue
        result = read_task_json(ctx, task_id, "result.json")
        finding = result.get("finding") if isinstance(result, dict) else None
        plan = finding.get("validation_plan") if isinstance(finding, dict) else None
        if isinstance(plan, dict):
            kept = {
                key: plan[key]
                for key in ("local", "deployment")
                if isinstance(plan.get(key), str) and clean_text(plan[key])
            }
            if kept:
                return kept
    template = _ENGINE_PLAN.get(ctx.lang, _ENGINE_PLAN["en"])
    return {"local": template.format(reason=clean_text(reason, 1000))}


def build_outcome(
    ctx: RunContext, task: dict[str, Any], result: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return ``(outcome, reviewed record)`` for a review result (module docstring)."""
    task_id = task["id"]
    data = task_input(ctx, task_id)
    subject, record = data.get("subject"), data.get("finding")
    if (
        not isinstance(subject, dict)
        or not isinstance(record, dict)
        or record.get("verdict") not in REVIEWED_VERDICTS
    ):
        raise ValidationError(
            f"the input of {task_id} holds no reviewable record", ["$input.finding: missing"]
        )
    if result["finding_id"] != subject.get("finding_id"):
        raise ValidationError(
            f"the result of {task_id} reviews another finding",
            [f"$result.finding_id: must be {subject.get('finding_id')}"],
        )
    verdict = record["verdict"]
    _check_checklist(task_id, verdict, result["checks"])
    requested = result["decision"]
    if requested == "verified":
        _check_verified(task_id, result)
    evidence, verified = _quotes(result, ctx)
    reason = result["reason"]
    notes: list[str] = []
    codes: list[str] = []
    decision = requested
    if requested == "reject" and not verified:
        decision = "downgrade"
        codes.append(UNGROUNDED_REJECTION)
        notes.append("reject without a verified quote: applied as a downgrade")
    meta = task.get("meta") or {}
    verify_tasks = [item for item in meta.get("verify_tasks") or [] if isinstance(item, str)]
    severity = remediation = plan = None
    blockers: list[str] = []
    if verdict == "confirmed" and decision != "reject":
        if "severity" in result:
            severity = lower_severity(record["severity"], result["severity"])
            if severity is None:
                notes.append("the corrected severity lowers nothing; the record keeps its own")
        if decision == "downgrade" and severity is None:
            blockers = unique([reason, *codes])
            plan = _validation_plan(ctx, verify_tasks, reason)
        elif "remediation" in result:
            remediation = _remediation(result["remediation"], notes)
    elif verdict == "needs_validation":
        if decision == "downgrade":
            blockers = unique([reason, *codes])
        if any(name in result for name in _CORRECTABLE):
            notes.append("a needs_validation record takes no severity or remediation; ignored")
    outcome: dict[str, Any] = {
        "task_id": task_id,
        "finding_id": subject["finding_id"],
        "fingerprint": record.get("fingerprint"),
        "verify_tasks": verify_tasks,
        "verdict_before": verdict,
        "requested": requested,
        "decision": decision,
        "reason": reason,
        "severity": severity,
        "remediation": remediation,
        "blockers": blockers,
        "validation_plan": plan,
        "verdict_after": None,
        "checks": copy.deepcopy(result["checks"]),
        "evidence": evidence,
        "verified_quotes": verified,
        "normalized": notes,
    }
    reviewed = apply_review(record, outcome)
    outcome["verdict_after"] = reviewed["verdict"]
    return outcome, reviewed


def handle(ctx: RunContext, task: dict[str, Any], result: dict[str, Any]) -> None:
    """Check a review result, then write ``tasks/<id>/review.json``."""
    outcome, reviewed = build_outcome(ctx, task, result)
    errors = validate_findings([reviewed])
    if errors:
        raise ValidationError(
            f"the result of {task['id']} does not give a valid reviewed record", errors
        )
    write_json(ctx.task_dir(task["id"]) / OUTCOME_NAME, outcome)
