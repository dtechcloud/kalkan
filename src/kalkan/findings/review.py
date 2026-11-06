# SPDX-License-Identifier: MIT
"""The final review of a canonical finding (docs/PHASES.md section 4, ENGINE-SPEC section 18).

The ``review`` task is a second, independent pass over each final ``confirmed`` and
``needs_validation`` record (Cloudflare security-audit Phase 5, "verify the final records with
fresh eyes"). A reviewer sees only the canonical record (:func:`review_record`) and the source;
it never sees the verifier's audit answers or the hunter text.

The review handler (:mod:`kalkan.run.handlers.review`) checks a result and stores the outcome
in ``tasks/<id>/review.json``. :func:`apply_review` turns an outcome into the reviewed record.
The handler calls it on the record that the reviewer saw, so that a result that would give an
invalid record fails the attempt; :mod:`kalkan.findings.merge` calls it on the merged record.

Outcome fields that :func:`apply_review` reads: ``verdict_before``, ``decision`` (the applied
decision), ``reason``, ``severity`` (null or the lowered severity), ``remediation`` (null or the
corrected remediation), ``blockers`` (added blockers) and ``validation_plan`` (null, or the plan
of a confirmed record that becomes ``needs_validation``).

Rules. A reviewer never promotes a record:

- ``verified``: ``reviewer`` joins ``engines``. A confirmed record takes a lowered severity and a
  corrected remediation when the outcome has them; its confidence stays at most ``medium`` (no
  PoC ran).
- ``downgrade`` of a confirmed record: with a lowered severity the record stays confirmed with
  that severity; otherwise it becomes ``needs_validation`` with the reason as a blocker.
- ``downgrade`` of a ``needs_validation`` record: the reason joins the blockers.
- ``reject``: the record becomes ``rejected`` with the reason; ``findings.json`` keeps it.

Every reviewed record carries ``review = {decision, reason}``.
"""

from __future__ import annotations

import copy
from collections.abc import Mapping
from typing import Any, Final

__all__ = [
    "CHECKLISTS",
    "CONFIRMED_ONLY_FIELDS",
    "DECISIONS",
    "RECORD_FIELDS",
    "REVIEWED_VERDICTS",
    "REVIEWER_ENGINE",
    "SEVERITY_RANK",
    "apply_review",
    "lower_severity",
    "review_record",
]

REVIEWER_ENGINE: Final = "reviewer"
DECISIONS: Final = ("verified", "downgrade", "reject")
REVIEWED_VERDICTS: Final = ("confirmed", "needs_validation")
#: The Cloudflare Phase 5 checklist of each reviewed verdict (one ``checks`` item per entry).
CHECKLISTS: Final[Mapping[str, tuple[str, ...]]] = {
    "confirmed": (
        "trace_and_evidence",
        "entry_interface",
        "conditions_and_controls",
        "impact",
        "severity",
        "remediation",
    ),
    "needs_validation": (
        "source_path",
        "blockers",
        "boundary_and_result",
        "validation_plan",
        "fingerprint",
    ),
}
#: The canonical record fields that a reviewer sees (no audit answers, engines or candidates).
RECORD_FIELDS: Final = (
    "verdict",
    "fingerprint",
    "title",
    "description",
    "root_cause",
    "claimed_root_cause",
    "intended_behavior",
    "trace",
    "evidence",
    "conditions",
    "execution",
    "remediation",
    "severity",
    "confidence",
    "blockers",
    "validation_plan",
    "id",
    "class",
    "cwe",
)
#: Fields of the ``confirmed`` branch that the other branches forbid.
CONFIRMED_ONLY_FIELDS: Final = (
    "root_cause",
    "intended_behavior",
    "conditions",
    "execution",
    "remediation",
    "severity",
    "confidence",
    "cvss",
)
_NEEDS_VALIDATION_ONLY: Final = ("blockers", "validation_plan")
SEVERITY_RANK: Final = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def review_record(finding: Mapping[str, Any]) -> dict[str, Any]:
    """Return the part of a canonical finding that a reviewer sees (:data:`RECORD_FIELDS`)."""
    return {key: copy.deepcopy(finding[key]) for key in RECORD_FIELDS if key in finding}


def _score(part: object) -> int | None:
    value = part.get("score") if isinstance(part, Mapping) else None
    return SEVERITY_RANK.get(value) if isinstance(value, str) else None


def lower_severity(
    current: Mapping[str, Any], proposed: Mapping[str, Any]
) -> dict[str, Any] | None:
    """Return ``proposed`` limited to ``current``, or None when it lowers nothing.

    Likelihood and impact each take the proposed score (with its reason) only when it is lower.
    The overall severity is the lower of both overall values and never exceeds the new impact.
    The result never raises a score.
    """
    result: dict[str, Any] = {}
    lowered = False
    for part in ("likelihood", "impact"):
        old, new = _score(current.get(part)), _score(proposed.get(part))
        if old is not None and new is not None and new < old:
            result[part] = copy.deepcopy(proposed[part])
            lowered = True
        else:
            result[part] = copy.deepcopy(current[part])
    old_overall = SEVERITY_RANK.get(current.get("overall_severity"), 4)
    new_overall = SEVERITY_RANK.get(proposed.get("overall_severity"), old_overall)
    rank = min(old_overall, new_overall, _score(result["impact"]) or 0)
    if rank < old_overall:
        lowered = True
    result["overall_severity"] = next(
        name for name, value in SEVERITY_RANK.items() if value == rank
    )
    return result if lowered else None


def _cap_confidence(finding: dict[str, Any]) -> None:
    confidence = finding.get("confidence")
    if isinstance(confidence, dict) and confidence.get("score") == "high":
        confidence["score"] = "medium"


def _add_unique(finding: dict[str, Any], key: str, values: list[str]) -> None:
    items = list(finding.get(key) or [])
    for value in values:
        if value not in items:
            items.append(value)
    finding[key] = items


def _to_needs_validation(finding: dict[str, Any], outcome: Mapping[str, Any]) -> dict[str, Any]:
    record = {
        key: value
        for key, value in finding.items()
        if key not in CONFIRMED_ONLY_FIELDS and key != "verdict"
    }
    record["verdict"] = "needs_validation"
    record["claimed_root_cause"] = finding["root_cause"]
    record["blockers"] = list(outcome["blockers"])
    record["validation_plan"] = copy.deepcopy(outcome["validation_plan"])
    return record


def _to_rejected(finding: dict[str, Any], reason: str) -> dict[str, Any]:
    record = {
        key: value
        for key, value in finding.items()
        if key not in CONFIRMED_ONLY_FIELDS
        and key not in _NEEDS_VALIDATION_ONLY
        and key not in ("verdict", "claimed_root_cause")
    }
    record["verdict"] = "rejected"
    record["claimed_root_cause"] = finding.get("root_cause") or finding.get("claimed_root_cause")
    record["reason"] = reason
    return record


def apply_review(finding: Mapping[str, Any], outcome: Mapping[str, Any]) -> dict[str, Any]:
    """Return ``finding`` after the review ``outcome`` (module docstring). The input stays.

    Raises ``ValueError`` when the finding's verdict is not the outcome's ``verdict_before``
    (the record changed after the review).
    """
    record = copy.deepcopy(dict(finding))
    verdict = record.get("verdict")
    if verdict != outcome.get("verdict_before") or verdict not in REVIEWED_VERDICTS:
        raise ValueError(
            f"the review of a {outcome.get('verdict_before')} record cannot apply to a "
            f"{verdict} record"
        )
    decision, reason = outcome["decision"], outcome["reason"]
    if decision not in DECISIONS:
        raise ValueError(f"unknown review decision {decision!r}")
    if decision == "reject":
        record = _to_rejected(record, reason)
    elif verdict == "needs_validation":
        if decision == "downgrade":
            _add_unique(record, "blockers", list(outcome.get("blockers") or [reason]))
    elif decision == "downgrade" and not outcome.get("severity"):
        record = _to_needs_validation(record, outcome)
    else:  # a confirmed record stays confirmed
        if outcome.get("severity"):
            record["severity"] = copy.deepcopy(outcome["severity"])
        if outcome.get("remediation"):
            record["remediation"] = copy.deepcopy(outcome["remediation"])
        _cap_confidence(record)
    if decision == "verified":
        _add_unique(record, "engines", [REVIEWER_ENGINE])
    record["review"] = {"decision": decision, "reason": reason}
    return record
