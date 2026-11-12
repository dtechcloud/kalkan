# SPDX-License-Identifier: MIT
"""Severity normalization (ENGINE-SPEC section 7).

kalkan uses five severities: ``critical`` > ``high`` > ``medium`` > ``low`` > ``info``.
The functions map numeric scores, SARIF levels and tool text labels to this scale. The
``from_*`` functions return None for a value they do not recognize.

Precedence for a SARIF result (:func:`for_sarif_result`):

1. A numeric ``security-severity`` above 0: result properties, then rule properties.
2. A text label: the ``severity``, ``issue_severity`` and ``problem.severity`` properties of
   the result, then of the rule. Then a tag that is only a severity label (gosec writes the
   severity as a tag), in the result tags, then in the rule tags.
3. The result ``level``, then the rule ``defaultConfiguration.level``.
4. A ``security-severity`` of 0 gives ``info``. Trivy and Grype write ``0.0`` when they have
   no score, so a score of 0 yields to a label or a level.
5. ``medium``.
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Mapping
from typing import Any

SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low", "info")

_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

_LEVELS = {"error": "high", "warning": "medium", "note": "low", "none": "info"}

_LABELS = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
    "unknown": "info",
    # deepsec: HIGH_BUG and BUG are bugs without a security impact (ENGINE-SPEC 7).
    "high_bug": "info",
    "bug": "info",
    # Grype and Anchore use "Negligible" below "Low".
    "negligible": "info",
    # The CVSS qualitative rating of the score 0.0.
    "none": "info",
}

# A tag counts as a severity label only when it is one of these words. "bug" and "none" are
# common tags with another meaning.
_TAG_LABELS = frozenset(
    {"critical", "high", "medium", "moderate", "low", "info", "informational", "unknown"}
)

# CodeQL writes "problem.severity" with the values error, warning and recommendation.
_PROBLEM_SEVERITY = {"recommendation": "low"}

_LABEL_KEYS = ("severity", "issue_severity", "problem.severity")

_SECURITY_SEVERITY = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.5",
    "low": "2.0",
    "info": "0.0",
}

_DEFAULT = "medium"


def rank(severity: str) -> int:
    """Return the rank of a severity: ``info`` is 0, ``critical`` is 4.

    Raise ValueError for a value that is not a severity.
    """
    return _RANK[_canonical(severity)]


def from_score(value: float | int | str) -> str | None:
    """Map a CVSS score or a SARIF ``security-severity`` value to a severity.

    ``>= 9.0`` critical, ``>= 7.0`` high, ``>= 4.0`` medium, ``> 0`` low, ``0`` info.
    A numeric string is accepted. Return None for a negative, non-finite or non-numeric value.
    """
    score = _to_score(value)
    if score is None:
        return None
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def from_level(value: str) -> str | None:
    """Map a SARIF level to a severity: error high, warning medium, note low, none info."""
    if not isinstance(value, str):
        return None
    return _LEVELS.get(value.strip().lower())


def from_label(value: str) -> str | None:
    """Map a tool text label to a severity, case-insensitively.

    ``CRITICAL``; ``HIGH``; ``MEDIUM`` and ``MODERATE``; ``LOW``; ``INFO``,
    ``INFORMATIONAL`` and ``UNKNOWN``. Also: deepsec ``HIGH_BUG`` and ``BUG`` (info), Grype
    ``Negligible`` (info) and ``None`` (info). The canonical names map to themselves.
    """
    if not isinstance(value, str):
        return None
    key = value.strip().lower().replace("-", "_").replace(" ", "_")
    return _LABELS.get(key)


def max_severity(*values: str | None) -> str | None:
    """Return the highest of the given severities, or None when no value is given.

    None values are ignored. Raise ValueError for a value that is not a severity.
    """
    best: str | None = None
    for value in values:
        if value is None:
            continue
        current = _canonical(value)
        if best is None or _RANK[current] > _RANK[best]:
            best = current
    return best


def for_sarif_result(result: Mapping[str, Any], rule: Mapping[str, Any] | None) -> tuple[str, str]:
    """Return ``(severity, tool_severity)`` for a SARIF result and its rule.

    ``tool_severity`` is the value that decided, as text: the score, the label or the level.
    It is empty when no value was found and the default ``medium`` applies. See the module
    docstring for the precedence.
    """
    result_props = _properties(result)
    rule_props = _properties(rule)
    zero_score: str | None = None

    for props in (result_props, rule_props):
        raw = props.get("security-severity")
        score = _to_score(raw)
        if score is None:
            continue
        if score > 0:
            severity = from_score(score)
            if severity is not None:
                return severity, _as_text(raw)
        elif zero_score is None:
            zero_score = _as_text(raw)

    for props in (result_props, rule_props):
        for key in _LABEL_KEYS:
            raw = _label_value(props, key)
            severity = _label_or_level(raw)
            if severity is not None:
                return severity, raw.strip()

    for props in (result_props, rule_props):
        for tag in _strings(props.get("tags")):
            if tag.strip().lower() in _TAG_LABELS:
                severity = from_label(tag)
                if severity is not None:
                    return severity, tag.strip()

    for level in (_mapping(result).get("level"), _default_level(rule)):
        severity = from_level(level) if isinstance(level, str) else None
        if severity is not None:
            return severity, level.strip()

    if zero_score is not None:
        return "info", zero_score
    return _DEFAULT, ""


def to_sarif_level(severity: str | None, verdict: str | None = None) -> str:
    """Return the SARIF level for a finding (ENGINE-SPEC 8.2).

    A ``needs_validation`` finding gives ``warning``. Else critical and high give ``error``,
    medium gives ``warning``, and low, info and a missing severity give ``note``. Raise
    ValueError for a value that is not a severity.
    """
    if verdict == "needs_validation":
        return "warning"
    if severity is None:
        return "note"
    current = _canonical(severity)
    if current in ("critical", "high"):
        return "error"
    if current == "medium":
        return "warning"
    return "note"


def to_security_severity(severity: str) -> str:
    """Return the SARIF ``security-severity`` text for a severity.

    critical 9.5, high 8.0, medium 5.5, low 2.0, info 0.0. Raise ValueError for a value that
    is not a severity.
    """
    return _SECURITY_SEVERITY[_canonical(severity)]


def _canonical(value: str) -> str:
    severity = from_label(value) if isinstance(value, str) else None
    if severity is None:
        raise ValueError(f"not a severity: {value!r}")
    return severity


def _to_score(value: object) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        score = float(value)
    elif isinstance(value, str):
        try:
            score = float(value.strip())
        except ValueError:
            return None
    else:
        return None
    if not math.isfinite(score) or score < 0:
        return None
    return score


def _as_text(value: object) -> str:
    return value.strip() if isinstance(value, str) else str(value)


def _label_or_level(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    return from_label(value) or from_level(value) or _PROBLEM_SEVERITY.get(value.strip().lower())


def _label_value(props: Mapping[str, Any], key: str) -> Any:
    value = props.get(key)
    if value is None and "." in key:
        # Accept {"problem": {"severity": ...}} as well as the dotted key.
        head, _, tail = key.partition(".")
        value = _mapping(props.get(head)).get(tail)
    return value


def _default_level(rule: Mapping[str, Any] | None) -> Any:
    return _mapping(_mapping(rule).get("defaultConfiguration")).get("level")


def _properties(item: Mapping[str, Any] | None) -> Mapping[str, Any]:
    return _mapping(_mapping(item).get("properties"))


def _mapping(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _strings(value: object) -> Iterable[str]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []
