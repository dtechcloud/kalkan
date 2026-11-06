# SPDX-License-Identifier: Apache-2.0
# Ported from block/codecrucible@b5c8086: internal/cli/scan_audit_v2.go
# Copyright 2026 Block, Inc. Changes: translated from Go to Python; source lines come from an
# injected get_lines callable (no path repair, evidence keeps the cited path); canonical
# verdict mapping, JSON entry point and kalkan error types added.
"""Evidence quote verification and the verdict policy (ENGINE-SPEC 6.3).

An agent answers three evidentiary questions per finding and quotes the source lines behind
each answer. This module keeps only the quotes that appear in the source near the cited line.
It downgrades an answer when its evidence fails. Then it computes the verdict in code:

- A refuted answer (with a verified quote) rejects the finding.
- Three established answers confirm the finding.
- Anything else leaves the finding unverified. Missing evidence never rejects.

The module never opens files. Source lines come from an injected ``get_lines(path)`` callable
that returns the lines of a file, or None when the file is not available.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass, field
from typing import Any

from kalkan.errors import ValidationError
from kalkan.findings.fingerprint import (
    GetLines,
    cached_get_lines,
    collapse_whitespace,
    trim_whitespace,
)

#: The evidentiary questions, in prompt order (Go ``llm.AuditQuestions``). Each has the same
#: polarity: "established" supports the finding and "refuted" defeats it.
QUESTIONS = ("attacker_control", "privilege_boundary", "unmitigated")
STATUSES = ("established", "refuted", "unknown")
EXPOSURE_STATUSES = ("default_on", "config_enabled", "config_dependent", "not_deployed", "unknown")

#: Reason code: the answer cited quotes, but no quote is in the source.
UNVERIFIED_EVIDENCE = "unverified_evidence"
#: Reason code: the answer is "refuted" without a quote.
UNGROUNDED_REFUTATION = "ungrounded_refutation"

CONFIRMED = "confirmed"
REJECTED = "rejected"
UNVERIFIED = "unverified"
NEEDS_VALIDATION = "needs_validation"

#: A collapsed quote needs at least this many UTF-8 bytes (Go ``len``). A lone brace never passes.
MIN_QUOTE_BYTES = 4
#: Lines before and after the cited line that a quote can come from.
WINDOW_LINES = 2

# Go: regexp.MustCompile(`^\s*\d+\|\s?`). In RE2, \s is [\t\n\f\r ] and \d is [0-9].
# Python \s and \d also match other Unicode characters, so the classes are explicit.
_LINE_NUMBER_PREFIX = re.compile(r"^[\t\n\f\r ]*[0-9]+\|[\t\n\f\r ]?")

_CANONICAL = {
    CONFIRMED: CONFIRMED,
    REJECTED: REJECTED,
    UNVERIFIED: NEEDS_VALIDATION,
    NEEDS_VALIDATION: NEEDS_VALIDATION,
}
_DUPLICATE_RANK = {CONFIRMED: 2, UNVERIFIED: 1, NEEDS_VALIDATION: 1}
_DOTTED_CAPITAL_I = chr(0x0130)


@dataclass(frozen=True, slots=True)
class Evidence:
    """One quoted source line: the file path, the 1-based line and the quoted text."""

    file: str
    line: int
    quote: str


@dataclass(frozen=True, slots=True)
class Answer:
    """The answer to one question: a status, a one-sentence reason and the evidence."""

    status: str
    reason: str = ""
    evidence: list[Evidence] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class Exposure:
    """Deployment exposure: a status from :data:`EXPOSURE_STATUSES`, a detail and evidence."""

    status: str
    detail: str = ""
    evidence: list[Evidence] = field(default_factory=list)


def numbered_source(text: str) -> str:
    """Return ``text`` with each line prefixed by ``"N| "``, the form that evidence cites.

    Port of Go ``numberedSource``. Lines are split on ``"\\n"``, the same split that
    ``get_lines`` must use. Every output line ends with ``"\\n"``.
    """
    lines = text.split("\n")
    if lines[-1] == "":
        lines.pop()
    return "".join(f"{number}| {line}\n" for number, line in enumerate(lines, start=1))


def verify_quote(lines: Sequence[str], line: int, quote: str) -> bool:
    """Return True when ``quote`` appears in the source near the 1-based ``line``.

    Port of the check in Go ``evidenceVerifier.verify``:

    - ``line`` must be between 1 and ``len(lines)``.
    - The window is the cited line and two lines on each side, joined with spaces and
      whitespace-collapsed.
    - The quote passes as given, or without a leading ``N|`` line-number prefix, when its
      whitespace-collapsed form has at least 4 UTF-8 bytes, contains a letter and occurs in
      the window.
    """
    return _matching_quote(lines, line, quote) is not None


def verify_evidence(evidence: Iterable[Evidence], get_lines: GetLines) -> list[Evidence]:
    """Return the evidence items whose quotes pass :func:`verify_quote`, in order.

    Port of Go ``evidenceVerifier.verify``. An item whose file ``get_lines`` cannot supply
    does not pass. A passed item keeps its cited file and line. Its quote is the form that
    passed (as given or without the prefix), trimmed.
    """
    lines_for = cached_get_lines(get_lines)
    verified: list[Evidence] = []
    for item in evidence:
        lines = lines_for(item.file) if item.file else None
        if lines is None:
            continue
        quote = _matching_quote(lines, item.line, item.quote)
        if quote is not None:
            verified.append(Evidence(item.file, item.line, quote))
    return verified


def check_answer(answer: Answer, get_lines: GetLines) -> tuple[Answer, str | None]:
    """Keep only the verified evidence of ``answer`` and downgrade it when the evidence fails.

    Port of Go ``evidenceVerifier.answer``. The status is trimmed and in lower case, and the
    reason is trimmed. The result is ``(answer, reason_code)``:

    - The status is "unknown", or a quote passed: the answer stays, the code is None.
    - Quotes were cited, but none passed: "unknown" with :data:`UNVERIFIED_EVIDENCE`.
    - "refuted" without quotes: "unknown" with :data:`UNGROUNDED_REFUTATION`.
    - Otherwise the answer stays, the code is None. A status outside :data:`STATUSES` also
      stays. :func:`compute_verdict` counts it as unknown.
    """
    status = _answer_status(answer.status)
    reason = trim_whitespace(answer.reason)
    evidence = verify_evidence(answer.evidence, get_lines)
    if status == "unknown" or evidence:
        return Answer(status, reason, evidence), None
    if answer.evidence:
        return Answer("unknown", reason, evidence), UNVERIFIED_EVIDENCE
    if status == "refuted":
        return Answer("unknown", reason, evidence), UNGROUNDED_REFUTATION
    return Answer(status, reason, evidence), None


def check_exposure(exposure: Exposure, get_lines: GetLines) -> Exposure | None:
    """Check deployment exposure under the same evidence rule as the answers.

    Port of Go ``evidenceVerifier.exposure``. A status outside :data:`EXPOSURE_STATUSES`
    becomes "unknown". Cited quotes that all fail make the status "unknown". "not_deployed"
    needs a verified quote. The result is None when the status is "unknown" and the detail is
    empty. Exposure never changes the verdict.
    """
    status = _answer_status(exposure.status)
    detail = trim_whitespace(exposure.detail)
    evidence = verify_evidence(exposure.evidence, get_lines)
    if status not in EXPOSURE_STATUSES:
        status = "unknown"
    if not evidence and (exposure.evidence or status == "not_deployed"):
        status = "unknown"
    if status == "unknown" and not detail:
        return None
    return Exposure(status, detail, evidence)


def audit_verdict(answers: Mapping[str, Answer]) -> tuple[str, list[str]]:
    """Return ``(verdict, reasons)`` for checked answers. Port of Go ``auditVerdictV2``.

    - Any "refuted" answer: ``"rejected"``, reasons ``["refuted:<question>", ...]``.
    - Three "established" answers: ``"confirmed"``, no reasons.
    - Otherwise: ``"unverified"``, reasons ``["unknown:<question>", ...]``.

    A missing question counts as unknown. The status must match exactly, so give answers
    that :func:`check_answer` returned.
    """
    refuted: list[str] = []
    unknown: list[str] = []
    for question in QUESTIONS:
        answer = answers.get(question)
        status = answer.status if answer is not None else ""
        if status == "refuted":
            refuted.append(question)
        elif status != "established":
            unknown.append(question)
    if refuted:
        return REJECTED, [f"refuted:{question}" for question in refuted]
    if not unknown:
        return CONFIRMED, []
    return UNVERIFIED, [f"unknown:{question}" for question in unknown]


def compute_verdict(answers: Mapping[str, Answer]) -> str:
    """Return ``"confirmed"``, ``"rejected"`` or ``"unverified"`` (see :func:`audit_verdict`)."""
    return audit_verdict(answers)[0]


def to_canonical_verdict(verdict: str) -> str:
    """Map a verdict to the canonical finding verdict.

    ``"confirmed"`` and ``"rejected"`` stay. ``"unverified"`` becomes ``"needs_validation"``.
    ``"needs_validation"`` stays. Any other value raises ``ValueError``.
    """
    try:
        return _CANONICAL[verdict]
    except KeyError:
        raise ValueError(f"unknown verdict: {verdict!r}") from None


def mark_duplicates(
    verdicts: Mapping[str, str],
    duplicate_of: Mapping[str, str],
    batch_of: Mapping[str, int] | None = None,
) -> dict[str, str]:
    """Return ``{finding_id: primary_id}`` for each ``duplicate_of`` claim that is honored.

    Port of Go ``markDuplicates``. ``verdicts`` maps each assessed finding to its verdict.
    ``duplicate_of`` maps a finding to the primary finding that its assessment names (or "").
    With ``batch_of`` None, all findings are in one batch. A finding is a duplicate of its
    target only when all of these are true:

    - The finding is not rejected.
    - The target is a different assessed finding in the same batch.
    - The target names no duplicate itself.
    - The target's verdict ranks at least as high as the finding's verdict
      (confirmed > unverified or needs_validation > other).

    Thus the finding that stays visible is never the weaker one.
    """
    batches = batch_of or {}
    honored: dict[str, str] = {}
    for finding, verdict in verdicts.items():
        if verdict == REJECTED:
            continue
        target = trim_whitespace(duplicate_of.get(finding) or "")
        if not target or target == finding or target not in verdicts:
            continue
        if batches.get(target, 0) != batches.get(finding, 0):
            continue
        if trim_whitespace(duplicate_of.get(target) or ""):
            continue
        if _DUPLICATE_RANK.get(verdicts[target], 0) < _DUPLICATE_RANK.get(verdict, 0):
            continue
        honored[finding] = target
    return honored


def evaluate(answers_json: Mapping[str, Any], get_lines: GetLines) -> dict[str, Any]:
    """Check the ``audit_answers`` JSON of a finding and compute its canonical verdict.

    Port of Go ``evaluateAssessment`` for the three questions. The input has the shape of
    ``audit_answers`` (ENGINE-SPEC 5). The result is::

        {"verdict": "confirmed" | "rejected" | "needs_validation",
         "audit_answers": {<question>: {"status", "reason", "evidence": [...]}},
         "reasons": {<question>: "unverified_evidence" | "ungrounded_refutation"}}

    ``audit_answers`` holds all three questions with only the verified evidence. ``reasons``
    holds only the downgraded questions.

    Raises ``ValidationError`` when an answer is missing or not an object, when a status is
    not "established", "refuted" or "unknown" (after trim and lower case), or when a value
    has the wrong JSON type. A null value counts as empty, like the Go JSON decoder.
    """
    answers = _parse_answers(answers_json)
    lines_for = cached_get_lines(get_lines)
    checked: dict[str, Answer] = {}
    reasons: dict[str, str] = {}
    for question in QUESTIONS:
        answer, code = check_answer(answers[question], lines_for)
        checked[question] = answer
        if code is not None:
            reasons[question] = code
    return {
        "verdict": to_canonical_verdict(compute_verdict(checked)),
        "audit_answers": {question: asdict(checked[question]) for question in QUESTIONS},
        "reasons": reasons,
    }


def _answer_status(status: str) -> str:
    # Go strings.ToLower uses simple case mapping: U+0130 becomes "i". Python lower() gives
    # "i" plus U+0307, so the Turkish dotted capital I is mapped first.
    return trim_whitespace(status).replace(_DOTTED_CAPITAL_I, "i").lower()


def _matching_quote(lines: Sequence[str], line: int, quote: str) -> str | None:
    """Return the trimmed form of ``quote`` that passes, or None (see :func:`verify_quote`)."""
    if line < 1 or line > len(lines):
        return None
    # Go: lines[max(0, L-3):min(len(lines), L+2)], which is lines L-2 to L+2 (1-based).
    start = max(0, line - 1 - WINDOW_LINES)
    stop = min(len(lines), line + WINDOW_LINES)
    window = collapse_whitespace(" ".join(lines[start:stop]))
    for candidate in (quote, _LINE_NUMBER_PREFIX.sub("", quote, count=1)):
        collapsed = collapse_whitespace(candidate)
        if (
            len(collapsed.encode("utf-8", "surrogatepass")) >= MIN_QUOTE_BYTES
            and any(char.isalpha() for char in collapsed)
            and collapsed in window
        ):
            return trim_whitespace(candidate)
    return None


def _parse_answers(data: object) -> dict[str, Answer]:
    if not isinstance(data, Mapping):
        raise ValidationError(
            "audit_answers failed validation", ["audit_answers: expected an object"]
        )
    errors: list[str] = []
    answers: dict[str, Answer] = {}
    for question in QUESTIONS:
        where = f"audit_answers.{question}"
        value = data.get(question)
        if not isinstance(value, Mapping):
            errors.append(f"{where}: expected an object with a status")
            continue
        answer = _parse_answer(value, where, errors)
        if answer is not None:
            answers[question] = answer
    if errors:
        raise ValidationError("audit_answers failed validation", errors)
    return answers


def _parse_answer(data: Mapping[str, Any], where: str, errors: list[str]) -> Answer | None:
    count = len(errors)
    status = _or_empty(data.get("status"), "")
    if not isinstance(status, str) or _answer_status(status) not in STATUSES:
        errors.append(f"{where}.status: expected established, refuted or unknown")
    reason = _or_empty(data.get("reason"), "")
    if not isinstance(reason, str):
        errors.append(f"{where}.reason: expected a string")
    evidence = _parse_evidence(data.get("evidence"), f"{where}.evidence", errors)
    if len(errors) > count:
        return None
    return Answer(status, reason, evidence)


def _parse_evidence(data: object, where: str, errors: list[str]) -> list[Evidence]:
    if data is None:
        return []
    if not isinstance(data, list):
        errors.append(f"{where}: expected an array")
        return []
    evidence: list[Evidence] = []
    for index, item in enumerate(data):
        at = f"{where}[{index}]"
        if item is None:
            item = {}
        if not isinstance(item, Mapping):
            errors.append(f"{at}: expected an object")
            continue
        file = _or_empty(item.get("file"), "")
        line = _or_empty(item.get("line"), 0)
        quote = _or_empty(item.get("quote"), "")
        problems = []
        if not isinstance(file, str):
            problems.append(f"{at}.file: expected a string")
        if not isinstance(line, int) or isinstance(line, bool):
            problems.append(f"{at}.line: expected an integer")
        if not isinstance(quote, str):
            problems.append(f"{at}.quote: expected a string")
        if problems:
            errors.extend(problems)
        else:
            evidence.append(Evidence(file, line, quote))
    return evidence


def _or_empty(value: Any, empty: Any) -> Any:
    # The Go JSON decoder leaves the zero value for null.
    return empty if value is None else value
