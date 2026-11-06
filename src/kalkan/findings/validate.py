# SPDX-License-Identifier: MIT
# Ported from cloudflare/security-audit-skill@c1c8a8c: skills/security-audit/validate-findings.cjs
# Copyright (c) 2025-2026 Cloudflare, Inc. Changes: translated from JavaScript to Python; added
# checks for the kalkan finding extensions (ENGINE-SPEC section 5) and for candidate records
# (section 4); the command-line runner became validate_findings_file.
"""Validate findings documents and candidate records (port of the Cloudflare findings validator).

A findings document is a JSON array of records in three branches selected by ``verdict``:
``confirmed``, ``needs_validation`` and ``rejected`` (``kalkan/schemas/finding.schema.json``).
:func:`validate_findings` runs the schema and then the document-level rules that the schema
cannot express:

- fingerprints are unique and sorted (UTF-16 code unit order, as JavaScript sorts);
- trace and evidence lines are positive and their files are safe repository-relative paths;
- a multi-step trace starts at ``entrypoint``, ends at ``sink`` and has ``propagation`` between;
  a one-step trace is ``entrypoint`` or ``sink``;
- each verdict forbids the fields of the other verdicts; ``needs_validation`` carries no severity;
- a confirmed record has a visible observed result and remediation, and its overall severity
  does not exceed the demonstrated impact;
- a ``needs_validation`` record has a visible local or deployment validation plan.

kalkan extensions add: unique finding ``id`` values, safe paths and positive lines in
``audit_answers`` evidence, safe ``poc.artifacts`` paths, a ``cvss.score`` of at most 10, no
``cvss`` outside ``confirmed``, and the consolidation fields: ``duplicate_of`` names another
record and comes with ``duplicate_reason``; a duplicate holds no ``related`` list. At most 100
errors are returned, with control characters escaped.
"""

from __future__ import annotations

import os
from types import MappingProxyType
from typing import Final

from kalkan.errors import UnsafeInputError
from kalkan.schema.loader import shared_schema
from kalkan.schema.validator import (
    LIMITS,
    JsonStructureError,
    check_schema,
    collect_data_limit_errors,
    collect_unchecked,
    enforce_json_text_limits,
    parse_json_text,
    property_path,
)
from kalkan.util.paths import (
    WINDOWS_RESERVED_COMPONENT,
    is_safe_relative_path,
    is_safe_relative_source_path,
)
from kalkan.util.safe_io import read_text_bounded
from kalkan.util.text import (
    PATH_FORBIDDEN_CHARACTER,
    UNDEFINED,
    UNSAFE_DIAGNOSTIC_CHARACTER,
    VISIBLE_CONTENT,
    ErrorList,
    escape_unsafe_diagnostic_characters,
    has_visible_prose,
    is_js_integer,
    is_number,
    js_number_str,
    safe_quote,
    type_of,
    utf16_key,
)

__all__ = [
    "LIMITS",
    "PATH_FORBIDDEN_CHARACTER",
    "SEVERITY_RANK",
    "UNSAFE_DIAGNOSTIC_CHARACTER",
    "VISIBLE_CONTENT",
    "WINDOWS_RESERVED_COMPONENT",
    "collect_finding_semantic_errors",
    "has_visible_prose",
    "is_safe_relative_source_path",
    "validate_candidate",
    "validate_document",
    "validate_findings",
    "validate_findings_file",
]

SEVERITY_RANK: Final = MappingProxyType(
    {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
)
_FORBIDDEN_FIELDS: Final = MappingProxyType(
    {
        "confirmed": ("claimed_root_cause", "blockers", "validation_plan", "reason"),
        "needs_validation": (
            "severity",
            "execution",
            "remediation",
            "reason",
            "root_cause",
            "cvss",
        ),
        "rejected": (
            "severity",
            "execution",
            "remediation",
            "blockers",
            "validation_plan",
            "root_cause",
            "cvss",
        ),
    }
)
_CVSS_MAXIMUM: Final = 10


def _prop(value: object, key: str) -> object:
    """Read ``value[key]`` like JavaScript: UNDEFINED unless ``value`` is an object with ``key``."""
    if isinstance(value, dict):
        return value.get(key, UNDEFINED)
    return UNDEFINED


def _js_truthy(value: object) -> bool:
    if value is None or value is UNDEFINED or value is False:
        return False
    if isinstance(value, bool):
        return True
    if isinstance(value, int | float):
        return value == value and value != 0  # NaN and zero are falsy
    if isinstance(value, str):
        return value != ""
    return True


def _is_positive_line(value: object) -> bool:
    return is_js_integer(value) and value >= 1


def _check_locations(finding: dict, base: str, errors: ErrorList) -> None:
    for field in ("trace", "evidence"):
        entries = finding.get(field)
        if not isinstance(entries, list):
            continue
        for entry_index, entry in enumerate(entries):
            if not isinstance(entry, dict):
                continue
            where = f"{base}.{field}[{entry_index}]"
            if "line" in entry and not _is_positive_line(entry["line"]):
                errors.push(f"{where}.line: must be a positive integer")
            if "file" in entry and not is_safe_relative_source_path(entry["file"]):
                errors.push(f"{where}.file: must be a safe repository-relative source path")
    changes = _prop(finding.get("remediation"), "code_changes")
    if isinstance(changes, list):
        for change_index, change in enumerate(changes):
            if (
                isinstance(change, dict)
                and "file_name" in change
                and not is_safe_relative_source_path(change["file_name"])
            ):
                errors.push(
                    f"{base}.remediation.code_changes[{change_index}].file_name: "
                    "must be a safe repository-relative source path"
                )


def _check_trace_order(finding: dict, base: str, errors: ErrorList) -> None:
    trace = finding.get("trace")
    if not isinstance(trace, list):
        return
    if len(trace) == 1:
        kind = _prop(trace[0], "kind")
        if kind != "entrypoint" and kind != "sink":
            errors.push(f'{base}.trace[0].kind: a one-line trace must be "entrypoint" or "sink"')
    elif len(trace) > 1:
        last = len(trace) - 1
        first_kind = _prop(trace[0], "kind")
        if _js_truthy(trace[0]) and first_kind != "entrypoint":
            errors.push(f'{base}.trace[0].kind: must be "entrypoint", got {safe_quote(first_kind)}')
        last_kind = _prop(trace[last], "kind")
        if _js_truthy(trace[last]) and last_kind != "sink":
            errors.push(f'{base}.trace[{last}].kind: must be "sink", got {safe_quote(last_kind)}')
        for trace_index in range(1, last):
            if errors.full:
                return
            kind = _prop(trace[trace_index], "kind")
            if _js_truthy(trace[trace_index]) and kind != "propagation":
                errors.push(
                    f'{base}.trace[{trace_index}].kind: must be "propagation", '
                    f"got {safe_quote(kind)}"
                )


def _check_verdict_rules(finding: dict, base: str, errors: ErrorList) -> None:
    verdict = finding.get("verdict")
    if not isinstance(verdict, str) or verdict not in _FORBIDDEN_FIELDS:
        return
    for name in _FORBIDDEN_FIELDS[verdict]:
        if name in finding:
            errors.push(f"{base}: {verdict} finding must not contain {safe_quote(name)}")
    if verdict == "confirmed":
        if not has_visible_prose(_prop(finding.get("execution"), "observed_result")):
            errors.push(f"{base}: confirmed finding requires a visible execution observed_result")
        if not has_visible_prose(_prop(finding.get("remediation"), "strategy")):
            errors.push(f"{base}: confirmed finding requires visible remediation")
        severity = finding.get("severity")
        overall = _prop(severity, "overall_severity")
        impact = _prop(_prop(severity, "impact"), "score")
        if (
            isinstance(overall, str)
            and isinstance(impact, str)
            and overall in SEVERITY_RANK
            and impact in SEVERITY_RANK
            and SEVERITY_RANK[overall] > SEVERITY_RANK[impact]
        ):
            errors.push(
                f"{base}.severity.overall_severity: cannot exceed demonstrated impact "
                f"{safe_quote(impact)}"
            )
    elif verdict == "needs_validation":
        plan = finding.get("validation_plan")
        if not has_visible_prose(_prop(plan, "local")) and not has_visible_prose(
            _prop(plan, "deployment")
        ):
            errors.push(
                f"{base}.validation_plan: requires at least one visible local or deployment plan"
            )


def _check_extensions(
    finding: dict, base: str, errors: ErrorList, finding_ids: dict[str, int], index: int
) -> None:
    finding_id = finding.get("id")
    if isinstance(finding_id, str):
        if finding_id in finding_ids:
            errors.push(f"{base}.id: duplicate of $[{finding_ids[finding_id]}].id")
        else:
            finding_ids[finding_id] = index
    answers = finding.get("audit_answers")
    if isinstance(answers, dict):
        for key, answer in answers.items():
            evidence = _prop(answer, "evidence")
            if not isinstance(evidence, list):
                continue
            where = property_path(f"{base}.audit_answers", key)
            for entry_index, entry in enumerate(evidence):
                if not isinstance(entry, dict):
                    continue
                if "line" in entry and not _is_positive_line(entry["line"]):
                    errors.push(f"{where}.evidence[{entry_index}].line: must be a positive integer")
                if "file" in entry and not is_safe_relative_source_path(entry["file"]):
                    errors.push(
                        f"{where}.evidence[{entry_index}].file: "
                        "must be a safe repository-relative source path"
                    )
    artifacts = _prop(finding.get("poc"), "artifacts")
    if isinstance(artifacts, list):
        for artifact_index, artifact in enumerate(artifacts):
            if not is_safe_relative_path(artifact):
                errors.push(f"{base}.poc.artifacts[{artifact_index}]: must be a safe relative path")
    score = _prop(finding.get("cvss"), "score")
    if is_number(score) and score > _CVSS_MAXIMUM:
        errors.push(
            f"{base}.cvss.score: must be at most {_CVSS_MAXIMUM}, got {js_number_str(score)}"
        )
    duplicate_of = finding.get("duplicate_of")
    if duplicate_of is not None:
        if isinstance(finding_id, str) and duplicate_of == finding_id:
            errors.push(f"{base}.duplicate_of: must name another record")
        if "related" in finding:
            errors.push(f"{base}.related: a duplicate record cannot hold related records")
        if "duplicate_reason" not in finding:
            errors.push(f"{base}.duplicate_reason: required with duplicate_of")
    elif "duplicate_reason" in finding:
        errors.push(f"{base}.duplicate_reason: allowed only with duplicate_of")


def collect_finding_semantic_errors(findings: object) -> list[str]:
    """Return the document-level errors of a findings array (port of
    ``collectFindingSemanticErrors``, plus the checks of the kalkan extensions).

    Records that are not objects are skipped; the schema reports them.
    """
    errors = ErrorList(LIMITS.validation_errors)
    if not isinstance(findings, list):
        return []
    fingerprints: dict[str, int] = {}
    finding_ids: dict[str, int] = {}
    previous: str | None = None
    for index, finding in enumerate(findings):
        if errors.full:
            break
        if not isinstance(finding, dict):
            continue
        base = f"$[{index}]"
        fingerprint = finding.get("fingerprint")
        if isinstance(fingerprint, str):
            if fingerprint in fingerprints:
                errors.push(
                    f"{base}.fingerprint: duplicate of $[{fingerprints[fingerprint]}].fingerprint"
                )
            else:
                fingerprints[fingerprint] = index
            if previous is not None and utf16_key(previous) > utf16_key(fingerprint):
                errors.push(f"{base}.fingerprint: findings must be sorted lexicographically")
            previous = fingerprint
        _check_locations(finding, base, errors)
        _check_trace_order(finding, base, errors)
        _check_verdict_rules(finding, base, errors)
        _check_extensions(finding, base, errors, finding_ids, index)
    return list(errors)


def _validate_checked(findings: object, schema: dict) -> list[str]:
    limit_errors = collect_data_limit_errors(findings, "$")
    if limit_errors:
        return limit_errors
    errors = collect_unchecked(findings, schema, "$")
    if not errors.full:
        errors.push(*collect_finding_semantic_errors(findings))
    return list(errors)


def validate_document(findings: object, schema: object) -> list[str]:
    """Validate ``findings`` against ``schema`` and the document rules (port of
    ``validateDocument``). Schema errors are returned first and stop the run."""
    schema_errors = check_schema(schema)
    if schema_errors:
        return schema_errors
    assert isinstance(schema, dict)  # check_schema rejects every other root
    return _validate_checked(findings, schema)


def validate_findings(doc: object) -> list[str]:
    """Return the errors of a parsed findings document; an empty list means valid."""
    return _validate_checked(doc, shared_schema("finding"))


def validate_findings_file(path: str | os.PathLike[str]) -> list[str]:
    """Read, parse and validate a findings file; an empty list means valid.

    Every failure becomes a message, in the upstream wording:

    - ``Failed to read findings JSON: <reason>`` (symlink, not a regular file, over 5 MiB,
      invalid UTF-8, or not readable);
    - ``Failed to parse findings JSON: <reason>`` (over 64 nesting levels, an array over 1000
      items, or invalid JSON syntax);
    - otherwise the validation errors of :func:`validate_findings` (at most 100).

    Messages never contain the path or raw control characters.
    """
    schema = shared_schema("finding")
    try:
        contents = read_text_bounded(path, LIMITS.input_bytes)
    except UnsafeInputError as exc:
        return [f"Failed to read findings JSON: {escape_unsafe_diagnostic_characters(exc)}"]
    try:
        enforce_json_text_limits(contents)
    except JsonStructureError as exc:
        return [f"Failed to parse findings JSON: {exc}"]
    try:
        findings = parse_json_text(contents)
    except JsonStructureError:
        return ["Failed to parse findings JSON: invalid JSON syntax"]
    try:
        return _validate_checked(findings, schema)
    except Exception:  # upstream reports a generic message, never a trace
        return ["Failed to validate findings JSON: unexpected validation error"]


def validate_candidate(candidate: object) -> list[str]:
    """Return the errors of one candidate record (``kalkan/schemas/candidate.schema.json``).

    Beyond the schema, the function checks that every ``fingerprints`` value is a string and that
    ``end_line`` is not less than ``start_line``.
    """
    limit_errors = collect_data_limit_errors(candidate, "$")
    if limit_errors:
        return limit_errors
    errors = collect_unchecked(candidate, shared_schema("candidate"), "$")
    if isinstance(candidate, dict):
        fingerprints = candidate.get("fingerprints")
        if isinstance(fingerprints, dict):
            for key, value in fingerprints.items():
                if not isinstance(value, str):
                    where = property_path("$.fingerprints", key)
                    errors.push(f"{where}: expected string, got {type_of(value)}")
        start, end = candidate.get("start_line"), candidate.get("end_line")
        if is_js_integer(start) and is_js_integer(end) and end < start:
            errors.push("$.end_line: must not be less than start_line")
    return list(errors)
