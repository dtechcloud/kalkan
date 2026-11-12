# SPDX-License-Identifier: MIT
"""SARIF 2.1.0 emit: canonical findings to one SARIF run (ENGINE-SPEC 8.2).

The output is deterministic: the same findings in any order give the same document.

- Rules: one per class, else one per CWE, else ``unclassified``. Order: taxonomy order, then
  unknown class slugs, then CWE rules by number, then ``unclassified``.
- Results: sorted by file, line, rule ID, finding ID and the finding content.
- Location: :func:`kalkan.findings.fingerprint.finding_location`, the location that the
  finding ID also uses. URIs are relative to ``%SRCROOT%``, the target root.
- ``partialFingerprints["kalkanFinding/v1"]`` is the full finding hash. Its collision counter
  is the one that reproduces the ``KF-`` ID. When no counter reproduces it (for example, a
  CWE changed after the ID was assigned), the first counter that no other result uses wins.
- Suppressions: a ``rejected`` finding gets ``{kind: external, status: accepted,
  justification: <reason>}``. A record that consolidation folded into another one
  (``duplicate_of``) stays a result with ``{kind: external, status: accepted, justification:
  "duplicate of <id>"}`` and the property ``duplicateOf``, so code-scanning views hide it.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

from kalkan.findings.fingerprint import (
    FINGERPRINT_KEY,
    GetLines,
    cached_get_lines,
    finding_hash,
    finding_location,
)
from kalkan.findings.severity import from_label, to_sarif_level, to_security_severity
from kalkan.findings.taxonomy import SLUGS, get_class, normalize_cwe
from kalkan.util.safe_io import atomic_write_json

SARIF_SCHEMA = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
)
SARIF_VERSION = "2.1.0"
TOOL_NAME = "kalkan"
#: The uriBaseId of every location: the target root.
SOURCE_ROOT_ID = "%SRCROOT%"
UNCLASSIFIED_RULE = "unclassified"
UNCLASSIFIED_TITLE = "Unclassified finding"

# The class that is not a security class. Its rule does not get the "security" tag.
_NON_SECURITY_CLASSES = frozenset({"code-quality"})
# The highest collision counter that is tried to reproduce a finding ID.
_MAX_COUNTER = 64
_SLUG_ORDER = {slug: index for index, slug in enumerate(SLUGS)}
_CONFIDENCE = frozenset({"high", "medium", "low"})


@dataclass(frozen=True)
class _Entry:
    finding: Mapping[str, Any]
    verdict: str
    class_slug: str | None
    raw_cwe: tuple[str, ...]
    cwe: tuple[str, ...]
    rule_id: str
    severity: str | None
    confidence: str | None
    file: str
    line: int | None
    snippet: str | None
    finding_id: str
    sort_key: tuple[Any, ...]

    def hash_inputs(self) -> dict[str, Any]:
        return {
            "cwe": list(self.raw_cwe),
            "class_slug": self.class_slug,
            "rule_id": None,
            "uri": self.file,
            "snippet": self.snippet,
            "start_line": self.line,
        }


def emit(
    findings: Sequence[Mapping[str, Any]],
    *,
    tool_version: str,
    run_id: str,
    get_lines: GetLines | None = None,
) -> dict[str, Any]:
    """Return a SARIF 2.1.0 document with one run for ``findings``.

    ``get_lines(path)`` gives the source lines of a target file. Pass the same callable that
    assigned the finding IDs (``fingerprint.assign_finding_ids``), so that the full hash
    matches the ID. Without it, the hash anchor is ``line:<line>``.
    """
    lines_for = cached_get_lines(get_lines) if get_lines is not None else None
    entries = sorted(
        (_entry(finding, lines_for) for finding in findings), key=lambda item: item.sort_key
    )

    seen_cwe: dict[str, list[str]] = {}
    for entry in entries:
        cwes = seen_cwe.setdefault(entry.rule_id, [])
        cwes.extend(cwe for cwe in entry.cwe if cwe not in cwes)
    rule_ids = sorted(seen_cwe, key=_rule_sort_key)
    rule_index = {rule_id: index for index, rule_id in enumerate(rule_ids)}
    hashes = _partial_hashes(entries)

    results = [
        _result(entry, rule_index[entry.rule_id], hashes[index])
        for index, entry in enumerate(entries)
    ]
    driver = {
        "name": TOOL_NAME,
        "version": tool_version,
        "rules": [_rule(rule_id, seen_cwe[rule_id]) for rule_id in rule_ids],
    }
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {"driver": driver},
                "automationDetails": {"id": f"{TOOL_NAME}/{run_id}"},
                "results": results,
            }
        ],
    }


def write_sarif(path: str | os.PathLike[str], sarif: Mapping[str, Any]) -> None:
    """Write ``sarif`` to ``path`` in the kalkan JSON format, atomically.

    :func:`kalkan.util.safe_io.atomic_write_json` writes UTF-8 with ``\\n`` line endings to a
    temporary file and then replaces ``path``. The parent directory must exist. NaN and
    infinity raise ``ValueError``, because they are not JSON.
    """
    atomic_write_json(path, sarif)


def _entry(finding: Mapping[str, Any], lines_for: GetLines | None) -> _Entry:
    class_slug = _text(finding.get("class")) or None
    raw_cwe = tuple(item for item in _list(finding.get("cwe")) if isinstance(item, str))
    cwe = tuple(dict.fromkeys(c for c in map(normalize_cwe, raw_cwe) if c is not None))
    rule_id = class_slug or (cwe[0] if cwe else UNCLASSIFIED_RULE)
    file, line = finding_location(finding)
    finding_id = _text(finding.get("id"))
    sort_key = (
        file,
        line or 0,
        rule_id,
        finding_id,
        _text(finding.get("fingerprint")),
        _text(finding.get("title")),
        json.dumps(finding, sort_keys=True, ensure_ascii=False, default=str),
    )
    return _Entry(
        finding=finding,
        verdict=_text(finding.get("verdict")),
        class_slug=class_slug,
        raw_cwe=raw_cwe,
        cwe=cwe,
        rule_id=rule_id,
        severity=_overall_severity(finding),
        confidence=_confidence(finding),
        file=file,
        line=line,
        snippet=_source_line(lines_for, file, line),
        finding_id=finding_id,
        sort_key=sort_key,
    )


def _rule_sort_key(rule_id: str) -> tuple[int, int, str]:
    if rule_id in _SLUG_ORDER:
        return (0, _SLUG_ORDER[rule_id], "")
    if rule_id == UNCLASSIFIED_RULE:
        return (3, 0, "")
    cwe = normalize_cwe(rule_id) if rule_id.upper().startswith("CWE-") else None
    if cwe is not None:
        return (2, int(cwe[4:]), rule_id)
    return (1, 0, rule_id)


def _rule(rule_id: str, seen_cwe: list[str]) -> dict[str, Any]:
    item = get_class(rule_id)
    if item is not None:
        text = item.title_en
        cwes = [*item.cwe, *(cwe for cwe in seen_cwe if cwe not in item.cwe)]
        security = item.slug not in _NON_SECURITY_CLASSES
    elif rule_id == UNCLASSIFIED_RULE:
        text, cwes, security = UNCLASSIFIED_TITLE, list(seen_cwe), True
    else:
        # A CWE rule (no class), or a class slug that the taxonomy does not know.
        own = normalize_cwe(rule_id) if rule_id.upper().startswith("CWE-") else None
        text = rule_id
        cwes = list(dict.fromkeys([*([own] if own else []), *seen_cwe]))
        security = True
    tags = (["security"] if security else []) + [f"external/cwe/cwe-{cwe[4:]}" for cwe in cwes]
    return {"id": rule_id, "shortDescription": {"text": text}, "properties": {"tags": tags}}


def _result(entry: _Entry, rule_index: int, partial_hash: str) -> dict[str, Any]:
    finding = entry.finding
    result: dict[str, Any] = {
        "ruleId": entry.rule_id,
        "ruleIndex": rule_index,
        "level": to_sarif_level(entry.severity, entry.verdict),
        "message": {"text": _message(finding, entry.rule_id)},
    }
    if entry.file:
        result["locations"] = [_location(entry.file, entry.line, None)]
    flow = _code_flow(finding.get("trace"))
    if flow is not None:
        result["codeFlows"] = [flow]
    result["partialFingerprints"] = {FINGERPRINT_KEY: partial_hash}
    duplicate_of = _text(finding.get("duplicate_of"))
    if entry.verdict == "rejected":
        suppression: dict[str, Any] = {"kind": "external", "status": "accepted"}
        reason = _text(finding.get("reason"))
        if reason:
            suppression["justification"] = reason
        result["suppressions"] = [suppression]
    elif duplicate_of:
        result["suppressions"] = [
            {
                "kind": "external",
                "status": "accepted",
                "justification": f"duplicate of {duplicate_of}",
            }
        ]
    result["properties"] = _properties(entry)
    if duplicate_of:
        result["properties"]["duplicateOf"] = duplicate_of
    return result


def _properties(entry: _Entry) -> dict[str, Any]:
    properties: dict[str, Any] = {}
    if entry.finding_id:
        properties["findingId"] = entry.finding_id
    properties["verdict"] = entry.verdict
    if entry.severity is not None:
        properties["severity"] = entry.severity
    if entry.confidence is not None:
        properties["confidence"] = entry.confidence
    engines = [item for item in _list(entry.finding.get("engines")) if isinstance(item, str)]
    if engines:
        properties["engines"] = engines
    if entry.class_slug:
        properties["class"] = entry.class_slug
    if entry.cwe:
        properties["cwe"] = list(entry.cwe)
    if entry.severity is not None:
        properties["security-severity"] = to_security_severity(entry.severity)
    return properties


def _message(finding: Mapping[str, Any], rule_id: str) -> str:
    parts = [_text(finding.get("title")), _text(finding.get("description"))]
    text = "\n\n".join(part for part in parts if part)
    if text:
        return text
    item = get_class(rule_id)
    return item.title_en if item is not None else rule_id


def _location(file: str, line: int | None, message: str | None) -> dict[str, Any]:
    physical: dict[str, Any] = {
        "artifactLocation": {"uri": quote(file, safe="/"), "uriBaseId": SOURCE_ROOT_ID}
    }
    if line is not None and line >= 1:
        physical["region"] = {"startLine": line}
    location: dict[str, Any] = {"physicalLocation": physical}
    if message:
        location["message"] = {"text": message}
    return location


def _code_flow(trace: object) -> dict[str, Any] | None:
    steps: list[dict[str, Any]] = []
    for step in _list(trace):
        if not isinstance(step, Mapping):
            continue
        file = _text(step.get("file"))
        if not file:
            continue
        line = step.get("line")
        line = line if isinstance(line, int) and not isinstance(line, bool) else None
        thread_location: dict[str, Any] = {
            "location": _location(file, line, _text(step.get("description")) or None)
        }
        properties = {key: value for key in ("kind", "scope") if (value := _text(step.get(key)))}
        if properties:
            thread_location["properties"] = properties
        steps.append(thread_location)
    if not steps:
        return None
    return {"threadFlows": [{"locations": steps}]}


def _partial_hashes(entries: list[_Entry]) -> list[str]:
    hashes: list[str | None] = [None] * len(entries)
    used: set[str] = set()
    # Pass 1: the hash whose first 16 hex characters are the finding ID.
    for index, entry in enumerate(entries):
        if not entry.finding_id.startswith("KF-"):
            continue
        wanted = entry.finding_id[3:].upper()
        inputs = entry.hash_inputs()
        for counter in range(_MAX_COUNTER):
            value = finding_hash(**inputs, counter=counter)
            if value[:16].upper() == wanted:
                if value not in used:
                    hashes[index] = value
                    used.add(value)
                break
    # Pass 2: the first counter that no other result uses.
    for index, entry in enumerate(entries):
        if hashes[index] is not None:
            continue
        inputs = entry.hash_inputs()
        counter = 0
        value = finding_hash(**inputs, counter=counter)
        while value in used:
            counter += 1
            value = finding_hash(**inputs, counter=counter)
        hashes[index] = value
        used.add(value)
    return [value for value in hashes if value is not None]


def _overall_severity(finding: Mapping[str, Any]) -> str | None:
    value = finding.get("severity")
    if isinstance(value, Mapping):
        value = value.get("overall_severity")
    return from_label(value) if isinstance(value, str) else None


def _confidence(finding: Mapping[str, Any]) -> str | None:
    value = finding.get("confidence")
    if isinstance(value, Mapping):
        value = value.get("score")
    if isinstance(value, str) and value.strip().lower() in _CONFIDENCE:
        return value.strip().lower()
    return None


def _source_line(lines_for: GetLines | None, file: str, line: int | None) -> str | None:
    if lines_for is None or not file or line is None or line < 1:
        return None
    lines = lines_for(file)
    if lines is None or line > len(lines):
        return None
    text = lines[line - 1]
    return text if isinstance(text, str) else None


def _text(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


def _list(value: object) -> list[Any]:
    return value if isinstance(value, list) else []
