# SPDX-License-Identifier: Apache-2.0
# Ported from block/codecrucible@b5c8086: internal/sarif/identity.go
# Copyright 2026 Block, Inc. Changes: translated from Go to Python; prefix KF- instead of CC-;
# the class key falls back from the first CWE to the class slug, the rule ID and "unknown";
# CWE and path normalization; IDs assigned to kalkan finding dicts; candidate IDs added.
"""Stable finding IDs and candidate IDs (ENGINE-SPEC 6.1 and 6.2).

A finding ID hashes the weakness class, the file and the whitespace-collapsed flagged source.
It does not hash model prose (title, description). When a snippet exists, it does not hash the
line number either. Both drift between scans of unchanged code. Thus the same defect keeps its
ID across rescans and across unrelated edits that move lines. Identical flagged source in one
file gets distinct IDs through a collision counter, in the order of assignment.

The module never opens files. Source lines come from an injected ``get_lines(path)`` callable.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable, Iterable, Mapping
from typing import Any

from kalkan.errors import KalkanError

#: ``get_lines(path)`` returns the lines of a target file, or None when the file is not
#: available. Use ``text.split("\n")`` so that the numbers match the numbered source.
GetLines = Callable[[str], list[str] | None]

FINDING_ID_PREFIX = "KF-"
CANDIDATE_ID_PREFIX = "CAND-"
#: SARIF ``partialFingerprints`` key for the finding identity (Go: ``FingerprintKey``).
FINGERPRINT_KEY = "kalkanFinding/v1"
SEED_VERSION = "v1"
UNKNOWN_CLASS = "unknown"

#: The characters for which Go ``unicode.IsSpace`` is true (the Unicode White_Space property).
#: Python ``str.isspace()`` also accepts U+001C to U+001F. Thus ``str.split()`` does not match Go.
WHITESPACE = "".join(
    chr(code)
    for code in (
        *range(0x09, 0x0E),  # tab, line feed, vertical tab, form feed, carriage return
        0x20,
        0x85,
        0xA0,
        0x1680,
        *range(0x2000, 0x200B),
        0x2028,
        0x2029,
        0x202F,
        0x205F,
        0x3000,
    )
)

_FIELD = re.compile("[^" + re.escape(WHITESPACE) + "]+")
_CWE = re.compile(r"CWE-([0-9]+)", re.IGNORECASE)
# Errors that make a path "not available" instead of a crash. Paths come from agent output.
# ValueError covers UnicodeDecodeError and a NUL character in a path.
_LOOKUP_ERRORS = (KalkanError, OSError, ValueError)


def collapse_whitespace(text: str) -> str:
    """Replace each run of whitespace with one space and remove it at both ends.

    This is Go ``strings.Join(strings.Fields(text), " ")``, with :data:`WHITESPACE`.
    """
    return " ".join(_FIELD.findall(text))


def trim_whitespace(text: str) -> str:
    """Remove :data:`WHITESPACE` at both ends of ``text`` (Go ``strings.TrimSpace``)."""
    return text.strip(WHITESPACE)


def cached_get_lines(get_lines: GetLines) -> GetLines:
    """Wrap ``get_lines`` so that it runs at most one time per path.

    The wrapper returns None when ``get_lines`` raises ``KalkanError``, ``OSError`` or
    ``ValueError``. A refused or unreadable path is "not available", never a crash.
    """
    cache: dict[str, list[str] | None] = {}

    def lines_for(path: str) -> list[str] | None:
        if path not in cache:
            try:
                cache[path] = get_lines(path)
            except _LOOKUP_ERRORS:
                cache[path] = None
        return cache[path]

    return lines_for


def identity_seed(
    *,
    cwe: Iterable[str] | None,
    class_slug: str | None,
    rule_id: str | None,
    uri: str,
    snippet: str | None,
    start_line: int | None,
) -> str:
    """Return the identity seed: ``"v1"``, class key, URI and anchor, joined with ``"\\x00"``.

    Port of Go ``identitySeed``.

    - Class key: the first valid CWE as ``CWE-<n>``, else ``class_slug``, else ``rule_id``,
      else ``"unknown"``.
    - URI: ``uri`` with ``/`` separators and without a leading ``./``.
    - Anchor: the whitespace-collapsed ``snippet``, else ``line:<start_line>``, else empty.
    """
    return "\x00".join(
        (
            SEED_VERSION,
            _class_key(cwe, class_slug, rule_id),
            _posix_uri(uri),
            _anchor(snippet, start_line),
        )
    )


def finding_hash(
    *,
    cwe: Iterable[str] | None,
    class_slug: str | None,
    rule_id: str | None,
    uri: str,
    snippet: str | None,
    start_line: int | None,
    counter: int = 0,
) -> str:
    """Return the full SHA-256 (64 lower-case hex) of the seed and the collision counter.

    Go stores this value in ``partialFingerprints``. For the counter ``n`` that
    :func:`finding_id` selects, the ID is ``"KF-" + finding_hash(..., counter=n)[:16].upper()``.
    """
    if counter < 0:
        raise ValueError("counter must not be negative")
    seed = identity_seed(
        cwe=cwe,
        class_slug=class_slug,
        rule_id=rule_id,
        uri=uri,
        snippet=snippet,
        start_line=start_line,
    )
    return _sha256_hex(f"{seed}\x00{counter}")


def finding_id(
    *,
    cwe: Iterable[str] | None,
    class_slug: str | None,
    rule_id: str | None,
    uri: str,
    snippet: str | None,
    start_line: int | None,
    used: set[str],
) -> str:
    """Return a finding ID that is not in ``used`` and add it to ``used``.

    The ID is ``"KF-"`` plus the first 16 hex characters, in upper case, of the SHA-256 of
    ``seed + "\\x00" + str(n)``. The counter ``n`` starts at 0. The first unused ID wins.
    """
    seed = identity_seed(
        cwe=cwe,
        class_slug=class_slug,
        rule_id=rule_id,
        uri=uri,
        snippet=snippet,
        start_line=start_line,
    )
    counter = 0
    while True:
        candidate = FINDING_ID_PREFIX + _sha256_hex(f"{seed}\x00{counter}")[:16].upper()
        if candidate not in used:
            used.add(candidate)
            return candidate
        counter += 1


def candidate_id(
    engine: str, rule_id: str, file: str, start_line: int | None, snippet: str | None
) -> str:
    """Return the candidate ID (ENGINE-SPEC 6.2).

    ``"CAND-"`` plus the first 16 hex characters, in upper case, of the SHA-256 of
    ``engine \\0 rule_id \\0 file \\0 str(start_line or 0) \\0 collapsed snippet``.
    The file gets the same POSIX normalization as the finding URI.
    """
    text = "\x00".join(
        (
            engine,
            rule_id,
            _posix_uri(file),
            str(start_line or 0),
            collapse_whitespace(snippet or ""),
        )
    )
    return CANDIDATE_ID_PREFIX + _sha256_hex(text)[:16].upper()


def finding_location(finding: Mapping[str, Any]) -> tuple[str, int | None]:
    """Return ``(file, line)`` of a canonical finding.

    The location is the first ``trace`` element with ``kind == "sink"``, else the first
    ``evidence`` element. Without one, the result is ``("", None)``. ENGINE-SPEC 8.2 uses the
    same rule for the SARIF location.
    """
    trace = finding.get("trace")
    if isinstance(trace, list):
        for step in trace:
            if isinstance(step, Mapping) and step.get("kind") == "sink":
                return _file_and_line(step)
    evidence = finding.get("evidence")
    if isinstance(evidence, list) and evidence and isinstance(evidence[0], Mapping):
        return _file_and_line(evidence[0])
    return "", None


def assign_finding_ids(
    findings: list[dict[str, Any]], *, get_lines: GetLines | None = None
) -> None:
    """Give each finding without an ``id`` a stable finding ID, in list order.

    Port of Go ``AssignFindingIDs``. Existing non-empty ``id`` values stay, and new IDs never
    reuse them. Thus an ID that was assigned before the audit stays when the audit refines the
    CWE. The inputs are the finding's ``cwe`` list, its ``class`` slug and its location
    (:func:`finding_location`). With ``get_lines``, the snippet is the source line at the
    location. Without it, or when the line is not available, the anchor is ``line:<line>``.
    """
    used = {finding["id"] for finding in findings if _has_id(finding)}
    lines_for = cached_get_lines(get_lines) if get_lines is not None else None
    for finding in findings:
        if _has_id(finding):
            continue
        uri, line = finding_location(finding)
        cwe = finding.get("cwe")
        class_slug = finding.get("class")
        finding["id"] = finding_id(
            cwe=[c for c in cwe if isinstance(c, str)] if isinstance(cwe, list) else [],
            class_slug=class_slug if isinstance(class_slug, str) else None,
            rule_id=None,
            uri=uri,
            snippet=_source_line(lines_for, uri, line),
            start_line=line,
            used=used,
        )


def _sha256_hex(text: str) -> str:
    # Go hashes the bytes of the string. "surrogatepass" keeps a lone surrogate from JSON input.
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()


def _class_key(cwe: Iterable[str] | None, class_slug: str | None, rule_id: str | None) -> str:
    values = [cwe] if isinstance(cwe, str) else (cwe or ())
    for value in values:
        if isinstance(value, str):
            match = _CWE.fullmatch(trim_whitespace(value))
            if match:
                return "CWE-" + (match.group(1).lstrip("0") or "0")
    if class_slug:
        return class_slug
    if rule_id:
        return rule_id
    return UNKNOWN_CLASS


def _posix_uri(uri: str | None) -> str:
    path = (uri or "").replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    return path


def _anchor(snippet: str | None, start_line: int | None) -> str:
    text = collapse_whitespace(snippet or "")
    if text:
        return text
    if start_line is None:
        return ""
    return f"line:{start_line}"


def _has_id(finding: Mapping[str, Any]) -> bool:
    value = finding.get("id")
    return isinstance(value, str) and value != ""


def _file_and_line(element: Mapping[str, Any]) -> tuple[str, int | None]:
    file = element.get("file")
    line = element.get("line")
    return (
        file if isinstance(file, str) else "",
        line if isinstance(line, int) and not isinstance(line, bool) else None,
    )


def _source_line(lines_for: GetLines | None, uri: str, line: int | None) -> str:
    if lines_for is None or not uri or line is None or line < 1:
        return ""
    lines = lines_for(uri)
    if lines is None or line > len(lines):
        return ""
    text = lines[line - 1]
    return text if isinstance(text, str) else ""
