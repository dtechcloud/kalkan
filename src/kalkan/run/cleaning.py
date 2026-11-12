# SPDX-License-Identifier: MIT
"""Text helpers of the phase engine (docs/PHASES.md): clean agent text, build canonical ledger
references and reduce Cloudflare fingerprints to their allowed characters.

Agent results pass the JSON Schema, but the coverage ledger and the findings validator are
stricter: ledger text must be NFC, trimmed, visible and free of control or format characters,
and a fingerprint must match ``^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$``. These helpers make engine
derived values satisfy those rules deterministically.

:func:`normalize_trace` and :func:`normalize_path` repair cosmetic slips of honest agent results
(trace kinds in the wrong order, ``./`` path prefixes, backslashes) before the strict finding
validator runs. They never change a quote, a line number or a verdict.
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from collections.abc import Iterable, Mapping
from typing import Any, Final

from kalkan.util.paths import is_safe_relative_path
from kalkan.util.text import PATH_FORBIDDEN_CHARACTER, has_visible_prose, js_trim, utf16_length

__all__ = [
    "FINGERPRINT_PATTERN",
    "MAX_FINGERPRINT_CHARS",
    "MAX_TEXT_UNITS",
    "clean_text",
    "cut_words",
    "dedupe_key",
    "fingerprint_for",
    "normalize_path",
    "normalize_trace",
    "reduce_fingerprint",
    "safe_paths",
    "sink_of",
    "unique",
]

#: The Cloudflare fingerprint pattern of the finding schema and the ledger.
FINGERPRINT_PATTERN: Final = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._:/@+-]*\Z")
#: The ledger allows 4096 UTF-16 code units per text field; the engine keeps a margin.
MAX_TEXT_UNITS: Final = 4000
MAX_FINGERPRINT_CHARS: Final = 400
_FINGERPRINT_BAD: Final = re.compile(r"[^A-Za-z0-9._:/@+-]+")
_DASHES: Final = re.compile(r"-{2,}")
_WHITESPACE: Final = re.compile(r"\s+")
_SURROGATE: Final = re.compile(r"[\ud800-\udfff]")
_MAX_DEDUPE_KEY: Final = 500


def _cut_units(text: str, limit: int) -> str:
    if utf16_length(text) <= limit:
        return text
    out: list[str] = []
    used = 0
    for char in text:
        width = 2 if ord(char) > 0xFFFF else 1
        if used + width > limit:
            break
        out.append(char)
        used += width
    return "".join(out)


def clean_text(value: object, limit: int = MAX_TEXT_UNITS) -> str:
    """Return ``value`` as one line of visible text, or ``""`` when nothing visible remains.

    The text is NFC-normalized; control, format, separator and default-ignorable characters and
    lone surrogates become spaces; whitespace runs become one space; the result is trimmed and
    cut to ``limit`` UTF-16 code units.
    """
    if not isinstance(value, str):
        return ""
    text = _SURROGATE.sub(" ", value)
    text = unicodedata.normalize("NFC", text)
    text = PATH_FORBIDDEN_CHARACTER.sub(" ", text)
    text = _WHITESPACE.sub(" ", text)
    text = js_trim(_cut_units(js_trim(text), limit))
    return text if has_visible_prose(text) else ""


def cut_words(text: str, limit: int) -> str:
    """Return ``text`` cut to at most ``limit`` words (an ellipsis marks a cut)."""
    words = text.split()
    if len(words) <= limit:
        return text.strip()
    return " ".join(words[:limit]) + " …"


def unique(values: Iterable[Any]) -> list[Any]:
    """Return the values in order without duplicates (values must be hashable)."""
    return list(dict.fromkeys(values))


def safe_paths(values: object) -> list[str]:
    """Return the safe target-relative paths of ``values`` in order, without duplicates.

    A leading ``./`` is removed; unsafe paths (absolute, traversal, drive letters, colons,
    backslashes, control characters) are dropped.
    """
    if not isinstance(values, list | tuple):
        return []
    out: list[str] = []
    for value in values:
        if not isinstance(value, str):
            continue
        path = value[2:] if value.startswith("./") else value
        if is_safe_relative_path(path) and path not in out:
            out.append(path)
    return out


def normalize_path(value: object) -> object:
    """Return a cited path without ``./`` prefixes and with ``/`` separators.

    The result is used only when it is a safe target-relative path; otherwise ``value`` comes
    back unchanged (the validator then reports it). Non-strings come back unchanged.
    """
    if not isinstance(value, str):
        return value
    path = value.replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    return path if path != value and is_safe_relative_path(path) else value


def _trace_kinds(steps: list[dict[str, Any]], notes: list[str]) -> None:
    last = len(steps) - 1
    for index, step in enumerate(steps):
        if last == 0:
            wanted = step.get("kind") if step.get("kind") in ("entrypoint", "sink") else "sink"
        else:
            wanted = "entrypoint" if index == 0 else "sink" if index == last else "propagation"
        if step.get("kind") != wanted:
            notes.append(f"trace[{index}].kind: {step.get('kind')} -> {wanted}")
            step["kind"] = wanted


def normalize_trace(trace: object) -> tuple[list[dict[str, Any]], list[str]]:
    """Return ``(trace, notes)``: the trace in the Cloudflare kind order and what changed.

    The agent's order of steps stays. A multi-step trace gets ``entrypoint`` first, ``sink``
    last and ``propagation`` between; a one-step trace keeps ``entrypoint`` or ``sink`` (any
    other kind becomes ``sink``). Cited paths lose ``./`` prefixes and backslashes
    (:func:`normalize_path`). Exact duplicate steps are removed, also when the new kinds make
    two steps equal. ``notes`` is empty when nothing changed.
    """
    if not isinstance(trace, list):
        return [], []
    notes: list[str] = []
    steps: list[dict[str, Any]] = []
    for item in trace:
        if not isinstance(item, Mapping):
            continue
        step = dict(item)
        if "file" in step:
            path = normalize_path(step["file"])
            if path != step["file"]:
                notes.append(f"trace path {step['file']!r} -> {path!r}")
                step["file"] = path
        steps.append(step)
    while True:
        kept: list[dict[str, Any]] = []
        for step in steps:
            if step not in kept:
                kept.append(step)
        if len(kept) != len(steps):
            notes.append(f"{len(steps) - len(kept)} duplicate trace step(s) removed")
        steps = kept
        before = [step.get("kind") for step in steps]
        _trace_kinds(steps, notes)
        if before == [step.get("kind") for step in steps] or len(steps) < 2:
            return steps, notes
        if all(steps.count(step) == 1 for step in steps):
            return steps, notes


def sink_of(trace: object) -> Mapping[str, Any] | None:
    """Return the first ``sink`` element of a trace, else its last element, else None."""
    if not isinstance(trace, list) or not trace:
        return None
    for step in trace:
        if isinstance(step, Mapping) and step.get("kind") == "sink":
            return step
    last = trace[-1]
    return last if isinstance(last, Mapping) else None


def reduce_fingerprint(text: str) -> str:
    """Reduce ``text`` to the fingerprint alphabet ``[A-Za-z0-9._:/@+-]``.

    Every run of other characters becomes one ``-``, repeated dashes collapse, leading
    characters that are not ASCII letters or digits are removed and the result is cut to
    :data:`MAX_FINGERPRINT_CHARS`. An empty result becomes ``unknown``.
    """
    reduced = _DASHES.sub("-", _FINGERPRINT_BAD.sub("-", text))
    start = 0
    while start < len(reduced) and not (reduced[start].isascii() and reduced[start].isalnum()):
        start += 1
    reduced = reduced[start:][:MAX_FINGERPRINT_CHARS]
    return reduced if reduced and FINGERPRINT_PATTERN.fullmatch(reduced) else "unknown"


def fingerprint_for(class_slug: str, trace: object) -> str:
    """Return the Cloudflare fingerprint ``<class>:<sink file>:<sink scope>`` of a claim.

    The sink is :func:`sink_of` the trace. Without a scope the line (``line-<n>``) stands in.
    The result passes :data:`FINGERPRINT_PATTERN`.
    """
    sink = sink_of(trace) or {}
    file = sink.get("file") if isinstance(sink.get("file"), str) else ""
    scope = sink.get("scope") if isinstance(sink.get("scope"), str) else ""
    if not scope.strip():
        line = sink.get("line")
        scope = f"line-{line}" if isinstance(line, int) else "unknown"
    return reduce_fingerprint(f"{class_slug or 'unknown'}:{file or 'unknown'}:{scope}")


def dedupe_key(prefix: str, value: str) -> str:
    """Return a task dedupe key ``<prefix>:<value>``; a long value is replaced by its SHA-256."""
    key = f"{prefix}:{value}"
    if len(key) <= _MAX_DEDUPE_KEY:
        return key
    return f"{prefix}:sha256:{hashlib.sha256(value.encode('utf-8', 'surrogatepass')).hexdigest()}"
