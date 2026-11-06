# SPDX-License-Identifier: MIT
"""Glob to regex translation with the minimatch semantics that the deepsec matchers use.

Supported syntax:

- ``**`` as a whole path segment matches zero or more segments (``**/x`` also matches ``x``).
  Inside a segment (``a**b``) it acts like ``*``.
- ``*`` matches any characters except ``/``. ``?`` matches one character except ``/``.
- ``[abc]``, ``[a-z]``, ``[!abc]`` and ``[^abc]`` match one character except ``/``. A ``]``
  directly after ``[`` or ``[!`` is a member. A ``[`` without a closing ``]`` is a literal.
- ``{a,b}`` alternatives, also nested, are expanded before matching. A brace group without a
  top-level comma (``{a}``) is a literal.

The options match minimatch with ``dot: true``: wildcards also match names that start with a
dot, and the match is case-sensitive. Paths use forward slashes and are relative to the
target root. Extended globs (``*(a|b)``), POSIX classes (``[[:alpha:]]``) and numeric ranges
(``{1..3}``) are not implemented; ``kalkan.matchers.safety`` rejects the first two.
"""

from __future__ import annotations

import functools
import re
from collections.abc import Iterable

#: Upper bound for the number of brace alternatives of one glob.
MAX_EXPANSIONS = 1024

_CLASS_SPECIAL = frozenset("\\]^-[")


class GlobError(ValueError):
    """A glob cannot be translated."""


def expand_braces(pattern: str) -> list[str]:
    """Expand ``{a,b}`` groups (nested groups too) like the ``brace-expansion`` package."""
    results: list[str] = []
    pending = [pattern]
    while pending:
        current = pending.pop()
        group = _first_brace_group(current)
        if group is None:
            results.append(current)
        else:
            start, end, alternatives = group
            prefix, suffix = current[:start], current[end + 1 :]
            pending.extend(prefix + item + suffix for item in reversed(alternatives))
        if len(results) + len(pending) > MAX_EXPANSIONS:
            raise GlobError(f"more than {MAX_EXPANSIONS} brace alternatives")
    return results


def glob_to_regex(pattern: str) -> str:
    """Return a regex source that matches the same paths as ``pattern`` (use ``fullmatch``)."""
    if not pattern:
        raise GlobError("empty glob")
    alternatives = [_translate(item) for item in expand_braces(pattern)]
    unique = list(dict.fromkeys(alternatives))
    return unique[0] if len(unique) == 1 else "(?:" + "|".join(unique) + ")"


@functools.lru_cache(maxsize=4096)
def compile_glob(pattern: str) -> re.Pattern[str]:
    """Compile ``pattern`` to a regex. The regex must be used with ``fullmatch``."""
    try:
        return re.compile(glob_to_regex(pattern), re.DOTALL)
    except re.error as exc:  # pragma: no cover - the translation escapes every literal
        raise GlobError(str(exc)) from exc


def glob_matches(pattern: str, path: str) -> bool:
    """Return True when the POSIX path ``path`` matches ``pattern``."""
    return compile_glob(pattern).fullmatch(path) is not None


class GlobSet:
    """A list of globs that matches a path when any glob matches it."""

    def __init__(self, patterns: Iterable[str]) -> None:
        self.patterns: tuple[str, ...] = tuple(patterns)
        if self.patterns:
            source = "|".join(f"(?:{glob_to_regex(item)})" for item in self.patterns)
            self._regex: re.Pattern[str] | None = re.compile(source, re.DOTALL)
        else:
            self._regex = None

    def __bool__(self) -> bool:
        return bool(self.patterns)

    def matches(self, path: str) -> bool:
        """Return True when any glob matches ``path``. An empty set matches nothing."""
        return self._regex is not None and self._regex.fullmatch(path) is not None


def _first_brace_group(text: str) -> tuple[int, int, list[str]] | None:
    """Find the first ``{...}`` group with a top-level comma.

    Return ``(start, end, alternatives)`` with the indexes of the braces, or None.
    """
    index = 0
    length = len(text)
    while index < length:
        if text[index] == "{":
            end, alternatives = _brace_body(text, index)
            if end is not None and len(alternatives) > 1:
                return index, end, alternatives
        index += 1
    return None


def _brace_body(text: str, start: int) -> tuple[int | None, list[str]]:
    depth = 0
    pieces: list[str] = []
    piece_start = start + 1
    for index in range(start, len(text)):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                pieces.append(text[piece_start:index])
                return index, pieces
        elif char == "," and depth == 1:
            pieces.append(text[piece_start:index])
            piece_start = index + 1
    return None, []


def _translate(pattern: str) -> str:
    segments: list[str] = []
    for segment in pattern.split("/"):
        if segment == "**" and segments and segments[-1] == "**":
            continue
        segments.append(segment)
    parts: list[str] = []
    last = len(segments) - 1
    for position, segment in enumerate(segments):
        if segment == "**":
            parts.append(r"[^/]+(?:/[^/]+)*" if position == last else r"(?:[^/]+/)*")
            continue
        parts.append(_segment(segment))
        if position != last:
            parts.append("/")
    return "".join(parts)


def _segment(segment: str) -> str:
    out: list[str] = []
    index = 0
    length = len(segment)
    while index < length:
        char = segment[index]
        if char == "*":
            while index < length and segment[index] == "*":
                index += 1
            out.append("[^/]*")
            continue
        if char == "?":
            out.append("[^/]")
            index += 1
            continue
        if char == "[":
            translated = _bracket(segment, index)
            if translated is not None:
                regex, index = translated
                out.append(regex)
                continue
        if char == "\\" and index + 1 < length:
            out.append(re.escape(segment[index + 1]))
            index += 2
            continue
        out.append(re.escape(char))
        index += 1
    return "".join(out)


def _bracket(segment: str, start: int) -> tuple[str, int] | None:
    """Translate the class at ``segment[start] == "["``; None when it has no closing ``]``."""
    index = start + 1
    length = len(segment)
    negate = index < length and segment[index] in "!^"
    if negate:
        index += 1
    members: list[str] = []
    first = True
    while index < length:
        char = segment[index]
        if char == "]" and not first:
            body = "".join(members)
            if negate:
                return f"[^/{body}]", index + 1
            # A range such as "*-0" contains "/"; a class never matches "/" in minimatch.
            return (f"(?!/)[{body}]" if body else "(?!)"), index + 1
        first = False
        if char == "\\" and index + 1 < length:
            index += 1
            char = segment[index]
        if index + 2 < length and segment[index + 1] == "-" and segment[index + 2] != "]":
            high = segment[index + 2]
            if char <= high:
                members.append(f"{_class_char(char)}-{_class_char(high)}")
            index += 3
            continue
        members.append(_class_char(char))
        index += 1
    return None


def _class_char(char: str) -> str:
    return "\\" + char if char in _CLASS_SPECIAL else char
