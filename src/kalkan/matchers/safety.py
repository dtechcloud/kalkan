# SPDX-License-Identifier: Apache-2.0
# Ported from vercel-labs/deepsec@4fa6722: packages/scanner/src/declarative-matcher.ts
# Copyright 2026 Vercel, Inc. and contributors. Changes: translated from TypeScript to Python;
# the regex checks are adapted to Python `re` syntax; added checks for Python-only syntax,
# inline flags, possessive quantifiers and repeated unbounded wildcards; the glob checks use
# kalkan.matchers.globs instead of minimatch.
"""Safety checks for matcher regexes and globs (port of ``regexSafetyError``/``globSafetyError``).

Every regex in a matcher spec passes :func:`regex_safety_error` before it is compiled. The
engine then runs a compiled regex against one line at a time and skips lines longer than
:data:`MAX_LINE_LENGTH` characters. These three measures bound the backtracking cost, because
Python ``re`` has no timeout.

Differences between JavaScript and Python regex semantics, and how kalkan handles them:

- ``\\d``, ``\\w``, ``\\b`` and ``\\s`` are ASCII-only in JavaScript without the ``u`` flag.
  kalkan compiles every regex with :data:`re.ASCII`, so the classes have the same meaning.
  One difference stays: JavaScript ``\\s`` also matches Unicode spaces (U+00A0, U+2028,
  U+FEFF and others). Python ``\\s`` with ``re.ASCII`` matches only ``[ \\t\\n\\r\\f\\v]``.
- The ``i`` flag: with ``re.ASCII``, Python folds only ASCII letters. JavaScript without ``u``
  also folds non-ASCII letters, but it never maps a non-ASCII letter to an ASCII letter. The
  results are the same for ASCII patterns.
- ``.`` does not match ``\\r``, U+2028 and U+2029 in JavaScript. In Python it matches them
  (only ``\\n`` is excluded). The engine splits lines on ``\\n`` and removes one trailing
  ``\\r``, so the common CRLF case behaves the same.
- ``$`` without the ``m`` flag matches only at the end of the input in JavaScript. Python also
  matches before a final ``\\n``. A line never contains ``\\n``, so the results are the same.
- ``{,n}`` and ``{,}`` are literals in JavaScript and quantifiers in Python. The port script
  escapes them. This module treats them as quantifiers.
- ``[^]`` (any character) and ``[]`` (no character) exist only in JavaScript. In Python a ``]``
  directly after ``[`` or ``[^`` is a literal. The port script rewrites both forms.
- A ``[`` inside a character class is a literal in JavaScript. Python warns ("possible nested
  set"). This module turns every warning into an error. The port script escapes the bracket.
- Named groups are ``(?<name>...)`` in JavaScript and ``(?P<name>...)`` in Python. Python 3.13
  rejects the JavaScript form.
- Identity escapes such as ``\\a`` or ``\\e`` mean the plain letter in JavaScript. In Python
  ``\\a`` is the bell character and ``\\e`` is an error. The port script removes such escapes.
- Python-only syntax is rejected: possessive quantifiers (``a++``), atomic groups (``(?>``),
  conditional groups (``(?(``), comments (``(?#``), named backreferences (``(?P=name)``) and
  global inline flags (``(?i)``). Scoped inline flags (``(?i:...)``) with the letters ``i``,
  ``m`` and ``s`` are allowed, because the file-level regex lists have no ``flags`` field.
- JavaScript counts UTF-16 code units, Python counts code points. A bounded repeat such as
  ``[^x]{0,200}`` can span more astral characters in Python. The difference is harmless.
- kalkan adds one check to the deepsec set: a regex contains at most one unbounded wildcard
  (``.*``, ``.+``, ``.{n,}``). deepsec rejects two of them only when they are less than 80
  characters apart in the same alternative.
"""

from __future__ import annotations

import re
import warnings
from collections.abc import Iterator

from kalkan.errors import ValidationError
from kalkan.matchers.globs import GlobError, compile_glob, glob_matches

MAX_REGEX_LENGTH = 500
MAX_GLOB_LENGTH = 240
MAX_REPEAT = 1000
#: The engine skips a line longer than this many characters.
MAX_LINE_LENGTH = 20_000
ALLOWED_FLAGS = frozenset("ims")

# deepsec checks. The JavaScript sources work unchanged in Python. The quantifier alternative
# also covers Python's ``{,n}`` and ``{,}``, which deepsec does not know.
_ATOM = r"(?:\\.|\[[^\]]*\]|[^()[\]\\])"
_QUANT = r"(?:[*+]|\{\d+\}|\{\d*,\d*\})"
_NESTED_QUANTIFIER = re.compile(
    r"\((?:" + _ATOM + r")*" + _QUANT + r"(?:" + _ATOM + r")*\)\s*" + _QUANT
)
_QUANTIFIED_ALTERNATION = re.compile(r"\((?:" + _ATOM + r")*\|(?:" + _ATOM + r")*\)\s*" + _QUANT)
_MULTIPLE_WILDCARDS = re.compile(r"(?:\.\*|\.\+)[^|\n]{0,80}(?:\.\*|\.\+)")
_BACKREFERENCE = re.compile(r"\\[1-9]|\\k[<{]|\(\?P=")
_LOOKBEHIND = re.compile(r"\(\?<[=!]")

# Python syntax.
_BRACE_QUANTIFIER = re.compile(r"\{(\d+)\}|\{(\d*),(\d*)\}")
_UNBOUNDED_BRACE = re.compile(r"\{\d*,\}")
_SCOPED_FLAGS = re.compile(r"\(\?([a-zA-Z-]+)([:)])")

_GLOB_TOO_BROAD = re.compile(r"(?:\*|\*\*|\*\*/\*+/?|\*\*/\*\*/?)")
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
_BREADTH_PROBES = ("README.md", "src/index.ts", ".env", "deep/a/config.yaml")


def regex_flags(flags: str) -> int:
    """Return the :mod:`re` flags for a spec ``flags`` string, always with ``re.ASCII``."""
    value = re.ASCII
    if "i" in flags:
        value |= re.IGNORECASE
    if "m" in flags:
        value |= re.MULTILINE
    if "s" in flags:
        value |= re.DOTALL
    return value


def flags_error(flags: object) -> str | None:
    """Return why ``flags`` is not a valid flag string, or None."""
    if not isinstance(flags, str):
        return "flags must be a string"
    if any(flag not in ALLOWED_FLAGS for flag in flags):
        return "flags may only contain i, m and s"
    if len(set(flags)) != len(flags):
        return "flags must not repeat a letter"
    return None


def regex_safety_error(source: object, flags: object = "") -> str | None:
    """Return why ``source`` is not a safe matcher regex, or None when it is safe.

    The order follows deepsec: the structural checks first, then compilation, then the
    empty-string probe.
    """
    if not isinstance(source, str) or not source:
        return "must be a non-empty string"
    error = flags_error(flags)
    if error:
        return error
    flag_text = str(flags)
    if len(source) > MAX_REGEX_LENGTH:
        return f"must be at most {MAX_REGEX_LENGTH} characters"
    if "\0" in source:
        return "must not contain NUL bytes"
    if _BACKREFERENCE.search(source):
        return "backreferences are not supported"
    if _LOOKBEHIND.search(source):
        return "lookbehind assertions are not supported"
    error = _python_syntax_error(source)
    if error:
        return error
    if _NESTED_QUANTIFIER.search(source):
        return "nested quantifiers are not supported"
    if _QUANTIFIED_ALTERNATION.search(source):
        return "quantified alternations are not supported"
    if _MULTIPLE_WILDCARDS.search(source) or count_unbounded_wildcards(source) > 1:
        return "multiple wildcard repetitions are not supported"
    for match in _BRACE_QUANTIFIER.finditer(source):
        bounds = [int(value) for value in match.groups() if value]
        if bounds and max(bounds) > MAX_REPEAT:
            return f"repeat counts greater than {MAX_REPEAT} are not supported"
    try:
        compiled = _compile(source, flag_text)
    except (re.error, Warning) as exc:
        return f"is not a valid regular expression: {exc}"
    if compiled.search(""):
        return "must not match an empty string"
    return None


def compile_regex(source: str, flags: str = "") -> re.Pattern[str]:
    """Check ``source`` with :func:`regex_safety_error` and compile it.

    Raises :class:`~kalkan.errors.ValidationError` when the regex is not safe.
    """
    error = regex_safety_error(source, flags)
    if error:
        message = f"unsafe regex {source!r}: {error}"
        raise ValidationError(message, [message])
    return _compile(source, flags)


def python_syntax_error(source: str, *, allow_lookbehind: bool = False) -> str | None:
    """Return why ``source`` uses syntax that Python and JavaScript read differently, or None.

    The syntax check of :func:`regex_safety_error` without the structural checks: possessive
    quantifiers, atomic and conditional groups, inline comments, named backreferences, inline
    global flags, JavaScript named groups and (unless ``allow_lookbehind``) lookbehind
    assertions. A lookbehind that Python compiles has a fixed width, and a fixed-width
    lookbehind means the same in both languages. The RetireJS extractors
    (:mod:`kalkan.sca.retirejs`) use this check; they run with a process time limit instead of
    the structural checks.
    """
    if not allow_lookbehind and _LOOKBEHIND.search(source):
        return "lookbehind assertions are not supported"
    return _python_syntax_error(source, allow_lookbehind=allow_lookbehind)


def count_unbounded_wildcards(source: str) -> int:
    """Count ``.*``, ``.+``, ``.{n,}`` and ``.{,}`` outside escapes and character classes."""
    count = 0
    for index, kind in _atoms(source):
        if kind != ".":
            continue
        following = source[index + 1 : index + 2]
        if following in ("*", "+") or _UNBOUNDED_BRACE.match(source, index + 1):
            count += 1
    return count


def glob_safety_error(pattern: object, *, allow_broad: bool = False) -> str | None:
    """Return why ``pattern`` is not a safe file glob, or None when it is safe.

    ``allow_broad`` skips the breadth checks (``**/*`` is accepted). Only the file patterns of
    a file matcher with ``file_signatures`` use it: such a matcher reads a few bytes of a file,
    never its lines (:mod:`kalkan.matchers.spec`).
    """
    if not isinstance(pattern, str) or not pattern.strip():
        return "must be a non-empty string"
    if pattern != pattern.strip():
        return "must not start or end with whitespace"
    if len(pattern) > MAX_GLOB_LENGTH:
        return f"must be at most {MAX_GLOB_LENGTH} characters"
    if _CONTROL_CHARS.search(pattern):
        return "must not contain control characters"
    if "\\" in pattern:
        return "must use forward slashes"
    if pattern.startswith(("!", "#")):
        return "negated and comment globs are not supported"
    if pattern.startswith("/") or re.match(r"[A-Za-z]:/", pattern):
        return "must be relative to the repository root"
    if any(part in ("..", ".") for part in pattern.split("/")):
        return "must not contain traversal segments"
    if pattern.count("{") > 3 or pattern.count(",") > 16 or pattern.count("*") > 12:
        return "is too complex to compile safely"
    if not allow_broad and _GLOB_TOO_BROAD.fullmatch(pattern):
        return "is too broad; constrain it by directory, filename, or extension"
    if not allow_broad and not re.search(r"[A-Za-z0-9]", pattern):
        return "is too broad; include a literal directory, filename, or extension"
    # kalkan additions: minimatch syntax that kalkan.matchers.globs does not implement.
    if re.search(r"[@!+*?]\(", pattern):
        return "extended globs such as *(a|b) are not supported"
    if re.search(r"\[[:=.]", pattern):
        return "POSIX bracket expressions are not supported"
    try:
        compile_glob(pattern)
    except GlobError as exc:
        return f"is not a valid glob: {exc}"
    if not allow_broad and all(glob_matches(pattern, probe) for probe in _BREADTH_PROBES):
        return "is too broad; constrain it by directory, filename, or extension"
    return None


def _compile(source: str, flags: str) -> re.Pattern[str]:
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        return re.compile(source, regex_flags(flags))


def _atoms(source: str) -> Iterator[tuple[int, str]]:
    """Yield ``(index, kind)`` per token: an escape (``"\\\\"``), a class (``"["``) or a char.

    For a plain character ``kind`` is the character itself.
    """
    index = 0
    length = len(source)
    while index < length:
        char = source[index]
        if char == "\\":
            yield index, "\\"
            index += 2
        elif char == "[":
            yield index, "["
            index = _class_end(source, index)
        else:
            yield index, char
            index += 1


def _class_end(source: str, index: int) -> int:
    """Return the index after the character class that starts at ``source[index] == "["``."""
    length = len(source)
    index += 1
    if index < length and source[index] == "^":
        index += 1
    if index < length and source[index] == "]":
        index += 1  # a "]" right after "[" or "[^" is a literal in Python
    while index < length:
        char = source[index]
        if char == "\\":
            index += 2
            continue
        if char == "]":
            return index + 1
        index += 1
    return length


def _python_syntax_error(source: str, *, allow_lookbehind: bool = False) -> str | None:
    """Reject syntax that only Python accepts, or that the deepsec checks do not see."""
    after_quantifier = False
    skip_until = -1
    for index, char in _atoms(source):
        if index < skip_until:
            continue
        if char in ("\\", "["):
            after_quantifier = False
            continue
        if char == "(" and source.startswith("(?", index):
            error = _group_extension_error(source, index, allow_lookbehind)
            if error:
                return error
            skip_until = index + 2  # the "?" of "(?" is not a quantifier
            after_quantifier = False
            continue
        if char in "*+?":
            if after_quantifier and char == "+":
                return "possessive quantifiers are not supported"
            # "*?", "+?" and "??" are lazy; a "?" after a quantifier closes the run.
            after_quantifier = not (after_quantifier and char == "?")
            continue
        if char == "{":
            match = _BRACE_QUANTIFIER.match(source, index)
            if match:
                after_quantifier = True
                skip_until = match.end()
                continue
        after_quantifier = False
    return None


def _group_extension_error(source: str, index: int, allow_lookbehind: bool = False) -> str | None:
    rest = source[index + 2 :]
    if rest.startswith((":", "=", "!", "P<")):
        return None
    if rest.startswith(("<=", "<!")):
        return None if allow_lookbehind else "lookbehind assertions are not supported"
    if rest.startswith("<"):
        return "named groups must use the Python form (?P<name>...)"
    if rest.startswith(">"):
        return "atomic groups are not supported"
    if rest.startswith("#"):
        return "inline comments are not supported"
    if rest.startswith("("):
        return "conditional groups are not supported"
    if rest.startswith("P="):
        return "backreferences are not supported"
    match = _SCOPED_FLAGS.match(source, index)
    if match and match.group(2) == ")":
        return "inline global flags are not supported; use the flags field"
    if match and set(match.group(1)) <= set("ims-"):
        return None
    return "inline flags other than scoped i, m and s are not supported"
