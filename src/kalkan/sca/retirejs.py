# SPDX-License-Identifier: Apache-2.0
# Ported from RetireJS/retire.js@6.1.0: node/lib/retire.js
# Copyright 2018 Erlend Oftedal. Changes: the matching functions (scan, simpleMatch,
# replacementMatch, scanhash, check, isAtOrAbove, replaceVersion) translated from JavaScript to
# Python; the repository parser, the regex safety checks and the lookbehind expansion added.
"""The RetireJS library repository as data (docs/ENGINE-SPEC.md 17, ADR-0005).

kalkan reads the library repository of RetireJS (github.com/RetireJS/retire.js, Apache-2.0)
as data: the file ``repository/jsrepository-v5.json``, which the retire 6.1.0 command line
downloads from the ``master`` branch. No Node, no retire command, no JavaScript runs.
``kalkan sca update-db`` stores the file (:mod:`kalkan.sca.retiredb`); the detector of
:mod:`kalkan.sca.vendored` runs the extractors below over the target copy.

1. **Repository** (:func:`parse_repository`). The document maps a library name to
   ``extractors``, ``vulnerabilities`` and the optional ``npmname``, ``bowername``,
   ``basePurl`` and ``licenses``. The entries ``dont check`` (URIs that are not version
   extractors) and ``retire-example`` (a sample) are skipped. A bad library entry or a bad
   vulnerability is skipped with a warning; the parse raises
   :class:`~kalkan.errors.ValidationError` only when no library is usable. The npm name of a
   library is its ``npmname``, else the library name (as the retire CycloneDX reporter does).
2. **Extractors** (:func:`compile_extractor`). The repository regexes are JavaScript regexes
   with the placeholder ``§§version§§``. kalkan replaces it with the retire version class
   ``[0-9][0-9.a-z_\\-]+`` (``retire.replaceVersion``) and compiles the regex with
   :data:`re.ASCII`. :mod:`kalkan.matchers.safety` describes the remaining differences
   between JavaScript and Python regexes. JavaScript allows a lookbehind of variable width;
   :func:`expand_lookbehinds` rewrites a bounded one into fixed-width alternatives with the
   same meaning (the minified lodash rule needs it). The repository is third-party data, so a
   regex is skipped (counted in :attr:`Repository.skipped`) when it

   - is not a string, is longer than :data:`MAX_REGEX_CHARS` characters or holds a NUL;
   - uses syntax that Python reads differently
     (:func:`kalkan.matchers.safety.python_syntax_error`: possessive quantifiers, atomic and
     conditional groups, inline global flags, JavaScript named groups);
   - repeats more than :data:`MAX_REPEAT` times;
   - does not compile without a warning (for example a lookbehind of unbounded width),
     matches the empty string, or has no capture group (group 1 is the version).

   The structural checks of the matcher engine (nested quantifiers, quantified alternations,
   more than one wildcard) are not applied: they would drop 22 of the 336 extractors of the
   2026-10-25 file, among them every jQuery UI widget rule. Instead, :mod:`kalkan.sca.vendored`
   runs the extractors in a separate process with a time limit per file.
3. **Supported extractors.** ``filename`` (the file name, anchored as ``^regex$``), ``uri``
   (the target-relative path with a leading ``/``), ``filecontent``, ``filecontentreplace``
   (``/search/replacement/`` with the JavaScript ``$n``, ``$&`` and ``$$`` references) and
   ``hashes`` (the SHA-1 of the content with ``\\n`` line ends). Not supported: ``func`` (it
   runs code in a browser) and ``ast`` (it needs a JavaScript parser); their counts go to
   :attr:`Repository.unsupported`.
4. **Scan order** (:func:`detect_name`, :func:`detect_content`), as ``retire.scanJsFile``: the
   file name and the path first; only when they give nothing, the content: ``filecontent``,
   else ``filecontentreplace``, else the hash. A version loses a ``.min`` or ``-min`` suffix
   and must look like a version (:data:`MAX_VERSION_CHARS` at most). One
   :class:`Detection` per (library, version) and file; a ``filecontent`` detection keeps the
   line of the match and the matched text (cut to :data:`MAX_MATCH_CHARS`).
5. **Vulnerabilities** (:meth:`Library.affecting`), as ``retire.check``: a version is
   affected when it is below ``below``, at or above ``atOrAbove`` (when set) and not in
   ``excludes``. :func:`is_at_or_above` compares like ``retire.isAtOrAbove``: the parts
   between ``.`` and ``-`` compare as numbers when both are numbers, a number ranks above a
   text part, and a missing part counts as 0. The advisory IDs are the GHSA ID and the CVE
   IDs; a vulnerability without them gets the stable ID
   ``RETIRE-<library>-<identifier kind>-<value>`` (:attr:`Vulnerability.ids`).

The repository fields follow ``node/src/repo.ts`` of the same release (its validator).
"""

from __future__ import annotations

import hashlib
import itertools
import json
import os
import re
import warnings
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Final

from kalkan.errors import UnsafeInputError, ValidationError
from kalkan.matchers.safety import python_syntax_error
from kalkan.util.safe_io import read_bounded

__all__ = [
    "CONTENT_EXTRACTORS",
    "MAX_REGEX_CHARS",
    "NAME_EXTRACTORS",
    "SKIPPED_ENTRIES",
    "UNSUPPORTED_EXTRACTORS",
    "VERSION_CLASS",
    "VERSION_PLACEHOLDER",
    "Detection",
    "Extractor",
    "Library",
    "Repository",
    "Vulnerability",
    "compile_extractor",
    "content_sha1",
    "detect_content",
    "detect_name",
    "expand_lookbehinds",
    "is_at_or_above",
    "load_repository",
    "normalized_text",
    "parse_repository",
]

#: The version placeholder of the repository regexes and the class that replaces it.
VERSION_PLACEHOLDER: Final = "§§version§§"
VERSION_CLASS: Final = r"[0-9][0-9.a-z_\-]+"
#: Entries of the repository that are not libraries.
SKIPPED_ENTRIES: Final = frozenset({"dont check", "retire-example"})
#: The regex extractors in scan order: the name first, then the content.
NAME_EXTRACTORS: Final = ("filename", "uri")
CONTENT_EXTRACTORS: Final = ("filecontent", "filecontentreplace")
#: Extractors that need JavaScript (a browser or a parser); kalkan counts and skips them.
UNSUPPORTED_EXTRACTORS: Final = ("func", "ast")
#: The largest repository file that is read (the 2026-10-25 file has 609958 bytes).
MAX_REPOSITORY_BYTES: Final = 32 * 1024 * 1024
MAX_REGEX_CHARS: Final = 1000
MAX_REPEAT: Final = 10_000
MAX_VERSION_CHARS: Final = 64
MAX_MATCH_CHARS: Final = 200
MAX_INFO_LINKS: Final = 10
MAX_LIBRARIES: Final = 5000
MAX_VULNERABILITIES: Final = 5000
#: A variable-width lookbehind becomes at most this many fixed-width forms.
MAX_LOOKBEHIND_VARIANTS: Final = 64
MAX_LOOKBEHIND_REPEAT: Final = 16

_SEVERITIES: Final = {
    "none": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}
#: Identifier kinds (in this order) that name a vulnerability without a GHSA or CVE ID.
_FALLBACK_KINDS: Final = (
    "retid",
    "issue",
    "bug",
    "PR",
    "release",
    "gist",
    "blog",
    "tenable",
    "osvdb",
)
_REPLACE_FORM: Final = re.compile(r"/(.*[^\\])/([^/]+)/")
_BRACE: Final = re.compile(r"\{(\d+)(?:,(\d*))?\}")
_BOUNDS: Final = re.compile(r"\{(\d+)(?:,(\d+))?\}")
_HEX4: Final = re.compile(r"[0-9A-Fa-f]{4}")
_HEX2: Final = re.compile(r"[0-9A-Fa-f]{2}")
_MIN_SUFFIX: Final = re.compile(r"(?:\.|-)min$")
_VERSION_TEXT: Final = re.compile(r"[0-9][0-9A-Za-z._+~-]*")
#: The version form that the retire validator accepts in ``below``, ``atOrAbove``, ``excludes``.
_RANGE_VERSION: Final = re.compile(r"[\d.]+(?:[a-zA-Z\d.-]+)?")
_VERSION_SPLIT: Final = re.compile(r"[.\-]")
_DIGITS: Final = re.compile(r"[0-9]+")
_GHSA: Final = re.compile(r"GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}", re.IGNORECASE)
_CVE: Final = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}", re.IGNORECASE)
_CWE: Final = re.compile(r"CWE-[0-9]{1,6}")
_URL: Final = re.compile(r"https?://[^\s<>\"']{1,500}")
_SHA1: Final = re.compile(r"[0-9a-f]{40}")
_ID_PART: Final = re.compile(r"[^A-Za-z0-9._-]+")
_NPM_NAME: Final = re.compile(r"(?:@[A-Za-z0-9._~-]+/)?[A-Za-z0-9._~-]{1,214}")


# --- data ----------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Extractor:
    """One compiled regex extractor of a library."""

    kind: str  # filename | uri | filecontent | filecontentreplace
    source: str  # the regex text of the repository (placeholder not replaced)
    pattern: re.Pattern[str]
    template: str | None = None  # filecontentreplace: the Python form of the replacement


@dataclass(frozen=True)
class Vulnerability:
    """One vulnerable version range of a library."""

    below: str
    at_or_above: str | None
    excludes: tuple[str, ...]
    severity: str  # kalkan severity label: critical, high, medium, low, info ("" when unknown)
    cwe: tuple[str, ...]
    ids: tuple[str, ...]  # the GHSA ID and the CVE IDs, else the RETIRE fallback ID
    summary: str
    info: tuple[str, ...]

    def affects(self, version: str) -> bool:
        """Return True when ``version`` is in this range (``retire.check``)."""
        if is_at_or_above(version, self.below):
            return False
        if self.at_or_above is not None and not is_at_or_above(version, self.at_or_above):
            return False
        return version not in self.excludes

    def range_text(self) -> str:
        """Return the range as text, for example ``>=1.2.1, <1.9.0``."""
        parts = [f">={self.at_or_above}"] if self.at_or_above else []
        parts.append(f"<{self.below}")
        text = ", ".join(parts)
        if self.excludes:
            text += f" (except {', '.join(self.excludes)})"
        return text

    def fixed_version(self) -> str | None:
        """Return ``below`` as the first fixed version, or None for the retire placeholder of
        an unknown fix (a part of 999 or more, for example ``2.999.999`` or ``999.0.0``)."""
        parts = [part for part in _VERSION_SPLIT.split(self.below) if _DIGITS.fullmatch(part)]
        if any(int(part) >= 999 for part in parts):
            return None
        return self.below


@dataclass(frozen=True)
class Library:
    """One library of the repository."""

    name: str
    npm_name: str
    extractors: tuple[Extractor, ...]
    hashes: Mapping[str, str]  # SHA-1 of the content -> version
    vulnerabilities: tuple[Vulnerability, ...]

    def affecting(self, version: str) -> list[Vulnerability]:
        """Return the vulnerabilities whose range holds ``version``."""
        return [item for item in self.vulnerabilities if item.affects(version)]


@dataclass
class Repository:
    """The usable libraries of a repository document, with the counts of what was skipped."""

    libraries: dict[str, Library] = field(default_factory=dict)
    #: ``(library, extractor kind, reason)`` for each regex that kalkan does not run.
    skipped: list[tuple[str, str, str]] = field(default_factory=list)
    #: Extractor kind -> number of regexes that need JavaScript (``func``, ``ast``).
    unsupported: dict[str, int] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def extractor_count(self) -> int:
        """Return the number of usable regex extractors."""
        return sum(len(library.extractors) for library in self.libraries.values())

    def stats(self) -> dict[str, Any]:
        """Return the counts for the status file and ``update-db``."""
        return {
            "libraries": len(self.libraries),
            "vulnerabilities": sum(len(x.vulnerabilities) for x in self.libraries.values()),
            "extractors": self.extractor_count(),
            "hashes": sum(len(library.hashes) for library in self.libraries.values()),
            "skipped_extractors": len(self.skipped),
            "unsupported_extractors": dict(sorted(self.unsupported.items())),
        }


@dataclass(frozen=True)
class Detection:
    """One library version that an extractor found in one file."""

    library: str
    npm_name: str
    version: str
    path: str  # target-relative POSIX path
    extractor: str  # filename | uri | filecontent | filecontentreplace | hash
    line: int | None = None
    match: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-ready dict."""
        return {
            "library": self.library,
            "npm_name": self.npm_name,
            "version": self.version,
            "path": self.path,
            "extractor": self.extractor,
            "line": self.line,
            "match": self.match,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Detection:
        """Return a detection from :meth:`to_dict` output. Raise ValueError when malformed."""
        texts = {key: data.get(key) for key in ("library", "npm_name", "version", "path")}
        if not all(isinstance(value, str) and value for value in texts.values()):
            raise ValueError("a detection needs library, npm_name, version and path")
        line = data.get("line")
        if not (line is None or (isinstance(line, int) and not isinstance(line, bool))):
            raise ValueError("line must be a number or null")
        match = data.get("match")
        return cls(
            library=str(texts["library"]),
            npm_name=str(texts["npm_name"]),
            version=str(texts["version"]),
            path=str(texts["path"]),
            extractor=str(data.get("extractor") or ""),
            line=line,
            match=match if isinstance(match, str) else "",
        )


# --- versions ------------------------------------------------------------------------------------


def _comparable(part: str | None) -> int | str:
    if part is None:
        return 0
    return int(part) if _DIGITS.fullmatch(part) else part


def is_at_or_above(version1: str, version2: str) -> bool:
    """Return True when ``version1`` is at or above ``version2`` (``retire.isAtOrAbove``)."""
    left = _VERSION_SPLIT.split(version1)
    right = _VERSION_SPLIT.split(version2)
    for index in range(max(len(left), len(right))):
        a = _comparable(left[index] if index < len(left) else None)
        b = _comparable(right[index] if index < len(right) else None)
        if type(a) is not type(b):
            return isinstance(a, int)
        if a > b:  # type: ignore[operator]
            return True
        if a < b:  # type: ignore[operator]
            return False
    return True


def _clean_version(text: object) -> str | None:
    """Return a detected version without a ``.min``/``-min`` suffix, or None when it is not a
    version."""
    if not isinstance(text, str):
        return None
    version = _MIN_SUFFIX.sub("", text.strip())
    if not version or len(version) > MAX_VERSION_CHARS or not _VERSION_TEXT.fullmatch(version):
        return None
    return version


# --- extractors ----------------------------------------------------------------------------------


def _class_end(text: str, index: int) -> int:
    """Return the index after the character class at ``text[index] == "["``, or -1."""
    position = index + 1
    if text[position : position + 1] == "^":
        position += 1
    if text[position : position + 1] == "]":
        position += 1
    while position < len(text):
        if text[position] == "\\":
            position += 2
            continue
        if text[position] == "]":
            return position + 1
        position += 1
    return -1


def _atom_end(text: str, index: int) -> int:
    """Return the index after one simple atom (an escape, a class or a literal), or -1."""
    char = text[index]
    if char == "\\":
        following = text[index + 1 : index + 2]
        if not following or _DIGITS.fullmatch(following):
            return -1  # a backreference or an octal escape is not expanded
        if following == "u" and _HEX4.fullmatch(text[index + 2 : index + 6]):
            return index + 6
        if following == "x" and _HEX2.fullmatch(text[index + 2 : index + 4]):
            return index + 4
        return index + 2
    if char == "[":
        return _class_end(text, index)
    if char in "()|*+?{}^$":
        return -1
    return index + 1


def _expand_lookbehind(text: str, start: int) -> tuple[str, int] | None:
    """Return a lookbehind of bounded variable width as fixed-width alternatives, with the
    index after it; None when the group is not a plain sequence of simple atoms."""
    negative = text[start + 3] == "!"
    position = start + 4
    pieces: list[list[str]] = []
    while position < len(text) and text[position] != ")":
        end = _atom_end(text, position)
        if end < 0:
            return None
        atom = text[position:end]
        low = high = 1
        position = end
        if text[position : position + 1] == "?":
            low, position = 0, position + 1
        elif text[position : position + 1] in ("*", "+"):
            return None
        else:
            bounds = _BOUNDS.match(text, position)
            if bounds is not None:
                low = int(bounds.group(1))
                high = int(bounds.group(2)) if bounds.group(2) is not None else low
                position = bounds.end()
                if high < low or high > MAX_LOOKBEHIND_REPEAT:
                    return None
        if text[position : position + 1] == "?" and (low, high) != (1, 1):
            position += 1  # a lazy marker does not change an assertion
        pieces.append(
            [
                atom if count == 1 else f"{atom}{{{count}}}" if count else ""
                for count in range(low, high + 1)
            ]
        )
    if position >= len(text) or all(len(options) == 1 for options in pieces):
        return None
    total = 1
    for options in pieces:
        total *= len(options)
        if total > MAX_LOOKBEHIND_VARIANTS:
            return None
    variants = ["".join(parts) for parts in itertools.product(*pieces)]
    if negative:
        return "".join(f"(?<!{variant})" for variant in variants), position + 1
    return "(?:" + "|".join(f"(?<={variant})" for variant in variants) + ")", position + 1


def expand_lookbehinds(text: str) -> str:
    """Rewrite each lookbehind of bounded variable width into fixed-width lookbehinds.

    JavaScript allows a lookbehind of variable width, Python only a fixed width. A lookbehind
    that is a plain sequence of escapes, classes and literals with ``?`` or ``{m,n}`` repeats
    (at most :data:`MAX_LOOKBEHIND_VARIANTS` combinations) becomes the alternation of its
    fixed-width forms: ``(?<=[0-9]{1,2}\\.)`` becomes ``(?:(?<=[0-9]\\.)|(?<=[0-9]{2}\\.))``.
    The meaning stays the same. Any other lookbehind stays as it is (Python then refuses a
    variable width).
    """
    out: list[str] = []
    position = 0
    while position < len(text):
        char = text[position]
        if char == "\\":
            out.append(text[position : position + 2])
            position += 2
            continue
        if char == "[":
            end = _class_end(text, position)
            if end < 0:
                out.append(text[position:])
                break
            out.append(text[position:end])
            position = end
            continue
        if text.startswith(("(?<=", "(?<!"), position):
            expanded = _expand_lookbehind(text, position)
            if expanded is not None:
                out.append(expanded[0])
                position = expanded[1]
                continue
        out.append(char)
        position += 1
    return "".join(out)


def _python_template(replacement: str, groups: int) -> str:
    """Return the :meth:`re.Match.expand` form of a JavaScript replacement string.

    ``$n`` and ``$nn`` name a group (JavaScript keeps them as text when the group does not
    exist), ``$&`` is the whole match and ``$$`` a dollar sign. ``$```, ``$'`` and ``$<name>``
    are not supported (ValueError).
    """
    out: list[str] = []
    index = 0
    while index < len(replacement):
        char = replacement[index]
        if char == "\\":
            out.append("\\\\")
            index += 1
            continue
        if char != "$":
            out.append(char)
            index += 1
            continue
        following = replacement[index + 1 : index + 2]
        two = replacement[index + 1 : index + 3]
        if following == "$":
            out.append("$")
            index += 2
        elif following == "&":
            out.append("\\g<0>")
            index += 2
        elif len(two) == 2 and _DIGITS.fullmatch(two) and 1 <= int(two) <= groups:
            out.append(f"\\g<{int(two)}>")
            index += 3
        elif _DIGITS.fullmatch(following) and 1 <= int(following) <= groups:
            out.append(f"\\g<{following}>")
            index += 2
        elif following in ("`", "'", "<"):
            raise ValueError(f"the replacement reference ${following} is not supported")
        else:
            out.append("$")
            index += 1
    return "".join(out)


def compile_extractor(kind: str, text: object) -> Extractor:
    """Return the compiled extractor of one repository regex (module docstring, item 2).

    Raise :class:`ValueError` with the reason when the regex is not usable.
    """
    if kind not in (*NAME_EXTRACTORS, *CONTENT_EXTRACTORS):
        raise ValueError(f"unknown extractor kind {kind}")
    if not isinstance(text, str) or not text:
        raise ValueError("not a non-empty string")
    source = text
    replacement: str | None = None
    if kind == "filecontentreplace":
        form = _REPLACE_FORM.fullmatch(text)
        if form is None:
            raise ValueError("not in the form /search/replacement/")
        source, replacement = form.group(1), form.group(2)
    if len(source) > MAX_REGEX_CHARS:
        raise ValueError(f"longer than {MAX_REGEX_CHARS} characters")
    if "\0" in source:
        raise ValueError("holds a NUL character")
    expanded = expand_lookbehinds(source.replace(VERSION_PLACEHOLDER, VERSION_CLASS))
    error = python_syntax_error(expanded, allow_lookbehind=True)
    if error:
        raise ValueError(error)
    for match in _BRACE.finditer(expanded):
        bounds = [int(value) for value in match.groups() if value]
        if bounds and max(bounds) > MAX_REPEAT:
            raise ValueError(f"repeats more than {MAX_REPEAT} times")
    regex = f"^{expanded}$" if kind == "filename" else expanded
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            pattern = re.compile(regex, re.ASCII)
    except (re.error, Warning, RecursionError, OverflowError) as exc:
        raise ValueError(f"does not compile in Python: {exc}") from None
    if pattern.groups < 1:
        raise ValueError("has no capture group for the version")
    if pattern.search("") is not None:
        raise ValueError("matches the empty string")
    template = _python_template(replacement, pattern.groups) if replacement is not None else None
    return Extractor(kind, text, pattern, template)


# --- the repository ------------------------------------------------------------------------------


def _ids_of(library: str, identifiers: Mapping[str, Any], below: str) -> tuple[str, ...]:
    """Return the GHSA and CVE IDs of a vulnerability, else the RETIRE fallback ID."""
    ids: list[str] = []
    ghsa = identifiers.get("githubID")
    if isinstance(ghsa, str) and _GHSA.fullmatch(ghsa.strip()):
        ids.append("GHSA-" + ghsa.strip()[5:].lower())
    cves = identifiers.get("CVE")
    for cve in cves if isinstance(cves, list) else []:
        if isinstance(cve, str) and _CVE.fullmatch(cve.strip()) and cve.strip().upper() not in ids:
            ids.append(cve.strip().upper())
    if ids:
        return tuple(ids)
    name = _ID_PART.sub("_", library).strip("_")[:60] or "library"
    for kind in _FALLBACK_KINDS:
        value = identifiers.get(kind)
        if isinstance(value, list):
            value = next((item for item in value if isinstance(item, str | int)), None)
        if isinstance(value, str | int) and not isinstance(value, bool) and str(value).strip():
            part = _ID_PART.sub("_", str(value).strip()).strip("_")[:60]
            if part:
                return (f"RETIRE-{name}-{kind}-{part}",)
    summary = identifiers.get("summary")
    digest = hashlib.sha1(f"{summary}|{below}".encode(), usedforsecurity=False).hexdigest()
    return (f"RETIRE-{name}-{digest[:12]}",)


def _range_version(value: object) -> str | None:
    if isinstance(value, str) and _RANGE_VERSION.fullmatch(value.strip()):
        return value.strip()
    return None


def _vulnerability(library: str, item: object) -> Vulnerability:
    """Return one vulnerability of a library. Raise ValueError when it is malformed."""
    if not isinstance(item, Mapping):
        raise ValueError("not an object")
    below = _range_version(item.get("below"))
    if below is None:
        raise ValueError("no valid 'below' version")
    at_or_above = None
    if item.get("atOrAbove") is not None:
        at_or_above = _range_version(item.get("atOrAbove"))
        if at_or_above is None:
            raise ValueError("an invalid 'atOrAbove' version")
    excludes = item.get("excludes")
    excluded = tuple(
        value for value in (excludes if isinstance(excludes, list) else []) if _range_version(value)
    )
    identifiers = item.get("identifiers")
    identifiers = identifiers if isinstance(identifiers, Mapping) else {}
    severity = item.get("severity")
    label = _SEVERITIES.get(severity.strip().lower(), "") if isinstance(severity, str) else ""
    cwes = item.get("cwe")
    info = item.get("info")
    summary = identifiers.get("summary")
    return Vulnerability(
        below=below,
        at_or_above=at_or_above,
        excludes=excluded,
        severity=label,
        cwe=tuple(
            dict.fromkeys(
                cwe.strip()
                for cwe in (cwes if isinstance(cwes, list) else [])
                if isinstance(cwe, str) and _CWE.fullmatch(cwe.strip())
            )
        ),
        ids=_ids_of(library, identifiers, below),
        summary=" ".join(summary.split())[:2000] if isinstance(summary, str) else "",
        info=tuple(
            dict.fromkeys(
                url.strip()
                for url in (info if isinstance(info, list) else [])
                if isinstance(url, str) and _URL.fullmatch(url.strip())
            )
        )[:MAX_INFO_LINKS],
    )


def _library(name: str, entry: Mapping[str, Any], repository: Repository) -> Library | None:
    npm = entry.get("npmname")
    npm_name = npm.strip() if isinstance(npm, str) and _NPM_NAME.fullmatch(npm.strip()) else ""
    if not npm_name:
        npm_name = name if _NPM_NAME.fullmatch(name) else ""
    if not npm_name:
        repository.warnings.append(f"{name}: no usable npm name; skipped")
        return None
    raw = entry.get("extractors")
    extractors_doc = raw if isinstance(raw, Mapping) else {}
    extractors: list[Extractor] = []
    for kind in (*NAME_EXTRACTORS, *CONTENT_EXTRACTORS):
        values = extractors_doc.get(kind)
        for text in values if isinstance(values, list) else []:
            try:
                extractors.append(compile_extractor(kind, text))
            except ValueError as exc:
                repository.skipped.append((name, kind, str(exc)[:200]))
    for kind in UNSUPPORTED_EXTRACTORS:
        values = extractors_doc.get(kind)
        if isinstance(values, list) and values:
            repository.unsupported[kind] = repository.unsupported.get(kind, 0) + len(values)
    hashes: dict[str, str] = {}
    raw_hashes = extractors_doc.get("hashes")
    for digest, version in raw_hashes.items() if isinstance(raw_hashes, Mapping) else []:
        cleaned = _clean_version(version)
        if isinstance(digest, str) and _SHA1.fullmatch(digest.lower()) and cleaned:
            hashes[digest.lower()] = cleaned
    vulnerabilities: list[Vulnerability] = []
    raw_vulns = entry.get("vulnerabilities")
    for index, item in enumerate(raw_vulns if isinstance(raw_vulns, list) else []):
        if index >= MAX_VULNERABILITIES:
            repository.warnings.append(f"{name}: more than {MAX_VULNERABILITIES} vulnerabilities")
            break
        try:
            vulnerabilities.append(_vulnerability(name, item))
        except ValueError as exc:
            repository.warnings.append(f"{name}: vulnerability {index} skipped: {exc}")
    if not extractors and not hashes:
        repository.warnings.append(f"{name}: no usable extractor; skipped")
        return None
    return Library(name, npm_name, tuple(extractors), hashes, tuple(vulnerabilities))


def parse_repository(doc: object) -> Repository:
    """Return the usable libraries of a repository document (module docstring, item 1).

    Raise :class:`~kalkan.errors.ValidationError` when the document is not an object of
    libraries or no library is usable.
    """
    if not isinstance(doc, Mapping):
        message = "the RetireJS repository is not a JSON object of libraries"
        raise ValidationError(message, [message])
    repository = Repository()
    for name, entry in doc.items():
        if name in SKIPPED_ENTRIES:
            continue
        if len(repository.libraries) >= MAX_LIBRARIES:
            repository.warnings.append(f"more than {MAX_LIBRARIES} libraries; the rest skipped")
            break
        if not isinstance(name, str) or not name.strip() or len(name) > 200:
            repository.warnings.append("a library without a usable name was skipped")
            continue
        if not isinstance(entry, Mapping):
            repository.warnings.append(f"{name}: not an object; skipped")
            continue
        library = _library(name, entry, repository)
        if library is not None:
            repository.libraries[name] = library
    if not repository.libraries:
        message = "the RetireJS repository holds no usable library"
        raise ValidationError(message, [message])
    return repository


def load_repository(path: str | os.PathLike[str]) -> Repository:
    """Read and parse a repository file (bounded read, strict UTF-8 JSON).

    Raise :class:`~kalkan.errors.ValidationError` for a file that cannot be read or parsed.
    """
    try:
        data = read_bounded(path, MAX_REPOSITORY_BYTES)
        doc = json.loads(data.decode("utf-8"))
    except (UnsafeInputError, UnicodeDecodeError, ValueError, RecursionError) as exc:
        message = f"the RetireJS repository cannot be read: {exc}"
        raise ValidationError(message, [message]) from None
    return parse_repository(doc)


# --- detection -----------------------------------------------------------------------------------


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _add(
    found: dict[tuple[str, str], Detection],
    library: Library,
    raw_version: object,
    path: str,
    extractor: str,
    line: int | None = None,
    match: str = "",
) -> None:
    version = _clean_version(raw_version)
    if version is None or (library.name, version) in found:
        return
    found[(library.name, version)] = Detection(
        library=library.name,
        npm_name=library.npm_name,
        version=version,
        path=path,
        extractor=extractor,
        line=line,
        match=" ".join(match.split())[:MAX_MATCH_CHARS],
    )


def _libraries(repository: Repository) -> Iterable[Library]:
    return repository.libraries.values()


def detect_name(repository: Repository, path: str) -> list[Detection]:
    """Return the detections of the ``filename`` and ``uri`` extractors for a target-relative
    POSIX ``path`` (``retire.scanFileName`` with URIs)."""
    name = path.rsplit("/", 1)[-1]
    uri = "/" + path.lstrip("/")
    found: dict[tuple[str, str], Detection] = {}
    for kind, text in (("filename", name), ("uri", uri)):
        for library in _libraries(repository):
            for extractor in library.extractors:
                if extractor.kind != kind:
                    continue
                for match in extractor.pattern.finditer(text):
                    _add(found, library, match.group(1), path, kind)
    return list(found.values())


def normalized_text(data: bytes) -> str:
    """Return file bytes as text with ``\\n`` line ends (invalid UTF-8 becomes U+FFFD)."""
    return data.decode("utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n")


def content_sha1(text: str) -> str:
    """Return the SHA-1 of normalized content, as the retire ``hashes`` extractor computes it."""
    return hashlib.sha1(text.encode("utf-8"), usedforsecurity=False).hexdigest()


def detect_content(repository: Repository, path: str, data: bytes) -> list[Detection]:
    """Return the content detections of one file (``retire.scanFileContent``).

    ``filecontent`` first; only when it finds nothing, ``filecontentreplace``; only when that
    finds nothing, the SHA-1 of the content.
    """
    text = normalized_text(data)
    found: dict[tuple[str, str], Detection] = {}
    for library in _libraries(repository):
        for extractor in library.extractors:
            if extractor.kind != "filecontent":
                continue
            for match in extractor.pattern.finditer(text):
                line = _line_of(text, match.start())
                _add(found, library, match.group(1), path, "filecontent", line, match.group(0))
    if found:
        return list(found.values())
    for library in _libraries(repository):
        for extractor in library.extractors:
            if extractor.kind != "filecontentreplace" or extractor.template is None:
                continue
            for match in extractor.pattern.finditer(text):
                try:
                    version = match.expand(extractor.template)
                except (re.error, IndexError):
                    continue
                line = _line_of(text, match.start())
                _add(found, library, version, path, "filecontentreplace", line, match.group(0))
    if found:
        return list(found.values())
    digest = content_sha1(text)
    for library in _libraries(repository):
        version = library.hashes.get(digest)
        if version is not None:
            _add(found, library, version, path, "hash")
            break
    return list(found.values())
