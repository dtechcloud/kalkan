# SPDX-License-Identifier: Apache-2.0
# Ported from vercel-labs/deepsec@4fa6722: packages/scanner/src/matchers/utils.ts
# Copyright 2026 Vercel, Inc. and contributors. Changes: translated from TypeScript to Python;
# regexMatcher became a data-driven engine over JSON specs with repository gates, file gates,
# line-window conditions, path filters, a bounded file walk and ENGINE-SPEC candidate records.
"""Run matcher specs over a target folder and produce candidates (ENGINE-SPEC sections 4, 14).

The engine walks the target once in sorted order. It skips the folders in :data:`SKIP_DIRS`,
symbolic links, files larger than :data:`MAX_FILE_BYTES` and binary files (a NUL byte in the
first :data:`BINARY_SNIFF_BYTES` bytes). It decodes text as UTF-8 (invalid bytes become
U+FFFD, a BOM is removed), splits lines on ``\\n`` and removes one trailing ``\\r`` per line.
Every regex runs against one line at a time; lines longer than
:data:`~kalkan.matchers.safety.MAX_LINE_LENGTH` characters are never searched.

A matcher applies to a file when a ``file_patterns`` glob matches the target-relative POSIX
path and no ``exclude_file_patterns`` glob does. The engine reports one candidate per
(slug, file): ``start_line`` is the first matching line, the snippet is that line plus and minus
:data:`SNIPPET_CONTEXT` lines, and the message lists the labels and the matching lines (at most
:data:`MAX_MESSAGE_LINES`, then their number).

A condition with ``scope: "document"`` looks at the YAML document of the hit: the lines between
the nearest ``---`` or ``...`` separator lines around it (the whole file without separators).

A file matcher (``file_signatures`` or ``name_patterns``, :mod:`kalkan.matchers.spec`) reads
no lines. It reports one file-level candidate (``start_line`` and ``end_line`` null) when a
name glob matches the lower-case path, or when the first bytes start with a signature and the
first :data:`BINARY_SNIFF_BYTES` bytes hold a NUL byte (binary content; a text file that starts
with ``MZ`` does not count). It reads binary and large files too, but only their first bytes.
"""

from __future__ import annotations

import bisect
import os
import re
import stat
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from kalkan.errors import KalkanError
from kalkan.matchers.globs import GlobSet
from kalkan.matchers.safety import MAX_LINE_LENGTH, compile_regex
from kalkan.matchers.spec import Condition, MatcherSpec, Pattern

ENGINE = "matcher"
SKIP_DIRS = frozenset({".git", "node_modules", ".venv", "venv", "dist", "build"})
MAX_FILE_BYTES = 2 * 1024 * 1024
BINARY_SNIFF_BYTES = 8 * 1024
SNIPPET_CONTEXT = 2
#: A snippet line longer than this is cut, so that minified neighbours stay small.
MAX_SNIPPET_LINE = 2_000
#: At most this many sentinel files are read for one ``sentinel_contains`` gate.
MAX_SENTINEL_READS = 200
#: Default time budget for matching one file. A crafted line can make a single regex search
#: take seconds (one ``.*`` against thousands of repeats of its literal). When the budget is
#: used up, the engine stops matching that file and records a warning, so a hostile target
#: cannot stall the run. The results for that file are then incomplete.
MAX_FILE_SECONDS = 20.0
#: Default time budget for the whole run. The file budget alone did not bound the total: a
#: target controls the number of files, and many crafted files of 20 s each could stall the
#: audit (self-audit of 2026-11-13). When this budget is used up, the engine stops, keeps the
#: candidates found so far and records the number of files that were not scanned.
MAX_TOTAL_SECONDS = 900.0
#: The candidate message lists at most this many line numbers (a lockfile can match on
#: thousands of lines), then the number of the others.
MAX_MESSAGE_LINES = 50
_CHECK_EVERY = 1024
_SHORT_LINE = 2_000
# A YAML document separator: "---" (document start, may carry content) or "..." (document end).
_DOCUMENT_SEPARATOR = re.compile(r"(?:---|\.\.\.)(?:\s|$)")

TIER_SEVERITY = {"precise": "medium", "normal": "low", "noisy": "info"}
TIER_CONFIDENCE = {"precise": "medium", "normal": "low", "noisy": "low"}


@dataclass
class MatchStats:
    """Counters of one engine run."""

    files_total: int = 0
    files_scanned: int = 0
    files_skipped_binary: int = 0
    files_skipped_large: int = 0
    files_skipped_unreadable: int = 0
    files_timed_out: int = 0
    files_not_scanned_budget: int = 0
    lines_skipped_long: int = 0
    matchers_total: int = 0
    matchers_applied: int = 0
    candidates: int = 0

    def to_dict(self) -> dict[str, int]:
        return dict(vars(self))


@dataclass
class MatchRun:
    """Result of :func:`run`."""

    candidates: list[dict[str, Any]]
    stats: MatchStats
    #: Matchers that did not run, with the reason (``noisy``, ``tech``, ``sentinel``).
    skipped: dict[str, str] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


def run(
    target_dir: str | Path,
    tech: Iterable[str],
    specs: Iterable[MatcherSpec],
    *,
    include_noisy: bool = True,
    max_file_seconds: float | None = MAX_FILE_SECONDS,
    max_total_seconds: float | None = MAX_TOTAL_SECONDS,
) -> MatchRun:
    """Run ``specs`` over ``target_dir`` and return the candidates in a deterministic order.

    ``tech`` is the list of detected technology tags (``kalkan.run.tech.detect``). A matcher
    with ``requires.tech`` runs only when the tags intersect. With ``include_noisy=False`` the
    ``noisy`` tier is skipped. ``max_file_seconds`` bounds the matching time of one file
    (None: no bound); a file that exceeds it keeps the candidates of the matchers that
    finished and gets a warning. ``max_total_seconds`` bounds the whole run (None: no bound):
    when it is used up, the remaining files are not scanned, and one warning names their number.
    """
    root = Path(target_dir)
    if not root.is_dir():
        raise KalkanError(f"target folder not found: {root}")
    stats = MatchStats()
    result = MatchRun(candidates=[], stats=stats)
    files = list_files(root)
    stats.files_total = len(files)
    reader = _Reader(root, stats)
    sentinels = _Sentinels(files, reader)
    tags = {item.strip().lower() for item in tech}
    matchers: list[_CompiledMatcher] = []
    for spec in sorted(specs, key=lambda item: item.slug):
        stats.matchers_total += 1
        reason = _gate_reason(spec, tags, sentinels, include_noisy)
        if reason:
            result.skipped[spec.slug] = reason
            continue
        matchers.append(_CompiledMatcher(spec))
    stats.matchers_applied = len(matchers)

    candidates: list[dict[str, Any]] = []
    run_deadline = None if max_total_seconds is None else time.monotonic() + max_total_seconds
    for position, rel in enumerate(files):
        if run_deadline is not None and time.monotonic() >= run_deadline:
            stats.files_not_scanned_budget = len(files) - position
            result.warnings.append(
                f"matching stopped after {max_total_seconds:g} s for the whole run; "
                f"{stats.files_not_scanned_budget} files were not scanned"
            )
            break
        applicable = [item for item in matchers if item.applies_to(rel)]
        if not applicable:
            continue
        file_level = [item for item in applicable if item.spec.is_file_matcher]
        if file_level:
            head = _Head(root / rel)
            for matcher in file_level:
                labels, header = matcher.match_file(rel, head)
                if labels:
                    candidates.append(_file_candidate(matcher.spec, rel, labels, header))
            applicable = [item for item in applicable if not item.spec.is_file_matcher]
            if not applicable:
                continue
        lines = reader.lines(rel)
        if lines is None:
            continue
        stats.files_scanned += 1
        deadline = None if max_file_seconds is None else time.monotonic() + max_file_seconds
        if run_deadline is not None:
            deadline = run_deadline if deadline is None else min(deadline, run_deadline)
        context = _FileContext(lines, stats, deadline)
        try:
            for matcher in applicable:
                hits = matcher.match(rel, context)
                if hits:
                    candidates.append(_candidate(matcher.spec, rel, lines, hits))
        except _Timeout:
            stats.files_timed_out += 1
            result.warnings.append(
                f"{rel}: matching stopped after the time budget; "
                "the results for this file are incomplete"
            )
    candidates.sort(key=lambda item: (item["file"], item["start_line"] or 0, item["rule_id"]))
    for index, candidate in enumerate(candidates):
        candidate["raw"]["result_index"] = index
    stats.candidates = len(candidates)
    result.candidates = candidates
    return result


def list_files(root: Path) -> list[str]:
    """Return the target-relative POSIX paths of all regular files, sorted.

    Folders in :data:`SKIP_DIRS`, symbolic links and Windows junctions are not entered.
    """
    found: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        base = Path(dirpath)
        dirnames[:] = sorted(
            name for name in dirnames if name not in SKIP_DIRS and not _is_link(base / name)
        )
        for name in filenames:
            path = base / name
            try:
                mode = os.lstat(path).st_mode
            except OSError:
                continue
            if stat.S_ISREG(mode):
                found.append(path.relative_to(root).as_posix())
    return sorted(found)


def severity_for(spec: MatcherSpec) -> str:
    """Return the candidate severity: ``info`` for surface matchers (no class), else by tier."""
    if spec.vuln_class is None:
        return "info"
    return TIER_SEVERITY[spec.noise_tier]


def _is_link(path: Path) -> bool:
    if path.is_symlink():
        return True
    isjunction = getattr(os.path, "isjunction", None)
    return bool(isjunction and isjunction(path))


def _gate_reason(
    spec: MatcherSpec,
    tags: set[str],
    sentinels: _Sentinels,
    include_noisy: bool,
) -> str:
    if spec.noise_tier == "noisy" and not include_noisy:
        return "noisy"
    gate = spec.requires
    if gate.tech and not tags.intersection(item.lower() for item in gate.tech):
        return "tech"
    if gate.sentinel_files and not sentinels.passes(gate.sentinel_files, gate.sentinel_contains):
        return "sentinel"
    return ""


class _Sentinels:
    """Evaluates sentinel gates once per distinct gate."""

    def __init__(self, files: list[str], reader: _Reader) -> None:
        self.files = files
        self.reader = reader
        self._found: dict[tuple[str, ...], list[str]] = {}
        self._results: dict[tuple[tuple[str, ...], tuple[str, ...]], bool] = {}

    def passes(self, globs: tuple[str, ...], contains: tuple[str, ...]) -> bool:
        key = (globs, contains)
        if key not in self._results:
            self._results[key] = self._evaluate(globs, contains)
        return self._results[key]

    def _evaluate(self, globs: tuple[str, ...], contains: tuple[str, ...]) -> bool:
        found = self._found.get(globs)
        if found is None:
            matcher = GlobSet(globs)
            # Shallow files first: manifests near the root decide most gates.
            found = sorted(
                (rel for rel in self.files if matcher.matches(rel)),
                key=lambda rel: (rel.count("/"), rel),
            )
            self._found[globs] = found
        if not contains:
            return bool(found)
        regexes = [compile_regex(item) for item in contains]
        for rel in found[:MAX_SENTINEL_READS]:
            lines = self.reader.lines(rel, count=False)
            if lines is not None and all(_any_line(regex, lines) for regex in regexes):
                return True
        return False


def _any_line(regex: re.Pattern[str], lines: list[str]) -> bool:
    return any(len(line) <= MAX_LINE_LENGTH and regex.search(line) for line in lines)


class _Reader:
    """Bounded file reads. Sentinel reads (``count=False``) stay cached for later gates."""

    def __init__(self, root: Path, stats: MatchStats) -> None:
        self.root = root
        self.stats = stats
        self._cache: dict[str, tuple[list[str] | None, str]] = {}

    def lines(self, rel: str, *, count: bool = True) -> list[str] | None:
        cached = self._cache.get(rel)
        if cached is None:
            cached = read_lines(self.root / rel)
            if not count:
                self._cache[rel] = cached
        lines, status = cached
        if count:
            if status == "binary":
                self.stats.files_skipped_binary += 1
            elif status == "too-large":
                self.stats.files_skipped_large += 1
            elif status != "ok":
                self.stats.files_skipped_unreadable += 1
        return lines


def read_lines(path: Path) -> tuple[list[str] | None, str]:
    """Read ``path`` as text lines. Return ``(lines, "ok")`` or ``(None, reason)``.

    Reasons: ``unreadable``, ``not-regular``, ``too-large``, ``binary``.
    """
    try:
        info = os.lstat(path)
    except OSError:
        return None, "unreadable"
    if not stat.S_ISREG(info.st_mode):
        return None, "not-regular"
    if info.st_size > MAX_FILE_BYTES:
        return None, "too-large"
    try:
        with open(path, "rb") as handle:
            data = handle.read(MAX_FILE_BYTES + 1)
    except OSError:
        return None, "unreadable"
    if len(data) > MAX_FILE_BYTES:
        return None, "too-large"
    if b"\x00" in data[:BINARY_SNIFF_BYTES]:
        return None, "binary"
    text = data.decode("utf-8-sig", errors="replace")
    return [line[:-1] if line.endswith("\r") else line for line in text.split("\n")], "ok"


class _Head:
    """The first bytes of one file, read once for all file matchers (lazy)."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._data: bytes | None = None
        self._binary: bool | None = None

    def data(self) -> bytes:
        """Return the first :data:`BINARY_SNIFF_BYTES` bytes (empty for a file that cannot be
        read or is not a regular file)."""
        if self._data is None:
            self._data = b""
            try:
                if stat.S_ISREG(os.lstat(self.path).st_mode):
                    with open(self.path, "rb") as handle:
                        self._data = handle.read(BINARY_SNIFF_BYTES)
            except OSError:
                self._data = b""
        return self._data

    def binary(self) -> bool:
        """Return True when the first bytes hold a NUL byte."""
        if self._binary is None:
            self._binary = b"\x00" in self.data()
        return self._binary


class _Timeout(Exception):
    """The time budget of one file is used up."""


class _FileContext:
    """The lines of one file, the time budget and a cache of regex hits per line."""

    def __init__(self, lines: list[str], stats: MatchStats, deadline: float | None) -> None:
        self.lines = lines
        self.deadline = deadline
        self._searchable = [
            index for index, line in enumerate(lines) if len(line) <= MAX_LINE_LENGTH
        ]
        stats.lines_skipped_long += len(lines) - len(self._searchable)
        # Small files without long lines take the fast path: one budget check per scan.
        self._fast = deadline is None or (
            len(self._searchable) <= _CHECK_EVERY
            and all(len(lines[index]) <= _SHORT_LINE for index in self._searchable)
        )
        self._hits: dict[re.Pattern[str], list[int]] = {}
        self._present: dict[re.Pattern[str], bool] = {}
        self._separators: list[int] | None = None

    def document(self, index: int) -> tuple[int, int]:
        """Return the first and last 0-based line of the YAML document of line ``index``."""
        if self._separators is None:
            self._separators = [
                number
                for number, line in enumerate(self.lines)
                if len(line) <= MAX_LINE_LENGTH and _DOCUMENT_SEPARATOR.match(line)
            ]
        position = bisect.bisect_right(self._separators, index)
        start = self._separators[position - 1] + 1 if position else 0
        if position < len(self._separators):
            end = self._separators[position] - 1
        else:
            end = len(self.lines) - 1
        return start, end

    def hits(self, regex: re.Pattern[str]) -> list[int]:
        """Return the sorted 0-based indexes of the lines that ``regex`` matches."""
        found = self._hits.get(regex)
        if found is None:
            found = self.scan(regex, self._searchable)
            self._hits[regex] = found
        return found

    def present(self, regex: re.Pattern[str]) -> bool:
        """Return True when ``regex`` matches any line (stops at the first hit)."""
        cached = self._present.get(regex)
        if cached is None:
            if regex in self._hits:
                cached = bool(self._hits[regex])
            else:
                cached = bool(self.scan(regex, self._searchable, first=True))
            self._present[regex] = cached
        return cached

    def scan(self, regex: re.Pattern[str], indexes: list[int], first: bool = False) -> list[int]:
        """Return the indexes in ``indexes`` whose line ``regex`` matches, in order."""
        lines = self.lines
        search = regex.search
        self.check()
        if self._fast:
            if first:
                return next(([index] for index in indexes if search(lines[index])), [])
            return [index for index in indexes if search(lines[index])]
        found: list[int] = []
        for count, index in enumerate(indexes):
            line = lines[index]
            if len(line) > _SHORT_LINE or not count % _CHECK_EVERY:
                self.check()
            if search(line):
                found.append(index)
                if first:
                    break
        return found

    def check(self) -> None:
        if self.deadline is not None and time.monotonic() > self.deadline:
            raise _Timeout


class _CompiledCondition:
    def __init__(self, condition: Condition) -> None:
        self.regex = compile_regex(condition.regex, condition.flags)
        self.before = condition.before
        self.after = condition.after
        self.whole_file = condition.whole_file
        self.document = condition.document

    def holds(self, context: _FileContext, index: int) -> bool:
        if self.whole_file:
            return context.present(self.regex)
        if self.document:
            first, last = context.document(index)
        else:
            first, last = index - self.before, index + self.after
        found = context.hits(self.regex)
        position = bisect.bisect_left(found, first)
        return position < len(found) and found[position] <= last


class _CompiledPattern:
    def __init__(self, pattern: Pattern) -> None:
        self.label = pattern.label
        self.regex = compile_regex(pattern.regex, pattern.flags)
        self.near = [_CompiledCondition(item) for item in pattern.near]
        self.not_near = [_CompiledCondition(item) for item in pattern.not_near]
        self.paths = GlobSet(pattern.paths)

    def lines(self, rel: str, context: _FileContext, candidates: list[int] | None) -> list[int]:
        if self.paths and not self.paths.matches(rel):
            return []
        if candidates is None:
            found = context.hits(self.regex)
        else:
            found = context.scan(self.regex, candidates)
        return [
            index
            for index in found
            if all(item.holds(context, index) for item in self.near)
            and not any(item.holds(context, index) for item in self.not_near)
        ]


class _CompiledMatcher:
    def __init__(self, spec: MatcherSpec) -> None:
        self.spec = spec
        self.include = GlobSet(spec.file_patterns)
        self.exclude = GlobSet(spec.exclude_file_patterns)
        self.file_contains = [compile_regex(item) for item in spec.file_contains]
        self.file_excludes = [compile_regex(item) for item in spec.file_excludes]
        self.patterns = [_CompiledPattern(item) for item in spec.patterns]
        self.prefilter = _prefilter(spec.patterns)
        self.names = [(GlobSet((item.glob,)), item.label) for item in spec.name_patterns]
        self.signatures = [(item.prefix, item.label) for item in spec.file_signatures]

    def applies_to(self, rel: str) -> bool:
        return self.include.matches(rel) and not self.exclude.matches(rel)

    def match_file(self, rel: str, head: _Head) -> tuple[list[str], bytes]:
        """Return the labels of a file matcher for one file and the bytes of a signature hit
        (empty without one). A signature counts only for binary content."""
        lowered = rel.lower()
        labels = [label for globs, label in self.names if globs.matches(lowered)]
        header = b""
        if self.signatures:
            data = head.data()
            hits = [label for prefix, label in self.signatures if data.startswith(prefix)]
            if hits and head.binary():
                header = data[:HEADER_BYTES]
                labels += [label for label in hits if label not in labels]
        return labels, header

    def match(self, rel: str, context: _FileContext) -> dict[int, list[str]]:
        """Return ``{0-based line index: [labels]}`` for the hits of this matcher in a file."""
        if not all(context.present(regex) for regex in self.file_contains):
            return {}
        if any(context.present(regex) for regex in self.file_excludes):
            return {}
        # The prefilter matches a line exactly when some pattern regex matches it, so the
        # patterns only need to look at those lines.
        candidates = context.hits(self.prefilter) if self.prefilter is not None else None
        if candidates == []:
            return {}
        hits: dict[int, list[str]] = {}
        for pattern in self.patterns:
            for index in pattern.lines(rel, context, candidates):
                labels = hits.setdefault(index, [])
                if pattern.label not in labels:
                    labels.append(pattern.label)
        return hits


def _prefilter(patterns: Iterable[Pattern]) -> re.Pattern[str] | None:
    """Join the pattern regexes of a matcher into one alternation (flags scoped per branch).

    Each branch already passed the safety checks; an unquantified alternation of safe
    branches adds no nested repetition. None for a single pattern or when the branches do not
    combine (for example duplicate group names).
    """
    items = list(patterns)
    if len(items) < 2:
        return None
    branches = [
        f"(?{item.flags}:{item.regex})" if item.flags else f"(?:{item.regex})" for item in items
    ]
    try:
        return re.compile("|".join(branches), re.ASCII)
    except re.error:
        return None


def _candidate(
    spec: MatcherSpec, rel: str, lines: list[str], hits: Mapping[int, list[str]]
) -> dict[str, Any]:
    from kalkan.findings.fingerprint import candidate_id  # lazy: phase 1 module

    indexes = sorted(hits)
    first = indexes[0]
    labels: list[str] = []
    for pattern in spec.patterns:  # labels in pattern order
        if pattern.label not in labels and any(pattern.label in hits[i] for i in indexes):
            labels.append(pattern.label)
    start = max(0, first - SNIPPET_CONTEXT)
    end = min(len(lines), first + SNIPPET_CONTEXT + 1)
    snippet = "\n".join(line[:MAX_SNIPPET_LINE] for line in lines[start:end])
    numbers = [index + 1 for index in indexes]
    listed = ", ".join(str(n) for n in numbers[:MAX_MESSAGE_LINES])
    if len(numbers) > MAX_MESSAGE_LINES:
        listed += f" and {len(numbers) - MAX_MESSAGE_LINES} more"
    message = f"Matched: {'; '.join(labels)}. Line{'s' if len(numbers) > 1 else ''}: {listed}."
    start_line = first + 1
    return {
        "id": candidate_id(ENGINE, spec.slug, rel, start_line, snippet),
        "engine": ENGINE,
        "rule_id": spec.slug,
        "class": spec.vuln_class,
        "cwe": list(spec.cwe),
        "title": spec.description,
        "message": message,
        "file": rel,
        "start_line": start_line,
        "end_line": start_line,
        "snippet": snippet,
        "severity": severity_for(spec),
        "tool_severity": spec.noise_tier,
        "confidence": TIER_CONFIDENCE[spec.noise_tier],
        "tags": [f"noise:{spec.noise_tier}"],
        "fingerprints": {},
        "sca": None,
        "raw": {"sarif_file": "", "run_index": 0, "result_index": 0},
    }


#: The snippet of a file-level candidate shows this many bytes of the signature hit.
HEADER_BYTES = 8


def _file_candidate(
    spec: MatcherSpec, rel: str, labels: list[str], header: bytes
) -> dict[str, Any]:
    """Return the file-level candidate of a file matcher (no line; ENGINE-SPEC 14)."""
    from kalkan.findings.fingerprint import candidate_id  # lazy: phase 1 module

    name = rel.rsplit("/", 1)[-1]
    snippet = f"file header: {header.hex(' ')}" if header else f"file name: {name}"
    message = f"Matched: {'; '.join(labels)}. File-level result: {name}."
    return {
        "id": candidate_id(ENGINE, spec.slug, rel, None, snippet),
        "engine": ENGINE,
        "rule_id": spec.slug,
        "class": spec.vuln_class,
        "cwe": list(spec.cwe),
        "title": spec.description,
        "message": message,
        "file": rel,
        "start_line": None,
        "end_line": None,
        "snippet": snippet,
        "severity": severity_for(spec),
        "tool_severity": spec.noise_tier,
        "confidence": TIER_CONFIDENCE[spec.noise_tier],
        "tags": [f"noise:{spec.noise_tier}", "file-level"],
        "fingerprints": {},
        "sca": None,
        "raw": {"sarif_file": "", "run_index": 0, "result_index": 0},
    }
