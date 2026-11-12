# SPDX-License-Identifier: Apache-2.0
# Ported from vercel-labs/deepsec@4fa6722: packages/scanner/src/declarative-matcher.ts
# Copyright 2026 Vercel, Inc. and contributors. Changes: translated from TypeScript to Python;
# the zod schema became hand-written validation of the kalkan JSON format (ENGINE-SPEC 14) with
# snake_case keys, a vulnerability class, CWE IDs, sentinel content regexes, file-level content
# gates, line-window conditions, per-pattern path filters, examples and source provenance.
"""Load and validate matcher specs (``rules/matchers/<slug>.json``, ENGINE-SPEC section 14).

A spec is strict data: unknown keys are errors, every glob passes
:func:`~kalkan.matchers.safety.glob_safety_error`, every regex passes
:func:`~kalkan.matchers.safety.regex_safety_error`, and every example is matched by at least one
pattern (line by line, as the engine matches).

Keys beyond the ENGINE-SPEC example (all optional):

- ``file_contains``: regexes. The engine scans a file only when each regex matches at least one
  line of the file (all of them).
- ``file_excludes``: regexes. The engine skips a file when any regex matches any line.
- Per pattern, ``near`` and ``not_near``: conditions ``{regex, flags, before, after}``,
  ``{regex, flags, scope: "file"}`` or ``{regex, flags, scope: "document"}``. A hit on line *n*
  counts only when every ``near`` regex matches a line in ``[n - before, n + after]`` (or
  anywhere in the file, or anywhere in the YAML document of line *n*: the lines between the
  ``---`` or ``...`` separators around it) and no ``not_near`` regex does.
- Per pattern, ``paths``: globs. The pattern applies only to files that match one of them.
- File matchers (kalkan extension): ``file_signatures`` (``{hex, label}``: a byte prefix of the
  file, 2 to 16 bytes in lower-case hex) and ``name_patterns`` (``{glob, label}``: a lower-case
  glob, compared with the lower-case path). A spec with either key has ``patterns: []`` and no
  ``file_contains`` or ``file_excludes``; the engine reports one file-level result per file
  (``start_line`` null) when a name glob matches, or a signature matches a file with a NUL byte
  in its first 8 KiB (binary content). Its ``file_patterns`` may be broad (``**/*``) when it has
  signatures, because it reads only the first bytes of a file. Each example is a path that a
  name glob matches, or ``hex:<bytes>`` that starts with a signature.

Gate semantics: ``requires.tech`` passes when the detected technologies intersect it.
``requires.sentinel_files`` passes when a target file matches one of the globs and, when
``requires.sentinel_contains`` is not empty, that file has a line for each regex. When both
are given, both must pass. File-level regex lists take scoped inline flags such as ``(?i:...)``.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from kalkan.errors import ValidationError
from kalkan.matchers.globs import GlobSet
from kalkan.matchers.safety import (
    MAX_LINE_LENGTH,
    compile_regex,
    flags_error,
    glob_safety_error,
    regex_safety_error,
)

SPEC_VERSION = 1
MAX_SLUG_LENGTH = 80
MAX_DESCRIPTION_LENGTH = 500
MAX_LABEL_LENGTH = 240
MAX_NOTES_LENGTH = 4000
MAX_GLOBS = 32
MAX_PATTERNS = 32
MAX_REGEX_LIST = 32
MAX_CONDITIONS = 8
MAX_WINDOW = 10_000
MAX_EXAMPLES = 64
MAX_EXAMPLE_LENGTH = 10_000
MAX_TECH = 32
MAX_TECH_LENGTH = 80
MAX_CWE = 16
NOISE_TIERS = ("precise", "normal", "noisy")

#: Vulnerability class slugs of ENGINE-SPEC section 3 (``kalkan.findings.taxonomy``).
CLASS_SLUGS = frozenset(
    {
        "sqli",
        "nosqli",
        "os-command-injection",
        "code-injection",
        "ssti",
        "xss",
        "ssrf",
        "path-traversal",
        "file-upload",
        "xxe",
        "deserialization",
        "authn",
        "jwt",
        "oauth-oidc-saml",
        "missing-authz",
        "idor",
        "multi-tenant",
        "csrf",
        "open-redirect",
        "cors",
        "mass-assignment",
        "business-logic",
        "race-condition",
        "crypto",
        "hardcoded-secrets",
        "sensitive-data-exposure",
        "security-misconfig",
        "graphql",
        "prototype-pollution",
        "dos-redos",
        "request-smuggling-crlf-cache",
        "webhook-replay",
        "rate-limit-bruteforce",
        "llm-ai",
        "memory-safety",
        "smart-contract",
        "mobile-desktop-ipc",
        "vulnerable-dependency",
        "malicious-dependency",
        "supply-chain-cicd",
        "iac-cloud-container",
        "code-quality",
    }
)

_SLUG = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
_CWE = re.compile(r"CWE-[0-9]+")
_TECH = re.compile(r"[a-z0-9][a-z0-9.+_-]*")

_TOP_KEYS = frozenset(
    {
        "version",
        "slug",
        "description",
        "class",
        "cwe",
        "noise_tier",
        "file_patterns",
        "exclude_file_patterns",
        "requires",
        "file_contains",
        "file_excludes",
        "file_signatures",
        "name_patterns",
        "patterns",
        "examples",
        "source",
        "notes",
    }
)
_REQUIRED_KEYS = (
    "version",
    "slug",
    "description",
    "class",
    "cwe",
    "noise_tier",
    "file_patterns",
    "patterns",
    "examples",
)
_REQUIRES_KEYS = frozenset({"tech", "sentinel_files", "sentinel_contains"})
_PATTERN_KEYS = frozenset({"regex", "flags", "label", "near", "not_near", "paths"})
_CONDITION_KEYS = frozenset({"regex", "flags", "before", "after", "scope"})
_SOURCE_KEYS = frozenset({"repo", "commit", "path"})
_SIGNATURE_KEYS = frozenset({"hex", "label"})
_NAME_PATTERN_KEYS = frozenset({"glob", "label"})
_HEX = re.compile(r"(?:[0-9a-f]{2}){2,16}")
#: The prefix of a file matcher example that gives file bytes (``hex:7f454c46``).
HEX_EXAMPLE_PREFIX = "hex:"
CONDITION_SCOPES = ("lines", "file", "document")


@dataclass(frozen=True)
class Condition:
    """A regex that must (``near``) or must not (``not_near``) match close to a hit."""

    regex: str
    flags: str = ""
    before: int = 0
    after: int = 0
    whole_file: bool = False
    #: The YAML document of the hit: the lines between the ``---``/``...`` separators.
    document: bool = False

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"regex": self.regex}
        if self.flags:
            data["flags"] = self.flags
        if self.whole_file:
            data["scope"] = "file"
        elif self.document:
            data["scope"] = "document"
        else:
            if self.before:
                data["before"] = self.before
            if self.after:
                data["after"] = self.after
        return data


@dataclass(frozen=True)
class Pattern:
    """One regex of a matcher, with its label and optional context conditions."""

    regex: str
    flags: str
    label: str
    near: tuple[Condition, ...] = ()
    not_near: tuple[Condition, ...] = ()
    paths: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"regex": self.regex, "flags": self.flags, "label": self.label}
        if self.near:
            data["near"] = [item.to_dict() for item in self.near]
        if self.not_near:
            data["not_near"] = [item.to_dict() for item in self.not_near]
        if self.paths:
            data["paths"] = list(self.paths)
        return data


@dataclass(frozen=True)
class Signature:
    """A byte prefix of a file matcher (``file_signatures``)."""

    hex: str
    label: str

    @property
    def prefix(self) -> bytes:
        return bytes.fromhex(self.hex)

    def to_dict(self) -> dict[str, str]:
        return {"hex": self.hex, "label": self.label}


@dataclass(frozen=True)
class NamePattern:
    """A lower-case file name glob of a file matcher (``name_patterns``)."""

    glob: str
    label: str

    def to_dict(self) -> dict[str, str]:
        return {"glob": self.glob, "label": self.label}


@dataclass(frozen=True)
class Requires:
    """Repository-level gate of a matcher."""

    tech: tuple[str, ...] = ()
    sentinel_files: tuple[str, ...] = ()
    sentinel_contains: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "tech": list(self.tech),
            "sentinel_files": list(self.sentinel_files),
            "sentinel_contains": list(self.sentinel_contains),
        }


@dataclass(frozen=True)
class Source:
    """Provenance of a ported spec."""

    repo: str
    commit: str
    path: str

    def to_dict(self) -> dict[str, str]:
        return {"repo": self.repo, "commit": self.commit, "path": self.path}


@dataclass(frozen=True)
class MatcherSpec:
    """A validated matcher spec."""

    slug: str
    description: str
    vuln_class: str | None
    cwe: tuple[str, ...]
    noise_tier: str
    file_patterns: tuple[str, ...]
    patterns: tuple[Pattern, ...]
    examples: tuple[str, ...]
    exclude_file_patterns: tuple[str, ...] = ()
    requires: Requires = field(default_factory=Requires)
    file_contains: tuple[str, ...] = ()
    file_excludes: tuple[str, ...] = ()
    source: Source | None = None
    notes: str = ""
    origin: str = field(default="", compare=False)
    file_signatures: tuple[Signature, ...] = ()
    name_patterns: tuple[NamePattern, ...] = ()

    @property
    def is_file_matcher(self) -> bool:
        """True for a file matcher: one file-level result per file, no line patterns."""
        return bool(self.file_signatures or self.name_patterns)

    def to_dict(self) -> dict[str, Any]:
        """Return the canonical JSON form (key order of ENGINE-SPEC 14)."""
        data: dict[str, Any] = {
            "version": SPEC_VERSION,
            "slug": self.slug,
            "description": self.description,
            "class": self.vuln_class,
            "cwe": list(self.cwe),
            "noise_tier": self.noise_tier,
            "file_patterns": list(self.file_patterns),
            "exclude_file_patterns": list(self.exclude_file_patterns),
            "requires": self.requires.to_dict(),
        }
        if self.file_contains:
            data["file_contains"] = list(self.file_contains)
        if self.file_excludes:
            data["file_excludes"] = list(self.file_excludes)
        if self.file_signatures:
            data["file_signatures"] = [item.to_dict() for item in self.file_signatures]
        if self.name_patterns:
            data["name_patterns"] = [item.to_dict() for item in self.name_patterns]
        data["patterns"] = [item.to_dict() for item in self.patterns]
        data["examples"] = list(self.examples)
        data["source"] = self.source.to_dict() if self.source else None
        data["notes"] = self.notes
        return data


def spec_errors(data: object) -> list[str]:
    """Return every validation error of ``data`` (an empty list when the spec is valid)."""
    try:
        parse_spec(data)
    except ValidationError as exc:
        return list(exc.errors)
    return []


def parse_spec(data: object, *, origin: str = "") -> MatcherSpec:
    """Validate ``data`` (a decoded JSON object) and return the spec.

    Raises :class:`~kalkan.errors.ValidationError` with every problem in ``errors``.
    """
    checker = _Checker(origin or "<spec>")
    spec = checker.spec(data)
    if checker.errors or spec is None:
        raise ValidationError(f"invalid matcher spec {checker.origin}", checker.errors)
    return spec


def load_spec(path: str | Path) -> MatcherSpec:
    """Read and validate one spec file. The file name must be ``<slug>.json``."""
    file = Path(path)
    origin = file.as_posix()
    try:
        data = json.loads(file.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        message = f"{origin}: cannot read JSON: {exc}"
        raise ValidationError(message, [message]) from exc
    spec = parse_spec(data, origin=origin)
    if file.name != f"{spec.slug}.json":
        message = f"{origin}: file name must be {spec.slug}.json"
        raise ValidationError(message, [message])
    return spec


def load_specs(directory: str | Path) -> list[MatcherSpec]:
    """Load every ``*.json`` spec in ``directory``, sorted by slug.

    Raises :class:`~kalkan.errors.ValidationError` with the errors of all files, also for
    duplicate slugs.
    """
    folder = Path(directory)
    if not folder.is_dir():
        message = f"matcher directory not found: {folder.as_posix()}"
        raise ValidationError(message, [message])
    specs: list[MatcherSpec] = []
    errors: list[str] = []
    for file in sorted(folder.glob("*.json"), key=lambda item: item.name):
        try:
            specs.append(load_spec(file))
        except ValidationError as exc:
            errors.extend(exc.errors)
    try:
        specs = validate_specs(specs)
    except ValidationError as exc:
        errors.extend(exc.errors)
    if errors:
        raise ValidationError(f"{len(errors)} matcher spec error(s) in {folder.as_posix()}", errors)
    return specs


def validate_specs(specs: Iterable[MatcherSpec]) -> list[MatcherSpec]:
    """Return ``specs`` sorted by slug. Raise :class:`ValidationError` on duplicate slugs."""
    seen: dict[str, MatcherSpec] = {}
    errors: list[str] = []
    for spec in specs:
        first = seen.get(spec.slug)
        if first is not None:
            errors.append(
                f"{spec.origin or '<spec>'}: duplicate matcher slug {spec.slug} "
                f"(also in {first.origin or '<spec>'})"
            )
            continue
        seen[spec.slug] = spec
    if errors:
        raise ValidationError(f"{len(errors)} duplicate matcher slug(s)", errors)
    return sorted(seen.values(), key=lambda item: item.slug)


def default_rules_dir() -> Path:
    """Return the ``rules/matchers`` folder (:func:`kalkan.resources.rules_dir`)."""
    from kalkan.resources import rules_dir

    return rules_dir("matchers")


def example_matches(spec: MatcherSpec, example: str) -> bool:
    """Return True when a pattern regex of ``spec`` matches a line of ``example``.

    Only the pattern regexes count. Gates, conditions and path filters do not apply. For a
    file matcher the example is a path that a name glob matches, or ``hex:<bytes>`` that
    starts with a signature.
    """
    if spec.is_file_matcher:
        return file_example_matches(spec.file_signatures, spec.name_patterns, example)
    compiled = [compile_regex(item.regex, item.flags) for item in spec.patterns]
    return _any_line_matches(compiled, example)


def file_example_matches(
    signatures: Iterable[Signature], names: Iterable[NamePattern], example: str
) -> bool:
    """Return True when a file matcher example matches (see :func:`example_matches`)."""
    if example.startswith(HEX_EXAMPLE_PREFIX):
        try:
            data = bytes.fromhex(example[len(HEX_EXAMPLE_PREFIX) :])
        except ValueError:
            return False
        return any(data.startswith(item.prefix) for item in signatures)
    globs = [item.glob for item in names]
    return bool(globs) and GlobSet(globs).matches(example.lower())


def _any_line_matches(compiled: Iterable[re.Pattern[str]], text: str) -> bool:
    regexes = list(compiled)
    for raw in text.split("\n"):
        line = raw[:-1] if raw.endswith("\r") else raw
        if len(line) > MAX_LINE_LENGTH:
            continue
        if any(regex.search(line) for regex in regexes):
            return True
    return False


class _Checker:
    """Collects validation errors with JSON-path prefixes."""

    def __init__(self, origin: str) -> None:
        self.origin = origin
        self.errors: list[str] = []

    def error(self, where: str, message: str) -> None:
        self.errors.append(f"{self.origin}: {where}: {message}")

    def spec(self, data: object) -> MatcherSpec | None:
        if not isinstance(data, Mapping):
            self.error("$", "must be a JSON object")
            return None
        for key in sorted(set(data) - _TOP_KEYS):
            self.error(key, "unknown key")
        for key in _REQUIRED_KEYS:
            if key not in data:
                self.error(key, "is required")
        if self.errors:
            return None
        version = data["version"]
        if version != SPEC_VERSION or isinstance(version, bool):
            self.error("version", f"must be {SPEC_VERSION}")
        slug = self.text(data["slug"], "slug", MAX_SLUG_LENGTH)
        if slug and not _SLUG.fullmatch(slug):
            self.error("slug", "must be a lowercase kebab-case slug")
        description = self.text(data["description"], "description", MAX_DESCRIPTION_LENGTH)
        vuln_class = data["class"]
        if vuln_class is not None and not (
            isinstance(vuln_class, str) and vuln_class in CLASS_SLUGS
        ):
            self.error("class", f"must be a taxonomy class slug or null, got {vuln_class!r}")
        cwe = self.cwe(data["cwe"])
        noise_tier = data["noise_tier"]
        if noise_tier not in NOISE_TIERS:
            self.error("noise_tier", f"must be one of {', '.join(NOISE_TIERS)}")
        signatures = self.signatures(data.get("file_signatures", []))
        names = self.name_patterns(data.get("name_patterns", []))
        file_matcher = bool(signatures or names)
        file_patterns = self.globs(
            data["file_patterns"], "file_patterns", minimum=1, allow_broad=bool(signatures)
        )
        exclude = self.globs(data.get("exclude_file_patterns", []), "exclude_file_patterns")
        requires = self.requires(data.get("requires", {}))
        file_contains = self.regexes(data.get("file_contains", []), "file_contains")
        file_excludes = self.regexes(data.get("file_excludes", []), "file_excludes")
        patterns = self.patterns(data["patterns"], file_matcher=file_matcher)
        if file_matcher and (file_contains or file_excludes):
            self.error("file_contains", "a file matcher has no line gates")
        examples = self.examples(data["examples"])
        source = self.source(data.get("source"))
        notes = data.get("notes", "")
        if not isinstance(notes, str) or len(notes) > MAX_NOTES_LENGTH:
            self.error("notes", f"must be a string of at most {MAX_NOTES_LENGTH} characters")
        if self.errors:
            return None
        spec = MatcherSpec(
            slug=slug,
            description=description,
            vuln_class=vuln_class,
            cwe=cwe,
            noise_tier=noise_tier,
            file_patterns=file_patterns,
            exclude_file_patterns=exclude,
            requires=requires,
            file_contains=file_contains,
            file_excludes=file_excludes,
            patterns=patterns,
            examples=examples,
            source=source,
            notes=notes,
            origin=self.origin,
            file_signatures=signatures,
            name_patterns=names,
        )
        if file_matcher:
            for index, example in enumerate(examples):
                if not file_example_matches(signatures, names, example):
                    self.error(
                        f"examples[{index}]",
                        "must be a path that a name pattern matches or hex: bytes that start "
                        "with a signature",
                    )
            return spec
        compiled = [compile_regex(item.regex, item.flags) for item in patterns]
        for index, example in enumerate(examples):
            if not _any_line_matches(compiled, example):
                self.error(f"examples[{index}]", "must be matched by at least one pattern")
        return spec

    def text(self, value: object, where: str, maximum: int) -> str:
        if not isinstance(value, str) or not value.strip():
            self.error(where, "must be a non-empty string")
            return ""
        if value != value.strip():
            self.error(where, "must not start or end with whitespace")
        if len(value) > maximum:
            self.error(where, f"must be at most {maximum} characters")
        return value

    def string_list(self, value: object, where: str, maximum: int, minimum: int = 0) -> list[str]:
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            self.error(where, "must be a list of strings")
            return []
        if len(value) < minimum:
            self.error(where, f"must have at least {minimum} item(s)")
        if len(value) > maximum:
            self.error(where, f"must have at most {maximum} items")
        if len(set(value)) != len(value):
            self.error(where, "must not contain duplicates")
        return list(value)

    def cwe(self, value: object) -> tuple[str, ...]:
        items = self.string_list(value, "cwe", MAX_CWE)
        for index, item in enumerate(items):
            if not _CWE.fullmatch(item):
                self.error(f"cwe[{index}]", "must match CWE-<number>")
        return tuple(items)

    def globs(
        self, value: object, where: str, minimum: int = 0, *, allow_broad: bool = False
    ) -> tuple[str, ...]:
        items = self.string_list(value, where, MAX_GLOBS, minimum)
        for index, item in enumerate(items):
            error = glob_safety_error(item, allow_broad=allow_broad)
            if error:
                self.error(f"{where}[{index}]", f"{item!r} {error}")
        return tuple(items)

    def signatures(self, value: object) -> tuple[Signature, ...]:
        items = self.objects(value, "file_signatures", MAX_PATTERNS, _SIGNATURE_KEYS)
        result: list[Signature] = []
        for index, item in items:
            where = f"file_signatures[{index}]"
            hex_text = item.get("hex")
            if not isinstance(hex_text, str) or not _HEX.fullmatch(hex_text):
                self.error(f"{where}.hex", "must be 2 to 16 bytes as lower-case hex")
                continue
            label = self.text(item.get("label"), f"{where}.label", MAX_LABEL_LENGTH)
            if any(known.hex == hex_text for known in result):
                self.error(f"{where}.hex", "must not repeat a signature")
            result.append(Signature(hex_text, label))
        return tuple(result)

    def name_patterns(self, value: object) -> tuple[NamePattern, ...]:
        items = self.objects(value, "name_patterns", MAX_GLOBS, _NAME_PATTERN_KEYS)
        result: list[NamePattern] = []
        for index, item in items:
            where = f"name_patterns[{index}]"
            glob = item.get("glob")
            error = glob_safety_error(glob)
            if error or not isinstance(glob, str):
                self.error(f"{where}.glob", f"{glob!r} {error}")
                continue
            if glob != glob.lower():
                self.error(f"{where}.glob", "must be lower case (it is compared without case)")
            label = self.text(item.get("label"), f"{where}.label", MAX_LABEL_LENGTH)
            result.append(NamePattern(glob, label))
        return tuple(result)

    def objects(
        self, value: object, where: str, maximum: int, keys: frozenset[str]
    ) -> list[tuple[int, Mapping[str, Any]]]:
        if not isinstance(value, list):
            self.error(where, "must be a list")
            return []
        if len(value) > maximum:
            self.error(where, f"must have at most {maximum} items")
        found = []
        for index, item in enumerate(value):
            if not isinstance(item, Mapping):
                self.error(f"{where}[{index}]", "must be an object")
                continue
            for key in sorted(set(item) - keys):
                self.error(f"{where}[{index}].{key}", "unknown key")
            found.append((index, item))
        return found

    def regexes(self, value: object, where: str) -> tuple[str, ...]:
        items = self.string_list(value, where, MAX_REGEX_LIST)
        for index, item in enumerate(items):
            error = regex_safety_error(item)
            if error:
                self.error(f"{where}[{index}]", f"{item!r} {error}")
        return tuple(items)

    def requires(self, value: object) -> Requires:
        if not isinstance(value, Mapping):
            self.error("requires", "must be an object")
            return Requires()
        for key in sorted(set(value) - _REQUIRES_KEYS):
            self.error(f"requires.{key}", "unknown key")
        tech = self.string_list(value.get("tech", []), "requires.tech", MAX_TECH)
        for index, item in enumerate(tech):
            if len(item) > MAX_TECH_LENGTH or not _TECH.fullmatch(item):
                self.error(f"requires.tech[{index}]", "must be a lowercase technology tag")
        sentinel_files = self.globs(value.get("sentinel_files", []), "requires.sentinel_files")
        sentinel_contains = self.regexes(
            value.get("sentinel_contains", []), "requires.sentinel_contains"
        )
        if sentinel_contains and not sentinel_files:
            self.error("requires.sentinel_contains", "needs requires.sentinel_files")
        return Requires(tuple(tech), sentinel_files, sentinel_contains)

    def patterns(self, value: object, *, file_matcher: bool = False) -> tuple[Pattern, ...]:
        if file_matcher:
            if value != []:
                self.error("patterns", "must be an empty list for a file matcher")
            return ()
        if not isinstance(value, list) or not value:
            self.error("patterns", "must be a non-empty list")
            return ()
        if len(value) > MAX_PATTERNS:
            self.error("patterns", f"must have at most {MAX_PATTERNS} items")
        result = []
        for index, item in enumerate(value):
            pattern = self.pattern(item, f"patterns[{index}]")
            if pattern is not None:
                result.append(pattern)
        return tuple(result)

    def pattern(self, value: object, where: str) -> Pattern | None:
        if not isinstance(value, Mapping):
            self.error(where, "must be an object")
            return None
        for key in sorted(set(value) - _PATTERN_KEYS):
            self.error(f"{where}.{key}", "unknown key")
        regex, flags = self.regex_and_flags(value, where)
        label = self.text(value.get("label"), f"{where}.label", MAX_LABEL_LENGTH)
        near = self.conditions(value.get("near", []), f"{where}.near")
        not_near = self.conditions(value.get("not_near", []), f"{where}.not_near")
        paths = self.globs(value.get("paths", []), f"{where}.paths")
        if regex is None:
            return None
        return Pattern(regex, flags, label, near, not_near, paths)

    def regex_and_flags(self, value: Mapping[str, Any], where: str) -> tuple[str | None, str]:
        regex = value.get("regex")
        flags = value.get("flags", "")
        error = flags_error(flags)
        if error:
            self.error(f"{where}.flags", error)
            return None, ""
        error = regex_safety_error(regex, flags)
        if error or not isinstance(regex, str):
            self.error(f"{where}.regex", f"{regex!r} {error}")
            return None, flags
        return regex, flags

    def conditions(self, value: object, where: str) -> tuple[Condition, ...]:
        if not isinstance(value, list):
            self.error(where, "must be a list")
            return ()
        if len(value) > MAX_CONDITIONS:
            self.error(where, f"must have at most {MAX_CONDITIONS} items")
        result = []
        for index, item in enumerate(value):
            here = f"{where}[{index}]"
            if not isinstance(item, Mapping):
                self.error(here, "must be an object")
                continue
            for key in sorted(set(item) - _CONDITION_KEYS):
                self.error(f"{here}.{key}", "unknown key")
            regex, flags = self.regex_and_flags(item, here)
            scope = item.get("scope", "lines")
            if scope not in CONDITION_SCOPES:
                self.error(f"{here}.scope", 'must be "lines", "file" or "document"')
            whole_file = scope == "file"
            document = scope == "document"
            window = []
            for key in ("before", "after"):
                number = item.get(key, 0)
                if (whole_file or document) and key in item:
                    self.error(f"{here}.{key}", f'is not allowed with scope "{scope}"')
                if isinstance(number, bool) or not isinstance(number, int):
                    self.error(f"{here}.{key}", "must be an integer")
                    number = 0
                elif not 0 <= number <= MAX_WINDOW:
                    self.error(f"{here}.{key}", f"must be between 0 and {MAX_WINDOW}")
                window.append(number)
            if regex is not None:
                result.append(Condition(regex, flags, window[0], window[1], whole_file, document))
        return tuple(result)

    def examples(self, value: object) -> tuple[str, ...]:
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            self.error("examples", "must be a list of strings")
            return ()
        if not 1 <= len(value) <= MAX_EXAMPLES:
            self.error("examples", f"must have between 1 and {MAX_EXAMPLES} items")
        for index, item in enumerate(value):
            if not item or len(item) > MAX_EXAMPLE_LENGTH:
                self.error(
                    f"examples[{index}]",
                    f"must have between 1 and {MAX_EXAMPLE_LENGTH} characters",
                )
        return tuple(value)

    def source(self, value: object) -> Source | None:
        if value is None:
            return None
        if not isinstance(value, Mapping):
            self.error("source", "must be an object or null")
            return None
        for key in sorted(set(value) - _SOURCE_KEYS):
            self.error(f"source.{key}", "unknown key")
        parts = []
        for key in ("repo", "commit", "path"):
            item = value.get(key)
            if not isinstance(item, str) or not item.strip():
                self.error(f"source.{key}", "must be a non-empty string")
                item = ""
            parts.append(item)
        return Source(*parts)
