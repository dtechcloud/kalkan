# SPDX-License-Identifier: MIT
# Ported from cloudflare/security-audit-skill@c1c8a8c: skills/security-audit/validate-coverage-ledger.cjs  # noqa: E501
# Copyright (c) 2025-2026 Cloudflare, Inc. Changes: translated from JavaScript to Python; the input
# is read through kalkan.util.safe_io, so the validator also runs on Windows; the command-line
# runner became validate_ledger_file.
"""Validate a coverage ledger (port of the Cloudflare coverage-ledger validator).

A coverage ledger (``coverage-ledger.json``) is a JSON array of coverage units. Each unit names
one combination of entry surface, trust boundary, subsystem and attack class, and records who
reviewed it and with which evidence. :func:`validate_ledger` checks:

- the 19 required fields, visible text and safe repository-relative paths;
- ``canonical_refs`` (NFC, visible, no control or format characters, at most 1024 UTF-16 code
  units) and ``coverage_id``, which must equal :func:`canonical_coverage_id` of the references;
- unique coverage IDs, no two IDs for one semantic tuple, and lexicographic order;
- the status state table ("evidence" is ``reviewed_paths`` and ``local_checks``, "results" is
  ``result_fingerprints``):

  ==================================  ========  ==========  =========  ==========
  Status                              agent_id  evidence    results    unresolved
  ==================================  ========  ==========  =========  ==========
  planned                             null      empty       empty      empty
  not_applicable, out_of_scope,       null      empty       empty      non-empty
  deferred
  in_progress                         owner     empty       empty      empty
  blocked                             owner     non-empty   empty      non-empty
  covered                             owner     non-empty   empty      empty
  candidate                           owner     non-empty   non-empty  any
  ==================================  ========  ==========  =========  ==========

- checks: a source check has ``artifact: null``; a local check needs an artifact under
  ``agents/<check agent_id>/artifacts/``; the unit ``reviewed_paths`` equal the union of the
  check paths;
- archived ``attempts``: strictly increasing waves below the current wave, a fresh owner per
  attempt, and no reuse of an earlier owner's evidence or artifacts.

At most 100 errors are returned, with control characters escaped.
"""

from __future__ import annotations

import os
import re
import unicodedata
from dataclasses import dataclass
from typing import Final, NoReturn

from kalkan.errors import UnsafeInputError, ValidationError
from kalkan.schema.validator import JsonStructureError, parse_json_text
from kalkan.util.paths import WINDOWS_RESERVED_COMPONENT, is_safe_relative_path
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
    js_trim,
    safe_quote,
    utf16_key,
    utf16_length,
)

__all__ = [
    "ATTEMPT_FIELDS",
    "ATTEMPT_STATUSES",
    "LIMITS",
    "PATH_FORBIDDEN_CHARACTER",
    "PRIOR_STATUSES",
    "REF_FIELDS",
    "REQUIRED_FIELDS",
    "STATUSES",
    "UNSAFE_DIAGNOSTIC_CHARACTER",
    "VISIBLE_CONTENT",
    "WINDOWS_RESERVED_COMPONENT",
    "CanonicalRefError",
    "LedgerLimits",
    "canonical_coverage_id",
    "encode_canonical_ref",
    "has_visible_prose",
    "is_canonical_ref",
    "is_owned_artifact_path",
    "is_safe_agent_id",
    "is_safe_relative_path",
    "is_visible_text",
    "preflight_document",
    "preflight_json_text",
    "safe_quote",
    "validate_ledger",
    "validate_ledger_file",
]


@dataclass(frozen=True)
class LedgerLimits:
    """Bounds of the coverage-ledger validator (upstream ``LIMITS``). They apply to the JSON
    text before parsing and again to the parsed document."""

    input_bytes: int = 5 * 1024 * 1024
    units: int = 10000
    collection_items: int = 1000
    object_fields: int = 1000
    nesting_depth: int = 64
    preflight_values: int = 500000
    validation_errors: int = 100


LIMITS: Final = LedgerLimits()
MAX_TEXT_LENGTH: Final = 4096
MAX_REF_LENGTH: Final = 1024
MAX_COVERAGE_ID_LENGTH: Final = 65536
REQUIRED_FIELDS: Final = (
    "coverage_id",
    "canonical_refs",
    "surface",
    "boundary",
    "subsystem",
    "attack_class",
    "starting_paths",
    "ordinary_attack_class_block",
    "selected_companion_blocks",
    "excluded_blocks",
    "prior_status",
    "attempts",
    "wave",
    "status",
    "agent_id",
    "reviewed_paths",
    "local_checks",
    "result_fingerprints",
    "unresolved",
)
REF_FIELDS: Final = ("surface", "boundary", "subsystem", "attack_class")
STATUSES: Final = frozenset(
    {
        "planned",
        "not_applicable",
        "out_of_scope",
        "in_progress",
        "covered",
        "candidate",
        "blocked",
        "deferred",
    }
)
ATTEMPT_STATUSES: Final = frozenset({"covered", "candidate", "blocked"})
ATTEMPT_FIELDS: Final = (
    "wave",
    "status",
    "agent_id",
    "reviewed_paths",
    "local_checks",
    "result_fingerprints",
    "unresolved",
    "reassignment_reason",
)
PRIOR_STATUSES: Final = frozenset(
    {
        "new",
        "prior_confirmed_same_source",
        "prior_confirmed_changed_source",
        "prior_needs_validation",
        "prior_deferred",
        "prior_blocked",
        "prior_out_of_scope",
        "prior_covered_same_source",
        "prior_covered_changed_source",
        "prior_rejected_claim_changed",
        "none",
    }
)
CHECK_FIELDS: Final = ("agent_id", "reviewed_paths", "invariant", "method", "result", "artifact")
FINGERPRINT_PATTERN: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]*\Z")
AGENT_ID_PATTERN: Final = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}\Z")
WINDOWS_RESERVED_AGENT_ID: Final = re.compile(r"^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])\Z")
_UNRESERVED_BYTES: Final = frozenset(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)


class CanonicalRefError(ValidationError, ValueError):
    """A canonical reference or a ``canonical_refs`` object is not canonical."""

    def __init__(self, message: str) -> None:
        super().__init__(message, [message])


# ---------------------------------------------------------------------------------------------
# Text, references and identifiers


def is_visible_text(value: object, max_length: int = MAX_TEXT_LENGTH) -> bool:
    """Return True for a non-empty string of at most ``max_length`` UTF-16 code units, without
    surrounding whitespace, with valid scalar values and a visible character."""
    return (
        isinstance(value, str)
        and 0 < utf16_length(value) <= max_length
        and js_trim(value) == value
        and has_visible_prose(value)
    )


def is_canonical_ref(value: object) -> bool:
    """Return True for a canonical reference: visible text of at most 1024 UTF-16 code units in
    Unicode NFC, without control, format, separator or default-ignorable characters."""
    return (
        is_visible_text(value, MAX_REF_LENGTH)
        and PATH_FORBIDDEN_CHARACTER.search(value) is None
        and unicodedata.normalize("NFC", value) == value
    )


def encode_canonical_ref(value: object) -> str:
    """Percent-encode the UTF-8 bytes of a canonical reference (RFC 3986: only ``A-Z a-z 0-9
    - . _ ~`` stay as they are; every other byte becomes upper-case ``%HH``).

    Raises :class:`CanonicalRefError` for a value that :func:`is_canonical_ref` rejects.
    """
    if not is_canonical_ref(value):
        raise CanonicalRefError("invalid canonical reference")
    assert isinstance(value, str)
    return "".join(
        chr(byte) if byte in _UNRESERVED_BYTES else f"%{byte:02X}" for byte in value.encode("utf-8")
    )


def canonical_coverage_id(refs: object) -> str:
    """Return the coverage ID of ``canonical_refs``: the encoded ``surface``, ``boundary``,
    ``subsystem`` and ``attack_class`` references (and ``lifecycle`` when present), joined with
    ``::``.

    Raises :class:`CanonicalRefError` when ``refs`` is not an object, has missing or unexpected
    fields, or holds a reference that is not canonical.
    """
    if not isinstance(refs, dict):
        raise CanonicalRefError("canonical_refs must be an object")
    fields = (*REF_FIELDS, "lifecycle") if "lifecycle" in refs else REF_FIELDS
    if len(refs) != len(fields) or any(field not in refs for field in fields):
        raise CanonicalRefError("canonical_refs has missing or unexpected fields")
    return "::".join(encode_canonical_ref(refs[field]) for field in fields)


def is_safe_agent_id(value: object) -> bool:
    """Return True for a canonical lowercase agent ID that is not a Windows device name."""
    return (
        isinstance(value, str)
        and AGENT_ID_PATTERN.match(value) is not None
        and WINDOWS_RESERVED_AGENT_ID.match(value) is None
    )


def is_owned_artifact_path(value: object, agent_id: object) -> bool:
    """Return True when ``value`` is a safe path below ``agents/<agent_id>/artifacts/``."""
    if not is_safe_agent_id(agent_id) or not is_safe_relative_path(value):
        return False
    assert isinstance(value, str)
    prefix = f"agents/{agent_id}/artifacts/"
    return value.startswith(prefix) and len(value) > len(prefix)


# ---------------------------------------------------------------------------------------------
# Structural limits


# Matches the body of a JSON string: everything up to the closing quote, with escape pairs.
_STRING_BODY: Final = re.compile(r'[^"\\]*(?:\\.[^"\\]*)*', re.DOTALL)
# The rest of a scalar token (number, true, false, null) up to the next delimiter.
_TOKEN_TAIL: Final = re.compile(r'[^ \t\r\n,:\[\]{}"]*')


class _Container:
    __slots__ = ("count", "is_array", "state", "top_level")

    def __init__(self, is_array: bool, top_level: bool) -> None:
        self.is_array = is_array
        self.state = "firstValueOrEnd" if is_array else "firstKeyOrEnd"
        self.count = 0
        self.top_level = top_level


def _fail(message: str) -> NoReturn:
    raise JsonStructureError(f"input {message}")


def _match_end(pattern: re.Pattern[str], contents: str, index: int) -> int:
    match = pattern.match(contents, index)
    return index if match is None else match.end()


def preflight_json_text(contents: str) -> None:
    """Check the structure and the size of JSON text before ``json.loads`` runs (port of
    ``preflightJsonText``).

    Raises :class:`~kalkan.schema.validator.JsonStructureError` (message ``input ...``) for
    malformed or truncated structure, nesting deeper than 64, more than 10000 top-level units,
    more than 1000 items in a nested array, more than 1000 fields in an object, or more than
    500000 values in total.
    """
    limits = LIMITS
    containers: list[_Container] = []
    root_done = False
    total_values = 0

    def begin_value() -> None:
        nonlocal root_done, total_values
        if not containers:
            if root_done:
                _fail("has malformed JSON structure")
            root_done = True
        else:
            container = containers[-1]
            if container.is_array:
                if container.state != "firstValueOrEnd" and container.state != "value":
                    _fail("has malformed JSON array structure")
                container.count += 1
                limit = limits.units if container.top_level else limits.collection_items
                if container.count > limit:
                    if container.top_level:
                        _fail(f"exceeds {limit} top-level unit limit")
                    _fail(f"exceeds {limit} item array limit")
                container.state = "commaOrEnd"
            else:
                if container.state != "value":
                    _fail("has malformed JSON object structure")
                container.state = "commaOrEnd"
        total_values += 1
        if total_values > limits.preflight_values:
            _fail(f"exceeds {limits.preflight_values} total value limit")

    def begin_string() -> None:
        container = containers[-1] if containers else None
        if (
            container is not None
            and not container.is_array
            and container.state in ("firstKeyOrEnd", "key")
        ):
            container.count += 1
            if container.count > limits.object_fields:
                _fail(f"exceeds {limits.object_fields} field object limit")
            container.state = "colon"
        else:
            begin_value()

    def begin_container(is_array: bool) -> None:
        begin_value()
        if len(containers) >= limits.nesting_depth:
            _fail(f"exceeds nesting depth limit {limits.nesting_depth}")
        containers.append(_Container(is_array, top_level=not containers))

    def close_container(is_array: bool) -> None:
        container = containers[-1] if containers else None
        if container is None or container.is_array != is_array:
            _fail("has mismatched JSON containers")
        first = "firstValueOrEnd" if is_array else "firstKeyOrEnd"
        if container.state != first and container.state != "commaOrEnd":
            _fail(f"has malformed JSON {'array' if is_array else 'object'} structure")
        containers.pop()

    index = 0
    length = len(contents)
    while index < length:
        character = contents[index]
        if character in " \t\r\n":
            index += 1
            continue
        if character == '"':
            begin_string()
            end = _match_end(_STRING_BODY, contents, index + 1)
            if end >= length or contents[end] != '"':
                _fail("has an unterminated JSON string")
            index = end + 1
            continue
        if character == "[":
            begin_container(True)
        elif character == "{":
            begin_container(False)
        elif character == "]":
            close_container(True)
        elif character == "}":
            close_container(False)
        elif character == ":":
            container = containers[-1] if containers else None
            if container is None or container.is_array or container.state != "colon":
                _fail("has malformed JSON object structure")
            container.state = "value"
        elif character == ",":
            container = containers[-1] if containers else None
            if container is None or container.state != "commaOrEnd":
                _fail("has malformed JSON collection structure")
            container.state = "value" if container.is_array else "key"
        else:
            begin_value()
            index = _match_end(_TOKEN_TAIL, contents, index + 1)
            continue
        index += 1

    if containers:
        _fail("has truncated JSON structure")
    if not root_done:
        _fail("has no JSON value")


# A location is rendered only when a message needs it: (parent, index, is_object_field) or "$".
_Location = object


def _render_location(location: _Location) -> str:
    parts: list[str] = []
    while not isinstance(location, str):
        location, index, is_object_field = location
        parts.append(f"{{{index}}}" if is_object_field else f"[{index}]")
    return location + "".join(reversed(parts))


def preflight_document(root: object) -> list[str]:
    """Return one error when a parsed ledger nests 64 or more levels, has an array over its
    limit (10000 units at the top, 1000 below), an object with over 1000 fields, or over 500000
    values in total (port of ``preflightDocument``). The traversal is iterative."""
    limits = LIMITS
    errors = ErrorList(limits.validation_errors)
    stack: list[tuple[object, int, _Location]] = [(root, 0, "$")]
    visited = 0
    while stack:
        value, depth, location = stack.pop()
        visited += 1
        if visited > limits.preflight_values:
            errors.push(f"$: exceeds {limits.preflight_values} total values")
            return list(errors)
        if not isinstance(value, dict | list):
            continue
        if depth >= limits.nesting_depth:
            where = _render_location(location)
            errors.push(f"{where}: exceeds nesting depth limit {limits.nesting_depth}")
            return list(errors)
        if isinstance(value, list):
            limit = limits.units if location == "$" else limits.collection_items
            if len(value) > limit:
                errors.push(f"{_render_location(location)}: exceeds {limit} entries")
                return list(errors)
            for index in range(len(value) - 1, -1, -1):
                stack.append((value[index], depth + 1, (location, index, False)))
            continue
        keys = list(value)
        if len(keys) > limits.object_fields:
            where = _render_location(location)
            errors.push(f"{where}: exceeds {limits.object_fields} object fields")
            return list(errors)
        for index in range(len(keys) - 1, -1, -1):
            stack.append((value[keys[index]], depth + 1, (location, index, True)))
    return list(errors)


# ---------------------------------------------------------------------------------------------
# Unit checks


def _same_value_key(value: object) -> object:
    """A hashable key with the JavaScript ``Set`` equality (SameValueZero) for JSON values."""
    if isinstance(value, str):
        return ("string", value)
    if isinstance(value, bool):
        return ("boolean", value)
    if isinstance(value, int | float):
        return ("number", value)
    if value is None:
        return ("null",)
    if value is UNDEFINED:
        return ("undefined",)
    return ("object", id(value))


def _validate_string_array(
    value: object,
    location: str,
    errors: ErrorList,
    *,
    allow_empty: bool = True,
    fingerprint: bool = False,
    path_value: bool = False,
) -> None:
    if not isinstance(value, list):
        errors.push(f"{location}: expected array")
        return
    limit = LIMITS.collection_items
    if not allow_empty and not value:
        errors.push(f"{location}: must not be empty")
    if len(value) > limit:
        errors.push(f"{location}: exceeds {limit} entries")
    kind = "repository-relative path" if path_value else "text"
    seen: set[str] = set()
    for index, entry in enumerate(value[:limit]):
        if errors.full:
            return
        entry_location = f"{location}[{index}]"
        valid = is_safe_relative_path(entry) if path_value else is_visible_text(entry)
        if not valid:
            errors.push(f"{entry_location}: invalid {kind}")
        if isinstance(entry, str):
            if fingerprint and FINGERPRINT_PATTERN.match(entry) is None:
                errors.push(f"{entry_location}: invalid fingerprint")
            if entry in seen:
                errors.push(f"{entry_location}: duplicate entry")
            seen.add(entry)


def _validate_checks(value: object, location: str, errors: ErrorList) -> None:
    if not isinstance(value, list):
        errors.push(f"{location}: expected array")
        return
    limit = LIMITS.collection_items
    if len(value) > limit:
        errors.push(f"{location}: exceeds {limit} entries")
    for index, check in enumerate(value[:limit]):
        if errors.full:
            return
        base = f"{location}[{index}]"
        if not isinstance(check, dict):
            errors.push(f"{base}: expected object")
            continue
        for field in CHECK_FIELDS:
            if field not in check:
                errors.push(f"{base}: missing required field {safe_quote(field)}")
        agent_id = check.get("agent_id", UNDEFINED)
        if not is_safe_agent_id(agent_id):
            errors.push(f"{base}.agent_id: expected a canonical lowercase agent ID")
        _validate_string_array(
            check.get("reviewed_paths", UNDEFINED),
            f"{base}.reviewed_paths",
            errors,
            allow_empty=False,
            path_value=True,
        )
        if not is_visible_text(check.get("invariant", UNDEFINED)):
            errors.push(f"{base}.invariant: invalid text")
        method = check.get("method", UNDEFINED)
        if method != "source" and method != "local":
            errors.push(f'{base}.method: expected "source" or "local"')
        if not is_visible_text(check.get("result", UNDEFINED)):
            errors.push(f"{base}.result: invalid text")
        artifact = check.get("artifact", UNDEFINED)
        if method == "source" and artifact is not None:
            errors.push(f"{base}.artifact: source-only check must use null")
        elif method == "local":
            if not is_owned_artifact_path(artifact, agent_id):
                owner = agent_id if is_safe_agent_id(agent_id) else "<agent-id>"
                errors.push(
                    f"{base}.artifact: local check requires an artifact owned by agent "
                    f"{safe_quote(owner)}"
                )
        elif method != "source" and artifact is not None and not is_safe_relative_path(artifact):
            errors.push(f"{base}.artifact: expected null or a safe output-relative path")


def _validate_reviewed_path_ownership(unit: dict, base: str, errors: ErrorList) -> None:
    reviewed = unit.get("reviewed_paths")
    checks = unit.get("local_checks")
    if not isinstance(reviewed, list) or not isinstance(checks, list):
        return
    aggregate = dict.fromkeys(path for path in reviewed if isinstance(path, str))
    owned: dict[str, None] = {}
    for check in checks:
        paths = check.get("reviewed_paths") if isinstance(check, dict) else None
        if not isinstance(paths, list):
            continue
        for path in paths:
            if isinstance(path, str):
                owned.setdefault(path, None)
    for path in aggregate:
        if path not in owned:
            errors.push(f"{base}.reviewed_paths: {safe_quote(path)} has no check owner")
    for path in owned:
        if path not in aggregate:
            errors.push(
                f"{base}.local_checks: owned path {safe_quote(path)} "
                "is absent from aggregate reviewed_paths"
            )


def _validate_excluded_blocks(value: object, location: str, errors: ErrorList) -> None:
    if not isinstance(value, list):
        errors.push(f"{location}: expected array")
        return
    limit = LIMITS.collection_items
    if len(value) > limit:
        errors.push(f"{location}: exceeds {limit} entries")
    seen: set[str] = set()
    for index, entry in enumerate(value[:limit]):
        if errors.full:
            return
        base = f"{location}[{index}]"
        if not isinstance(entry, dict):
            errors.push(f"{base}: expected object")
            continue
        block = entry.get("block", UNDEFINED)
        if not is_visible_text(block):
            errors.push(f"{base}.block: invalid text")
        if not is_visible_text(entry.get("reason", UNDEFINED)):
            errors.push(f"{base}.reason: invalid text")
        if isinstance(block, str):
            if block in seen:
                errors.push(f"{base}.block: duplicate entry")
            seen.add(block)


def _semantic_key(unit: dict) -> tuple[object, ...]:
    lifecycle = unit["lifecycle"] if "lifecycle" in unit else None
    return (unit["surface"], unit["boundary"], unit["subsystem"], unit["attack_class"], lifecycle)


def _has_valid_semantic_fields(unit: dict) -> bool:
    return all(is_visible_text(unit.get(field, UNDEFINED)) for field in REF_FIELDS) and (
        "lifecycle" not in unit or is_visible_text(unit["lifecycle"])
    )


def _require_empty_array(unit: dict, field: str, base: str, errors: ErrorList) -> None:
    value = unit.get(field)
    if isinstance(value, list) and value:
        status = safe_quote(unit.get("status", UNDEFINED))
        errors.push(f"{base}.{field}: unit with status {status} must keep this array empty")


def _require_nonempty_array(unit: dict, field: str, base: str, errors: ErrorList) -> None:
    value = unit.get(field)
    if not isinstance(value, list) or not value:
        status = safe_quote(unit.get("status", UNDEFINED))
        errors.push(f"{base}.{field}: unit with status {status} requires entries")


def _validate_state_invariants(unit: dict, base: str, errors: ErrorList) -> None:
    status = unit.get("status", UNDEFINED)
    agent_id = unit.get("agent_id", UNDEFINED)

    def empty_evidence() -> None:
        _require_empty_array(unit, "reviewed_paths", base, errors)
        _require_empty_array(unit, "local_checks", base, errors)

    def require_owner() -> None:
        if not is_safe_agent_id(agent_id):
            errors.push(
                f"{base}.agent_id: unit with status {safe_quote(status)} "
                "requires a canonical lowercase agent ID"
            )

    if status != "candidate":
        _require_empty_array(unit, "result_fingerprints", base, errors)

    if status == "planned":
        if agent_id is not None:
            errors.push(f"{base}.agent_id: planned unit must be unassigned")
        empty_evidence()
        _require_empty_array(unit, "unresolved", base, errors)
    elif status in ("not_applicable", "out_of_scope", "deferred"):
        if agent_id is not None:
            errors.push(
                f"{base}.agent_id: unit with status {safe_quote(status)} must be unassigned"
            )
        empty_evidence()
        _require_nonempty_array(unit, "unresolved", base, errors)
    elif status == "in_progress":
        require_owner()
        empty_evidence()
        _require_empty_array(unit, "unresolved", base, errors)
    elif status == "blocked":
        require_owner()
        _require_nonempty_array(unit, "reviewed_paths", base, errors)
        _require_nonempty_array(unit, "local_checks", base, errors)
        _require_nonempty_array(unit, "unresolved", base, errors)
    elif status == "covered":
        require_owner()
        _require_nonempty_array(unit, "reviewed_paths", base, errors)
        _require_nonempty_array(unit, "local_checks", base, errors)
        _require_empty_array(unit, "unresolved", base, errors)
    elif status == "candidate":
        require_owner()
        _require_nonempty_array(unit, "reviewed_paths", base, errors)
        _require_nonempty_array(unit, "local_checks", base, errors)
        _require_nonempty_array(unit, "result_fingerprints", base, errors)


def _validate_attempts(value: object, unit: dict, base: str, errors: ErrorList) -> None:
    if not isinstance(value, list):
        errors.push(f"{base}.attempts: expected array")
        return
    limit = LIMITS.collection_items
    if len(value) > limit:
        errors.push(f"{base}.attempts: exceeds {limit} entries")

    unit_wave = unit.get("wave", UNDEFINED)
    prior_owners: set[str] = set()
    prior_artifacts: set[str] = set()
    previous_wave = 0
    for index, attempt in enumerate(value[:limit]):
        attempt_base = f"{base}.attempts[{index}]"
        if not isinstance(attempt, dict):
            errors.push(f"{attempt_base}: expected object")
            continue
        for field in ATTEMPT_FIELDS:
            if field not in attempt:
                errors.push(f"{attempt_base}: missing required field {safe_quote(field)}")
        wave = attempt.get("wave", UNDEFINED)
        if not is_js_integer(wave) or wave < 1:
            errors.push(f"{attempt_base}.wave: expected a positive integer")
        else:
            if wave <= previous_wave:
                errors.push(
                    f"{attempt_base}.wave: archived attempt waves must be strictly increasing"
                )
            if is_js_integer(unit_wave) and wave >= unit_wave:
                errors.push(
                    f"{attempt_base}.wave: archived attempt wave must precede current wave "
                    f"{safe_quote(unit_wave)}"
                )
            previous_wave = wave
        status = attempt.get("status", UNDEFINED)
        if not (isinstance(status, str) and status in ATTEMPT_STATUSES):
            errors.push(f'{attempt_base}.status: expected "covered", "candidate", or "blocked"')
        agent_id = attempt.get("agent_id", UNDEFINED)
        fresh_owner = False
        if not is_safe_agent_id(agent_id):
            errors.push(
                f"{attempt_base}.agent_id: archived attempt requires a canonical lowercase agent ID"
            )
        elif agent_id in prior_owners:
            errors.push(f"{attempt_base}.agent_id: assignment owner must be fresh for each attempt")
        else:
            fresh_owner = True
        _validate_string_array(
            attempt.get("reviewed_paths", UNDEFINED),
            f"{attempt_base}.reviewed_paths",
            errors,
            path_value=True,
        )
        _validate_checks(
            attempt.get("local_checks", UNDEFINED), f"{attempt_base}.local_checks", errors
        )
        _validate_reviewed_path_ownership(attempt, attempt_base, errors)
        _validate_string_array(
            attempt.get("result_fingerprints", UNDEFINED),
            f"{attempt_base}.result_fingerprints",
            errors,
            fingerprint=True,
        )
        _validate_string_array(
            attempt.get("unresolved", UNDEFINED), f"{attempt_base}.unresolved", errors
        )
        if not is_visible_text(attempt.get("reassignment_reason", UNDEFINED)):
            errors.push(f"{attempt_base}.reassignment_reason: invalid text")
        _validate_state_invariants(attempt, attempt_base, errors)

        checks = attempt.get("local_checks")
        if isinstance(checks, list):
            for check_index, check in enumerate(checks):
                if not isinstance(check, dict):
                    continue
                where = f"{attempt_base}.local_checks[{check_index}]"
                check_agent = check.get("agent_id", UNDEFINED)
                if isinstance(check_agent, str) and check_agent in prior_owners:
                    errors.push(
                        f"{where}.agent_id: prior assignment owner evidence must remain in its "
                        "earlier attempt"
                    )
                artifact = check.get("artifact", UNDEFINED)
                if isinstance(artifact, str) and artifact in prior_artifacts:
                    errors.push(
                        f"{where}.artifact: artifact from an earlier attempt cannot be reused"
                    )
                if check.get("method") == "local" and isinstance(artifact, str):
                    prior_artifacts.add(artifact)
        if fresh_owner:
            prior_owners.add(agent_id)

    unit_agent = unit.get("agent_id", UNDEFINED)
    if is_safe_agent_id(unit_agent) and unit_agent in prior_owners:
        errors.push(f"{base}.agent_id: current assignment owner must be fresh after reassignment")
    unit_checks = unit.get("local_checks")
    if isinstance(unit_checks, list):
        for index, check in enumerate(unit_checks):
            if not isinstance(check, dict):
                continue
            check_agent = check.get("agent_id", UNDEFINED)
            if isinstance(check_agent, str) and check_agent in prior_owners:
                errors.push(
                    f"{base}.local_checks[{index}].agent_id: prior assignment owner evidence "
                    "must remain in its archived attempt"
                )
            artifact = check.get("artifact", UNDEFINED)
            if isinstance(artifact, str) and artifact in prior_artifacts:
                errors.push(
                    f"{base}.local_checks[{index}].artifact: artifact from an archived attempt "
                    "cannot be reused"
                )


def _validate_canonical_refs(unit: dict, base: str, errors: ErrorList) -> str | None:
    refs = unit.get("canonical_refs", UNDEFINED)
    if not isinstance(refs, dict):
        errors.push(f"{base}.canonical_refs: expected object")
        return None
    expected_fields = (*REF_FIELDS, "lifecycle") if "lifecycle" in refs else REF_FIELDS
    for field in expected_fields:
        if field not in refs:
            errors.push(f"{base}.canonical_refs: missing required field {safe_quote(field)}")
        elif not is_canonical_ref(refs[field]):
            errors.push(f"{base}.canonical_refs.{field}: invalid canonical reference")
    if any(field not in expected_fields for field in refs):
        errors.push(f"{base}.canonical_refs: contains unexpected fields")
    if ("lifecycle" in unit) != ("lifecycle" in refs):
        errors.push(f"{base}: lifecycle and canonical_refs.lifecycle must appear together")
    try:
        return canonical_coverage_id(refs)
    except CanonicalRefError:
        return None  # the specific reference errors above are more useful


def _collect_unit_errors(unit: object, index: int) -> list[str]:
    base = f"$[{index}]"
    if not isinstance(unit, dict):
        return [f"{base}: expected object"]
    errors = ErrorList(LIMITS.validation_errors)

    for field in REQUIRED_FIELDS:
        if field not in unit:
            errors.push(f"{base}: missing required field {safe_quote(field)}")
    for field in REF_FIELDS:
        if not is_visible_text(unit.get(field, UNDEFINED)):
            errors.push(f"{base}.{field}: invalid text")
    if "lifecycle" in unit and not is_visible_text(unit["lifecycle"]):
        errors.push(f"{base}.lifecycle: invalid text")

    expected_id = _validate_canonical_refs(unit, base, errors)
    coverage_id = unit.get("coverage_id", UNDEFINED)
    if not is_visible_text(coverage_id, MAX_COVERAGE_ID_LENGTH):
        errors.push(f"{base}.coverage_id: invalid text")
    elif expected_id is not None and coverage_id != expected_id:
        errors.push(f"{base}.coverage_id: expected canonical ID {safe_quote(expected_id)}")

    _validate_string_array(
        unit.get("starting_paths", UNDEFINED),
        f"{base}.starting_paths",
        errors,
        allow_empty=False,
        path_value=True,
    )
    block = unit.get("ordinary_attack_class_block", UNDEFINED)
    if block is not None and not is_visible_text(block):
        errors.push(f"{base}.ordinary_attack_class_block: expected null or non-empty text")
    selected = unit.get("selected_companion_blocks", UNDEFINED)
    excluded = unit.get("excluded_blocks", UNDEFINED)
    _validate_string_array(selected, f"{base}.selected_companion_blocks", errors)
    _validate_excluded_blocks(excluded, f"{base}.excluded_blocks", errors)
    if isinstance(selected, list) and isinstance(excluded, list):
        selected_keys = {_same_value_key(entry) for entry in selected}
        for block_index, entry in enumerate(excluded):
            if isinstance(entry, dict) and (
                _same_value_key(entry.get("block", UNDEFINED)) in selected_keys
            ):
                errors.push(f"{base}.excluded_blocks[{block_index}].block: block is also selected")

    prior_status = unit.get("prior_status", UNDEFINED)
    if not (isinstance(prior_status, str) and prior_status in PRIOR_STATUSES):
        errors.push(f"{base}.prior_status: invalid value {safe_quote(prior_status)}")
    status = unit.get("status", UNDEFINED)
    if not (isinstance(status, str) and status in STATUSES):
        errors.push(f"{base}.status: invalid value {safe_quote(status)}")
    wave = unit.get("wave", UNDEFINED)
    if not is_js_integer(wave) or wave < 1:
        errors.push(f"{base}.wave: expected a positive integer")
    agent_id = unit.get("agent_id", UNDEFINED)
    if agent_id is not None and not is_safe_agent_id(agent_id):
        errors.push(f"{base}.agent_id: expected null or a safe agent ID")

    _validate_attempts(unit.get("attempts", UNDEFINED), unit, base, errors)
    _validate_string_array(
        unit.get("reviewed_paths", UNDEFINED), f"{base}.reviewed_paths", errors, path_value=True
    )
    _validate_checks(unit.get("local_checks", UNDEFINED), f"{base}.local_checks", errors)
    _validate_reviewed_path_ownership(unit, base, errors)
    _validate_string_array(
        unit.get("result_fingerprints", UNDEFINED),
        f"{base}.result_fingerprints",
        errors,
        fingerprint=True,
    )
    _validate_string_array(unit.get("unresolved", UNDEFINED), f"{base}.unresolved", errors)

    _validate_state_invariants(unit, base, errors)
    return list(errors)


# ---------------------------------------------------------------------------------------------
# Documents and files


def validate_ledger(ledger: object) -> list[str]:
    """Return the errors of a parsed coverage ledger; an empty list means valid (port of
    ``validateDocument``)."""
    errors = ErrorList(LIMITS.validation_errors)
    if not isinstance(ledger, list):
        errors.push("$: expected a top-level array")
        return list(errors)
    if len(ledger) > LIMITS.units:
        errors.push(f"$: exceeds {LIMITS.units} coverage units")
        return list(errors)
    errors.push(*preflight_document(ledger))
    if errors:
        return list(errors)

    ids: dict[str, tuple[int, tuple[object, ...] | None]] = {}
    semantics: dict[tuple[object, ...], tuple[str, int]] = {}
    previous_id: str | None = None
    for index, unit in enumerate(ledger):
        if errors.full:
            break
        errors.push(*_collect_unit_errors(unit, index))
        if errors.full:
            break
        if not isinstance(unit, dict) or not isinstance(unit.get("coverage_id"), str):
            continue
        coverage_id: str = unit["coverage_id"]
        key = _semantic_key(unit) if _has_valid_semantic_fields(unit) else None
        if coverage_id in ids:
            previous_index, previous_key = ids[coverage_id]
            if key is not None and previous_key is not None and previous_key != key:
                qualifier = "canonical identity collision with different semantic fields"
            else:
                qualifier = "duplicate coverage ID"
            errors.push(f"$[{index}].coverage_id: {qualifier} at $[{previous_index}]")
        else:
            ids[coverage_id] = (index, key)
        if key is not None and key in semantics and semantics[key][0] != coverage_id:
            other_id, other_index = semantics[key]
            errors.push(
                f"$[{index}].canonical_refs: semantic tuple already uses coverage ID "
                f"{safe_quote(other_id)} at $[{other_index}]"
            )
        elif key is not None:
            semantics[key] = (coverage_id, index)
        if previous_id is not None and utf16_key(previous_id) > utf16_key(coverage_id):
            errors.push(f"$[{index}].coverage_id: units must be sorted lexicographically")
        previous_id = coverage_id
    return list(errors)


def validate_ledger_file(path: str | os.PathLike[str]) -> list[str]:
    """Read, check and validate a coverage ledger file; an empty list means valid.

    Every failure becomes a message, in the upstream wording:

    - ``Failed to read coverage ledger: <reason>`` (symlink, not a regular file, over 5 MiB,
      invalid UTF-8, or not readable);
    - ``Failed to parse coverage ledger: <reason>`` (a structural limit of
      :func:`preflight_json_text`, or invalid JSON syntax);
    - otherwise the validation errors of :func:`validate_ledger` (at most 100).

    Messages never contain the path or raw control characters.
    """
    try:
        contents = read_text_bounded(path, LIMITS.input_bytes)
    except UnsafeInputError as exc:
        return [f"Failed to read coverage ledger: {escape_unsafe_diagnostic_characters(exc)}"]
    try:
        preflight_json_text(contents)
    except JsonStructureError as exc:
        return [f"Failed to parse coverage ledger: {exc}"]
    try:
        ledger = parse_json_text(contents)
    except JsonStructureError:
        return ["Failed to parse coverage ledger: invalid JSON syntax"]
    try:
        return validate_ledger(ledger)
    except Exception:  # upstream reports a generic message, never a trace
        return ["Failed to validate coverage ledger: unexpected validation error"]
