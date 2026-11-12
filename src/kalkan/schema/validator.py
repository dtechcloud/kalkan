# SPDX-License-Identifier: MIT
# Ported from cloudflare/security-audit-skill@c1c8a8c: skills/security-audit/validate-findings.cjs
# Copyright (c) 2025-2026 Cloudflare, Inc. Changes: translated from JavaScript to Python; the schema
# interpreter, the data limits and the JSON text limits form a reusable module; schema patterns
# keep the JavaScript regular-expression dialect and are translated to Python's re syntax.
r"""Restricted JSON Schema validator (port of the Cloudflare findings validator).

Supported keywords: ``$comment``, ``additionalProperties`` (boolean only), ``const``,
``description``, ``enum``, ``items`` (one schema), ``minimum``, ``minItems``, ``minLength``,
``oneOf``, ``pattern``, ``properties``, ``required``, ``type`` (one name), ``uniqueItems`` and the
custom ``visibleContent``. :func:`check_schema` rejects every other keyword, so a schema can never
ask for a check that the validator skips without a word.

Semantics:

- ``oneOf`` requires exactly one passing branch. When no branch passes and the instance matches
  the ``const`` discriminator of exactly one branch, the errors of that branch follow.
- ``visibleContent: true`` requires valid Unicode scalar values and at least one character
  outside White_Space, Cc, Cf and Default_Ignorable_Code_Point.
- ``minLength`` counts code points. ``uniqueItems`` compares canonical keys: the key order of an
  object does not matter, and ``1`` equals ``1.0``.
- ``pattern`` uses the JavaScript regular-expression dialect without flags, as upstream.
  :func:`compile_pattern` translates it: ``$`` matches only at the very end, ``.`` excludes line
  terminators, ``\d``, ``\w`` and ``\b`` are ASCII-only, and ``\s`` is the JavaScript set. A
  pattern matches code points, not UTF-16 code units.

Limits (:data:`LIMITS`): nesting depth 64, 1000 items per array, 1 MiB per canonical key, 5 MiB
per uniqueness set, 100 errors. :func:`collect_data_limit_errors` applies them to parsed data and
rejects repeated or cyclic references. :func:`enforce_json_text_limits` applies the depth and
array limits to JSON text before :func:`parse_json_text` runs ``json.loads``.
"""

from __future__ import annotations

import functools
import json
import math
import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Final, NamedTuple

from kalkan.errors import ValidationError
from kalkan.util.text import (
    JS_WHITESPACE_CHARACTERS,
    ErrorList,
    escape_unsafe_diagnostic_characters,
    has_valid_unicode_scalar_values,
    has_visible_content,
    is_js_integer,
    js_json_string,
    js_number_str,
    safe_quote,
    type_of,
)

__all__ = [
    "LIMITS",
    "SUPPORTED_KEYWORDS",
    "SUPPORTED_TYPES",
    "CanonicalKeyError",
    "JsonStructureError",
    "Limits",
    "PatternSyntaxError",
    "canonical_key",
    "check_schema",
    "collect_data_limit_errors",
    "collect_unchecked",
    "compile_pattern",
    "deep_equal",
    "enforce_json_text_limits",
    "parse_json_text",
    "property_path",
    "validate",
]


@dataclass(frozen=True)
class Limits:
    """Bounds of the findings validator (upstream ``LIMITS``)."""

    input_bytes: int = 5 * 1024 * 1024
    nesting_depth: int = 64
    array_items: int = 1000
    canonical_key_bytes: int = 1024 * 1024
    unique_set_bytes: int = 5 * 1024 * 1024
    validation_errors: int = 100


LIMITS: Final = Limits()

SUPPORTED_TYPES: Final = frozenset(
    {"object", "array", "string", "integer", "number", "boolean", "null"}
)
SUPPORTED_KEYWORDS: Final = frozenset(
    {
        "$comment",
        "additionalProperties",
        "const",
        "description",
        "enum",
        "items",
        "minimum",
        "minItems",
        "minLength",
        "oneOf",
        "pattern",
        "properties",
        "required",
        "type",
        "uniqueItems",
        "visibleContent",
    }
)


class JsonStructureError(ValidationError, ValueError):
    """JSON text exceeds a structural limit or is not valid JSON."""

    def __init__(self, message: str) -> None:
        super().__init__(message, [message])


class CanonicalKeyError(ValueError):
    """A canonical key grew beyond ``LIMITS.canonical_key_bytes``."""


class PatternSyntaxError(ValueError):
    """A schema ``pattern`` is not a valid or supported JavaScript regular expression."""


# ---------------------------------------------------------------------------------------------
# Diagnostic paths


_IDENTIFIER: Final = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def property_path(base: str, key: object) -> str:
    """Return ``base.key`` for an identifier key, else ``base["key"]`` with a safe quote."""
    name = key if isinstance(key, str) else str(key)
    if _IDENTIFIER.fullmatch(name):
        return f"{base}.{name}"
    return f"{base}[{safe_quote(name)}]"


# A location is built only when a message needs it: (parent, key, is_object_key) or a string.
_Location = Any


def _render_location(location: _Location) -> str:
    parts: list[tuple[object, bool]] = []
    while not isinstance(location, str):
        location, key, is_object_key = location
        parts.append((key, is_object_key))
    text = location
    for key, is_object_key in reversed(parts):
        text = property_path(text, key) if is_object_key else f"{text}[{key}]"
    return text


# ---------------------------------------------------------------------------------------------
# Canonical keys and equality


def canonical_key(value: object, limit: int = LIMITS.canonical_key_bytes) -> tuple[str, int]:
    """Return ``(key, utf8_bytes)``, a canonical text form of a JSON value (port of
    ``canonicalKey``).

    Equal JSON values give equal keys, whatever the key order of their objects. Raises
    :class:`CanonicalKeyError` when the key would exceed ``limit`` bytes. The encoder is
    iterative, so deep or cyclic input ends at the byte limit instead of the recursion limit.
    """
    chunks: list[str] = []
    total = 0
    stack: list[tuple[bool, object]] = [(False, value)]
    while stack:
        is_text, item = stack.pop()
        if is_text:
            chunk = str(item)
        elif item is None:
            chunk = "null"
        elif isinstance(item, bool):
            chunk = "boolean:true" if item else "boolean:false"
        elif isinstance(item, str):
            chunk = f"string:{js_json_string(item)}"
        elif isinstance(item, int | float):
            chunk = f"number:{js_number_str(item)}"
        elif isinstance(item, list):
            chunk = "array:["
            stack.append((True, "]"))
            for index in range(len(item) - 1, -1, -1):
                stack.append((False, item[index]))
                if index > 0:
                    stack.append((True, ","))
        elif isinstance(item, dict):
            chunk = "object:{"
            names = sorted(item, key=str)
            stack.append((True, "}"))
            for index in range(len(names) - 1, -1, -1):
                name = names[index]
                stack.append((False, item[name]))
                stack.append((True, ":"))
                stack.append((True, js_json_string(str(name))))
                if index > 0:
                    stack.append((True, ","))
        else:
            # Not a JSON value. The identity keeps two different objects apart.
            chunk = f"{type_of(item)}:{id(item)}"
        total += len(chunk.encode("utf-8", "surrogatepass"))
        if total > limit:
            raise CanonicalKeyError(f"canonical key exceeds {limit} byte limit")
        chunks.append(chunk)
    return "".join(chunks), total


def deep_equal(left: object, right: object) -> bool:
    """Return True when two JSON values are equal (port of ``deepEqual``).

    Numbers compare by value (``1`` equals ``1.0``), ``True`` never equals ``1``, and objects
    compare without regard to key order.
    """
    if left is right:
        return True
    if type_of(left) != type_of(right):
        return False
    if isinstance(left, list) and isinstance(right, list):
        return len(left) == len(right) and all(
            deep_equal(a, b) for a, b in zip(left, right, strict=True)
        )
    if isinstance(left, dict) and isinstance(right, dict):
        return len(left) == len(right) and all(
            key in right and deep_equal(left[key], right[key]) for key in left
        )
    if left is None or isinstance(left, str | int | float):
        return left == right
    return False


# ---------------------------------------------------------------------------------------------
# Data limits


def collect_data_limit_errors(value: object, location: str = "$data") -> list[str]:
    """Return one error when parsed data exceeds the nesting depth or the array size limit, or
    holds a repeated or cyclic reference (port of ``collectDataLimitErrors``)."""
    limits = LIMITS
    stack: list[tuple[object, _Location, int]] = [
        (value, location, 1 if isinstance(value, dict | list) else 0)
    ]
    seen: set[int] = set()
    while stack:
        current, where, depth = stack.pop()
        if not isinstance(current, dict | list):
            continue
        if depth > limits.nesting_depth:
            message = f"{_render_location(where)}: exceeds {limits.nesting_depth} level nesting"
            return [escape_unsafe_diagnostic_characters(f"{message} depth limit")]
        marker = id(current)
        if marker in seen:
            message = "input must not contain repeated or cyclic object references"
            return [escape_unsafe_diagnostic_characters(f"{_render_location(where)}: {message}")]
        seen.add(marker)
        if isinstance(current, list):
            if len(current) > limits.array_items:
                message = f"{_render_location(where)}: exceeds {limits.array_items} item array"
                return [escape_unsafe_diagnostic_characters(f"{message} limit")]
            for index in range(len(current) - 1, -1, -1):
                child = current[index]
                if isinstance(child, dict | list):
                    stack.append((child, (where, index, False), depth + 1))
        else:
            keys = list(current)
            for index in range(len(keys) - 1, -1, -1):
                child = current[keys[index]]
                if isinstance(child, dict | list):
                    stack.append((child, (where, keys[index], True), depth + 1))
    return []


# ---------------------------------------------------------------------------------------------
# Schema checks


def check_schema(schema: object, location: str = "schema") -> list[str]:
    """Return the errors of a schema: unsupported keywords and malformed keyword values (port
    of ``collectSchemaErrors``). An empty list means the validator can interpret the schema."""
    errors = ErrorList(LIMITS.validation_errors)
    _check_schema_node(schema, location, errors, 1)
    return list(errors)


def _check_schema_node(node: object, path: str, errors: ErrorList, depth: int) -> None:
    if errors.full:
        return
    if depth > LIMITS.nesting_depth:
        errors.push(f"{path}: schema exceeds {LIMITS.nesting_depth} level nesting depth limit")
        return
    if not isinstance(node, dict):
        errors.push(f"{path}: schema must be an object")
        return

    for key in node:
        if not (isinstance(key, str) and key in SUPPORTED_KEYWORDS):
            errors.push(f"{path}: unsupported schema keyword {safe_quote(key)}")

    if "$comment" in node and not isinstance(node["$comment"], str):
        errors.push(f"{path}.$comment: expected string")
    if "description" in node and not isinstance(node["description"], str):
        errors.push(f"{path}.description: expected string")
    if "type" in node:
        kind = node["type"]
        if not (isinstance(kind, str) and kind in SUPPORTED_TYPES):
            errors.push(f"{path}.type: unsupported type {safe_quote(kind)}")
    if "properties" in node:
        properties = node["properties"]
        if not isinstance(properties, dict):
            errors.push(f"{path}.properties: expected object")
        else:
            for key, child in properties.items():
                _check_schema_node(
                    child, property_path(f"{path}.properties", key), errors, depth + 1
                )
    if "required" in node:
        required = node["required"]
        if not isinstance(required, list) or any(not isinstance(key, str) for key in required):
            errors.push(f"{path}.required: expected an array of strings")
        elif len(set(required)) != len(required):
            errors.push(f"{path}.required: entries must be unique")
    if "additionalProperties" in node and not isinstance(node["additionalProperties"], bool):
        errors.push(f"{path}.additionalProperties: only boolean values are supported")
    if "enum" in node:
        _check_enum(node["enum"], path, errors)
    if "items" in node:
        _check_schema_node(node["items"], f"{path}.items", errors, depth + 1)
    for keyword in ("minItems", "minLength"):
        if keyword in node and (not is_js_integer(node[keyword]) or node[keyword] < 0):
            errors.push(f"{path}.{keyword}: expected a non-negative integer")
    if "minimum" in node and not _is_finite(node["minimum"]):
        errors.push(f"{path}.minimum: expected a finite number")
    if "pattern" in node:
        pattern = node["pattern"]
        if not isinstance(pattern, str):
            errors.push(f"{path}.pattern: expected string")
        else:
            try:
                compile_pattern(pattern)
            except PatternSyntaxError:
                errors.push(f"{path}.pattern: invalid regular expression")
    if "uniqueItems" in node and not isinstance(node["uniqueItems"], bool):
        errors.push(f"{path}.uniqueItems: expected boolean")
    if "visibleContent" in node:
        visible = node["visibleContent"]
        if not isinstance(visible, bool):
            errors.push(f"{path}.visibleContent: expected boolean")
        elif visible is True and node.get("type") != "string":
            errors.push(f'{path}.visibleContent: requires type "string"')
    if "oneOf" in node:
        branches = node["oneOf"]
        if not isinstance(branches, list) or not branches:
            errors.push(f"{path}.oneOf: expected a non-empty array")
        else:
            for index, branch in enumerate(branches):
                _check_schema_node(branch, f"{path}.oneOf[{index}]", errors, depth + 1)


def _check_enum(values: object, path: str, errors: ErrorList) -> None:
    if not isinstance(values, list) or not values:
        errors.push(f"{path}.enum: expected a non-empty array")
        return
    seen: set[str] = set()
    for value in values:
        try:
            key = canonical_key(value)[0]
        except CanonicalKeyError as exc:
            errors.push(f"{path}.enum: {exc}")
            return
        if key in seen:
            errors.push(f"{path}.enum: entries must be unique")
            return
        seen.add(key)


def _is_finite(value: object) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return True
    return isinstance(value, float) and math.isfinite(value)


# ---------------------------------------------------------------------------------------------
# Instance validation


def _find_discriminator(schema: object) -> tuple[str, object] | None:
    if not isinstance(schema, dict):
        return None
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        return None
    for key, child in properties.items():
        if isinstance(child, dict) and "const" in child:
            return key, child["const"]
    return None


def _validate(value: object, schema: dict[str, Any], path: str, errors: ErrorList) -> None:
    if errors.full:
        return
    if "oneOf" in schema:
        branches = schema["oneOf"]
        results = [collect_unchecked(value, branch, path) for branch in branches]
        passing = [index for index, result in enumerate(results) if not result]
        if len(passing) != 1:
            errors.push(f"{path}: must match exactly one schema in oneOf; matched {len(passing)}")
            if not passing and isinstance(value, dict):
                matching = []
                for index, branch in enumerate(branches):
                    found = _find_discriminator(branch)
                    if (
                        found is not None
                        and found[0] in value
                        and deep_equal(value[found[0]], found[1])
                    ):
                        matching.append(index)
                if len(matching) == 1:
                    errors.push(*results[matching[0]])

    if "const" in schema and not deep_equal(value, schema["const"]):
        errors.push(f"{path}: must equal {safe_quote(schema['const'])}, got {safe_quote(value)}")
    if "enum" in schema and not any(deep_equal(value, allowed) for allowed in schema["enum"]):
        allowed_text = ", ".join(safe_quote(allowed) for allowed in schema["enum"])
        errors.push(f"{path}: invalid value {safe_quote(value)} (expected one of {allowed_text})")

    kind = type_of(value)
    if "type" in schema:
        expected = schema["type"]
        if kind != expected and not (
            expected == "integer" and kind == "number" and is_js_integer(value)
        ):
            errors.push(f"{path}: expected {expected}, got {kind}")
            return

    if isinstance(value, dict):
        for name in schema.get("required", ()):
            if name not in value:
                errors.push(f"{path}: missing required field {safe_quote(name)}")
        properties = schema.get("properties")
        closed = schema.get("additionalProperties") is False
        for key in value:
            if errors.full:
                break
            if isinstance(properties, dict) and isinstance(key, str) and key in properties:
                _validate(value[key], properties[key], property_path(path, key), errors)
            elif closed:
                errors.push(f"{path}: unexpected field {safe_quote(key)}")

    if isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            minimum = js_number_str(schema["minItems"])
            errors.push(f"{path}: must have at least {minimum} item(s), got {len(value)}")
        if schema.get("uniqueItems") is True:
            _check_unique(value, path, errors)
        if "items" in schema:
            for index, item in enumerate(value):
                if errors.full:
                    break
                _validate(item, schema["items"], f"{path}[{index}]", errors)

    if isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            minimum = js_number_str(schema["minLength"])
            errors.push(f"{path}: must have at least {minimum} character(s)")
        if schema.get("visibleContent") is True:
            if not has_valid_unicode_scalar_values(value):
                errors.push(f"{path}: must contain only valid Unicode scalar values")
            elif not has_visible_content(value):
                errors.push(f"{path}: must contain a visible character")
        pattern = schema.get("pattern")
        if isinstance(pattern, str) and compile_pattern(pattern).search(value) is None:
            errors.push(f"{path}: must match pattern {js_json_string(pattern)}")

    if (
        isinstance(value, int | float)
        and not isinstance(value, bool)
        and "minimum" in schema
        and value < schema["minimum"]
    ):
        minimum = js_number_str(schema["minimum"])
        errors.push(f"{path}: must be at least {minimum}, got {js_number_str(value)}")


def _check_unique(items: list, path: str, errors: ErrorList) -> None:
    seen: set[str] = set()
    set_bytes = 0
    for index, item in enumerate(items):
        if errors.full:
            return
        try:
            key, size = canonical_key(item)
        except CanonicalKeyError as exc:
            errors.push(f"{path}[{index}]: {exc}")
            return
        if key in seen:
            errors.push(f"{path}: items must be unique; duplicate at index {index}")
            continue
        set_bytes += size
        if set_bytes > LIMITS.unique_set_bytes:
            errors.push(
                f"{path}: canonical uniqueness set exceeds {LIMITS.unique_set_bytes} byte limit"
            )
            return
        seen.add(key)


def collect_unchecked(value: object, schema: dict[str, Any], path: str = "$data") -> ErrorList:
    """Validate ``value`` against an already checked schema, without the data limit check
    (port of ``collectUnchecked``). Most callers want :func:`validate`."""
    errors = ErrorList(LIMITS.validation_errors)
    _validate(value, schema, path, errors)
    return errors


def validate(instance: object, schema: object, path: str = "$data") -> list[str]:
    """Return the errors of ``instance`` against ``schema``; an empty list means valid.

    The function checks the schema first (:func:`check_schema`), then the data limits
    (:func:`collect_data_limit_errors`), then the instance. Each step returns its errors
    without running the next one. At most 100 errors are returned.
    """
    schema_errors = check_schema(schema)
    if schema_errors:
        return schema_errors
    limit_errors = collect_data_limit_errors(instance, path)
    if limit_errors:
        return limit_errors
    assert isinstance(schema, dict)  # check_schema rejects every other root
    return list(collect_unchecked(instance, schema, path))


# ---------------------------------------------------------------------------------------------
# JSON text


# Matches the body of a JSON string: everything up to the closing quote, with escape pairs.
_STRING_BODY: Final = re.compile(r'[^"\\]*(?:\\.[^"\\]*)*', re.DOTALL)
# The characters that open or close a string or a container.
_STRUCTURAL: Final = re.compile(r'["\[\]{}]')
# Two commas with only whitespace between them: a flat run with an empty item.
_EMPTY_ITEM: Final = re.compile(",[" + re.escape(JS_WHITESPACE_CHARACTERS) + "]*,")


def _skip(pattern: re.Pattern[str], contents: str, index: int) -> int:
    """Return the end of the (possibly empty) match of ``pattern`` at ``index``."""
    match = pattern.match(contents, index)
    return index if match is None else match.end()


def _has_content(text: str) -> bool:
    return bool(text.strip(JS_WHITESPACE_CHARACTERS))


def _count_flat_run(run: str, container: list[Any], item_limit: int) -> None:
    """Apply the upstream item counting to a run without strings or containers.

    Upstream counts a value when a non-whitespace character starts while the array expects an
    item; ``[`` and ``,`` set the expectation, a counted value clears it. Inside a run only
    scalars, commas, colons and whitespace occur, so the count follows from the comma-separated
    parts: each part with content after a comma counts once, and the first part counts when the
    array expected an item on entry.
    """
    expects = container[1]
    commas = run.count(",")
    if commas == 0:
        if expects and _has_content(run):
            container[2] += 1
            expects = False
    else:
        first = run.find(",")
        last = run.rfind(",")
        count = 1 if expects and _has_content(run[:first]) else 0
        if commas > 1 and _EMPTY_ITEM.search(run, first, last + 1):
            # Malformed JSON with an empty item: count part by part.
            for part in run[first + 1 : last].split(","):
                if _has_content(part):
                    count += 1
        else:
            count += commas - 1
        expects = not _has_content(run[last + 1 :])
        if not expects:
            count += 1
        container[2] += count
    container[1] = expects
    if container[2] > item_limit:
        raise JsonStructureError(f"input exceeds {item_limit} item array limit")


def _enforce_json_text_limits(contents: str, depth_limit: int, item_limit: int) -> None:
    # Each container: [is_array, expects_item, items].
    containers: list[list[Any]] = []

    def mark_array_item() -> None:
        if not containers:
            return
        container = containers[-1]
        if not container[0] or not container[1]:
            return
        container[1] = False
        container[2] += 1
        if container[2] > item_limit:
            raise JsonStructureError(f"input exceeds {item_limit} item array limit")

    index = 0
    length = len(contents)
    while True:
        match = _STRUCTURAL.search(contents, index)
        stop = length if match is None else match.start()
        if stop > index and containers and containers[-1][0]:
            # Scalars and commas only change the state of an array.
            _count_flat_run(contents[index:stop], containers[-1], item_limit)
        if match is None:
            return
        character = match.group()
        index = stop + 1
        if character == '"':
            mark_array_item()
            end = _skip(_STRING_BODY, contents, index)
            if end >= length or contents[end] != '"':
                return  # unterminated string: json.loads reports the syntax error
            index = end + 1
        elif character == "[" or character == "{":
            mark_array_item()
            if len(containers) >= depth_limit:
                raise JsonStructureError(f"input exceeds {depth_limit} level nesting depth limit")
            is_array = character == "["
            containers.append([is_array, is_array, 0])
        elif containers:
            containers.pop()


def enforce_json_text_limits(contents: str) -> None:
    """Raise :class:`JsonStructureError` when JSON text nests deeper than 64 containers or holds
    an array with more than 1000 items (port of ``enforceJsonTextLimits``).

    The scan runs before ``json.loads`` so that hostile text cannot exhaust the parser. It does
    not check the syntax; :func:`parse_json_text` does. The scan jumps between strings and
    containers and counts the items of a flat run in one step; the result equals the upstream
    character-by-character scan.
    """
    _enforce_json_text_limits(contents, LIMITS.nesting_depth, LIMITS.array_items)


def _reject_constant(name: str) -> object:
    raise ValueError(f"invalid JSON constant {name}")


def parse_json_text(contents: str) -> Any:
    """Parse strict JSON text, like ``JSON.parse``.

    ``NaN``, ``Infinity`` and ``-Infinity`` are rejected, as are a byte order mark, trailing data
    and control characters in strings. Raises :class:`JsonStructureError` with the message
    ``invalid JSON syntax``; parser details never reach the message.
    """
    try:
        return json.loads(contents, parse_constant=_reject_constant)
    except (ValueError, RecursionError):
        raise JsonStructureError("invalid JSON syntax") from None


# ---------------------------------------------------------------------------------------------
# Schema patterns: JavaScript regular expressions (no flags, Annex B) translated to Python


def _to_ranges(codes: Iterable[int]) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    for code in sorted(set(codes)):
        if ranges and ranges[-1][1] + 1 == code:
            ranges[-1] = (ranges[-1][0], code)
        else:
            ranges.append((code, code))
    return ranges


def _complement(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    result: list[tuple[int, int]] = []
    start = 0
    for low, high in ranges:
        if low > start:
            result.append((start, low - 1))
        start = high + 1
    if start <= 0x10FFFF:
        result.append((start, 0x10FFFF))
    return result


def _render_code(code: int) -> str:
    character = chr(code)
    if character.isascii() and character.isalnum():
        return character
    if code < 0x100:
        return f"\\x{code:02x}"
    if code < 0x10000:
        return f"\\u{code:04x}"
    return f"\\U{code:08x}"


def _render_ranges(ranges: Iterable[tuple[int, int]]) -> str:
    return "".join(
        _render_code(low) if low == high else f"{_render_code(low)}-{_render_code(high)}"
        for low, high in ranges
    )


_SPACE_RANGES: Final = _to_ranges(ord(character) for character in JS_WHITESPACE_CHARACTERS)
_SPACE_BODY: Final = _render_ranges(_SPACE_RANGES)
_NON_SPACE_BODY: Final = _render_ranges(_complement(_SPACE_RANGES))
_DOT: Final = r"[^\n\r\U00002028\U00002029]"
_ANY: Final = r"[\x00-\U0010ffff]"
_NOTHING: Final = r"(?!)"
_BRACE_QUANTIFIER: Final = re.compile(r"\{([0-9]+)(,([0-9]*))?\}")
_HEX2: Final = re.compile(r"[0-9A-Fa-f]{2}")
_HEX4: Final = re.compile(r"[0-9A-Fa-f]{4}")
_DECIMAL: Final = re.compile(r"[0-9]+")
_GROUP_NAME: Final = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_OCTAL_DIGITS: Final = "01234567"
_CONTROL_ESCAPES: Final = {"t": 9, "n": 10, "v": 11, "f": 12, "r": 13}


class _Atom(NamedTuple):
    kind: str  # "char", "set", "assert" or "backref"
    text: str  # Python syntax outside a character class
    code: int = -1  # the code point of a "char"
    body: str = ""  # Python syntax inside a character class ("char" and "set")


def _char_atom(code: int) -> _Atom:
    text = _render_code(code)
    return _Atom("char", text, code, text)


def _count_capture_groups(source: str) -> int:
    count = 0
    index = 0
    in_class = False
    while index < len(source):
        character = source[index]
        if character == "\\":
            index += 2
            continue
        if in_class:
            in_class = character != "]"
        elif character == "[":
            in_class = True
        elif character == "(" and (
            not source.startswith("(?", index)
            or (source.startswith("(?<", index) and not source.startswith(("(?<=", "(?<!"), index))
        ):
            count += 1
        index += 1
    return count


class _PatternTranslator:
    """Translates a JavaScript pattern (no flags, Annex B syntax) into Python ``re`` syntax."""

    def __init__(self, source: str) -> None:
        self.source = source
        self.length = len(source)
        self.capture_groups = _count_capture_groups(source)

    def translate(self) -> str:
        source = self.source
        out: list[str] = []
        index = 0
        # "atom": the last token can take a quantifier; "quantifier": the last token is one;
        # "none": nothing to repeat.
        state = "none"
        while index < self.length:
            character = source[index]
            if character == "\\":
                atom, index = self._escape(index + 1, in_class=False)
                out.append(atom.text)
                state = "none" if atom.kind == "assert" else "atom"
            elif character == "[":
                text, index = self._character_class(index + 1)
                out.append(text)
                state = "atom"
            elif character in "*+?":
                if state == "quantifier" and character == "?":
                    out.append("?")  # lazy quantifier
                    state = "none"
                elif state != "atom":
                    raise PatternSyntaxError("nothing to repeat")
                else:
                    out.append(character)
                    state = "quantifier"
                index += 1
            elif character == "{" and (match := _BRACE_QUANTIFIER.match(source, index)):
                if state != "atom":
                    raise PatternSyntaxError("nothing to repeat")
                if match.group(3) and int(match.group(3)) < int(match.group(1)):
                    raise PatternSyntaxError("numbers out of order in {} quantifier")
                out.append(match.group(0))
                state = "quantifier"
                index = match.end()
            elif character == "(":
                text, index = self._group(index)
                out.append(text)
                state = "none"
            elif character == ")":
                out.append(")")
                state = "atom"
                index += 1
            elif character == ".":
                out.append(_DOT)
                state = "atom"
                index += 1
            elif character in "^|":
                out.append(character)
                state = "none"
                index += 1
            elif character == "$":
                out.append(r"\Z")
                state = "none"
                index += 1
            else:
                # A literal. Annex B also allows a lone "{", "}" and "]".
                out.append(_render_code(ord(character)))
                state = "atom"
                index += 1
        return "".join(out)

    def _group(self, index: int) -> tuple[str, int]:
        source = self.source
        if not source.startswith("(?", index):
            return "(", index + 1
        for prefix in ("(?:", "(?=", "(?!", "(?<=", "(?<!"):
            if source.startswith(prefix, index):
                return prefix, index + len(prefix)
        if source.startswith("(?<", index):
            end = source.find(">", index + 3)
            name = source[index + 3 : end] if end != -1 else ""
            if not _GROUP_NAME.fullmatch(name):
                raise PatternSyntaxError("invalid capture group name")
            return f"(?P<{name}>", end + 1
        raise PatternSyntaxError("invalid group")

    def _escape(self, index: int, *, in_class: bool) -> tuple[_Atom, int]:
        source = self.source
        if index >= self.length:
            raise PatternSyntaxError("\\ at end of pattern")
        character = source[index]
        if character in "dDwW":
            return _Atom("set", f"\\{character}", body=f"\\{character}"), index + 1
        if character == "s":
            return _Atom("set", f"[{_SPACE_BODY}]", body=_SPACE_BODY), index + 1
        if character == "S":
            return _Atom("set", f"[{_NON_SPACE_BODY}]", body=_NON_SPACE_BODY), index + 1
        if character in "bB":
            if in_class:
                return _char_atom(8 if character == "b" else ord("B")), index + 1
            return _Atom("assert", f"\\{character}"), index + 1
        if character in _CONTROL_ESCAPES:
            return _char_atom(_CONTROL_ESCAPES[character]), index + 1
        if character == "c":
            following = source[index + 1] if index + 1 < self.length else ""
            if following.isascii() and (
                following.isalpha() or (in_class and (following.isdigit() or following == "_"))
            ):
                return _char_atom(ord(following) % 32), index + 2
            # Annex B: without a control letter, the backslash is a literal and "c" follows.
            return _char_atom(ord("\\")), index
        if character == "x":
            if _HEX2.match(source, index + 1):
                return _char_atom(int(source[index + 1 : index + 3], 16)), index + 3
            return _char_atom(ord("x")), index + 1
        if character == "u":
            if _HEX4.match(source, index + 1):
                return _char_atom(int(source[index + 1 : index + 5], 16)), index + 5
            return _char_atom(ord("u")), index + 1
        if character == "k" and not in_class and source.startswith("<", index + 1):
            end = source.find(">", index + 2)
            name = source[index + 2 : end] if end != -1 else ""
            if not _GROUP_NAME.fullmatch(name):
                raise PatternSyntaxError("invalid named reference")
            return _Atom("backref", f"(?P={name})"), end + 1
        if character in "89":
            return _char_atom(ord(character)), index + 1
        if character in "1234567" and not in_class:
            end = _skip(_DECIMAL, source, index)
            number = int(source[index:end])
            if number <= self.capture_groups:
                return _Atom("backref", f"(?:\\{number})"), end
            return self._octal(index)
        if character in _OCTAL_DIGITS:
            return self._octal(index)
        return _char_atom(ord(character)), index + 1

    def _octal(self, index: int) -> tuple[_Atom, int]:
        # Annex B LegacyOctalEscapeSequence: up to three digits, at most 0o377.
        source = self.source
        first = source[index]
        digits = first
        position = index + 1
        if position < self.length and source[position] in _OCTAL_DIGITS:
            digits += source[position]
            position += 1
            if first in "0123" and position < self.length and source[position] in _OCTAL_DIGITS:
                digits += source[position]
                position += 1
        return _char_atom(int(digits, 8)), position

    def _class_atom(self, index: int) -> tuple[_Atom, int]:
        if self.source[index] == "\\":
            return self._escape(index + 1, in_class=True)
        return _char_atom(ord(self.source[index])), index + 1

    def _character_class(self, index: int) -> tuple[str, int]:
        source = self.source
        negate = index < self.length and source[index] == "^"
        if negate:
            index += 1
        items: list[str] = []
        while True:
            if index >= self.length:
                raise PatternSyntaxError("unterminated character class")
            if source[index] == "]":
                index += 1
                break
            first, index = self._class_atom(index)
            if index + 1 < self.length and source[index] == "-" and source[index + 1] != "]":
                second, after = self._class_atom(index + 1)
                if first.kind == "char" and second.kind == "char":
                    if second.code < first.code:
                        raise PatternSyntaxError("range out of order in character class")
                    items.append(f"{first.body}-{second.body}")
                else:
                    # Annex B: a class escape at a range end makes the "-" a literal.
                    items.extend((first.body, _render_code(ord("-")), second.body))
                index = after
                continue
            items.append(first.body)
        if not items:
            return (_ANY if negate else _NOTHING), index
        return f"[{'^' if negate else ''}{''.join(items)}]", index


@functools.lru_cache(maxsize=256)
def compile_pattern(pattern: str) -> re.Pattern[str]:
    """Compile a schema ``pattern`` written in the JavaScript dialect (no flags).

    Raises :class:`PatternSyntaxError` when the pattern is invalid or uses syntax that has no
    exact Python translation (for example possessive quantifiers or inline flags).
    """
    translated = _PatternTranslator(pattern).translate()
    try:
        return re.compile(translated, re.ASCII)
    except (re.error, OverflowError, RecursionError) as exc:
        raise PatternSyntaxError(str(exc)) from None
