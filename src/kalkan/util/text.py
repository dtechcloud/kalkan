# SPDX-License-Identifier: MIT
# Ported from cloudflare/security-audit-skill@c1c8a8c: skills/security-audit/validate-findings.cjs
# Ported from cloudflare/security-audit-skill@c1c8a8c: skills/security-audit/validate-coverage-ledger.cjs  # noqa: E501
# Copyright (c) 2025-2026 Cloudflare, Inc. Changes: translated from JavaScript to Python; the
# helpers that both validators share moved into one module; the Unicode property classes are
# spelled out as code point ranges; the JavaScript string semantics that a verdict or a message
# depends on are reproduced explicitly.
r"""Visible-prose checks and safe diagnostic formatting shared by the kalkan validators.

The Cloudflare validators are JavaScript programs. Some of their verdicts and messages depend on
JavaScript string semantics, so this module reproduces those semantics:

- ``\p{...}`` classes. Python's ``re`` module has no Unicode property classes. The classes are
  spelled out as code point ranges. The ranges equal Unicode 16.0 (Node.js 22) and Unicode 15.1
  (``unicodedata`` in Python 3.13) for every property used here.
- ``String.prototype.trim`` and the ``\s`` class use a fixed whitespace set. The set differs from
  ``str.strip()``: JavaScript trims U+FEFF, but not U+0085 or U+001C to U+001F.
- ``string.length`` counts UTF-16 code units, and ``<`` on strings orders UTF-16 code units.
- ``JSON.stringify`` escapes lone surrogates, and ``String(number)`` has its own number format.

``json.loads`` joins a valid surrogate pair into one code point. A surrogate code point in a
parsed ``str`` is therefore always a lone surrogate, which is never a Unicode scalar value.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Iterable
from typing import Final

__all__ = [
    "CC_RANGES",
    "CF_RANGES",
    "CS_RANGES",
    "DEFAULT_ERROR_LIMIT",
    "DEFAULT_IGNORABLE_CODE_POINT",
    "DEFAULT_IGNORABLE_RANGES",
    "JS_WHITESPACE",
    "JS_WHITESPACE_CHARACTERS",
    "JS_WHITESPACE_RANGES",
    "MAX_DIAGNOSTIC_STRING_LENGTH",
    "PATH_FORBIDDEN_CHARACTER",
    "UNDEFINED",
    "UNSAFE_DIAGNOSTIC_CHARACTER",
    "VISIBLE_CONTENT",
    "WHITE_SPACE",
    "WHITE_SPACE_RANGES",
    "ZL_RANGES",
    "ZP_RANGES",
    "ErrorList",
    "escape_unsafe_diagnostic_characters",
    "has_valid_unicode_scalar_values",
    "has_visible_content",
    "has_visible_prose",
    "is_js_integer",
    "is_number",
    "js_json_string",
    "js_number_str",
    "js_trim",
    "safe_quote",
    "type_of",
    "utf16_key",
    "utf16_length",
    "utf16_prefix",
]

DEFAULT_ERROR_LIMIT: Final = 100
MAX_DIAGNOSTIC_STRING_LENGTH: Final = 256

# Code point ranges of the Unicode classes that the upstream expressions use. Python's re module
# has no \p{...} classes. The ranges equal Unicode 16.0 (Node.js 22) and Unicode 15.1 (Python
# 3.13) for these properties; tests/unit/test_text.py checks them against unicodedata.
_Ranges = tuple[tuple[int, int], ...]

#: General category Cc (control).
CC_RANGES: Final[_Ranges] = ((0x00, 0x1F), (0x7F, 0x9F))
#: General category Cf (format).
CF_RANGES: Final[_Ranges] = (
    (0xAD, 0xAD),
    (0x600, 0x605),
    (0x61C, 0x61C),
    (0x6DD, 0x6DD),
    (0x70F, 0x70F),
    (0x890, 0x891),
    (0x8E2, 0x8E2),
    (0x180E, 0x180E),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x2064),
    (0x2066, 0x206F),
    (0xFEFF, 0xFEFF),
    (0xFFF9, 0xFFFB),
    (0x110BD, 0x110BD),
    (0x110CD, 0x110CD),
    (0x13430, 0x1343F),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0001, 0xE0001),
    (0xE0020, 0xE007F),
)
#: General category Cs (surrogate).
CS_RANGES: Final[_Ranges] = ((0xD800, 0xDFFF),)
#: General categories Zl (line separator) and Zp (paragraph separator).
ZL_RANGES: Final[_Ranges] = ((0x2028, 0x2028),)
ZP_RANGES: Final[_Ranges] = ((0x2029, 0x2029),)
#: Binary property White_Space.
WHITE_SPACE_RANGES: Final[_Ranges] = (
    (0x09, 0x0D),
    (0x20, 0x20),
    (0x85, 0x85),
    (0xA0, 0xA0),
    (0x1680, 0x1680),
    (0x2000, 0x200A),
    (0x2028, 0x2029),
    (0x202F, 0x202F),
    (0x205F, 0x205F),
    (0x3000, 0x3000),
)
#: Derived property Default_Ignorable_Code_Point (4174 code points).
DEFAULT_IGNORABLE_RANGES: Final[_Ranges] = (
    (0xAD, 0xAD),
    (0x34F, 0x34F),
    (0x61C, 0x61C),
    (0x115F, 0x1160),
    (0x17B4, 0x17B5),
    (0x180B, 0x180F),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x206F),
    (0x3164, 0x3164),
    (0xFE00, 0xFE0F),
    (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0),
    (0xFFF0, 0xFFF8),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0000, 0xE0FFF),
)
#: The JavaScript WhiteSpace and LineTerminator characters (``\s`` and ``trim``).
JS_WHITESPACE_RANGES: Final[_Ranges] = (
    (0x09, 0x0D),
    (0x20, 0x20),
    (0xA0, 0xA0),
    (0x1680, 0x1680),
    (0x2000, 0x200A),
    (0x2028, 0x2029),
    (0x202F, 0x202F),
    (0x205F, 0x205F),
    (0x3000, 0x3000),
    (0xFEFF, 0xFEFF),
)


def _class_body(*tables: _Ranges) -> str:
    """Return a regular-expression class body (escaped code points) for the given ranges."""
    parts = []
    for table in tables:
        for low, high in table:
            first = f"\\U{low:08x}"
            parts.append(first if low == high else f"{first}-\\U{high:08x}")
    return "".join(parts)


#: Port of ``/[^\p{White_Space}\p{Cc}\p{Cf}\p{Default_Ignorable_Code_Point}]/u``.
VISIBLE_CONTENT: Final = re.compile(
    f"[^{_class_body(WHITE_SPACE_RANGES, CC_RANGES, CF_RANGES, DEFAULT_IGNORABLE_RANGES)}]"
)
#: Port of ``/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}]/u``.
PATH_FORBIDDEN_CHARACTER: Final = re.compile(
    f"[{_class_body(CC_RANGES, CF_RANGES, ZL_RANGES, ZP_RANGES, DEFAULT_IGNORABLE_RANGES)}]"
)
#: Port of ``/[\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}]/gu``.
UNSAFE_DIAGNOSTIC_CHARACTER: Final = re.compile(
    "["
    + _class_body(CC_RANGES, CF_RANGES, CS_RANGES, ZL_RANGES, ZP_RANGES, DEFAULT_IGNORABLE_RANGES)
    + "]"
)
#: ``\p{White_Space}``.
WHITE_SPACE: Final = re.compile(f"[{_class_body(WHITE_SPACE_RANGES)}]")
#: ``\p{Default_Ignorable_Code_Point}``.
DEFAULT_IGNORABLE_CODE_POINT: Final = re.compile(f"[{_class_body(DEFAULT_IGNORABLE_RANGES)}]")
#: The JavaScript ``\s`` class (WhiteSpace and LineTerminator).
JS_WHITESPACE: Final = re.compile(f"[{_class_body(JS_WHITESPACE_RANGES)}]")
#: The characters that ``String.prototype.trim`` removes, as one string.
JS_WHITESPACE_CHARACTERS: Final = "".join(
    chr(code) for low, high in JS_WHITESPACE_RANGES for code in range(low, high + 1)
)
_SURROGATE: Final = re.compile(f"[{_class_body(CS_RANGES)}]")


class _Undefined:
    """The JavaScript ``undefined`` value: the result of reading a missing property."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "undefined"

    def __bool__(self) -> bool:
        return False

    def __reduce__(self) -> str:
        # copy, deepcopy and pickle return the module-level singleton.
        return "UNDEFINED"


#: Stands for the JavaScript ``undefined`` value (a missing property) in ported checks.
UNDEFINED: Final = _Undefined()


def has_valid_unicode_scalar_values(value: str) -> bool:
    """Return True when ``value`` holds no surrogate code point (port of
    ``hasValidUnicodeScalarValues``)."""
    return _SURROGATE.search(value) is None


def has_visible_content(value: str) -> bool:
    """Return True when ``value`` holds a character outside White_Space, Cc, Cf and
    Default_Ignorable_Code_Point (port of ``VISIBLE_CONTENT.test``)."""
    return VISIBLE_CONTENT.search(value) is not None


def has_visible_prose(value: object) -> bool:
    """Return True for a string with valid scalar values and visible content (port of
    ``hasVisibleProse``). A non-string value is never visible prose."""
    return (
        isinstance(value, str)
        and has_valid_unicode_scalar_values(value)
        and has_visible_content(value)
    )


def js_trim(value: str) -> str:
    """Return ``value.trim()`` with the JavaScript whitespace set."""
    return value.strip(JS_WHITESPACE_CHARACTERS)


def utf16_length(value: str) -> int:
    """Return the JavaScript ``length`` of ``value`` (UTF-16 code units)."""
    return len(value.encode("utf-16-le", "surrogatepass")) // 2


def utf16_key(value: str) -> bytes:
    """Return a sort key that orders strings like JavaScript ``<`` (UTF-16 code units)."""
    return value.encode("utf-16-be", "surrogatepass")


def utf16_prefix(value: str, limit: int) -> str:
    """Return ``value.slice(0, limit)`` with JavaScript semantics.

    When the cut falls inside a surrogate pair, JavaScript keeps the high surrogate as a lone
    surrogate. This function does the same.
    """
    units = 0
    for index, character in enumerate(value):
        code = ord(character)
        width = 2 if code > 0xFFFF else 1
        if units + width > limit:
            if width == 2 and units + 1 == limit:
                return value[:index] + chr(0xD800 + ((code - 0x10000) >> 10))
            return value[:index]
        units += width
    return value


def _escape_surrogate(match: re.Match[str]) -> str:
    return f"\\u{ord(match.group()):04x}"


def js_json_string(value: str) -> str:
    """Return ``JSON.stringify(value)`` for a string.

    The result equals ``json.dumps(value, ensure_ascii=False)``, except that a lone surrogate is
    written as a lower-case ``\\uXXXX`` escape, as in JavaScript.
    """
    return _SURROGATE.sub(_escape_surrogate, json.dumps(value, ensure_ascii=False))


_EXACT_INTEGER_LIMIT: Final = 10**21


def js_number_str(value: int | float) -> str:
    """Return ``String(value)`` for a JavaScript number.

    Python and JavaScript both print the shortest digit string that round-trips. They differ in
    the layout: JavaScript prints ``1`` for ``1.0``, ``1e+21`` and ``1e-7``, and switches to
    exponent notation only at ``1e21`` and below ``1e-6``.
    """
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        if -_EXACT_INTEGER_LIMIT < value < _EXACT_INTEGER_LIMIT:
            return str(value)
        try:
            value = float(value)
        except OverflowError:
            return "Infinity" if value > 0 else "-Infinity"
    if math.isnan(value):
        return "NaN"
    if math.isinf(value):
        return "Infinity" if value > 0 else "-Infinity"
    if value == 0:
        return "0"
    sign = "-" if value < 0 else ""
    mantissa, _, exponent_text = repr(abs(value)).partition("e")
    whole, _, fraction = mantissa.partition(".")
    digits = (whole + fraction).lstrip("0")
    stripped = digits.rstrip("0")
    exponent = int(exponent_text or "0") - len(fraction) + (len(digits) - len(stripped))
    digits = stripped
    count = len(digits)
    point = count + exponent
    if count <= point <= 21:
        text = digits + "0" * (point - count)
    elif 0 < point <= 21:
        text = f"{digits[:point]}.{digits[point:]}"
    elif -6 < point <= 0:
        text = "0." + "0" * (-point) + digits
    else:
        power = point - 1
        mark = "+" if power >= 0 else "-"
        head = digits if count == 1 else f"{digits[0]}.{digits[1:]}"
        text = f"{head}e{mark}{abs(power)}"
    return sign + text


def is_number(value: object) -> bool:
    """Return True for a JavaScript number (``int`` or ``float``, but not ``bool``)."""
    return isinstance(value, int | float) and not isinstance(value, bool)


def is_js_integer(value: object) -> bool:
    """Return ``Number.isInteger(value)``: an integral, finite number that is not a ``bool``."""
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return True
    return isinstance(value, float) and math.isfinite(value) and value.is_integer()


def _is_finite_number(value: object) -> bool:
    if not is_number(value):
        return False
    if isinstance(value, int):
        try:
            float(value)
        except OverflowError:
            return False
        return True
    return math.isfinite(value)


def type_of(value: object) -> str:
    """Return the JSON type name of ``value`` (port of ``typeOf``).

    The names are ``null``, ``boolean``, ``number``, ``string``, ``array`` and ``object``, plus
    ``undefined`` for :data:`UNDEFINED`. A value that JSON cannot hold gets its Python type name.
    """
    if value is None:
        return "null"
    if value is UNDEFINED:
        return "undefined"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int | float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return type(value).__name__


def _escape_character(match: re.Match[str]) -> str:
    code = ord(match.group())
    return f"\\u{code:04x}" if code <= 0xFFFF else f"\\u{{{code:x}}}"


def escape_unsafe_diagnostic_characters(value: object) -> str:
    """Replace control, format, surrogate, separator and default-ignorable characters with
    ``\\uXXXX`` (or ``\\u{XXXXX}``) text (port of ``escapeUnsafeDiagnosticCharacters``)."""
    text = value if isinstance(value, str) else str(value)
    return UNSAFE_DIAGNOSTIC_CHARACTER.sub(_escape_character, text)


def safe_quote(value: object) -> str:
    """Quote an input-derived value for a diagnostic (port of ``safeQuote``).

    A string longer than 256 UTF-16 code units is clipped and gets ``...``. The result never
    holds a raw control, format or separator character.
    """
    if isinstance(value, str):
        if utf16_length(value) > MAX_DIAGNOSTIC_STRING_LENGTH:
            value = utf16_prefix(value, MAX_DIAGNOSTIC_STRING_LENGTH) + "..."
        serialized = js_json_string(value)
    elif value is None:
        serialized = "null"
    elif isinstance(value, bool):
        serialized = "true" if value else "false"
    elif _is_finite_number(value):
        serialized = js_number_str(value)
    else:
        serialized = f'"<{type_of(value)}>"'
    return escape_unsafe_diagnostic_characters(serialized)


class ErrorList(list[str]):
    """A list of diagnostics with a size cap (port of ``createErrorList``).

    :meth:`push` escapes every message and drops messages beyond the cap. ``append`` and
    ``extend`` go through :meth:`push`.
    """

    __slots__ = ("limit",)

    def __init__(self, limit: int = DEFAULT_ERROR_LIMIT) -> None:
        super().__init__()
        self.limit = limit

    @property
    def full(self) -> bool:
        """True when the list holds ``limit`` messages."""
        return len(self) >= self.limit

    def push(self, *messages: str) -> int:
        """Add escaped messages up to the cap and return the new length."""
        remaining = self.limit - len(self)
        for message in messages[: max(remaining, 0)]:
            super().append(escape_unsafe_diagnostic_characters(message))
        return len(self)

    def append(self, message: str) -> None:
        """Add one message (see :meth:`push`)."""
        self.push(message)

    def extend(self, messages: Iterable[str]) -> None:
        """Add messages (see :meth:`push`)."""
        self.push(*messages)
