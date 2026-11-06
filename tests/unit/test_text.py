# SPDX-License-Identifier: MIT
"""Tests for kalkan.util.text: Unicode tables, JavaScript string semantics and diagnostics."""

from __future__ import annotations

import json
import unicodedata

import pytest

from kalkan.util import text
from kalkan.util.text import (
    CC_RANGES,
    CF_RANGES,
    CS_RANGES,
    DEFAULT_IGNORABLE_CODE_POINT,
    DEFAULT_IGNORABLE_RANGES,
    JS_WHITESPACE,
    JS_WHITESPACE_CHARACTERS,
    JS_WHITESPACE_RANGES,
    PATH_FORBIDDEN_CHARACTER,
    UNDEFINED,
    UNSAFE_DIAGNOSTIC_CHARACTER,
    VISIBLE_CONTENT,
    WHITE_SPACE,
    WHITE_SPACE_RANGES,
    ZL_RANGES,
    ZP_RANGES,
    ErrorList,
    escape_unsafe_diagnostic_characters,
    has_valid_unicode_scalar_values,
    has_visible_content,
    has_visible_prose,
    is_js_integer,
    is_number,
    js_json_string,
    js_number_str,
    js_trim,
    safe_quote,
    type_of,
    utf16_key,
    utf16_length,
    utf16_prefix,
)

LONE_HIGH = "\U0000d800"
LONE_LOW = "\U0000dc00"
EMOJI = "\U0001f600"
SUPPORTED_UNICODE = unicodedata.unidata_version in ("15.1.0", "16.0.0")


def expand(*tables: tuple[tuple[int, int], ...]) -> set[int]:
    codes: set[int] = set()
    for table in tables:
        for low, high in table:
            codes.update(range(low, high + 1))
    return codes


@pytest.fixture(scope="module")
def all_characters() -> str:
    return "".join(chr(code) for code in range(0x110000))


@pytest.fixture(scope="module")
def categories() -> dict[str, set[int]]:
    wanted = {"Cc", "Cf", "Cs", "Zl", "Zp", "Zs"}
    found: dict[str, set[int]] = {name: set() for name in wanted}
    for code in range(0x110000):
        category = unicodedata.category(chr(code))
        if category in wanted:
            found[category].add(code)
    return found


def matched(pattern, characters: str) -> set[int]:
    return {ord(match.group()) for match in pattern.finditer(characters)}


@pytest.mark.skipif(not SUPPORTED_UNICODE, reason="tables are pinned to Unicode 15.1 and 16.0")
def test_category_tables_match_unicodedata(categories):
    assert expand(CC_RANGES) == categories["Cc"]
    assert expand(CF_RANGES) == categories["Cf"]
    assert expand(CS_RANGES) == categories["Cs"]
    assert expand(ZL_RANGES) == categories["Zl"]
    assert expand(ZP_RANGES) == categories["Zp"]


def test_white_space_tables_follow_their_definitions(categories):
    separators = categories["Zs"] | categories["Zl"] | categories["Zp"]
    assert expand(WHITE_SPACE_RANGES) == separators | set(range(0x09, 0x0E)) | {0x85}
    javascript = categories["Zs"] | set(range(0x09, 0x0E)) | {0x2028, 0x2029, 0xFEFF}
    assert expand(JS_WHITESPACE_RANGES) == javascript
    assert {ord(character) for character in JS_WHITESPACE_CHARACTERS} == javascript


def test_default_ignorable_table_holds_the_derived_property():
    ignorable = expand(DEFAULT_IGNORABLE_RANGES)
    assert len(ignorable) == 4174
    # Variation selectors, the soft hyphen, the combining grapheme joiner and the fillers.
    for code in (0xAD, 0x34F, 0x115F, 0x3164, 0xFFA0, 0x180B, 0x180F, 0xFE00, 0xFE0F):
        assert code in ignorable, hex(code)
    assert set(range(0xE0000, 0xE1000)) <= ignorable
    # Format characters, except the visible ones that the derivation removes.
    visible_format = {0x600, 0x601, 0x602, 0x603, 0x604, 0x605, 0x6DD, 0x70F, 0x890, 0x891}
    visible_format |= {0x8E2, 0x110BD, 0x110CD, 0xFFF9, 0xFFFA, 0xFFFB}
    visible_format |= set(range(0x13430, 0x13440))
    assert expand(CF_RANGES) - visible_format <= ignorable
    assert not visible_format & ignorable
    assert not expand(WHITE_SPACE_RANGES) & ignorable


def test_patterns_combine_the_tables(all_characters):
    every = set(range(0x110000))
    ws, cc, cf = expand(WHITE_SPACE_RANGES), expand(CC_RANGES), expand(CF_RANGES)
    di, cs = expand(DEFAULT_IGNORABLE_RANGES), expand(CS_RANGES)
    zl, zp = expand(ZL_RANGES), expand(ZP_RANGES)
    assert matched(VISIBLE_CONTENT, all_characters) == every - (ws | cc | cf | di)
    assert matched(PATH_FORBIDDEN_CHARACTER, all_characters) == cc | cf | zl | zp | di
    assert matched(UNSAFE_DIAGNOSTIC_CHARACTER, all_characters) == cc | cf | cs | zl | zp | di
    assert matched(WHITE_SPACE, all_characters) == ws
    assert matched(DEFAULT_IGNORABLE_CODE_POINT, all_characters) == di
    assert matched(JS_WHITESPACE, all_characters) == expand(JS_WHITESPACE_RANGES)


def test_module_source_is_ascii():
    # Invisible or bidirectional characters in source code are a review hazard.
    assert open(text.__file__, "rb").read().isascii()


def test_visible_prose_matches_the_upstream_corpus():
    corpus = {
        "Valid prose.": True,
        "caf\U000000e9": True,
        "": False,
        " \t\r\n": False,
        "\U0000200b": False,
        "\U0000034f": False,
        "\U0000fe0f": False,
        LONE_HIGH: False,
        LONE_LOW: False,
        "visible" + LONE_HIGH: False,
    }
    for value, expected in corpus.items():
        assert has_visible_prose(value) is expected, ascii(value)
    assert has_visible_prose(None) is False
    assert has_visible_content("visible" + LONE_HIGH) is True
    assert has_valid_unicode_scalar_values("Finding " + EMOJI) is True
    assert has_valid_unicode_scalar_values(LONE_LOW) is False


def test_js_trim_uses_the_javascript_whitespace_set():
    assert js_trim(" \t\U0000feffvalue\U00003000\n") == "value"
    # JavaScript does not trim NEL or the information separators; Python's strip() does.
    assert js_trim("value\x85") == "value\x85"
    assert js_trim("\x1fvalue") == "\x1fvalue"
    assert "value\x85".strip() == "value"


def test_utf16_semantics():
    assert utf16_length("abc") == 3
    assert utf16_length(EMOJI) == 2
    assert utf16_length(LONE_HIGH) == 1
    # JavaScript orders UTF-16 code units: an astral character sorts before U+FF61.
    assert sorted(["b", "\U0000ff61", EMOJI, "a"], key=utf16_key) == [
        "a",
        "b",
        EMOJI,
        "\U0000ff61",
    ]
    assert utf16_prefix("ab" + EMOJI + "c", 3) == "ab\U0000d83d"  # high surrogate of U+1F600
    assert utf16_prefix("ab" + EMOJI + "c", 4) == "ab" + EMOJI
    assert utf16_prefix("abc", 10) == "abc"


def test_js_json_string_matches_json_stringify():
    value = "a\x00\x07\b\t\n\x0b\f\r\x1f\x7f\x85\U00002028" + LONE_HIGH + '"\\'
    expected = '"a\\u0000\\u0007\\b\\t\\n\\u000b\\f\\r\\u001f\x7f\x85\U00002028\\ud800\\"\\\\"'
    assert js_json_string(value) == expected
    assert json.loads(js_json_string(value)) == value


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (1, "1"),
        (1.5, "1.5"),
        (100.0, "100"),
        (1e21, "1e+21"),
        (1e20, "100000000000000000000"),
        (0.000001, "0.000001"),
        (1e-7, "1e-7"),
        (123.456, "123.456"),
        (5e-324, "5e-324"),
        (1.7976931348623157e308, "1.7976931348623157e+308"),
        (-0.0, "0"),
        (-2.5, "-2.5"),
        (0.1 + 0.2, "0.30000000000000004"),
        (123456789012345680000.0, "123456789012345680000"),
        (2.0**53, "9007199254740992"),
        (10**21, "1e+21"),
        (10**400, "Infinity"),
        (float("nan"), "NaN"),
        (float("-inf"), "-Infinity"),
    ],
)
def test_js_number_str_matches_javascript(value, expected):
    # Expected values come from String(value) in Node.js 22.
    assert js_number_str(value) == expected


def test_safe_quote_clips_quotes_and_escapes():
    assert safe_quote("x" * 256) == '"' + "x" * 256 + '"'
    assert safe_quote("x" * 257) == '"' + "x" * 256 + '..."'
    assert safe_quote("x" * 255 + EMOJI) == '"' + "x" * 255 + '\\ud83d..."'
    assert safe_quote(None) == "null"
    assert safe_quote(True) == "true"
    assert safe_quote(3) == "3"
    assert safe_quote(2.0) == "2"
    assert safe_quote(float("nan")) == '"<number>"'
    assert safe_quote(10**400) == '"<number>"'
    assert safe_quote([1]) == '"<array>"'
    assert safe_quote({}) == '"<object>"'
    assert safe_quote(UNDEFINED) == '"<undefined>"'
    assert safe_quote(("tuple",)) == '"<tuple>"'
    assert safe_quote("a\x1b\U0000202e") == '"a\\u001b\\u202e"'


def test_escape_unsafe_diagnostic_characters():
    raw = "a\x1b\x07\x85\U0000202e\U0000034f\U0000fe0f\U000e0001" + LONE_HIGH + "\U00002028b"
    escaped = escape_unsafe_diagnostic_characters(raw)
    assert escaped == ("a\\u001b\\u0007\\u0085\\u202e\\u034f\\ufe0f\\u{e0001}\\ud800\\u2028b")
    assert escaped.isascii()
    assert escape_unsafe_diagnostic_characters(42) == "42"
    assert escape_unsafe_diagnostic_characters("caf\U000000e9 " + EMOJI) == (
        "caf\U000000e9 " + EMOJI
    )


def test_type_and_number_helpers():
    assert [type_of(value) for value in (None, True, 1, 1.5, "s", [], {}, UNDEFINED)] == [
        "null",
        "boolean",
        "number",
        "number",
        "string",
        "array",
        "object",
        "undefined",
    ]
    assert type_of((1,)) == "tuple"
    assert is_js_integer(3) and is_js_integer(3.0) and is_js_integer(10**30)
    assert not is_js_integer(True)
    assert not is_js_integer(3.5)
    assert not is_js_integer(float("inf"))
    assert not is_js_integer("3")
    assert is_number(0) and is_number(0.5) and not is_number(False)
    assert repr(UNDEFINED) == "undefined" and not UNDEFINED


def test_undefined_stays_a_singleton():
    import copy
    import pickle

    assert copy.copy(UNDEFINED) is UNDEFINED
    assert copy.deepcopy({"missing": UNDEFINED})["missing"] is UNDEFINED
    assert pickle.loads(pickle.dumps(UNDEFINED)) is UNDEFINED


def test_error_list_caps_and_escapes():
    errors = ErrorList(3)
    assert errors.push("one\x1b", "two") == 2
    errors.append("three")
    errors.extend(["four", "five"])
    assert errors == ["one\\u001b", "two", "three"]
    assert errors.full
    assert errors.push("six") == 3
    assert isinstance(errors, list)
