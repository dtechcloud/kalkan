# SPDX-License-Identifier: MIT
"""Tests for kalkan.schema.validator and kalkan.schema.loader.

The ported upstream findings tests live in test_findings_validate.py. This module tests the
validator mechanics in more depth: every schema keyword check, the data and text limits,
canonical keys, the JavaScript pattern translation and the schema loader.
"""

from __future__ import annotations

import json
import random
from pathlib import Path

import pytest

from kalkan.errors import KalkanError, ValidationError
from kalkan.schema import loader, validator
from kalkan.schema.loader import load_schema, shared_schema
from kalkan.schema.validator import (
    LIMITS,
    SUPPORTED_KEYWORDS,
    CanonicalKeyError,
    JsonStructureError,
    PatternSyntaxError,
    canonical_key,
    check_schema,
    collect_data_limit_errors,
    compile_pattern,
    deep_equal,
    enforce_json_text_limits,
    parse_json_text,
    property_path,
    validate,
)
from kalkan.util.text import JS_WHITESPACE_CHARACTERS

REPOSITORY = Path(__file__).resolve().parents[2]
UPSTREAM_SCHEMA = (
    REPOSITORY / "third_party/security-audit-skill/skills/security-audit/report-schema.json"
)
BS = "\\"
EMOJI = "\U0001f600"


def nested_arrays(levels: int) -> object:
    value: object = 0
    for _ in range(levels):
        value = [value]
    return value


def nested_objects(levels: int) -> object:
    value: object = 0
    for _ in range(levels):
        value = {"child": value}
    return value


# --- check_schema ---------------------------------------------------------------------------


def test_supported_keywords_match_upstream():
    assert SUPPORTED_KEYWORDS == {
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


@pytest.mark.parametrize(
    ("schema", "message"),
    [
        ({"type": "string", "format": "uuid"}, 'schema: unsupported schema keyword "format"'),
        ({"type": "array", "maxItems": 1}, 'schema: unsupported schema keyword "maxItems"'),
        ([], "schema: schema must be an object"),
        ({"$comment": 1}, "schema.$comment: expected string"),
        ({"description": None}, "schema.description: expected string"),
        ({"type": "date"}, 'schema.type: unsupported type "date"'),
        ({"type": ["string", "null"]}, 'schema.type: unsupported type "<array>"'),
        ({"properties": []}, "schema.properties: expected object"),
        ({"properties": {"a b": 1}}, 'schema.properties["a b"]: schema must be an object'),
        ({"required": "a"}, "schema.required: expected an array of strings"),
        ({"required": ["a", 1]}, "schema.required: expected an array of strings"),
        ({"required": ["a", "a"]}, "schema.required: entries must be unique"),
        (
            {"additionalProperties": {"type": "string"}},
            "schema.additionalProperties: only boolean values are supported",
        ),
        ({"enum": []}, "schema.enum: expected a non-empty array"),
        ({"enum": [{"a": 1, "b": 2}, {"b": 2, "a": 1}]}, "schema.enum: entries must be unique"),
        ({"enum": [1, 1.0]}, "schema.enum: entries must be unique"),
        ({"items": [{"type": "string"}]}, "schema.items: schema must be an object"),
        ({"minItems": -1}, "schema.minItems: expected a non-negative integer"),
        ({"minLength": 1.5}, "schema.minLength: expected a non-negative integer"),
        ({"minLength": True}, "schema.minLength: expected a non-negative integer"),
        ({"minimum": "1"}, "schema.minimum: expected a finite number"),
        ({"minimum": float("nan")}, "schema.minimum: expected a finite number"),
        ({"pattern": 1}, "schema.pattern: expected string"),
        ({"type": "string", "pattern": "["}, "schema.pattern: invalid regular expression"),
        ({"uniqueItems": "true"}, "schema.uniqueItems: expected boolean"),
        ({"type": "string", "visibleContent": "yes"}, "schema.visibleContent: expected boolean"),
        (
            {"type": "array", "visibleContent": True},
            'schema.visibleContent: requires type "string"',
        ),
        ({"oneOf": []}, "schema.oneOf: expected a non-empty array"),
        ({"oneOf": [{"type": "string"}, 3]}, "schema.oneOf[1]: schema must be an object"),
    ],
)
def test_check_schema_reports_each_malformed_keyword(schema, message):
    assert message in check_schema(schema)


def test_check_schema_accepts_valid_schemas():
    assert check_schema({"type": "string", "visibleContent": False}) == []
    assert check_schema({"minLength": 2.0, "minimum": 0, "enum": [1, "1", True, None]}) == []
    assert check_schema(load_schema("finding")) == []
    assert check_schema(load_schema("candidate")) == []


def test_check_schema_reports_nested_paths_and_caps_errors():
    errors = check_schema({"properties": {"title": {"minLength": -1}}})
    assert errors == ["schema.properties.title.minLength: expected a non-negative integer"]
    many = {f"x{index}": 1 for index in range(150)}
    assert len(check_schema(many)) == LIMITS.validation_errors


def test_check_schema_survives_a_cyclic_schema():
    schema: dict = {"type": "object", "properties": {}}
    schema["properties"]["self"] = schema
    errors = check_schema(schema)
    assert any("schema exceeds 64 level nesting depth limit" in error for error in errors)


# --- validate ---------------------------------------------------------------------------------


def test_validate_reports_schema_errors_first():
    assert validate([], {"type": "array", "maxItems": 1}) == [
        'schema: unsupported schema keyword "maxItems"'
    ]


def test_one_of_needs_exactly_one_branch_and_uses_the_discriminator():
    assert validate("value", {"oneOf": [{"type": "string"}, {"minLength": 1}]}, "$t") == [
        "$t: must match exactly one schema in oneOf; matched 2"
    ]
    schema = {
        "oneOf": [
            {"type": "object", "properties": {"kind": {"const": "a"}, "x": {"type": "string"}}},
            {"type": "object", "properties": {"kind": {"const": "b"}, "x": {"type": "number"}}},
        ]
    }
    assert validate({"kind": "a", "x": "text"}, schema) == []
    assert validate({"kind": "a", "x": 1}, schema) == [
        "$data: must match exactly one schema in oneOf; matched 0",
        "$data.x: expected string, got number",
    ]
    # Without a matching discriminator, the branch errors stay hidden.
    assert validate({"kind": "c"}, schema) == [
        "$data: must match exactly one schema in oneOf; matched 0"
    ]


def test_type_const_and_enum_messages():
    assert validate(2.0, {"type": "integer"}) == []
    assert validate(2.5, {"type": "integer"}) == ["$data: expected integer, got number"]
    assert validate(True, {"type": "integer"}) == ["$data: expected integer, got boolean"]
    assert validate(1, {"type": "boolean"}) == ["$data: expected boolean, got number"]
    assert validate(None, {"type": "object"}) == ["$data: expected object, got null"]
    assert validate("b", {"const": "a"}) == ['$data: must equal "a", got "b"']
    assert validate(True, {"const": 1}) == ["$data: must equal 1, got true"]
    assert validate(1.0, {"const": 1}) == []
    assert validate("x", {"enum": ["a", 1, None]}) == [
        '$data: invalid value "x" (expected one of "a", 1, null)'
    ]


def test_object_array_string_and_number_messages():
    schema = {
        "type": "object",
        "properties": {"a": {"type": "string"}},
        "required": ["a", "b"],
        "additionalProperties": False,
    }
    assert validate({"a": "x", "c": 1}, schema) == [
        '$data: missing required field "b"',
        '$data: unexpected field "c"',
    ]
    assert validate([], {"type": "array", "minItems": 2}) == [
        "$data: must have at least 2 item(s), got 0"
    ]
    assert validate("", {"type": "string", "minLength": 1}) == [
        "$data: must have at least 1 character(s)"
    ]
    assert validate(EMOJI, {"type": "string", "minLength": 1}) == []
    assert validate(EMOJI, {"type": "string", "minLength": 2}) != []
    assert validate("a\nb", {"type": "string", "pattern": "^a$"}) == [
        '$data: must match pattern "^a$"'
    ]
    assert validate(0.5, {"type": "number", "minimum": 1}) == ["$data: must be at least 1, got 0.5"]
    assert validate(" \t", {"type": "string", "visibleContent": True}) == [
        "$data: must contain a visible character"
    ]
    assert validate("x\U0000d800", {"type": "string", "visibleContent": True}) == [
        "$data: must contain only valid Unicode scalar values"
    ]


def test_unique_items_use_canonical_keys():
    schema = {"type": "array", "uniqueItems": True}
    assert validate([{"a": 1, "b": 2}, {"b": 2, "a": 1}], schema) == [
        "$data: items must be unique; duplicate at index 1"
    ]
    assert validate([1, 1.0], schema) == ["$data: items must be unique; duplicate at index 1"]
    assert validate([1, True, "1", None, [1], {"1": 1}], schema) == []


def test_error_output_is_capped():
    schema = {"type": "array", "items": {"type": "string"}}
    assert len(validate(list(range(1000)), schema)) == LIMITS.validation_errors


def test_property_path_quotes_non_identifier_keys():
    assert property_path("$", "title") == "$.title"
    assert property_path("$", "a-b") == '$["a-b"]'
    assert property_path("$", "x\n") == '$["x\\n"]'
    assert property_path("$", "x\x1b") == '$["x\\u001b"]'
    assert property_path("$", 7) == '$["7"]'


# --- data limits ------------------------------------------------------------------------------


def test_data_limits_on_nesting_depth():
    assert collect_data_limit_errors(nested_arrays(64)) == []
    assert collect_data_limit_errors(nested_arrays(65)) == [
        "$data" + "[0]" * 64 + ": exceeds 64 level nesting depth limit"
    ]
    assert collect_data_limit_errors(nested_objects(64), "$") == []
    errors = collect_data_limit_errors(nested_objects(65), "$")
    assert errors == ["$" + ".child" * 64 + ": exceeds 64 level nesting depth limit"]
    deep = nested_arrays(20000)
    assert collect_data_limit_errors(deep) != []


def test_data_limits_on_array_size():
    assert collect_data_limit_errors([None] * 1000) == []
    assert collect_data_limit_errors({"list": [None] * 1001}) == [
        "$data.list: exceeds 1000 item array limit"
    ]


def test_data_limits_reject_repeated_and_cyclic_references():
    shared = {"a": 1}
    assert collect_data_limit_errors([shared, shared]) == [
        "$data[1]: input must not contain repeated or cyclic object references"
    ]
    cyclic: dict = {}
    cyclic["key with space"] = cyclic
    assert collect_data_limit_errors(cyclic, "$input") == [
        '$input["key with space"]: input must not contain repeated or cyclic object references'
    ]
    assert validate(cyclic, {"type": "object"}) != []


# --- canonical keys and equality --------------------------------------------------------------


def test_canonical_key_format_and_equality():
    key, size = canonical_key({"b": 1, "a": [True, None, "x"]})
    assert key == 'object:{"a":array:[boolean:true,null,string:"x"],"b":number:1}'
    assert size == len(key.encode())
    assert canonical_key(-0.0)[0] == canonical_key(0)[0] == "number:0"
    assert canonical_key(1)[0] == canonical_key(1.0)[0]
    assert canonical_key(True)[0] != canonical_key(1)[0]
    assert canonical_key("\U0000d800")[0] == 'string:"\\ud800"'


def test_canonical_key_limits():
    with pytest.raises(CanonicalKeyError, match="canonical key exceeds 1048576 byte limit"):
        canonical_key("x" * (1024 * 1024))
    cyclic: list = []
    cyclic.append(cyclic)
    with pytest.raises(CanonicalKeyError):
        canonical_key(cyclic)


def test_deep_equal_follows_javascript_values():
    assert deep_equal({"a": [1, {"b": None}]}, {"a": [1.0, {"b": None}]})
    assert not deep_equal({"a": 1}, {"a": 1, "b": 2})
    assert not deep_equal(True, 1)
    assert not deep_equal([1], {"0": 1})
    assert not deep_equal(float("nan"), float("nan") + 0)


# --- JavaScript patterns ----------------------------------------------------------------------


PATTERN_CASES = [
    (r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$", ["abc", "a:b/c@d+e-f"], ["abc\n", "a b", "-a"]),
    (r"^a.c$", ["abc", "a\x85c"], ["a\nc", "a\rc", "a\U00002028c", "a\U00002029c"]),
    (r"^\s$", ["\U0000feff", "\xa0", "\U00003000", "\t"], ["\x1c", "\x85", "a"]),
    (r"^\S$", ["\x1c", "\x85", "a"], [" ", "\U0000feff"]),
    (r"^[\S]$", ["a"], ["\U00002028"]),
    (r"^\d+$", ["0123"], ["\U00000663"]),
    (r"^\w+$", ["abc_1"], ["caf\U000000e9"]),
    (r"\bfoo\b", ["a foo b", "\U000000e9foo"], ["afoo"]),
    (r"^[\d-z]+$", ["1-z"], ["y"]),
    (r"^a{2}$", ["aa"], ["a", "aaa"]),
    (r"^a{$", ["a{"], ["aa"]),
    (r"^x{,3}$", ["x{,3}"], ["xxx"]),
    (r"^a{2,}?$", ["aaa"], ["a"]),
    (r"^(?<year>\d{4})-\k<year>$", ["2024-2024"], ["2024-2025"]),
    (r"^(a)\1$", ["aa"], ["ab"]),
    (r"^[^]$", ["\n", "a"], ["ab"]),
    (r"[]", [], ["", "a"]),
    (r"^\cJ$", ["\n"], ["cJ"]),
    (r"^\/$", ["/"], [BS + "/"]),
    (r"^\0$", ["\x00"], ["0"]),
    (r"^\x41$", ["A"], ["x41"]),
    ("^" + BS + "u0041$", ["A"], ["u0041"]),
    (r"^\8$", ["8"], []),
    (r"^[\b]$", ["\x08"], ["b"]),
    (r"^a\Z$", ["aZ"], ["a"]),
    (r"^\p{L}$", ["p{L}"], ["a"]),
    (r"^[a-]$", ["a", "-"], ["b"]),
    (r"^[\[\]]$", ["[", "]"], ["a"]),
    (r"^[&&~~||]+$", ["&~|"], ["a"]),
    (r"^(?=a)a$", ["a"], ["b"]),
    (r"^(?:ab|cd)$", ["cd"], ["ac"]),
]


@pytest.mark.parametrize(("pattern", "matches", "rejects"), PATTERN_CASES, ids=ascii)
def test_patterns_follow_javascript_semantics(pattern, matches, rejects):
    compiled = compile_pattern(pattern)
    for value in matches:
        assert compiled.search(value), ascii(value)
    for value in rejects:
        assert not compiled.search(value), ascii(value)


@pytest.mark.parametrize(
    "pattern",
    ["[", "a*+", "a++", "(?i)a", BS, "a**", "{2}", "*a", "a{3,1}", "(?P<x>a)", "(a", "a)", "[z-a]"],
    ids=ascii,
)
def test_invalid_or_untranslatable_patterns_are_rejected(pattern):
    with pytest.raises(PatternSyntaxError):
        compile_pattern(pattern)
    assert check_schema({"type": "string", "pattern": pattern}) == [
        "schema.pattern: invalid regular expression"
    ]


# --- JSON text --------------------------------------------------------------------------------


def reference_text_limits(contents: str, depth_limit: int, item_limit: int) -> None:
    """The upstream enforceJsonTextLimits, ported character by character."""
    containers: list[list] = []
    in_string = escaped = False

    def mark() -> None:
        if containers and containers[-1][0] and containers[-1][1]:
            containers[-1][1] = False
            containers[-1][2] += 1
            if containers[-1][2] > item_limit:
                raise JsonStructureError(f"input exceeds {item_limit} item array limit")

    for character in contents:
        if in_string:
            if escaped:
                escaped = False
            elif character == BS:
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            mark()
            in_string = True
        elif character in "[{":
            mark()
            if len(containers) >= depth_limit:
                raise JsonStructureError(f"input exceeds {depth_limit} level nesting depth limit")
            containers.append([character == "[", character == "[", 0])
        elif character in "]}":
            if containers:
                containers.pop()
        elif character == ",":
            if containers and containers[-1][0]:
                containers[-1][1] = True
        elif character not in JS_WHITESPACE_CHARACTERS:
            mark()


def text_limit_outcome(function, contents: str, depth: int, items: int) -> str | None:
    try:
        function(contents, depth, items)
    except JsonStructureError as exc:
        return str(exc)
    return None


def test_text_limit_scan_equals_the_character_by_character_port():
    generator = random.Random(20261015)
    alphabet = list('[]{},:" \t0ax,,0') + [BS, "\xa0", "\U00002028", "\x85"]
    for _ in range(20000):
        contents = "".join(generator.choice(alphabet) for _ in range(generator.randint(0, 24)))
        depth, items = generator.randint(1, 4), generator.randint(0, 4)
        expected = text_limit_outcome(reference_text_limits, contents, depth, items)
        actual = text_limit_outcome(validator._enforce_json_text_limits, contents, depth, items)
        assert actual == expected, ascii(contents)


def test_text_limits():
    enforce_json_text_limits("[" * 64 + "0" + "]" * 64)
    with pytest.raises(JsonStructureError, match="^input exceeds 64 level nesting depth limit$"):
        enforce_json_text_limits("[" * 65 + "0" + "]" * 65)
    enforce_json_text_limits(json.dumps([None] * 1000))
    with pytest.raises(JsonStructureError, match="^input exceeds 1000 item array limit$"):
        enforce_json_text_limits(json.dumps({"a": [[None] * 1001]}))
    # Structural characters inside strings do not count.
    enforce_json_text_limits(json.dumps(["[" * 100 + '\\"' + "," * 2000]))
    enforce_json_text_limits('["unterminated')


def test_parse_json_text_is_strict():
    assert parse_json_text('{"a": [1, 2.5, "\\ud800"]}') == {"a": [1, 2.5, "\U0000d800"]}
    for bad in ("NaN", "[Infinity]", "[-Infinity]", "\U0000feff[]", "[] []", '["a\x01"]', ""):
        with pytest.raises(JsonStructureError, match="^invalid JSON syntax$"):
            parse_json_text(bad)
    with pytest.raises(JsonStructureError, match="^invalid JSON syntax$"):
        parse_json_text("[" * 100000)


def test_json_structure_error_is_a_validation_error():
    error = JsonStructureError("input exceeds 64 level nesting depth limit")
    assert isinstance(error, ValidationError) and isinstance(error, ValueError)
    assert error.errors == ["input exceeds 64 level nesting depth limit"]


# --- loader -----------------------------------------------------------------------------------


def test_load_schema_returns_private_copies():
    first = load_schema("finding")
    first["items"] = {}
    assert load_schema("finding")["items"] != {}
    assert shared_schema("finding") is shared_schema("finding")
    assert shared_schema("finding") is not load_schema("finding")


def test_load_schema_rejects_bad_names():
    for name in ("../finding", "Finding", "", "finding.schema"):
        with pytest.raises(ValueError):
            load_schema(name)
    with pytest.raises(KalkanError, match="schema not found: missing"):
        load_schema("missing")


def test_loader_checks_the_schema_once(monkeypatch):
    loader._checked_schema.cache_clear()
    calls: list[object] = []
    real_check = loader.check_schema

    def counting_check(schema):
        calls.append(schema)
        return real_check(schema)

    monkeypatch.setattr(loader, "check_schema", counting_check)
    load_schema("candidate")
    load_schema("candidate")
    shared_schema("candidate")
    assert len(calls) == 1
    loader._checked_schema.cache_clear()


def test_finding_schema_keeps_every_upstream_base_rule():
    if not UPSTREAM_SCHEMA.is_file():
        pytest.skip("third_party copy is not available")
    upstream = json.loads(UPSTREAM_SCHEMA.read_text(encoding="utf-8"))
    ours = load_schema("finding")
    assert ours["type"] == upstream["type"] == "array"
    assert len(ours["items"]["oneOf"]) == len(upstream["items"]["oneOf"]) == 3
    for mine, base in zip(ours["items"]["oneOf"], upstream["items"]["oneOf"], strict=True):
        assert mine["required"] == base["required"]
        assert mine["additionalProperties"] is False
        assert mine["description"] == base["description"]
        for name, rule in base["properties"].items():
            assert mine["properties"][name] == rule, name
        added = set(mine["properties"]) - set(base["properties"])
        expected = {"id", "class", "cwe", "owasp", "engines", "candidates", "audit_answers"}
        expected |= {"poc", "sca", "i18n", "review"}
        if base["properties"]["verdict"]["const"] == "confirmed":
            expected.add("cvss")
        if base["properties"]["verdict"]["const"] in ("confirmed", "needs_validation"):
            expected |= {"duplicate_of", "duplicate_reason", "related"}  # consolidation
        assert added == expected


def test_schema_files_are_ascii_json_with_lf():
    package = Path(validator.__file__).resolve().parents[1] / "schemas"
    for name in ("finding", "candidate"):
        data = (package / f"{name}.schema.json").read_bytes()
        assert data.isascii() and data.endswith(b"\n") and b"\r" not in data
