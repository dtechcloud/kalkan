# SPDX-License-Identifier: MIT
# Ported from cloudflare/security-audit-skill@c1c8a8c: skills/security-audit/validate-findings.test.cjs  # noqa: E501
# Copyright (c) 2025-2026 Cloudflare, Inc. Changes: translated from node:test to pytest; the CLI
# tests call validate_findings_file; tests for the kalkan extensions and candidates were added.
"""Tests for kalkan.findings.validate (port of the upstream findings validator tests).

The first part keeps the upstream tests one to one and in the upstream order. Upstream runs the
CLI in a child process; here the same cases call validate_findings_file, which returns the
messages that the upstream CLI prints. The upstream tests that need O_NOFOLLOW and O_NONBLOCK run
on every platform here, because kalkan.util.safe_io does not depend on those flags.
"""

from __future__ import annotations

import copy
import json
import os
from collections.abc import Callable
from dataclasses import fields
from pathlib import Path

import pytest

from kalkan.findings import ledger as ledger_module
from kalkan.findings import validate as findings_module
from kalkan.findings.validate import (
    LIMITS,
    validate_candidate,
    validate_document,
    validate_findings,
    validate_findings_file,
)
from kalkan.schema.loader import load_schema
from kalkan.schema.validator import check_schema, validate
from kalkan.util.safe_io import dumps_json

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "findings"
TERMINAL_CONTROL_PAYLOAD = "\x1b\x07\x85\U0000202e\U0000034f\U0000fe0f"
LONE_HIGH, LONE_LOW = "\U0000d800", "\U0000dc00"

Finding = dict
Mutation = Callable[[Finding], None]


def load_fixture(name: str) -> object:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def source(kind: str = "entrypoint", file: str = "src/handler.c", line: int = 10) -> dict:
    return {
        "kind": kind,
        "file": file,
        "line": line,
        "scope": "handle",
        "description": "Attacker data reaches the operation.",
    }


def evidence(file: str = "src/handler.c", line: int = 10) -> dict:
    return {
        "file": file,
        "line": line,
        "description": "The source performs the operation without the required check.",
    }


def confirmed() -> Finding:
    return load_fixture("confirmed.json")


def needs_validation() -> Finding:
    return load_fixture("needs_validation.json")


def rejected() -> Finding:
    return load_fixture("rejected.json")


def errors_for(value: object) -> list[str]:
    return validate_findings(value)


def write_findings(tmp_path: Path, contents: str | bytes) -> Path:
    path = tmp_path / "findings.json"
    path.write_bytes(contents.encode("utf-8") if isinstance(contents, str) else contents)
    return path


def stringify(value: object) -> str:
    """JSON text like JSON.stringify: non-ASCII stays raw, lone surrogates are escaped."""
    return dumps_json(value)


def assert_no_injected_control_characters(output: str) -> None:
    for marker in TERMINAL_CONTROL_PAYLOAD:
        assert marker not in output, f"found raw control character {ascii(marker)}"


def put(path: str, value: object) -> Mutation:
    """Return a mutation that sets ``path`` (dot-separated keys and list indexes)."""

    def apply(record: Finding) -> None:
        *parents, last = path.split(".")
        target: object = record
        for part in parents:
            target = target[int(part)] if isinstance(target, list) else target[part]
        if isinstance(target, list):
            target[int(last)] = copy.deepcopy(value)
        else:
            target[last] = copy.deepcopy(value)

    return apply


def drop(path: str) -> Mutation:
    def apply(record: Finding) -> None:
        *parents, last = path.split(".")
        target: object = record
        for part in parents:
            target = target[part]
        del target[last]

    return apply


def producer_shaped_findings() -> list[Finding]:
    demonstrated = confirmed()
    demonstrated["conditions"] = [
        {"kind": "authentication_level", "description": "The attacker needs a normal account."}
    ]
    demonstrated["execution"]["payloads"] = [
        "",
        " \t\r\n",
        "\x00\x1f\x7f",
        "\U0000034f",
        "\U0000fe0f",
        LONE_HIGH,
        LONE_LOW,
        '[{,}]\\"',
    ]
    demonstrated["remediation"]["code_changes"] = [{"file_name": "src/handler.c", "fixed_code": ""}]
    blocked = needs_validation()
    del blocked["validation_plan"]["deployment"]
    return [demonstrated, blocked, rejected()]


def reject_mutation(factory: Callable[[], Finding], mutate: Mutation) -> None:
    value = factory()
    mutate(value)
    assert errors_for([value]) != []


def make_symlink(target: Path, link: Path) -> None:
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"cannot create a symlink here: {exc}")


# --- upstream: validate-findings.test.cjs ----------------------------------------------------


def test_schema_is_an_actual_top_level_array_with_exactly_three_branches():
    schema = load_schema("finding")
    assert schema["type"] == "array"
    branches = schema["items"]["oneOf"]
    assert len(branches) == 3
    assert [branch["properties"]["verdict"]["const"] for branch in branches] == [
        "confirmed",
        "needs_validation",
        "rejected",
    ]
    confirmed_schema = branches[0]["properties"]
    assert confirmed_schema["title"]["visibleContent"] is True
    payload_items = confirmed_schema["execution"]["properties"]["payloads"]["items"]
    assert "minLength" not in payload_items
    assert "visibleContent" not in payload_items
    code_change = confirmed_schema["remediation"]["properties"]["code_changes"]["items"]
    assert "minLength" not in code_change["properties"]["fixed_code"]


def test_accepts_a_producer_shaped_findings_document_through_the_file_api(tmp_path):
    findings = producer_shaped_findings()
    assert validate_findings_file(write_findings(tmp_path, stringify(findings))) == []
    assert len(findings) == 3  # upstream prints "PASS: 3 findings valid"


def test_accepts_empty_output_and_each_complete_branch():
    assert errors_for([]) == []
    assert errors_for([confirmed(), needs_validation(), rejected()]) == []
    local_only = needs_validation()
    del local_only["validation_plan"]["deployment"]
    assert errors_for([local_only]) == []
    deployment_only = needs_validation()
    del deployment_only["validation_plan"]["local"]
    assert errors_for([deployment_only]) == []


def test_allows_a_one_line_finding_trace():
    finding = confirmed()
    finding["trace"] = [source("entrypoint")]
    assert errors_for([finding]) == []


def test_rejects_empty_required_content():
    cases = [
        (confirmed, put("title", "")),
        (confirmed, put("title", "   ")),
        (confirmed, put("evidence", [])),
        (confirmed, put("execution.payloads", [])),
        (confirmed, put("execution.instructions", [])),
        (confirmed, put("execution.observed_result", "")),
        (confirmed, put("remediation.strategy", "")),
        (needs_validation, put("blockers", [])),
        (needs_validation, put("validation_plan", {})),
        (needs_validation, put("validation_plan", {"local": " "})),
        (rejected, put("claimed_root_cause", "")),
    ]
    for factory, mutate in cases:
        reject_mutation(factory, mutate)


def test_preserves_exact_payload_and_replacement_code_strings():
    finding = confirmed()
    payloads = ["", " \t\r\n", "\x00\x1f\x7f", "\U0000034f", "\U0000fe0f", LONE_HIGH, LONE_LOW]
    fixed_code = "\x00 \t\r\n\x1f\x7f\U0000034f\U0000fe0f" + LONE_HIGH + "x" + LONE_LOW
    finding["execution"]["payloads"] = list(payloads)
    finding["remediation"]["code_changes"] = [
        {"file_name": "src/handler.c", "fixed_code": fixed_code}
    ]
    assert errors_for([finding]) == []
    assert finding["execution"]["payloads"] == payloads
    assert finding["remediation"]["code_changes"][0]["fixed_code"] == fixed_code


def test_rejects_invalid_scalars_and_whitespace_control_format_or_default_ignorable_prose():
    invisible_values = [
        "\x00\t\r\n\x1f\x7f\U0000200b",
        "\U0000034f",
        "\U0000fe0f",
        LONE_HIGH,
        LONE_LOW,
        "visible" + LONE_HIGH,
    ]
    for invisible in invisible_values:
        cases = [
            (confirmed, put("title", invisible)),
            (confirmed, put("trace.0.scope", invisible)),
            (confirmed, put("evidence.0.description", invisible)),
            (confirmed, put("execution.instructions", [invisible])),
            (confirmed, put("remediation.strategy", invisible)),
            (confirmed, put("severity.impact.reason", invisible)),
            (confirmed, put("confidence.reason", invisible)),
            (needs_validation, put("blockers", [invisible])),
            (needs_validation, put("validation_plan", {"local": invisible})),
            (rejected, put("reason", invisible)),
        ]
        for factory, mutate in cases:
            reject_mutation(factory, mutate)


def test_quotes_input_derived_controls_in_direct_validation_values_and_paths():
    finding = confirmed()
    finding["trace"][0]["kind"] = f"invalid-{TERMINAL_CONTROL_PAYLOAD}"
    finding["execution"][f"extra-{TERMINAL_CONTROL_PAYLOAD}"] = "value"
    cyclic: dict = {}
    cyclic[f"path-{TERMINAL_CONTROL_PAYLOAD}"] = cyclic
    output = "\n".join([*errors_for([finding]), *validate(cyclic, {"type": "object"}, "$input")])
    for escaped in ("\\u001b", "\\u0007", "\\u0085", "\\u202e", "\\u034f", "\\ufe0f"):
        assert escaped in output, f"missing escaped diagnostic {escaped}"
    assert_no_injected_control_characters(output)


def test_rejects_line_zero():
    reject_mutation(confirmed, put("trace.0.line", 0))
    reject_mutation(rejected, put("evidence.0.line", 0))


def test_does_not_treat_inherited_or_object_prototype_properties_as_schema_properties():
    # Python dicts have no prototype chain. The analog: a class attribute is not a key.
    reject_mutation(confirmed, put("constructor", "not allowed"))

    class InheritedVerdict(dict):
        verdict = "confirmed"

    assert any("exactly one" in error for error in errors_for([InheritedVerdict()]))

    class InheritedConstructor(dict):
        constructor = "inherited"

    schema = {
        "type": "object",
        "properties": {"constructor": {"type": "string"}},
        "required": ["constructor"],
        "additionalProperties": False,
    }
    assert any("missing required" in error for error in validate(InheritedConstructor(), schema))


def test_one_of_requires_exactly_one_passing_branch():
    two = validate("value", {"oneOf": [{"type": "string"}, {"minLength": 1}]}, "$test")
    assert any("matched 2" in error for error in two)
    none = validate(7, {"oneOf": [{"type": "string"}, {"minimum": 10}]}, "$test")
    assert any("matched 0" in error for error in none)


def test_rejects_duplicate_fingerprints_and_unique_array_entries():
    first = confirmed()
    second = rejected()
    second["fingerprint"] = first["fingerprint"]
    assert any("duplicate of" in error for error in errors_for([first, second]))
    reject_mutation(
        needs_validation,
        lambda finding: finding.update(blockers=[finding["blockers"][0], finding["blockers"][0]]),
    )


def test_uses_canonical_set_uniqueness_for_structured_entries_at_the_array_limit():
    schema = {"type": "array", "uniqueItems": True}
    entries = [{"id": index, "label": str(index)} for index in range(LIMITS.array_items)]
    assert validate(entries, schema) == []
    duplicate = entries[:-1] + [{"label": "0", "id": 0}]
    expected = f"duplicate at index {LIMITS.array_items - 1}"
    assert any(expected in error for error in validate(duplicate, schema))


def test_bounds_canonical_uniqueness_keys_and_set_storage():
    schema = {"type": "array", "uniqueItems": True}
    oversized_key = "x" * (LIMITS.canonical_key_bytes + 1)
    assert any("canonical key exceeds" in error for error in validate([oversized_key], schema))
    item_length = LIMITS.unique_set_bytes // 6
    large_unique_items = [f"{index}{'x' * item_length}" for index in range(6)]
    errors = validate(large_unique_items, schema)
    assert any("canonical uniqueness set exceeds" in error for error in errors)


def test_requires_findings_to_be_sorted_by_fingerprint():
    first = confirmed()
    second = rejected()
    assert any("sorted lexicographically" in error for error in errors_for([second, first]))


def test_rejects_severity_above_demonstrated_impact():
    def raise_overall(finding: Finding) -> None:
        finding["severity"]["overall_severity"] = "high"
        finding["severity"]["impact"]["score"] = "medium"

    reject_mutation(confirmed, raise_overall)


def test_rejects_unsafe_source_paths():
    bad_paths = [
        "/etc/passwd",
        "../src/file.c",
        "src/../file.c",
        "src//file.c",
        "C:\\src\\file.c",
        "src/file:name.c",
        "src/file\nname.c",
        "src/file\x01name.c",
        "src/file\x85name.c",
        "src/file\U00002028name.c",
        "src/file\U0000202ename.c",
        "src/file\U00002066name.c",
        "src/file\U0000200dname.c",
        "src/file\U0000034fname.c",
        "src/file\U0000fe0fname.c",
        "src/file" + LONE_HIGH + "name.c",
        "src/file" + LONE_LOW + "name.c",
        "CON",
        "src/con.txt",
        "src/PRN",
        "src/AUX.c",
        "src/NUL",
        "src/COM1.log",
        "src/lpt9",
        "src/CONIN$",
        "src/CONOUT$.txt",
        "src/CLOCK$.txt",
        "src/COM\U000000b9.log",
        "src/LPT\U000000b2.log",
        "src /file.c",
        "src./file.c",
        "src/file.c ",
        "src/file.c.",
    ]
    for bad_path in bad_paths:
        reject_mutation(confirmed, put("trace.0.file", bad_path))
    reject_mutation(rejected, put("evidence.0.file", "NUL.txt"))
    reject_mutation(
        confirmed,
        put(
            "remediation.code_changes",
            [{"file_name": "src/file:name.c", "fixed_code": "replacement"}],
        ),
    )


def test_accepts_legitimate_unicode_source_paths_and_prose():
    finding = confirmed()
    finding["title"] = "Finding \U0001f600 cafe\U00000301"
    finding["trace"][0]["file"] = "src/\U000065e5\U0000672c\U00008a9e/cafe\U00000301-\U0001f600.ts"
    finding["evidence"][0]["file"] = (
        "src/ma\U000000f1ana/\U00000444\U00000430\U00000439\U0000043b.ts"
    )
    finding["remediation"]["code_changes"] = [
        {"file_name": "src/\U00004fee\U00006b63/\U000000e9xito.ts", "fixed_code": "replacement"}
    ]
    assert errors_for([finding]) == []


def test_file_api_rejects_input_above_the_byte_limit_without_an_exception_trace(tmp_path):
    path = write_findings(tmp_path, b" " * (LIMITS.input_bytes + 1))
    assert validate_findings_file(path) == [
        f"Failed to read findings JSON: input exceeds {LIMITS.input_bytes} byte limit"
    ]


def test_file_api_rejects_invalid_utf8_without_replacement_or_an_exception_trace(tmp_path):
    findings = producer_shaped_findings()
    findings[0]["execution"]["payloads"] = ["INVALID_UTF8"]
    encoded = stringify(findings).encode("utf-8")
    marker = b"INVALID_UTF8"
    offset = encoded.index(marker)
    malformed = encoded[:offset] + b"\x80" + encoded[offset + len(marker) :]
    assert validate_findings_file(write_findings(tmp_path, malformed)) == [
        "Failed to read findings JSON: input is not valid UTF-8"
    ]


def test_quotes_input_derived_controls_in_file_validation_errors(tmp_path):
    finding = confirmed()
    finding["trace"][0]["kind"] = f"invalid-{TERMINAL_CONTROL_PAYLOAD}"
    finding["execution"][f"extra-{TERMINAL_CONTROL_PAYLOAD}"] = "value"
    errors = validate_findings_file(write_findings(tmp_path, stringify([finding])))
    output = "\n".join(errors)
    assert errors
    assert "$[0].trace[0].kind" in output
    assert "\\u001b" in output
    assert "\\u202e" in output
    assert_no_injected_control_characters(output)


def test_returns_a_generic_syntax_error_without_parser_supplied_controls(tmp_path):
    malformed = b"[" + TERMINAL_CONTROL_PAYLOAD.encode("utf-8") + b"]"
    errors = validate_findings_file(write_findings(tmp_path, malformed))
    assert errors == ["Failed to parse findings JSON: invalid JSON syntax"]
    assert_no_injected_control_characters("\n".join(errors))


def test_does_not_reflect_controls_from_a_failed_input_path(tmp_path):
    missing = tmp_path / f"missing-{TERMINAL_CONTROL_PAYLOAD}.json"
    errors = validate_findings_file(missing)
    assert len(errors) == 1
    assert errors[0].startswith("Failed to read findings JSON:")
    assert_no_injected_control_characters(errors[0])


def test_file_api_rejects_lone_surrogate_prose_without_changing_payload_semantics(tmp_path):
    findings = producer_shaped_findings()
    findings[0]["title"] = LONE_HIGH
    errors = validate_findings_file(write_findings(tmp_path, stringify(findings)))
    assert any("must contain only valid Unicode scalar values" in error for error in errors)
    assert not any("Traceback" in error for error in errors)


def test_file_api_rejects_unicode_format_controls_in_source_paths(tmp_path):
    findings = producer_shaped_findings()
    findings[0]["trace"][0]["file"] = "src/file\U0000202ename.c"
    errors = validate_findings_file(write_findings(tmp_path, stringify(findings)))
    assert any("must be a safe repository-relative source path" in error for error in errors)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="this platform has no FIFOs")
def test_file_api_rejects_a_fifo_without_blocking(tmp_path):
    fifo = tmp_path / "findings.json"
    os.mkfifo(fifo)
    assert validate_findings_file(fifo) == [
        "Failed to read findings JSON: input must be a regular file"
    ]


def test_file_api_rejects_a_symlink_without_following_it(tmp_path):
    target = write_findings(tmp_path, stringify(producer_shaped_findings()))
    link = tmp_path / "link.json"
    make_symlink(target, link)
    assert validate_findings_file(link) == [
        "Failed to read findings JSON: input must not be a symlink"
    ]


def test_file_api_rejects_input_above_the_nesting_depth_limit_without_an_exception_trace(
    tmp_path,
):
    levels = LIMITS.nesting_depth + 1
    path = write_findings(tmp_path, "[" * levels + "0" + "]" * levels)
    assert validate_findings_file(path) == [
        f"Failed to parse findings JSON: input exceeds {LIMITS.nesting_depth} level "
        "nesting depth limit"
    ]


def test_file_api_rejects_an_oversized_array_without_an_exception_trace(tmp_path):
    path = write_findings(tmp_path, json.dumps([None] * (LIMITS.array_items + 1)))
    assert validate_findings_file(path) == [
        f"Failed to parse findings JSON: input exceeds {LIMITS.array_items} item array limit"
    ]


def test_checks_pattern_and_branch_invariants():
    reject_mutation(rejected, put("fingerprint", "not stable"))
    reject_mutation(
        needs_validation,
        put("severity", {"impact": {"score": "low"}, "overall_severity": "low"}),
    )


def test_rejects_unsupported_and_malformed_schema_keywords():
    assert any("format" in error for error in check_schema({"type": "string", "format": "uuid"}))
    assert any(
        "regular expression" in error for error in check_schema({"type": "string", "pattern": "["})
    )
    assert any(
        "expected boolean" in error
        for error in check_schema({"type": "string", "visibleContent": "yes"})
    )
    assert any(
        "requires type" in error
        for error in check_schema({"type": "array", "visibleContent": True})
    )
    assert validate_document([], {"type": "array", "maxItems": 1}) != []


def test_caps_malformed_1000_finding_validation_output(tmp_path):
    assert len(errors_for([None] * LIMITS.array_items)) == LIMITS.validation_errors
    path = write_findings(tmp_path, json.dumps([None] * LIMITS.array_items))
    errors = validate_findings_file(path)
    assert len(errors) == LIMITS.validation_errors  # upstream adds "output capped at 100"
    assert len("\n".join(errors)) < 20000


def test_caps_amplified_in_limit_findings_output(tmp_path):
    findings = [
        {
            "verdict": "confirmed",
            "trace": [0] * LIMITS.array_items,
            "evidence": [0] * LIMITS.array_items,
        }
        for _ in range(750)
    ]
    contents = json.dumps(findings)
    assert len(contents) > 3 * 1000 * 1000
    assert len(contents) <= LIMITS.input_bytes
    errors = validate_findings_file(write_findings(tmp_path, contents))
    assert len(errors) == LIMITS.validation_errors
    assert len("\n".join(errors)) < 20000


def test_keeps_shared_helpers_aligned_with_the_coverage_ledger_validator():
    for name in (
        "VISIBLE_CONTENT",
        "PATH_FORBIDDEN_CHARACTER",
        "WINDOWS_RESERVED_COMPONENT",
        "UNSAFE_DIAGNOSTIC_CHARACTER",
    ):
        assert getattr(findings_module, name) is getattr(ledger_module, name), name

    findings_limits = {field.name for field in fields(findings_module.LIMITS)}
    ledger_limits = {field.name for field in fields(ledger_module.LIMITS)}
    shared = sorted(findings_limits & ledger_limits)
    assert shared == ["input_bytes", "nesting_depth", "validation_errors"]
    for key in shared:
        assert getattr(findings_module.LIMITS, key) == getattr(ledger_module.LIMITS, key), key

    path_corpus = [
        "src/handler.js",
        "src/caf\U000000e9/handler.js",
        "src/\U000065e5\U0000672c\U00008a9e/\U00000444\U00000430\U00000439\U0000043b.ts",
        "src/cloc\U0000212a$.txt",
        "src/CLOCK$.txt",
        "src/con.txt",
        "CON",
        "src/COM\U000000b9.log",
        "src/lpt\U000000b3",
        "/etc/passwd",
        "../src/file.c",
        "src/../file.c",
        "src//file.c",
        "src\\file.c",
        "src/file:name.c",
        "~home/file.c",
        "C:/file.c",
        "src/file.c ",
        "src/file.c.",
        "src/file\U0000202ename.c",
        "src/file\U0000200b.js",
        "src/file\U0000034f.js",
        "src/file\U0000fe0f.js",
        "src/file" + LONE_HIGH + "name.c",
        "src/file" + LONE_LOW + "name.c",
    ]
    for value in path_corpus:
        assert findings_module.is_safe_relative_source_path(
            value
        ) == ledger_module.is_safe_relative_path(value), ascii(value)
    assert findings_module.is_safe_relative_source_path("src/cloc\U0000212a$.txt") is False
    assert ledger_module.is_safe_relative_path("src/cloc\U0000212a$.txt") is False

    prose_corpus = [
        "Valid prose.",
        "caf\U000000e9",
        "",
        " \t\r\n",
        "\U0000200b",
        "\U0000034f",
        "\U0000fe0f",
        LONE_HIGH,
        LONE_LOW,
        "visible" + LONE_HIGH,
    ]
    for value in prose_corpus:
        assert findings_module.has_visible_prose(value) == ledger_module.has_visible_prose(value), (
            ascii(value)
        )


# --- kalkan: finding extensions (ENGINE-SPEC section 5) --------------------------------------


def extended() -> list[Finding]:
    return load_fixture("extended_findings.json")


def errors_after(index: int, mutate: Mutation) -> list[str]:
    document = extended()
    mutate(document[index])
    return errors_for(document)


def test_accepts_the_extended_fixture(tmp_path):
    document = extended()
    assert [finding["verdict"] for finding in document] == [
        "confirmed",
        "needs_validation",
        "rejected",
    ]
    assert errors_for(document) == []
    assert validate_findings_file(write_findings(tmp_path, stringify(document))) == []


def test_extension_fields_are_optional():
    for name in ("id", "class", "cwe", "owasp", "engines", "candidates", "audit_answers"):
        assert errors_after(0, drop(name)) == [], name
    for name in ("poc", "i18n", "cvss"):
        assert errors_after(0, drop(name)) == [], name


@pytest.mark.parametrize(
    ("index", "mutation", "expected"),
    [
        (0, put("id", "KF-123"), 'must match pattern "^KF-[0-9A-F]{16}$"'),
        (0, put("id", "KF-0123456789abcdef"), "must match pattern"),
        (0, put("class", "SQL injection"), "$[0].class: must match pattern"),
        (0, put("cwe", ["CWE-639", "CWE-639"]), "items must be unique; duplicate at index 1"),
        (0, put("cwe", ["639"]), '$[0].cwe[0]: must match pattern "^CWE-[0-9]+$"'),
        (0, put("owasp", ["Broken access control"]), "$[0].owasp[0]: must match pattern"),
        (0, put("engines", []), "$[0].engines: must have at least 1 item(s), got 0"),
        (0, put("engines", ["Opengrep"]), "$[0].engines[0]: must match pattern"),
        (0, put("candidates", ["CAND-1"]), "$[0].candidates[0]: must match pattern"),
        (0, drop("audit_answers.unmitigated"), 'missing required field "unmitigated"'),
        (
            0,
            put("audit_answers.unmitigated.status", "maybe"),
            '$[0].audit_answers.unmitigated.status: invalid value "maybe"',
        ),
        (0, put("audit_answers.unmitigated.reason", ""), "must have at least 1 character(s)"),
        (
            0,
            put("audit_answers.attacker_control.evidence.0.line", 0),
            "$[0].audit_answers.attacker_control.evidence[0].line: must be a positive integer",
        ),
        (
            0,
            put("audit_answers.attacker_control.evidence.0.file", "../etc/passwd"),
            "$[0].audit_answers.attacker_control.evidence[0].file: "
            "must be a safe repository-relative source path",
        ),
        (0, put("audit_answers.extra", {}), 'unexpected field "extra"'),
        (0, put("poc.level", "system"), '$[0].poc.level: invalid value "system"'),
        (0, put("poc.status", "ok"), '$[0].poc.status: invalid value "ok"'),
        (0, drop("poc.observed_result"), 'missing required field "observed_result"'),
        (0, put("poc.artifacts", ["/tmp/out.txt"]), "$[0].poc.artifacts[0]: must be a safe"),
        (0, put("i18n", {}), 'missing required field "en"'),
        (0, put("i18n.en.title", ""), "$[0].i18n.en.title: must have at least 1 character(s)"),
        (0, put("i18n.en.summary", "x"), 'unexpected field "summary"'),
        (0, put("cvss.score", 10.5), "$[0].cvss.score: must be at most 10, got 10.5"),
        (0, put("cvss.score", -1), "$[0].cvss.score: must be at least 0, got -1"),
        (0, drop("cvss.vector"), 'missing required field "vector"'),
        (
            1,
            put("cvss", {"vector": "CVSS:3.1/AV:N", "score": 5.0}),
            '$[1]: needs_validation finding must not contain "cvss"',
        ),
        (
            2,
            put("cvss", {"vector": "CVSS:3.1/AV:N", "score": 5.0}),
            '$[2]: rejected finding must not contain "cvss"',
        ),
        (1, put("id", "KF-0123456789ABCDEF"), "$[1].id: duplicate of $[0].id"),
        (
            1,
            put(
                "sca",
                {
                    "ecosystem": "npm",
                    "package": "parser-lib",
                    "version": "1.2.3",
                    "vuln_ids": [],
                    "fixed_versions": [],
                    "reachability": "unknown",
                },
            ),
            "$[1].sca.vuln_ids: must have at least 1 item(s), got 0",
        ),
        (
            1,
            put(
                "sca",
                {
                    "ecosystem": "npm",
                    "package": "parser-lib",
                    "version": "1.2.3",
                    "vuln_ids": ["CVE-2026-0001"],
                    "fixed_versions": [],
                    "reachability": "maybe",
                },
            ),
            '$[1].sca.reachability: invalid value "maybe"',
        ),
    ],
    ids=lambda value: value if isinstance(value, str) else None,
)
def test_rejects_invalid_extension_values(index, mutation, expected):
    errors = errors_after(index, mutation)
    assert any(expected in error for error in errors), errors


def test_accepts_sca_data_and_cvss_bounds():
    sca = {
        "ecosystem": "npm",
        "package": "parser-lib",
        "version": "1.2.3",
        "vuln_ids": ["CVE-2026-0001", "GHSA-abcd-efgh-ijkl"],
        "fixed_versions": ["1.2.4"],
        "reachability": "reachable",
    }
    assert errors_after(1, put("sca", sca)) == []
    assert errors_after(0, put("cvss.score", 0)) == []
    assert errors_after(0, put("cvss.score", 10)) == []
    assert errors_after(0, put("owasp", ["A01:2021", "LLM01:2025", "API1"])) == []


def test_extension_checks_skip_malformed_containers():
    # The schema reports these shapes; the semantic checks must not fail on them.
    for mutation in (
        put("audit_answers", []),
        put("audit_answers.attacker_control", "text"),
        put("audit_answers.attacker_control.evidence", {}),
        put("audit_answers.attacker_control.evidence", [None]),
        put("poc", None),
        put("poc.artifacts", "agents/x"),
        put("cvss", [1]),
        put("cvss.score", "11"),
    ):
        assert errors_after(0, mutation) != []


# --- kalkan: candidate records (ENGINE-SPEC section 4) ----------------------------------------


def candidate(name: str = "candidate.json") -> dict:
    return load_fixture(name)


def test_accepts_valid_candidates():
    for name in ("candidate.json", "candidate_sca.json"):
        record = candidate(name)
        assert validate_candidate(record) == [], name
        assert validate(record, load_schema("candidate"), "$") == [], name


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        (put("id", "CAND-xyz"), '$.id: must match pattern "^CAND-[0-9A-F]{16}$"'),
        (put("engine", "semgrep"), '$.engine: invalid value "semgrep"'),
        (drop("raw"), '$: missing required field "raw"'),
        (put("verdict", "confirmed"), '$: unexpected field "verdict"'),
        (put("start_line", 0), "$.start_line: must match exactly one schema in oneOf; matched 0"),
        (put("start_line", 1.5), "$.start_line: must match exactly one schema in oneOf"),
        (put("class", "SQL Injection"), "$.class: must match exactly one schema in oneOf"),
        (put("confidence", "certain"), '$.confidence: invalid value "certain"'),
        (put("cwe", ["89"]), '$.cwe[0]: must match pattern "^CWE-[0-9]+$"'),
        (put("severity", "error"), '$.severity: invalid value "error"'),
        (put("tags", "security"), "$.tags: expected array, got string"),
        (put("fingerprints", {"matchBasedId/v1": 7}), '$.fingerprints["matchBasedId/v1"]'),
        (put("end_line", 41), "$.end_line: must not be less than start_line"),
        (put("raw.run_index", -1), "$.raw.run_index: must be at least 0, got -1"),
        (put("raw.result_index", "3"), "$.raw.result_index: expected integer, got string"),
        (put("snippet", None), "$.snippet: expected string, got null"),
        (put("sca", {"ecosystem": "npm"}), "$.sca: must match exactly one schema in oneOf"),
    ],
    ids=lambda value: value if isinstance(value, str) else None,
)
def test_rejects_invalid_candidates(mutation, expected):
    record = candidate()
    mutation(record)
    errors = validate_candidate(record)
    assert any(expected in error for error in errors), errors


def test_rejects_invalid_sca_candidates():
    record = candidate("candidate_sca.json")
    del record["sca"]["cvss_vector"]
    assert any("$.sca: must match exactly one schema" in e for e in validate_candidate(record))
    record = candidate("candidate_sca.json")
    record["sca"]["cvss_score"] = "6.5"
    assert validate_candidate(record) != []


def test_rejects_non_object_candidates():
    assert validate_candidate([]) == ["$: expected object, got array"]
    assert validate_candidate(None) == ["$: expected object, got null"]
