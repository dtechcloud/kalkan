# SPDX-License-Identifier: MIT
# Ported from cloudflare/security-audit-skill@c1c8a8c: skills/security-audit/validate-coverage-ledger.test.cjs  # noqa: E501
# Copyright (c) 2025-2026 Cloudflare, Inc. Changes: translated from node:test to pytest; the CLI
# tests call validate_ledger_file; kalkan tests were added at the end.
"""Tests for kalkan.findings.ledger (port of the upstream coverage-ledger validator tests).

The first part keeps the upstream tests one to one and in the upstream order. Upstream runs the
CLI in a child process and skips most CLI tests where Node lacks O_NOFOLLOW and O_NONBLOCK (for
example on Windows). Here the same cases call validate_ledger_file and run on every platform.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from kalkan.findings.ledger import (
    LIMITS,
    CanonicalRefError,
    canonical_coverage_id,
    encode_canonical_ref,
    is_owned_artifact_path,
    is_safe_agent_id,
    is_safe_relative_path,
    preflight_document,
    preflight_json_text,
    validate_ledger,
    validate_ledger_file,
)
from kalkan.schema.validator import JsonStructureError

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "ledger"
TERMINAL_CONTROL_PAYLOAD = "\x1b\x07\x85\U0000202e"
IS_WINDOWS = os.name == "nt"


def load_fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def unit(**overrides: object) -> dict:
    """Port of the upstream unit() helper: a planned unit with a canonical coverage ID."""
    value = load_fixture("unit.json")
    canonical_refs = overrides.pop("canonical_refs", None) or value["canonical_refs"]
    value["coverage_id"] = canonical_coverage_id(canonical_refs)
    value.update(overrides)
    value["canonical_refs"] = canonical_refs
    return value


def source_check(agent_id: object = "hunter-1", **overrides: object) -> dict:
    value = load_fixture("source_check.json")
    value["agent_id"] = agent_id
    value.update(overrides)
    return value


def local_check(agent_id: object = "hunter-1", **overrides: object) -> dict:
    params: dict[str, object] = {
        "method": "local",
        "result": "The bounded fixture accepted the other owner's object.",
        "artifact": f"agents/{agent_id}/artifacts/result.txt",
    }
    params.update(overrides)
    return source_check(agent_id, **params)


def archived_attempt(**overrides: object) -> dict:
    value = load_fixture("archived_attempt.json")
    value.update(overrides)
    return value


def errors_for(value: object) -> list[str]:
    return validate_ledger(value)


def write_ledger(tmp_path: Path, contents: str | bytes) -> Path:
    path = tmp_path / "coverage-ledger.json"
    path.write_bytes(contents.encode("utf-8") if isinstance(contents, str) else contents)
    return path


def assert_no_injected_control_characters(output: str) -> None:
    for marker in TERMINAL_CONTROL_PAYLOAD:
        assert marker not in output, f"found raw control character {ascii(marker)}"


def make_symlink(target: Path, link: Path) -> None:
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"cannot create a symlink here: {exc}")


# --- upstream: validate-coverage-ledger.test.cjs ---------------------------------------------


def test_accepts_an_empty_ledger_and_complete_units():
    assert errors_for([]) == []
    assert errors_for([unit()]) == []

    missing_attempts = unit()
    del missing_attempts["attempts"]
    assert any(
        'missing required field "attempts"' in error for error in errors_for([missing_attempts])
    )

    covered = unit(
        status="covered",
        agent_id="hunter-1",
        reviewed_paths=["src/router.ts"],
        local_checks=[source_check()],
    )
    assert errors_for([covered]) == []


def test_accepts_a_complete_ledger_through_the_file_api(tmp_path):
    assert validate_ledger_file(write_ledger(tmp_path, json.dumps([unit()]))) == []


def test_text_preflight_ignores_structural_characters_and_escapes_inside_strings(tmp_path):
    value = unit(
        surface='Route \\ slash [list] {object}, colon: quoted "value"',
        excluded_blocks=[
            {
                "block": "COMPANION.md#Literal [brackets] {braces}",
                "reason": 'The text contains a backslash \\ before an escaped "quote".',
            }
        ],
    )
    contents = json.dumps([value])
    preflight_json_text(contents)
    assert json.loads(contents) == [value]
    assert validate_ledger_file(write_ledger(tmp_path, contents)) == []


def test_text_preflight_enforces_structural_cardinality_limits():
    depth_limit = LIMITS.nesting_depth
    preflight_json_text("[" * depth_limit + "0" + "]" * depth_limit)
    with pytest.raises(JsonStructureError, match="exceeds nesting depth limit 64"):
        preflight_json_text("[" * (depth_limit + 1) + "0" + "]" * (depth_limit + 1))

    too_many_units = "[" + "null," * LIMITS.units + "null]"
    with pytest.raises(JsonStructureError, match="exceeds 10000 top-level unit limit"):
        preflight_json_text(too_many_units)

    too_many_items = "[[" + "null," * LIMITS.collection_items + "null]]"
    with pytest.raises(JsonStructureError, match="exceeds 1000 item array limit"):
        preflight_json_text(too_many_items)

    object_fields = ",".join(f'"field{index}":null' for index in range(LIMITS.object_fields + 1))
    with pytest.raises(JsonStructureError, match="exceeds 1000 field object limit"):
        preflight_json_text("[{" + object_fields + "}]")

    full_array = "[" + "null," * (LIMITS.collection_items - 1) + "null]"
    arrays_needed = LIMITS.preflight_values // (LIMITS.collection_items + 1) + 1
    too_many_values = "[" + ",".join([full_array] * arrays_needed) + "]"
    with pytest.raises(JsonStructureError, match="exceeds 500000 total value limit"):
        preflight_json_text(too_many_values)


def test_text_preflight_rejects_malformed_structural_truncation_cleanly():
    with pytest.raises(JsonStructureError, match="truncated JSON structure"):
        preflight_json_text("[")
    with pytest.raises(JsonStructureError, match="unterminated JSON string"):
        preflight_json_text('["unterminated')
    with pytest.raises(JsonStructureError, match="mismatched JSON containers"):
        preflight_json_text('[{"field":1]')


def test_derives_collision_free_canonical_ids_from_exact_utf8_references():
    assert encode_canonical_ref("route:POST /users") == "route%3APOST%20%2Fusers"
    assert encode_canonical_ref("route name") != encode_canonical_ref("route-name")
    refs = {"surface": "a", "boundary": "b", "subsystem": "c", "attack_class": "d"}
    assert canonical_coverage_id({**refs, "lifecycle": "retry"}) == "a::b::c::d::retry"
    for bad in ("e\U00000301", "bad\x00ref", "hidden\U0000200bref"):
        with pytest.raises(CanonicalRefError, match="invalid canonical reference"):
            encode_canonical_ref(bad)


def test_rejects_noncanonical_duplicate_and_colliding_ids():
    wrong = unit(coverage_id="display-label-slug")
    assert any("expected canonical ID" in error for error in errors_for([wrong]))

    duplicate = unit()
    assert any("duplicate coverage ID" in error for error in errors_for([duplicate, unit()]))

    collision = unit()
    different_meaning = unit(surface="Delete-user route")
    errors = errors_for([collision, different_meaning])
    assert any("canonical identity collision" in error for error in errors)


def test_requires_canonical_references_to_be_own_properties():
    # Python dicts have no prototype chain. The analog: class attributes are not keys.
    defaults = unit()["canonical_refs"]

    class InheritedRefs(dict):
        surface = defaults["surface"]
        boundary = defaults["boundary"]
        subsystem = defaults["subsystem"]
        attack_class = defaults["attack_class"]

    value = unit()
    value["canonical_refs"] = InheritedRefs()
    assert any("missing required field" in error for error in errors_for([value]))


def test_rejects_aliases_for_one_semantic_tuple():
    first = unit()
    refs = {**first["canonical_refs"], "surface": "src/alias.ts#updateUser"}
    alias = unit(canonical_refs=refs)
    ledger = sorted([first, alias], key=lambda entry: entry["coverage_id"])
    errors = errors_for(ledger)
    assert any("semantic tuple already uses coverage ID" in error for error in errors)


def test_requires_lexicographic_order():
    second_refs = {
        "surface": "zzz",
        "boundary": "src/authz.ts#requireOwner",
        "subsystem": "packages/api",
        "attack_class": "ATTACK-CLASSES.md#Access control",
    }
    errors = errors_for([unit(canonical_refs=second_refs), unit()])
    assert any("sorted lexicographically" in error for error in errors)


def test_validates_assignment_block_maps():
    overlap = unit(
        selected_companion_blocks=["AI-AND-LLM.md#Tool calls"],
        excluded_blocks=[{"block": "AI-AND-LLM.md#Tool calls", "reason": "Claimed irrelevant."}],
    )
    assert any("also selected" in error for error in errors_for([overlap]))

    no_reason = unit(excluded_blocks=[{"block": "AI-AND-LLM.md#Tool calls", "reason": ""}])
    assert any("reason" in error for error in errors_for([no_reason]))


def test_requires_owned_artifacts_for_local_checks_and_null_artifacts_for_source_checks():
    local = unit(
        status="covered",
        agent_id="hunter-1",
        reviewed_paths=["src/router.ts"],
        local_checks=[local_check()],
    )
    assert errors_for([local]) == []

    independently_verified = unit(
        status="covered",
        agent_id="hunter-1",
        reviewed_paths=["src/router.ts", "src/authz.ts"],
        local_checks=[source_check(), local_check("verifier-1", reviewed_paths=["src/authz.ts"])],
    )
    assert errors_for([independently_verified]) == []

    unowned_path = unit(
        status="covered",
        agent_id="hunter-1",
        reviewed_paths=["src/router.ts", "src/authz.ts"],
        local_checks=[source_check()],
    )
    assert any("has no check owner" in error for error in errors_for([unowned_path]))

    for check_agent_id, artifact in [
        (None, "agents/hunter-1/artifacts/result.txt"),
        ("hunter-1", None),
        ("hunter-1", "result.txt"),
        ("hunter-1", "agents/hunter-2/artifacts/result.txt"),
        ("../hunter", "agents/../hunter/artifacts/result.txt"),
    ]:
        value = unit(
            status="covered",
            agent_id="hunter-1",
            reviewed_paths=["src/router.ts"],
            local_checks=[local_check(check_agent_id, artifact=artifact)],
        )
        assert errors_for([value]) != [], f"{check_agent_id}: {artifact}"

    unowned_source = unit(
        status="blocked",
        reviewed_paths=["src/router.ts"],
        local_checks=[source_check()],
        unresolved=["The boundary behavior is not source-visible."],
    )
    assert any(
        'unit with status "blocked" requires a canonical lowercase agent ID' in error
        for error in errors_for([unowned_source])
    )

    source_with_artifact = unit(
        status="covered",
        agent_id="hunter-1",
        reviewed_paths=["src/router.ts"],
        local_checks=[source_check("hunter-1", artifact="agents/hunter-1/artifacts/source.txt")],
    )
    errors = errors_for([source_with_artifact])
    assert any("source-only check must use null" in error for error in errors)


def test_requires_canonical_lowercase_filesystem_safe_agent_ids():
    for value in ("hunter-1", "verifier_2", "a0"):
        assert is_safe_agent_id(value) is True, value
    for value in (
        "Hunter-1",
        "hunter.1",
        "hunter-1.",
        "hunter ",
        "con",
        "prn",
        "aux",
        "nul",
        "com1",
        "lpt9",
        "../hunter",
    ):
        assert is_safe_agent_id(value) is False, value

    case_alias = unit(status="in_progress", agent_id="Hunter-1")
    assert any("canonical lowercase agent ID" in error for error in errors_for([case_alias]))


def test_enforces_state_evidence():
    assert any(
        'unit with status "in_progress" requires' in error
        for error in errors_for([unit(status="in_progress")])
    )
    assert any("unresolved" in error for error in errors_for([unit(status="blocked")]))
    assert any("reviewed_paths" in error for error in errors_for([unit(status="candidate")]))

    assert errors_for([unit(status="in_progress", agent_id="hunter-1")]) == []
    in_progress_evidence = unit(
        status="in_progress",
        agent_id="hunter-1",
        reviewed_paths=["src/router.ts"],
        local_checks=[source_check()],
    )
    errors = errors_for([in_progress_evidence])
    assert any("must keep this array empty" in error for error in errors)

    assigned_planned = unit(
        agent_id="hunter-1", reviewed_paths=["src/router.ts"], local_checks=[source_check()]
    )
    errors = errors_for([assigned_planned])
    assert any("planned unit must be unassigned" in error for error in errors)

    candidate = unit(
        status="candidate",
        agent_id="hunter-1",
        reviewed_paths=["src/router.ts"],
        local_checks=[
            source_check("hunter-1", invariant="Ownership is required.", result="No check exists.")
        ],
        result_fingerprints=["src-router-missing-owner-check"],
        unresolved=["validation_budget_exhausted"],
    )
    assert errors_for([candidate]) == []

    blocked = unit(
        status="blocked",
        agent_id="hunter-1",
        reviewed_paths=["src/router.ts"],
        local_checks=[source_check()],
        unresolved=["The deployed policy is unavailable."],
    )
    assert errors_for([blocked]) == []
    blocked_fingerprint = {**blocked, "result_fingerprints": ["forbidden-fingerprint"]}
    assert any("result_fingerprints" in error for error in errors_for([blocked_fingerprint]))

    for status in ("not_applicable", "out_of_scope", "deferred"):
        assert errors_for([unit(status=status, unresolved=["Reason recorded."])]) == []
        invalid = unit(
            status=status,
            agent_id="hunter-1",
            reviewed_paths=["src/router.ts"],
            local_checks=[source_check()],
            result_fingerprints=["forbidden-fingerprint"],
            unresolved=["Reason recorded."],
        )
        errors = errors_for([invalid])
        assert any("must be unassigned" in error for error in errors), status
        assert any("reviewed_paths" in error for error in errors), status
        assert any("result_fingerprints" in error for error in errors), status

    covered_fingerprint = unit(
        status="covered",
        agent_id="hunter-1",
        reviewed_paths=["src/router.ts"],
        local_checks=[source_check()],
        result_fingerprints=["forbidden-fingerprint"],
    )
    assert any("result_fingerprints" in error for error in errors_for([covered_fingerprint]))

    covered_unresolved = unit(
        status="covered",
        agent_id="hunter-1",
        reviewed_paths=["src/router.ts"],
        local_checks=[source_check()],
        unresolved=["Unexpected unresolved claim."],
    )
    assert any("unresolved" in error for error in errors_for([covered_unresolved]))


def test_archives_prior_evidence_when_a_critic_assigns_a_fresh_owner():
    reassigned = unit(
        attempts=[archived_attempt()], wave=2, status="in_progress", agent_id="hunter-2"
    )
    assert errors_for([reassigned]) == []

    final_closure = unit(
        attempts=[archived_attempt()],
        wave=2,
        status="covered",
        agent_id="hunter-2",
        reviewed_paths=["src/authz.ts"],
        local_checks=[source_check("hunter-2", reviewed_paths=["src/authz.ts"])],
    )
    assert errors_for([final_closure]) == []


def test_preserves_candidate_provenance_when_reassignment_must_be_deferred():
    candidate_attempt = archived_attempt(
        status="candidate",
        result_fingerprints=["src-router-missing-owner-check"],
        unresolved=["validation_budget_exhausted"],
    )
    deferred = unit(
        attempts=[candidate_attempt],
        wave=2,
        status="deferred",
        unresolved=["fast_profile_final_critic"],
    )
    assert errors_for([deferred]) == []


def test_rejects_reassignment_owner_reuse_and_evidence_mixing():
    reused_owner = unit(
        attempts=[archived_attempt()], wave=2, status="in_progress", agent_id="hunter-1"
    )
    errors = errors_for([reused_owner])
    assert any("current assignment owner must be fresh" in error for error in errors)

    mixed_evidence = unit(
        attempts=[archived_attempt(local_checks=[local_check()])],
        wave=2,
        status="covered",
        agent_id="hunter-2",
        reviewed_paths=["src/router.ts"],
        local_checks=[local_check()],
    )
    errors = errors_for([mixed_evidence])
    assert any("prior assignment owner evidence must remain" in error for error in errors)
    assert any("artifact from an archived attempt cannot be reused" in error for error in errors)

    mixed_history = unit(
        attempts=[
            archived_attempt(local_checks=[local_check()]),
            archived_attempt(wave=2, agent_id="hunter-2", local_checks=[local_check()]),
        ],
        wave=3,
        status="in_progress",
        agent_id="hunter-3",
    )
    history_errors = errors_for([mixed_history])
    assert any(
        "prior assignment owner evidence must remain in its earlier attempt" in error
        for error in history_errors
    )
    assert any(
        "artifact from an earlier attempt cannot be reused" in error for error in history_errors
    )

    unordered = unit(
        attempts=[
            archived_attempt(),
            archived_attempt(wave=1, agent_id="hunter-2", local_checks=[source_check("hunter-2")]),
        ],
        wave=3,
        status="in_progress",
        agent_id="hunter-3",
    )
    assert any("strictly increasing" in error for error in errors_for([unordered]))


def test_rejects_unsafe_paths_and_malformed_fingerprints():
    for value in (
        "/etc/passwd",
        "../src/file.js",
        "src/../file.js",
        "src/con.txt",
        "src/PRN",
        "src/AUX.c",
        "src/NUL",
        "src/CLOCK$.txt",
        "src/conin$.txt",
        "src/conout$",
        "src/COM1.log",
        "src/lpt9",
        "src/COM\U000000b9.log",
        "src/COM\U000000b2.log",
        "src/COM\U000000b3.log",
        "src/lpt\U000000b9",
        "src/lpt\U000000b2",
        "src/lpt\U000000b3",
        "src/file.js.",
        "C:/src/file.js",
        "src/file\n.js",
        "src/file\x85.js",
        "src/file\U00002028.js",
        "src/file\U0000200b.js",
        "src/file\U0000034f.js",
        "src/file\U0000fe0f.js",
    ):
        assert is_safe_relative_path(value) is False, ascii(value)
    assert is_safe_relative_path("src/handler.js") is True
    assert is_safe_relative_path("src/caf\U000000e9/handler.js") is True
    errors = errors_for([unit(starting_paths=["../src/router.ts"])])
    assert any("repository-relative path" in error for error in errors)
    fingerprint_unit = unit(
        status="candidate",
        agent_id="hunter-1",
        reviewed_paths=["src/router.ts"],
        local_checks=[
            source_check("hunter-1", invariant="Ownership is required.", result="No check exists.")
        ],
        result_fingerprints=["not stable"],
    )
    assert any("invalid fingerprint" in error for error in errors_for([fingerprint_unit]))


def test_rejects_format_default_ignorable_and_invalid_scalar_prose():
    for invisible in ("\U0000200b", "\U0000034f", "\U0000fe0f", "\U0000d800"):
        assert any("surface" in error for error in errors_for([unit(surface=invisible)]))
        blocks = [{"block": "ATTACK-CLASSES.md#Access control", "reason": invisible}]
        assert any("reason" in error for error in errors_for([unit(excluded_blocks=blocks)]))


def test_quotes_input_derived_controls_in_direct_validation_errors():
    invalid_status = f"invalid-{TERMINAL_CONTROL_PAYLOAD}"
    invalid_path = f"src/{TERMINAL_CONTROL_PAYLOAD}.js"
    value = unit(
        status=invalid_status,
        agent_id="hunter-1",
        reviewed_paths=[invalid_path],
        local_checks=[source_check()],
        result_fingerprints=["force-state-error"],
    )
    output = "\n".join(errors_for([value]))
    assert "$[0].status" in output
    assert "$[0].reviewed_paths" in output
    for escaped in ("\\u001b", "\\u0007", "\\u0085", "\\u202e"):
        assert escaped in output, escaped
    assert_no_injected_control_characters(output)


def test_quotes_input_derived_controls_in_file_validation_errors(tmp_path):
    value = unit(
        status=f"invalid-{TERMINAL_CONTROL_PAYLOAD}", result_fingerprints=["force-state-error"]
    )
    contents = json.dumps([value], ensure_ascii=False)
    errors = validate_ledger_file(write_ledger(tmp_path, contents))
    output = "\n".join(errors)
    assert errors
    assert "$[0].status" in output
    assert "\\u001b" in output
    assert_no_injected_control_characters(output)


def test_returns_a_generic_syntax_error_without_parser_supplied_controls(tmp_path):
    malformed = b"[" + TERMINAL_CONTROL_PAYLOAD.encode("utf-8") + b"]"
    errors = validate_ledger_file(write_ledger(tmp_path, malformed))
    assert errors == ["Failed to parse coverage ledger: invalid JSON syntax"]
    assert_no_injected_control_characters("\n".join(errors))


def test_does_not_reflect_controls_from_a_failed_input_path(tmp_path):
    missing = tmp_path / f"missing-{TERMINAL_CONTROL_PAYLOAD}.json"
    errors = validate_ledger_file(missing)
    assert len(errors) == 1
    assert errors[0].startswith("Failed to read coverage ledger:")
    assert_no_injected_control_characters(errors[0])


def test_rejects_invalid_utf8_through_the_file_api(tmp_path):
    encoded = json.dumps([unit()]).encode("utf-8")
    marker = b"Update-user route"
    offset = encoded.index(marker)
    malformed = encoded[:offset] + b"\x80" + encoded[offset + len(marker) :]
    assert validate_ledger_file(write_ledger(tmp_path, malformed)) == [
        "Failed to read coverage ledger: input is not valid UTF-8"
    ]


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="this platform has no FIFOs")
def test_rejects_a_fifo_through_the_file_api_without_blocking(tmp_path):
    fifo = tmp_path / "coverage-ledger.json"
    os.mkfifo(fifo)
    assert validate_ledger_file(fifo) == [
        "Failed to read coverage ledger: input must be a regular file"
    ]


def test_rejects_a_symlink_through_the_file_api(tmp_path):
    target = tmp_path / "target.json"
    target.write_text(json.dumps([unit()]), encoding="utf-8")
    link = tmp_path / "coverage-ledger.json"
    make_symlink(target, link)
    assert validate_ledger_file(link) == [
        "Failed to read coverage ledger: input must not be a symlink"
    ]


def test_rejects_deeply_nested_input_without_recursion_failure(tmp_path):
    nested: object = 0
    for _ in range(20000):
        nested = [nested]
    assert any("exceeds nesting depth limit 64" in error for error in errors_for(nested))
    path = write_ledger(tmp_path, "[" * 20000 + "0" + "]" * 20000)
    assert validate_ledger_file(path) == [
        "Failed to parse coverage ledger: input exceeds nesting depth limit 64"
    ]


def test_rejects_multi_megabyte_nesting_without_exhausting_memory(tmp_path):
    open_containers = "[" * 2_000_000
    for contents in (open_containers, open_containers + "0" + "]" * 2_000_000):
        assert validate_ledger_file(write_ledger(tmp_path, contents)) == [
            "Failed to parse coverage ledger: input exceeds nesting depth limit 64"
        ]


def test_caps_malformed_10000_unit_validation_output(tmp_path):
    assert len(errors_for([None] * LIMITS.units)) == LIMITS.validation_errors
    errors = validate_ledger_file(write_ledger(tmp_path, json.dumps([None] * LIMITS.units)))
    assert len(errors) == LIMITS.validation_errors  # upstream adds "output capped at 100"
    assert len("\n".join(errors)) < 20000


def test_rejects_malformed_top_level_data_and_excessive_unit_counts():
    assert errors_for({"units": []}) == ["$: expected a top-level array"]
    assert errors_for([None] * 10001) == ["$: exceeds 10000 coverage units"]
    oversized_collection = unit(extra=[None] * (LIMITS.collection_items + 1))
    assert any("exceeds 1000 entries" in error for error in errors_for([oversized_collection]))


def test_accepts_a_canonical_id_derived_from_near_maximum_multibyte_references(tmp_path):
    canonical_refs = {
        "surface": "\U00006f22" * 1024,
        "boundary": "\U000000e9" * 1024,
        "subsystem": "packages/api",
        "attack_class": "\U00006f22" * 1023 + "\U000000e9",
    }
    value = unit(canonical_refs=canonical_refs)
    assert len(value["coverage_id"]) > 16384
    assert len(value["coverage_id"]) <= 65536
    assert errors_for([value]) == []
    contents = json.dumps([value], ensure_ascii=False)
    assert validate_ledger_file(write_ledger(tmp_path, contents)) == []


# --- kalkan ----------------------------------------------------------------------------------


def test_unit_fixture_holds_the_canonical_coverage_id():
    fixture = load_fixture("unit.json")
    assert fixture["coverage_id"] == canonical_coverage_id(fixture["canonical_refs"])
    assert fixture["coverage_id"] == (
        "src%2Frouter.ts%23POST%20%2Fusers%2F%3Aid::src%2Fauthz.ts%23requireOwner"
        "::packages%2Fapi::ATTACK-CLASSES.md%23Access%20control"
    )


def test_canonical_coverage_id_rejects_malformed_refs():
    with pytest.raises(CanonicalRefError, match="canonical_refs must be an object"):
        canonical_coverage_id(["a", "b", "c", "d"])
    refs = {"surface": "a", "boundary": "b", "subsystem": "c", "attack_class": "d"}
    with pytest.raises(CanonicalRefError, match="missing or unexpected fields"):
        canonical_coverage_id({**refs, "extra": "e"})
    with pytest.raises(CanonicalRefError, match="missing or unexpected fields"):
        canonical_coverage_id({"surface": "a"})
    with pytest.raises(CanonicalRefError, match="invalid canonical reference"):
        canonical_coverage_id({**refs, "surface": " padded"})
    error = CanonicalRefError("invalid canonical reference")
    assert isinstance(error, ValueError)


def test_lifecycle_appears_in_refs_and_unit_together():
    refs = {**unit()["canonical_refs"], "lifecycle": "retry"}
    with_lifecycle = unit(canonical_refs=refs, lifecycle="Retry")
    assert errors_for([with_lifecycle]) == []
    only_refs = unit(canonical_refs=refs)
    errors = errors_for([only_refs])
    assert any("lifecycle and canonical_refs.lifecycle must appear together" in e for e in errors)


def test_is_owned_artifact_path():
    assert is_owned_artifact_path("agents/hunter-1/artifacts/result.txt", "hunter-1")
    assert is_owned_artifact_path("agents/hunter-1/artifacts/sub/result.txt", "hunter-1")
    assert not is_owned_artifact_path("agents/hunter-1/artifacts/", "hunter-1")
    assert not is_owned_artifact_path("agents/hunter-1/scratch/result.txt", "hunter-1")
    assert not is_owned_artifact_path("agents/hunter-1/artifacts/result.txt", "hunter-2")
    assert not is_owned_artifact_path("agents/con/artifacts/result.txt", "con")
    assert not is_owned_artifact_path(None, "hunter-1")


def test_preflight_document_reports_index_locations():
    errors = preflight_document([unit(extra=[None] * (LIMITS.collection_items + 1))])
    assert errors == ["$[0]{19}: exceeds 1000 entries"]
    wide = {f"field{index}": None for index in range(LIMITS.object_fields + 1)}
    assert preflight_document([wide]) == ["$[0]: exceeds 1000 object fields"]


def test_file_api_rejects_a_byte_order_mark(tmp_path):
    path = write_ledger(tmp_path, b"\xef\xbb\xbf" + json.dumps([unit()]).encode("utf-8"))
    assert validate_ledger_file(path) == [
        "Failed to parse coverage ledger: input has malformed JSON structure"
    ]


@pytest.mark.skipif(not IS_WINDOWS, reason="junctions exist only on Windows")
def test_file_api_rejects_a_windows_junction(tmp_path):
    winapi = pytest.importorskip("_winapi")
    target = tmp_path / "directory"
    target.mkdir()
    junction = tmp_path / "coverage-ledger.json"
    try:
        winapi.CreateJunction(str(target), str(junction))
    except OSError as exc:
        pytest.skip(f"cannot create a junction here: {exc}")
    assert validate_ledger_file(junction) == [
        "Failed to read coverage ledger: input must not be a symlink or other reparse point"
    ]


def test_validation_never_fails_on_python_values_that_json_cannot_hold():
    strange = unit(
        status=("planned",),
        agent_id={"id": "hunter-1"},
        selected_companion_blocks=[b"bytes", 1, True, None, 1.0],
        excluded_blocks=[{"block": 1, "reason": "Number block."}, {"block": True, "reason": "x"}],
        local_checks=[{"agent_id": ["hunter-1"], "method": {"local": 1}, "artifact": 5}],
        wave=float("nan"),
        prior_status=["new"],
    )
    errors = errors_for([strange])
    assert errors
    assert any("block is also selected" in error for error in errors)
