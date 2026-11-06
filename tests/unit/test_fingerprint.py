# SPDX-License-Identifier: Apache-2.0
# Ported from block/codecrucible@b5c8086: internal/sarif/review_test.go
# Copyright 2026 Block, Inc. Changes: translated from Go to Python (TestFindingIDsAreStableAndUnique
# and the unique-ID check of TestReviewPresentation); kalkan test vectors and edge cases added.
"""Tests for kalkan.findings.fingerprint (ENGINE-SPEC 6.1 and 6.2)."""

from __future__ import annotations

import hashlib
import re

import pytest

from kalkan.errors import UnsafeInputError
from kalkan.findings.fingerprint import (
    CANDIDATE_ID_PREFIX,
    FINDING_ID_PREFIX,
    FINGERPRINT_KEY,
    WHITESPACE,
    assign_finding_ids,
    cached_get_lines,
    candidate_id,
    collapse_whitespace,
    finding_hash,
    finding_id,
    finding_location,
    identity_seed,
    trim_whitespace,
)

FINDING_ID = re.compile(r"^KF-[0-9A-F]{16}$")
CANDIDATE_ID = re.compile(r"^CAND-[0-9A-F]{16}$")
SQL_SNIPPET = '\tdb.Query("SELECT * FROM t WHERE id = " + id)'
GO_FILE = "package a\n\nfunc f() { exec(input) }\nfunc g() { exec(input) }\n"


def identity(**overrides):
    inputs = {
        "cwe": ["CWE-89"],
        "class_slug": "sqli",
        "rule_id": "go.sqli",
        "uri": "app/db.go",
        "snippet": SQL_SNIPPET,
        "start_line": 4,
    }
    inputs.update(overrides)
    return inputs


def new_id(used=None, **overrides):
    return finding_id(**identity(**overrides), used=set() if used is None else used)


def line_anchor(uri, line, cwe=("CWE-78",)):
    """The inputs of a finding whose ID uses the line anchor (no snippet)."""
    return identity(
        cwe=list(cwe), class_slug=None, rule_id=None, uri=uri, snippet="", start_line=line
    )


def lines_of(files):
    def get_lines(path):
        text = files.get(path)
        return None if text is None else text.split("\n")

    return get_lines


def finding(file, line, *, cwe=("CWE-78",), title="Command injection", **extra):
    record = {
        "verdict": "needs_validation",
        "title": title,
        "description": "Input reaches a shell.",
        "trace": [
            {
                "kind": "entrypoint",
                "file": "main.go",
                "line": 1,
                "scope": "main",
                "description": "x",
            },
            {"kind": "sink", "file": file, "line": line, "scope": "f", "description": "exec"},
        ],
        "evidence": [{"file": file, "line": line, "description": "exec call"}],
        "cwe": list(cwe),
    }
    record.update(extra)
    return record


# --- Frozen test vectors -------------------------------------------------------------------

FINDING_VECTORS = [
    pytest.param(identity(), "KF-2CC44B27C1508C41", id="first-cwe"),
    pytest.param(
        identity(
            cwe=[],
            class_slug="xss",
            rule_id="r1",
            uri="web/views/profile.html",
            snippet="<div>{{ bio | safe }}</div>",
            start_line=12,
        ),
        "KF-88628A8FC942DCA1",
        id="class-slug",
    ),
    pytest.param(
        identity(
            cwe=[],
            class_slug=None,
            rule_id="python.lang.security.audit.eval",
            uri="tools/run.py",
            snippet="eval(expr)",
            start_line=7,
        ),
        "KF-417764ED96EE9000",
        id="rule-id",
    ),
    pytest.param(
        identity(
            cwe=[], class_slug=None, rule_id=None, uri="src/main.c", snippet="", start_line=42
        ),
        "KF-5CB9A976A5BC4B8A",
        id="unknown-class-line-anchor",
    ),
    pytest.param(
        identity(
            cwe=["CWE-798"], class_slug=None, rule_id=None, uri="", snippet=None, start_line=None
        ),
        "KF-5B16212DB76F731E",
        id="no-location",
    ),
    pytest.param(
        identity(
            cwe=["CWE-79"],
            class_slug="xss",
            rule_id=None,
            uri="web/şablon.go",
            snippet='ad := istek.FormValue("kullanıcı")',
            start_line=9,
        ),
        "KF-577BF02AA5EB9928",
        id="utf8",
    ),
]

CANDIDATE_VECTORS = [
    pytest.param(
        (
            "opengrep",
            "python.lang.security.audit.formatted-sql-query",
            "app/db.py",
            10,
            'cursor.execute("SELECT * FROM t WHERE id = %s" % id)',
        ),
        "CAND-2C86C7F310335EEA",
        id="opengrep",
    ),
    pytest.param(("trivy", "CVE-2024-1234", "", None, ""), "CAND-3077FD6E129401C8", id="no-file"),
    pytest.param(
        ("gitleaks", "generic-api-key", "config/settings.py", 3, "  API_KEY = 'abc123'\n"),
        "CAND-7B3323A6A50C8CBD",
        id="gitleaks",
    ),
]


@pytest.mark.parametrize(("inputs", "expected"), FINDING_VECTORS)
def test_finding_id_vectors(inputs, expected):
    assert finding_id(**inputs, used=set()) == expected


@pytest.mark.parametrize(("args", "expected"), CANDIDATE_VECTORS)
def test_candidate_id_vectors(args, expected):
    assert candidate_id(*args) == expected


def test_finding_id_is_the_sha256_of_seed_and_counter():
    seed = b'v1\x00CWE-89\x00app/db.go\x00db.Query("SELECT * FROM t WHERE id = " + id)'
    assert identity_seed(**identity()) == seed.decode()
    digest = hashlib.sha256(seed + b"\x000").hexdigest()
    assert digest == "2cc44b27c1508c41ef3a22ff0e8c08dcf7c38b73ab742ab3e6a53ca15aab1911"
    assert finding_hash(**identity()) == digest
    assert new_id() == FINDING_ID_PREFIX + digest[:16].upper()


def test_candidate_id_is_the_sha256_of_the_joined_fields():
    text = b"trivy\x00CVE-2024-1234\x00\x000\x00"
    expected = CANDIDATE_ID_PREFIX + hashlib.sha256(text).hexdigest()[:16].upper()
    assert candidate_id("trivy", "CVE-2024-1234", "", None, "") == expected


def test_id_formats_and_fingerprint_key():
    assert FINDING_ID.match(new_id())
    assert re.fullmatch(r"[0-9a-f]{64}", finding_hash(**identity()))
    assert CANDIDATE_ID.match(candidate_id("matcher", "go-command-injection", "a.go", 3, "x"))
    assert FINGERPRINT_KEY == "kalkanFinding/v1"


# --- Translated from review_test.go: TestFindingIDsAreStableAndUnique ----------------------


def test_go_model_wording_does_not_change_the_id():
    get_lines = lines_of({"a.go": GO_FILE})
    first = [finding("a.go", 3, title="Command injection", description="first wording")]
    reworded = [finding("a.go", 3, title="OS command injection via f", description="second")]
    assign_finding_ids(first, get_lines=get_lines)
    assign_finding_ids(reworded, get_lines=get_lines)
    assert first[0]["id"] == reworded[0]["id"]
    assert FINDING_ID.match(first[0]["id"])


def test_go_unrelated_line_shift_keeps_the_id():
    original = [finding("a.go", 3)]
    moved = [finding("a.go", 4)]
    assign_finding_ids(original, get_lines=lines_of({"a.go": GO_FILE}))
    shifted = "package a\n\n// added\nfunc f() { exec(input) }\n"
    assign_finding_ids(moved, get_lines=lines_of({"a.go": shifted}))
    assert moved[0]["id"] == original[0]["id"]


def test_go_identical_flagged_source_gets_distinct_ids():
    findings = [finding("a.go", 3), finding("a.go", 4)]
    assign_finding_ids(findings, get_lines=lines_of({"a.go": "\n\nexec(input)\nexec(input)\n"}))
    assert findings[0]["id"] != findings[1]["id"]
    inputs = identity(
        cwe=["CWE-78"], class_slug=None, rule_id=None, uri="a.go", snippet="exec(input)"
    )
    assert findings[0]["id"] == FINDING_ID_PREFIX + finding_hash(**inputs)[:16].upper()
    assert findings[1]["id"] == FINDING_ID_PREFIX + finding_hash(**inputs, counter=1)[:16].upper()


def test_go_existing_ids_survive_a_cwe_change():
    get_lines = lines_of({"a.go": "\n\nexec(input)\nexec(input)\n"})
    findings = [finding("a.go", 3), finding("a.go", 4)]
    assign_finding_ids(findings, get_lines=get_lines)
    before = [record["id"] for record in findings]
    findings[0]["cwe"] = ["CWE-77"]
    assign_finding_ids(findings, get_lines=get_lines)
    assert [record["id"] for record in findings] == before


def test_go_findings_in_different_files_get_unique_ids():
    # review_test.go TestReviewPresentation: "findings lack unique IDs".
    findings = [finding("a.go", 1, cwe=("CWE-79",)), finding("b.go", 1, cwe=("CWE-80",))]
    assign_finding_ids(findings)
    assert findings[0]["id"] != findings[1]["id"]


# --- Stability -------------------------------------------------------------------------------


def test_line_shift_keeps_the_id_when_a_snippet_exists():
    assert new_id(start_line=4) == new_id(start_line=40) == new_id(start_line=None)


def test_whitespace_changes_keep_the_id():
    reformatted = '  db.Query("SELECT *   FROM t\tWHERE id = "\r\n  +  id)\n'
    assert new_id(snippet=reformatted) == new_id()


def test_title_and_message_are_not_inputs():
    # Only the class key, the URI and the anchor enter the seed.
    assert identity_seed(**identity()).split("\x00") == [
        "v1",
        "CWE-89",
        "app/db.go",
        'db.Query("SELECT * FROM t WHERE id = " + id)',
    ]


def test_line_anchor_when_the_snippet_is_blank():
    assert identity_seed(**identity(snippet=" \t\n", start_line=12)).endswith("\x00line:12")
    assert new_id(snippet="", start_line=12) != new_id(snippet="", start_line=13)
    assert identity_seed(**identity(snippet=None, start_line=None)).endswith("app/db.go\x00")
    assert identity_seed(**identity(snippet="", start_line=0)).endswith("\x00line:0")


def test_a_different_file_or_class_changes_the_id():
    assert new_id(uri="app/other.go") != new_id()
    assert new_id(cwe=["CWE-564"]) != new_id()


def test_uri_uses_posix_separators():
    assert new_id(uri="app\\db.go") == new_id(uri="./app/db.go") == new_id(uri="app/db.go")
    assert new_id(uri="/app/db.go") != new_id(uri="app/db.go")


@pytest.mark.parametrize(
    ("cwe", "class_slug", "rule_id", "key"),
    [
        (["CWE-89", "CWE-564"], "sqli", "r", "CWE-89"),
        ([], "sqli", "r", "sqli"),
        ([], None, "r", "r"),
        ([], None, None, "unknown"),
        ([], "", "", "unknown"),
        (None, "xss", None, "xss"),
        (["cwe-089"], None, None, "CWE-89"),
        (["CWE-000"], None, None, "CWE-0"),
        (["NVD-CWE-noinfo", " CWE-79 "], None, None, "CWE-79"),
        (["NVD-CWE-Other", "CWE89"], "xss", None, "xss"),
        ("CWE-22", None, None, "CWE-22"),
    ],
)
def test_class_key_precedence_and_cwe_normalization(cwe, class_slug, rule_id, key):
    seed = identity_seed(
        cwe=cwe, class_slug=class_slug, rule_id=rule_id, uri="a.go", snippet="x()", start_line=1
    )
    assert seed.split("\x00")[1] == key


def test_a_lone_surrogate_does_not_crash():
    assert FINDING_ID.match(new_id(snippet="exec(" + chr(0xD800) + ")"))
    assert CANDIDATE_ID.match(candidate_id("matcher", "r", "a.go", 1, chr(0xDFFF)))


# --- Collision counter -----------------------------------------------------------------------


def test_collision_counter_picks_the_first_unused_id():
    used: set[str] = set()
    first, second, third = new_id(used), new_id(used), new_id(used)
    assert (first, second, third) == (
        "KF-2CC44B27C1508C41",
        "KF-199F155553E54C80",
        "KF-C687F4E54428AB2F",
    )
    assert used == {first, second, third}
    assert second == FINDING_ID_PREFIX + finding_hash(**identity(), counter=1)[:16].upper()
    assert third == FINDING_ID_PREFIX + finding_hash(**identity(), counter=2)[:16].upper()


def test_collision_counter_skips_only_used_ids():
    assert new_id({"KF-199F155553E54C80"}) == "KF-2CC44B27C1508C41"
    used = {"KF-2CC44B27C1508C41", "KF-199F155553E54C80", "KF-OTHER"}
    assert new_id(used) == "KF-C687F4E54428AB2F"
    assert used == {"KF-2CC44B27C1508C41", "KF-199F155553E54C80", "KF-OTHER", "KF-C687F4E54428AB2F"}


def test_finding_hash_rejects_a_negative_counter():
    with pytest.raises(ValueError):
        finding_hash(**identity(), counter=-1)


# --- assign_finding_ids ----------------------------------------------------------------------


def test_assign_keeps_existing_ids_and_never_reuses_them():
    natural = new_id(**line_anchor("a.go", 3))
    findings = [finding("a.go", 3), finding("a.go", 3, id=natural)]
    assign_finding_ids(findings)
    assert findings[1]["id"] == natural
    expected = finding_hash(**line_anchor("a.go", 3), counter=1)
    assert findings[0]["id"] == FINDING_ID_PREFIX + expected[:16].upper()


def test_assign_keeps_any_non_empty_id():
    findings = [finding("a.go", 3, id="legacy-1")]
    assign_finding_ids(findings)
    assert findings[0]["id"] == "legacy-1"


@pytest.mark.parametrize("bad_id", ["", None, 7])
def test_assign_replaces_an_empty_or_non_string_id(bad_id):
    findings = [finding("a.go", 3, id=bad_id)]
    assign_finding_ids(findings)
    assert findings[0]["id"] == new_id(**line_anchor("a.go", 3))


def test_assign_follows_list_order_for_collisions():
    findings = [finding("a.go", 3, title="first"), finding("a.go", 3, title="second")]
    assign_finding_ids(findings)
    assert findings[0]["id"] == new_id(**line_anchor("a.go", 3))
    expected = finding_hash(**line_anchor("a.go", 3), counter=1)
    assert findings[1]["id"] == FINDING_ID_PREFIX + expected[:16].upper()


def test_assign_uses_the_class_slug_without_a_cwe():
    with_class = finding("a.go", 3, cwe=(), **{"class": "os-command-injection"})
    without = finding("a.go", 3, cwe=())
    assign_finding_ids([with_class, without])
    slug_inputs = {**line_anchor("a.go", 3, cwe=()), "class_slug": "os-command-injection"}
    assert with_class["id"] == new_id(**slug_inputs)
    assert without["id"] == new_id(**line_anchor("a.go", 3, cwe=()))
    assert identity_seed(**line_anchor("a.go", 3, cwe=())).split("\x00")[1] == "unknown"


def test_assign_ignores_non_string_cwe_items_and_a_non_string_class():
    record = finding("a.go", 3, cwe=(), **{"class": 5})
    record["cwe"] = [89, "CWE-78"]
    assign_finding_ids([record])
    assert record["id"] == new_id(**line_anchor("a.go", 3))


def test_assign_without_get_lines_uses_the_line_anchor():
    findings = [finding("a.go", 3)]
    assign_finding_ids(findings)
    assert findings[0]["id"] == new_id(**line_anchor("a.go", 3))


def test_assign_with_get_lines_uses_the_source_line():
    findings = [finding("a.go", 3)]
    assign_finding_ids(findings, get_lines=lines_of({"a.go": GO_FILE}))
    inputs = line_anchor("a.go", 3)
    inputs["snippet"] = "func f() { exec(input) }"
    assert findings[0]["id"] == new_id(**inputs)


@pytest.mark.parametrize(
    ("files", "line"),
    [
        ({}, 3),
        ({"a.go": GO_FILE}, 99),
        ({"a.go": GO_FILE}, 2),
    ],
    ids=["missing-file", "line-out-of-range", "blank-line"],
)
def test_assign_falls_back_to_the_line_anchor(files, line):
    findings = [finding("a.go", line)]
    assign_finding_ids(findings, get_lines=lines_of(files))
    assert findings[0]["id"] == new_id(**line_anchor("a.go", line))


@pytest.mark.parametrize(
    "error",
    [OSError("denied"), UnsafeInputError("symlink"), ValueError("embedded null character")],
)
def test_assign_treats_lookup_errors_as_missing_lines(error):
    def get_lines(path):
        raise error

    findings = [finding("a.go", 3)]
    assign_finding_ids(findings, get_lines=get_lines)
    assert findings[0]["id"] == new_id(**line_anchor("a.go", 3))


def test_assign_reads_each_file_once():
    calls = []

    def get_lines(path):
        calls.append(path)
        return GO_FILE.split("\n")

    findings = [finding("a.go", 3), finding("a.go", 4), finding("b.go", 1), finding("a.go", 1)]
    assign_finding_ids(findings, get_lines=get_lines)
    assert calls == ["a.go", "b.go"]


def test_assign_skips_get_lines_for_findings_with_ids():
    calls = []
    findings = [finding("a.go", 3, id="KF-0000000000000001")]
    assign_finding_ids(findings, get_lines=lambda path: calls.append(path))
    assert calls == []


def test_assign_handles_an_empty_list():
    findings: list[dict] = []
    assign_finding_ids(findings)
    assert findings == []


# --- finding_location ------------------------------------------------------------------------


def test_location_prefers_the_first_sink_trace_element():
    record = {
        "trace": [
            {"kind": "entrypoint", "file": "api.py", "line": 2},
            {"kind": "sink", "file": "db.py", "line": 9},
            {"kind": "sink", "file": "db2.py", "line": 1},
        ],
        "evidence": [{"file": "ev.py", "line": 5}],
    }
    assert finding_location(record) == ("db.py", 9)


def test_location_falls_back_to_the_first_evidence_element():
    record = {
        "trace": [{"kind": "entrypoint", "file": "api.py", "line": 2}],
        "evidence": [{"file": "ev.py", "line": 5}, {"file": "ev2.py", "line": 6}],
    }
    assert finding_location(record) == ("ev.py", 5)


@pytest.mark.parametrize(
    "record",
    [
        {},
        {"trace": "bad", "evidence": ["bad"]},
        {"trace": [], "evidence": []},
        {"evidence": [{"file": 3, "line": True}]},
    ],
)
def test_location_without_a_usable_element(record):
    assert finding_location(record) == ("", None)


# --- collapse_whitespace, trim_whitespace, cached_get_lines ----------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("", ""),
        ("   ", ""),
        ("a", "a"),
        ("  a  b  ", "a b"),
        ("a\tb\nc\r\nd\x0be\x0cf", "a b c d e f"),
        ("a\xa0b\x85c", "a b c"),
        ("a" + chr(0x3000) + "b" + chr(0x2028) + "c" + chr(0x1680) + "d" + chr(0x202F), "a b c d"),
        ("a\x1cb\x1fc", "a\x1cb\x1fc"),
        ("a" + chr(0x200B) + "b", "a" + chr(0x200B) + "b"),
        ("kullanıcı  adı", "kullanıcı adı"),
    ],
)
def test_collapse_whitespace_matches_go_strings_fields(text, expected):
    assert collapse_whitespace(text) == expected


def test_whitespace_is_the_go_unicode_isspace_set():
    python_space = {chr(code) for code in range(0x110000) if chr(code).isspace()}
    separators = {chr(code) for code in range(0x1C, 0x20)}
    assert set(WHITESPACE) == python_space - separators
    assert len(WHITESPACE) == 25


def test_trim_whitespace_matches_go_strings_trimspace():
    assert trim_whitespace("\xa0 x y \t") == "x y"
    assert trim_whitespace("\x1c x \x1f") == "\x1c x \x1f"
    assert trim_whitespace(chr(0x3000) + "x") == "x"


def test_cached_get_lines_calls_get_lines_once_per_path():
    calls = []

    def get_lines(path):
        calls.append(path)
        return None if path == "missing" else ["line"]

    lines_for = cached_get_lines(get_lines)
    assert lines_for("a") == ["line"]
    assert lines_for("a") == ["line"]
    assert lines_for("missing") is None
    assert lines_for("missing") is None
    assert calls == ["a", "missing"]


@pytest.mark.parametrize(
    "error",
    [OSError("gone"), UnsafeInputError("unsafe"), UnicodeDecodeError("utf-8", b"\xff", 0, 1, "x")],
)
def test_cached_get_lines_maps_lookup_errors_to_none(error):
    def get_lines(path):
        raise error

    assert cached_get_lines(get_lines)("a") is None


def test_cached_get_lines_lets_other_errors_through():
    def get_lines(path):
        raise RuntimeError("bug")

    with pytest.raises(RuntimeError):
        cached_get_lines(get_lines)("a")


# --- candidate_id ----------------------------------------------------------------------------


def test_candidate_id_treats_a_missing_start_line_as_zero():
    assert candidate_id("bandit", "B602", "a.py", None, "x") == candidate_id(
        "bandit", "B602", "a.py", 0, "x"
    )


def test_candidate_id_collapses_snippet_whitespace():
    assert candidate_id("bandit", "B602", "a.py", 3, "  os.system( cmd )\n") == candidate_id(
        "bandit", "B602", "a.py", 3, "os.system(\tcmd\t)"
    )
    assert candidate_id("bandit", "B602", "a.py", 3, None) == candidate_id(
        "bandit", "B602", "a.py", 3, ""
    )


def test_candidate_id_uses_posix_paths():
    expected = candidate_id("bandit", "B602", "app/a.py", 3, "x")
    assert candidate_id("bandit", "B602", "app\\a.py", 3, "x") == expected
    assert candidate_id("bandit", "B602", "./app/a.py", 3, "x") == expected


@pytest.mark.parametrize(
    "changed",
    [
        ("semgrep", "B602", "a.py", 3, "x"),
        ("bandit", "B603", "a.py", 3, "x"),
        ("bandit", "B602", "b.py", 3, "x"),
        ("bandit", "B602", "a.py", 4, "x"),
        ("bandit", "B602", "a.py", 3, "y"),
    ],
)
def test_candidate_id_depends_on_every_field(changed):
    assert candidate_id(*changed) != candidate_id("bandit", "B602", "a.py", 3, "x")


def test_field_separator_prevents_shifted_collisions():
    assert candidate_id("ab", "c", "f", 1, "s") != candidate_id("a", "bc", "f", 1, "s")
