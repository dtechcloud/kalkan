# SPDX-License-Identifier: Apache-2.0
# Ported from block/codecrucible@b5c8086: internal/cli/scan_audit_v2_test.go
# Copyright 2026 Block, Inc. Changes: translated from Go to Python (verdict policy, evidence
# verifier, numbered source, and the evaluation and duplicate parts of the audit tests);
# kalkan edge cases added.
"""Tests for kalkan.findings.quote_verify (ENGINE-SPEC 6.3)."""

from __future__ import annotations

import builtins
import io
import json

import pytest

from kalkan.errors import UnsafeInputError, ValidationError
from kalkan.findings.quote_verify import (
    EXPOSURE_STATUSES,
    QUESTIONS,
    STATUSES,
    UNGROUNDED_REFUTATION,
    UNVERIFIED_EVIDENCE,
    Answer,
    Evidence,
    Exposure,
    audit_verdict,
    check_answer,
    check_exposure,
    compute_verdict,
    evaluate,
    mark_duplicates,
    numbered_source,
    to_canonical_verdict,
    verify_evidence,
    verify_quote,
)

DB_GO = (
    "package db\n"
    "\n"
    "func Find(id string) {\n"
    '\trows := db.Query("SELECT * FROM t WHERE id = ?", id)\n'
    "\t_ = rows\n"
    "}\n"
)

# v2Fixture in scan_audit_v2_test.go.
FIXTURE = {
    "app/db.go": (
        'package app\n\nfunc Find(id string) {\n\tdb.Query("SELECT * FROM t WHERE id = " + id)\n}\n'
    ),
    "app/admin.go": 'package app\n\n// @RequiresRole("admin")\nfunc Purge() {\n\tdeleteAll()\n}\n',
    "app/file.go": "package app\n\nfunc Read(name string) {\n\tos.ReadFile(name)\n}\n",
}


def source(files):
    """Return a get_lines over in-memory files, split like Go strings.Split(text, "\\n")."""

    def get_lines(path):
        text = files.get(path)
        return None if text is None else text.split("\n")

    return get_lines


GET_DB = source({"app/db.go": DB_GO})
GET_FIXTURE = source(FIXTURE)


def counting(get_lines):
    calls = []

    def wrapped(path):
        calls.append(path)
        return get_lines(path)

    return wrapped, calls


def statuses(ac, pb, um):
    return {
        "attacker_control": Answer(ac),
        "privilege_boundary": Answer(pb),
        "unmitigated": Answer(um),
    }


def answer_json(status, reason="", evidence=()):
    return {
        "status": status,
        "reason": reason,
        "evidence": [{"file": f, "line": n, "quote": q} for f, n, q in evidence],
    }


def established_json(reason="x"):
    return answer_json("established", reason)


def answers_from(result):
    """Rebuild Answer objects from the audit_answers JSON that evaluate returns."""
    return {
        question: Answer(
            value["status"], value["reason"], [Evidence(**item) for item in value["evidence"]]
        )
        for question, value in result["audit_answers"].items()
    }


# --- Translated from TestAuditVerdictV2Policy ------------------------------------------------


@pytest.mark.parametrize(
    ("answers", "verdict", "reasons"),
    [
        (statuses("established", "established", "established"), "confirmed", []),
        (
            statuses("established", "refuted", "established"),
            "rejected",
            ["refuted:privilege_boundary"],
        ),
        (statuses("unknown", "established", "refuted"), "rejected", ["refuted:unmitigated"]),
        (
            statuses("established", "unknown", "established"),
            "unverified",
            ["unknown:privilege_boundary"],
        ),
        (statuses("", "established", "established"), "unverified", ["unknown:attacker_control"]),
    ],
)
def test_go_verdict_policy(answers, verdict, reasons):
    assert audit_verdict(answers) == (verdict, reasons)
    assert compute_verdict(answers) == verdict


def test_every_refutation_is_a_reason_in_question_order():
    answers = statuses("refuted", "unknown", "refuted")
    assert audit_verdict(answers) == (
        "rejected",
        ["refuted:attacker_control", "refuted:unmitigated"],
    )


def test_missing_questions_count_as_unknown():
    assert audit_verdict({}) == (
        "unverified",
        ["unknown:attacker_control", "unknown:privilege_boundary", "unknown:unmitigated"],
    )
    partial = {
        "attacker_control": Answer("established"),
        "privilege_boundary": Answer("established"),
    }
    assert audit_verdict(partial) == ("unverified", ["unknown:unmitigated"])


def test_verdict_needs_exact_statuses():
    # check_answer normalizes the status. audit_verdict compares it exactly, like Go.
    assert compute_verdict(statuses("Refuted", "established", "established")) == "unverified"
    assert compute_verdict(statuses(" established", "established", "established")) == "unverified"


def test_verdict_ignores_extra_questions():
    answers = statuses("established", "established", "established")
    answers["deployment_exposure"] = Answer("refuted")
    assert compute_verdict(answers) == "confirmed"


# --- Translated from TestEvidenceVerifierChecksQuotesAgainstSource ---------------------------


@pytest.mark.parametrize(
    ("item", "ok"),
    [
        pytest.param(
            Evidence("app/db.go", 4, 'rows := db.Query("SELECT * FROM t WHERE id = ?", id)'),
            True,
            id="exact",
        ),
        pytest.param(Evidence("app/db.go", 4, "rows   :=  db.Query("), True, id="whitespace"),
        pytest.param(Evidence("app/db.go", 6, "db.Query("), True, id="within-two-lines"),
        pytest.param(
            Evidence("app/db.go", 3, "3| func Find(id string) {"), True, id="line-prefix-copied"
        ),
        pytest.param(Evidence("app/db.go", 1, "db.Query("), False, id="too-far"),
        pytest.param(
            Evidence("app/db.go", 4, "if !isAdmin(user) { return }"), False, id="fabricated"
        ),
        pytest.param(Evidence("app/db.go", 6, "}"), False, id="too-short"),
        pytest.param(Evidence("other.go", 1, "package db"), False, id="unknown-file"),
        pytest.param(Evidence("app/db.go", 99, "package db"), False, id="line-out-of-range"),
    ],
)
def test_go_evidence_verifier_checks_quotes_against_source(item, ok):
    got = verify_evidence([item], GET_DB)
    assert (len(got) == 1) is ok
    if ok:
        assert got[0].file == "app/db.go"
        assert got[0].line == item.line


def test_go_repaired_path_needs_a_resolving_get_lines():
    # Go ResolvePath turns "db.go" into "app/db.go". kalkan leaves path repair to get_lines,
    # and a verified item keeps the cited path.
    item = Evidence("db.go", 3, "func Find")
    assert verify_evidence([item], GET_DB) == []

    def resolving(path):
        matches = [name for name in ("app/db.go",) if name == path or name.endswith("/" + path)]
        return GET_DB(matches[0]) if len(matches) == 1 else None

    assert verify_evidence([item], resolving) == [Evidence("db.go", 3, "func Find")]


def test_go_refutation_without_evidence_is_ungrounded():
    assert check_answer(Answer("refuted", "guarded"), GET_DB) == (
        Answer("unknown", "guarded", []),
        UNGROUNDED_REFUTATION,
    )


def test_go_refutation_with_fabricated_evidence_is_unverified():
    refuted = Answer("refuted", "guarded", [Evidence("app/db.go", 4, "if !isAdmin(user)")])
    assert check_answer(refuted, GET_DB) == (Answer("unknown", "guarded", []), UNVERIFIED_EVIDENCE)


def test_go_established_without_evidence_stays():
    answer = Answer("established", "searched handlers; no guard")
    assert check_answer(answer, GET_DB) == (answer, None)


def test_go_not_deployed_without_evidence_is_not_recorded():
    assert check_exposure(Exposure("not_deployed"), GET_DB) is None


def test_go_config_enabled_exposure_is_recorded():
    exposure = Exposure("config_enabled", "feature.flag")
    assert check_exposure(exposure, GET_DB) == Exposure("config_enabled", "feature.flag", [])


# --- Translated from TestNumberedSource ------------------------------------------------------


def test_go_numbered_source():
    assert numbered_source("a\nb\n") == "1| a\n2| b\n"
    assert numbered_source("a\nb") == "1| a\n2| b\n"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("", ""),
        ("\n", "1| \n"),
        ("a\n\nb", "1| a\n2| \n3| b\n"),
        ("a\r\nb\r\n", "1| a\r\n2| b\r\n"),
    ],
)
def test_numbered_source_edges(text, expected):
    assert numbered_source(text) == expected


def test_numbered_lines_verify_with_their_prefix():
    lines = DB_GO.split("\n")
    for number, numbered in enumerate(numbered_source(DB_GO).splitlines(), start=1):
        text = numbered.split("| ", 1)[1].strip()
        if len(text) >= 4:
            assert verify_quote(lines, number, numbered), numbered


# --- Translated from the audit tests (evaluation parts) --------------------------------------


def test_go_audit_sql_injection_is_confirmed():
    quote = '"SELECT * FROM t WHERE id = " + id'
    result = evaluate(
        {
            "attacker_control": answer_json("established", "", [("app/db.go", 4, quote)]),
            "privilege_boundary": established_json("unauthenticated"),
            "unmitigated": established_json("no escaping"),
        },
        GET_FIXTURE,
    )
    assert result["verdict"] == "confirmed"
    assert result["reasons"] == {}
    assert result["audit_answers"]["attacker_control"]["evidence"] == [
        {"file": "app/db.go", "line": 4, "quote": quote}
    ]


def test_go_audit_admin_by_design_is_rejected():
    result = evaluate(
        {
            "attacker_control": established_json("request reaches Purge"),
            "privilege_boundary": answer_json(
                "refuted", "admin-only by design", [("app/admin.go", 3, '@RequiresRole("admin")')]
            ),
            "unmitigated": established_json("no other check"),
        },
        GET_FIXTURE,
    )
    assert result["verdict"] == "rejected"
    assert result["reasons"] == {}
    assert audit_verdict(answers_from(result)) == ("rejected", ["refuted:privilege_boundary"])
    assert result["audit_answers"]["privilege_boundary"]["evidence"] == [
        {"file": "app/admin.go", "line": 3, "quote": '@RequiresRole("admin")'}
    ]


def test_go_audit_fabricated_refutation_stays_unverified():
    result = evaluate(
        {
            "attacker_control": established_json("name is a query parameter"),
            "privilege_boundary": established_json("public"),
            "unmitigated": answer_json(
                "refuted", "sanitized", [("app/file.go", 4, "filepath.Base(name)")]
            ),
        },
        GET_FIXTURE,
    )
    assert result["verdict"] == "needs_validation"
    assert result["reasons"] == {"unmitigated": UNVERIFIED_EVIDENCE}
    assert audit_verdict(answers_from(result)) == ("unverified", ["unknown:unmitigated"])
    exposure = check_exposure(Exposure("not_deployed", "looks like a dev tool"), GET_FIXTURE)
    assert exposure == Exposure("unknown", "looks like a dev tool", [])


def test_go_audit_second_report_is_a_duplicate():
    verdicts = {
        "sqli": "confirmed",
        "admin": "rejected",
        "path": "unverified",
        "sqli-2": "confirmed",
    }
    batch_of = dict.fromkeys(verdicts, 0)
    assert mark_duplicates(verdicts, {"sqli-2": "sqli"}, batch_of) == {"sqli-2": "sqli"}


def test_go_partial_coverage_answer_is_unverified():
    result = evaluate(
        {
            "attacker_control": established_json(),
            "privilege_boundary": answer_json("unknown"),
            "unmitigated": established_json(),
        },
        GET_FIXTURE,
    )
    assert result["verdict"] == "needs_validation"
    assert result["reasons"] == {}


def test_go_duplicate_never_hides_the_stronger_finding():
    unverified_primary = {"a": "unverified", "b": "confirmed"}
    assert mark_duplicates(unverified_primary, {"b": "a"}, {"a": 0, "b": 0}) == {}
    across_batches = {"a": "confirmed", "b": "confirmed"}
    assert mark_duplicates(across_batches, {"b": "a"}, {"a": 0, "b": 1}) == {}


# --- verify_quote: window, prefix, length and letter rules -----------------------------------

FIVE = ["alpha one", "bravo two", "charlie three", "delta four", "echo five"]


@pytest.mark.parametrize(
    ("line", "quote", "ok"),
    [
        (1, "alpha one", True),
        (1, "charlie three", True),
        (1, "delta four", False),
        (5, "echo five", True),
        (5, "charlie three", True),
        (5, "bravo two", False),
        (3, "alpha one", True),
        (3, "echo five", True),
        (0, "alpha one", False),
        (-1, "alpha one", False),
        (6, "echo five", False),
    ],
)
def test_window_is_two_lines_on_each_side_and_clipped_at_file_edges(line, quote, ok):
    assert verify_quote(FIVE, line, quote) is ok


def test_window_does_not_reach_three_lines_away():
    lines = ["a1 x", "b2 x", "c3 x", "d4 x", "e5 x", "f6 x", "g7 x"]
    assert verify_quote(lines, 4, "b2 x")
    assert verify_quote(lines, 4, "f6 x")
    assert not verify_quote(lines, 4, "a1 x")
    assert not verify_quote(lines, 4, "g7 x")


def test_empty_element_after_the_final_newline_is_a_line():
    # Go strings.Split keeps the empty element after a trailing newline.
    lines = DB_GO.split("\n")
    assert len(lines) == 7
    assert verify_quote(lines, 7, "_ = rows")
    assert not verify_quote(lines, 8, "_ = rows")


def test_quote_can_span_two_lines_inside_the_window():
    lines = ["result = compute(", "    user_input,", "    trusted=False)"]
    assert verify_quote(lines, 2, "compute( user_input,")
    assert verify_quote(lines, 1, "user_input,\n    trusted=False)")
    # The window joins lines with a space, so the quote needs whitespace at the line break.
    assert not verify_quote(lines, 2, "compute(user_input,")


def test_quote_must_lie_inside_the_window():
    lines = ["a1 x", "b2 x", "c3 x", "d4 x", "e5 x", "f6 x"]
    assert verify_quote(lines, 3, "d4 x e5 x")
    assert not verify_quote(lines, 3, "e5 x f6 x")


def test_lines_with_and_without_carriage_returns_verify():
    crlf = "first line\r\nsecond line\r\n".split("\n")
    assert verify_quote(crlf, 2, "second line")
    assert verify_quote(crlf, 1, "first line\r\nsecond line")
    plain = "first line\nsecond line".splitlines()
    assert verify_quote(plain, 2, "second line")
    assert verify_quote(plain, 2, "first line second line")


PREFIXED = ["x = 1"] * 11 + ["foo(bar)"] + ["y = 2"] * 3


@pytest.mark.parametrize(
    ("quote", "ok"),
    [
        ("12| foo(bar)", True),
        ("12|foo(bar)", True),
        ("  12|  foo(bar)", True),
        ("\t12|\tfoo(bar)", True),
        ("7| foo(bar)", True),
        ("12 | foo(bar)", False),
        ("L12| foo(bar)", False),
        ("12: foo(bar)", False),
        ("12| 13| foo(bar)", False),
        ("12|", False),
        ("12| foo", False),
        ("\x0b12| foo(bar)", False),
        (chr(0xFF11) + chr(0xFF12) + "| foo(bar)", False),
    ],
    ids=[
        "space-after-bar",
        "no-space",
        "leading-and-extra-spaces",
        "tabs",
        "number-not-checked",
        "space-before-bar",
        "letter-before-number",
        "colon",
        "only-one-prefix-removed",
        "prefix-only",
        "stripped-quote-too-short",
        "vertical-tab-is-not-re2-space",
        "fullwidth-digits-are-not-re2-digits",
    ],
)
def test_line_number_prefix_forms(quote, ok):
    assert verify_quote(PREFIXED, 12, quote) is ok


def test_verified_quote_is_stored_trimmed_and_without_the_prefix():
    item = Evidence("app/db.go", 3, "  3| func Find(id string) {  ")
    assert verify_evidence([item], GET_DB) == [Evidence("app/db.go", 3, "func Find(id string) {")]


def test_quote_as_given_wins_over_the_stripped_form():
    lines = ['table = "1| alpha"']
    item = Evidence("t.py", 1, ' 1| alpha" ')
    assert verify_evidence([item], source({"t.py": lines[0]})) == [Evidence("t.py", 1, '1| alpha"')]


def test_a_multi_line_quote_with_prefixes_does_not_verify():
    # Only the leading prefix is removed, like Go.
    quote = "3| func Find(id string) {\n4| \trows := db.Query("
    assert not verify_quote(DB_GO.split("\n"), 3, quote)
    assert verify_quote(DB_GO.split("\n"), 3, "func Find(id string) {\n\trows := db.Query(")


SAMPLE = ["abcd 1234 _+-* a{}; éé kullanıcı переменная 日本"]


@pytest.mark.parametrize(
    ("quote", "ok"),
    [
        ("abcd", True),
        ("abc", False),
        ("  ab  ", False),
        ("1234", False),
        ("_+-*", False),
        ("a{}", False),
        ("a{};", True),
        ("é", False),
        ("éé", True),
        ("日本", True),
        ("kullanıcı", True),
        ("переменная", True),
        ("", False),
        ("   ", False),
    ],
)
def test_length_is_counted_in_utf8_bytes_and_a_letter_is_required(quote, ok):
    # Go len() counts bytes: "日本" has 2 characters but 6 bytes, so it passes.
    assert verify_quote(SAMPLE, 1, quote) is ok


def test_unicode_whitespace_in_the_source_collapses_like_go():
    assert verify_quote(["x\xa0=\xa0input()"], 1, "x = input()")
    assert verify_quote(["x = input()"], 1, "x" + chr(0x3000) + "=\xa0input()")
    # U+001C is not whitespace in Go, so it does not collapse.
    assert not verify_quote(["a\x1cb cdef"], 1, "a b cdef")


def test_unicode_source_and_quote():
    lines = [
        "def kaydet(kullanıcı_adı):",
        "    sorgu = f\"SELECT * FROM üye WHERE ad = '{kullanıcı_adı}'\"",
    ]
    assert verify_quote(lines, 2, "SELECT * FROM üye WHERE ad")
    assert not verify_quote(lines, 2, "SELECT * FROM uye WHERE ad")


def test_a_lone_surrogate_does_not_crash():
    assert not verify_quote(["abcd"], 1, chr(0xD800) + "abc")
    assert verify_quote(["x" + chr(0xD800) + "abc"], 1, chr(0xD800) + "abc")


# --- verify_evidence and get_lines -----------------------------------------------------------


def test_missing_file_is_unverifiable():
    item = Evidence("missing.go", 1, "package db")
    assert verify_evidence([item], GET_DB) == []
    answer, code = check_answer(Answer("established", "x", [item]), GET_DB)
    assert (answer, code) == (Answer("unknown", "x", []), UNVERIFIED_EVIDENCE)


@pytest.mark.parametrize(
    "error",
    [OSError("no such file"), UnsafeInputError("outside the target"), ValueError("NUL in path")],
)
def test_lookup_errors_count_as_unverifiable(error):
    def get_lines(path):
        raise error

    assert verify_evidence([Evidence("../etc/passwd", 1, "root:x:0:0")], get_lines) == []


def test_other_errors_from_get_lines_propagate():
    def get_lines(path):
        raise RuntimeError("bug")

    with pytest.raises(RuntimeError):
        verify_evidence([Evidence("app/db.go", 1, "package db")], get_lines)


def test_empty_file_name_is_never_looked_up():
    get_lines, calls = counting(GET_DB)
    assert verify_evidence([Evidence("", 1, "package db")], get_lines) == []
    assert calls == []


def test_verify_evidence_keeps_order_and_reads_each_file_once():
    get_lines, calls = counting(GET_FIXTURE)
    items = [
        Evidence("app/file.go", 4, "os.ReadFile(name)"),
        Evidence("app/db.go", 4, "invented()"),
        Evidence("app/db.go", 3, "func Find(id string)"),
        Evidence("app/file.go", 3, "func Read"),
    ]
    assert verify_evidence(items, get_lines) == [items[0], items[2], items[3]]
    assert calls == ["app/file.go", "app/db.go"]


# --- check_answer ------------------------------------------------------------------------------


def test_check_answer_normalizes_status_and_reason():
    assert check_answer(Answer(" Established ", "  reason \n"), GET_DB) == (
        Answer("established", "reason", []),
        None,
    )


def test_check_answer_maps_the_dotted_capital_i_like_go():
    status = "ESTABL" + chr(0x130) + "SHED"
    assert check_answer(Answer(status), GET_DB)[0].status == "established"


def test_unknown_answer_with_failed_quotes_has_no_reason_code():
    answer = Answer("unknown", "x", [Evidence("app/db.go", 4, "not in the source")])
    assert check_answer(answer, GET_DB) == (Answer("unknown", "x", []), None)


def test_established_answer_keeps_only_verified_quotes():
    kept = Evidence("app/db.go", 4, "rows := db.Query(")
    answer = Answer("established", "", [kept, Evidence("app/db.go", 4, "invented call()")])
    assert check_answer(answer, GET_DB) == (Answer("established", "", [kept]), None)


def test_refuted_answer_with_a_verified_quote_stays_refuted():
    kept = Evidence("app/db.go", 4, 'db.Query("SELECT * FROM t WHERE id = ?", id)')
    answer = Answer("refuted", "parameterized", [kept])
    assert check_answer(answer, GET_DB) == (answer, None)


def test_status_outside_the_set_passes_through_and_counts_as_unknown():
    answer, code = check_answer(Answer("maybe"), GET_DB)
    assert (answer.status, code) == ("maybe", None)
    answers = statuses("established", "established", "established")
    answers["attacker_control"] = answer
    assert compute_verdict(answers) == "unverified"
    cited = Answer("maybe", "", [Evidence("app/db.go", 4, "invented()")])
    assert check_answer(cited, GET_DB) == (Answer("unknown", "", []), UNVERIFIED_EVIDENCE)


def test_check_answer_does_not_change_its_input():
    original = Answer("refuted", " r ", [Evidence("app/db.go", 4, " 4| rows := db.Query( ")])
    snapshot = Answer("refuted", " r ", [Evidence("app/db.go", 4, " 4| rows := db.Query( ")])
    checked, _ = check_answer(original, GET_DB)
    assert original == snapshot
    assert checked == Answer("refuted", "r", [Evidence("app/db.go", 4, "rows := db.Query(")])


# --- check_exposure ----------------------------------------------------------------------------

VERIFIED = Evidence("app/db.go", 1, "package db")
FAILED = Evidence("app/db.go", 4, "invented()")


@pytest.mark.parametrize(
    ("exposure", "expected"),
    [
        (Exposure("not_deployed"), None),
        (Exposure("not_deployed", "dev tool"), Exposure("unknown", "dev tool", [])),
        (Exposure("not_deployed", "", [VERIFIED]), Exposure("not_deployed", "", [VERIFIED])),
        (Exposure("not_deployed", "", [FAILED]), None),
        (Exposure("config_enabled", "flag", [FAILED]), Exposure("unknown", "flag", [])),
        (
            Exposure("config_dependent", "", [VERIFIED, FAILED]),
            Exposure("config_dependent", "", [VERIFIED]),
        ),
        (Exposure("default_on"), Exposure("default_on", "", [])),
        (Exposure("sometimes", "x"), Exposure("unknown", "x", [])),
        (Exposure("sometimes"), None),
        (Exposure(" Default_On ", "  x "), Exposure("default_on", "x", [])),
        (Exposure("unknown"), None),
        (
            Exposure("unknown", "depends on the chart"),
            Exposure("unknown", "depends on the chart", []),
        ),
    ],
)
def test_check_exposure(exposure, expected):
    assert check_exposure(exposure, GET_DB) == expected


# --- to_canonical_verdict and mark_duplicates ------------------------------------------------


@pytest.mark.parametrize(
    ("verdict", "canonical"),
    [
        ("confirmed", "confirmed"),
        ("rejected", "rejected"),
        ("unverified", "needs_validation"),
        ("needs_validation", "needs_validation"),
    ],
)
def test_canonical_verdicts(verdict, canonical):
    assert to_canonical_verdict(verdict) == canonical


@pytest.mark.parametrize("verdict", ["duplicate", "not_audited", "Confirmed", ""])
def test_unknown_verdict_raises(verdict):
    with pytest.raises(ValueError):
        to_canonical_verdict(verdict)


@pytest.mark.parametrize(
    ("verdicts", "duplicate_of", "expected"),
    [
        pytest.param({"a": "confirmed"}, {"a": "a"}, {}, id="self"),
        pytest.param({"a": "confirmed"}, {"a": "b"}, {}, id="target-not-assessed"),
        pytest.param({"a": "rejected", "b": "confirmed"}, {"a": "b"}, {}, id="rejected-claim"),
        pytest.param({"a": "unverified", "b": "rejected"}, {"a": "b"}, {}, id="target-ranks-lower"),
        pytest.param(
            {"a": "unverified", "b": "confirmed"}, {"a": "b"}, {"a": "b"}, id="target-stronger"
        ),
        pytest.param(
            {"a": "needs_validation", "b": "unverified"},
            {"a": " b "},
            {"a": "b"},
            id="canonical-name-and-trimmed-target",
        ),
        pytest.param(
            {"a": "confirmed", "b": "confirmed", "c": "confirmed"},
            {"a": "b", "b": "c"},
            {"b": "c"},
            id="target-names-a-duplicate-itself",
        ),
        pytest.param({"a": "confirmed", "b": "confirmed"}, {"a": "", "b": "  "}, {}, id="empty"),
    ],
)
def test_mark_duplicates(verdicts, duplicate_of, expected):
    assert mark_duplicates(verdicts, duplicate_of) == expected


def test_mark_duplicates_defaults_missing_batches_to_zero():
    verdicts = {"a": "confirmed", "b": "confirmed"}
    assert mark_duplicates(verdicts, {"b": "a"}, {"a": 0}) == {"b": "a"}
    assert mark_duplicates(verdicts, {"b": "a"}, {"a": 1}) == {}


# --- evaluate ----------------------------------------------------------------------------------


def test_evaluate_returns_the_documented_shape():
    result = evaluate(
        {question: established_json() for question in QUESTIONS},
        GET_FIXTURE,
    )
    assert set(result) == {"verdict", "audit_answers", "reasons"}
    assert list(result["audit_answers"]) == list(QUESTIONS)
    for value in result["audit_answers"].values():
        assert value == {"status": "established", "reason": "x", "evidence": []}
    assert json.loads(json.dumps(result)) == result


def test_evaluate_downgrades_and_reports_reason_codes():
    result = evaluate(
        {
            "attacker_control": answer_json("established", "a", [("app/db.go", 4, "invented()")]),
            "privilege_boundary": answer_json("refuted", "b"),
            "unmitigated": answer_json(" ESTABLISHED ", " c "),
        },
        GET_FIXTURE,
    )
    assert result["verdict"] == "needs_validation"
    assert result["reasons"] == {
        "attacker_control": UNVERIFIED_EVIDENCE,
        "privilege_boundary": UNGROUNDED_REFUTATION,
    }
    assert result["audit_answers"] == {
        "attacker_control": {"status": "unknown", "reason": "a", "evidence": []},
        "privilege_boundary": {"status": "unknown", "reason": "b", "evidence": []},
        "unmitigated": {"status": "established", "reason": "c", "evidence": []},
    }


def test_evaluate_reads_each_file_once():
    get_lines, calls = counting(GET_FIXTURE)
    result = evaluate(
        {
            "attacker_control": answer_json("established", "", [("app/db.go", 3, "func Find")]),
            "privilege_boundary": answer_json("established", "", [("app/db.go", 1, "package")]),
            "unmitigated": answer_json("established", "", [("app/db.go", 4, "db.Query(")]),
        },
        get_lines,
    )
    assert result["verdict"] == "confirmed"
    assert calls == ["app/db.go"]


def test_evaluate_never_opens_files(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("quote_verify opened a file")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(io, "open", forbidden)
    result = evaluate(
        {
            "attacker_control": answer_json("established", "", [("app/db.go", 3, "func Find")]),
            "privilege_boundary": established_json(),
            "unmitigated": established_json(),
        },
        GET_FIXTURE,
    )
    assert result["verdict"] == "confirmed"


def test_evaluate_ignores_extra_keys():
    answers = {question: dict(established_json(), confidence="high") for question in QUESTIONS}
    answers["deployment_exposure"] = {"status": "not_deployed"}
    answers["unmitigated"]["evidence"] = [
        {"file": "app/db.go", "line": 3, "quote": "func Find", "note": "x"}
    ]
    result = evaluate(answers, GET_FIXTURE)
    assert result["verdict"] == "confirmed"
    assert result["audit_answers"]["unmitigated"]["evidence"] == [
        {"file": "app/db.go", "line": 3, "quote": "func Find"}
    ]


def test_evaluate_treats_null_like_the_go_zero_value():
    result = evaluate(
        {
            "attacker_control": {"status": "established", "reason": None, "evidence": None},
            "privilege_boundary": {"status": "established", "evidence": [None]},
            "unmitigated": {
                "status": "established",
                "evidence": [{"file": None, "line": None, "quote": None}],
            },
        },
        GET_FIXTURE,
    )
    assert result["verdict"] == "needs_validation"
    assert result["reasons"] == {
        "privilege_boundary": UNVERIFIED_EVIDENCE,
        "unmitigated": UNVERIFIED_EVIDENCE,
    }
    assert result["audit_answers"]["attacker_control"] == {
        "status": "established",
        "reason": "",
        "evidence": [],
    }


def test_evaluate_with_unicode_source():
    files = {
        "uygulama/üye.py": (
            "def bul(ad):\n    return db.sorgu(f\"SELECT * FROM üye WHERE ad='{ad}'\")\n"
        )
    }
    result = evaluate(
        {
            "attacker_control": established_json(),
            "privilege_boundary": established_json(),
            "unmitigated": answer_json(
                "refuted", "x", [("uygulama/üye.py", 2, '2| return db.sorgu(f"SELECT * FROM üye')]
            ),
        },
        source(files),
    )
    assert result["verdict"] == "rejected"
    assert result["audit_answers"]["unmitigated"]["evidence"][0]["quote"] == (
        'return db.sorgu(f"SELECT * FROM üye'
    )


def valid_answers(**changes):
    answers = {question: established_json() for question in QUESTIONS}
    answers.update(changes)
    return answers


def with_evidence(item):
    return valid_answers(attacker_control={"status": "established", "evidence": [item]})


@pytest.mark.parametrize(
    ("answers_json", "message"),
    [
        ([], "audit_answers: expected an object"),
        (None, "audit_answers: expected an object"),
        (
            valid_answers(attacker_control=None),
            "audit_answers.attacker_control: expected an object with a status",
        ),
        (
            {"privilege_boundary": established_json(), "unmitigated": established_json()},
            "audit_answers.attacker_control: expected an object with a status",
        ),
        (
            valid_answers(unmitigated={"status": "maybe"}),
            "audit_answers.unmitigated.status: expected established, refuted or unknown",
        ),
        (
            valid_answers(unmitigated={"reason": "x"}),
            "audit_answers.unmitigated.status: expected established, refuted or unknown",
        ),
        (
            valid_answers(unmitigated={"status": 3}),
            "audit_answers.unmitigated.status: expected established, refuted or unknown",
        ),
        (
            valid_answers(unmitigated={"status": "unknown", "reason": 5}),
            "audit_answers.unmitigated.reason: expected a string",
        ),
        (
            valid_answers(unmitigated={"status": "unknown", "evidence": "x"}),
            "audit_answers.unmitigated.evidence: expected an array",
        ),
        (
            with_evidence("x"),
            "audit_answers.attacker_control.evidence[0]: expected an object",
        ),
        (
            with_evidence({"file": "a", "line": "4", "quote": "abcd"}),
            "audit_answers.attacker_control.evidence[0].line: expected an integer",
        ),
        (
            with_evidence({"file": "a", "line": 4.0, "quote": "abcd"}),
            "audit_answers.attacker_control.evidence[0].line: expected an integer",
        ),
        (
            with_evidence({"file": "a", "line": True, "quote": "abcd"}),
            "audit_answers.attacker_control.evidence[0].line: expected an integer",
        ),
        (
            with_evidence({"file": 1, "line": 4, "quote": "abcd"}),
            "audit_answers.attacker_control.evidence[0].file: expected a string",
        ),
        (
            with_evidence({"file": "a", "line": 4, "quote": ["abcd"]}),
            "audit_answers.attacker_control.evidence[0].quote: expected a string",
        ),
    ],
)
def test_evaluate_rejects_invalid_json(answers_json, message):
    with pytest.raises(ValidationError) as caught:
        evaluate(answers_json, GET_FIXTURE)
    assert message in caught.value.errors


def test_evaluate_collects_every_error():
    with pytest.raises(ValidationError) as caught:
        evaluate({"unmitigated": {"status": "maybe", "reason": 1}}, GET_FIXTURE)
    assert caught.value.errors == [
        "audit_answers.attacker_control: expected an object with a status",
        "audit_answers.privilege_boundary: expected an object with a status",
        "audit_answers.unmitigated.status: expected established, refuted or unknown",
        "audit_answers.unmitigated.reason: expected a string",
    ]


def test_constants_match_the_go_schema():
    assert QUESTIONS == ("attacker_control", "privilege_boundary", "unmitigated")
    assert STATUSES == ("established", "refuted", "unknown")
    assert EXPOSURE_STATUSES == (
        "default_on",
        "config_enabled",
        "config_dependent",
        "not_deployed",
        "unknown",
    )
