# SPDX-License-Identifier: MIT
"""Tests for kalkan.findings.severity (ENGINE-SPEC 7)."""

from __future__ import annotations

import math

import pytest

from kalkan.findings.severity import (
    SEVERITIES,
    for_sarif_result,
    from_label,
    from_level,
    from_score,
    max_severity,
    rank,
    to_sarif_level,
    to_security_severity,
)


def test_severities_are_ordered_from_high_to_low():
    assert SEVERITIES == ("critical", "high", "medium", "low", "info")
    assert [rank(s) for s in SEVERITIES] == [4, 3, 2, 1, 0]


def test_rank_accepts_labels_and_rejects_other_values():
    assert rank("CRITICAL") == 4
    assert rank("informational") == 0
    with pytest.raises(ValueError):
        rank("severe")
    with pytest.raises(ValueError):
        rank(None)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (10.0, "critical"),
        (9.0, "critical"),
        (8.99, "high"),
        (7.0, "high"),
        (6.99, "medium"),
        (4.0, "medium"),
        (3.99, "low"),
        (0.1, "low"),
        (0.0, "info"),
        (0, "info"),
        (9, "critical"),
        (11.5, "critical"),
        ("7.5", "high"),
        (" 5.5 ", "medium"),
        ("0.0", "info"),
    ],
)
def test_from_score_thresholds(score, expected):
    assert from_score(score) == expected


@pytest.mark.parametrize("score", [-0.1, -5, "abc", "", None, True, math.nan, math.inf, [7.0]])
def test_from_score_rejects_invalid_values(score):
    assert from_score(score) is None


@pytest.mark.parametrize(
    ("level", "expected"),
    [
        ("error", "high"),
        ("warning", "medium"),
        ("note", "low"),
        ("none", "info"),
        ("Error", "high"),
        (" WARNING ", "medium"),
    ],
)
def test_from_level(level, expected):
    assert from_level(level) == expected


@pytest.mark.parametrize("level", ["fatal", "", "high", None, 1])
def test_from_level_rejects_other_values(level):
    assert from_level(level) is None


@pytest.mark.parametrize(
    ("label", "expected"),
    [
        ("CRITICAL", "critical"),
        ("High", "high"),
        ("MEDIUM", "medium"),
        ("moderate", "medium"),
        ("MODERATE", "medium"),
        ("LOW", "low"),
        ("INFO", "info"),
        ("Informational", "info"),
        ("UNKNOWN", "info"),
        # deepsec (ENGINE-SPEC 7)
        ("HIGH_BUG", "info"),
        ("high-bug", "info"),
        ("BUG", "info"),
        # Grype
        ("Negligible", "info"),
        ("None", "info"),
        # open-code-review labels map directly
        ("critical", "critical"),
        ("low", "low"),
    ],
)
def test_from_label(label, expected):
    assert from_label(label) == expected


@pytest.mark.parametrize("label", ["severe", "", "error", "P1", None, 3])
def test_from_label_rejects_other_values(label):
    assert from_label(label) is None


def test_max_severity():
    assert max_severity("low", "high", "medium") == "high"
    assert max_severity("info", None, "low") == "low"
    assert max_severity("CRITICAL", "high") == "critical"
    assert max_severity() is None
    assert max_severity(None, None) is None
    with pytest.raises(ValueError):
        max_severity("low", "severe")


# --- for_sarif_result: one test per precedence rule (ENGINE-SPEC 7) ---------------------------


def test_result_security_severity_comes_first():
    result = {"level": "note", "properties": {"security-severity": "9.1", "severity": "LOW"}}
    rule = {"properties": {"security-severity": "2.0"}}
    assert for_sarif_result(result, rule) == ("critical", "9.1")


def test_rule_security_severity_when_the_result_has_none():
    result = {"level": "note"}
    rule = {"properties": {"security-severity": "7.5", "tags": ["LOW"]}}
    assert for_sarif_result(result, rule) == ("high", "7.5")


def test_numeric_security_severity_value_is_accepted():
    assert for_sarif_result({"properties": {"security-severity": 4}}, None) == ("medium", "4")


def test_invalid_security_severity_is_ignored():
    result = {"properties": {"security-severity": "n/a", "severity": "HIGH"}}
    assert for_sarif_result(result, None) == ("high", "HIGH")
    result = {"level": "warning", "properties": {"security-severity": "-1"}}
    assert for_sarif_result(result, None) == ("medium", "warning")


def test_text_label_beats_level():
    result = {"level": "error", "properties": {"severity": "LOW"}}
    assert for_sarif_result(result, None) == ("low", "LOW")


def test_bandit_issue_severity_label():
    result = {"level": "warning", "properties": {"issue_severity": "HIGH"}}
    assert for_sarif_result(result, None) == ("high", "HIGH")


def test_codeql_problem_severity_label():
    rule = {"properties": {"problem.severity": "recommendation"}}
    assert for_sarif_result({}, rule) == ("low", "recommendation")
    rule = {"properties": {"problem": {"severity": "error"}}}
    assert for_sarif_result({}, rule) == ("high", "error")


def test_result_label_beats_rule_label():
    result = {"properties": {"severity": "MODERATE"}}
    rule = {"properties": {"severity": "CRITICAL"}}
    assert for_sarif_result(result, rule) == ("medium", "MODERATE")


def test_rule_label_when_the_result_has_none():
    rule = {"properties": {"issue_severity": "LOW"}, "defaultConfiguration": {"level": "error"}}
    assert for_sarif_result({"level": "error"}, rule) == ("low", "LOW")


def test_unknown_label_falls_through_to_the_level():
    result = {"level": "note", "properties": {"severity": "P1"}}
    assert for_sarif_result(result, None) == ("low", "note")


def test_severity_tag_beats_level():
    # gosec writes the severity as a rule tag and a higher level (MEDIUM gives "error").
    rule = {
        "properties": {"tags": ["security", "MEDIUM"]},
        "defaultConfiguration": {"level": "error"},
    }
    assert for_sarif_result({"level": "error"}, rule) == ("medium", "MEDIUM")


def test_property_label_beats_tag_label():
    result = {"properties": {"severity": "HIGH", "tags": ["LOW"]}}
    assert for_sarif_result(result, None) == ("high", "HIGH")


def test_other_tags_are_not_labels():
    rule = {"properties": {"tags": ["security", "bug", "HIGH CONFIDENCE", "none"]}}
    assert for_sarif_result({"level": "note"}, rule) == ("low", "note")


def test_result_level_beats_rule_default_level():
    rule = {"defaultConfiguration": {"level": "error"}}
    assert for_sarif_result({"level": "note"}, rule) == ("low", "note")


def test_rule_default_level_when_the_result_has_no_level():
    rule = {"defaultConfiguration": {"level": "error"}}
    assert for_sarif_result({}, rule) == ("high", "error")


def test_level_none_gives_info():
    assert for_sarif_result({"level": "none"}, None) == ("info", "none")


def test_default_is_medium_with_an_empty_tool_severity():
    assert for_sarif_result({}, None) == ("medium", "")
    assert for_sarif_result({"level": "fatal"}, {"properties": "bad"}) == ("medium", "")


def test_zero_security_severity_yields_to_a_label():
    # Trivy writes "0.0" when the vendor score has no CVSS v3 value.
    rule = {"properties": {"security-severity": "0.0", "tags": ["vulnerability", "HIGH"]}}
    assert for_sarif_result({"level": "error"}, rule) == ("high", "HIGH")


def test_zero_security_severity_yields_to_a_level():
    rule = {"properties": {"security-severity": "0.0"}}
    assert for_sarif_result({"level": "warning"}, rule) == ("medium", "warning")


def test_zero_security_severity_alone_gives_info():
    rule = {"properties": {"security-severity": "0.0"}}
    assert for_sarif_result({}, rule) == ("info", "0.0")


def test_zero_result_score_does_not_hide_a_rule_score():
    result = {"properties": {"security-severity": "0"}}
    rule = {"properties": {"security-severity": "8.1"}}
    assert for_sarif_result(result, rule) == ("high", "8.1")


def test_tool_severity_keeps_the_original_text():
    assert for_sarif_result({"properties": {"severity": " Moderate "}}, None) == (
        "medium",
        "Moderate",
    )
    assert for_sarif_result({"properties": {"security-severity": "6.10"}}, None) == (
        "medium",
        "6.10",
    )


def test_malformed_input_does_not_raise():
    assert for_sarif_result({"properties": None, "level": 3}, {"defaultConfiguration": []}) == (
        "medium",
        "",
    )
    assert for_sarif_result({"properties": {"tags": "HIGH"}}, None) == ("medium", "")


# --- emit helpers ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("severity", "verdict", "level"),
    [
        ("critical", "confirmed", "error"),
        ("high", "confirmed", "error"),
        ("medium", "confirmed", "warning"),
        ("low", "confirmed", "note"),
        ("info", "confirmed", "note"),
        ("informational", "confirmed", "note"),
        ("critical", "needs_validation", "warning"),
        (None, "needs_validation", "warning"),
        ("low", "needs_validation", "warning"),
        (None, "rejected", "note"),
        ("high", "rejected", "error"),
        ("high", None, "error"),
    ],
)
def test_to_sarif_level(severity, verdict, level):
    assert to_sarif_level(severity, verdict) == level


def test_to_sarif_level_rejects_an_unknown_severity():
    with pytest.raises(ValueError):
        to_sarif_level("severe", "confirmed")


@pytest.mark.parametrize(
    ("severity", "value"),
    [
        ("critical", "9.5"),
        ("high", "8.0"),
        ("medium", "5.5"),
        ("low", "2.0"),
        ("info", "0.0"),
        ("INFORMATIONAL", "0.0"),
    ],
)
def test_to_security_severity(severity, value):
    assert to_security_severity(severity) == value
    # The emitted value maps back to the same severity, except info (score 0 is the weakest
    # signal, so an emitted info result also carries the label).
    if severity in ("critical", "high", "medium", "low"):
        assert from_score(value) == severity


def test_to_security_severity_rejects_an_unknown_severity():
    with pytest.raises(ValueError):
        to_security_severity("severe")
