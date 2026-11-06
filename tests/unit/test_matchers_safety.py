# SPDX-License-Identifier: MIT
"""Tests for kalkan.matchers.safety (regex and glob safety checks)."""

from __future__ import annotations

import re

import pytest

from kalkan.errors import ValidationError
from kalkan.matchers.safety import (
    MAX_LINE_LENGTH,
    compile_regex,
    count_unbounded_wildcards,
    flags_error,
    glob_safety_error,
    regex_flags,
    regex_safety_error,
)


def error_of(source: str, flags: str = "") -> str:
    return regex_safety_error(source, flags) or ""


# --- regexes: positive cases --------------------------------------------------------------


@pytest.mark.parametrize(
    "source",
    [
        r"exec\.Command\s*\(",
        r"child_process.*exec\s*\(",
        r"a(?=b)",
        r"a(?!b)c",
        r"(ab)+",
        r"(a|b)",
        r"x(a|b)?",
        r"x(?:a+)?",
        r"[*+]+x",
        r"\++x",
        r"x{1000}",
        r"x{2,1000}",
        r"a.*b.{0,40}c",
        r"(?i:abc)def",
        r"(?-i:abc)",
        r"(?P<name>a)b",
        r"\$\{[^}]{0,200}\}",
        r"^\s*FROM\s+(?:--platform=\S+\s+)?\S+",
    ],
)
def test_safe_regexes_pass(source: str) -> None:
    assert regex_safety_error(source) is None


def test_the_flags_change_nothing_for_a_safe_regex() -> None:
    for flags in ("", "i", "m", "s", "ims"):
        assert regex_safety_error(r"abc", flags) is None


# --- regexes: one test per rule -----------------------------------------------------------


def test_length_limit() -> None:
    assert regex_safety_error("a" * 500) is None
    assert "at most 500" in error_of("a" * 501)


def test_empty_and_non_string_sources_fail() -> None:
    assert "non-empty" in error_of("")
    assert "non-empty" in (regex_safety_error(None) or "")  # type: ignore[arg-type]


def test_nul_byte() -> None:
    assert "NUL" in error_of("a\0b")


@pytest.mark.parametrize("source", [r"(a)\1", r"(?P<n>a)\k<n>", r"(?P<n>a)(?P=n)"])
def test_backreferences(source: str) -> None:
    assert "backreference" in error_of(source)


@pytest.mark.parametrize("source", [r"(?<=a)b", r"(?<!a)b"])
def test_lookbehind(source: str) -> None:
    assert "lookbehind" in error_of(source)


@pytest.mark.parametrize("source", [r"(a+)+", r"(a*)*", r"(?:ab+){2}", r"(a{1,3})+", r"(x+){,5}"])
def test_nested_quantifiers(source: str) -> None:
    assert "nested quantifiers" in error_of(source)


@pytest.mark.parametrize("source", [r"(a|b)+", r"(?:x|y){2,5}", r"(a|b)*c"])
def test_quantified_alternations(source: str) -> None:
    assert "quantified alternations" in error_of(source)


@pytest.mark.parametrize(
    "source",
    [r"a.*b.*c", r".+x.+", r"a.*b|c.*d", r"a.{2,}b.*", r"x.{,}y.*"],
)
def test_multiple_wildcards(source: str) -> None:
    assert "multiple wildcard" in error_of(source)


@pytest.mark.parametrize("source", [r"a{1001}", r"a{1,1001}", r"a{,1001}", r"a{2000,}"])
def test_repeat_counts(source: str) -> None:
    assert "repeat counts" in error_of(source)


@pytest.mark.parametrize("source", [r"a*", r"x?", r"^", r"a|", r"(?:)", r"(?!x)"])
def test_regexes_that_match_the_empty_string(source: str) -> None:
    assert "empty string" in error_of(source)


@pytest.mark.parametrize("source", [r"(", r"[a", r"a{2,1}", r"[[]x"])
def test_invalid_regexes(source: str) -> None:
    assert "not a valid regular expression" in error_of(source)


@pytest.mark.parametrize(
    ("source", "message"),
    [
        (r"a++", "possessive"),
        (r"a*+", "possessive"),
        (r"a?+b", "possessive"),
        (r"a{2}+", "possessive"),
        (r"(?>a)", "atomic"),
        (r"(a)?(?(1)b|c)", "conditional"),
        (r"(?#note)a", "comments"),
        (r"(?i)a", "global flags"),
        (r"(?x:a)", "scoped i, m and s"),
        (r"(?<name>a)", "(?P<name>"),
    ],
)
def test_python_only_syntax(source: str, message: str) -> None:
    assert message in error_of(source)


def test_flags() -> None:
    assert flags_error("ims") is None
    assert "only contain" in (flags_error("g") or "")
    assert "repeat" in (flags_error("ii") or "")
    assert "string" in (flags_error(None) or "")
    assert "only contain" in error_of("abc", "u")


def test_regex_flags_always_use_ascii() -> None:
    assert regex_flags("") == re.ASCII
    assert regex_flags("ims") == re.ASCII | re.IGNORECASE | re.MULTILINE | re.DOTALL


def test_compile_regex_returns_an_ascii_pattern() -> None:
    compiled = compile_regex(r"\w+")
    assert compiled.flags & re.ASCII
    assert compiled.fullmatch("abc_1")
    assert not compiled.fullmatch("é")  # JavaScript \w is ASCII-only without the u flag


def test_compile_regex_raises_validation_error() -> None:
    with pytest.raises(ValidationError) as caught:
        compile_regex(r"(a+)+")
    assert "nested quantifiers" in caught.value.errors[0]


def test_count_unbounded_wildcards() -> None:
    assert count_unbounded_wildcards(r"a.*b") == 1
    assert count_unbounded_wildcards(r"a.+b.{2,}c.{,}") == 3
    assert count_unbounded_wildcards(r"\.*x[.*]y") == 0
    assert count_unbounded_wildcards(r"a.{0,40}b") == 0


def test_line_length_limit_constant() -> None:
    assert MAX_LINE_LENGTH == 20_000


# --- globs ----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pattern",
    [
        "**/*.go",
        "**/*.{ts,tsx,js,jsx}",
        ".github/workflows/**/*.yml",
        "**/app/api/**/route.{ts,tsx}",
        "**/Dockerfile.*",
        "**/[[][[]...rest[]][]]/route.{ts,tsx}",
        "**/(payload)/**/*.{ts,tsx}",
        "src/**",
    ],
)
def test_safe_globs_pass(pattern: str) -> None:
    assert glob_safety_error(pattern) is None


@pytest.mark.parametrize(
    ("pattern", "message"),
    [
        ("", "non-empty"),
        (" **/*.go", "whitespace"),
        ("a" * 241, "at most 240"),
        ("**/a\tb.go", "control characters"),
        ("src\\a.go", "forward slashes"),
        ("!**/*.go", "negated"),
        ("#**/*.go", "comment"),
        ("/etc/passwd", "relative"),
        ("C:/x/*.go", "relative"),
        ("../x/*.go", "traversal"),
        ("src/./a.go", "traversal"),
        ("{a,b}/{c,d}/{e,f}/{g,h}.go", "too complex"),
        ("**/{a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r}.go", "too complex"),
        ("*", "too broad"),
        ("**", "too broad"),
        ("**/*", "too broad"),
        ("**/**/", "too broad"),
        ("**/*.*", "include a literal"),
        ("**/*.{md,ts,env,yaml}", "too broad"),
        ("**/*(a|b).ts", "extended globs"),
        ("**/@(a|b).ts", "extended globs"),
        ("**/[[:alpha:]].ts", "POSIX"),
    ],
)
def test_unsafe_globs_fail(pattern: str, message: str) -> None:
    assert message in (glob_safety_error(pattern) or "")


def test_allow_broad_skips_only_the_breadth_checks() -> None:
    for pattern in ("**/*", "*", "**/*.*"):
        assert glob_safety_error(pattern, allow_broad=True) is None
    assert "traversal" in (glob_safety_error("../**/*", allow_broad=True) or "")
    assert "negated" in (glob_safety_error("!**/*", allow_broad=True) or "")
