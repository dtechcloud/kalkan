# SPDX-License-Identifier: MIT
"""Tests for kalkan.matchers.globs (minimatch semantics for deepsec file patterns)."""

from __future__ import annotations

import pytest

from kalkan.matchers.globs import (
    MAX_EXPANSIONS,
    GlobError,
    GlobSet,
    expand_braces,
    glob_matches,
    glob_to_regex,
)


def test_expand_braces() -> None:
    assert expand_braces("a{b,c}d{e,f}") == ["abde", "abdf", "acde", "acdf"]
    assert expand_braces("{a,{b,c}}") == ["a", "b", "c"]
    assert expand_braces("x{,y}") == ["x", "xy"]
    assert expand_braces("{a}") == ["{a}"]  # no top-level comma: literal
    assert expand_braces("{a,b") == ["{a,b"]  # unclosed: literal
    assert expand_braces("**/*.{ts,tsx}") == ["**/*.ts", "**/*.tsx"]


def test_too_many_expansions() -> None:
    group = "{" + ",".join(str(i) for i in range(11)) + "}"
    with pytest.raises(GlobError):
        expand_braces(group * 3)
    assert 11**3 > MAX_EXPANSIONS


# Real deepsec file patterns (some after the port's literal-bracket rewrite).
@pytest.mark.parametrize(
    ("pattern", "path", "expected"),
    [
        ("**/*.go", "main.go", True),
        ("**/*.go", "cmd/app/main.go", True),
        ("**/*.go", "main.go.bak", False),
        ("**/*.{ts,tsx,js,jsx}", "src/a.tsx", True),
        ("**/*.{ts,tsx,js,jsx}", "src/a.mjs", False),
        ("**/app/api/**/route.{ts,tsx}", "app/api/users/route.ts", True),
        ("**/app/api/**/route.{ts,tsx}", "src/app/api/route.tsx", True),
        ("**/app/api/**/route.{ts,tsx}", "app/apix/route.ts", False),
        (".github/workflows/**/*.yml", ".github/workflows/ci.yml", True),
        (".github/workflows/**/*.yml", "sub/.github/workflows/ci.yml", False),
        ("**/Dockerfile", "Dockerfile", True),
        ("**/Dockerfile.*", "docker/Dockerfile.prod", True),
        ("**/*.Dockerfile", "api.Dockerfile", True),
        ("**/*webhook*/**/*.{ts,tsx,js,jsx}", "app/stripe-webhooks/x/handler.ts", True),
        ("**/services/**/src/index.ts", "services/billing/src/index.ts", True),
        ("**/+server.{ts,js}", "src/routes/api/+server.ts", True),
        ("**/**/actions/**/*.{ts,tsx}", "app/actions/save.ts", True),
        ("**/containers/**/entrypoint*.sh", "containers/sandbox/entrypoint-main.sh", True),
        ("**/*.tf.json", "infra/main.tf.json", True),
        ("**/apps/**/route.*.ts", "apps/web/route.get.ts", True),
        ("**/api/cron*/**/*.{ts,tsx,js,jsx}", "app/api/cron-daily/run/route.ts", True),
        ("**/(payload)/**/*.{ts,tsx}", "app/(payload)/admin/page.tsx", True),
        ("**/[[][[]...rest[]][]]/route.{ts,tsx}", "app/[[...rest]]/route.ts", True),
        ("**/[[]...slug[]]/route.{ts,tsx}", "app/[...slug]/route.ts", True),
        ("**/.env", ".env", True),
        ("**/.env.*", "config/.env.local", True),
    ],
)
def test_deepsec_patterns(pattern: str, path: str, expected: bool) -> None:
    assert glob_matches(pattern, path) is expected


def test_brackets_are_classes_as_in_minimatch() -> None:
    # deepsec wrote '**/[[...rest]]/route.ts'; minimatch reads '[[...rest]' as one class.
    assert not glob_matches("**/[[...rest]]/route.ts", "app/[[...rest]]/route.ts")
    assert glob_matches("**/[[...rest]]/route.ts", "app/r]/route.ts")


@pytest.mark.parametrize(
    ("pattern", "path", "expected"),
    [
        ("**/x", "x", True),  # globstar matches zero segments
        ("a/**/b", "a/b", True),
        ("a/**/b", "a/x/y/b", True),
        ("a/**", "a/b/c", True),
        ("a/**", "a", False),
        ("*.go", "a/b.go", False),  # * never crosses /
        ("a**b", "axyb", True),  # ** inside a segment acts like *
        ("a**b", "ax/yb", False),
        ("**/a?c", "x/abc", True),
        ("**/a?c", "x/a/c", False),
        ("**/[abc].txt", "b.txt", True),
        ("**/[a-c].txt", "d.txt", False),
        ("**/[!a].txt", "b.txt", True),
        ("**/[^a].txt", "a.txt", False),
        ("**/[]].txt", "].txt", True),
        ("**/[ab.txt", "[ab.txt", True),  # unclosed bracket: literal
        ("**/*.ts", ".hidden/main.ts", True),  # dot: true
        ("**/*.ts", "src/.eslintrc.ts", True),
        ("**/*.TS", "a.ts", False),  # case-sensitive
        ("**/{a}.ts", "{a}.ts", True),
    ],
)
def test_minimatch_semantics(pattern: str, path: str, expected: bool) -> None:
    assert glob_matches(pattern, path) is expected


def test_regex_is_anchored_with_fullmatch() -> None:
    assert glob_to_regex("**/*.go") == r"(?:[^/]+/)*[^/]*\.go"


def test_glob_set() -> None:
    empty = GlobSet([])
    assert not empty
    assert not empty.matches("a.go")
    both = GlobSet(["**/*.go", "**/*.py"])
    assert both
    assert both.matches("a/b.py")
    assert not both.matches("a/b.rb")


def test_empty_glob_is_an_error() -> None:
    with pytest.raises(GlobError):
        glob_to_regex("")
