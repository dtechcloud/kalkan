# SPDX-License-Identifier: MIT
"""Regexes that read target files stay linear (self-audit of 2026-11-13, eight ReDoS findings).

Each crafted input below took seconds to minutes before the fix (20,000 "?" took 33 s in
``_openapi._KEY``). The inputs here are ten times larger and must finish well under the limit;
the other tests show that the patterns still match what they matched before.
"""

from __future__ import annotations

import time

import pytest

from kalkan.run import tech
from kalkan.sca import manifests
from kalkan.scanners.adapters import _openapi, gixy

N = 200_000
LIMIT_SECONDS = 2.0


def _fast(call) -> None:
    started = time.perf_counter()
    call()
    assert time.perf_counter() - started < LIMIT_SECONDS


@pytest.mark.parametrize(
    "call",
    [
        lambda: manifests._GEM_LINE.match("gem" + " " * N + "x"),
        lambda: tech._GEM_RAILS.search("\n" * N + "x"),
        lambda: tech._KOTLIN_BUILD.search("id" + " " * N + "x"),
        lambda: _openapi._KEY.search("?" * N),
        lambda: _openapi._KEY.search("{?" * N),
        lambda: gixy._BLOCK.search("location" + " " * N + "x"),
        lambda: manifests._pep508("a." * (N // 2) + "\nb", manifests._Parsed()),
    ],
    ids=[
        "gem-line",
        "gem-rails",
        "kotlin-build",
        "openapi-key",
        "openapi-key-flow",
        "gixy-block",
        "pep508",
    ],
)
def test_crafted_input_stays_fast(call):
    _fast(call)


def test_gem_patterns_still_match():
    assert manifests._GEM_LINE.match("  gem ( 'rack', '2.2.8'").group(2) == "rack"
    assert manifests._GEM_LINE.match('gem"rails"').group(2) == "rails"
    assert tech._GEM_RAILS.search("source 'x'\n  gem 'rails', '7.1'\n")
    assert tech._GEM_RAILS.search('gem\t"railties"')
    assert not tech._GEM_RAILS.search("# gem 'rails'")


def test_kotlin_and_nginx_patterns_still_match():
    for text in ('id("kotlin")', "id 'kotlin-jvm'", 'kotlin("jvm")', "org.jetbrains.kotlin"):
        assert tech._KOTLIN_BUILD.search(text), text
    for text in ("http {", "  server{", "location /api/ {", "location /x\n{", "upstream app {"):
        assert gixy._BLOCK.search(text), text
    assert not gixy._BLOCK.search("location;")


def test_pep508_counts_an_oversized_or_multiline_requirement_as_a_range():
    parsed = manifests._Parsed()
    manifests._pep508("requests==2.32.3", parsed)
    manifests._pep508("x" * (manifests.MAX_REQUIREMENT_CHARS + 1), parsed)
    manifests._pep508("flask\n==3.0", parsed)
    assert parsed.pins == [("requests", "2.32.3")]
    assert parsed.ranges == 2


@pytest.mark.parametrize(
    ("line", "reason"),
    [
        ("? $ref: '#/a'", "an explicit key"),
        ("&anchor $ref: '#/a'", "a key with an alias, anchor or tag"),
        ("!!str $ref: '#/a'", "a key with an alias, anchor or tag"),
        ("- ? $ref: x", "an explicit key"),
        ('[&a "$ref": x]', "a key with an alias, anchor or tag"),
    ],
)
def test_openapi_leads_are_still_found(line, reason):
    found = _openapi.reference_values(line + "\n")
    assert found and found[0].reason == reason, found


def test_openapi_plain_ref_value_is_read():
    found = _openapi.reference_values("$ref: '#/components/schemas/A'\n")
    assert [value.value for value in found][:1] == ["#/components/schemas/A"]


def test_success_pattern_of_a_harness_passes_the_matcher_checks():
    from kalkan.sandbox import runner

    pattern, problem = runner.success_pattern("KALKAN_POC_OK")
    assert pattern is not None and problem == ""
    for bad in ("(a+)+$", "(x|x)*y", "", None, "(?<=a)b"):
        pattern, problem = runner.success_pattern(bad)
        assert pattern is None and problem, bad
    # A line over the length limit is never searched.
    long_line = "KALKAN_POC_OK" + "x" * runner.MAX_LINE_LENGTH
    good = runner.success_pattern("KALKAN_POC_OK")[0]
    assert runner._match_line(good, long_line) is None
    assert runner._match_line(good, "noise\nKALKAN_POC_OK done") == "KALKAN_POC_OK done"
