# SPDX-License-Identifier: MIT
"""Corpus test: every matcher spec in rules/matchers is valid, safe and matches its examples."""

from __future__ import annotations

import importlib.util
import sys
import time
from functools import cache
from pathlib import Path

import pytest

from kalkan.matchers.safety import compile_regex, glob_safety_error, regex_safety_error
from kalkan.matchers.spec import MatcherSpec, example_matches, load_specs

ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / "rules" / "matchers"
UPSTREAM = ROOT / "third_party" / "deepsec" / "scanner" / "matchers"
PORT_SCRIPT = ROOT / "scripts" / "port_deepsec_matchers.py"
DEEPSEC_MATCHERS = 198


@cache
def specs() -> tuple[MatcherSpec, ...]:
    return tuple(load_specs(RULES))


def spec_ids() -> list[str]:
    return sorted(path.stem for path in RULES.glob("*.json"))


def by_slug(slug: str) -> MatcherSpec:
    return next(spec for spec in specs() if spec.slug == slug)


def all_regexes(spec: MatcherSpec) -> list[tuple[str, str]]:
    found = [(pattern.regex, pattern.flags) for pattern in spec.patterns]
    for pattern in spec.patterns:
        found += [(item.regex, item.flags) for item in (*pattern.near, *pattern.not_near)]
    found += [(regex, "") for regex in (*spec.file_contains, *spec.file_excludes)]
    found += [(regex, "") for regex in spec.requires.sentinel_contains]
    return found


def all_globs(spec: MatcherSpec) -> list[str]:
    globs = [*spec.exclude_file_patterns, *spec.requires.sentinel_files]
    if not spec.file_signatures:  # a signature matcher may scan every file (**/*)
        globs += spec.file_patterns
    globs += [item.glob for item in spec.name_patterns]
    for pattern in spec.patterns:
        globs += pattern.paths
    return globs


def test_every_spec_loads() -> None:
    assert len(specs()) == len(spec_ids()) >= DEEPSEC_MATCHERS
    assert [spec.slug for spec in specs()] == spec_ids()


@pytest.mark.parametrize("slug", spec_ids())
def test_spec_is_safe_and_matches_its_examples(slug: str) -> None:
    spec = by_slug(slug)
    for regex, flags in all_regexes(spec):
        assert regex_safety_error(regex, flags) is None, regex
    for glob in all_globs(spec):
        assert glob_safety_error(glob) is None, glob
    for example in spec.examples:
        assert example_matches(spec, example), example


def native_ids() -> list[str]:
    """Return the kalkan-native specs (``source: null``)."""
    return [spec.slug for spec in specs() if spec.source is None]


def test_native_specs_are_kalkan_rules() -> None:
    native = [by_slug(slug) for slug in native_ids()]
    assert len(specs()) - len(native) == DEEPSEC_MATCHERS
    for spec in native:
        assert spec.notes.startswith("kalkan rule (ADR-0005"), spec.slug
        assert spec.vuln_class is not None and spec.cwe, spec.slug


@pytest.mark.parametrize("slug", [s for s in spec_ids() if s not in native_ids()])
def test_ported_spec_names_its_source(slug: str) -> None:
    spec = by_slug(slug)
    assert spec.source is not None
    assert spec.source.repo == "vercel-labs/deepsec"
    assert spec.source.commit == "4fa6722"
    prefix = "packages/scanner/src/matchers/"
    assert spec.source.path.startswith(prefix)
    assert (UPSTREAM / spec.source.path[len(prefix) :]).is_file()


def test_surface_specs_have_no_class() -> None:
    for spec in specs():
        if "surface" in spec.notes.split(".")[0]:
            assert spec.vuln_class is None and spec.cwe == (), spec.slug
        if spec.vuln_class is None:
            assert spec.cwe == (), spec.slug
            assert spec.notes.startswith("surface"), spec.slug


def test_rules_match_the_port_script(monkeypatch: pytest.MonkeyPatch) -> None:
    name = "port_deepsec_matchers"
    module_spec = importlib.util.spec_from_file_location(name, PORT_SCRIPT)
    assert module_spec is not None and module_spec.loader is not None
    module = importlib.util.module_from_spec(module_spec)
    monkeypatch.setitem(sys.modules, name, module)  # dataclasses look the module up
    module_spec.loader.exec_module(module)
    ported, errors = module.port_all()
    assert errors == []
    assert len(ported) == DEEPSEC_MATCHERS
    for slug, data in ported.items():
        path = RULES / f"{slug}.json"
        assert path.read_text(encoding="utf-8") == module.render(data), slug


ADVERSARIAL_UNITS = ("a", " ", "${", "(", '"', "'", "`", "x.", "<a", "\\", "=== ", "{{", "..")
ADVERSARIAL_LENGTH = 5_000
#: Generous: a quadratic regex needs about 0.1 s here; an exponential one never finishes.
MAX_SEARCH_SECONDS = 1.0


def test_no_regex_backtracks_badly_on_adversarial_lines() -> None:
    lines = [(unit * ADVERSARIAL_LENGTH)[:ADVERSARIAL_LENGTH] for unit in ADVERSARIAL_UNITS]
    slow = []
    for spec in specs():
        for regex, flags in all_regexes(spec):
            compiled = compile_regex(regex, flags)
            for line in lines:
                start = time.perf_counter()
                compiled.search(line)
                elapsed = time.perf_counter() - start
                if elapsed > MAX_SEARCH_SECONDS:
                    slow.append((round(elapsed, 2), spec.slug, regex, line[:6]))
    assert slow == []
