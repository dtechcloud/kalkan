# SPDX-License-Identifier: MIT
"""Tests for kalkan.matchers.spec (matcher spec loading and validation)."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from kalkan.errors import ValidationError
from kalkan.matchers.spec import (
    CLASS_SLUGS,
    Condition,
    MatcherSpec,
    example_matches,
    load_spec,
    load_specs,
    parse_spec,
    spec_errors,
    validate_specs,
)


def valid() -> dict[str, Any]:
    return {
        "version": 1,
        "slug": "go-command-injection",
        "description": "Go exec.Command with potentially dynamic arguments",
        "class": "os-command-injection",
        "cwe": ["CWE-78"],
        "noise_tier": "precise",
        "file_patterns": ["**/*.go"],
        "exclude_file_patterns": ["**/*_test.go"],
        "requires": {"tech": ["go"], "sentinel_files": [], "sentinel_contains": []},
        "patterns": [{"regex": r"exec\.Command\s*\(", "flags": "", "label": "exec.Command"}],
        "examples": ['cmd := exec.Command("sh", "-c", userInput)'],
        "source": {
            "repo": "vercel-labs/deepsec",
            "commit": "4fa6722",
            "path": "packages/scanner/src/matchers/go-command-injection.ts",
        },
        "notes": "",
    }


def errors_for(**changes: Any) -> list[str]:
    data = valid()
    for key, value in changes.items():
        if value is KeyError:
            data.pop(key)
        else:
            data[key] = value
    return spec_errors(data)


def test_valid_spec() -> None:
    spec = parse_spec(valid())
    assert isinstance(spec, MatcherSpec)
    assert spec.slug == "go-command-injection"
    assert spec.vuln_class == "os-command-injection"
    assert spec.requires.tech == ("go",)
    assert spec.patterns[0].label == "exec.Command"
    assert spec.source is not None and spec.source.commit == "4fa6722"


def test_round_trip_through_to_dict() -> None:
    spec = parse_spec(valid())
    assert parse_spec(spec.to_dict()) == spec
    assert list(spec.to_dict())[:4] == ["version", "slug", "description", "class"]


def test_optional_keys_default() -> None:
    data = valid()
    for key in ("exclude_file_patterns", "requires", "source", "notes"):
        del data[key]
    spec = parse_spec(data)
    assert spec.exclude_file_patterns == ()
    assert spec.requires.tech == ()
    assert spec.source is None
    assert spec.notes == ""


def test_class_null_and_empty_cwe_are_valid() -> None:
    assert errors_for(**{"class": None, "cwe": []}) == []


def test_extension_keys() -> None:
    data = valid()
    data["file_contains"] = [r'import\s+"os/exec"']
    data["file_excludes"] = [r"(?i:generated)"]
    data["patterns"][0]["near"] = [{"regex": r"\buser", "before": 2, "after": 3}]
    data["patterns"][0]["not_near"] = [{"regex": "shellescape", "scope": "file"}]
    data["patterns"][0]["paths"] = ["cmd/**/*.go"]
    spec = parse_spec(data)
    assert spec.file_contains == (r'import\s+"os/exec"',)
    assert spec.patterns[0].near == (Condition(r"\buser", "", 2, 3, False),)
    assert spec.patterns[0].not_near[0].whole_file
    assert parse_spec(spec.to_dict()) == spec


@pytest.mark.parametrize(
    ("changes", "fragment"),
    [
        ({"surprise": 1}, "surprise: unknown key"),
        ({"slug": KeyError}, "slug: is required"),
        ({"version": 2}, "version: must be 1"),
        ({"version": True}, "version: must be 1"),
        ({"slug": "Go-Cmd"}, "kebab-case"),
        ({"slug": "-go"}, "kebab-case"),
        ({"slug": "a" * 81}, "at most 80"),
        ({"description": ""}, "non-empty"),
        ({"description": " x"}, "whitespace"),
        ({"description": "x" * 501}, "at most 500"),
        ({"class": "rce"}, "taxonomy class"),
        ({"class": ["sqli"]}, "taxonomy class"),
        ({"cwe": ["78"]}, "CWE-<number>"),
        ({"cwe": ["CWE-78", "CWE-78"]}, "duplicates"),
        ({"noise_tier": "loud"}, "noise_tier"),
        ({"file_patterns": []}, "at least 1"),
        ({"file_patterns": [f"**/*.e{i}" for i in range(33)]}, "at most 32"),
        ({"file_patterns": ["**/*"]}, "too broad"),
        ({"exclude_file_patterns": ["../x.go"]}, "traversal"),
        ({"requires": {"tech": ["Go"]}}, "technology tag"),
        ({"requires": {"os": ["linux"]}}, "requires.os: unknown key"),
        ({"requires": {"sentinel_contains": ["x"]}}, "needs requires.sentinel_files"),
        (
            {"requires": {"sentinel_files": ["**/go.mod"], "sentinel_contains": ["(a+)+"]}},
            "nested quantifiers",
        ),
        ({"file_contains": ["a*"]}, "empty string"),
        ({"file_excludes": "x"}, "list of strings"),
        ({"patterns": []}, "non-empty list"),
        ({"examples": []}, "between 1 and 64"),
        ({"examples": ["x" * 10_001]}, "between 1 and 10000"),
        ({"examples": ["no match here"]}, "examples[0]: must be matched"),
        ({"source": {"repo": "x", "commit": "", "path": "p"}}, "source.commit"),
        ({"source": "deepsec"}, "object or null"),
        ({"notes": "x" * 4001}, "notes"),
    ],
)
def test_invalid_specs(changes: dict[str, Any], fragment: str) -> None:
    errors = errors_for(**changes)
    assert any(fragment in error for error in errors), errors


@pytest.mark.parametrize(
    ("pattern_changes", "fragment"),
    [
        ({"label": ""}, "label: must be a non-empty string"),
        ({"label": "x" * 241}, "at most 240"),
        ({"flags": "g"}, "only contain"),
        ({"regex": r"(?<=x)exec\.Command\s*\("}, "lookbehind"),
        ({"extra": 1}, "extra: unknown key"),
        ({"near": [{"regex": "x", "before": 10_001}]}, "between 0 and 10000"),
        ({"near": [{"regex": "x", "before": True}]}, "must be an integer"),
        ({"near": [{"regex": "x", "scope": "file", "after": 1}]}, 'not allowed with scope "file"'),
        ({"near": [{"regex": "x", "scope": "block"}]}, 'must be "lines", "file" or "document"'),
        (
            {"near": [{"regex": "x", "scope": "document", "before": 1}]},
            'not allowed with scope "document"',
        ),
        ({"not_near": [{"regex": "x", "window": 3}]}, "window: unknown key"),
        ({"not_near": [{"regex": "x"}] * 9}, "at most 8"),
        ({"paths": ["/abs/*.go"]}, "relative"),
    ],
)
def test_invalid_patterns(pattern_changes: dict[str, Any], fragment: str) -> None:
    data = valid()
    data["patterns"][0].update(pattern_changes)
    errors = spec_errors(data)
    assert any(fragment in error for error in errors), errors


def test_all_errors_are_collected() -> None:
    errors = errors_for(slug="BAD", noise_tier="x", cwe=["x"])
    assert len(errors) == 3


def test_parse_spec_raises_validation_error_with_origin() -> None:
    with pytest.raises(ValidationError) as caught:
        parse_spec({"version": 1}, origin="rules/matchers/x.json")
    assert caught.value.errors
    assert all(error.startswith("rules/matchers/x.json: ") for error in caught.value.errors)


def test_example_matching_is_line_based() -> None:
    data = valid()
    data["examples"] = ['x := 1\ncmd := exec.Command("ls")\r\nfoo()']
    spec = parse_spec(data)
    assert example_matches(spec, 'cmd := exec.Command("ls")')
    assert not example_matches(spec, "exec\n.Command(")


def write(folder: Path, name: str, data: dict[str, Any]) -> Path:
    path = folder / name
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_load_spec_requires_the_slug_as_file_name(tmp_path: Path) -> None:
    good = write(tmp_path, "go-command-injection.json", valid())
    assert load_spec(good).origin == good.as_posix()
    bad = write(tmp_path, "other.json", valid())
    with pytest.raises(ValidationError, match="file name must be go-command-injection.json"):
        load_spec(bad)


def test_load_spec_rejects_broken_json(tmp_path: Path) -> None:
    path = tmp_path / "x.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValidationError, match="cannot read JSON"):
        load_spec(path)


def test_load_specs_sorts_and_collects_errors(tmp_path: Path) -> None:
    second = copy.deepcopy(valid())
    second["slug"] = "a-first"
    write(tmp_path, "go-command-injection.json", valid())
    write(tmp_path, "a-first.json", second)
    specs = load_specs(tmp_path)
    assert [spec.slug for spec in specs] == ["a-first", "go-command-injection"]

    broken = copy.deepcopy(valid())
    broken["slug"] = "broken"
    broken["noise_tier"] = "x"
    write(tmp_path, "broken.json", broken)
    with pytest.raises(ValidationError) as caught:
        load_specs(tmp_path)
    assert any("broken.json" in error for error in caught.value.errors)


def test_load_specs_needs_a_folder(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="not found"):
        load_specs(tmp_path / "missing")


def test_validate_specs_rejects_duplicate_slugs() -> None:
    spec = parse_spec(valid(), origin="a.json")
    twin = parse_spec(valid(), origin="b.json")
    with pytest.raises(ValidationError) as caught:
        validate_specs([spec, twin])
    assert "duplicate matcher slug go-command-injection" in caught.value.errors[0]
    assert validate_specs([spec]) == [spec]


def test_class_slugs_match_the_taxonomy_module() -> None:
    taxonomy = pytest.importorskip("kalkan.findings.taxonomy")
    assert set(taxonomy.SLUGS) == set(CLASS_SLUGS)
