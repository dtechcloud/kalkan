# SPDX-License-Identifier: MIT
"""The YAML reader for rule files (kalkan.util.miniyaml)."""

from __future__ import annotations

from pathlib import Path

import pytest

from kalkan.util import miniyaml
from kalkan.util.miniyaml import MiniYamlError, load

ROOT = Path(__file__).resolve().parents[2]


def test_block_mappings_sequences_and_scalars():
    text = """---
# a comment
rules:
  - id: a-rule
    languages: [python, "js", 'ts']
    severity: WARNING
    message: >-
      first line
      second line
    pattern-either:
    - pattern: eval($X)
    - patterns:
        - pattern: exec($Y)   # trailing comment
        - pattern-not: exec("...")
    metadata:
      cwe:
        - "CWE-94: Improper Control of Generation of Code ('Code Injection')"
      confidence: HIGH
      count: 3
      ratio: 0.5
      enabled: true
      nothing: ~
"""
    rule = load(text)["rules"][0]
    assert rule["id"] == "a-rule"
    assert rule["languages"] == ["python", "js", "ts"]
    assert rule["message"] == "first line second line"
    assert rule["pattern-either"][0] == {"pattern": "eval($X)"}
    assert rule["pattern-either"][1]["patterns"] == [
        {"pattern": "exec($Y)"},
        {"pattern-not": 'exec("...")'},
    ]
    metadata = rule["metadata"]
    assert metadata["cwe"] == ["CWE-94: Improper Control of Generation of Code ('Code Injection')"]
    assert (metadata["count"], metadata["ratio"], metadata["enabled"], metadata["nothing"]) == (
        3,
        0.5,
        True,
        None,
    )


def test_literal_block_scalars_keep_lines_and_chomping():
    text = "a: |\n  one\n    two\n\n  three\nb: |-\n  x\nc: |+\n  y\n\nd: >\n  p\n  q\n\n  r\n"
    doc = load(text)
    assert doc["a"] == "one\n  two\n\nthree\n"
    assert doc["b"] == "x"
    assert doc["c"] == "y\n\n"
    assert doc["d"] == "p q\nr\n"


def test_quoted_scalars_fold_and_escape():
    doc = load("a: 'it''s'\nb: \"tab\\there\\u00e9\"\nc: \"one\n  two\"\nd: 'x\n\n  y'\n")
    assert doc == {"a": "it's", "b": "tab\thereé", "c": "one two", "d": "x\ny"}


def test_multi_line_plain_scalars_and_flow_sequences():
    doc = load("message: one\n  two\n\n  three\nlist: [a,\n  b, [c, d]]\nempty: []\n")
    assert doc == {"message": "one two\nthree", "list": ["a", "b", ["c", "d"]], "empty": []}


def test_a_sequence_at_the_key_indentation_belongs_to_the_key():
    assert load("key:\n- a\n- b\nother: 1\n") == {"key": ["a", "b"], "other": 1}


@pytest.mark.parametrize(
    "text",
    [
        "a: &anchor 1\n",
        "a: *alias\n",
        "a: !tag x\n",
        "a: {b: 1}\n",
        "a: 1\n---\nb: 2\n",
        "a: value: other\n",
        "? complex\n: key\n",
    ],
)
def test_unsupported_or_invalid_yaml_raises(text):
    with pytest.raises(MiniYamlError):
        load(text)


def test_kalkan_rule_files_load():
    files = sorted((ROOT / "rules" / "opengrep").glob("*.yaml"))
    assert files
    for path in files:
        doc = miniyaml.load(path.read_text(encoding="utf-8"))
        assert isinstance(doc["rules"], list) and doc["rules"], path.name
        assert all(isinstance(rule.get("id"), str) for rule in doc["rules"])
