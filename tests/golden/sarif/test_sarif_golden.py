# SPDX-License-Identifier: MIT
"""Golden tests: the SARIF output of each scanner gives the expected candidates (ENGINE-SPEC 8.1).

Each ``<tool>.sarif`` file follows the SARIF shape of the real output of that tool: rule
properties, tags, ``security-severity``, fingerprints, relative and absolute URIs, Windows
paths. Each ``<tool>.expected.json`` holds the engine, the target root, the SARIF file name,
the expected warnings and the full candidate records.

Change an expected file only for a deliberate behavior change. Review every changed field.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pytest

from kalkan.findings.severity import SEVERITIES
from kalkan.findings.taxonomy import SLUGS
from kalkan.findings.validate import validate_candidate
from kalkan.sarif.ingest import ingest_document, ingest_file
from kalkan.schema.loader import load_schema

HERE = Path(__file__).resolve().parent
TOOLS = [
    "bandit",
    "checkov",
    "gitleaks",
    "gitleaks-history",
    "gosec",
    "grype",
    "hadolint",
    "opengrep",
    "osv-scanner",
    "trivy",
]
FIELDS = [
    "id",
    "engine",
    "rule_id",
    "class",
    "cwe",
    "title",
    "message",
    "file",
    "start_line",
    "end_line",
    "snippet",
    "severity",
    "tool_severity",
    "confidence",
    "tags",
    "fingerprints",
    "sca",
    "raw",
]
SCA_FIELDS = [
    "ecosystem",
    "package",
    "version",
    "vuln_ids",
    "fixed_versions",
    "cvss_score",
    "cvss_vector",
]
CWE = re.compile(r"CWE-[0-9]+")


def load(name: str) -> tuple[dict, dict]:
    doc = json.loads((HERE / f"{name}.sarif").read_text(encoding="utf-8"))
    expected = json.loads((HERE / f"{name}.expected.json").read_text(encoding="utf-8"))
    return doc, expected


def spec_candidate_id(candidate: dict) -> str:
    """ENGINE-SPEC 6.2, written out here so that the expected IDs do not trust the code."""
    snippet = " ".join(candidate["snippet"].split())
    fields = [
        candidate["engine"],
        candidate["rule_id"],
        candidate["file"],
        str(candidate["start_line"] or 0),
        snippet,
    ]
    digest = hashlib.sha256("\x00".join(fields).encode("utf-8")).hexdigest()
    return "CAND-" + digest[:16].upper()


def test_every_tool_has_a_sample_and_an_expected_file():
    samples = sorted(path.name.removesuffix(".sarif") for path in HERE.glob("*.sarif"))
    expected = sorted(
        path.name.removesuffix(".expected.json") for path in HERE.glob("*.expected.json")
    )
    assert samples == TOOLS
    assert expected == TOOLS


@pytest.mark.parametrize("name", TOOLS)
def test_ingest_gives_the_expected_candidates(name):
    doc, expected = load(name)
    outcome = ingest_document(
        doc, expected["engine"], expected["target_root"], expected["sarif_file"]
    )
    assert outcome.warnings == expected["warnings"]
    assert len(outcome.candidates) == len(expected["candidates"])
    for index, (actual, wanted) in enumerate(
        zip(outcome.candidates, expected["candidates"], strict=True)
    ):
        assert actual == wanted, f"{name}: candidate {index}"
        assert list(actual) == FIELDS, f"{name}: candidate {index}: field order"


@pytest.mark.parametrize("name", TOOLS)
def test_ingest_file_gives_the_same_candidates(name):
    _, expected = load(name)
    path = HERE / f"{name}.sarif"
    outcome = ingest_file(path, expected["engine"], expected["target_root"])
    assert outcome.warnings == [
        warning.replace(expected["sarif_file"], path.as_posix()) for warning in expected["warnings"]
    ]
    wanted = [
        {**candidate, "raw": {**candidate["raw"], "sarif_file": path.as_posix()}}
        for candidate in expected["candidates"]
    ]
    assert outcome.candidates == wanted


@pytest.mark.parametrize("name", TOOLS)
def test_expected_candidates_follow_engine_spec_4(name):
    # This test checks the expected data, so that a regenerated file cannot drift from the spec.
    _, expected = load(name)
    assert expected["candidates"], name
    for index, candidate in enumerate(expected["candidates"]):
        where = f"{name}: candidate {index}"
        assert list(candidate) == FIELDS, where
        assert candidate["id"] == spec_candidate_id(candidate), where
        assert candidate["engine"] == expected["engine"], where
        assert isinstance(candidate["rule_id"], str) and candidate["rule_id"], where
        assert candidate["class"] is None or candidate["class"] in SLUGS, where
        assert all(CWE.fullmatch(cwe) for cwe in candidate["cwe"]), where
        assert len(set(candidate["cwe"])) == len(candidate["cwe"]), where
        for key in ("title", "message", "snippet", "tool_severity"):
            assert isinstance(candidate[key], str), (where, key)
        assert candidate["title"], where
        file = candidate["file"]
        assert isinstance(file, str), where
        assert "\\" not in file and not file.startswith(("/", "./", "../")), where
        assert not re.match(r"[A-Za-z]:", file), where
        start, end = candidate["start_line"], candidate["end_line"]
        assert start is None or (isinstance(start, int) and start >= 1), where
        assert (start is None and end is None) or (isinstance(end, int) and end >= start), where
        assert candidate["severity"] in SEVERITIES, where
        assert candidate["confidence"] in ("high", "medium", "low", None), where
        assert all(isinstance(tag, str) for tag in candidate["tags"]), where
        assert all(
            isinstance(key, str) and isinstance(value, str)
            for key, value in candidate["fingerprints"].items()
        ), where
        sca = candidate["sca"]
        if sca is not None:
            assert list(sca) == SCA_FIELDS, where
            assert all(isinstance(item, str) for item in sca["vuln_ids"]), where
            assert all(isinstance(item, str) for item in sca["fixed_versions"]), where
            assert sca["cvss_score"] is None or isinstance(sca["cvss_score"], float), where
            assert sca["cvss_vector"] is None or isinstance(sca["cvss_vector"], str), where
        assert candidate["raw"] == {
            "sarif_file": expected["sarif_file"],
            "run_index": 0,
            "result_index": index,
        }, where


def test_candidate_ids_are_unique_across_the_samples():
    ids = [candidate["id"] for name in TOOLS for candidate in load(name)[1]["candidates"]]
    assert len(ids) == len(set(ids))


SCHEMA_ENGINES = load_schema("candidate")["properties"]["engine"]["enum"]


@pytest.mark.parametrize("name", TOOLS)
def test_expected_candidates_pass_the_candidate_validator(name):
    _, expected = load(name)
    if expected["engine"] not in SCHEMA_ENGINES:
        pytest.skip(f"candidate.schema.json does not list the engine {expected['engine']!r} yet")
    for index, candidate in enumerate(expected["candidates"]):
        assert validate_candidate(candidate) == [], f"{name}: candidate {index}"


@pytest.mark.parametrize("name", TOOLS)
def test_engines_with_a_default_class_never_give_a_null_class(name):
    _, expected = load(name)
    if expected["engine"] in ("bandit", "gosec", "opengrep"):
        pytest.skip("this engine has no default class")
    assert all(candidate["class"] for candidate in expected["candidates"]), name
