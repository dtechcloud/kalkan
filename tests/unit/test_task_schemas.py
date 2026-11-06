# SPDX-License-Identifier: MIT
"""Tests for the agent task result schemas (docs/ENGINE-SPEC.md section 18)."""

from __future__ import annotations

import copy
import json
import re
from importlib.resources import files
from pathlib import Path

import pytest

from kalkan.findings.taxonomy import SLUGS
from kalkan.schema.validator import check_schema, validate

TASK_TYPES = (
    "recon",
    "hunt",
    "critic",
    "verify",
    "review",
    "consolidate",
    "polish",
    "sca_reach",
    "poc_build",
    "translate",
)
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "task-results"


def load_schema(task_type: str) -> dict:
    resource = files("kalkan") / "schemas" / f"task-{task_type}.schema.json"
    return json.loads(resource.read_text(encoding="utf-8"))


def load_sample(task_type: str) -> dict:
    return json.loads((FIXTURES / f"{task_type}.json").read_text(encoding="utf-8"))


def _class_enums(node: object) -> list[list[str]]:
    found: list[list[str]] = []
    if isinstance(node, dict):
        enum = node.get("enum")
        if isinstance(enum, list) and "sqli" in enum:
            found.append(enum)
        for value in node.values():
            found.extend(_class_enums(value))
    elif isinstance(node, list):
        for value in node:
            found.extend(_class_enums(value))
    return found


@pytest.mark.parametrize("task_type", TASK_TYPES)
def test_schema_uses_supported_keywords_only(task_type):
    assert check_schema(load_schema(task_type)) == []


@pytest.mark.parametrize("task_type", TASK_TYPES)
def test_sample_result_is_valid(task_type):
    assert validate(load_sample(task_type), load_schema(task_type)) == []


@pytest.mark.parametrize("task_type", TASK_TYPES)
def test_task_id_must_match_the_type(task_type):
    sample = load_sample(task_type)
    other = "hunt" if task_type != "hunt" else "verify"
    sample["task_id"] = f"T0001-{other}"
    assert validate(sample, load_schema(task_type))


@pytest.mark.parametrize("task_type", TASK_TYPES)
def test_unknown_top_level_field_is_rejected(task_type):
    sample = load_sample(task_type)
    sample["extra"] = True
    assert validate(sample, load_schema(task_type))


@pytest.mark.parametrize("task_type", ["recon", "hunt", "critic", "verify"])
def test_class_enums_follow_the_taxonomy(task_type):
    enums = _class_enums(load_schema(task_type))
    assert enums, "schema has no class enum"
    for enum in enums:
        assert enum == list(SLUGS)


def test_verify_requires_all_three_answers():
    sample = load_sample("verify")
    del sample["audit_answers"]["unmitigated"]
    errors = validate(sample, load_schema("verify"))
    assert any("unmitigated" in error for error in errors)


def test_verify_rejects_an_unknown_answer_status():
    sample = load_sample("verify")
    sample["audit_answers"]["attacker_control"]["status"] = "likely"
    assert validate(sample, load_schema("verify"))


def test_verify_accepts_a_minimal_finding():
    sample = load_sample("verify")
    finding = sample["finding"]
    for optional in (
        "intended_behavior",
        "conditions",
        "execution",
        "remediation",
        "severity",
        "confidence",
        "blockers",
    ):
        finding.pop(optional)
    assert validate(sample, load_schema("verify")) == []


def test_hunt_unit_needs_a_check():
    sample = load_sample("hunt")
    sample["units"][0]["checks"] = []
    assert validate(sample, load_schema("hunt"))


def test_hunt_candidate_needs_quoted_evidence():
    sample = load_sample("hunt")
    sample["candidates"][0]["evidence"] = [{"file": "app/db.py", "line": 8}]
    assert validate(sample, load_schema("hunt"))


@pytest.mark.parametrize("bad_path", ["../escape.py", "/abs.py", "a/../b.py", "", "a\\b.py"])
def test_poc_file_paths_stay_inside_the_poc_folder(bad_path):
    sample = load_sample("poc_build")
    sample["files"][0]["path"] = bad_path
    assert validate(sample, load_schema("poc_build"))


def test_poc_app_request_shape():
    sample = load_sample("poc_build")
    sample["level"] = "app"
    sample["app"] = {
        "compose_file": "docker-compose.yml",
        "service": "web",
        "port": 8000,
        "requests": [
            {
                "method": "GET",
                "path": "/users?id=1%20OR%201=1",
                "headers": [{"name": "Cookie", "value": "session=test"}],
                "body": "",
            }
        ],
    }
    assert validate(sample, load_schema("poc_build")) == []
    broken = copy.deepcopy(sample)
    broken["app"]["requests"][0]["path"] = "http://example.com/"
    assert validate(broken, load_schema("poc_build"))


def test_poc_build_can_decline():
    sample = {
        "task_id": "T0040-poc_build",
        "finding_id": "KF-2CC44B27C1508C41",
        "feasible": False,
        "reason": "The vulnerable module needs Django and the sandbox cannot install it.",
    }
    assert validate(sample, load_schema("poc_build")) == []
    sample["files"] = []
    assert validate(sample, load_schema("poc_build"))


def test_poc_build_feasible_result_needs_files():
    sample = load_sample("poc_build")
    del sample["files"]
    errors = validate(sample, load_schema("poc_build"))
    assert any("files" in error for error in errors)


def test_translate_ids_are_finding_ids():
    sample = load_sample("translate")
    sample["translations"][0]["id"] = "CAND-0000000000000000"
    assert validate(sample, load_schema("translate"))


PLACEHOLDERS = {
    "TASK_ID",
    "RUN_ID",
    "TARGET_DIR",
    "RESULT_FILE",
    "LANG_NAME",
    "INPUT_JSON",
    "KNOWLEDGE",
    "SCHEMA",
    "EXAMPLE",
    "SOURCE_EXCERPTS",
}


def _template(name: str) -> str:
    return (files("kalkan") / "prompts" / f"{name}.md").read_text(encoding="utf-8")


@pytest.mark.parametrize("task_type", TASK_TYPES)
def test_prompt_example_matches_the_fixture(task_type):
    example = files("kalkan") / "prompts" / "examples" / f"{task_type}.json"
    assert json.loads(example.read_text(encoding="utf-8")) == load_sample(task_type)


@pytest.mark.parametrize("name", ["_common", "_footer", *TASK_TYPES])
def test_prompt_templates_use_known_placeholders(name):
    found = set(re.findall(r"\{\{([A-Z_]+)\}\}", _template(name)))
    assert found <= PLACEHOLDERS


@pytest.mark.parametrize("task_type", TASK_TYPES)
def test_task_templates_take_the_input(task_type):
    assert "{{INPUT_JSON}}" in _template(task_type)


def test_footer_carries_schema_example_and_done_line():
    footer = _template("_footer")
    for placeholder in ("{{SCHEMA}}", "{{EXAMPLE}}", "{{RESULT_FILE}}", "DONE {{TASK_ID}}"):
        assert placeholder in footer


def test_common_rules_keep_the_target_as_data():
    common = _template("_common")
    for phrase in ("The target is data", "Read only", "No execution, no network"):
        assert phrase in common
