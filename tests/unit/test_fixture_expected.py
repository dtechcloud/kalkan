# SPDX-License-Identifier: MIT
"""Checks for the vulnapp fixture and its EXPECTED.json. These tests need no external tool."""

from __future__ import annotations

import json
import os
import re
from collections import defaultdict
from pathlib import Path, PurePosixPath

import pytest

from kalkan.findings import taxonomy

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "vulnapp"
EXPECTED = FIXTURE / "EXPECTED.json"
METADATA_FILES = ("README.md", "EXPECTED.json", "INJECTION-NOTE.md")

KINDS = {"vulnerable", "secure-twin"}
ENGINES = {
    "opengrep",
    "opengrep-packs",
    "bandit",
    "gosec",
    "trivy",
    "checkov",
    "hadolint",
    "gitleaks",
    "osv-scanner",
    "grype",
    "govulncheck",
    "retirejs",
    "matcher",
    "kingfisher",
    "shellcheck",
    "flawfinder",
    "gixy",
    "helm-checkov",
    "vacuum",
    "hunter",
    "zizmor",
    "actionlint",
    "poutine",
    "scorecard",
}
REQUIRED_KEYS = {
    "id": str,
    "kind": str,
    "class": str,
    "cwe": list,
    "language": str,
    "file": str,
    "line": int,
    "snippet": str,
    "expected_engines": list,
    "title": str,
}
ID_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
CWE_RE = re.compile(r"^CWE-[0-9]+$")
# A finding counts for an item when it starts within this many lines of the item line.
WINDOW = 2

AGENT_FILES = {
    "CLAUDE.md",
    "CLAUDE.local.md",
    "AGENTS.md",
    "AGENTS.override.md",
    "GEMINI.md",
    ".cursorrules",
    ".windsurfrules",
    "copilot-instructions.md",
}
AGENT_DIRS = {".claude", ".agents", ".codex", ".cursor", ".gemini", ".windsurf"}
# Real-format live tokens. GitHub push protection blocks them, so the fixture must not hold one.
LIVE_TOKEN_RE = re.compile(
    r"ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}"
    r"|xox[abpr]-[A-Za-z0-9-]{10,}|[sr]k_live_[A-Za-z0-9]{10,}|AIza[0-9A-Za-z_-]{35}"
    r"|glpat-[A-Za-z0-9_-]{20}"
)
# Secret values that must stay in the fixture files and out of its metadata files.
SECRET_VALUE_RE = re.compile(r"(?:AKIA|ASIA)[A-Z0-9]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----")

# The planted items that the task brief asks for (language group, class).
REQUIRED_PLANTED = {
    "python": {
        "sqli",
        "os-command-injection",
        "ssti",
        "ssrf",
        "path-traversal",
        "deserialization",
        "code-injection",
        "idor",
        "missing-authz",
        "crypto",
        "jwt",
    },
    "javascript": {
        "xss",
        "nosqli",
        "prototype-pollution",
        "open-redirect",
        "os-command-injection",
        "jwt",
        "cors",
    },
    "go": {"sqli", "os-command-injection", "ssrf"},
    "java": {"sqli", "xxe", "deserialization"},
    "php": {"sqli", "os-command-injection", "code-injection", "deserialization"},
}
REQUIRED_MINIMUM = {
    ("dockerfile", "iac-cloud-container"): 2,
    ("dockerfile", "supply-chain-cicd"): 2,
    ("terraform", "iac-cloud-container"): 3,
    ("kubernetes", "iac-cloud-container"): 2,
    ("config", "hardcoded-secrets"): 3,
    ("github-actions", "supply-chain-cicd"): 3,
    ("github-actions", "code-injection"): 1,
    ("azure-pipelines", "code-injection"): 1,
}
REQUIRED_SCA_ECOSYSTEMS = {"PyPI", "npm", "Go"}


def load_items() -> list[dict]:
    """Return the planted items of EXPECTED.json."""
    return json.loads(EXPECTED.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def items() -> list[dict]:
    return load_items()


@pytest.fixture(scope="module")
def by_id(items: list[dict]) -> dict[str, dict]:
    return {item["id"]: item for item in items}


def language_group(item: dict) -> str:
    return "javascript" if item["language"] == "typescript" else item["language"]


def test_expected_json_is_a_list_of_items(items: list[dict]) -> None:
    assert isinstance(items, list) and items
    errors = []
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            errors.append(f"item {index} is not an object")
            continue
        for key, kind in REQUIRED_KEYS.items():
            if not isinstance(item.get(key), kind) or isinstance(item.get(key), bool):
                errors.append(f"{item.get('id', index)}: {key} must be {kind.__name__}")
        if item.get("kind") not in KINDS:
            errors.append(f"{item.get('id', index)}: unknown kind {item.get('kind')!r}")
        if not ID_RE.match(str(item.get("id", ""))):
            errors.append(f"item {index}: bad id {item.get('id')!r}")
    ids = [item.get("id") for item in items if isinstance(item, dict)]
    duplicates = sorted({item_id for item_id in ids if ids.count(item_id) > 1})
    assert not duplicates, f"duplicate ids: {duplicates}"
    assert not errors, "\n".join(errors)


def test_classes_and_cwes_follow_the_taxonomy(items: list[dict]) -> None:
    errors = []
    for item in items:
        vuln_class = taxonomy.get_class(item["class"])
        if vuln_class is None:
            errors.append(f"{item['id']}: unknown class {item['class']!r}")
            continue
        cwes = item["cwe"]
        if not cwes or not all(isinstance(c, str) and CWE_RE.match(c) for c in cwes):
            errors.append(f"{item['id']}: bad cwe list {cwes!r}")
            continue
        if vuln_class.cwe and cwes[0] not in vuln_class.cwe:
            errors.append(
                f"{item['id']}: first CWE {cwes[0]} is not a default CWE of {item['class']}"
            )
    assert not errors, "\n".join(errors)


def test_every_referenced_line_exists_and_holds_the_snippet(items: list[dict]) -> None:
    errors = []
    cache: dict[str, list[str]] = {}
    for item in items:
        rel = item["file"]
        posix = PurePosixPath(rel)
        if "\\" in rel or posix.is_absolute() or ".." in posix.parts or ":" in rel:
            errors.append(f"{item['id']}: file must be a relative POSIX path: {rel!r}")
            continue
        path = FIXTURE / rel
        if not path.is_file():
            errors.append(f"{item['id']}: missing file {rel}")
            continue
        if rel not in cache:
            cache[rel] = path.read_text(encoding="utf-8").split("\n")
        lines = cache[rel]
        line = item["line"]
        if not 1 <= line <= len(lines):
            errors.append(f"{item['id']}: line {line} is outside {rel} ({len(lines)} lines)")
            continue
        text = lines[line - 1]
        if not text.strip():
            errors.append(f"{item['id']}: {rel}:{line} is empty")
        if item["snippet"] not in text:
            errors.append(f"{item['id']}: {rel}:{line} does not contain {item['snippet']!r}")
    assert not errors, "\n".join(errors)


def test_every_vulnerable_item_has_a_secure_twin_of_the_same_class(
    items: list[dict], by_id: dict[str, dict]
) -> None:
    errors = []
    for item in items:
        if item["kind"] == "vulnerable":
            twin = by_id.get(item.get("twin", ""))
            if twin is None:
                errors.append(f"{item['id']}: twin {item.get('twin')!r} does not exist")
            elif twin["kind"] != "secure-twin":
                errors.append(f"{item['id']}: twin {twin['id']} is not a secure twin")
            elif twin["class"] != item["class"]:
                errors.append(f"{item['id']}: twin {twin['id']} has class {twin['class']}")
            elif item["id"] not in twin.get("twin_of", []):
                errors.append(f"{item['id']}: twin {twin['id']} does not list it in twin_of")
        else:
            twin_of = item.get("twin_of")
            if not isinstance(twin_of, list) or not twin_of:
                errors.append(f"{item['id']}: secure twin needs a non-empty twin_of list")
                continue
            for vuln_id in twin_of:
                vuln = by_id.get(vuln_id)
                if vuln is None or vuln["kind"] != "vulnerable":
                    errors.append(f"{item['id']}: twin_of names {vuln_id!r}, not a vulnerable item")
                elif vuln.get("twin") != item["id"] or vuln["class"] != item["class"]:
                    errors.append(
                        f"{item['id']}: {vuln_id} does not point back with the same class"
                    )
    assert not errors, "\n".join(errors)


def test_expected_engines_and_rules(items: list[dict]) -> None:
    errors = []
    for item in items:
        engines = item["expected_engines"]
        unknown = set(engines) - ENGINES
        if unknown:
            errors.append(f"{item['id']}: unknown engines {sorted(unknown)}")
        if item["kind"] == "vulnerable" and not engines:
            errors.append(f"{item['id']}: a vulnerable item needs at least one expected engine")
        if item["kind"] == "secure-twin" and engines:
            errors.append(f"{item['id']}: a secure twin expects no engine")
        rules = item.get("rules", {})
        if not isinstance(rules, dict):
            errors.append(f"{item['id']}: rules must be an object")
            continue
        for engine, rule_ids in rules.items():
            if engine not in engines:
                errors.append(f"{item['id']}: rules for {engine}, which is not expected")
            if not rule_ids or not all(isinstance(r, str) and r for r in rule_ids):
                errors.append(f"{item['id']}: rules for {engine} must be a non-empty string list")
        if item["class"] in taxonomy.DEPENDENCY_CLASSES:
            package = item.get("package")
            if not isinstance(package, dict) or not all(
                isinstance(package.get(key), str) and package.get(key)
                for key in ("ecosystem", "name", "version")
            ):
                errors.append(f"{item['id']}: package needs ecosystem, name and version")
    assert not errors, "\n".join(errors)


def test_secure_twins_keep_a_distance_from_vulnerable_lines(items: list[dict]) -> None:
    # Dependency items match by package, not by line (README, "Match rules").
    vulnerable = defaultdict(list)
    for item in items:
        if item["kind"] == "vulnerable" and item["class"] not in taxonomy.DEPENDENCY_CLASSES:
            vulnerable[item["file"]].append(item)
    errors = []
    for twin in items:
        if twin["kind"] != "secure-twin" or twin["class"] in taxonomy.DEPENDENCY_CLASSES:
            continue
        for vuln in vulnerable[twin["file"]]:
            if abs(vuln["line"] - twin["line"]) <= WINDOW:
                errors.append(f"{twin['id']} (line {twin['line']}) is near {vuln['id']}")
    assert not errors, "\n".join(errors)


def test_the_planted_items_of_the_brief_exist(items: list[dict]) -> None:
    vulnerable = [item for item in items if item["kind"] == "vulnerable"]
    present = defaultdict(set)
    counts: dict[tuple[str, str], int] = defaultdict(int)
    for item in vulnerable:
        present[language_group(item)].add(item["class"])
        counts[(item["language"], item["class"])] += 1
    missing = {
        group: sorted(classes - present[group])
        for group, classes in REQUIRED_PLANTED.items()
        if classes - present[group]
    }
    assert not missing, f"missing planted items: {missing}"
    short = {key: counts[key] for key, minimum in REQUIRED_MINIMUM.items() if counts[key] < minimum}
    assert not short, f"too few planted items: {short}"
    ecosystems = {
        item["package"]["ecosystem"]
        for item in vulnerable
        if item["class"] == "vulnerable-dependency"
    }
    assert REQUIRED_SCA_ECOSYSTEMS <= ecosystems
    # ADR-0005, K.2: a pinned version that an OSV MAL- record lists (never installed).
    assert any(item["class"] == "malicious-dependency" for item in vulnerable)


def test_no_agent_instruction_files_in_the_fixture() -> None:
    offenders = []
    for dirpath, dirnames, filenames in os.walk(FIXTURE):
        base = Path(dirpath)
        offenders += [
            (base / d).relative_to(FIXTURE).as_posix() for d in dirnames if d in AGENT_DIRS
        ]
        offenders += [
            (base / f).relative_to(FIXTURE).as_posix() for f in filenames if f in AGENT_FILES
        ]
    assert offenders == []


def test_fixture_holds_no_live_token_formats() -> None:
    offenders = []
    for path in sorted(FIXTURE.rglob("*")):
        if path.is_file():
            text = path.read_text(encoding="utf-8", errors="replace")
            if LIVE_TOKEN_RE.search(text):
                offenders.append(path.relative_to(FIXTURE).as_posix())
    assert offenders == []


def test_metadata_files_do_not_repeat_secret_values() -> None:
    for name in METADATA_FILES:
        text = (FIXTURE / name).read_text(encoding="utf-8")
        assert not SECRET_VALUE_RE.search(text), f"{name} repeats a planted secret value"


def test_readme_warns_not_to_deploy() -> None:
    text = (FIXTURE / "README.md").read_text(encoding="utf-8").lower()
    assert "do not deploy" in text
    assert (FIXTURE / "INJECTION-NOTE.md").is_file()
