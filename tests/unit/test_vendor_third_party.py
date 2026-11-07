# SPDX-License-Identifier: MIT
"""The copy filters and license headers of scripts/vendor_third_party.py (K.8 rule packs)."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "vendor_third_party.py"


@pytest.fixture(scope="module")
def vendor():
    spec = importlib.util.spec_from_file_location("vendor_third_party", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_name_filters(vendor):
    rule = {"include": ["*.yaml", "*.yml"], "exclude": ["*.test.yaml"]}
    assert vendor.name_selected(rule, Path("python/a/rule.yaml"))
    assert vendor.name_selected(rule, Path("rule.yml"))
    assert not vendor.name_selected(rule, Path("python/a/rule.test.yaml"))
    assert not vendor.name_selected(rule, Path("python/a/test.py"))
    assert vendor.name_selected({}, Path("anything.txt"))
    # A copy rule for a single file always selects it.
    assert vendor.name_selected(rule, Path())


def test_text_filter(vendor):
    rule = {"require": "(?m)^rules:"}
    assert vendor.text_selected(rule, b"# header\nrules:\n  - id: x\n")
    assert not vendor.text_selected(rule, b"jobs:\n  build: {}\n")
    assert vendor.text_selected({}, b"")


def test_license_header(vendor):
    component = {
        "license_header": {
            "regex": "^# License: (.+)$",
            "allowed": {"MIT (c) GitLab Inc.": "MIT"},
        }
    }
    text = b"---\n# License: MIT (c) GitLab Inc.\nrules: []\n"
    assert vendor.license_header(component, text) == ("MIT", "MIT (c) GitLab Inc.")
    spdx, header = vendor.license_header(component, b"# License: Commons Clause [LGPL]\n")
    assert spdx is None and header == "Commons Clause [LGPL]"
    assert vendor.license_header(component, b"rules: []\n") == (None, "(no license header)")


def test_header_exemptions(vendor):
    component = {
        "license_files": ["LICENSE", "rules/lgpl/LICENSE"],
        "copy": [
            {"from": "csharp", "to": "csharp"},
            {"from": "README.md", "to": "README.upstream.md", "license_header": False},
        ],
    }
    assert vendor.header_exempt(component, "LICENSE")
    assert vendor.header_exempt(component, "rules/lgpl/LICENSE")
    assert vendor.header_exempt(component, "README.upstream.md")
    assert not vendor.header_exempt(component, "csharp/rule-x.yml")


def test_rule_pack_components_are_pinned_on_or_before_the_14_day_limit():
    """ADR-0005 rule 1: the pin day (2026-10-25; 2026-11-07 for the packs of ADR-0007) is at
    least 14 days after the commit."""
    manifest = json.loads((ROOT / "third_party" / "MANIFEST.json").read_text(encoding="utf-8"))
    packs = {
        "gitlab-sast-rules": (("MIT", "LGPL-3.0-only"), "2026-10-11"),
        "0xdea-semgrep-rules": (("MIT",), "2026-10-11"),
        "trailofbits-semgrep-rules": (("AGPL-3.0-only",), "2026-10-11"),
        "elttam-semgrep-rules": (("MIT",), "2026-10-24"),
        "mobsfscan-rules": (("LGPL-3.0-or-later",), "2026-10-24"),
        "njsscan-rules": (("LGPL-3.0-or-later",), "2026-10-24"),
        "atlassian-sast-ruleset": (("LGPL-2.1-only",), "2026-10-24"),
        "mindedsecurity-android-rules": (("GPL-3.0-only",), "2026-10-24"),
        "aikido-opengrep-rules": (("MIT",), "2026-10-24"),
        "semgrep-codeql-rules": (("MIT",), "2026-10-24"),
    }
    by_name = {component["name"]: component for component in manifest["components"]}
    for name, (licenses, last_day) in packs.items():
        component = by_name[name]
        assert len(component["commit"]) == 40
        assert component["commit_date"] <= last_day, name
        assert all(text in component["license"] for text in licenses), name
        for license_file in component["license_files"]:
            assert (ROOT / "third_party" / name / license_file).is_file()


def test_no_gitlab_file_outside_the_mit_and_lgpl_headers(vendor):
    manifest = json.loads((ROOT / "third_party" / "MANIFEST.json").read_text(encoding="utf-8"))
    component = next(item for item in manifest["components"] if item["name"] == "gitlab-sast-rules")
    folder = ROOT / "third_party" / "gitlab-sast-rules"
    files = [path for path in folder.rglob("*.yml")]
    assert files
    for path in files:
        spdx, header = vendor.license_header(component, path.read_bytes())
        assert spdx in {"MIT", "LGPL-3.0-only"}, (path, header)
    assert not (folder / "rules" / "lgpl-cc").exists()
    assert not (folder / "rules" / "gitlab").exists()
