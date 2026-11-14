# SPDX-License-Identifier: MIT
"""Bandit: the B101 results (assert_used) in test files are dropped; every other result stays."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kalkan.scanners.adapters._sources import is_test_path
from kalkan.scanners.adapters.bandit import BanditAdapter, drop_test_asserts
from kalkan.scanners.base import Invocation, ScanContext


@pytest.mark.parametrize(
    ("rel", "expected"),
    [
        ("tests/unit/test_cli.py", True),
        ("pkg/tests/helpers.py", True),
        ("Test/x.py", True),
        ("src/test_app.py", True),
        ("src/app_test.py", True),
        ("conftest.py", True),
        ("src/kalkan/cli.py", False),
        ("src/testing_tools.py", False),  # a name that only starts with "test"
        ("src/contest.py", False),
        ("docs/test_plan.md", False),
    ],
)
def test_is_test_path(rel, expected):
    assert is_test_path(rel) is expected


def _result(rule: str, uri: str) -> dict:
    return {
        "ruleId": rule,
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}],
    }


def _sarif(target: Path) -> dict:
    absolute = (target / "tests" / "unit" / "test_a.py").as_uri()
    return {
        "version": "2.1.0",
        "runs": [
            {
                "results": [
                    _result("B101", absolute),  # dropped: an absolute URI of a test file
                    _result("B101", "tests/test_b.py"),  # dropped: a relative URI
                    _result("B101", "src/app.py"),  # kept: an assert in the code
                    _result("B603", "tests/test_c.py"),  # kept: another rule in a test
                ]
            }
        ],
    }


def test_drop_test_asserts(tmp_path):
    doc, dropped = drop_test_asserts(_sarif(tmp_path), tmp_path)
    assert dropped == 2
    kept = [
        (r["ruleId"], r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"])
        for r in doc["runs"][0]["results"]
    ]
    assert kept == [("B101", "src/app.py"), ("B603", "tests/test_c.py")]


def test_after_run_rewrites_the_output_and_counts(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    out = tmp_path / "bandit.sarif"
    out.write_text(json.dumps(_sarif(target)), encoding="utf-8")
    adapter = BanditAdapter()
    ctx = ScanContext(tmp_path, target, None, frozenset({"python"}))
    adapter.prepare(ctx, out)
    adapter.after_run(ctx, Invocation(("bandit",), tmp_path, out))
    assert len(json.loads(out.read_text(encoding="utf-8"))["runs"][0]["results"]) == 2
    assert adapter.status_details(ctx, out, out, [out]) == {"test_asserts_dropped": 2}
    adapter.prepare(ctx, out)  # a new run starts the count again
    assert adapter.status_details(ctx, out, out, [out]) == {"test_asserts_dropped": 0}
