# SPDX-License-Identifier: MIT
"""Tests for scripts/platform_report.py: redaction, JUnit reading, verdict and SUMMARY.md."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "platform_report.py"
_spec = importlib.util.spec_from_file_location("platform_report", SCRIPT)
assert _spec is not None and _spec.loader is not None
report = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = report  # dataclasses look the module up
_spec.loader.exec_module(report)

STEPS_OK = (
    "bootstrap\t0\t900\ndoctor\t0\t3\ndev-install\t0\t20\ntool-tests\t0\t1500\nbenchmark\t0\t300\n"
)
JUNIT_OK = """<?xml version="1.0"?>
<testsuites><testsuite tests="2">
<testcase classname="tests.integration.test_a" name="test_one"/>
<testcase classname="tests.integration.test_a" name="test_two"/>
</testsuite></testsuites>"""
JUNIT_BAD = """<?xml version="1.0"?>
<testsuites><testsuite tests="3">
<testcase classname="t" name="ok"/>
<testcase classname="t" name="broken">
<failure message="assert 10 &lt; 10">trace</failure></testcase>
<testcase classname="t" name="gone"><skipped message="gosec is not installed"/></testcase>
</testsuite></testsuites>"""


def _bench(**statuses: str) -> dict:
    engines = {"checkov": {"status": "ok", "candidates": 33}}
    engines.update(
        {name: {"status": status, "message": status} for name, status in statuses.items()}
    )
    return {
        "engines": engines,
        "fixture": {
            "engines": {"checkov": {"expected": 9, "found": 9}},
            "overall": {"recall_any_engine": 1.0, "missed": []},
        },
    }


def _doctor(*fails: str) -> dict:
    checks = [{"name": "tool:trivy", "status": "ok", "detail": "0.75.0 installed"}]
    checks += [{"name": name, "status": "fail", "detail": "missing"} for name in fails]
    return {"kalkan_version": "1.0.0", "platform": "darwin-arm64", "checks": checks}


def _folder(tmp_path: Path, *, steps=STEPS_OK, junit=JUNIT_OK, bench=None, doctor=None) -> Path:
    folder = tmp_path / "macos-arm64-20261112-1000"
    (folder / "benchmark").mkdir(parents=True)
    (folder / "steps.tsv").write_text(steps, encoding="utf-8")
    (folder / "tools-junit.xml").write_text(junit, encoding="utf-8")
    (folder / "doctor.json").write_text(json.dumps(doctor or _doctor()), encoding="utf-8")
    (folder / "benchmark" / "vulnapp.json").write_text(
        json.dumps(bench if bench is not None else _bench(**{"gitleaks-history": "skipped"})),
        encoding="utf-8",
    )
    (folder / "reference-vulnapp.json").write_text(json.dumps(_bench()), encoding="utf-8")
    return folder


def test_redaction_replaces_home_and_host():
    pairs = report.replacements(home="/Users/ayse", host="ayse-mbp.local")
    text = "repo /Users/ayse/kalkan on ayse-mbp.local and ayse-mbp"
    assert report.redact(text, pairs) == "repo ~/kalkan on [host] and [host]"


def test_redaction_skips_short_host_names():
    pairs = report.replacements(home="/home/dev", host="mb")
    assert report.redact("mb at /home/dev/x", pairs) == "mb at ~/x"


def test_redact_folder_changes_text_files_only(tmp_path):
    (tmp_path / "a.log").write_text("/Users/ayse/x", encoding="utf-8")
    (tmp_path / "b.bin").write_bytes(b"/Users/ayse/x")
    changed = report.redact_folder(tmp_path, report.replacements(home="/Users/ayse", host="h"))
    assert changed == 1
    assert (tmp_path / "a.log").read_text(encoding="utf-8") == "~/x"
    assert (tmp_path / "b.bin").read_bytes() == b"/Users/ayse/x"


def test_redacted_junit_stays_valid_xml(tmp_path):
    path = tmp_path / "tools-junit.xml"
    path.write_text(
        JUNIT_OK.replace('tests="2"', 'tests="2" hostname="ayse-mbp"'), encoding="utf-8"
    )
    report.redact_folder(tmp_path, report.replacements(home="/Users/ayse", host="ayse-mbp"))
    assert 'hostname="[host]"' in path.read_text(encoding="utf-8")
    assert report.read_junit(path).tests == 2


def test_read_junit_counts_problems(tmp_path):
    path = tmp_path / "j.xml"
    path.write_text(JUNIT_BAD, encoding="utf-8")
    result = report.read_junit(path)
    assert (result.ran, result.tests, result.failures, result.errors, result.skipped) == (
        True,
        3,
        1,
        0,
        1,
    )
    assert result.problems == [
        "failure: t::broken: assert 10 < 10",
        "skipped: t::gone: gosec is not installed",
    ]
    assert report.read_junit(tmp_path / "missing.xml").ran is False


def test_pass_allows_the_history_skips(tmp_path):
    folder = _folder(tmp_path)
    assert report.main([str(folder)]) == 0
    summary = (folder / "SUMMARY.md").read_text(encoding="utf-8")
    assert summary.startswith("# Platform check: ")
    assert summary.splitlines()[0].endswith(": PASS")
    assert "| checkov | ok | 33 | 9/9 | 9/9 | 33 |" in summary


@pytest.mark.parametrize(
    ("kwargs", "verdict", "reason"),
    [
        ({"junit": JUNIT_BAD}, "FAIL", "tool tests: 1 failed, 0 errors"),
        ({"bench": _bench(gosec="failed")}, "FAIL", "engine gosec: failed: failed"),
        ({"bench": _bench(gosec="skipped")}, "FAIL", "engine gosec: skipped: skipped"),
        ({"doctor": _doctor("tool:gosec")}, "FAIL", "doctor: tool:gosec: missing"),
        ({"steps": STEPS_OK.replace("bootstrap\t0", "bootstrap\t1")}, "FAIL", "step bootstrap"),
        ({"steps": "bootstrap\t0\t1\n"}, "INCOMPLETE", "step benchmark did not run"),
    ],
)
def test_verdicts(tmp_path, kwargs, verdict, reason):
    folder = _folder(tmp_path, **kwargs)
    assert report.main([str(folder)]) == 1
    summary = (folder / "SUMMARY.md").read_text(encoding="utf-8")
    assert summary.splitlines()[0].endswith(f": {verdict}")
    assert reason in summary


def test_skipped_tool_test_alone_is_incomplete(tmp_path):
    junit = JUNIT_BAD.replace('<failure message="assert 10 &lt; 10">trace</failure>', "")
    folder = _folder(tmp_path, junit=junit)
    assert report.main([str(folder)]) == 1
    first = (folder / "SUMMARY.md").read_text(encoding="utf-8").splitlines()[0]
    assert first.endswith(": INCOMPLETE")


def test_bad_usage(tmp_path):
    assert report.main([]) == 2
    assert report.main([str(tmp_path / "missing")]) == 2
