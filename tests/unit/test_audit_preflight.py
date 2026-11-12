# SPDX-License-Identifier: MIT
"""Tests for the setup checks of ``kalkan audit`` (kalkan.audit.preflight). No process starts."""

from __future__ import annotations

import io
import subprocess
import sys

import pytest

from kalkan.audit import preflight
from kalkan.audit.preflight import Preflight, Problem
from kalkan.sca.vulndb import DEFAULT_ECOSYSTEMS
from kalkan.tools.doctor import Check, DoctorReport

ALL_DATABASES = {"osv_ecosystems": list(DEFAULT_ECOSYSTEMS), "grype": True, "go": {"x": 1}}


def report(*checks: Check) -> DoctorReport:
    return DoctorReport(tuple(checks), "linux-amd64", "/fake")


def ok(name: str, data: dict | None = None) -> Check:
    return Check(name, "ok", f"{name} ok", data or {})


def test_a_clean_report_needs_nothing():
    found = preflight.evaluate(
        report(ok("python"), ok("tool:trivy"), ok("vulndb", ALL_DATABASES), ok("claude")),
        agents=True,
    )
    assert found == Preflight()
    assert not found.needs_setup and preflight.setup_commands(found) == []


def test_failing_tool_rows_are_generic():
    found = preflight.evaluate(
        report(
            Check("tool:trivy", "fail", "not installed; run: kalkan tools install trivy"),
            Check("tool:brand-new-scanner", "fail", "not installed; run: kalkan tools ..."),
            Check("tool:gixy", "warn", "no pinned 1.0 build for windows-arm64"),
            ok("tool:opengrep"),
        ),
        agents=False,
    )
    assert found.tool_names == ["trivy", "brand-new-scanner"]
    assert found.warnings == (Problem("tool:gixy", "no pinned 1.0 build for windows-arm64"),)
    assert found.needs_setup and preflight.setup_commands(found) == [preflight.TOOLS_COMMAND]


def test_missing_and_stale_databases():
    missing = Check("vulndb", "warn", "no local vulnerability databases", {"osv_ecosystems": []})
    found = preflight.evaluate(report(missing), agents=False)
    assert found.databases == Problem("vulndb", "no local vulnerability databases")
    assert preflight.setup_commands(found) == [preflight.DATABASES_COMMAND]
    no_go = Check("vulndb", "warn", "no Go database", {**ALL_DATABASES, "go": None})
    assert preflight.evaluate(report(no_go), agents=False).databases is not None
    stale = Check("vulndb", "warn", "the databases are 30 days old", ALL_DATABASES)
    found = preflight.evaluate(report(stale), agents=False)
    assert found.databases is None and found.stale is not None and not found.needs_setup


def test_tools_and_databases_give_both_commands_in_order():
    found = preflight.evaluate(
        report(
            Check("vulndb", "warn", "no databases", {}),
            Check("tool:go", "fail", "not installed; run: kalkan tools install go"),
        ),
        agents=False,
    )
    assert preflight.setup_commands(found) == [
        preflight.TOOLS_COMMAND,
        preflight.DATABASES_COMMAND,
    ]


def test_claude_and_trust_count_only_in_agent_mode():
    rows = report(
        Check("claude", "warn", "Claude Code CLI not found"),
        Check("unattended:workspace-trust", "warn", "Claude Code does not trust this folder"),
        Check("unattended:print-mode", "warn", "claude -p --help does not list ..."),
    )
    agents = preflight.evaluate(rows, agents=True)
    assert agents.claude == Problem("claude", "Claude Code CLI not found")
    assert agents.trust is not None
    assert agents.warnings == (
        Problem("unattended:print-mode", "claude -p --help does not list ..."),
    )
    tools_only = preflight.evaluate(rows, agents=False)
    assert tools_only.claude is None and tools_only.trust is None
    info = report(Check("unattended:workspace-trust", "info", "Claude Code plugin: ..."))
    assert preflight.evaluate(info, agents=True).trust is None
    named = report(
        Check("unattended:workspace-trust", "warn", "Run `claude` once.", {"repo": "C:/kalkan"})
    )
    trust = preflight.evaluate(named, agents=True).trust
    assert trust is not None and trust.detail == "Run `claude` once. Folder: C:/kalkan"


def test_other_failures_are_fatal_and_other_warnings_selected():
    found = preflight.evaluate(
        report(
            Check("python", "fail", "Python 3.10 is too old"),
            Check("runs-writable", "fail", "cannot write; set KALKAN_RUNS_DIR"),
            Check("disk", "warn", "1.0 GB free"),
            Check("docker-engine", "warn", "not running"),  # never shown by the audit
        ),
        agents=True,
    )
    assert [problem.check for problem in found.fatal] == ["python", "runs-writable"]
    assert [problem.check for problem in found.warnings] == ["disk"]


def test_to_dict_is_json_ready():
    found = Preflight(tools=(Problem("tool:a", "x"),), databases=Problem("vulndb", "y"))
    data = found.to_dict()
    assert data["tools"] == [{"check": "tool:a", "detail": "x"}]
    assert data["databases"] == {"check": "vulndb", "detail": "y"}
    assert data["claude"] is None and data["fatal"] == []


def test_describe_and_fix_lines():
    found = Preflight(
        tools=(Problem("tool:trivy", "a"), Problem("tool:syft", "b")),
        databases=Problem("vulndb", "no local vulnerability databases (run: ...)"),
    )
    lines = preflight.describe(found)
    assert lines[0] == "2 pinned tools are missing or broken: trivy, syft"
    assert lines[1].startswith("local vulnerability databases: no local")
    one = preflight.describe(Preflight(tools=(Problem("tool:go", "a"),)))
    assert one == ["1 pinned tool is missing or broken: go"]
    fix = preflight.fix_lines(found, engine='"C:/d/kalkan.exe"', retry="kalkan-audit app --yes")
    assert fix == [
        "Fix it with these commands, then start the audit again:",
        '  "C:/d/kalkan.exe" tools install --all',
        '  "C:/d/kalkan.exe" sca update-db --max-age 168',
        "Or let the audit install them first: kalkan-audit app --yes",
    ]


@pytest.mark.parametrize(
    ("answer", "expected"),
    [("y\n", True), ("YES\n", True), ("evet\n", True), ("e\n", True), ("n\n", False)]
    + [("\n", False), ("maybe\n", False), ("", False)],
)
def test_ask_yes_no(answer, expected):
    err = io.StringIO()
    assert preflight.ask_yes_no("Install?", stdin=io.StringIO(answer), stderr=err) is expected
    text = err.getvalue()
    assert text.startswith("Install? [y/N] ")
    assert text.endswith("\n") is (answer == "")  # the end of input finishes the line


def test_run_setup_runs_the_engine_with_stdout_on_stderr():
    calls, said = [], []

    def runner(argv, **kwargs):
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0 if argv[-1] == "--all" else 1)

    steps = preflight.run_setup(
        [preflight.TOOLS_COMMAND, preflight.DATABASES_COMMAND],
        say=said.append,
        runner=runner,
        python="/venv/python",
    )
    assert [argv for argv, _ in calls] == [
        ["/venv/python", "-m", "kalkan", "tools", "install", "--all"],
        ["/venv/python", "-m", "kalkan", "sca", "update-db", "--max-age", "168"],
    ]
    for _, kwargs in calls:
        assert kwargs["stdout"] == 2 and kwargs["stderr"] == 2
        assert kwargs["shell"] is False and kwargs["timeout"] == preflight.SETUP_TIMEOUT_SECONDS
        assert kwargs["stdin"] == subprocess.DEVNULL
    assert [step.ok for step in steps] == [True, False]
    assert steps[1].to_dict() == {
        "command": ["kalkan", "sca", "update-db", "--max-age", "168"],
        "exit_code": 1,
    }
    assert "setup: kalkan sca update-db --max-age 168 ended with exit code 1" in said


def test_run_setup_reports_a_command_that_does_not_start():
    def runner(argv, **kwargs):
        raise OSError("no such file")

    said: list[str] = []
    (step,) = preflight.run_setup([preflight.TOOLS_COMMAND], say=said.append, runner=runner)
    assert step.exit_code is None and step.error == "no such file" and not step.ok
    assert step.to_dict()["error"] == "no such file"
    assert any("did not run" in line for line in said)


def test_run_setup_uses_this_python_by_default():
    calls = []

    def runner(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0)

    preflight.run_setup([preflight.DATABASES_COMMAND], say=lambda _m: None, runner=runner)
    assert calls[0][0] == sys.executable


@pytest.mark.parametrize(
    ("agents", "tools", "skip"),
    [
        (True, True, {"docker", "node"}),
        (False, True, {"docker", "node", "claude"}),
        (True, False, {"docker", "node", "tools"}),
    ],
)
def test_run_checks_skips_what_the_audit_does_not_need(agents, tools, skip):
    seen = {}

    def doctor(**kwargs):
        seen.update(kwargs)
        return report()

    preflight.run_checks(agents=agents, tools=tools, doctor=doctor, repo_root="/x")
    assert seen["skip"] == frozenset(skip) and seen["repo_root"] == "/x"
