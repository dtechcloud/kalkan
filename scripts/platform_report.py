# SPDX-License-Identifier: MIT
"""Summarize a platform check (scripts/platform_check.sh) into SUMMARY.md.

Usage: python scripts/platform_report.py <result folder>

The result folder holds what platform_check.sh wrote: ``steps.tsv`` (step, exit code,
seconds), ``doctor.json``, ``tools-junit.xml``, optionally ``docker-junit.xml``,
``benchmark/vulnapp.json`` and ``reference-vulnapp.json`` (the committed Windows result).

The script first removes personal data from every text file of the folder: the home folder
becomes ``~``, the host name ``[host]`` and the user name in a path ``[user]``. Then it writes
``SUMMARY.md`` and prints the verdict on the last line. Exit code 0: PASS; 1: FAIL or
INCOMPLETE; 2: bad usage.

Verdict rules:
- FAIL: a step failed, the doctor reports a fail, a tool test failed, or a vulnapp engine has a
  status other than ``ok`` (the history engines may skip: the fixture copy has no git history).
- INCOMPLETE: no FAIL, but a tool test was skipped (a missing tool, database or git), a step
  did not run, the base images of the sandbox could not be pulled, or a Docker test was skipped.
- PASS: everything else. The Docker tests count only when Docker was available.
"""

from __future__ import annotations

import getpass
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

#: Engines that skip on the vulnapp fixture by design: the copy has no git history.
EXPECTED_SKIPS = frozenset({"gitleaks-history", "kingfisher-history"})
#: The steps of platform_check.sh that must run.
REQUIRED_STEPS = ("bootstrap", "doctor", "dev-install", "tool-tests", "benchmark")
TEXT_SUFFIXES = frozenset({".json", ".md", ".log", ".xml", ".txt", ".tsv"})
MAX_PROBLEM_LINES = 40


# --- redaction -------------------------------------------------------------------------------


Replacement = tuple[str | re.Pattern[str], str]


def replacements(
    home: str | None = None, host: str | None = None, user: str | None = None
) -> list[Replacement]:
    """Return the (old, new) pairs of :func:`redact`: the home folder, the host name and the
    user name as a path part (``/private/var/folders/.../pytest-of-<user>/``), longest first."""
    home = home if home is not None else str(Path.home())
    host = host if host is not None else socket.gethostname()
    user = user if user is not None else _user_name()
    pairs: list[Replacement] = []
    if len(home) > 1:
        pairs.append((home, "~"))
        real = os.path.realpath(home)
        if real != home:
            pairs.append((real, "~"))
    for name in {host, host.split(".")[0]}:
        if len(name) >= 4:
            pairs.append((name, "[host]"))  # no < or >: the folder holds XML files
    pairs.sort(key=lambda pair: len(str(pair[0])), reverse=True)
    if len(user) >= 2:
        name = re.escape(user)
        # A whole path part (/Users/x/, pytest-of-x/), never a part of a longer word.
        pairs.append((re.compile(rf"(?<=pytest-of-){name}(?![\w.-])"), "[user]"))
        pairs.append((re.compile(rf"(?<=[/\\]){name}(?=[/\\])"), "[user]"))
    return pairs


def _user_name() -> str:
    try:
        return getpass.getuser()
    except (KeyError, OSError):  # no passwd entry
        return ""


def redact(text: str, pairs: list[Replacement]) -> str:
    """Replace each personal string or pattern of ``pairs`` in ``text``."""
    for old, new in pairs:
        text = old.sub(new, text) if isinstance(old, re.Pattern) else text.replace(old, new)
    return text


def redact_folder(folder: Path, pairs: list[Replacement]) -> int:
    """Redact every text file under ``folder``; return the count of changed files."""
    changed = 0
    for path in sorted(folder.rglob("*")):
        if not path.is_file() or path.suffix not in TEXT_SUFFIXES:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        new = redact(text, pairs)
        if new != text:
            path.write_text(new, encoding="utf-8", newline="\n")
            changed += 1
    return changed


# --- inputs ----------------------------------------------------------------------------------


@dataclass
class SuiteResult:
    """The counts and the problem lines of one JUnit XML file."""

    ran: bool = False
    tests: int = 0
    failures: int = 0
    errors: int = 0
    skipped: int = 0
    problems: list[str] = field(default_factory=list)


def read_junit(path: Path) -> SuiteResult:
    """Read a pytest JUnit XML file; a missing or broken file gives ``ran=False``."""
    result = SuiteResult()
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError):
        return result
    result.ran = True
    for case in root.iter("testcase"):
        result.tests += 1
        name = f"{case.get('classname', '')}::{case.get('name', '')}".strip(":")
        for kind in ("failure", "error", "skipped"):
            node = case.find(kind)
            if node is None:
                continue
            message = (node.get("message") or (node.text or "")).strip().splitlines()
            first = message[0][:200] if message else ""
            if kind == "failure":
                result.failures += 1
            elif kind == "error":
                result.errors += 1
            else:
                result.skipped += 1
            result.problems.append(f"{kind}: {name}: {first}")
    return result


def read_steps(path: Path) -> dict[str, tuple[int, int]]:
    """Read ``steps.tsv``: step name -> (exit code, seconds)."""
    steps: dict[str, tuple[int, int]] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return steps
    for line in lines:
        parts = line.split("\t")
        if len(parts) == 3 and parts[1].lstrip("-").isdigit() and parts[2].isdigit():
            steps[parts[0]] = (int(parts[1]), int(parts[2]))
    return steps


def read_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _run(*argv: str) -> str:
    if shutil.which(argv[0]) is None:
        return ""
    try:
        done = subprocess.run(argv, capture_output=True, text=True, timeout=30, check=False)
    except (OSError, subprocess.SubprocessError):
        return ""
    return done.stdout.strip() if done.returncode == 0 else ""


def host_facts() -> dict[str, str]:
    """Describe the machine without personal data."""
    system = platform.system()
    if system == "Darwin":
        name = "macOS " + (_run("sw_vers", "-productVersion") or platform.mac_ver()[0])
        chip = _run("sysctl", "-n", "machdep.cpu.brand_string")
    else:
        name = f"{system} {platform.release()}"
        chip = platform.processor()
    return {
        "os": name,
        "arch": platform.machine(),
        "cpu": chip or "unknown",
        "cpus": str(os.cpu_count() or 0),
        "python": platform.python_version(),
        "git": _run("git", "--version") or "not found",
        "docker": _run("docker", "version", "--format", "{{.Server.Version}}") or "not running",
    }


# --- verdict ---------------------------------------------------------------------------------


@dataclass
class Verdict:
    value: str
    reasons: list[str]


def decide(
    steps: dict[str, tuple[int, int]],
    doctor: dict,
    tools: SuiteResult,
    docker: SuiteResult,
    bench: dict,
) -> Verdict:
    """Apply the verdict rules of the module docstring."""
    fails: list[str] = []
    gaps: list[str] = []
    for name in REQUIRED_STEPS:
        if name not in steps:
            gaps.append(f"step {name} did not run")
    for name, (code, _seconds) in steps.items():
        if code == 0:
            continue
        # Docker is optional: a failed image pull leaves the sandbox untested, not broken.
        (gaps if name == "docker-pull" else fails).append(f"step {name} exited with {code}")
    for check in doctor.get("checks") or []:
        if isinstance(check, dict) and check.get("status") == "fail":
            fails.append(f"doctor: {check.get('name')}: {check.get('detail')}")
    if tools.ran:
        if tools.failures or tools.errors:
            fails.append(f"tool tests: {tools.failures} failed, {tools.errors} errors")
        if tools.skipped:
            gaps.append(f"tool tests: {tools.skipped} skipped")
    else:
        gaps.append("tool tests: no result file")
    if docker.ran and (docker.failures or docker.errors):
        fails.append(f"Docker tests: {docker.failures} failed, {docker.errors} errors")
    if docker.ran and docker.skipped:
        gaps.append(f"Docker tests: {docker.skipped} skipped (a base image is missing)")
    engines = bench.get("engines") or {}
    if not engines:
        gaps.append("benchmark: no vulnapp result")
    for engine, info in sorted(engines.items()):
        status = (info or {}).get("status")
        if status == "ok" or (status == "skipped" and engine in EXPECTED_SKIPS):
            continue
        fails.append(f"engine {engine}: {status}: {(info or {}).get('message')}")
    if fails:
        return Verdict("FAIL", fails + gaps)
    if gaps:
        return Verdict("INCOMPLETE", gaps)
    return Verdict("PASS", [])


# --- report ----------------------------------------------------------------------------------


def _count(info: dict) -> str:
    value = info.get("candidates")
    return "-" if value is None else str(value)


def _recall(fixture_engines: dict, engine: str) -> str:
    item = fixture_engines.get(engine) or {}
    if not item.get("expected"):
        return "-"
    return f"{item.get('found', 0)}/{item.get('expected')}"


def render(
    facts: dict[str, str],
    steps: dict[str, tuple[int, int]],
    doctor: dict,
    tools: SuiteResult,
    docker: SuiteResult,
    bench: dict,
    reference: dict,
    verdict: Verdict,
) -> str:
    lines = [f"# Platform check: {facts['os']} {facts['arch']}: {verdict.value}", ""]
    lines += [
        f"- kalkan {doctor.get('kalkan_version', '?')}, "
        f"platform key `{doctor.get('platform', '?')}`",
        f"- CPU: {facts['cpu']} ({facts['cpus']} CPUs)",
        f"- Python {facts['python']}; {facts['git']}; Docker: {facts['docker']}",
        "",
    ]
    if verdict.reasons:
        lines += ["## Problems", ""]
        lines += [f"- {reason}" for reason in verdict.reasons[:MAX_PROBLEM_LINES]]
        lines.append("")

    lines += ["## Steps", "", "| Step | Exit code | Time |", "|---|---|---|"]
    for name, (code, seconds) in steps.items():
        lines.append(f"| {name} | {code} | {seconds // 60} min {seconds % 60} s |")
    lines.append("")

    lines += ["## Tools (kalkan doctor)", "", "| Check | Status | Detail |", "|---|---|---|"]
    for check in doctor.get("checks") or []:
        if not isinstance(check, dict):
            continue
        detail = str(check.get("detail", "")).replace("|", "/")[:160]
        lines.append(f"| {check.get('name')} | {check.get('status')} | {detail} |")
    lines.append("")

    lines += [
        "## Tests",
        "",
        "| Suite | Tests | Failed | Errors | Skipped |",
        "|---|---|---|---|---|",
    ]
    for label, result in (("tool tests (-m tools)", tools), ("Docker tests (-m docker)", docker)):
        if result.ran:
            lines.append(
                f"| {label} | {result.tests} | {result.failures} | {result.errors} "
                f"| {result.skipped} |"
            )
        else:
            lines.append(f"| {label} | not run | | | |")
    problems = tools.problems + docker.problems
    if problems:
        lines += ["", "```"] + problems[:MAX_PROBLEM_LINES] + ["```"]
    lines.append("")

    engines = bench.get("engines") or {}
    fixture = (bench.get("fixture") or {}).get("engines") or {}
    ref_fixture = (reference.get("fixture") or {}).get("engines") or {}
    ref_engines = reference.get("engines") or {}
    lines += [
        "## Engines on the vulnapp fixture",
        "",
        "Found: planted items found / expected. Reference: the committed Windows 11 result "
        "(`benchmarks/results/vulnapp.json`).",
        "",
        "| Engine | Status | Candidates | Found | Reference found | Reference candidates |",
        "|---|---|---|---|---|---|",
    ]
    for engine, info in sorted(engines.items()):
        info = info or {}
        ref = ref_engines.get(engine) or {}
        lines.append(
            f"| {engine} | {info.get('status')} | {_count(info)} "
            f"| {_recall(fixture, engine)} | {_recall(ref_fixture, engine)} "
            f"| {_count(ref)} |"
        )
    overall = (bench.get("fixture") or {}).get("overall") or {}
    if overall:
        lines += [
            "",
            f"Fixture recall: {overall.get('recall_expected_engines')} by the expected engines, "
            f"{overall.get('recall_any_engine')} by any engine. Missed by the expected engines: "
            f"{', '.join(overall.get('missed') or []) or 'none'}.",
        ]
    lines += ["", f"Verdict: **{verdict.value}**", ""]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1 or not Path(args[0]).is_dir():
        print("usage: python scripts/platform_report.py <result folder>", file=sys.stderr)
        return 2
    folder = Path(args[0])
    redact_folder(folder, replacements())
    steps = read_steps(folder / "steps.tsv")
    doctor = read_json(folder / "doctor.json")
    tools = read_junit(folder / "tools-junit.xml")
    docker = read_junit(folder / "docker-junit.xml")
    bench = read_json(folder / "benchmark" / "vulnapp.json")
    reference = read_json(folder / "reference-vulnapp.json")
    verdict = decide(steps, doctor, tools, docker, bench)
    facts = host_facts()
    text = render(facts, steps, doctor, tools, docker, bench, reference, verdict)
    (folder / "SUMMARY.md").write_text(redact(text, replacements()), encoding="utf-8", newline="\n")
    for reason in verdict.reasons[:MAX_PROBLEM_LINES]:
        print(f"  - {reason}")
    print(f"verdict: {verdict.value}")
    return 0 if verdict.value == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
