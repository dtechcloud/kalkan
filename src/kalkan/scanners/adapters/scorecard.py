# SPDX-License-Identifier: MIT
"""OpenSSF Scorecard in local mode: repository security posture (ENGINE-SPEC 13, ADR-0005).

Contract:

1. **Applies** to every target with at least one file: the posture checks (security policy,
   license, dependency update tool, binary artifacts) concern any repository.
2. **Command line**, checked against ``scorecard --help`` of the pinned 5.5.0 on 2026-10-25,
   working directory ``scans/``::

       scorecard --local <target> --checks Binary-Artifacts,Dangerous-Workflow,
           Dependency-Update-Tool,License,Security-Policy,Token-Permissions
           --format json --show-details --output <run>/scans/.work/scorecard/scorecard.json

   - ``--local``: the file-based client (``clients/localdir``). It walks the folder (no git, no
     ``.gitignore``) and has no GitHub, GitLab or Azure DevOps client.
   - ``--checks`` (:data:`CHECKS`): the checks that read files only. Measured with the proxy
     trap on 2026-10-25 (vulnapp fixture): these six made zero connections. Left out
     (:data:`CHECKS_NOT_RUN`): ``Pinned-Dependencies`` asks the container registry
     (``crane.Digest``, ``index.docker.io``) for the digest of every unpinned image to write its
     remediation text, with the Docker credential helpers of the user, and no option turns that
     off (6 connections); ``Vulnerabilities`` asks ``api.osv.dev`` and ``api.deps.dev``;
     ``Fuzzing`` downloads the OSS-Fuzz project list; ``SAST`` needs the pull request history
     (in local mode it always reports "no pull requests merged into dev branch");
     ``Packaging`` needs successful workflow runs from the API and is inconclusive locally. The
     other checks do not support local mode. zizmor, poutine, Hadolint and the kalkan matchers
     cover action and image pinning instead of ``Pinned-Dependencies``.
   - ``--format json --show-details``: the JSON v2 format with the detail lines of each check.
     ``--output`` writes it to a file (logs stay on stderr). Exit code 0; Scorecard exits with 1
     only when a check has a runtime error.
   - Not passed: ``--show-annotations`` (the maintainer annotations of a ``scorecard.yml`` of the
     target never change a score), ``--policy`` and the SARIF format (it needs
     ``ENABLE_SARIF``).
3. **Environment**: the minimal tool environment. No ``GITHUB_AUTH_TOKEN``, ``GITHUB_TOKEN``,
   ``GITLAB_AUTH_TOKEN``, ``ENABLE_SARIF``, ``SCORECARD_EXPERIMENTAL`` or ``SCORECARD_V6``.
4. **Candidates** (:func:`report_to_sarif`): for each check with a score from 0 to 9, every
   ``Warn:`` detail line with a file of the target becomes one result at that file and line
   (the detail format is ``Warn: <text>: <path>:<line>[-<end>][: <remediation>]``; the path is
   the first ``: ``-separated part that names a file of the target). The ``Warn:`` lines of a
   check without a file (no security policy, no license, no dependency update tool) become one
   result without a location: the repository root. ``Info:`` lines, passing checks (10) and
   inconclusive checks (-1) give no result.
5. **Severity and classes** (:data:`CHECK_RULES`): one step below the risk that Scorecard gives
   the check, because Scorecard measures posture, not a proven flaw: ``Dangerous-Workflow``
   (critical) high; ``Binary-Artifacts``, ``Token-Permissions``, ``Dependency-Update-Tool``
   (high) medium; ``Security-Policy`` (medium) low; ``License`` (low) info. Classes:
   ``Dangerous-Workflow`` results whose text starts with ``script injection`` are
   ``code-injection`` (CWE-94), its other results (untrusted code checkout) ``supply-chain-cicd``
   (CWE-829); ``Token-Permissions`` ``supply-chain-cicd`` (CWE-250); ``Binary-Artifacts``,
   ``Dependency-Update-Tool`` and ``Security-Policy`` ``supply-chain-cicd``; ``License``
   ``code-quality``.
6. **Status file** (:meth:`ScorecardAdapter.status_details`): ``scores`` (name, score, reason and
   documentation of each check that ran) and ``checks_not_run`` (check to reason), for the
   report. **Windows:** Scorecard 5.5.0 lists the files of ``--local`` with ``\\`` and compares
   them with ``/`` paths, so ``Dangerous-Workflow`` and ``Token-Permissions`` find no workflow
   ("no workflows found", score -1; checked on 2026-10-25). The status file then records
   ``platform_gap`` with the workflows of the target; zizmor and actionlint check them.
7. **Suppressions** (ADR-0003): Scorecard has no inline or configuration suppression: the
   annotations of a ``scorecard.yml`` explain results but never change them, and kalkan does not
   request them.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Final

from kalkan.errors import KalkanError, ToolError
from kalkan.scanners.adapters import _cicd
from kalkan.scanners.adapters._cicd import RuleClass
from kalkan.scanners.base import Invocation, ScanContext, ToolAdapter
from kalkan.util.safe_io import atomic_write_json, read_bounded

__all__ = [
    "CHECKS",
    "CHECKS_NOT_RUN",
    "CHECK_RULES",
    "ScorecardAdapter",
    "json_report_path",
    "parse_detail",
    "report_to_sarif",
]

#: The checks that kalkan runs (module docstring, point 2), in Scorecard's order.
CHECKS: Final = (
    "Binary-Artifacts",
    "Dangerous-Workflow",
    "Dependency-Update-Tool",
    "License",
    "Security-Policy",
    "Token-Permissions",
)
#: The local-mode checks that kalkan leaves out, and why (module docstring, point 2).
CHECKS_NOT_RUN: Final = {
    "Pinned-Dependencies": (
        "asks the container registry (crane.Digest) for the digest of every unpinned image"
    ),
    "Vulnerabilities": "queries api.osv.dev and api.deps.dev",
    "Fuzzing": "downloads the OSS-Fuzz project list",
    "SAST": "needs the pull request history; local mode always reports a failure",
    "Packaging": "needs successful workflow runs from the API; inconclusive in local mode",
}
_SCI: Final = "supply-chain-cicd"
#: Check name to (class, CWE IDs, severity) (module docstring, point 5).
CHECK_RULES: Final[dict[str, tuple[RuleClass, str]]] = {
    "Dangerous-Workflow": (RuleClass(_SCI, ("CWE-829",)), "high"),
    "Binary-Artifacts": (RuleClass(_SCI), "medium"),
    "Token-Permissions": (RuleClass(_SCI, ("CWE-250",)), "medium"),
    "Dependency-Update-Tool": (RuleClass(_SCI), "medium"),
    "Security-Policy": (RuleClass(_SCI), "low"),
    "License": (RuleClass("code-quality"), "info"),
}
_SCRIPT_INJECTION: Final = RuleClass("code-injection", ("CWE-94",))
#: Checks that read the workflows; Windows cannot see them (module docstring, point 6).
WORKFLOW_CHECKS: Final = ("Dangerous-Workflow", "Token-Permissions")
MAX_REPORT_BYTES: Final = 50 * 1024 * 1024
MAX_GAP_FILES: Final = 50
_LEVELS: Final = {"high": "error", "medium": "warning", "low": "note", "info": "note"}
_DETAIL: Final = re.compile(r"^(Warn|Info|Debug):\s*(.*)$", re.DOTALL)
_LOCATION: Final = re.compile(r"^(?P<path>.+?)(?::(?P<line>[0-9]+)(?:-(?P<end>[0-9]+))?)?$")


def json_report_path(sarif_part: Path) -> Path:
    """Return the path of the Scorecard JSON report that belongs to the staged SARIF output."""
    return sarif_part.with_suffix(".json")


def parse_detail(text: str, target: Path) -> dict[str, Any] | None:
    """Parse one ``Warn:`` detail line; return None for other lines.

    Returns ``{text, file, start_line, end_line, remediation}``: ``file`` is ``""`` when no part
    of the line names a file of the target (module docstring, point 4).
    """
    match = _DETAIL.match(text.strip())
    if match is None or match.group(1) != "Warn":
        return None
    parts = match.group(2).split(": ")
    for index in range(1, len(parts)):
        location = _LOCATION.match(parts[index].strip())
        if location is None:
            continue
        rel = _cicd.target_path(location.group("path"), target)
        if not rel or not (target / rel).is_file():
            continue
        start = int(location.group("line")) if location.group("line") else None
        end = int(location.group("end")) if location.group("end") else start
        return {
            "text": ": ".join(parts[:index]).strip(),
            "file": rel,
            "start_line": start,
            "end_line": end,
            "remediation": ": ".join(parts[index + 1 :]).strip(),
        }
    return {
        "text": match.group(2).strip(),
        "file": "",
        "start_line": None,
        "end_line": None,
        "remediation": "",
    }


def check_rule(name: str) -> tuple[RuleClass, str]:
    """Return the class and severity of a Scorecard check (module docstring, point 5)."""
    return CHECK_RULES.get(name, (RuleClass(_SCI), "low"))


def report_to_sarif(report: Any, target: Path) -> dict[str, Any]:
    """Convert the Scorecard JSON v2 report to SARIF 2.1.0 (module docstring, points 4 and 5).

    Raises :class:`~kalkan.errors.ToolError` for a report without a ``checks`` list.
    """
    if not isinstance(report, dict) or not isinstance(report.get("checks"), list):
        raise ToolError("the Scorecard report has no checks list")
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for check in report["checks"]:
        if not isinstance(check, dict):
            continue
        name = str(check.get("name") or "").strip()
        score = check.get("score")
        if not name or not isinstance(score, int) or not 0 <= score < 10:
            continue
        item, severity = check_rule(name)
        reason = str(check.get("reason") or "").strip()
        lines = [d for d in check.get("details") or [] if isinstance(d, str)]
        parsed = [p for p in (parse_detail(line, target) for line in lines) if p is not None]
        if not parsed:
            continue
        documentation = (
            check.get("documentation") if isinstance(check.get("documentation"), dict) else {}
        )
        rules.setdefault(
            name,
            _cicd.sarif_rule(
                name,
                RuleClass(item.vuln_class),
                title=str(documentation.get("short") or f"Scorecard {name}"),
                help_uri=str(documentation.get("url") or ""),
            ),
        )
        common = {"severity": severity, "scorecard/score": score, "scorecard/reason": reason}
        rootless: list[str] = []
        for detail in parsed:
            if not detail["file"]:
                if detail["text"] not in rootless:
                    rootless.append(detail["text"])
                continue
            result_class = item
            if name == "Dangerous-Workflow" and detail["text"].startswith("script injection"):
                result_class = _SCRIPT_INJECTION
            message = f"{name}: {detail['text']}"
            if detail["remediation"]:
                message += f". Remediation: {detail['remediation']}"
            results.append(
                _cicd.sarif_result(
                    name,
                    message,
                    level=_LEVELS[severity],
                    file=detail["file"],
                    start_line=detail["start_line"],
                    end_line=detail["end_line"],
                    properties={**common, **_class_properties(result_class)},
                )
            )
        if rootless:
            message = f"{name}: {reason}" if reason else name
            message += " (repository root). " + "; ".join(rootless)
            properties = {**common, **_class_properties(item), "location": "repository root"}
            results.append(
                _cicd.sarif_result(name, message, level=_LEVELS[severity], properties=properties)
            )
    version = report.get("scorecard") if isinstance(report.get("scorecard"), dict) else {}
    return _cicd.sarif_document(
        "scorecard",
        str(version.get("version") or ""),
        "https://github.com/ossf/scorecard",
        list(rules.values()),
        results,
    )


def _class_properties(item: RuleClass) -> dict[str, Any]:
    tags = [f"external/cwe/{cwe.lower()}" for cwe in item.cwe]
    return {_cicd.CLASS_PROPERTY: item.vuln_class, "tags": tags}


def scores(report: Any) -> list[dict[str, Any]]:
    """Return ``{name, score, reason, documentation}`` of each check of the JSON report."""
    found: list[dict[str, Any]] = []
    checks = report.get("checks") if isinstance(report, dict) else None
    for check in checks if isinstance(checks, list) else []:
        if not isinstance(check, dict) or not isinstance(check.get("name"), str):
            continue
        documentation = (
            check.get("documentation") if isinstance(check.get("documentation"), dict) else {}
        )
        found.append(
            {
                "name": check["name"],
                "score": check.get("score") if isinstance(check.get("score"), int) else None,
                "reason": str(check.get("reason") or ""),
                "documentation": str(documentation.get("url") or ""),
            }
        )
    return sorted(found, key=lambda item: item["name"])


def _has_files(target: Path) -> bool:
    for _dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [name for name in dirnames if name != ".git"]
        if filenames:
            return True
    return False


class ScorecardAdapter(ToolAdapter):
    """``scorecard --local`` with the offline checks (module docstring)."""

    name = "scorecard"
    tool = "scorecard"
    output = "sarif-file"
    output_dir = "scans"
    output_name = "scorecard.sarif"
    ok_exit_codes = (0,)
    timeout_seconds = 600

    def applies(self, ctx: ScanContext) -> tuple[bool, str]:
        if _has_files(ctx.target_dir):
            return True, ""
        return False, "the target has no file"

    def arguments(self, ctx: ScanContext, out: Path) -> list[str]:
        return [
            "--local",
            str(ctx.target_dir),
            "--checks",
            ",".join(CHECKS),
            "--format",
            "json",
            "--show-details",
            "--output",
            str(json_report_path(out)),
        ]

    def suppression_sources(self, ctx: ScanContext) -> tuple[list[str], list[str]]:
        return [
            "maintainer annotations of a scorecard.yml of the target (never change a score; "
            "not requested)"
        ], []

    def status_details(
        self, ctx: ScanContext, stdout_log: Path, stderr_log: Path, outputs: list[Path]
    ) -> dict[str, Any]:
        """Return ``scores``, ``checks_not_run`` and, on Windows, ``platform_gap``."""
        details: dict[str, Any] = {"checks_not_run": dict(CHECKS_NOT_RUN)}
        for output in outputs:
            try:
                report = json.loads(read_bounded(json_report_path(output), MAX_REPORT_BYTES))
            except (KalkanError, OSError, ValueError):
                continue
            details["scores"] = scores(report)
        if _cicd.on_windows():
            workflows = list(_cicd.ci_files(ctx.target_dir).workflows)
            if workflows:
                details["platform_gap"] = {
                    "checks": list(WORKFLOW_CHECKS),
                    "count": len(workflows),
                    "files": workflows[:MAX_GAP_FILES],
                    "truncated": len(workflows) > MAX_GAP_FILES,
                    "reason": (
                        "Scorecard 5.5.0 on Windows lists the files of --local with '\\' and "
                        "compares them with '/' paths: these checks saw no workflow. zizmor and "
                        "actionlint check the workflows."
                    ),
                }
        return details

    def after_run(self, ctx: ScanContext, item: Invocation) -> None:
        """Convert the JSON report to the staged SARIF output (module docstring, point 4)."""
        report_path = json_report_path(item.output)
        if not report_path.is_file():
            raise ToolError(f"no Scorecard report {report_path.name}")
        raw = read_bounded(report_path, MAX_REPORT_BYTES).decode("utf-8", errors="replace")
        try:
            report = json.loads(raw)
        except ValueError as exc:
            raise ToolError(f"the Scorecard report is not valid JSON: {exc}") from None
        atomic_write_json(item.output, report_to_sarif(report, ctx.target_dir))
