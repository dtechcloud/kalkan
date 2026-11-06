# SPDX-License-Identifier: MIT
"""poutine: supply chain checks of CI pipelines (ENGINE-SPEC 13, ADR-0005).

poutine reads GitHub Actions workflows and action definitions, GitLab CI, Azure Pipelines and
Tekton (Pipelines as Code) files. kalkan builds it from source (manifest kind ``go-install``):
the v1.1.6 release ships no Windows binary.

Contract:

1. **Applies** when the target has a file that poutine 1.1.6 reads, by its own path patterns
   (``scanner/parsers.go``): ``.github/workflows/*.yml``, ``action.yml`` in any folder,
   ``*gitlab-ci*.yml``, ``*azure-pipelines*.yml``, ``.tekton/*.yml`` (``.yaml`` too).
   **Windows:** poutine 1.1.6 matches the relative path of each file with ``/`` patterns, and Go
   writes these paths with ``\\`` on Windows. So on Windows it reads only GitLab CI and Azure
   Pipelines files and an ``action.yml`` in the target root; GitHub workflows, other action
   definitions and Tekton files are invisible to it (checked on 2026-10-25: no finding and no
   dependency for the GitHub workflows of the vulnapp fixture, the injection of its
   ``azure-pipelines.yml`` found). The adapter is then skipped when the target has no file that
   poutine can read there, and :meth:`PoutineAdapter.status_details` lists the invisible files
   as ``platform_gap``. zizmor and actionlint check the GitHub workflows on every platform.
2. **Command line**, checked against ``poutine analyze_local --help`` of the built 1.1.6 on
   2026-10-25, working directory ``scans/``, JSON on stdout::

       poutine analyze_local <target> --format json --quiet --disable-version-check
           --config <run>/scans/.work/poutine/poutine.yml

   - ``analyze_local``: the local folder mode. It walks the folder and evaluates the built-in
     Rego rules; the rule engine has no network capability (``opa/capabilities.json``:
     ``allow_net`` empty, no ``http.send``). The data of the ``known_vulnerability_*`` rules is
     built in.
   - ``--format json``: findings with ``meta`` (path, line, job, step, details, injection sources,
     event triggers, OSV ID) and the rule table. The SARIF format of poutine drops ``meta``
     (its message is only the rule description), so :meth:`after_run` converts the JSON to SARIF.
   - ``--quiet``: no progress bar on stderr.
   - ``--disable-version-check`` and the environment ``POUTINE_DISABLE_VERSION_CHECK=1``: every
     poutine command except ``mcp-server`` and ``completion`` otherwise sends a version check
     with an anonymous instance ID to ``version-check.cicd.fun`` once a day and writes
     ``~/.poutine/config.yaml`` (``versioncheck/``; seen by the proxy trap on 2026-10-25).
   - ``--config``: an empty kalkan file. poutine otherwise loads ``.poutine.yml`` or
     ``.github/poutine.yml`` of its working directory.
   - Exit code 0 (``--fail-on-violation`` is not passed).
3. **Environment**: the minimal tool environment plus ``POUTINE_DISABLE_VERSION_CHECK=1``. No
   SCM token reaches poutine (``analyze_local`` needs none).
4. **Output and classes** (:data:`RULES`; rule IDs are poutine's ``rule_id``): ``injection`` is
   ``code-injection`` (CWE-94; a GitHub expression, an Azure Pipelines macro or a Tekton template
   that expands into a script). Every other rule is ``supply-chain-cicd`` with the CWE of the
   table. The severity follows the rule level of poutine: ``error`` high, ``warning`` medium,
   ``note`` low. The message is the rule title, then ``details`` (for example ``Sources:
   github.event.issue.title``), the job and the step. A finding without a path
   (``known_vulnerability_in_build_platform``) has no location: the repository.
5. **Suppressions** (ADR-0003): poutine has no inline ignore comment. The ``skip`` rules of a
   ``.poutine.yml`` of the target are never applied, also with ``honor_suppressions``: the same
   file can name ``include`` paths with Rego policy code that poutine loads, and kalkan cannot
   apply ``skip`` alone. ``--skip`` and ``--allowed-rules`` are not passed.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Final

from kalkan.errors import ToolError
from kalkan.scanners.adapters import _cicd
from kalkan.scanners.adapters._cicd import RuleClass
from kalkan.scanners.base import Invocation, ScanContext, ToolAdapter
from kalkan.util.safe_io import atomic_write_json, atomic_write_text, read_bounded

__all__ = ["RULES", "PoutineAdapter", "platform_gap_files", "report_to_sarif"]

MAX_REPORT_BYTES: Final = 50 * 1024 * 1024
#: The empty configuration file in the work folder.
CONFIG_FILENAME: Final = "poutine.yml"
#: At most this many invisible files in ``platform_gap``.
MAX_GAP_FILES: Final = 50
_SCI: Final = "supply-chain-cicd"
#: poutine rule to kalkan class and CWE IDs (module docstring, point 4).
RULES: Final[dict[str, RuleClass]] = {
    "injection": RuleClass("code-injection", ("CWE-94",)),
    "untrusted_checkout_exec": RuleClass(_SCI, ("CWE-829",)),
    "pr_runs_on_self_hosted": RuleClass(_SCI, ("CWE-829",)),
    "unpinnable_action": RuleClass(_SCI, ("CWE-829",)),
    "unverified_script_exec": RuleClass(_SCI, ("CWE-494",)),
    "confused_deputy_auto_merge": RuleClass(_SCI, ("CWE-441",)),
    "debug_enabled": RuleClass(_SCI, ("CWE-489",)),
    "default_permissions_on_risky_events": RuleClass(_SCI, ("CWE-250",)),
    "job_all_secrets": RuleClass(_SCI, ("CWE-250",)),
    "github_action_from_unverified_creator_used": RuleClass(_SCI, ("CWE-1357",)),
    "if_always_true": RuleClass(_SCI, ("CWE-670",)),
    "known_vulnerability_in_build_component": RuleClass(_SCI, ("CWE-1395",)),
    "known_vulnerability_in_build_platform": RuleClass(_SCI, ("CWE-1395",)),
}
_SEVERITY: Final = {"error": "high", "warning": "medium", "note": "low"}
_EMPTY_CONFIG: Final = "# kalkan: an empty poutine configuration (no skip, include or rules).\n"
#: Files that poutine 1.1.6 reads on Windows: its patterns without a ``/`` anchor.
_WINDOWS_READABLE: Final = (
    _cicd.GITLAB_CI,
    _cicd.AZURE_PIPELINES,
    re.compile(r"^action\.ya?ml$"),
)


def rule_class(rule_id: str) -> RuleClass:
    """Return the class of a poutine rule (``supply-chain-cicd`` for an unknown rule)."""
    return RULES.get(rule_id, RuleClass(_SCI))


def poutine_files(target: Path) -> list[str]:
    """Return the files of ``target`` that poutine 1.1.6 reads on Linux and macOS."""
    files = _cicd.ci_files(target)
    found = [*files.workflows, *files.actions, *files.gitlab, *files.azure, *files.tekton]
    return sorted(set(found))


def platform_gap_files(files: list[str], *, windows: bool | None = None) -> list[str]:
    """Return the files that poutine 1.1.6 cannot read on Windows (module docstring, point 1)."""
    if not (_cicd.on_windows() if windows is None else windows):
        return []
    return [rel for rel in files if not any(p.search(rel) for p in _WINDOWS_READABLE)]


def report_to_sarif(report: Any, target: Path, *, version: str = "") -> dict[str, Any]:
    """Convert the JSON report of ``poutine analyze_local --format json`` to SARIF 2.1.0.

    Raises :class:`~kalkan.errors.ToolError` for a report without a ``findings`` list.
    """
    if not isinstance(report, dict) or not isinstance(report.get("findings"), list):
        raise ToolError("the poutine report has no findings list")
    table = report.get("rules") if isinstance(report.get("rules"), dict) else {}
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for finding in report["findings"]:
        if not isinstance(finding, dict):
            continue
        rule_id = str(finding.get("rule_id") or "").strip()
        if not rule_id:
            continue
        info = table.get(rule_id) if isinstance(table.get(rule_id), dict) else {}
        title = str(info.get("title") or rule_id)
        level = str(info.get("level") or "warning")
        if rule_id not in rules:
            refs = [r.get("ref") for r in info.get("refs") or [] if isinstance(r, dict)]
            rules[rule_id] = _cicd.sarif_rule(
                rule_id,
                rule_class(rule_id),
                title=title,
                description=str(info.get("description") or ""),
                help_uri=next(
                    (ref for ref in refs if isinstance(ref, str) and ref.startswith("https://")),
                    f"https://boostsecurityio.github.io/poutine/rules/{rule_id}",
                ),
            )
        meta = finding.get("meta") if isinstance(finding.get("meta"), dict) else {}
        line = meta.get("line")
        results.append(
            _cicd.sarif_result(
                rule_id,
                _message(title, meta),
                level=level if level in _SEVERITY else "warning",
                file=_cicd.target_path(meta.get("path"), target),
                start_line=line if isinstance(line, int) and line > 0 else None,
                properties=_properties(finding, meta, level),
            )
        )
    return _cicd.sarif_document(
        "poutine",
        version,
        "https://github.com/boostsecurityio/poutine",
        list(rules.values()),
        results,
    )


def _message(title: str, meta: dict[str, Any]) -> str:
    text = title
    details = str(meta.get("details") or "").strip()
    if details:
        text += f". {details}"
    where = [f"{key} {meta[key]}" for key in ("job", "step") if str(meta.get(key) or "").strip()]
    if where:
        text += f" ({', '.join(where)})"
    return text


def _properties(finding: dict[str, Any], meta: dict[str, Any], level: str) -> dict[str, Any]:
    properties: dict[str, Any] = {"severity": _SEVERITY.get(level, "medium")}
    for key in (
        "job",
        "step",
        "osv_id",
        "injection_sources",
        "event_triggers",
        "lotp_tool",
        "lotp_action",
        "lotp_targets",
        "referenced_secrets",
    ):
        value = meta.get(key)
        if value not in (None, "", []):
            properties[f"poutine/{key}"] = value
    purl = finding.get("purl")
    if isinstance(purl, str) and purl.startswith("pkg:") and not purl.startswith("pkg:localrepo"):
        properties["poutine/purl"] = purl
    return properties


class PoutineAdapter(ToolAdapter):
    """``poutine analyze_local --format json`` over the target (module docstring)."""

    name = "poutine"
    tool = "poutine"
    output = "sarif-stdout"
    output_dir = "scans"
    output_name = "poutine.sarif"
    ok_exit_codes = (0,)
    timeout_seconds = 600

    def applies(self, ctx: ScanContext) -> tuple[bool, str]:
        files = poutine_files(ctx.target_dir)
        if not files:
            return False, (
                "no CI file that poutine reads (GitHub Actions, GitLab CI, Azure Pipelines, "
                "Tekton) in the target"
            )
        if len(platform_gap_files(files)) == len(files):
            return False, (
                "poutine 1.1.6 on Windows reads only GitLab CI, Azure Pipelines and a root "
                "action.yml (it matches the other paths with '/'), and the target has none; "
                "zizmor and actionlint check the GitHub workflows"
            )
        return True, ""

    def arguments(self, ctx: ScanContext, out: Path) -> list[str]:
        return [
            "analyze_local",
            str(ctx.target_dir),
            "--format",
            "json",
            "--quiet",
            "--disable-version-check",
            "--config",
            str(out.parent / CONFIG_FILENAME),
        ]

    def env(self, ctx: ScanContext) -> dict[str, str]:
        return {"POUTINE_DISABLE_VERSION_CHECK": "1"}

    def prepare(self, ctx: ScanContext, stage: Path) -> None:
        """Write the empty kalkan configuration file next to the staged output."""
        atomic_write_text(stage.parent / CONFIG_FILENAME, _EMPTY_CONFIG)

    def suppression_sources(self, ctx: ScanContext) -> tuple[list[str], list[str]]:
        return [
            ".poutine.yml and .github/poutine.yml of the target: never loaded, also with "
            "--honor-suppressions (their include entries load Rego policy code)"
        ], []

    def status_details(
        self, ctx: ScanContext, stdout_log: Path, stderr_log: Path, outputs: list[Path]
    ) -> dict[str, Any]:
        """Return ``platform_gap`` on Windows: the files that poutine cannot read there."""
        gap = platform_gap_files(poutine_files(ctx.target_dir))
        if not gap:
            return {}
        return {
            "platform_gap": {
                "count": len(gap),
                "files": gap[:MAX_GAP_FILES],
                "truncated": len(gap) > MAX_GAP_FILES,
                "reason": (
                    "poutine 1.1.6 on Windows matches file paths with '/' patterns and Go "
                    "writes them with '\\': GitHub workflows, action definitions outside the "
                    "root and Tekton files are not analyzed. zizmor and actionlint check the "
                    "GitHub workflows."
                ),
            }
        }

    def after_run(self, ctx: ScanContext, item: Invocation) -> None:
        """Convert the JSON report on stdout to SARIF in place (module docstring, point 4)."""
        raw = read_bounded(item.output, MAX_REPORT_BYTES).decode("utf-8", errors="replace")
        try:
            report = json.loads(raw)
        except ValueError as exc:
            raise ToolError(f"poutine did not write a JSON report: {exc}") from None
        atomic_write_json(item.output, report_to_sarif(report, ctx.target_dir))
