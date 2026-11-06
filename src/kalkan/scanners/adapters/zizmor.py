# SPDX-License-Identifier: MIT
"""zizmor: GitHub Actions security audits (ENGINE-SPEC 13, ADR-0005).

Contract:

1. **Applies** when the target has a GitHub Actions workflow (``.github/workflows/*.yml`` or
   ``*.yaml``), an action definition (``action.yml`` or ``action.yaml`` in any folder) or a
   Dependabot file (``.github/dependabot.yml``): the inputs that zizmor collects. Otherwise the
   adapter is skipped with the reason ``no GitHub Actions workflow, action or Dependabot file``.
2. **Command line**, checked against ``zizmor --help`` of the pinned 1.30.1 on 2026-10-25,
   working directory ``scans/``, SARIF on stdout::

       zizmor --offline --no-config --no-ignores --collect=all --persona=regular
           --format=sarif --color=never <target>

   - ``--offline``: zizmor makes no request. 1.30.1 then drops any GitHub token, starts no
     GitHub client and skips the online audits (``impostor-commit``, ``known-vulnerable-actions``,
     ``ref-confusion``, ``ref-version-mismatch``, ``stale-action-refs``) and remote inputs. The
     flag stays in ``--online`` mode too: the online audits need a GitHub token, and kalkan
     gives no token to a tool.
   - ``--no-config``: no ``zizmor.yml`` is loaded. zizmor looks for one in the input folder, in
     ``.github`` and in every parent folder up to the file system root or a ``.git`` folder, so
     without the flag a file outside the target could change the audit too.
   - ``--no-ignores``: ``# zizmor: ignore[...]`` comments and the ``ignore`` rules of a
     configuration file do not hide results (ADR-0003).
   - ``--collect=all``: workflows, actions, Dependabot and pre-commit files, and ``.gitignore``
     files are not honored. With the default ``--collect=default`` a ``.gitignore`` of the target
     could hide its workflows, and the ``.gitignore`` of a repository that holds the runs folder
     (``runs/`` of a kalkan checkout) would hide every file.
   - ``--persona=regular``: zizmor's default persona, written out. ``pedantic`` adds code smells
     and ``auditor`` adds findings that zizmor itself calls likely false positives; the agent
     layer reads the workflows anyway.
   - ``--format=sarif``: SARIF 2.1.0 on stdout; zizmor then exits with 0 also when it finds
     something (1.30.1 ``main.rs``). ``--color=never`` keeps escape codes out of the stderr log
     and turns off the progress bar.
   - ``--fix`` is never passed: zizmor would rewrite the workflows.
3. **Environment**: the minimal tool environment only (ENGINE-SPEC 13.1). ``GH_TOKEN``,
   ``GITHUB_TOKEN``, ``ZIZMOR_GITHUB_TOKEN``, ``GH_HOST``, ``ZIZMOR_CONFIG`` and
   ``ZIZMOR_OFFLINE`` of the user never reach zizmor.
4. **Output**: :meth:`ZizmorAdapter.after_run` rewrites the SARIF of zizmor in place (zizmor
   writes no CWE and no ``shortDescription``):

   - URIs become target-relative (:func:`kalkan.scanners.adapters._cicd.target_path`): zizmor
     writes them relative to the git repository that holds the input, for example
     ``runs/<run-id>/target/.github/workflows/ci.yml`` inside a kalkan checkout.
   - Each rule gets ``shortDescription`` (zizmor's audit description), the CWE tags and the
     property ``kalkan-class`` of :data:`RULES`.
   - Each result gets ``severity`` and ``confidence`` from ``zizmor/severity`` and
     ``zizmor/confidence`` (``Informational`` becomes ``info``).
5. **Suppressions** (ADR-0003): by default ``--no-ignores`` and ``--no-config``. With
   ``honor_suppressions`` both are left out, and ``--config`` names the first of
   ``.github/zizmor.yml``, ``.github/zizmor.yaml``, ``zizmor.yml``, ``zizmor.yaml`` of the target
   root (else ``--no-config``, so that no file outside the target is loaded). zizmor drops the
   results that it ignores; no zizmor suppression source stays on in the default mode.
6. **Rules and classes** (:data:`RULES`; rule IDs are ``zizmor/<audit>``): ``template-injection``
   is ``code-injection`` (CWE-94): the expression expands into the script source before the shell
   or ``actions/github-script`` runs it, as CodeQL's ``actions/code-injection`` queries (CWE-94)
   rate it. ``github-env`` and ``insecure-commands`` are ``os-command-injection`` (CWE-77, as
   CodeQL's ``actions/envvar-injection``): attacker data in ``GITHUB_ENV`` or workflow commands
   sets variables such as ``BASH_ENV`` for later steps. ``hardcoded-container-credentials`` is
   ``hardcoded-secrets`` (CWE-798), ``unredacted-secrets`` is ``sensitive-data-exposure``
   (CWE-532). The style audits of the pedantic persona are ``code-quality``. Every other audit
   is ``supply-chain-cicd``, with the CWE of the table. An audit that the table does not know is
   ``supply-chain-cicd`` without a CWE.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Final

from kalkan.errors import ToolError
from kalkan.scanners.adapters import _cicd
from kalkan.scanners.adapters._cicd import RuleClass
from kalkan.scanners.base import Invocation, ScanContext, ToolAdapter
from kalkan.util.safe_io import atomic_write_json, read_bounded

__all__ = ["CONFIG_NAMES", "RULES", "ZizmorAdapter", "rewrite_sarif"]

#: The configuration files of the target root that ``honor_suppressions`` passes, in zizmor's
#: discovery order.
CONFIG_NAMES: Final = (".github/zizmor.yml", ".github/zizmor.yaml", "zizmor.yml", "zizmor.yaml")
MAX_SARIF_BYTES: Final = 50 * 1024 * 1024
_SCI: Final = "supply-chain-cicd"
#: zizmor audit to kalkan class and CWE IDs (module docstring, point 6).
RULES: Final[dict[str, RuleClass]] = {
    "template-injection": RuleClass("code-injection", ("CWE-94",)),
    "github-env": RuleClass("os-command-injection", ("CWE-77",)),
    "insecure-commands": RuleClass("os-command-injection", ("CWE-77",)),
    "hardcoded-container-credentials": RuleClass("hardcoded-secrets", ("CWE-798",)),
    "unredacted-secrets": RuleClass("sensitive-data-exposure", ("CWE-532",)),
    "artipacked": RuleClass(_SCI, ("CWE-522",)),
    "cache-poisoning": RuleClass(_SCI, ("CWE-349",)),
    "dangerous-triggers": RuleClass(_SCI, ("CWE-829",)),
    "unpinned-uses": RuleClass(_SCI, ("CWE-829",)),
    "unpinned-images": RuleClass(_SCI, ("CWE-829",)),
    "unpinned-tools": RuleClass(_SCI, ("CWE-494",)),
    "adhoc-packages": RuleClass(_SCI, ("CWE-494",)),
    "impostor-commit": RuleClass(_SCI, ("CWE-829",)),
    "ref-confusion": RuleClass(_SCI, ("CWE-829",)),
    "ref-version-mismatch": RuleClass(_SCI, ("CWE-829",)),
    "stale-action-refs": RuleClass(_SCI, ("CWE-829",)),
    "typosquat-uses": RuleClass(_SCI, ("CWE-829",)),
    "forbidden-uses": RuleClass(_SCI, ("CWE-829",)),
    "dependabot-execution": RuleClass(_SCI, ("CWE-829",)),
    "archived-uses": RuleClass(_SCI, ("CWE-1104",)),
    "known-vulnerable-actions": RuleClass(_SCI, ("CWE-1395",)),
    "dependabot-cooldown": RuleClass(_SCI, ("CWE-1357",)),
    "excessive-permissions": RuleClass(_SCI, ("CWE-250",)),
    "overprovisioned-secrets": RuleClass(_SCI, ("CWE-250",)),
    "secrets-inherit": RuleClass(_SCI, ("CWE-250",)),
    "secrets-outside-env": RuleClass(_SCI, ("CWE-250",)),
    "github-app": RuleClass(_SCI, ("CWE-250",)),
    "bot-conditions": RuleClass(_SCI, ("CWE-290",)),
    "unsound-condition": RuleClass(_SCI, ("CWE-670",)),
    "unsound-ternary": RuleClass(_SCI, ("CWE-670",)),
    "unsound-contains": RuleClass(_SCI, ("CWE-697",)),
    "insecure-url-scheme": RuleClass(_SCI, ("CWE-319",)),
    "self-hosted-runner": RuleClass(_SCI),
    "use-trusted-publishing": RuleClass(_SCI),
    "misfeature": RuleClass(_SCI),
    "obfuscation": RuleClass(_SCI),
    "anonymous-definition": RuleClass("code-quality"),
    "concurrency-limits": RuleClass("code-quality"),
    "self-repository": RuleClass("code-quality"),
    "superfluous-actions": RuleClass("code-quality"),
    "undocumented-permissions": RuleClass("code-quality"),
}
_PREFIX: Final = "zizmor/"
_LABELS: Final = {"informational": "info", "low": "low", "medium": "medium", "high": "high"}
_CONFIDENCE: Final = {"low": "low", "medium": "medium", "high": "high"}


def rule_class(rule_id: str) -> RuleClass:
    """Return the class of a zizmor rule ID (``zizmor/<audit>`` or the bare audit name)."""
    audit = rule_id[len(_PREFIX) :] if rule_id.startswith(_PREFIX) else rule_id
    return RULES.get(audit, RuleClass(_SCI))


def rewrite_sarif(doc: Any, target: Path) -> dict[str, Any]:
    """Return the zizmor SARIF ``doc`` with kalkan's additions (module docstring, point 4).

    Raises :class:`~kalkan.errors.ToolError` when ``doc`` is not a SARIF 2.1.0 document.
    """
    if not isinstance(doc, dict) or doc.get("version") != "2.1.0":
        raise ToolError("zizmor did not write a SARIF 2.1.0 document")
    runs = doc.get("runs")
    if not isinstance(runs, list):
        raise ToolError("the zizmor SARIF has no runs")
    for run in runs:
        if not isinstance(run, dict):
            continue
        driver = (run.get("tool") or {}).get("driver") or {}
        for rule in driver.get("rules") or []:
            if not isinstance(rule, dict):
                continue
            item = rule_class(str(rule.get("id", "")))
            help_block = rule.get("help")
            help_text = help_block.get("text") if isinstance(help_block, dict) else None
            if isinstance(help_text, str) and help_text and "shortDescription" not in rule:
                rule["shortDescription"] = {"text": help_text}
            properties = rule.setdefault("properties", {})
            if isinstance(properties, dict):
                extra = [t for t in properties.get("tags") or [] if isinstance(t, str)]
                properties.update(_cicd.rule_properties(item, tuple(extra)))
        for result in run.get("results") or []:
            if isinstance(result, dict):
                _rewrite_result(result, target)
    return doc


def _rewrite_result(result: dict[str, Any], target: Path) -> None:
    properties = result.setdefault("properties", {})
    if isinstance(properties, dict):
        severity = str(properties.get("zizmor/severity") or "").lower()
        confidence = str(properties.get("zizmor/confidence") or "").lower()
        if severity in _LABELS:
            properties["severity"] = _LABELS[severity]
        if confidence in _CONFIDENCE:
            properties["confidence"] = _CONFIDENCE[confidence]
    for key in ("locations", "relatedLocations"):
        for location in result.get(key) or []:
            _fix_location(location, target)
    for flow in result.get("codeFlows") or []:
        for thread in (flow or {}).get("threadFlows") or []:
            for step in (thread or {}).get("locations") or []:
                if isinstance(step, dict):
                    _fix_location(step.get("location"), target)


def _fix_location(location: Any, target: Path) -> None:
    if not isinstance(location, dict):
        return
    physical = location.get("physicalLocation")
    if not isinstance(physical, dict):
        return
    artifact = physical.get("artifactLocation")
    if isinstance(artifact, dict) and isinstance(artifact.get("uri"), str):
        artifact["uri"] = _cicd.target_path(artifact["uri"], target)


class ZizmorAdapter(ToolAdapter):
    """``zizmor --offline --format=sarif`` over the target (module docstring)."""

    name = "zizmor"
    tool = "zizmor"
    output = "sarif-stdout"
    output_dir = "scans"
    output_name = "zizmor.sarif"
    ok_exit_codes = (0,)
    timeout_seconds = 600

    def applies(self, ctx: ScanContext) -> tuple[bool, str]:
        files = _cicd.ci_files(ctx.target_dir)
        if files.workflows or files.actions or files.dependabot:
            return True, ""
        return False, "no GitHub Actions workflow, action or Dependabot file in the target"

    @staticmethod
    def target_config(ctx: ScanContext) -> Path | None:
        """Return the zizmor configuration file of the target root, or None."""
        for name in CONFIG_NAMES:
            path = ctx.target_dir / name
            if path.is_file() and not path.is_symlink():
                return path
        return None

    def arguments(self, ctx: ScanContext, out: Path) -> list[str]:
        args = ["--offline"]
        if ctx.honor_suppressions:
            config = self.target_config(ctx)
            args += ["--config", str(config)] if config is not None else ["--no-config"]
        else:
            args += ["--no-config", "--no-ignores"]
        args += ["--collect=all", "--persona=regular", "--format=sarif", "--color=never"]
        return [*args, str(ctx.target_dir)]

    def suppression_sources(self, ctx: ScanContext) -> tuple[list[str], list[str]]:
        comments = "# zizmor: ignore[...] comments"
        if not ctx.honor_suppressions:
            return [
                f"{comments} and the ignore rules of zizmor.yml (--no-ignores)",
                "zizmor.yml of the target and of its parent folders (--no-config)",
                ".gitignore files (--collect=all)",
            ], []
        config = self.target_config(ctx)
        honored = [comments]
        if config is not None:
            name = config.relative_to(ctx.target_dir).as_posix()
            honored.append(f"{name} of the target root (--config)")
        return [".gitignore files (--collect=all)"], honored

    def after_run(self, ctx: ScanContext, item: Invocation) -> None:
        """Rewrite the SARIF on stdout in place (module docstring, point 4)."""
        try:
            doc = json.loads(read_bounded(item.output, MAX_SARIF_BYTES))
        except ValueError as exc:
            raise ToolError(f"zizmor did not write valid JSON: {exc}") from None
        atomic_write_json(item.output, rewrite_sarif(doc, ctx.target_dir))
