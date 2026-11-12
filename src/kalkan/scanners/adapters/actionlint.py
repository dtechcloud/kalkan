# SPDX-License-Identifier: MIT
"""actionlint: GitHub Actions workflow checks (ENGINE-SPEC 13, ADR-0005).

Contract:

1. **Applies** when the target has a GitHub Actions workflow (``.github/workflows/*.yml`` or
   ``*.yaml``); otherwise the adapter is skipped with the reason ``no GitHub Actions workflow``.
2. **Staging.** actionlint takes the project of a workflow from the nearest parent folder that
   holds both ``.github/workflows`` and ``.git``. The target copy has no ``.git``, so actionlint
   would walk up to a repository that holds the run folder (a kalkan checkout) and resolve local
   actions (``uses: ./...``), reusable workflows and its configuration file there.
   :meth:`ActionlintAdapter.prepare` therefore copies the workflows and every ``action.yml`` /
   ``action.yaml`` of the target (regular files of at most 1 MiB) into
   ``scans/.work/actionlint/repo/`` and creates an empty ``.git`` folder there. That folder is
   the working directory and the project; the run removes it after a successful run.
3. **Command line**, checked against ``actionlint -help`` of the pinned 1.7.12 on 2026-10-25::

       actionlint -format "{{json .}}" -no-color -shellcheck= -pyflakes=
           -config-file <run>/scans/.work/actionlint/actionlint.yaml <workflow> [...]

   - The workflows are passed as paths relative to the staging folder
     (``.github/workflows/ci.yml``), so the paths of the report are target-relative. Without file
     arguments actionlint would lint the repository of its working directory.
   - ``-format "{{json .}}"``: one JSON array of errors on stdout (``message``, ``filepath``,
     ``line``, ``column``, ``end_column``, ``kind``, ``snippet``). :meth:`after_run` converts it to
     SARIF.
   - ``-config-file``: an empty kalkan file. It replaces the ``.github/actionlint.yaml`` of the
     project (actionlint 1.7.12 ``linter.go``: "-config-file option has higher priority than
     repository config file"), so the ``paths.<glob>.ignore`` rules of the target cannot hide
     errors (ADR-0003). The staging copy also leaves that file out.
   - ``-shellcheck=``: actionlint starts no ``shellcheck`` of the system. When the manifest pins
     ``shellcheck`` and ``kalkan tools install`` installed it under ``.tools``
     (:func:`shellcheck_path`), the flag names that copy instead; actionlint then runs
     ``shellcheck --norc -f json -x ...`` on each ``run:`` script (``--norc``: no
     ``.shellcheckrc``). ``-pyflakes=``: no ``pyflakes`` (the manifest pins none).
   - ``-no-color``: plain logs. Exit codes 0 (no error) and 1 (errors found).
4. **Network**: actionlint has no network feature (it never downloads action metadata; the
   inputs of popular actions are built in).
5. **Output and classes** (:data:`RULES`; the rule ID is actionlint's ``kind``): the untrusted
   input check of the ``expression`` kind ("... is potentially untrusted. avoid using it directly
   in inline scripts") gets the rule ID ``expression/untrusted-input`` and the class
   ``code-injection`` (CWE-94, severity high), for the reason that the zizmor adapter gives for
   ``template-injection``. ``credentials`` (hard-coded container passwords) is
   ``hardcoded-secrets`` (CWE-798, high). ``deprecated-commands`` (``set-env`` and ``add-path``
   workflow commands) is ``os-command-injection`` (CWE-77, medium). ``if-cond`` (a condition that
   is always true) is ``supply-chain-cicd`` (CWE-670, medium) and ``permissions`` (an invalid
   permission scope) ``supply-chain-cicd`` (low). Every other kind (syntax, type, expression,
   runner label, matrix, shellcheck and pyflakes errors) is ``code-quality`` with severity
   ``info``: lint errors, not security findings.
6. **Suppressions** (ADR-0003): actionlint 1.7.12 has no inline ignore comment. By default the
   target configuration file is replaced (point 3). With ``honor_suppressions``
   ``-config-file`` is left out and the staging copies the ``.github/actionlint.yaml`` (or
   ``.yml``) of the target, so actionlint applies its ``paths.*.ignore`` rules. When shellcheck
   runs, ``# shellcheck disable=...`` directives inside a ``run:`` script stay effective in both
   modes (no shellcheck option turns them off); the status file says so.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any, Final

from kalkan.errors import KalkanError, ToolError
from kalkan.scanners.adapters import _cicd
from kalkan.scanners.adapters._cicd import RuleClass
from kalkan.scanners.base import Invocation, ScanContext, ToolAdapter
from kalkan.util.safe_io import atomic_write_json, atomic_write_text, read_bounded

__all__ = ["CONFIG_NAMES", "RULES", "ActionlintAdapter", "report_to_sarif", "shellcheck_path"]

#: The configuration files of the target that ``honor_suppressions`` copies.
CONFIG_NAMES: Final = (".github/actionlint.yaml", ".github/actionlint.yml")
#: The staging folder below the work folder of the engine (module docstring, point 2).
STAGING_DIRNAME: Final = "repo"
#: The empty configuration file in the work folder.
CONFIG_FILENAME: Final = "actionlint.yaml"
#: Files above this size are not copied into the staging folder.
MAX_STAGED_BYTES: Final = 1024 * 1024
MAX_REPORT_BYTES: Final = 50 * 1024 * 1024
UNTRUSTED_RULE: Final = "expression/untrusted-input"
_UNTRUSTED_TEXT: Final = "is potentially untrusted"
_CODE_QUALITY: Final = RuleClass("code-quality")
#: actionlint kind (or ``expression/untrusted-input``) to class, CWE IDs and severity.
RULES: Final[dict[str, tuple[RuleClass, str]]] = {
    UNTRUSTED_RULE: (RuleClass("code-injection", ("CWE-94",)), "high"),
    "credentials": (RuleClass("hardcoded-secrets", ("CWE-798",)), "high"),
    "deprecated-commands": (RuleClass("os-command-injection", ("CWE-77",)), "medium"),
    "if-cond": (RuleClass("supply-chain-cicd", ("CWE-670",)), "medium"),
    "permissions": (RuleClass("supply-chain-cicd"), "low"),
}
_LEVELS: Final = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
_EMPTY_CONFIG: Final = (
    "# kalkan: an empty actionlint configuration (no paths.*.ignore rules, no extra labels).\n"
)


def rule_info(rule_id: str) -> tuple[RuleClass, str]:
    """Return the class and severity of an actionlint rule ID (module docstring, point 5)."""
    return RULES.get(rule_id, (_CODE_QUALITY, "info"))


def shellcheck_path() -> str:
    """Return the path of the kalkan copy of shellcheck, or ``""`` (module docstring, point 3).

    Only a copy that ``kalkan tools install`` placed under ``.tools`` counts, never a shellcheck
    on PATH. Without a ``shellcheck`` entry in the manifest the answer is ``""``.
    """
    from kalkan.tools.manifest import load_manifest  # lazy: small import graph
    from kalkan.tools.resolve import SOURCE_KALKAN, resolve

    try:
        manifest = load_manifest()
        if "shellcheck" not in manifest:
            return ""
        found = resolve("shellcheck", manifest=manifest, allow_path=False)
    except (KalkanError, OSError):
        return ""
    if found is None or found.source != SOURCE_KALKAN:
        return ""
    return str(found.path)


def report_to_sarif(report: Any, target: Path, *, cwd: Path, version: str = "") -> dict[str, Any]:
    """Convert the JSON report of actionlint (a list of errors) to SARIF 2.1.0.

    ``cwd`` is the working directory of actionlint (the staging folder): the report paths are
    relative to it. Raises :class:`~kalkan.errors.ToolError` for a report that is not a list.
    """
    if report is None:
        report = []
    if not isinstance(report, list):
        raise ToolError("the actionlint report is not a JSON array")
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for error in report:
        if not isinstance(error, dict):
            continue
        message = str(error.get("message") or "").strip()
        kind = str(error.get("kind") or "actionlint").strip() or "actionlint"
        rule_id = UNTRUSTED_RULE if kind == "expression" and _UNTRUSTED_TEXT in message else kind
        item, severity = rule_info(rule_id)
        if rule_id not in rules:
            title = (
                "Untrusted input used directly in an inline script"
                if rule_id == UNTRUSTED_RULE
                else f"actionlint {kind} check"
            )
            rules[rule_id] = _cicd.sarif_rule(
                rule_id,
                item,
                title=title,
                help_uri="https://github.com/rhysd/actionlint/blob/v1.7.12/docs/checks.md",
            )
        line = _int(error.get("line"))
        column = _int(error.get("column"))
        results.append(
            _cicd.sarif_result(
                rule_id,
                message,
                level=_LEVELS.get(severity, "note"),
                file=_cicd.target_path(error.get("filepath"), target, cwd=cwd),
                start_line=line,
                start_column=column,
                end_column=_int(error.get("end_column")),
                snippet=str(error.get("snippet") or "").rstrip("\n"),
                properties={"severity": severity, "actionlint-kind": kind},
            )
        )
    return _cicd.sarif_document(
        "actionlint", version, "https://github.com/rhysd/actionlint", list(rules.values()), results
    )


def _int(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else None


class ActionlintAdapter(ToolAdapter):
    """``actionlint -format "{{json .}}"`` over the staged workflows (module docstring)."""

    name = "actionlint"
    tool = "actionlint"
    output = "sarif-stdout"
    output_dir = "scans"
    output_name = "actionlint.sarif"
    ok_exit_codes = (0, 1)
    timeout_seconds = 600

    def applies(self, ctx: ScanContext) -> tuple[bool, str]:
        if _cicd.ci_files(ctx.target_dir).workflows:
            return True, ""
        return False, "no GitHub Actions workflow in the target"

    @staticmethod
    def staging_dir(out: Path) -> Path:
        """Return the staging folder that belongs to the staged output ``out``."""
        return out.parent / STAGING_DIRNAME

    @staticmethod
    def staged_files(ctx: ScanContext) -> tuple[list[str], list[str]]:
        """Return ``(workflows, other files)`` that the staging copies (module docstring)."""
        files = _cicd.ci_files(ctx.target_dir)
        others = list(files.actions)
        if ctx.honor_suppressions:
            others += list(CONFIG_NAMES)

        def small(rel: str) -> bool:
            path = ctx.target_dir / rel
            try:
                return (
                    path.is_file()
                    and not path.is_symlink()
                    and path.stat().st_size <= MAX_STAGED_BYTES
                )
            except OSError:
                return False

        workflows = [rel for rel in files.workflows if small(rel)]
        return workflows, [rel for rel in dict.fromkeys(others) if small(rel)]

    def prepare(self, ctx: ScanContext, stage: Path) -> None:
        """Write the empty configuration file and stage the files (module docstring, point 2)."""
        atomic_write_text(stage.parent / CONFIG_FILENAME, _EMPTY_CONFIG)
        repo = self.staging_dir(stage)
        (repo / ".git").mkdir(parents=True, exist_ok=True)
        workflows, others = self.staged_files(ctx)
        for rel in [*workflows, *others]:
            destination = repo / rel
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ctx.target_dir / rel, destination)

    def arguments(self, ctx: ScanContext, out: Path) -> list[str]:
        args = ["-format", "{{json .}}", "-no-color"]
        args += [f"-shellcheck={shellcheck_path()}", "-pyflakes="]
        if not ctx.honor_suppressions:
            args += ["-config-file", str(out.parent / CONFIG_FILENAME)]
        return [*args, *self.staged_files(ctx)[0]]

    def invocations(self, ctx: ScanContext, tool_path: Path, out: Path) -> list[Invocation]:
        argv = (str(tool_path), *self.arguments(ctx, out))
        return [Invocation(argv, self.staging_dir(out), out)]

    def suppression_sources(self, ctx: ScanContext) -> tuple[list[str], list[str]]:
        config = ".github/actionlint.yaml of the target"
        ignored: list[str] = []
        honored: list[str] = []
        if ctx.honor_suppressions:
            honored.append(f"{config} (paths.*.ignore rules)")
        else:
            ignored.append(f"{config} (-config-file names an empty kalkan file)")
        if shellcheck_path():
            honored.append("# shellcheck disable= directives in run: scripts (no option)")
        return ignored, honored

    def after_run(self, ctx: ScanContext, item: Invocation) -> None:
        """Convert the JSON report on stdout to SARIF in place (module docstring, point 5)."""
        raw = read_bounded(item.output, MAX_REPORT_BYTES).decode("utf-8", errors="replace")
        try:
            report = json.loads(raw) if raw.strip() else []
        except ValueError as exc:
            raise ToolError(f"actionlint did not write a JSON report: {exc}") from None
        atomic_write_json(item.output, report_to_sarif(report, ctx.target_dir, cwd=item.cwd))
