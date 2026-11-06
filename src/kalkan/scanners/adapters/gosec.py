# SPDX-License-Identifier: MIT
"""gosec Go scan, one run per Go module (ENGINE-SPEC 13).

Command line, checked against ``gosec -help`` of the pinned version 2.29.0, run with the module
folder (the folder of a ``go.mod``) as working directory::

    gosec -fmt json -out <run>/scans/.work/gosec/gosec.sarif.parts/<n>.json -no-fail -nosec
        ./...

gosec 2.29.0 writes an empty ``artifactLocation`` in its SARIF output on Windows, so the
adapter asks for the JSON report and converts it to SARIF itself (:func:`json_to_sarif`): one
result per issue with the rule ID, the message, the file, the line range, the code snippet
(line-number prefixes removed), the severity and confidence as properties and the CWE as a
rule tag. Issues marked ``nosec`` are dropped. A report without issues whose packages failed
to load (``Golang errors``) and that checked no file is a failed run, not a clean one: gosec
exits with 0 even when Go is missing.

Packages that load with errors (``Golang errors``) are a coverage gap: gosec still checks their
syntax, but its type-based checks and its SSA analyzers skip them. In local mode this happens
when a module of the target is not in the local module cache (``GOPROXY=off``: no download).
``status_details`` records them in ``scans/gosec.status.json`` as ``partial_packages``
(:func:`kalkan.scanners.adapters._common.go_partial_packages`: the package folder, its files,
the imports whose module was missing, the errors, the reason and the hint ``kalkan scan gosec
--online`` or a ``vendor`` folder), and the report lists them as a scan gap. A module with
``vendor/modules.txt`` runs with ``GOFLAGS=-mod=vendor`` (:attr:`Invocation.env`), so it loads
completely without the module cache; ``vendored_modules`` lists those modules. Checked on
2026-10-16 with gosec 2.29.0 and Go 1.26.9: a module that imports ``example.com/dep`` without
the module in the cache gives ``could not import example.com/dep (invalid package name: "")``
for ``main.go`` (an absolute path key), and gosec skips the SSA analysis of that package; the
same module with a ``vendor`` folder loads without errors.

gosec loads packages through the Go toolchain (it starts ``go list``), so it runs only when
the tech list has ``go``, a Go toolchain exists (:func:`kalkan.tools.golang.resolve_go`: the
kalkan copy from ``kalkan tools install go`` first, else a system Go of at least the required
version) and the target has a ``go.mod`` (``vendor`` and ``testdata`` folders are skipped).
:func:`~kalkan.scanners.adapters._common.go_env` puts the ``bin`` folder of that Go first on
PATH and sets ``GOROOT`` for the kalkan copy. Relative file names are relative to the module
folder; the parts become one SARIF file (``scans/gosec.sarif``, one run per module) with URIs
relative to the target. ``GOTOOLCHAIN=local`` stops Go from downloading the toolchain that a
``go.mod`` names; local mode (the default) sets ``GOPROXY=off``. Checked end to end on
2026-10-16 (Windows 11, Go 1.26.9 from ``.tools/go``): on the vulnapp fixture gosec found the
8 items that ``EXPECTED.json`` assigns to it.

Suppressions (ADR-0003): ``-nosec`` turns off the ``#nosec`` and ``//gosec:disable``
comments; with ``honor_suppressions`` it is left out.

Differences from section 13: ``-nosec``; ``-fmt json`` plus the conversion instead of
``-fmt sarif``; one run per module, each with its own part file.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from kalkan.errors import KalkanError, ToolError
from kalkan.scanners.adapters import _common
from kalkan.scanners.base import Invocation, ScanContext, ToolAdapter, part_path, work_dir
from kalkan.util.safe_io import atomic_write_json, read_bounded

MAX_REPORT_BYTES = 50 * 1024 * 1024
#: The fix that ``partial_packages`` names (docs/SECURITY.md, local mode).
PARTIAL_HINT = (
    "kalkan scan gosec --online (downloads the Go modules of the target) or a vendor/ folder "
    "in the target gives gosec full type information"
)
_LINE_RANGE = re.compile(r"\s*([0-9]+)(?:\s*-\s*([0-9]+))?\s*")
_CODE_PREFIX = re.compile(r"^\s*[0-9]+:\s?")
_LEVELS = {"HIGH": "error", "MEDIUM": "warning", "LOW": "note"}


def json_report_path(sarif_part: Path) -> Path:
    """Return the JSON report path that belongs to a SARIF part."""
    return sarif_part.with_suffix(".json")


def json_to_sarif(report: dict[str, Any], version: str = "") -> dict[str, Any]:
    """Convert a gosec JSON report to a SARIF 2.1.0 document.

    Raises :class:`~kalkan.errors.ToolError` when the report has no issues, its packages
    failed to load and gosec checked no file, or when it is not a gosec report.
    """
    if not isinstance(report, dict) or not isinstance(report.get("Issues", []), list):
        raise ToolError("the gosec report is not a JSON object with an 'Issues' list")
    issues = [item for item in report.get("Issues") or [] if isinstance(item, dict)]
    errors = report.get("Golang errors") or {}
    stats = report.get("Stats") if isinstance(report.get("Stats"), dict) else {}
    checked = stats.get("files") if isinstance(stats.get("files"), int) else 0
    if not issues and isinstance(errors, dict) and errors and checked < 1:
        first = _first_error(errors)
        raise ToolError(f"gosec could not load the Go packages: {first}")
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for issue in issues:
        if issue.get("nosec") is True:
            continue
        rule_id = str(issue.get("rule_id") or "").strip()
        if not rule_id:
            continue
        details = str(issue.get("details") or rule_id)
        severity = str(issue.get("severity") or "").upper()
        confidence = str(issue.get("confidence") or "").upper()
        cwe = _cwe(issue.get("cwe"))
        if rule_id not in rules:
            tags = ["security", *([cwe] if cwe else [])]
            rules[rule_id] = {
                "id": rule_id,
                "shortDescription": {"text": details},
                "properties": {"tags": tags},
            }
        region: dict[str, Any] = {}
        start, end = _lines(issue.get("line"))
        if start is not None:
            region["startLine"] = start
            region["endLine"] = end if end is not None else start
            snippet = _snippet(issue.get("code"))
            if snippet:
                region["snippet"] = {"text": snippet}
        location: dict[str, Any] = {
            "artifactLocation": {"uri": str(issue.get("file") or "").replace("\\", "/")}
        }
        if region:
            location["region"] = region
        properties: dict[str, Any] = {"severity": severity, "confidence": confidence}
        if cwe:
            properties["cwe"] = cwe
        results.append(
            {
                "ruleId": rule_id,
                "level": _LEVELS.get(severity, "warning"),
                "message": {"text": details},
                "locations": [{"physicalLocation": location}],
                "properties": properties,
            }
        )
    driver: dict[str, Any] = {"name": "gosec", "rules": list(rules.values())}
    if version:
        driver["version"] = version
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": driver}, "results": results}],
    }


def _first_error(errors: dict[str, Any]) -> str:
    for package, items in errors.items():
        if isinstance(items, list) and items and isinstance(items[0], dict):
            return f"{package}: {str(items[0].get('error', '')).strip()[:300]}"
    return "unknown error"


def _cwe(value: object) -> str | None:
    if isinstance(value, dict):
        value = value.get("id") or value.get("ID")
    text = str(value or "").strip()
    if text.upper().startswith("CWE-"):
        text = text[4:]
    return f"CWE-{int(text)}" if text.isdigit() else None


def _lines(value: object) -> tuple[int | None, int | None]:
    match = _LINE_RANGE.fullmatch(str(value or ""))
    if match is None:
        return None, None
    start = int(match.group(1))
    if start < 1:
        return None, None
    end = int(match.group(2)) if match.group(2) else start
    return start, max(start, end)


def _snippet(code: object) -> str:
    if not isinstance(code, str):
        return ""
    lines = [_CODE_PREFIX.sub("", line) for line in code.splitlines()]
    return "\n".join(lines).strip("\n")


class GosecAdapter(ToolAdapter):
    """``gosec -fmt json ./...`` in every Go module folder, converted to SARIF."""

    name = "gosec"
    tool = "gosec"
    output = "sarif-file"
    output_dir = "scans"
    output_name = "gosec.sarif"
    ok_exit_codes = (0,)
    timeout_seconds = 1200

    def applies(self, ctx: ScanContext) -> tuple[bool, str]:
        return _common.go_applies(ctx, "gosec")

    def arguments(self, ctx: ScanContext, out: Path) -> list[str]:
        nosec = [] if ctx.honor_suppressions else ["-nosec"]
        return ["-fmt", "json", "-out", str(json_report_path(out)), "-no-fail", *nosec, "./..."]

    def suppression_sources(self, ctx: ScanContext) -> tuple[list[str], list[str]]:
        comments = "#nosec and //gosec:disable comments"
        if ctx.honor_suppressions:
            return [], [comments]
        return [f"{comments} (-nosec)"], []

    def prepare(self, ctx: ScanContext, stage: Path) -> None:
        """Create the Go build cache and configuration folder in the work folder."""
        _common.go_prepare(work_dir(ctx.run_dir, self))

    def env(self, ctx: ScanContext) -> dict[str, str]:
        return _common.go_env(ctx, work_dir(ctx.run_dir, self))

    def invocations(self, ctx: ScanContext, tool_path: Path, out: Path) -> list[Invocation]:
        items: list[Invocation] = []
        for index, module in enumerate(_common.go_modules(ctx.target_dir)):
            part = part_path(out, index)
            folder = ctx.target_dir / module if module else ctx.target_dir
            items.append(
                Invocation(
                    (str(tool_path), *self.arguments(ctx, part)),
                    folder,
                    part,
                    base=module or None,
                    label=module or ".",
                    env=_common.go_module_env(folder),
                )
            )
        return items

    def status_details(
        self, ctx: ScanContext, stdout_log: Path, stderr_log: Path, outputs: list[Path]
    ) -> dict[str, Any]:
        """Return ``partial_packages`` and ``vendored_modules`` (module docstring)."""
        modules = _common.go_modules(ctx.target_dir)
        errors: list[tuple[str, str]] = []
        for output in outputs:
            try:
                index = int(output.stem)
                module = modules[index]
            except (ValueError, IndexError):
                module = ""
            folder = ctx.target_dir / module if module else ctx.target_dir
            try:
                report = json.loads(read_bounded(json_report_path(output), MAX_REPORT_BYTES))
            except (KalkanError, OSError, ValueError):
                continue
            found = report.get("Golang errors") if isinstance(report, dict) else None
            if not isinstance(found, dict):
                continue
            for key, items in found.items():
                file = _common.go_relative(str(key), ctx.target_dir, folder) if key else module
                for item in items if isinstance(items, list) else []:
                    if not isinstance(item, dict):
                        continue
                    where = f"{file}:{item.get('line', 0)}:{item.get('column', 0)}"
                    errors.append((file, f"{where}: {str(item.get('error', '')).strip()}"))
        details: dict[str, Any] = {}
        partial = _common.go_partial_packages(errors, offline=ctx.offline, hint=PARTIAL_HINT)
        if partial:
            details["partial_packages"] = partial
        vendored = [
            module or "."
            for module in modules
            if _common.go_vendored(ctx.target_dir / module if module else ctx.target_dir)
        ]
        if vendored:
            details["vendored_modules"] = vendored
        return details

    def after_run(self, ctx: ScanContext, item: Invocation) -> None:
        """Convert the JSON report of one run into the SARIF part ``item.output``."""
        report_path = json_report_path(item.output)
        if not report_path.is_file():
            raise ToolError(f"no gosec report {report_path.name}")
        try:
            report = json.loads(read_bounded(report_path, MAX_REPORT_BYTES))
        except ValueError as exc:
            raise ToolError(f"the gosec report is not valid JSON: {exc}") from None
        version = str(report.get("GosecVersion", "")) if isinstance(report, dict) else ""
        atomic_write_json(item.output, json_to_sarif(report, version))
