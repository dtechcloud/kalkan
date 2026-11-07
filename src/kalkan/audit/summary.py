# SPDX-License-Identifier: MIT
"""The deliverables and the end summary of ``kalkan audit`` (docs/ENGINE-SPEC.md, section 25).

:func:`deliverables` lists the files that exist after the audit, in this order:
``report/EXECUTIVE.html`` (open it first), ``REPORT.html``, ``REPORT.md``, the English versions,
``findings.sarif``, ``findings.json``, ``summary.json``, then every SBOM: the SBOM files of
``report/`` (a name with ``sbom``, or a ``.cdx.json`` or ``.spdx.json`` file) and the CycloneDX
SBOM of the SCA step (``sca/sbom.cdx.json``).

:func:`build_summary` reads the report model (:func:`kalkan.report.model.build_model`), so every
number equals the report:

- agent mode: the posture (:func:`kalkan.report.render_exec.posture`), the confirmed findings by
  severity, the needs_validation and rejected counts and the top 3 confirmed findings
  (:func:`kalkan.report.render_exec.top_findings`);
- tools-only mode: the posture ``unknown`` (not assessed), the unverified tool results by
  severity and the 3 most severe tool results;
- both: the SCA records (packages, reachable packages), the number of unverified tool results
  and the partial pass reasons (the short English texts of the executive page).

:func:`format_summary` renders the summary as one screen of plain text; its last line names
the file to open.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any, Final

from kalkan.findings.merge import severity_of
from kalkan.findings.severity import from_label, rank
from kalkan.report import i18n
from kalkan.report.model import SEVERITY_ORDER, ReportModel, build_model, clean, location_of
from kalkan.report.render_exec import posture, sca_packages, top_findings
from kalkan.unattended.auth import API_MODES

__all__ = [
    "REPORT_FILES",
    "SBOM_FILE",
    "TOP_COUNT",
    "build_summary",
    "deliverables",
    "format_summary",
]

#: The report files in the order of the deliverables list.
REPORT_FILES: Final = (
    "EXECUTIVE.html",
    "REPORT.html",
    "REPORT.md",
    "EXECUTIVE.en.html",
    "REPORT.en.html",
    "REPORT.en.md",
    "EXECUTIVE.tr.html",
    "REPORT.tr.html",
    "REPORT.tr.md",
    "findings.sarif",
    "findings.json",
    "summary.json",
)
#: The CycloneDX SBOM of the SCA step (kalkan.sca.commands).
SBOM_FILE: Final = "sca/sbom.cdx.json"
#: The number of findings (or tool results) in the summary.
TOP_COUNT: Final = 3
_TITLE_CHARS: Final = 100


def _sbom_label(name: str) -> str:
    lower = name.casefold()
    if lower.endswith(".spdx.json") or ".spdx" in lower:
        return "SBOM (SPDX)"
    if lower.endswith(".cdx.json") or "cyclonedx" in lower:
        return "SBOM (CycloneDX)"
    return "SBOM"


def _is_sbom(name: str) -> bool:
    lower = name.casefold()
    return "sbom" in lower or lower.endswith((".cdx.json", ".spdx.json"))


def deliverables(run_dir: str | Path) -> list[dict[str, str]]:
    """Return ``[{label, path}]`` of the files that exist (see the module docstring)."""
    folder = Path(run_dir)
    report = folder / "report"
    found: list[dict[str, str]] = []
    for name in REPORT_FILES:
        path = report / name
        if path.is_file():
            found.append({"label": name, "path": path.absolute().as_posix()})
    sboms = sorted(p for p in report.glob("*") if p.is_file() and _is_sbom(p.name))
    for path in sboms:
        found.append({"label": _sbom_label(path.name), "path": path.absolute().as_posix()})
    pipeline = folder / SBOM_FILE
    if pipeline.is_file() and pipeline.name not in {path.name for path in sboms}:
        found.append({"label": "SBOM (CycloneDX)", "path": pipeline.absolute().as_posix()})
    return found


def _counts(severities: list[str]) -> dict[str, int]:
    counts = dict.fromkeys(SEVERITY_ORDER, 0)
    for severity in severities:
        counts[severity if severity in counts else "info"] += 1
    return counts


def _tool_severity(candidate: Mapping[str, Any]) -> str:
    value = candidate.get("severity")
    return (from_label(value) if isinstance(value, str) else None) or "info"


def _short(text: object, limit: int = _TITLE_CHARS) -> str:
    flat = " ".join(clean(text).split())
    return flat if len(flat) <= limit else flat[: limit - 3] + "..."


def _reason(key: str, values: Mapping[str, Any]) -> str:
    """Return the short English text of a partial pass reason (as on the executive page)."""
    shown = dict(values)
    if key == "partial_not_done":
        shown["phase"] = i18n.phase_label("en", values.get("phase"))
    short = f"exec_{key}"
    return i18n.t("en", short if short in i18n.STRINGS["en"] else key, **shown)


def _top_tool_results(model: ReportModel) -> list[dict[str, Any]]:
    def key(item: Mapping[str, Any]) -> tuple[Any, ...]:
        return (
            -rank(_tool_severity(item)),
            clean(item.get("engine")),
            clean(item.get("file")),
            item.get("start_line") if isinstance(item.get("start_line"), int) else 0,
            clean(item.get("rule_id")),
            clean(item.get("id")),
        )

    rows = []
    for item in sorted(model.tool_results, key=key)[:TOP_COUNT]:
        file = clean(item.get("file"))
        line = item.get("start_line")
        location = f"{file}:{line}" if file and isinstance(line, int) else file
        rows.append(
            {
                "kind": "tool_result",
                "severity": _tool_severity(item),
                "title": _short(item.get("title") or item.get("rule_id")),
                "engine": clean(item.get("engine")),
                "location": location,
                "id": clean(item.get("id")),
            }
        )
    return rows


def _top_findings(model: ReportModel) -> list[dict[str, Any]]:
    return [
        {
            "kind": "finding",
            "severity": severity_of(finding) or "info",
            "title": _short(finding.get("title")),
            "engine": None,
            "location": location_of(finding),
            "id": clean(finding.get("id")),
        }
        for finding in top_findings(model, TOP_COUNT)
    ]


def build_summary(run_dir: str | Path, *, model: ReportModel | None = None) -> dict[str, Any]:
    """Return the end summary of the run in ``run_dir`` as a JSON-ready dict.

    ``model`` replaces :func:`kalkan.report.model.build_model` (tests).
    """
    folder = Path(run_dir)
    model = model or build_model(folder)
    level = posture(model)
    packages = sca_packages(model)
    verdicts = model.verdict_counts()
    files = deliverables(folder)
    executive = next((item["path"] for item in files if item["label"] == "EXECUTIVE.html"), None)
    return {
        "run_id": model.run_id,
        "run_dir": folder.absolute().as_posix(),
        "mode": "tools-only" if model.tools_only else "agents",
        "phase": model.phase,
        "complete": model.complete,
        "incomplete_reason": model.incomplete_reason,
        "posture": level,
        "posture_label": (
            i18n.t("en", "exec_posture_unknown")
            if level == "unknown"
            else i18n.severity_label("en", level)
        ),
        "partial_reasons": [
            {"code": key.removeprefix("partial_"), "text": _reason(key, values)}
            for key, values in model.partial_reasons
        ],
        "findings": {
            **verdicts,
            "by_severity": model.severity_counts(),
            "available": model.findings_available,
        },
        "tool_results": {
            "total": len(model.tool_results),
            "by_severity": _counts([_tool_severity(item) for item in model.tool_results]),
        },
        "sca": {
            "records": len(model.sca),
            "packages": len(packages),
            "reachable_packages": sum(1 for p in packages if p.reachability == "reachable"),
            "by_severity": _counts([record.severity or "info" for record in model.sca]),
        },
        "run": {
            "type": model.run_type(),
            "elapsed_seconds": model.elapsed_seconds(),
            "usage": model.usage,
        },
        "top": _top_tool_results(model) if model.tools_only else _top_findings(model),
        "deliverables": files,
        "open_first": executive,
    }


def _severity_text(counts: Mapping[str, int]) -> str:
    return ", ".join(f"{name} {counts.get(name, 0)}" for name in SEVERITY_ORDER)


def usage_text(usage: Mapping[str, Any] | None) -> str:
    """Return the cost line of a run: USD, active time, rounds and tokens, or "not recorded"."""
    if not usage:
        return "cost not recorded (interactive session or tools-only)"
    tokens = usage.get("tokens") or {}
    total_tokens = sum(int(value) for value in tokens.values() if isinstance(value, int))
    minutes = round((usage.get("active_seconds") or 0) / 60)
    api = [mode for mode in usage.get("auth") or [] if mode in API_MODES]
    basis = f"billed to {', '.join(api)}, estimate" if api else "API-equivalent"
    return (
        f"cost USD {usage.get('cost_usd', 0):.2f} ({basis}), {minutes} min active in "
        f"{usage.get('rounds', 0)} rounds, {total_tokens:,} tokens"
    )


def format_summary(summary: Mapping[str, Any], *, elapsed: str | None = None) -> str:
    """Return the end summary as plain text (one screen; the last line names the file to
    open). ``elapsed`` is the duration text, for example ``1 h 52 min``."""
    tools_only = summary["mode"] == "tools-only"
    if summary["phase"] != "done":
        state = f"stopped in phase {summary['phase']}"
    elif summary["incomplete_reason"]:
        state = f"finished incomplete ({summary['incomplete_reason']})"
    else:
        state = "done"
    head = f"{'Tools-only audit' if tools_only else 'Audit'} {state}: run {summary['run_id']}"
    lines = [head + (f" ({elapsed})" if elapsed else "")]
    if tools_only:
        lines.append("Posture: not assessed (tools-only mode: no agent validation)")
    else:
        lines.append(f"Posture: {summary['posture_label']}")
    findings, tools = summary["findings"], summary["tool_results"]
    if not tools_only:
        by_severity = _severity_text(findings["by_severity"])
        lines.append(
            f"Confirmed findings: {findings['confirmed']} ({by_severity}); need validation: "
            f"{findings['needs_validation']}; rejected: {findings['rejected']}"
        )
        lines.append(f"Unverified tool results: {tools['total']}")
    else:
        lines.append(
            f"Unverified tool results: {tools['total']} ({_severity_text(tools['by_severity'])})"
        )
    top = summary["top"]
    if top:
        lines.append("Top tool results:" if tools_only else "Top findings:")
        for index, item in enumerate(top, 1):
            engine = f"{item['engine']}: " if item.get("engine") else ""
            lines.append(f"  {index}. [{item['severity']}] {engine}{item['title']}")
            where = "  ".join(part for part in (item.get("location"), item.get("id")) if part)
            if where:
                lines.append(f"     {where}")
    sca = summary["sca"]
    lines.append(
        f"Vulnerable dependencies: {sca['records']} records in {sca['packages']} packages, "
        f"{sca['reachable_packages']} reachable"
    )
    for reason in summary["partial_reasons"]:
        if reason["code"] != "tools_only":  # the posture line says it
            lines.append(f"Partial pass: {reason['text']}")
    run = summary.get("run") or {}
    if run:
        lines.append(f"Run type: {run.get('type')}; {usage_text(run.get('usage'))}")
    if summary["deliverables"]:
        lines.append("Deliverables:")
        width = max(len(item["label"]) for item in summary["deliverables"])
        for item in summary["deliverables"]:
            lines.append(f"  {item['label'].ljust(width)}  {item['path']}")
    if summary["open_first"]:
        lines.append(f"Open the executive summary: {summary['open_first']}")
    return "\n".join(lines) + "\n"
