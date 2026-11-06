# SPDX-License-Identifier: MIT
"""Compare the findings of two or more runs (``kalkan run compare``, N.3 and N.5).

The runs are usually audits of the same commit: several fast audits for a stability test, or
two profiles side by side. Each run contributes its listed findings (``confirmed``,
``needs_validation`` and ``rejected``; records that consolidation folded are left out). Two
findings of different runs are the same issue when

1. their ``fingerprint`` is equal, or
2. their class and the file of their location are equal and the lines are at most
   :data:`LINE_WINDOW` apart.

The matching is greedy in run order: a finding joins the first group that holds no finding of
its own run yet. A group is one issue; it records the verdict and the severity in each run.
The result names the issues found by every run, by some runs, the verdict and severity changes
and, for each run, its type, time and recorded cost (``usage.jsonl``).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

from kalkan.findings.fingerprint import finding_location
from kalkan.findings.merge import severity_of
from kalkan.report.model import ReportModel, build_model

__all__ = ["LINE_WINDOW", "Issue", "compare_models", "compare_runs", "format_comparison"]

LINE_WINDOW: Final = 10
_OPEN: Final = ("confirmed", "needs_validation")


@dataclass
class Issue:
    """One issue across the runs: per run index, the finding that stands for it."""

    cls: str
    file: str
    line: int | None
    title: str
    fingerprint: str
    by_run: dict[int, dict[str, Any]] = field(default_factory=dict)

    def matches(self, finding: Mapping[str, Any], file: str, line: int | None) -> bool:
        if finding.get("fingerprint") and finding.get("fingerprint") == self.fingerprint:
            return True
        if not file or file != self.file or (finding.get("class") or "") != self.cls:
            return False
        if line is None or self.line is None:
            return line is None and self.line is None
        return abs(line - self.line) <= LINE_WINDOW


def _findings(model: ReportModel) -> list[dict[str, Any]]:
    return [*model.confirmed, *model.needs_validation, *model.rejected]


def compare_models(models: Sequence[ReportModel]) -> dict[str, Any]:
    """Return the comparison of ``models`` (two or more runs, module docstring)."""
    issues: list[Issue] = []
    for index, model in enumerate(models):
        for finding in _findings(model):
            file, line = finding_location(finding)
            target = next(
                (
                    issue
                    for issue in issues
                    if index not in issue.by_run and issue.matches(finding, file, line)
                ),
                None,
            )
            if target is None:
                target = Issue(
                    cls=str(finding.get("class") or ""),
                    file=file,
                    line=line,
                    title=str(finding.get("title") or ""),
                    fingerprint=str(finding.get("fingerprint") or ""),
                )
                issues.append(target)
            target.by_run[index] = {
                "id": finding.get("id"),
                "verdict": finding.get("verdict"),
                "severity": severity_of(finding),
            }
    count = len(models)
    rows = []
    for issue in issues:
        verdicts = {issue.by_run[i]["verdict"] for i in issue.by_run}
        severities = {
            issue.by_run[i]["severity"]
            for i in issue.by_run
            if issue.by_run[i]["verdict"] == "confirmed"
        }
        rows.append(
            {
                "class": issue.cls,
                "location": f"{issue.file}:{issue.line}" if issue.line else issue.file,
                "title": issue.title,
                "runs": {models[i].run_id: issue.by_run[i] for i in sorted(issue.by_run)},
                "in_runs": len(issue.by_run),
                "verdict_changed": len(verdicts) > 1,
                "severity_changed": len(severities) > 1,
            }
        )
    open_rows = [
        row for row in rows if any(item["verdict"] in _OPEN for item in row["runs"].values())
    ]
    in_all = [row for row in open_rows if row["in_runs"] == count]
    return {
        "runs": [
            {
                "run_id": model.run_id,
                "type": model.run_type(),
                "elapsed_seconds": model.elapsed_seconds(),
                "usage": model.usage,
                "counts": model.verdict_counts(),
            }
            for model in models
        ],
        "issues": rows,
        "open_issues": len(open_rows),
        "open_in_all_runs": len(in_all),
        "stability": round(len(in_all) / len(open_rows), 3) if open_rows else None,
        "verdict_changes": sum(1 for row in rows if row["verdict_changed"]),
        "severity_changes": sum(1 for row in rows if row["severity_changed"]),
    }


def compare_runs(run_dirs: Sequence[Path]) -> dict[str, Any]:
    """Build the report model of each run folder and compare them."""
    return compare_models([build_model(path) for path in run_dirs])


def format_comparison(result: Mapping[str, Any]) -> str:
    """Return the comparison as plain text: one line per run, the totals, then the issues."""
    lines = []
    for index, run in enumerate(result["runs"], start=1):
        usage = run.get("usage") or {}
        cost = f"USD {usage['cost_usd']:.2f}" if usage.get("cost_usd") is not None else "cost —"
        minutes = round((run.get("elapsed_seconds") or 0) / 60)
        counts = run["counts"]
        lines.append(
            f"[{index}] {run['run_id']}  {run['type']}  {minutes} min  {cost}  "
            f"confirmed {counts['confirmed']}, need validation {counts['needs_validation']}, "
            f"rejected {counts['rejected']}"
        )
    stability = result["stability"]
    lines.append(
        f"Open issues: {result['open_issues']}; in every run: {result['open_in_all_runs']}"
        + (f" (stability {stability:.0%})" if stability is not None else "")
        + f"; verdict changes: {result['verdict_changes']}; severity changes: "
        f"{result['severity_changes']}"
    )
    ids = [run["run_id"] for run in result["runs"]]
    for row in sorted(result["issues"], key=lambda r: (-r["in_runs"], r["class"], r["location"])):
        marks = []
        for run_id in ids:
            item = row["runs"].get(run_id)
            if item is None:
                marks.append("—")
            else:
                verdict = {"confirmed": "C", "needs_validation": "N", "rejected": "R"}.get(
                    item["verdict"], "?"
                )
                marks.append(f"{verdict}:{item['severity'] or '-'}")
        flag = " *" if row["verdict_changed"] or row["severity_changed"] else ""
        lines.append(f"  {' | '.join(marks)}  {row['class']}  {row['location']}{flag}")
    lines.append("C confirmed, N need validation, R rejected, — not found; * a change between runs")
    return "\n".join(lines)
