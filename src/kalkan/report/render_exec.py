# SPDX-License-Identifier: MIT
"""Executive summary page: ``EXECUTIVE.html`` and ``EXECUTIVE.en.html`` (docs/ENGINE-SPEC.md,
section 16).

One page for managers and security leads. Every number comes from the report model
(:mod:`kalkan.report.model`); the page has no data source of its own, so the records that
consolidation folded into a primary record (``duplicate_of``) never count (a note under the top
findings names their number). Top to bottom:

1. header: target, git commit, dates, profile, run status (full pass, or partial pass with the
   reasons in one line);
2. overall risk: the posture level (:func:`posture`), the confirmed findings by severity as
   stat tiles, the needs_validation and rejected counts; then, when the dependencies hold
   known malicious package versions, the malicious box (package, version, IDs, location and
   the action; the posture card names their number);
3. the top 10 confirmed findings (:func:`top_findings`), each linked to its anchor in
   ``REPORT.html`` (:func:`kalkan.report.render_html.finding_anchors`);
4. classes by severity (:func:`class_rows`) and the affected components (:func:`components`);
5. dependencies: vulnerable packages by severity and reachability, the top 5 packages with their
   upgrade target (:func:`sca_packages`, :func:`upgrade_target`; malicious package versions are
   in the box of point 2, not here);
6. tool results: one line per engine, unverified;
7. coverage and limits: profile, budget, ledger coverage, final review, scan gaps, missing
   inputs, warnings, the standing limits and the report outputs (the SBOM files with their
   formats);
8. priority actions: the remediations of the top findings (:func:`priority_actions`).

**Posture rule.** A confirmed critical finding gives ``critical``. Else a confirmed high finding
gives ``high``, else a confirmed medium finding gives ``medium``. Otherwise (only low or info
findings, or no confirmed finding) the level is ``low``. Findings that need validation, rejected
findings, tool results and SCA records do not count. Without ``findings.json`` the level is
``unknown``. A tools-only run (``kalkan audit --tools-only``) is ``unknown`` too, and its
severity tiles show a dash: no agent validated a finding, so a count of 0 would mislead.

The design follows ``REPORT.html``: the same theme "Gece" (:mod:`kalkan.report.theme`: tokens,
fonts, logo, badges and status dots), dark first with a light theme, the optional theme toggle as
the only script, print styles for one or two A4 pages, and a phone-width layout in which the wide
tables become stacked rows. Severity colors never stand alone: each badge, tile and table column
carries the severity word. Every text from the target or an agent goes through
:func:`render_html.h`; no such text is placed in a URL, an attribute name, a style or a script.
"""

from __future__ import annotations

import html
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

from kalkan.findings.deployment import SCOPE_TEMPLATE
from kalkan.findings.fingerprint import finding_location
from kalkan.findings.merge import severity_of
from kalkan.findings.severity import max_severity, rank
from kalkan.report import i18n
from kalkan.report.i18n import t
from kalkan.report.model import (
    SEVERITY_ORDER,
    ReportModel,
    ScaRecord,
    class_title,
    clean,
    fmt_ts,
    localized,
    location_of,
)
from kalkan.report.render_html import (
    SCRIPT,
    _code,
    _engine_status,
    _sev,
    finding_anchors,
    h,
)
from kalkan.report.sbom import FORMAT_NAMES
from kalkan.report.theme import COMPONENTS, FONT_FACES, PRINT_TOKENS, TOKENS
from kalkan.unattended.auth import API_MODES

__all__ = [
    "POSTURE_LEVELS",
    "TOP_ACTIONS",
    "TOP_FINDINGS",
    "TOP_PACKAGES",
    "Action",
    "ScaPackage",
    "class_rows",
    "component_of",
    "components",
    "one_line_summary",
    "posture",
    "priority_actions",
    "render_executive",
    "sca_packages",
    "top_findings",
    "upgrade_target",
]

#: The posture levels, from the highest.
POSTURE_LEVELS: Final = ("critical", "high", "medium", "low", "unknown")
TOP_FINDINGS: Final = 10
TOP_ACTIONS: Final = 5
TOP_PACKAGES: Final = 5
#: The malicious box lists at most this many package versions.
MAX_MALICIOUS_ROWS: Final = 10
MAX_CLASS_ROWS: Final = 8
MAX_COMPONENTS: Final = 8
#: A one-line text: the first sentences up to this length, else cut at a word boundary.
IMPACT_CHARS: Final = 100
ACTION_CHARS: Final = 120
TITLE_CHARS: Final = 110
SUMMARY_MIN_CHARS: Final = 40

_BACKTICK: Final = re.compile(r"`([^`]+)`")
_SENTENCE_END: Final = re.compile(r"(?<=[.!?])\s+")
_VERSION_PART: Final = re.compile(r"\d+|\D+")
_REACH_ORDER: Final = {"reachable": 0, "unknown": 1, "not_reachable": 2}
_REACH_CSS: Final = {"reachable": "st-crit", "unknown": "st-warn", "not_reachable": "st-good"}
_REVIEW_CSS: Final = {"verified": "st-good", "downgrade": "st-warn", "reject": "st-crit"}
#: Missing inputs that the page does not use (the tool versions are in the full report only).
_UNUSED_INPUTS: Final = frozenset({".tools/installed.json"})

CSS: Final = (
    FONT_FACES
    + TOKENS
    + COMPONENTS
    + """html { font-size: 15px; }
body {
  padding: 0 max(16px, env(safe-area-inset-right, 0px)) 0 max(16px, env(safe-area-inset-left, 0px));
}
p { margin: 0.5rem 0 0; }
.page { --gx: clamp(18px, 4vw, 48px); max-width: 72rem; margin-inline: auto; padding: 0 var(--gx); }
.head {
  position: relative; margin: 0 calc(-1 * var(--gx)); padding: 2.6rem var(--gx) 2.4rem;
  border: 1px solid var(--line); border-top: 0; border-radius: 0 0 22px 22px; overflow: hidden;
}
.head .theme-toggle { top: 2.6rem; right: var(--gx); }
.kicker {
  margin: 0; font-family: var(--mono); font-size: 0.72rem; letter-spacing: 0.14em;
  text-transform: uppercase; color: var(--muted); padding-right: 6rem; overflow-wrap: anywhere;
}
h1 {
  margin: 0.6rem 0 0; color: var(--fg); font-weight: 600; letter-spacing: -0.04em;
  font-size: clamp(2rem, 4.6vw, 3.1rem); line-height: 1.04; overflow-wrap: anywhere;
  text-wrap: balance;
}
.subtitle { color: var(--body); margin-top: 0.7rem; font-size: 1.02rem; }
.meta {
  margin: 1.8rem 0 0; display: grid; grid-template-columns: repeat(auto-fit, minmax(9.5rem, 1fr));
  gap: 1px; background: var(--line); border: 1px solid var(--line); border-radius: var(--r);
  overflow: hidden;
}
.meta div { background: var(--raise); padding: 0.7rem 0.9rem; min-width: 0; }
@media (min-width: 760px) { .meta div.wide { grid-column: span 2; } }
.meta dt, .lbl {
  font-family: var(--mono); font-size: 0.68rem; color: var(--muted); letter-spacing: 0.1em;
  text-transform: uppercase; font-weight: 400;
}
.meta dd {
  margin: 0.25rem 0 0; color: var(--fg); font-size: 0.93rem; font-weight: 500;
  overflow-wrap: anywhere;
}
.meta dd code { font-size: 0.82rem; font-weight: 400; }
.status {
  margin: 1rem 0 0; display: flex; flex-wrap: wrap; align-items: center; gap: 0.4rem 0.9rem;
  font-size: 0.9rem; color: var(--body);
}
.status .st {
  color: var(--fg); font-weight: 500; border: 1px solid var(--line-strong); border-radius: 999px;
  padding: 0.3rem 0.75rem; background: var(--fill);
}
section { margin-top: 3.2rem; min-width: 0; }
h2 {
  margin: 0; display: flex; gap: 0.9rem; align-items: baseline; color: var(--fg);
  font-size: 1.4rem; font-weight: 600; letter-spacing: -0.025em; line-height: 1.2;
}
h2 .num {
  font-family: var(--mono); font-size: 0.78rem; font-weight: 500; color: var(--accent);
  letter-spacing: 0.04em; flex: none; border: 1px solid var(--line-strong); border-radius: 999px;
  padding: 0.2rem 0.55rem;
}
h3 {
  margin: 1.4rem 0 0; color: var(--fg); font-size: 0.98rem; font-weight: 600;
  letter-spacing: -0.01em;
}
.intro { color: var(--body); font-size: 0.95rem; margin-top: 0.8rem; max-width: 70ch; }
.note { color: var(--muted); font-size: 0.84rem; max-width: 80ch; }
.mute { color: var(--muted); }
.small { font-size: 0.83rem; color: var(--muted); }
.two { display: grid; gap: 0 3rem; grid-template-columns: minmax(0, 1fr); }
@media (min-width: 900px) {
  .two { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .two.wide { grid-template-columns: minmax(0, 3fr) minmax(0, 2fr); }
}
.two > div, .risk > div { min-width: 0; }
.risk { margin-top: 1.3rem; display: grid; gap: 1.5rem; grid-template-columns: minmax(0, 1fr); }
@media (min-width: 760px) {
  .risk { grid-template-columns: minmax(260px, 1fr) minmax(0, 2fr); }
}
.posture {
  --sev: var(--line-strong); padding: 1.2rem 1.3rem 1.3rem; border: 1px solid var(--line);
  border-top: 3px solid var(--sev); border-radius: var(--r); background: var(--raise);
  background: radial-gradient(28rem 14rem at 0% 0%,
    color-mix(in oklab, var(--sev) 26%, transparent), transparent 75%), var(--raise);
}
.posture .lvl {
  display: block; color: var(--sev); font-size: 3.1rem; font-weight: 600;
  letter-spacing: -0.045em; line-height: 1; margin-top: 0.6rem; overflow-wrap: anywhere;
}
.posture p { margin: 0.6rem 0 0; font-size: 0.9rem; }
.posture p + p { margin-top: 0.3rem; color: var(--muted); }
.posture.lv-critical { --sev: var(--sev-c); }
.posture.lv-high { --sev: var(--sev-h); }
.posture.lv-medium { --sev: var(--sev-m); }
.posture.lv-low { --sev: var(--sev-l); }
.alert {
  border: 1px solid var(--line); border-top: 3px solid var(--sev-c); border-radius: var(--r);
  padding: 1rem 1.2rem; background: var(--raise);
}
.alert h2 { color: var(--sev-c); }
.alert p { margin: 0.4rem 0 0; font-size: 0.93rem; overflow-wrap: anywhere; }
.alert ul.mal { margin: 0.5rem 0 0; padding-left: 1.2rem; display: grid; gap: 0.2rem; }
.alert ul.mal li { overflow-wrap: anywhere; font-size: 0.93rem; }
.caption { margin: 0 0 0.5rem; }
.tiles {
  display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 1px;
  background: var(--line); border: 1px solid var(--line); border-radius: var(--r);
  overflow: hidden; margin-bottom: 1rem;
}
.tiles.pair { grid-template-columns: repeat(2, minmax(0, 1fr)); margin-bottom: 0; }
.tile {
  --sev: var(--fg); background: var(--raise); padding: 0.8rem 0.9rem 0.85rem; display: grid;
  gap: 0.35rem; align-content: start; min-width: 0;
}
.tile b {
  color: var(--sev); font-size: 2.3rem; font-weight: 600; line-height: 1;
  letter-spacing: -0.04em; font-variant-numeric: tabular-nums;
}
.tile span {
  font-family: var(--mono); font-size: 0.66rem; letter-spacing: 0.1em; text-transform: uppercase;
  color: var(--muted); overflow-wrap: anywhere;
}
.tiles.pair .tile b { font-size: 1.7rem; }
.tile.sev-critical { --sev: var(--sev-c); } .tile.sev-high { --sev: var(--sev-h); }
.tile.sev-medium { --sev: var(--sev-m); } .tile.sev-low { --sev: var(--sev-l); }
.tile.sev-info { --sev: var(--sev-i); }
.tile.zero b { color: var(--faint); }
.tbl-wrap {
  overflow-x: auto; margin-top: 0.9rem; max-width: 100%; border: 1px solid var(--line);
  border-radius: var(--r); background: var(--raise); padding: 0 1.1rem;
}
table.tbl { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
.tbl th, .tbl td {
  padding: 0.65rem 0.7rem; border-bottom: 1px solid var(--line); text-align: left;
  vertical-align: top; overflow-wrap: anywhere;
}
.tbl th:first-child, .tbl td:first-child { padding-left: 0; }
.tbl th:last-child, .tbl td:last-child { padding-right: 0; }
.tbl thead th {
  font-family: var(--mono); font-size: 0.66rem; font-weight: 400; letter-spacing: 0.1em;
  text-transform: uppercase; color: var(--muted); vertical-align: bottom; overflow-wrap: normal;
  padding-top: 0.7rem; padding-bottom: 0.6rem; border-bottom-color: var(--line-strong);
}
.tbl tbody th { font-weight: 500; color: var(--fg); }
.tbl tr:last-child > * { border-bottom: 0; }
.tbl tfoot th, .tbl tfoot td {
  border-top: 1px solid var(--line-strong); font-weight: 600; color: var(--fg);
}
.tbl .n, .tbl .c { font-variant-numeric: tabular-nums; white-space: nowrap; }
.tbl .n { text-align: right; }
.tbl .c { text-align: center; }
.tbl .c.z { color: var(--faint); }
.tbl td.c.sev-critical { color: var(--sev-c); font-weight: 600; }
.tbl td.c.sev-high { color: var(--sev-h); font-weight: 600; }
.tbl td.c.sev-medium { color: var(--sev-m); font-weight: 600; }
.tbl td.c.sev-low { color: var(--sev-l); font-weight: 600; }
.tbl .rank {
  font-family: var(--mono); font-size: 0.8rem; color: var(--muted); width: 2.4em;
  white-space: nowrap;
}
.tbl .lead a { font-weight: 500; }
.tbl .imp { color: var(--muted); font-size: 0.85rem; }
.tbl .loc code { font-size: 0.78rem; color: var(--body); overflow-wrap: break-word; }
.tbl .nw { white-space: nowrap; }
@media (min-width: 641px) {
  table.top { min-width: 760px; table-layout: fixed; }
  table.top thead th:nth-child(1) { width: 2.2rem; }
  table.top thead th:nth-child(2) { width: 25%; }
  table.top thead th:nth-child(3) { width: 6.6rem; }
  table.top thead th:nth-child(4) { width: 7.2rem; }
  table.top thead th:nth-child(5) { width: 11%; }
  table.top thead th:nth-child(6) { width: 19%; }
  table.top .loc code { overflow-wrap: anywhere; }
}
.bar {
  display: block; height: 3px; margin-top: 0.4rem; background: var(--fill); border-radius: 99px;
}
.bar i {
  display: block; height: 100%; border-radius: 99px; background: var(--accent);
  background: linear-gradient(90deg, var(--accent),
    color-mix(in oklab, var(--accent) 55%, var(--fg)));
}
.meter {
  display: block; height: 4px; margin-top: 0.45rem; max-width: 280px;
  background: var(--fill-strong);
  border-radius: 99px; overflow: hidden;
}
.meter i { display: block; height: 100%; background: var(--accent); border-radius: 99px; }
ul.chips {
  list-style: none; margin: 0.5rem 0 0; padding: 0; display: flex; flex-wrap: wrap;
  gap: 0.4rem 1.1rem;
}
ul.chips li { display: inline-flex; align-items: center; gap: 0.4rem; font-size: 0.9rem; }
ul.chips b { font-variant-numeric: tabular-nums; }
.facts {
  margin: 1rem 0 0; display: grid; grid-template-columns: max-content minmax(0, 1fr);
  gap: 0.75rem 1.4rem; font-size: 0.92rem;
}
.facts dt { padding-top: 0.2rem; }
.facts dd { margin: 0; min-width: 0; overflow-wrap: anywhere; }
.facts ul { margin: 0; padding-left: 1.1rem; display: grid; gap: 0.2rem; }
ol.actions {
  margin: 1rem 0 0; padding: 0; list-style: none; counter-reset: action; display: grid;
  gap: 0.6rem;
}
ol.actions li {
  counter-increment: action; display: grid; grid-template-columns: 2.2rem minmax(0, 1fr);
  gap: 0.25rem 0.6rem; padding: 0.95rem 1.1rem; border: 1px solid var(--line);
  border-radius: var(--r); background: var(--raise);
}
ol.actions li::before {
  content: counter(action, decimal-leading-zero); grid-row: span 2; font-family: var(--mono);
  font-size: 0.8rem; color: var(--accent); padding-top: 0.15rem;
}
ol.actions .what { color: var(--fg); font-weight: 500; overflow-wrap: anywhere; }
ol.actions .what .sev { margin-right: 0.6rem; vertical-align: 0.05em; }
ol.actions .why {
  grid-column: 2; font-size: 0.84rem; color: var(--muted); overflow-wrap: anywhere;
}
ol.actions .why a { color: var(--muted); }
footer.foot {
  margin-top: 3rem; padding: 1rem 0 2rem; font-family: var(--mono); font-size: 0.72rem;
  color: var(--muted); display: flex; flex-wrap: wrap; gap: 0.4rem 1.6rem;
  border-top: 1px solid var(--line);
}
footer.foot span { overflow-wrap: anywhere; }
footer.foot a { color: var(--muted); }
@media (max-width: 640px) {
  html { font-size: 14px; }
  .head { border-radius: 0 0 16px 16px; }
  .posture .lvl { font-size: 2.4rem; }
  .tile { padding: 0.6rem 0.45rem; }
  .tile b { font-size: 1.5rem; }
  .tile span { font-size: 0.58rem; letter-spacing: 0.04em; }
  .tbl-wrap { padding: 0 0.8rem; }
  table.stack, .stack tbody, .stack tr, .stack td { display: block; }
  .stack thead {
    position: absolute; width: 1px; height: 1px; overflow: hidden; clip-path: inset(50%);
    white-space: nowrap;
  }
  .stack tr { position: relative; padding: 0.8rem 0; border-bottom: 1px solid var(--line); }
  .stack tr:last-child { border-bottom: 0; }
  .stack.top tr { padding-left: 2.2rem; }
  .tbl.stack td { border: 0; padding: 0.15rem 0; }
  .stack td.rank { position: absolute; left: 0; top: 0.85rem; width: auto; }
  .stack td.inl { display: inline-block; margin-right: 0.8rem; }
  .tbl.stack td[data-label] { position: relative; padding-left: calc(var(--lw) + 0.6rem); }
  .stack td[data-label]::before {
    content: attr(data-label); position: absolute; left: 0; top: 0.3rem; width: var(--lw);
    white-space: nowrap; overflow: hidden; text-overflow: ellipsis; font-family: var(--mono);
    font-size: 0.66rem; letter-spacing: 0.06em; text-transform: uppercase; color: var(--muted);
  }
  .tbl.stack td.inl[data-label] { padding-left: 0; }
  .stack td.inl[data-label]::before { position: static; width: auto; margin-right: 0.4rem; }
  .stack.top { --lw: 4.6rem; }
  .stack.pkg { --lw: 8.2rem; }
}
@media (max-width: 560px) {
  table.grid, .grid thead, .grid tbody, .grid tfoot { display: block; }
  .grid tr { display: grid; grid-template-columns: repeat(6, minmax(0, 1fr)); }
  .grid thead th:first-child { display: none; }
  .tbl.grid tbody th, .tbl.grid tfoot th {
    grid-column: 1 / -1; border-bottom: 0; padding-bottom: 0;
  }
  .facts { grid-template-columns: minmax(0, 1fr); gap: 0.15rem; }
  .facts dd { margin-bottom: 0.7rem; }
}
@page { size: A4; margin: 12mm; }
@media print {
"""
    + PRINT_TOKENS
    + """  html { font-size: 7.6pt; }
  body { padding: 0; background: #ffffff; }
  .page { padding: 0; max-width: none; }
  .head { margin: 0 0 1rem; padding: 0 0 1rem; border: 0; border-radius: 0; background: none; }
  .theme-toggle { display: none !important; }
  section { margin-top: 1.6rem; }
  .risk { grid-template-columns: minmax(0, 1fr) minmax(0, 1.6fr); }
  .two { grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 0 1.8rem; }
  .two.wide { grid-template-columns: minmax(0, 3fr) minmax(0, 2fr); }
  .tbl-wrap { overflow: visible; padding: 0; border: 0; background: none; }
  table.tbl { min-width: 0 !important; line-height: 1.3; }
  .tbl th, .tbl td { padding: 0.32rem 0.45rem; }
  ol.actions li { padding: 0.45rem 0.7rem; }
  h2, h3 { break-after: avoid; }
  .posture, .alert, .tiles, tr, ol.actions li, .facts > * { break-inside: avoid; }
  a { text-decoration: none; }
  * { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
}
"""
)


# ---------------------------------------------------------------------------------------------
# Data (all derived from the report model)


def _score_rank(value: object) -> int:
    """Return the rank of a severity or score (``info`` 0 to ``critical`` 4), else -1."""
    if not isinstance(value, str):
        return -1
    try:
        return rank(value)
    except ValueError:
        return -1


def _likelihood(finding: Mapping[str, Any]) -> object:
    severity = finding.get("severity")
    likelihood = severity.get("likelihood") if isinstance(severity, Mapping) else None
    return likelihood.get("score") if isinstance(likelihood, Mapping) else None


def _impact_reason(finding: Mapping[str, Any]) -> object:
    severity = finding.get("severity")
    impact = severity.get("impact") if isinstance(severity, Mapping) else None
    return impact.get("reason") if isinstance(impact, Mapping) else None


def _top_key(finding: Mapping[str, Any]) -> tuple[Any, ...]:
    return (
        -_score_rank(severity_of(finding)),
        -_score_rank(_likelihood(finding)),
        clean(finding.get("title")).strip().casefold(),
        clean(finding.get("id")),
    )


def posture(model: ReportModel) -> str:
    """Return the overall risk level of the run (see the module docstring for the rule).

    ``critical``, ``high`` or ``medium`` is the highest severity of the confirmed findings;
    ``low`` stands for only low or info findings, or none; ``unknown`` means that
    ``findings.json`` is missing or unreadable, or that the run was tools-only (no agent
    validated anything, so "no confirmed finding" says nothing about the risk).
    """
    if not model.findings_available or model.tools_only:
        return "unknown"
    highest = model.highest_severity()
    return highest if highest in ("critical", "high", "medium") else "low"


def top_findings(model: ReportModel, limit: int = TOP_FINDINGS) -> list[dict[str, Any]]:
    """Return the most important confirmed findings: by severity, then likelihood (both from
    high to low), then by title and ID (in the run language, so both report languages agree).
    Findings that exist only in deployment templates come after the others."""
    return sorted(
        model.confirmed, key=lambda item: (model.scope_of(item) == SCOPE_TEMPLATE, _top_key(item))
    )[:limit]


def class_rows(model: ReportModel) -> list[tuple[str, dict[str, int]]]:
    """Return ``(class slug, {severity: count})`` for the confirmed findings: the class with the
    most critical findings first, then the most high findings, and so on, then by slug."""
    rows: dict[str, dict[str, int]] = {}
    for finding in model.confirmed:
        slug = clean(finding.get("class")).strip()
        severity = severity_of(finding) or "info"
        rows.setdefault(slug, dict.fromkeys(SEVERITY_ORDER, 0))[severity] += 1
    return sorted(
        rows.items(), key=lambda item: (tuple(-item[1][name] for name in SEVERITY_ORDER), item[0])
    )


def component_of(file: str) -> str:
    """Return the component of a file path: its first two folders (``""`` for a root file)."""
    parts = [part for part in clean(file).replace("\\", "/").split("/") if part not in ("", ".")]
    return "/".join(parts[:-1][:2])


def components(model: ReportModel) -> list[tuple[str, int, str | None]]:
    """Return ``(component, confirmed findings, highest severity)`` for the folders of the
    finding locations (:func:`component_of`): the most findings first, then the highest
    severity, then by name. Findings without a location are left out."""
    groups: dict[str, list[str | None]] = {}
    for finding in model.confirmed:
        file, _ = finding_location(finding)
        if file:
            groups.setdefault(component_of(file), []).append(severity_of(finding))
    rows = [(name, len(values), max_severity(*values)) for name, values in groups.items()]
    rows.sort(key=lambda row: (-row[1], -_score_rank(row[2]), row[0].casefold(), row[0]))
    return rows


@dataclass(frozen=True)
class ScaPackage:
    """One vulnerable package (ecosystem, name, version) and its SCA records."""

    ecosystem: str
    package: str
    version: str
    #: The highest severity of the records (None when no record has one).
    severity: str | None
    #: ``reachable`` when one record is reachable, else ``unknown`` when one is unknown, else
    #: ``not_reachable``.
    reachability: str
    vuln_ids: tuple[str, ...]
    #: The lowest version that fixes every record with a known fix (:func:`upgrade_target`).
    fixed_in: str | None
    #: The records without a known fix above the installed version.
    unfixed: int
    records: int


def _version_key(text: str) -> tuple[tuple[int, int, str], ...]:
    """Natural version order: numbers compare as numbers, a leading ``v`` is ignored."""
    if text[:1] in ("v", "V") and text[1:2].isdigit():
        text = text[1:]
    return tuple(
        (0, int(part), "") if part.isdigit() else (1, 0, part)
        for part in _VERSION_PART.findall(text)
    )


def _version_sort(text: str) -> tuple[Any, ...]:
    return (_version_key(text), text)


def upgrade_target(installed: str, records: Sequence[ScaRecord]) -> tuple[str | None, int]:
    """Return ``(version, unfixed)``: the lowest version that fixes every record with a known
    fix, and the number of records without one.

    The fix of a record is its lowest fixed version above ``installed``; the target is the
    highest of these fixes. Versions compare in a natural order (numbers as numbers): this fits
    the usual release numbers, not every pre-release scheme.
    """
    current = _version_key(installed)
    fixes = []
    unfixed = 0
    for record in records:
        newer = [value for value in record.fixed_versions if _version_key(value) > current]
        if newer:
            fixes.append(min(newer, key=_version_sort))
        else:
            unfixed += 1
    return (max(fixes, key=_version_sort) if fixes else None), unfixed


def sca_packages(model: ReportModel) -> list[ScaPackage]:
    """Group the SCA records by package. The most severe package comes first, then the
    reachable ones, then the package with more records, then by name and version. Known
    malicious package versions are left out: the malicious box shows them, and an upgrade
    target does not apply to them."""
    groups: dict[tuple[str, str, str], list[ScaRecord]] = {}
    for record in model.sca_vulnerable():
        groups.setdefault((record.ecosystem, record.package, record.version), []).append(record)
    packages = []
    for (ecosystem, package, version), records in groups.items():
        severities = [record.severity for record in records if record.severity]
        fixed_in, unfixed = upgrade_target(version, records)
        packages.append(
            ScaPackage(
                ecosystem=ecosystem,
                package=package,
                version=version,
                severity=max_severity(*severities) if severities else None,
                reachability=min(
                    (record.reachability for record in records),
                    key=lambda value: _REACH_ORDER.get(value, 1),
                ),
                vuln_ids=tuple(dict.fromkeys(r.vuln_id for r in records if r.vuln_id)),
                fixed_in=fixed_in,
                unfixed=unfixed,
                records=len(records),
            )
        )
    packages.sort(
        key=lambda item: (
            -_score_rank(item.severity),
            _REACH_ORDER.get(item.reachability, 1),
            -item.records,
            item.package.casefold(),
            item.package,
            item.version,
            item.ecosystem,
        )
    )
    return packages


@dataclass(frozen=True)
class Action:
    """One priority action: a remediation strategy of the top findings."""

    finding: Mapping[str, Any]
    #: The strategy in the report language, as one line (:func:`one_line_summary`).
    strategy: str
    not_translated: bool
    #: Other confirmed findings with the same strategy (in the run language).
    others: int


def priority_actions(model: ReportModel, lang: str, limit: int = TOP_ACTIONS) -> list[Action]:
    """Return the remediation strategies of the confirmed findings in the order of
    :func:`top_findings`, one per distinct strategy, at most ``limit``. A strategy that several
    findings share appears once, with the most important of them."""
    first: dict[str, Mapping[str, Any]] = {}
    counts: dict[str, int] = {}
    for finding in sorted(model.confirmed, key=_top_key):
        original, _ = localized(finding, "remediation_strategy", model.run_lang, model.run_lang)
        key = " ".join(original.split()).casefold().rstrip(". ")
        if not key:
            continue
        counts[key] = counts.get(key, 0) + 1
        first.setdefault(key, finding)
    actions = []
    for key, finding in list(first.items())[:limit]:
        text, note = localized(finding, "remediation_strategy", lang, model.run_lang)
        actions.append(Action(finding, one_line_summary(text, ACTION_CHARS), note, counts[key] - 1))
    return actions


def one_line_summary(value: object, limit: int) -> str:
    """Return the first sentences of ``value`` as one line: sentences are added until the text
    has :data:`SUMMARY_MIN_CHARS` characters, and a longer text is cut at a word boundary to at
    most ``limit`` characters (with an ellipsis)."""
    summary = ""
    for sentence in _SENTENCE_END.split(" ".join(clean(value).split())):
        summary = f"{summary} {sentence}".strip()
        if len(summary) >= SUMMARY_MIN_CHARS:
            break
    return _one_line(summary, limit)


def _one_line(text: str, limit: int) -> str:
    """Return ``text`` cut at a word boundary to at most ``limit`` characters."""
    if len(text) <= limit:
        return text
    cut = text[: limit - 1]
    space = cut.rfind(" ")
    if space > limit // 2:
        cut = cut[:space]
    return cut.rstrip(" ,;:.-") + "…"


# ---------------------------------------------------------------------------------------------
# Markup helpers


def _ui(lang: str, key: str, **values: object) -> str:
    """Return a UI string, escaped; its backtick spans become code. Text values lose their
    backticks, so that target text never adds markup."""
    safe = {
        name: clean(value).replace("`", "'") if isinstance(value, str) else value
        for name, value in values.items()
    }
    return _BACKTICK.sub(r"<code>\1</code>", html.escape(t(lang, key, **safe), quote=True))


class _Exec:
    def __init__(self, model: ReportModel, lang: str) -> None:
        self.model = model
        self.lang = lang
        run_lang = model.run_lang if model.run_lang in ("en", "tr") else "en"
        self.report = "REPORT.html" if lang == run_lang else f"REPORT.{lang}.html"
        self.anchors = finding_anchors(model)
        self.parts: list[str] = []

    def add(self, markup: str) -> None:
        if markup:
            self.parts.append(markup)

    def ui(self, key: str, **values: object) -> str:
        return _ui(self.lang, key, **values)

    def label(self, key: str) -> str:
        return h(t(self.lang, key))

    def note(self, key: str, **values: object) -> None:
        self.add(f'<p class="note">{self.ui(key, **values)}</p>')

    def href(self, finding: Mapping[str, Any]) -> str:
        return h(f"{self.report}#{self.anchors[id(finding)]}")

    def section(self, anchor: str, num: str, key: str) -> None:
        self.add(
            f'<section id="{anchor}" aria-labelledby="h-{anchor}">'
            f'<h2 id="h-{anchor}"><span class="num">{num.zfill(2)}</span>{self.label(key)}</h2>'
        )

    def table(
        self,
        headers: Sequence[tuple[str, str]],
        rows: Iterable[str],
        *,
        css: str = "",
        foot: str = "",
    ) -> None:
        """Add a table: ``headers`` are ``(label markup, cell class)``, ``rows`` are ``<tr>``."""
        head = "".join(
            (f'<th scope="col" class="{cls}">' if cls else '<th scope="col">') + f"{label}</th>"
            for label, cls in headers
        )
        tfoot = f"<tfoot>{foot}</tfoot>" if foot else ""
        classes = f"tbl {css}".strip()
        self.add(
            f'<div class="tbl-wrap"><table class="{classes}"><thead><tr>{head}</tr></thead>'
            f"<tbody>{''.join(rows)}</tbody>{tfoot}</table></div>"
        )

    def text(self) -> str:
        return "\n".join(self.parts)


def _review(lang: str, finding: Mapping[str, Any]) -> str:
    review = finding.get("review")
    decision = review.get("decision") if isinstance(review, Mapping) else None
    if isinstance(decision, str) and decision:
        label = i18n.review_label(lang, decision)
    else:
        label = t(lang, "review_none")
    css = _REVIEW_CSS.get(decision, "st-neutral") if isinstance(decision, str) else "st-neutral"
    return f'<span class="st {css}">{h(label)}</span>'


def _path_code(path: str) -> str:
    """Return a path as code that may break after each ``/`` (and nowhere else)."""
    text = h(path)
    return f"<code>{text.replace('/', '/<wbr>')}</code>" if text else ""


def _reach(lang: str, reachability: str, count: int | None = None) -> str:
    css = _REACH_CSS.get(reachability, "st-warn")
    number = f" <b>{count}</b>" if count is not None else ""
    return f'<span class="st {css}">{h(i18n.reachability_label(lang, reachability))}{number}</span>'


def _fill(part: int, whole: int) -> int:
    """Return ``part / whole`` as a whole percentage from 0 to 100 (0 for an empty whole)."""
    if whole <= 0:
        return 0
    return max(0, min(100, part * 100 // whole))


def _bar(css: str, percent: int) -> str:
    return f'<span class="{css}" aria-hidden="true"><i style="width: {percent}%"></i></span>'


# ---------------------------------------------------------------------------------------------
# Sections


def _header(page: _Exec) -> None:
    model, lang = page.model, page.lang
    name = clean(model.target_source).rstrip("/").rsplit("/", 1)[-1]
    title = t(lang, "exec_doc_title") + (f": {name}" if name else "")
    meta = [
        ("meta_target", _path_code(model.target_source)),
        ("meta_git_ref", _code(model.git_ref or "")),
        ("meta_profile", h(i18n.profile_label(lang, model.profile))),
        ("meta_created", h(fmt_ts(model.created_at))),
        ("meta_generated", h(fmt_ts(model.generated_at))),
    ]
    cells = "".join(
        ('<div class="wide">' if key == "meta_target" else "<div>")
        + f"<dt>{page.label(key)}</dt><dd>{value or '—'}</dd></div>"
        for key, value in meta
    )
    if model.partial_reasons:
        badge = f'<span class="st st-warn">{page.label("partial_title")}</span>'
        detail = " · ".join(_reason(page, key, values) for key, values in model.partial_reasons)
    else:
        badge = f'<span class="st st-good">{page.label("exec_status_full")}</span>'
        detail = page.ui("partial_full")
    page.add(
        '<header class="head logo-head field">'
        '<button type="button" class="theme-toggle" id="theme-toggle" hidden>'
        f"{page.label('theme_toggle')}</button>"
        f'<p class="kicker">{page.label("doc_kicker")} · {h(model.run_id)}</p>'
        f"<h1>{h(title)}</h1>"
        f'<p class="subtitle">{page.ui("exec_subtitle")} '
        f'<a href="{h(page.report)}">{h(page.report)}</a></p>'
        f'<dl class="meta">{cells}</dl>'
        f'<p class="status"><span class="lbl">{page.label("meta_status")}</span>{badge} '
        f"<span>{detail}</span></p>"
        "</header>"
    )


def _reason(page: _Exec, key: str, values: Mapping[str, Any]) -> str:
    """Return the short text of a partial pass reason (the full text for an unknown reason)."""
    shown = dict(values)
    if key == "partial_not_done":
        shown["phase"] = i18n.phase_label(page.lang, values.get("phase"))
    short = f"exec_{key}"
    return page.ui(short if short in i18n.STRINGS["en"] else key, **shown)


def _risk(page: _Exec) -> None:
    model, lang = page.model, page.lang
    level = posture(model)
    page.section("risk", "1", "exec_sec_risk")
    if level == "unknown":
        value = t(lang, "exec_posture_unknown")
        basis = page.ui("exec_posture_tools_only" if model.tools_only else "exec_posture_missing")
    else:
        value = i18n.severity_label(lang, level)
        highest = model.highest_severity()
        if highest:
            basis = page.ui("exec_posture_basis", label=i18n.severity_label(lang, highest))
        else:
            basis = page.ui("exec_posture_none")
    notes = [f"<p>{basis}</p>"]
    if model.partial_reasons:
        notes.append(f"<p>{page.ui('exec_posture_partial')}</p>")
    if level != "unknown":
        above = [
            item
            for item in sca_packages(model)
            if item.reachability == "reachable" and _score_rank(item.severity) > rank(level)
        ]
        if above:
            label = i18n.severity_label(lang, above[0].severity)
            notes.append(f"<p>{page.ui('exec_posture_sca', n=len(above), label=label)}</p>")
    malicious = model.sca_malicious()
    if malicious:
        notes.append(f"<p><b>{page.ui('exec_posture_malicious', n=len(malicious))}</b></p>")
    card = (
        f'<div><div class="posture lv-{level}"><span class="lbl">'
        f'{page.label("exec_posture_label")}</span><span class="lvl">{h(value)}</span>'
        f'{"".join(notes)}</div><p class="note">{page.ui("exec_posture_rule")}</p></div>'
    )
    known = model.findings_available and not model.tools_only
    counts = model.severity_counts()
    tiles = "".join(
        f'<div class="tile {f"sev-{name}" if known and counts[name] else "zero"}">'
        f"<b>{counts[name] if known else '—'}</b>"
        f"<span>{h(i18n.severity_label(lang, name))}</span></div>"
        for name in SEVERITY_ORDER
    )
    verdicts = model.verdict_counts()
    pair = "".join(
        f'<div class="tile{"" if known and verdicts[name] else " zero"}">'
        f"<b>{verdicts[name] if known else '—'}</b><span>{page.label(key)}</span></div>"
        for name, key in (
            ("needs_validation", "kpi_needs_validation"),
            ("rejected", "kpi_rejected"),
        )
    )
    total = verdicts["confirmed"] if known else "—"
    page.add(
        f'<div class="risk">{card}<div>'
        f'<p class="lbl caption">{page.ui("exec_tiles_confirmed", n=total)}</p>'
        f'<div class="tiles">{tiles}</div>'
        f'<p class="lbl caption">{page.label("exec_tiles_other")}</p>'
        f'<div class="tiles pair">{pair}</div>'
        f'<p class="note">{page.ui("kpi_severity_note")}</p></div></div>'
    )
    page.add("</section>")


def _malicious(page: _Exec) -> None:
    """The box of the known malicious package versions, right after the overall risk: one line
    per record (at most :data:`MAX_MALICIOUS_ROWS`) and the action."""
    records = page.model.sca_malicious()
    if not records:
        return
    items = []
    for record in records[:MAX_MALICIOUS_ROWS]:
        ids = _code(record.vuln_id) if record.vuln_id else ""
        if len(record.ids) > 1:
            ids += f" +{len(record.ids) - 1}"
        ecosystem = f" · {h(record.ecosystem)}" if record.ecosystem else ""
        where = f" · {_path_code(record.locations[0])}" if record.locations else ""
        items.append(
            f"<li>{_code(record.package)} {_code(record.version)}{ecosystem} · {ids}{where}</li>"
        )
    more = len(records) - MAX_MALICIOUS_ROWS
    page.add(
        '<section id="malicious" class="alert" aria-labelledby="h-malicious">'
        f'<h2 id="h-malicious">{page.ui("exec_malicious_title", n=len(records))}</h2>'
        f"<p>{page.ui('exec_malicious_intro')}</p>"
        f'<ul class="mal">{"".join(items)}</ul>'
        + (f'<p class="note">{page.ui("exec_malicious_more", n=more)}</p>' if more > 0 else "")
        + f'<p class="act"><b>{page.ui("exec_malicious_action")}</b></p></section>'
    )


def _top(page: _Exec) -> None:
    model, lang = page.model, page.lang
    page.section("top", "2", "exec_sec_top")
    if not model.findings_available:
        page.note("exec_top_missing")
    elif not model.confirmed:
        page.note("findings_none_confirmed")
    else:
        page.add(f'<p class="intro">{page.ui("exec_top_intro")}</p>')
        rows = []
        for index, finding in enumerate(top_findings(model), start=1):
            title, untranslated = localized(finding, "title", lang, model.run_lang)
            title = _one_line(" ".join(title.split()), TITLE_CHARS)
            extra = f' <span class="nt">{page.ui("not_translated")}</span>' if untranslated else ""
            if model.scope_of(finding) == SCOPE_TEMPLATE:
                extra += f' <span class="nt">{page.ui("deploy_template_tag")}</span>'
            impact = one_line_summary(_impact_reason(finding), IMPACT_CHARS)
            rows.append(
                "<tr>"
                f'<td class="rank">{index}</td>'
                f'<td class="lead"><a href="{page.href(finding)}">{h(title)}</a>{extra}</td>'
                f'<td class="inl nw">{_sev(lang, severity_of(finding))}</td>'
                f'<td class="inl nw" data-label="{page.label("f_review")}">'
                f"{_review(lang, finding)}</td>"
                f'<td data-label="{page.label("col_class")}">'
                f"{h(class_title(finding.get('class'), lang)) or '—'}</td>"
                f'<td class="loc" data-label="{page.label("col_location")}">'
                f"{_path_code(location_of(finding)) or '—'}</td>"
                f'<td class="imp" data-label="{page.label("exec_col_impact")}">'
                f"{h(impact) or '—'}</td>"
                "</tr>"
            )
        page.table(
            [
                (page.label("exec_col_rank"), "rank"),
                (page.label("exec_col_finding"), ""),
                (page.label("col_severity"), ""),
                (page.label("f_review"), ""),
                (page.label("col_class"), ""),
                (page.label("col_location"), ""),
                (page.label("exec_col_impact"), ""),
            ],
            rows,
            css="top stack",
        )
        if len(model.confirmed) > TOP_FINDINGS:
            page.note("exec_top_more", n=len(model.confirmed))
    if model.needs_validation:
        page.note("exec_top_needs_validation", n=len(model.needs_validation))
    if model.duplicates:
        page.note("exec_duplicates", n=len(model.duplicates))
    if model.confirmed and lang != model.run_lang:
        page.note("translation_scope")
    page.add("</section>")


def _classes(page: _Exec) -> None:
    model, lang = page.model, page.lang
    page.section("classes", "3", "exec_sec_classes")
    if not model.findings_available:
        page.note("exec_top_missing")
        page.add("</section>")
        return
    if not model.confirmed:
        page.note("findings_none_confirmed")
        page.add("</section>")
        return
    rows = class_rows(model)
    shown, folded = rows[:MAX_CLASS_ROWS], rows[MAX_CLASS_ROWS:]
    if folded:
        other = dict.fromkeys(SEVERITY_ORDER, 0)
        for _, counts in folded:
            for name in SEVERITY_ORDER:
                other[name] += counts[name]
        shown = [*shown, (None, other)]
    body = []
    for slug, counts in shown:
        if slug is None:
            label = page.ui("exec_class_other", n=len(folded))
        elif slug:
            label = h(class_title(slug, lang))
        else:
            label = page.label("exec_class_none")
        body.append(f'<tr><th scope="row">{label}</th>{_count_cells(counts)}</tr>')
    totals = dict.fromkeys(SEVERITY_ORDER, 0)
    for _, counts in rows:
        for name in SEVERITY_ORDER:
            totals[name] += counts[name]
    foot = f'<tr><th scope="row">{page.label("col_total")}</th>{_count_cells(totals)}</tr>'
    page.add('<div class="two wide"><div>')
    page.add(f"<h3>{page.label('exec_sub_classes')}</h3>")
    page.table(
        [
            (page.label("col_class"), ""),
            *((h(i18n.severity_label(lang, name)), "c") for name in SEVERITY_ORDER),
            (page.label("col_total"), "c"),
        ],
        body,
        css="grid",
        foot=foot,
    )
    page.note("exec_classes_intro")
    page.add("</div><div>")
    page.add(f"<h3>{page.label('exec_sub_components')}</h3>")
    found = components(model)
    widest = max((count for _, count, _ in found), default=0)
    lines = []
    for name, count, highest in found[:MAX_COMPONENTS]:
        path = (
            _path_code(name)
            if name
            else f'<span class="mute">{page.label("exec_root_folder")}</span>'
        )
        lines.append(
            f"<tr><td>{path}{_bar('bar', _fill(count, widest))}</td>"
            f'<td class="n">{count}</td><td class="nw">{_sev(lang, highest)}</td></tr>'
        )
    if lines:
        page.table(
            [
                (page.label("exec_col_component"), ""),
                (page.label("exec_col_count"), "n"),
                (page.label("exec_col_highest"), ""),
            ],
            lines,
        )
    if len(found) > MAX_COMPONENTS:
        page.note("exec_components_more", n=len(found) - MAX_COMPONENTS)
    page.note("exec_components_intro")
    page.add("</div></div>")
    page.add("</section>")


def _count_cells(counts: Mapping[str, int]) -> str:
    cells = "".join(
        f'<td class="c sev-{name}">{counts[name]}</td>'
        if counts[name]
        else '<td class="c z">0</td>'
        for name in SEVERITY_ORDER
    )
    return cells + f'<td class="c"><b>{sum(counts.values())}</b></td>'


def _sca(page: _Exec) -> None:
    model, lang = page.model, page.lang
    page.section("sca", "4", "exec_sec_sca")
    if model.sca_source is None:
        page.note("sca_missing")
        page.add("</section>")
        return
    if model.sca_source == "candidates":
        page.note("sca_from_candidates")
    packages = sca_packages(model)
    malicious = model.sca_malicious()
    if malicious:
        page.note("exec_sca_malicious", n=len(malicious))
    if not packages:
        if not malicious:
            page.note("sca_none")
        # "No vulnerable dependency" alone overstates the coverage when manifests had no lockfile.
        if model.unchecked_manifests:
            page.note("exec_sca_unchecked", n=len(model.unchecked_manifests))
        page.add("</section>")
        return
    records = len(model.sca_vulnerable())
    page.add(
        f'<p class="intro">'
        f"{page.ui('exec_sca_summary', packages=len(packages), records=records)}</p>"
    )
    by_severity: dict[str | None, int] = {}
    for item in packages:
        by_severity[item.severity] = by_severity.get(item.severity, 0) + 1
    chips = [
        f"<li>{_sev(lang, name)} <b>{by_severity[name]}</b></li>"
        for name in (*SEVERITY_ORDER, None)
        if by_severity.get(name)
    ]
    page.add(f'<h3>{page.label("exec_sca_severity")}</h3><ul class="chips">{"".join(chips)}</ul>')
    by_reach = dict.fromkeys(_REACH_ORDER, 0)
    for item in packages:
        by_reach[item.reachability] = by_reach.get(item.reachability, 0) + 1
    reach = "".join(f"<li>{_reach(lang, name, count)}</li>" for name, count in by_reach.items())
    page.add(f'<h3>{page.label("exec_sca_reach")}</h3><ul class="chips">{reach}</ul>')
    page.add(f"<h3>{page.label('exec_sca_top')}</h3>")
    rows = []
    for item in packages[:TOP_PACKAGES]:
        ids = _code(item.vuln_ids[0]) if item.vuln_ids else ""
        if len(item.vuln_ids) > 1:
            ids += f" +{len(item.vuln_ids) - 1}"
        if item.fixed_in:
            fixed = page.ui("exec_sca_fixed_in", version=item.fixed_in)
            if item.unfixed:
                unfixed = page.ui("exec_sca_unfixed", n=item.unfixed)
                fixed += f'<br><span class="small">{unfixed}</span>'
        else:
            fixed = page.ui("exec_sca_no_fix")
        ecosystem = f" · {h(item.ecosystem)}" if item.ecosystem else ""
        rows.append(
            "<tr>"
            f'<td class="lead">{_code(item.package)} {_code(item.version)}'
            f'<br><span class="small">{ids}{ecosystem}</span></td>'
            f'<td class="inl nw">{_sev(lang, item.severity)}</td>'
            f'<td class="inl nw">{_reach(lang, item.reachability)}</td>'
            f'<td data-label="{page.label("col_fixed")}">{fixed}</td>'
            "</tr>"
        )
    page.table(
        [
            (page.label("col_package"), ""),
            (page.label("col_severity"), ""),
            (page.label("col_reachability"), ""),
            (page.label("col_fixed"), ""),
        ],
        rows,
        css="pkg stack",
    )
    page.add("</section>")


def _tools(page: _Exec) -> None:
    model, lang = page.model, page.lang
    page.section("tools", "5", "sec_tool_results")
    page.add(f'<p class="intro">{page.ui("tool_results_intro")}</p>')
    by_engine = model.tool_results_by_engine()
    known = model.candidates_available
    rows = []
    listed = set()
    has_sca = False
    for engine in model.engines:
        listed.add(engine.engine)
        found = len(by_engine.get(engine.engine, []))
        if engine.group == "sca":
            has_sca = True
            count = '<span class="mute">SCA</span>'
        elif not known or (not found and engine.status != "ok"):
            count = "—"  # unknown, or the engine did not run
        else:
            count = str(found)
        rows.append(
            f"<tr><td>{_code(engine.engine)}</td><td>{_engine_status(lang, engine.status)}</td>"
            f'<td class="n">{count}</td></tr>'
        )
    for name, items in by_engine.items():
        if name not in listed:
            rows.append(
                f"<tr><td>{_code(name)}</td><td>{_engine_status(lang, 'unknown')}</td>"
                f'<td class="n">{len(items)}</td></tr>'
            )
    if rows:
        total = str(len(model.tool_results)) if known else "—"
        page.table(
            [
                (page.label("col_engine"), ""),
                (page.label("col_status"), ""),
                (page.label("exec_col_unverified"), "n"),
            ],
            rows,
            foot=(
                f'<tr><th scope="row" colspan="2">{page.label("col_total")}</th>'
                f'<td class="n">{total}</td></tr>'
            ),
        )
    else:
        page.note("engines_missing")
    if not known:
        page.note("tool_results_missing")
    if has_sca:
        page.note("exec_tools_sca")
    page.add("</section>")


def _coverage(page: _Exec) -> None:
    model, lang = page.model, page.lang
    page.section("coverage", "6", "exec_sec_coverage")
    facts: list[tuple[str, str]] = [
        ("meta_profile", h(i18n.profile_label(lang, model.profile)) or "—"),
    ]
    if model.budget:
        used, maximum = model.budget["used"], model.budget["max"]
        facts.append(
            (
                "exec_cov_budget",
                page.ui("exec_budget_value", used=used, max=maximum)
                + _bar("meter", _fill(used, maximum)),
            )
        )
    else:
        facts.append(("exec_cov_budget", page.ui("scope_budget_missing")))
    if model.ledger is None:
        facts.append(("exec_cov_ledger", page.ui("ledger_missing")))
    elif not model.ledger_total:
        facts.append(("exec_cov_ledger", page.ui("ledger_empty")))
    else:
        total = model.ledger_total
        closed = total - model.ledger_open
        facts.append(
            (
                "exec_cov_ledger",
                page.ui("exec_ledger_value", pct=_fill(closed, total), closed=closed, total=total)
                + _bar("meter", _fill(closed, total)),
            )
        )
    if model.profile == "fast":
        facts.append(("f_review", page.ui("exec_review_fast")))
    elif model.findings_available:
        facts.append(("f_review", page.ui("exec_review_value", **model.review_counts())))
    facts.append(("f_run", _run_fact(page)))
    deploy = _deployment_fact(page)
    if deploy:
        facts.append(("f_deploy", deploy))
    gaps = _gap_lines(page)
    if gaps:
        items = "".join(f"<li>{line}</li>" for line in gaps)
        facts.append(("sub_gaps", f"<ul>{items}</ul>{page.ui('exec_gaps_detail')}"))
    else:
        facts.append(("sub_gaps", page.ui("exec_gaps_none")))
    missing = [name for name in model.missing if name not in _UNUSED_INPUTS]
    if missing:
        facts.append(("sub_missing", ", ".join(_code(name) for name in missing)))
    if model.warnings:
        facts.append(("warnings_title", page.ui("exec_warnings", n=len(model.warnings))))
    limits = "".join(
        f"<li>{page.ui(key)}</li>" for key in (_poc_limit(model), "exec_limit_unverified")
    )
    facts.append(("exec_cov_limits", f"<ul>{limits}</ul>"))
    if model.outputs:
        files = ", ".join(
            _code(name) + (f" ({h(FORMAT_NAMES[name])})" if name in FORMAT_NAMES else "")
            for name in model.outputs
        )
        facts.append(("exec_cov_outputs", files))
    cells = "".join(
        f'<dt class="lbl">{page.label(key)}</dt><dd>{value}</dd>' for key, value in facts
    )
    page.add(f'<dl class="facts">{cells}</dl>')
    page.add("</section>")


def _duration(seconds: int | None, lang: str) -> str:
    if seconds is None:
        return "—"
    hours, minutes = divmod(round(seconds / 60), 60)
    unit_h, unit_m = ("sa", "dk") if lang == "tr" else ("h", "min")
    return f"{hours} {unit_h} {minutes} {unit_m}" if hours else f"{minutes} {unit_m}"


def _run_fact(page: _Exec) -> str:
    """Return the run line: the run type, the calendar time and the recorded cost."""
    model = page.model
    elapsed = _duration(model.elapsed_seconds(), page.lang)
    usage = model.usage
    if not usage:
        return page.ui("exec_run_no_cost", type=model.run_type(), elapsed=elapsed)
    cost = f"{usage.get('cost_usd', 0):.2f}"
    if page.lang == "tr":
        cost = cost.replace(".", ",")
    api = [mode for mode in usage.get("auth") or [] if mode in API_MODES]
    return page.ui(
        "exec_run_cost_api" if api else "exec_run_cost",
        type=model.run_type(),
        elapsed=elapsed,
        active=_duration(usage.get("active_seconds"), page.lang),
        cost=cost,
        rounds=usage.get("rounds", 0),
        auth=", ".join(api),
    )


def _deployment_fact(page: _Exec) -> str:
    """Return the deployment line: the live paths, the not-live code and the template-only
    count, or the deployments of the target with the hint to name the live one; empty without
    deployments."""
    model = page.model
    n = len(model.template_confirmed)
    not_live = (
        page.ui("exec_deploy_not_live", paths=", ".join(model.not_live_paths))
        if model.not_live_paths
        else ""
    )
    if model.live_paths:
        live = page.ui("exec_deploy_live", live=", ".join(model.live_paths), n=n)
        return f"{live} {not_live}".strip()
    if not_live:
        return f"{not_live} {page.ui('exec_deploy_template_n', n=n)}"
    if not model.deployments:
        return ""
    sets = ", ".join(f"{item['kind']} {item['path']}" for item in model.deployments)
    return page.ui("exec_deploy_unknown", sets=sets, n=len(model.deployments))


def _poc_limit(model: ReportModel) -> str:
    """Return the i18n key of the PoC limit: the sandbox ran when a PoC ran, else it did not."""
    ran = any(
        isinstance(finding.get("poc"), Mapping)
        and finding["poc"].get("status") in ("passed", "failed")
        for finding in model.findings
    )
    return "exec_limit_poc_unit" if ran else "poc_sandbox_unavailable"


def _gap_lines(page: _Exec) -> list[str]:
    model = page.model
    lines = []
    if model.unchecked_manifests:
        lines.append(page.ui("exec_gap_manifests", n=len(model.unchecked_manifests)))
    if model.database_gaps:
        lines.append(page.ui("exec_gap_databases", n=len(model.database_gaps)))
    for gap in model.scan_gaps:
        if gap.partial_count:
            lines.append(page.ui("exec_gap_partial", engine=gap.engine, n=gap.partial_count))
        if gap.skipped_count:
            lines.append(page.ui("exec_gap_skipped", engine=gap.engine, n=gap.skipped_count))
        if gap.package_count:
            lines.append(page.ui("exec_gap_packages", engine=gap.engine, n=gap.package_count))
    if model.long_paths:
        lines.append(page.ui("exec_gap_long_paths", n=model.long_paths["count"]))
    return lines


def _actions(page: _Exec) -> None:
    model, lang = page.model, page.lang
    page.section("actions", "7", "exec_sec_actions")
    actions = priority_actions(model, lang)
    if not model.findings_available:
        page.note("exec_top_missing")
    elif not actions:
        page.note("exec_actions_none")
    else:
        page.add(f'<p class="intro">{page.ui("exec_actions_intro")}</p>')
        items = []
        for action in actions:
            title, untranslated = localized(action.finding, "title", lang, model.run_lang)
            extra = f' <span class="nt">{page.ui("not_translated")}</span>' if untranslated else ""
            more = f" ({page.ui('exec_action_more', n=action.others)})" if action.others else ""
            note = f' <span class="nt">{page.ui("not_translated")}</span>'
            items.append(
                "<li>"
                f'<div class="what">{_sev(lang, severity_of(action.finding))}'
                f"{h(action.strategy)}{note if action.not_translated else ''}</div>"
                f'<div class="why"><a href="{page.href(action.finding)}">'
                f"{h(_one_line(' '.join(title.split()), TITLE_CHARS))}</a>{extra}"
                f"{more}</div>"
                "</li>"
            )
        page.add(f'<ol class="actions">{"".join(items)}</ol>')
    if model.sca and not actions:
        page.note("exec_actions_sca")
    page.add("</section>")


def render_executive(model: ReportModel, lang: str = "tr") -> str:
    """Return the self-contained executive summary page of ``model`` in ``lang``."""
    page = _Exec(model, lang)
    _header(page)
    _risk(page)
    _malicious(page)
    _top(page)
    _classes(page)
    page.add('<div class="two"><div>')
    _sca(page)
    page.add("</div><div>")
    _tools(page)
    page.add('</div></div><div class="two"><div>')
    _coverage(page)
    page.add("</div><div>")
    _actions(page)
    page.add("</div></div>")
    page.add(
        '<footer class="foot">'
        f"<span>{h(model.run_id)}</span>"
        f"<span>kalkan {h(model.kalkan_version)} · {h(fmt_ts(model.generated_at))}</span>"
        f"<span>{page.label('footer_static')}</span>"
        f'<span><a href="{h(page.report)}">'
        f"{page.ui('exec_footer_full', name=page.report)}</a></span>"
        "</footer>"
    )
    title = f"{t(lang, 'exec_doc_title')} · {model.run_id}"
    return (
        "<!doctype html>\n"
        f'<html lang="{h(lang)}">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        '<meta name="color-scheme" content="light dark">\n'
        f'<meta name="generator" content="kalkan {h(model.kalkan_version)}">\n'
        f"<title>{h(title)}</title>\n<style>{CSS}</style>\n</head>\n<body>\n"
        f'<main class="page">\n{page.text()}\n</main>\n<script>{SCRIPT}</script>\n'
        "</body>\n</html>\n"
    )
