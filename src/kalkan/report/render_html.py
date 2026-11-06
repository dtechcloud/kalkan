# SPDX-License-Identifier: MIT
"""HTML report: ``REPORT.html`` and ``REPORT.en.html`` (docs/ENGINE-SPEC.md, section 16).

The page is self-contained: inline CSS, system font stacks, no external request, no image. The
only script is a small optional theme toggle; the page works without it. The design follows the
approved "corporate technical report" page: a contents rail, one document surface, numbered
sections, dense tables, light and dark theme (``prefers-color-scheme`` and a ``data-theme``
override), print styles, and a phone-width layout in which wide tables scroll inside their own
container.

Every text that comes from the target or from an agent goes through :func:`h`
(:func:`kalkan.report.model.clean`, then :func:`html.escape` with quotes). No such text is ever
placed in a URL, an attribute name, a style or a script.
"""

from __future__ import annotations

import html
import re
from collections.abc import Iterable, Mapping, Sequence
from typing import Any, Final

from kalkan.findings.merge import severity_of
from kalkan.report import i18n
from kalkan.report.i18n import t
from kalkan.report.model import (
    MAX_TOOL_ROWS_PER_ENGINE,
    SEVERITY_ORDER,
    ReportModel,
    ScaRecord,
    class_title,
    clean,
    fmt_ts,
    localized,
    location_of,
    manifest_reason_key,
)
from kalkan.report.sbom import text_values

__all__ = ["CSS", "PRINT_TOKENS", "SCRIPT", "TOKENS", "finding_anchors", "h", "render_html"]

_ANCHOR_SAFE: Final = re.compile(r"[^A-Za-z0-9_-]")
_CODE_LIKE: Final = re.compile(r"[a-z0-9_.:-]+")

#: The design tokens (CSS custom properties) of the light and the dark theme. The executive
#: summary page (:mod:`kalkan.report.render_exec`) uses the same tokens.
TOKENS: Final = """
:root {
  --bg: #f3f5f8; --panel: #ffffff; --head: #f6f8fa; --line: #e1e5ea; --line-strong: #c5ccd6;
  --text: #17202b; --text-2: #44505f; --text-3: #5f6b7a;
  --accent: #1d5bb8; --accent-ink: #123e7a; --accent-soft: #d6e4f7; --accent-wash: #eef4fc;
  --good: #0ca30c; --warn: #fab219; --crit: #d03b3b;
  --warn-wash: #fff7e0;
  --sev-critical: #a61b1b; --sev-critical-wash: #fbe9e9;
  --sev-high: #a84300; --sev-high-wash: #fdeee2;
  --sev-medium: #7d5800; --sev-medium-wash: #fdf5dc;
  --sev-low: #1d5bb8; --sev-low-wash: #e8f0fb;
  --sev-info: #4f5b69; --sev-info-wash: #eef1f4;
  --font-sans: system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  --font-mono: ui-monospace, "Cascadia Mono", "SF Mono", Consolas, "Liberation Mono", monospace;
  color-scheme: light;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --bg: #0e131a; --panel: #141a23; --head: #19212c; --line: #253041; --line-strong: #344256;
    --text: #e4e9f0; --text-2: #b3bdca; --text-3: #93a0b1;
    --accent: #6ea8ff; --accent-ink: #cfe0ff; --accent-soft: #1e3a5f;
    --accent-wash: rgba(110, 168, 255, 0.10); --warn-wash: rgba(250, 178, 25, 0.10);
    --sev-critical: #ff8a80; --sev-critical-wash: rgba(208, 59, 59, 0.18);
    --sev-high: #ffb27a; --sev-high-wash: rgba(229, 112, 26, 0.18);
    --sev-medium: #f5cf6b; --sev-medium-wash: rgba(250, 178, 25, 0.15);
    --sev-low: #8fb8ff; --sev-low-wash: rgba(110, 168, 255, 0.15);
    --sev-info: #b3bdca; --sev-info-wash: rgba(179, 189, 202, 0.12);
    color-scheme: dark;
  }
}
:root[data-theme="dark"] {
  --bg: #0e131a; --panel: #141a23; --head: #19212c; --line: #253041; --line-strong: #344256;
  --text: #e4e9f0; --text-2: #b3bdca; --text-3: #93a0b1;
  --accent: #6ea8ff; --accent-ink: #cfe0ff; --accent-soft: #1e3a5f;
  --accent-wash: rgba(110, 168, 255, 0.10); --warn-wash: rgba(250, 178, 25, 0.10);
  --sev-critical: #ff8a80; --sev-critical-wash: rgba(208, 59, 59, 0.18);
  --sev-high: #ffb27a; --sev-high-wash: rgba(229, 112, 26, 0.18);
  --sev-medium: #f5cf6b; --sev-medium-wash: rgba(250, 178, 25, 0.15);
  --sev-low: #8fb8ff; --sev-low-wash: rgba(110, 168, 255, 0.15);
  --sev-info: #b3bdca; --sev-info-wash: rgba(179, 189, 202, 0.12);
  color-scheme: dark;
}
"""

#: The print colors, inside ``@media print``. The selector outranks ``:root[data-theme]``.
PRINT_TOKENS: Final = """  :root:not([data-print]):not([data-x]) {
    --bg: #ffffff; --panel: #ffffff; --head: #f4f5f7; --line: #d5d9de; --line-strong: #aab2bd;
    --text: #000000; --text-2: #222222; --text-3: #444444; --accent: #123e7a;
    --accent-wash: transparent; --warn-wash: #fff7e0;
    --sev-critical: #8a1010; --sev-high: #8a3800; --sev-medium: #6b4b00; --sev-low: #123e7a;
    --sev-info: #333333; color-scheme: light;
  }
"""

CSS: Final = (
    TOKENS
    + """* { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }
body {
  margin: 0; background: var(--bg); color: var(--text); font-family: var(--font-sans);
  font-size: 15px; line-height: 1.55;
  padding: 24px 16px 48px;
  padding-left: max(16px, env(safe-area-inset-left, 0px));
  padding-right: max(16px, env(safe-area-inset-right, 0px));
}
a { color: var(--accent); }
a:focus-visible, button:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
p { margin: 10px 0 0; max-width: 92ch; }
code, .mono { font-family: var(--font-mono); font-size: 0.86em; overflow-wrap: anywhere; }
.layout {
  max-width: 1320px; margin-inline: auto; display: grid; grid-template-columns: minmax(0, 1fr);
  gap: 20px;
}
@media (min-width: 1120px) { .layout { grid-template-columns: 232px minmax(0, 1fr); gap: 28px; } }
.toc {
  align-self: start; background: var(--panel); border: 1px solid var(--line); padding: 14px;
  font-size: 13.5px; min-width: 0;
}
@media (min-width: 1120px) { .toc { position: sticky; top: 24px; } }
.toc-doc {
  font-family: var(--font-mono); font-size: 11.5px; color: var(--text-3); padding: 0 8px 10px;
  border-bottom: 1px solid var(--line); margin-bottom: 8px; overflow-wrap: anywhere;
}
.toc-doc b {
  display: block; color: var(--text); font-family: var(--font-sans); font-size: 13.5px;
  font-weight: 600; margin-top: 2px;
}
.toc ol { list-style: none; margin: 0; padding: 0; display: grid; gap: 1px; }
@media (max-width: 1119px) {
  .toc ol {
    grid-template-columns: repeat(auto-fill, minmax(190px, 1fr));
  }
}
.toc a {
  display: grid; grid-template-columns: 34px minmax(0, 1fr); gap: 4px; padding: 5px 8px;
  text-decoration: none; color: var(--text-2); border-radius: 3px;
}
.toc a span { font-family: var(--font-mono); font-size: 12px; color: var(--text-3); }
.toc a:hover { background: var(--head); color: var(--text); }
.doc {
  background: var(--panel); border: 1px solid var(--line); padding: clamp(18px, 3.2vw, 44px);
  min-width: 0;
}
.doc-head { border-bottom: 2px solid var(--text); padding-bottom: 18px; position: relative; }
.kicker {
  font-family: var(--font-mono); font-size: 12px; color: var(--accent); font-weight: 600;
  letter-spacing: 0.03em; margin: 0; padding-right: 72px; overflow-wrap: anywhere;
}
h1 {
  font-size: clamp(1.45rem, 2.7vw, 2.05rem); font-weight: 700; line-height: 1.2; margin: 6px 0 0;
  letter-spacing: -0.01em; overflow-wrap: anywhere;
}
.subtitle { color: var(--text-2); margin-top: 6px; font-size: 1.02rem; }
.meta {
  margin: 18px 0 0; display: grid; grid-template-columns: repeat(auto-fit, minmax(165px, 1fr));
  gap: 1px; background: var(--line); border: 1px solid var(--line);
}
.meta div { background: var(--panel); padding: 9px 12px; min-width: 0; }
.meta dt {
  font-family: var(--font-mono); font-size: 11px; color: var(--text-3); letter-spacing: 0.03em;
  text-transform: uppercase;
}
.meta dd { margin: 2px 0 0; font-size: 13.5px; font-weight: 500; overflow-wrap: anywhere; }
.theme-toggle {
  position: absolute; top: 0; right: 0; font: inherit; font-size: 12px; color: var(--text-2);
  background: var(--head); border: 1px solid var(--line-strong); border-radius: 3px;
  padding: 3px 9px; cursor: pointer;
}
section { margin-top: 42px; scroll-margin-top: 20px; }
h2 {
  font-size: 1.25rem; font-weight: 700; margin: 0; display: flex; gap: 10px;
  align-items: baseline; padding-bottom: 8px; border-bottom: 1px solid var(--line);
}
h2 .num {
  font-family: var(--font-mono); font-size: 0.95rem; color: var(--accent); font-weight: 600;
  flex: none;
}
h3 { font-size: 1rem; font-weight: 600; margin: 26px 0 0; overflow-wrap: anywhere; }
h3 .num {
  font-family: var(--font-mono); font-size: 0.9rem; color: var(--text-3); margin-right: 6px;
  font-weight: 500;
}
h4 { font-size: 0.92rem; font-weight: 600; margin: 18px 0 0; color: var(--text-2); }
.intro { color: var(--text-2); max-width: 84ch; }
.note { color: var(--text-3); font-size: 13px; max-width: 90ch; }
.kpis {
  display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 1px;
  background: var(--line); border: 1px solid var(--line); margin-top: 16px;
}
.kpi {
  background: var(--panel); padding: 12px 14px; display: grid; gap: 4px; align-content: start;
}
.kpi b { font-size: 1.6rem; font-weight: 600; line-height: 1.1; }
.kpi span { font-size: 13px; color: var(--text-2); }
.kpi.sev-critical b { color: var(--sev-critical); } .kpi.sev-high b { color: var(--sev-high); }
.kpi.sev-medium b { color: var(--sev-medium); } .kpi.sev-low b { color: var(--sev-low); }
.kpi.sev-info b { color: var(--sev-info); }
.callout {
  margin-top: 16px; border: 1px solid var(--line-strong); border-left: 4px solid var(--warn);
  background: var(--warn-wash); padding: 12px 16px; max-width: 92ch;
}
.callout p { margin: 0; }
.callout ul { margin: 8px 0 0; padding-left: 20px; display: grid; gap: 4px; }
.callout.ok { border-left-color: var(--good); background: var(--head); }
.callout.crit { border-left-color: var(--crit); background: var(--sev-critical-wash); }
.callout.crit ol { margin: 8px 0 0; padding-left: 22px; display: grid; gap: 4px; }
.tbl-wrap { overflow-x: auto; margin-top: 14px; border: 1px solid var(--line); max-width: 100%; }
table.tbl { width: 100%; border-collapse: collapse; font-size: 13.5px; }
.tbl th, .tbl td {
  padding: 8px 10px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top;
  overflow-wrap: anywhere;
}
.tbl thead th {
  background: var(--head); color: var(--text-2); font-weight: 600; font-size: 12.5px;
  border-bottom: 1px solid var(--line-strong); white-space: nowrap; vertical-align: bottom;
  overflow-wrap: normal;
}
.tbl tbody th { font-weight: 600; }
.tbl tbody tr:hover > td, .tbl tbody tr:hover > th { background: var(--accent-wash); }
.tbl tr:last-child > * { border-bottom: 0; }
.tbl .num-col { text-align: right; font-family: var(--font-mono); white-space: nowrap; }
.tbl .id {
  font-family: var(--font-mono); font-size: 12.5px; color: var(--text-3); white-space: nowrap;
}
.tbl tfoot th, .tbl tfoot td {
  border-top: 1px solid var(--line-strong); background: var(--head); font-weight: 600;
}
.w-560 { min-width: 560px; } .w-720 { min-width: 720px; } .w-860 { min-width: 860px; }
.sev {
  display: inline-block; padding: 1px 8px; border-radius: 3px; font-size: 12px; font-weight: 600;
  line-height: 1.6; white-space: nowrap;
}
.sev-critical { color: var(--sev-critical); background: var(--sev-critical-wash); }
.sev-high { color: var(--sev-high); background: var(--sev-high-wash); }
.sev-medium { color: var(--sev-medium); background: var(--sev-medium-wash); }
.sev-low { color: var(--sev-low); background: var(--sev-low-wash); }
.sev-info, .sev-none { color: var(--sev-info); background: var(--sev-info-wash); }
.st { display: inline-flex; align-items: center; gap: 6px; white-space: nowrap; }
.st::before { content: ""; width: 8px; height: 8px; border-radius: 50%; flex: none; }
.st-good::before { background: var(--good); } .st-warn::before { background: var(--warn); }
.st-crit::before {
  background: var(--crit); } .st-neutral::before { background: var(--line-strong);
}
.finding {
  margin-top: 30px; padding-top: 18px; border-top: 1px solid var(--line);
  scroll-margin-top: 20px;
}
.finding h3 { margin-top: 0; display: flex; flex-wrap: wrap; gap: 8px; align-items: baseline; }
.facts {
  margin: 14px 0 0; display: grid; grid-template-columns: max-content minmax(0, 1fr);
  gap: 6px 18px; font-size: 14px; border: 1px solid var(--line); background: var(--head);
  padding: 12px 14px;
}
.facts dt {
  font-family: var(--font-mono); font-size: 12px; color: var(--text-3); padding-top: 2px;
}
.facts dd { margin: 0; min-width: 0; overflow-wrap: anywhere; }
@media (max-width: 520px) {
  .facts {
    grid-template-columns: minmax(0, 1fr); gap: 2px;
  }
  .facts dd {
    margin-bottom: 6px;
  }
}
.prose p:first-child { margin-top: 6px; }
.label { font-weight: 600; }
.nw { white-space: nowrap; }
ul.plain, ol.plain {
  margin: 8px 0 0; padding-left: 22px; display: grid; gap: 4px; max-width: 92ch;
}
pre.code {
  margin: 8px 0 0; background: var(--head); border: 1px solid var(--line); padding: 10px 12px;
  overflow-x: auto; font-family: var(--font-mono); font-size: 13px; line-height: 1.45;
  white-space: pre; max-width: 100%;
}
.nt { color: var(--text-3); font-style: italic; font-size: 0.9em; }
footer.foot {
  margin-top: 44px; padding-top: 12px; border-top: 1px solid var(--line);
  font-family: var(--font-mono); font-size: 12px; color: var(--text-3); display: flex;
  flex-wrap: wrap; gap: 6px 22px;
}
footer.foot span { overflow-wrap: anywhere; }
@media print {
"""
    + PRINT_TOKENS
    + """  body { padding: 0; font-size: 10.5pt; background: #ffffff; }
  .toc, .theme-toggle { display: none !important; }
  .layout { display: block; max-width: none; }
  .doc { border: 0; padding: 0; }
  .tbl-wrap { overflow: visible; }
  table.tbl { min-width: 0 !important; font-size: 9.5pt; }
  .tbl tbody tr:hover > td, .tbl tbody tr:hover > th { background: transparent; }
  pre.code { white-space: pre-wrap; overflow-wrap: anywhere; }
  h2, h3, h4 { break-after: avoid; }
  .facts, .callout, tr { break-inside: avoid; }
  a { color: inherit; text-decoration: none; }
}
"""
)

SCRIPT: Final = """
(function () {
  var button = document.getElementById("theme-toggle");
  if (!button) { return; }
  var root = document.documentElement;
  try {
    var saved = window.localStorage.getItem("kalkan-theme");
    if (saved === "light" || saved === "dark") { root.setAttribute("data-theme", saved); }
  } catch (e) {}
  button.hidden = false;
  button.addEventListener("click", function () {
    var current = root.getAttribute("data-theme");
    var dark = current ? current === "dark"
      : window.matchMedia("(prefers-color-scheme: dark)").matches;
    var next = dark ? "light" : "dark";
    root.setAttribute("data-theme", next);
    try { window.localStorage.setItem("kalkan-theme", next); } catch (e) {}
  });
})();
"""


def h(value: object) -> str:
    """Escape untrusted text for HTML text and attribute values."""
    return html.escape(clean(value), quote=True)


def _code(value: object) -> str:
    text = clean(value)
    return f"<code>{h(text)}</code>" if text else ""


def _codes(values: Iterable[object]) -> str:
    return ", ".join(code for code in (_code(value) for value in values) if code)


def _prose(value: object) -> str:
    text = clean(value).strip()
    if not text:
        return ""
    paragraphs = [part for part in re.split(r"\n\s*\n", text) if part.strip()]
    return "".join(
        "<p>" + "<br>".join(h(line.strip()) for line in part.split("\n")) + "</p>"
        for part in paragraphs
    )


def _anchor(value: object, prefix: str) -> str:
    return prefix + _ANCHOR_SAFE.sub("-", clean(value))


def _finding_anchor(finding: Mapping[str, Any], fallback: str) -> str:
    finding_id = finding.get("id")
    return _anchor(finding_id, "f-") if isinstance(finding_id, str) and finding_id else fallback


def finding_anchors(model: ReportModel) -> dict[int, str]:
    """Return the anchor of every finding in ``REPORT.html``, keyed by ``id(finding)``.

    The anchor is ``f-`` and the finding ID, with each character outside ``A-Za-z0-9_-``
    replaced by ``-``. A record without an ID gets ``f-<n>``: its position in the list of
    confirmed, needs_validation and rejected findings, from 1.
    """
    listed = [*model.confirmed, *model.needs_validation, *model.rejected]
    return {
        id(finding): _finding_anchor(finding, f"f-{index}")
        for index, finding in enumerate(listed, start=1)
    }


class _Page:
    def __init__(self, lang: str, run_lang: str, model: ReportModel | None = None) -> None:
        self.lang = lang
        self.run_lang = run_lang
        self.model = model
        self.parts: list[str] = []

    def add(self, markup: str) -> None:
        if markup:
            self.parts.append(markup)

    def tr(self, key: str, **values: object) -> str:
        """A UI string, escaped (UI strings hold backticks for Markdown; they become code)."""
        text = t(self.lang, key, **values)
        escaped = html.escape(text, quote=True)
        return re.sub(r"`([^`]+)`", r"<code>\1</code>", escaped)

    def table(
        self,
        headers: Sequence[str],
        rows: Iterable[Sequence[str]],
        *,
        width: str = "",
        foot: Sequence[str] | None = None,
    ) -> None:
        rows = list(rows)
        if not rows:
            return
        css = f"tbl {width}".strip()
        head = "".join(f'<th scope="col">{cell}</th>' for cell in headers)
        body = "".join(
            "<tr>" + "".join(f"<td>{cell or '—'}</td>" for cell in row) + "</tr>" for row in rows
        )
        tfoot = ""
        if foot:
            tfoot = "<tfoot><tr>" + "".join(f"<td>{cell}</td>" for cell in foot) + "</tr></tfoot>"
        self.add(
            f'<div class="tbl-wrap"><table class="{css}"><thead><tr>{head}</tr></thead>'
            f"<tbody>{body}</tbody>{tfoot}</table></div>"
        )

    def labeled(self, label: str, value: object, *, note: bool = False) -> None:
        body = _prose(value)
        if not body:
            return
        extra = f' <span class="nt">{self.tr("not_translated")}</span>' if note else ""
        self.add(f'<h4>{label}</h4><div class="prose">{body}{extra}</div>')

    def text(self) -> str:
        return "\n".join(self.parts)


def _sev(lang: str, severity: str | None) -> str:
    if not severity:
        return '<span class="sev sev-none">—</span>'
    return f'<span class="sev sev-{h(severity)}">{h(i18n.severity_label(lang, severity))}</span>'


def _verdict(lang: str, verdict: object) -> str:
    css = {"confirmed": "st-crit", "needs_validation": "st-warn"}.get(str(verdict), "st-neutral")
    return f'<span class="st {css}">{h(i18n.verdict_label(lang, verdict))}</span>'


def _engine_status(lang: str, status: str) -> str:
    css = {"ok": "st-good", "skipped": "st-neutral", "failed": "st-crit", "timeout": "st-crit"}
    return (
        f'<span class="st {css.get(status, "st-neutral")}">'
        f"{h(i18n.engine_status_label(lang, status))}</span>"
    )


def _poc_text(lang: str, poc: object) -> str:
    if not isinstance(poc, Mapping):
        return h(t(lang, "poc_none"))
    status = i18n.poc_status_label(lang, poc.get("status"))
    level = i18n.poc_level_label(lang, poc.get("level"))
    return h(f"{status} · {level}" if level else status)


def _location(file: object, line: object) -> str:
    text = clean(file)
    if isinstance(line, int) and not isinstance(line, bool):
        text = f"{text}:{line}"
    return _code(text)


def _class_text(lang: str, slug: object) -> str:
    if not isinstance(slug, str) or not slug:
        return "—"
    return f"{h(class_title(slug, lang))} ({_code(slug)})"


# ---------------------------------------------------------------------------------------------
# Sections


def _toc(page: _Page, model: ReportModel) -> str:
    lang = page.lang
    items = [
        ("1", "summary", "sec_summary"),
        ("2", "scope", "sec_scope"),
        ("3", "confirmed", "sec_confirmed"),
        ("4", "needs-validation", "sec_needs_validation"),
        ("5", "rejected", "sec_rejected"),
        ("6", "hardening", "sec_hardening"),
        ("7", "tool-results", "sec_tool_results"),
        ("8", "sca", "sec_sca"),
        (t(lang, "appendix_short"), "appendix", "sec_appendix"),
    ]
    links = "".join(
        f'<li><a href="#{anchor}"><span>{h(num)}</span>{h(t(lang, key))}</a></li>'
        for num, anchor, key in items
    )
    return (
        f'<aside class="toc" aria-label="{h(t(lang, "contents"))}">'
        f'<div class="toc-doc">{h(model.run_id)}<b>{h(t(lang, "doc_title"))}</b></div>'
        f"<ol>{links}</ol></aside>"
    )


def _header(page: _Page, model: ReportModel) -> None:
    lang = page.lang
    name = clean(model.target_source).rstrip("/").rsplit("/", 1)[-1]
    title = t(lang, "doc_title") + (f": {name}" if name else "")
    status = (
        t(lang, "status_complete")
        if model.complete
        else t(lang, "status_incomplete")
        if model.state_available
        else t(lang, "status_unknown")
    )
    kind = {"path": t(lang, "kind_path"), "git": t(lang, "kind_git")}.get(model.target_kind, "")
    meta = [
        ("meta_run_id", _code(model.run_id)),
        ("meta_target", _code(model.target_source)),
        ("meta_target_kind", h(kind)),
        ("meta_git_ref", _code(model.git_ref or "")),
        ("meta_profile", h(i18n.profile_label(lang, model.profile))),
        ("meta_lang", h(model.run_lang)),
        ("meta_created", h(fmt_ts(model.created_at))),
        ("meta_updated", h(fmt_ts(model.updated_at))),
        ("meta_generated", h(fmt_ts(model.generated_at))),
        ("meta_phase", h(i18n.phase_label(lang, model.phase))),
        ("meta_status", h(status)),
    ]
    if model.tech:
        meta.append(("meta_tech", _codes(model.tech)))
    cells = "".join(
        f"<div><dt>{h(t(lang, key))}</dt><dd>{value or '—'}</dd></div>" for key, value in meta
    )
    page.add(
        '<header class="doc-head">'
        f'<button type="button" class="theme-toggle" id="theme-toggle" hidden>'
        f"{h(t(lang, 'theme_toggle'))}</button>"
        f'<p class="kicker">{h(t(lang, "doc_kicker"))} · {h(model.run_id)}</p>'
        f"<h1>{h(title)}</h1>"
        f'<p class="subtitle">{h(t(lang, "doc_subtitle"))}</p>'
        f'<dl class="meta">{cells}</dl></header>'
    )


def _section_start(page: _Page, anchor: str, num: str, key: str) -> None:
    page.add(
        f'<section id="{anchor}" aria-labelledby="h-{anchor}">'
        f'<h2 id="h-{anchor}"><span class="num">{h(num)}</span>{h(t(page.lang, key))}</h2>'
    )


def _summary(page: _Page, model: ReportModel) -> None:
    lang = page.lang
    _section_start(page, "summary", "1", "sec_summary")
    verdicts = model.verdict_counts()
    sentences = []
    if not model.findings_available:
        sentences.append(page.tr("summary_findings_missing"))
    if verdicts["confirmed"]:
        sentences.append(page.tr("summary_confirmed", n=verdicts["confirmed"]))
        highest = model.highest_severity()
        if highest:
            sentences.append(page.tr("summary_highest", label=i18n.severity_label(lang, highest)))
    else:
        sentences.append(page.tr("summary_confirmed_none"))
    if verdicts["needs_validation"]:
        sentences.append(page.tr("summary_needs_validation", n=verdicts["needs_validation"]))
    if verdicts["rejected"]:
        sentences.append(page.tr("summary_rejected", n=verdicts["rejected"]))
    if model.tool_results:
        sentences.append(page.tr("summary_tool_results", n=len(model.tool_results)))
    malicious = model.sca_malicious()
    if malicious:
        sentences.append(page.tr("summary_malicious", n=len(malicious)))
    if model.sca:
        sentences.append(page.tr("summary_sca", n=len(model.sca), reachable=model.sca_reachable()))
    if model.unvalidated:
        sentences.append(page.tr("summary_unvalidated", n=len(model.unvalidated)))
    if model.duplicates:
        sentences.append(page.tr("summary_duplicates", n=len(model.duplicates)))
    page.add(f'<p class="intro">{" ".join(sentences)}</p>')
    severities = model.severity_counts()
    cards = "".join(
        f'<div class="kpi{f" sev-{name}" if severities[name] else ""}">'
        f"<b>{severities[name]}</b>"
        f"<span>{h(i18n.severity_label(lang, name))}</span></div>"
        for name in SEVERITY_ORDER
    )
    page.add(f'<div class="kpis" aria-label="{h(t(lang, "f_severity"))}">{cards}</div>')
    counts = [
        ("kpi_confirmed", verdicts["confirmed"]),
        ("kpi_needs_validation", verdicts["needs_validation"]),
        ("kpi_rejected", verdicts["rejected"]),
        ("kpi_tool_results", len(model.tool_results)),
        ("kpi_sca", len(model.sca)),
    ]
    if malicious:
        counts.append(("kpi_sca_malicious", len(malicious)))
    cards = "".join(
        f'<div class="kpi{" sev-critical" if key == "kpi_sca_malicious" else ""}">'
        f"<b>{count}</b><span>{h(t(lang, key))}</span></div>"
        for key, count in counts
    )
    page.add(f'<div class="kpis">{cards}</div>')
    page.add(f'<p class="note">{page.tr("kpi_severity_note")}</p>')
    if model.partial_reasons:
        page.add(
            f'<div class="callout"><p><b>{h(t(lang, "partial_title"))}.</b> '
            f"{page.tr('summary_partial')}</p></div>"
        )
    listed = [*model.confirmed, *model.needs_validation, *model.rejected]
    if listed:
        page.add(f'<h3><span class="num">1.1</span>{h(t(lang, "sub_findings_table"))}</h3>')
        anchors = finding_anchors(model)
        rows = []
        for finding in listed:
            title, _ = localized(finding, "title", lang, model.run_lang)
            anchor = anchors[id(finding)]
            rows.append(
                (
                    f'<a class="id" href="#{anchor}">{h(finding.get("id", ""))}</a>',
                    h(title),
                    _sev(lang, severity_of(finding)),
                    _verdict(lang, finding["verdict"]),
                    _code(location_of(finding)),
                )
            )
        page.table(
            [
                h(t(lang, key))
                for key in ("col_id", "col_title", "col_severity", "col_verdict", "col_location")
            ],
            rows,
            width="w-720",
        )
    if model.unvalidated:
        _unvalidated(page, model, "1.2" if listed else "1.1")
    page.add("</section>")


def _unvalidated(page: _Page, model: ReportModel, number: str) -> None:
    """List the hunter candidates without a verify task (Cloudflare incomplete-run rule)."""
    lang = page.lang
    page.add(f'<h3><span class="num">{number}</span>{h(t(lang, "sub_unvalidated"))}</h3>')
    page.add(f'<div class="callout"><p>{page.tr("unvalidated_intro")}</p></div>')
    rows = []
    for row in model.unvalidated:
        suggested = " / ".join(
            i18n.severity_label(lang, value) or "—" for value in (row.impact, row.likelihood)
        )
        rows.append(
            (
                _code(row.fingerprint),
                h(row.title),
                _class_text(lang, row.slug),
                h(suggested if row.impact or row.likelihood else "—"),
                _location(row.file, row.line),
                h("; ".join(row.units)) if row.units else "—",
            )
        )
    page.table(
        [
            h(t(lang, key))
            for key in (
                "col_fingerprint",
                "col_title",
                "col_class",
                "col_suggested",
                "col_location",
                "col_units",
            )
        ],
        rows,
    )


def _scope(page: _Page, model: ReportModel) -> None:
    lang = page.lang
    _section_start(page, "scope", "2", "sec_scope")
    if model.partial_reasons:
        items = []
        for key, values in model.partial_reasons:
            shown = dict(values)
            if key == "partial_not_done":
                shown["phase"] = i18n.phase_label(lang, values.get("phase"))
            items.append(f"<li>{page.tr(key, **{k: clean(v) for k, v in shown.items()})}</li>")
        page.add(
            f'<div class="callout"><p><b>{h(t(lang, "partial_title"))}.</b> '
            f"{page.tr('partial_intro')}</p><ul>{''.join(items)}</ul></div>"
        )
    else:
        page.add(f'<div class="callout ok"><p>{page.tr("partial_full")}</p></div>')

    page.add(f'<h3><span class="num">2.1</span>{h(t(lang, "sub_profile_budget"))}</h3>')
    parts = []
    if model.profile:
        parts.append(page.tr("scope_profile", profile=i18n.profile_label(lang, model.profile)))
    if model.budget:
        parts.append(page.tr("scope_budget", used=model.budget["used"], max=model.budget["max"]))
    else:
        parts.append(page.tr("scope_budget_missing"))
    page.add(f"<p>{' '.join(parts)}</p>")

    page.add(f'<h3><span class="num">2.2</span>{h(t(lang, "sub_phases"))}</h3>')
    if model.phases:
        page.table(
            [h(t(lang, k)) for k in ("col_phase", "col_status", "col_started", "col_finished")],
            [
                (
                    h(i18n.phase_label(lang, phase["name"])),
                    h(i18n.phase_status_label(lang, phase["status"])),
                    h(fmt_ts(phase["started_at"])),
                    h(fmt_ts(phase["finished_at"])),
                )
                for phase in model.phases
            ],
            width="w-560",
        )
    else:
        page.add(f'<p class="note">{page.tr("phases_missing")}</p>')

    page.add(f'<h3><span class="num">2.3</span>{h(t(lang, "sub_engines"))}</h3>')
    if model.engines:
        page.table(
            [
                h(t(lang, k))
                for k in (
                    "col_engine",
                    "col_group",
                    "col_status",
                    "col_version",
                    "col_duration",
                    "col_message",
                )
            ],
            [
                (
                    _code(engine.engine),
                    h(t(lang, "group_scans") if engine.group == "scans" else t(lang, "group_sca")),
                    _engine_status(lang, engine.status),
                    _code(engine.tool_version or ""),
                    h(t(lang, "seconds", s=f"{engine.duration_seconds:.1f}"))
                    if engine.duration_seconds is not None
                    else "",
                    h(engine.message),
                )
                for engine in model.engines
            ],
            width="w-720",
        )
    else:
        page.add(f'<p class="note">{page.tr("engines_missing")}</p>')

    page.add(f'<h3><span class="num">2.4</span>{h(t(lang, "sub_ledger"))}</h3>')
    if model.ledger is None:
        page.add(f'<p class="note">{page.tr("ledger_missing")}</p>')
    elif not model.ledger:
        page.add(f'<p class="note">{page.tr("ledger_empty")}</p>')
    else:
        page.table(
            [h(t(lang, "col_ledger_status")), h(t(lang, "col_count"))],
            [
                (h(i18n.ledger_status_label(lang, status)), f'<span class="mono">{count}</span>')
                for status, count in model.ledger.items()
            ],
            foot=[h(t(lang, "col_total")), f'<span class="mono">{model.ledger_total}</span>'],
        )
        if model.ledger_sibling_closed:
            closed = page.tr("ledger_sibling_closed", n=model.ledger_sibling_closed)
            page.add(f'<p class="note">{closed}</p>')
    if model.profile == "fast":
        page.add(f"<p><strong>{page.tr('f_review')}.</strong> {page.tr('review_fast')}</p>")
    elif model.findings_available:
        counts = page.tr("review_counts", **model.review_counts())
        page.add(f"<p><strong>{page.tr('f_review')}.</strong> {counts}</p>")

    page.add(f'<h3><span class="num">2.5</span>{h(t(lang, "sub_missing"))}</h3>')
    if model.missing:
        page.add(f'<p class="note">{page.tr("missing_intro")}</p>')
        page.add(
            '<ul class="plain">'
            + "".join(f"<li>{_code(name)}</li>" for name in model.missing)
            + "</ul>"
        )
    else:
        page.add(f'<p class="note">{page.tr("missing_none")}</p>')
    if model.has_coverage_gaps:
        _gaps(page, model)
    page.add("</section>")


def _ui_text(text: str) -> str:
    """Escape a UI text and turn its backtick spans into code (as :meth:`_Page.tr`)."""
    return re.sub(r"`([^`]+)`", r"<code>\1</code>", html.escape(text, quote=True))


def _path_list(page: _Page, paths: Sequence[str], total: int) -> None:
    if paths:
        page.add('<ul class="plain">' + "".join(f"<li>{_code(p)}</li>" for p in paths) + "</ul>")
    if total > len(paths):
        page.add(f'<p class="note">{page.tr("gaps_more", n=total - len(paths))}</p>')


def _gaps(page: _Page, model: ReportModel) -> None:
    lang = page.lang
    page.add(f'<h3><span class="num">2.6</span>{h(t(lang, "sub_gaps"))}</h3>')
    page.add(f'<div class="callout"><p>{page.tr("gaps_intro")}</p></div>')
    if model.unchecked_manifests:
        page.add(f"<p>{page.tr('gaps_manifests')}</p>")
        rows = []
        for item in model.unchecked_manifests:
            key = manifest_reason_key(item.reason)
            rows.append(
                (
                    _code(item.file),
                    h(item.ecosystem),
                    ""
                    if item.exact_pins is None
                    else f'<span class="mono">{item.exact_pins}</span>',
                    "" if item.ranges is None else f'<span class="mono">{item.ranges}</span>',
                    h(t(lang, key) if key else item.reason),
                )
            )
        page.table(
            [
                h(t(lang, k))
                for k in ("col_file", "col_ecosystem", "col_exact_pins", "col_ranges", "col_reason")
            ],
            rows,
            width="w-860",
        )
    if model.database_gaps:
        page.add(f"<p>{page.tr('gaps_databases')}</p>")
        page.table(
            [h(t(lang, k)) for k in ("col_engine", "col_ecosystem", "col_reason")],
            [
                (_code(item.engine), h(item.ecosystem or t(lang, "gaps_db_all")), h(item.reason))
                for item in model.database_gaps
            ],
            width="w-860",
        )
    for gap in model.scan_gaps:
        if gap.partial_count:
            text = page.tr(
                "gaps_partial",
                engine="`" + clean(gap.engine).replace("`", "") + "`",
                n=gap.partial_count,
            )
            page.add(f"<p>{text}</p>")
            _path_list(page, gap.partial_paths, gap.partial_count)
        if gap.skipped_count:
            text = page.tr(
                "gaps_skipped",
                engine="`" + clean(gap.engine).replace("`", "") + "`",
                n=gap.skipped_count,
            )
            page.add(f"<p>{text}</p>")
            page.add(
                '<ul class="plain">'
                + "".join(f"<li>{h(reason)}: {count}</li>" for reason, count in gap.skipped_reasons)
                + "</ul>"
            )
            _path_list(page, gap.skipped_paths, gap.skipped_count)
        if gap.package_count:
            line, fix = i18n.package_gap_keys(gap.engine)
            text = page.tr(
                line,
                engine="`" + clean(gap.engine).replace("`", "") + "`",
                n=gap.package_count,
            )
            page.add(f"<p>{text}</p>")
            reasons = (
                _ui_text(i18n.package_reason(lang, item.missing_imports, gap.packages_local))
                for item in gap.packages
            )
            page.add(
                '<ul class="plain">'
                + "".join(
                    f"<li>{_code(item.package)}: {reason}</li>"
                    for item, reason in zip(gap.packages, reasons, strict=True)
                )
                + "</ul>"
            )
            if gap.package_count > len(gap.packages):
                more = page.tr("gaps_packages_more", n=gap.package_count - len(gap.packages))
                page.add(f'<p class="note">{more}</p>')
            if fix:
                page.add(f"<p>{page.tr(fix)}</p>")
    if model.long_paths:
        info = model.long_paths
        parts = [page.tr("gaps_long_paths", n=info["count"], limit=info["limit"])]
        enabled = info.get("long_paths_enabled")
        if enabled is not None:
            value = t(lang, "value_on" if enabled else "value_off")
            parts.append(page.tr("gaps_long_paths_registry", value=value))
        parts.append(page.tr("gaps_long_paths_fix"))
        page.add(f"<p>{' '.join(parts)}</p>")
        if not any(gap.engine == "opengrep" for gap in model.scan_gaps):
            _path_list(page, info["paths"][:20], info["count"])


def _facts(page: _Page, finding: Mapping[str, Any]) -> None:
    lang = page.lang
    rows = [("f_id", _code(finding.get("id", "")))]
    severity = finding.get("severity")
    if isinstance(severity, Mapping):
        detail = t(
            lang,
            "f_severity_detail",
            overall=i18n.severity_label(lang, severity.get("overall_severity")),
            likelihood=i18n.severity_label(lang, (severity.get("likelihood") or {}).get("score")),
            impact=i18n.severity_label(lang, (severity.get("impact") or {}).get("score")),
        )
        rows.append(("f_severity", h(detail)))
    cvss = finding.get("cvss")
    if isinstance(cvss, Mapping):
        rows.append(("f_cvss", f"{h(cvss.get('score'))} · {_code(cvss.get('vector'))}"))
    confidence = finding.get("confidence")
    if isinstance(confidence, Mapping):
        rows.append(("f_confidence", h(i18n.confidence_label(lang, confidence.get("score")))))
    rows.append(("f_class", _class_text(lang, finding.get("class"))))
    rows.append(("f_cwe", h(", ".join(finding.get("cwe") or [])) or "—"))
    if finding.get("owasp"):
        rows.append(("f_owasp", h(", ".join(finding["owasp"]))))
    rows.append(("f_location", _code(location_of(finding)) or "—"))
    rows.append(("f_engines", _codes(finding.get("engines") or []) or "—"))
    review = finding.get("review")
    if isinstance(review, Mapping):
        label = h(i18n.review_label(lang, review.get("decision")))
        rows.append(("f_review", f"{label}: {h(review.get('reason'))}"))
    else:
        rows.append(("f_review", h(t(lang, "review_none"))))
    related = _related(page, finding)
    if related:
        rows.append(("f_related", related))
    if finding.get("candidates"):
        rows.append(("f_candidates", _codes(finding["candidates"])))
    rows.append(("f_poc", _poc_text(lang, finding.get("poc"))))
    rows.append(
        ("f_runtime", h(i18n.runtime_validation(lang, finding.get("poc"), finding.get("related"))))
    )
    scope = page.model.scope_of(finding) if page.model else None
    if scope:
        rows.append(("f_deploy", h(t(lang, f"deploy_scope_{scope}"))))
    sca = finding.get("sca")
    if isinstance(sca, Mapping):
        rows.append(
            (
                "f_sca",
                f"{_code(sca.get('package'))} {_code(sca.get('version'))} · "
                f"{h(i18n.reachability_label(lang, sca.get('reachability')))}",
            )
        )
    rows.append(("f_fingerprint", _code(finding.get("fingerprint", ""))))
    cells = "".join(f"<dt>{h(t(lang, key))}</dt><dd>{value}</dd>" for key, value in rows)
    page.add(f'<dl class="facts">{cells}</dl>')


def _related(page: _Page, finding: Mapping[str, Any]) -> str:
    """Return the records that consolidation folded into ``finding`` as links to the appendix."""
    items = finding.get("related")
    parts = []
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, Mapping):
            continue
        record = page.model.finding_by_id(item.get("id")) if page.model else None
        title = (
            localized(record, "title", page.lang, page.run_lang)[0]
            if record is not None
            else clean(item.get("title"))
        )
        anchor = _anchor(item.get("id"), "f-")
        parts.append(f'<a class="id" href="#{h(anchor)}">{h(item.get("id"))}</a> {h(title)}')
    return "; ".join(parts)


def _trace_and_evidence(page: _Page, finding: Mapping[str, Any]) -> None:
    lang = page.lang
    trace = finding.get("trace") or []
    if trace:
        page.add(f"<h4>{h(t(lang, 'f_trace'))}</h4>")
        page.table(
            [
                h(t(lang, k))
                for k in ("col_step", "col_kind", "col_location", "col_scope", "col_description")
            ],
            [
                (
                    f'<span class="mono">{index}</span>',
                    h(i18n.trace_kind_label(lang, step.get("kind"))),
                    _location(step.get("file"), step.get("line")),
                    _code(step.get("scope", "")),
                    h(step.get("description")),
                )
                for index, step in enumerate(trace, start=1)
            ],
            width="w-720",
        )
    evidence = finding.get("evidence") or []
    if evidence:
        page.add(f"<h4>{h(t(lang, 'f_evidence'))}</h4>")
        page.add(
            '<ul class="plain">'
            + "".join(
                f"<li>{_location(item.get('file'), item.get('line'))}: "
                f"{h(item.get('description'))}</li>"
                for item in evidence
            )
            + "</ul>"
        )


def _answers(page: _Page, finding: Mapping[str, Any]) -> None:
    lang = page.lang
    answers = finding.get("audit_answers")
    if not isinstance(answers, Mapping):
        return
    rows = []
    for question in ("attacker_control", "privilege_boundary", "unmitigated"):
        answer = answers.get(question)
        if not isinstance(answer, Mapping):
            continue
        quotes = "<br>".join(
            f"{_location(item.get('file'), item.get('line'))} {_code(item.get('quote'))}"
            for item in answer.get("evidence") or []
        )
        rows.append(
            (
                h(i18n.question_label(lang, question)),
                f'<span class="nw">{h(i18n.answer_label(lang, answer.get("status")))}</span>',
                h(answer.get("reason")),
                quotes,
            )
        )
    if rows:
        page.add(f"<h4>{h(t(lang, 'f_answers'))}</h4>")
        page.table(
            [h(t(lang, k)) for k in ("col_question", "col_answer", "col_reason", "col_quotes")],
            rows,
            width="w-860",
        )


def _poc_block(page: _Page, finding: Mapping[str, Any]) -> None:
    lang = page.lang
    poc = finding.get("poc")
    if not isinstance(poc, Mapping):
        return
    page.labeled(
        f"{h(t(lang, 'f_poc_detail'))} ({_poc_text(lang, poc)})",
        i18n.poc_observed(lang, poc.get("observed_result")),
    )
    artifacts = poc.get("artifacts") or []
    if artifacts:
        page.add(f'<p class="note">{h(t(lang, "f_poc_artifacts"))}: {_codes(artifacts)}</p>')


def _finding_heading(page: _Page, number: str, finding: Mapping[str, Any], badge: str) -> None:
    title, note = localized(finding, "title", page.lang, page.run_lang)
    extra = f' <span class="nt">{page.tr("not_translated")}</span>' if note else ""
    page.add(f'<h3><span class="num">{h(number)}</span>{badge}<span>{h(title)}</span>{extra}</h3>')


def _confirmed_finding(page: _Page, number: str, anchor: str, finding: Mapping[str, Any]) -> None:
    lang = page.lang
    page.add(f'<article class="finding" id="{h(anchor)}">')
    _finding_heading(page, number, finding, _sev(lang, severity_of(finding)))
    _facts(page, finding)
    description, note = localized(finding, "description", lang, page.run_lang)
    page.labeled(h(t(lang, "f_description")), description, note=note)
    page.labeled(h(t(lang, "f_root_cause")), finding.get("root_cause"))
    page.labeled(h(t(lang, "f_intended")), finding.get("intended_behavior"))
    _trace_and_evidence(page, finding)
    _answers(page, finding)
    conditions = finding.get("conditions") or []
    if conditions:
        page.add(f"<h4>{h(t(lang, 'f_conditions'))}</h4>")
        page.add(
            '<ul class="plain">'
            + "".join(
                f'<li><span class="label">{h(i18n.condition_label(lang, item.get("kind")))}'
                f"</span>: {h(item.get('description'))}</li>"
                for item in conditions
            )
            + "</ul>"
        )
    execution = finding.get("execution")
    if isinstance(execution, Mapping):
        page.labeled(
            f"{h(t(lang, 'f_execution'))}: {h(t(lang, 'f_attacker'))}",
            execution.get("attacker_perspective"),
        )
        steps = execution.get("instructions") or []
        if steps:
            page.add(f"<h4>{h(t(lang, 'f_steps'))}</h4>")
            page.add(
                '<ol class="plain">' + "".join(f"<li>{h(step)}</li>" for step in steps) + "</ol>"
            )
        payloads = execution.get("payloads") or []
        if payloads:
            page.add(f"<h4>{h(t(lang, 'f_payloads'))}</h4>")
            for payload in payloads:
                page.add(f'<pre class="code"><code>{h(payload)}</code></pre>')
        page.labeled(h(t(lang, "f_observed")), execution.get("observed_result"))
    _poc_block(page, finding)
    strategy, note = localized(finding, "remediation_strategy", lang, page.run_lang)
    page.labeled(h(t(lang, "f_remediation")), strategy, note=note)
    remediation = finding.get("remediation")
    if isinstance(remediation, Mapping):
        for change in remediation.get("code_changes") or []:
            page.add(
                f'<p class="note">{page.tr("f_code_change", file="")}'
                f"{_code(change.get('file_name'))}</p>"
            )
            page.add(f'<pre class="code"><code>{h(change.get("fixed_code"))}</code></pre>')
    page.add("</article>")


def _needs_validation_finding(
    page: _Page, number: str, anchor: str, finding: Mapping[str, Any]
) -> None:
    lang = page.lang
    page.add(f'<article class="finding" id="{h(anchor)}">')
    _finding_heading(page, number, finding, _verdict(lang, "needs_validation"))
    _facts(page, finding)
    description, note = localized(finding, "description", lang, page.run_lang)
    page.labeled(h(t(lang, "f_description")), description, note=note)
    page.labeled(h(t(lang, "f_claimed_root_cause")), finding.get("claimed_root_cause"))
    blockers = finding.get("blockers") or []
    if blockers:
        page.add(f"<h4>{h(t(lang, 'f_blockers'))}</h4>")
        items = []
        for blocker in blockers:
            text = clean(blocker)
            if not _CODE_LIKE.fullmatch(text):
                items.append(f"<li>{h(text)}</li>")
                continue
            note = i18n.blocker_note(lang, text)
            items.append(f"<li>{_code(text)}{': ' + h(note) if note else ''}</li>")
        page.add('<ul class="plain">' + "".join(items) + "</ul>")
    plan = finding.get("validation_plan")
    if isinstance(plan, Mapping):
        items = []
        if plan.get("local"):
            items.append(
                f'<li><span class="label">{h(t(lang, "f_plan_local"))}</span>: '
                f"{h(plan['local'])}</li>"
            )
        if plan.get("deployment"):
            items.append(
                f'<li><span class="label">{h(t(lang, "f_plan_deployment"))}</span>: '
                f"{h(plan['deployment'])}</li>"
            )
        if items:
            page.add(f"<h4>{h(t(lang, 'f_validation_plan'))}</h4>")
            page.add('<ul class="plain">' + "".join(items) + "</ul>")
    _trace_and_evidence(page, finding)
    _answers(page, finding)
    _poc_block(page, finding)
    page.add("</article>")


def _findings(page: _Page, model: ReportModel) -> None:
    lang = page.lang
    anchors = finding_anchors(model)

    _section_start(page, "confirmed", "3", "sec_confirmed")
    if model.confirmed:
        page.add(f'<p class="intro">{page.tr("confirmed_intro")}</p>')
        if lang != model.run_lang:
            page.add(f'<p class="note">{page.tr("translation_scope")}</p>')
        for index, finding in enumerate(model.confirmed, start=1):
            _confirmed_finding(page, f"3.{index}", anchors[id(finding)], finding)
    else:
        page.add(f'<p class="note">{page.tr("findings_none_confirmed")}</p>')
    page.add("</section>")

    _section_start(page, "needs-validation", "4", "sec_needs_validation")
    if model.needs_validation:
        page.add(f'<p class="intro">{page.tr("needs_validation_intro")}</p>')
        for index, finding in enumerate(model.needs_validation, start=1):
            _needs_validation_finding(page, f"4.{index}", anchors[id(finding)], finding)
    else:
        page.add(f'<p class="note">{page.tr("findings_none_needs_validation")}</p>')
    page.add("</section>")

    _section_start(page, "rejected", "5", "sec_rejected")
    if model.rejected:
        page.add(f'<p class="intro">{page.tr("rejected_intro")}</p>')
        rows = []
        for finding in model.rejected:
            title, note = localized(finding, "title", lang, model.run_lang)
            extra = f' <span class="nt">{page.tr("not_translated")}</span>' if note else ""
            anchor = anchors[id(finding)]
            rows.append(
                (
                    f'<span class="id" id="{h(anchor)}">{h(finding.get("id", ""))}</span>',
                    h(title) + extra,
                    _code(finding.get("class", "")),
                    _code(location_of(finding)),
                    _rejected_reason(lang, finding),
                )
            )
        page.table(
            [
                h(t(lang, k))
                for k in ("col_id", "col_title", "col_class", "col_location", "col_reason")
            ],
            rows,
            width="w-860",
        )
    else:
        page.add(f'<p class="note">{page.tr("findings_none_rejected")}</p>')
    page.add("</section>")


def _rejected_reason(lang: str, finding: Mapping[str, Any]) -> str:
    review = finding.get("review")
    if isinstance(review, Mapping) and review.get("decision") == "reject":
        return f"<strong>{h(t(lang, 'f_review'))}:</strong> {h(finding.get('reason'))}"
    return h(finding.get("reason"))


def _hardening(page: _Page, model: ReportModel) -> None:
    lang = page.lang
    _section_start(page, "hardening", "6", "sec_hardening")
    if model.hardening:
        page.add(f'<p class="intro">{page.tr("hardening_intro")}</p>')
        page.table(
            [h(t(lang, k)) for k in ("col_title", "col_location", "col_note")],
            [
                (h(note.title), _location(note.file, note.line), h(note.note))
                for note in model.hardening
            ],
            width="w-560",
        )
    else:
        key = "hardening_none" if model.hunt_done else "hardening_missing"
        page.add(f'<p class="note">{page.tr(key)}</p>')
    page.add("</section>")


def _severity_counts(lang: str, items: Iterable[Mapping[str, Any]]) -> str:
    counts = dict.fromkeys(SEVERITY_ORDER, 0)
    for item in items:
        severity = item.get("severity")
        counts[severity if severity in counts else "info"] += 1
    return " ".join(
        f'{_sev(lang, name)} <span class="mono">{count}</span>'
        for name, count in counts.items()
        if count
    )


def _tool_results(page: _Page, model: ReportModel) -> None:
    lang = page.lang
    _section_start(page, "tool-results", "7", "sec_tool_results")
    if not model.candidates_available:
        page.add(f'<p class="note">{page.tr("tool_results_missing")}</p>')
    elif not model.tool_results:
        page.add(f'<p class="note">{page.tr("tool_results_none")}</p>')
    else:
        page.add(f'<div class="callout"><p>{page.tr("tool_results_intro")}</p></div>')
        for index, (engine, items) in enumerate(model.tool_results_by_engine().items(), start=1):
            page.add(
                f'<h3 id="tool-{index}"><span class="num">7.{index}</span>{h(engine)} '
                f'<span class="note">({len(items)})</span></h3>'
            )
            page.add(f"<p>{_severity_counts(lang, items)}</p>")
            shown = items[:MAX_TOOL_ROWS_PER_ENGINE]
            page.table(
                [
                    h(t(lang, k))
                    for k in ("col_severity", "col_rule", "col_title", "col_location", "col_class")
                ],
                [
                    (
                        _sev(
                            lang,
                            item.get("severity") if isinstance(item.get("severity"), str) else None,
                        ),
                        _code(item.get("rule_id")),
                        h(item.get("title")),
                        _location(item.get("file"), item.get("start_line")),
                        _code(item.get("class") or ""),
                    )
                    for item in shown
                ],
                width="w-860",
            )
            if len(items) > len(shown):
                page.add(
                    f'<p class="note">'
                    f"{page.tr('tool_results_truncated', n=len(items) - len(shown))}</p>"
                )
    page.add("</section>")


def _sca(page: _Page, model: ReportModel) -> None:
    lang = page.lang
    _section_start(page, "sca", "8", "sec_sca")
    if model.sca_source is None:
        page.add(f'<p class="note">{page.tr("sca_missing")}</p>')
    else:
        if model.sca_source == "candidates":
            page.add(f'<p class="note">{page.tr("sca_from_candidates")}</p>')
        if model.unchecked_manifests:
            text = page.tr("sca_unchecked", n=len(model.unchecked_manifests))
            page.add(f'<div class="callout"><p>{text}</p></div>')
        malicious = model.sca_malicious()
        records = model.sca_vulnerable()
        if not model.sca:
            page.add(f'<p class="note">{page.tr("sca_none")}</p>')
        if malicious:
            _malicious(page, malicious)
            if records:
                page.add(f'<h3><span class="num">8.2</span>{h(t(lang, "sca_known_title"))}</h3>')
        if records:
            page.add(f'<p class="intro">{page.tr("sca_intro")}</p>')
            pins = sum(1 for record in records if record.pin_source == "manifest")
            if pins:
                page.add(f'<p class="note">{page.tr("sca_pin_note", n=pins)}</p>')
            vendored = [record for record in records if record.vendored_files]
            if vendored:
                files: dict[str, str] = {}
                for record in vendored:
                    for path in record.vendored_files:
                        label = f"{_code(path)} ({_code(f'{record.package} {record.version}')})"
                        files.setdefault(path, label)
                page.add(f'<p class="note">{page.tr("sca_vendored_note", n=len(vendored))}</p>')
                page.add(
                    '<ul class="plain">'
                    + "".join(f"<li>{item}</li>" for item in list(files.values())[:20])
                    + "</ul>"
                )
            reach_css = {"reachable": "st-crit", "not_reachable": "st-good"}
            page.table(
                [
                    h(t(lang, k))
                    for k in (
                        "col_package",
                        "col_version",
                        "col_ecosystem",
                        "col_vuln_ids",
                        "col_severity",
                        "col_fixed",
                        "col_reachability",
                    )
                ],
                [
                    (
                        _code(record.package),
                        _code(record.version) + _pin_badge(lang, record),
                        h(record.ecosystem),
                        _codes(record.ids),
                        _sev(lang, record.severity),
                        _codes(record.fixed_versions),
                        f'<span class="st {reach_css.get(record.reachability, "st-warn")}">'
                        f"{h(i18n.reachability_label(lang, record.reachability))}</span>",
                    )
                    for record in records
                ],
                width="w-860",
            )
        sbom = text_values(model, lang)
        if sbom is not None:
            page.add(f'<p class="note">{page.tr("sca_sbom", **sbom)}</p>')
    page.add("</section>")


#: The malicious package actions (keys ``sca_malicious_action_<n>``).
MALICIOUS_ACTIONS: Final = 4


def _malicious(page: _Page, records: Sequence[ScaRecord]) -> None:
    """The box of the known malicious package versions (ENGINE-SPEC 16), before the ordinary
    SCA table: the reason and the actions in a critical callout, then one row per record."""
    lang = page.lang
    page.add(f'<h3><span class="num">8.1</span>{h(t(lang, "sca_malicious_title"))}</h3>')
    actions = "".join(
        f"<li>{page.tr(f'sca_malicious_action_{index}')}</li>"
        for index in range(1, MALICIOUS_ACTIONS + 1)
    )
    page.add(
        '<div class="callout crit" role="note">'
        f"<p><b>{page.tr('sca_malicious_intro', n=len(records))}</b></p>"
        f"<p>{page.tr('sca_malicious_actions')}</p><ol>{actions}</ol></div>"
    )
    page.table(
        [
            h(t(lang, key))
            for key in (
                "col_package",
                "col_version",
                "col_ecosystem",
                "col_record_ids",
                "col_severity",
                "col_location",
            )
        ],
        [
            (
                _code(record.package),
                _code(record.version) + _pin_badge(lang, record),
                h(record.ecosystem),
                _codes(record.ids),
                _sev(lang, record.severity),
                _codes(record.locations),
            )
            for record in records
        ],
        width="w-860",
    )


def _pin_badge(lang: str, record: ScaRecord) -> str:
    """Return the badge of a record from a manifest pin or a vendored file, else ``""``."""
    if record.pin_source == "manifest":
        return f' <span class="st st-warn">{h(t(lang, "pin_label"))}</span>'
    if record.vendored_files:
        return f' <span class="st st-warn">{h(t(lang, "pin_label_vendored"))}</span>'
    return ""


def _appendix(page: _Page, model: ReportModel) -> None:
    lang = page.lang
    _section_start(page, "appendix", t(lang, "appendix_short"), "sec_appendix")
    page.add(f'<h3><span class="num">A.1</span>{h(t(lang, "sub_method"))}</h3>')
    page.add(
        '<ul class="plain">'
        + "".join(f"<li>{page.tr(f'method_{index}')}</li>" for index in range(1, 7))
        + "</ul>"
    )
    page.add(f'<h3><span class="num">A.2</span>{h(t(lang, "sub_tool_versions"))}</h3>')
    if model.tool_versions:
        page.table(
            [h(t(lang, k)) for k in ("col_tool", "col_version", "col_kind_tool")],
            [(_code(name), _code(version), h(kind)) for name, version, kind in model.tool_versions],
        )
    else:
        page.add(f'<p class="note">{page.tr("tool_versions_missing")}</p>')
    page.add(f'<h3><span class="num">A.3</span>{h(t(lang, "sub_run"))}</h3>')
    rows = [
        (h(t(lang, "meta_run_id")), _code(model.run_id)),
        (h(t(lang, "run_kalkan_version")), _code(model.kalkan_version)),
        (h(t(lang, "meta_generated")), h(fmt_ts(model.generated_at))),
    ]
    if model.outputs:
        rows.append((h(t(lang, "run_report_files")), _codes(model.outputs)))
    page.table([h(t(lang, "meta_field")), h(t(lang, "meta_value"))], rows)
    if model.warnings:
        page.add(f'<h3><span class="num">A.4</span>{h(t(lang, "warnings_title"))}</h3>')
        page.add(
            '<ul class="plain">'
            + "".join(f"<li>{h(warning)}</li>" for warning in model.warnings)
            + "</ul>"
        )
    if model.duplicates:
        _duplicates(page, model, "A.5" if model.warnings else "A.4")
    page.add("</section>")


def _duplicates(page: _Page, model: ReportModel, number: str) -> None:
    """List every record that consolidation folded, with its primary finding and the reason."""
    lang = page.lang
    anchors = finding_anchors(model)
    page.add(f'<h3><span class="num">{h(number)}</span>{h(t(lang, "sub_duplicates"))}</h3>')
    page.add(f'<p class="note">{page.tr("duplicates_intro")}</p>')
    rows = []
    for index, finding in enumerate(model.duplicates, start=1):
        title, note = localized(finding, "title", lang, model.run_lang)
        extra = f' <span class="nt">{page.tr("not_translated")}</span>' if note else ""
        primary = model.finding_by_id(finding.get("duplicate_of"))
        if primary is not None and id(primary) in anchors:
            primary_title = localized(primary, "title", lang, model.run_lang)[0]
            primary_cell = (
                f'<a class="id" href="#{h(anchors[id(primary)])}">'
                f"{h(finding.get('duplicate_of'))}</a> {h(primary_title)}"
            )
        else:
            primary_cell = _code(finding.get("duplicate_of"))
        anchor = _finding_anchor(finding, f"d-{index}")
        rows.append(
            (
                f'<span class="id" id="{h(anchor)}">{h(finding.get("id", ""))}</span>',
                h(title) + extra,
                _code(finding.get("class", "")),
                primary_cell,
                h(finding.get("duplicate_reason")),
            )
        )
    page.table(
        [
            h(t(lang, key))
            for key in ("col_id", "col_title", "col_class", "col_primary", "col_reason")
        ],
        rows,
        width="w-860",
    )


def render_html(model: ReportModel, lang: str = "tr") -> str:
    """Return the self-contained HTML report for ``model`` in ``lang`` (``tr`` or ``en``)."""
    page = _Page(lang, model.run_lang, model)
    _header(page, model)
    _summary(page, model)
    _scope(page, model)
    _findings(page, model)
    _hardening(page, model)
    _tool_results(page, model)
    _sca(page, model)
    _appendix(page, model)
    page.add(
        '<footer class="foot">'
        f"<span>{h(model.run_id)}</span>"
        f"<span>kalkan {h(model.kalkan_version)} · {h(fmt_ts(model.generated_at))}</span>"
        f"<span>{h(t(lang, 'footer_static'))}</span>"
        f"<span>{page.tr('english_hint')}</span>"
        "</footer>"
    )
    title = f"{t(lang, 'doc_title')} · {model.run_id}"
    return (
        "<!doctype html>\n"
        f'<html lang="{h(lang)}">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        '<meta name="color-scheme" content="light dark">\n'
        f'<meta name="generator" content="kalkan {h(model.kalkan_version)}">\n'
        f"<title>{h(title)}</title>\n<style>{CSS}</style>\n</head>\n<body>\n"
        f'<div class="layout">\n{_toc(page, model)}\n<main class="doc">\n'
        f"{page.text()}\n</main>\n</div>\n<script>{SCRIPT}</script>\n</body>\n</html>\n"
    )
