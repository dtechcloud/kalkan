# SPDX-License-Identifier: MIT
"""Markdown report: ``REPORT.md`` (Turkish) and ``REPORT.en.md`` (docs/ENGINE-SPEC.md, 16).

Every text that comes from the target or from an agent is untrusted. The helpers escape it:

- :func:`md_text` for prose: HTML-significant characters become entities (``&``, ``<``,
  ``>``), Markdown punctuation gets a backslash, and line-start block syntax (headings, lists,
  setext lines) is neutralized;
- :func:`md_inline` for one-line contexts such as table cells and headings: newlines become
  spaces and ``|`` is escaped;
- :func:`md_code` for code spans: the fence is longer than any backtick run in the text, and
  ``|`` is escaped inside tables;
- :func:`md_fence` for code blocks: the fence is longer than any backtick run in the text.
"""

from __future__ import annotations

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

__all__ = ["md_code", "md_fence", "md_inline", "md_text", "render_markdown"]

_INLINE_SPECIAL: Final = re.compile(r"([\\`*_\[\]|~$])")
_LINE_START: Final = re.compile(r"^([#+=-])")
_ORDERED: Final = re.compile(r"^(\d+)([.)])")
_BACKTICKS: Final = re.compile(r"`+")
_CODE_LIKE: Final = re.compile(r"[a-z0-9_.:-]+")


def _escape_line(line: str) -> str:
    line = line.strip(" \t")
    line = line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    line = _INLINE_SPECIAL.sub(r"\\\1", line)
    line = _LINE_START.sub(r"\\\1", line)
    return _ORDERED.sub(r"\1\\\2", line)


def md_text(value: object) -> str:
    """Escape untrusted prose for Markdown. Line breaks stay; blank lines are kept as one."""
    lines = clean(value).split("\n")
    out: list[str] = []
    for line in lines:
        escaped = _escape_line(line)
        if escaped or (out and out[-1]):
            out.append(escaped)
    return "\n".join(out).strip("\n")


def md_inline(value: object) -> str:
    """Escape untrusted text for one line (a heading or a table cell)."""
    return _escape_line(" ".join(clean(value).split("\n")))


def md_code(value: object, *, table: bool = False) -> str:
    """Return an inline code span for untrusted text (empty text gives an empty string)."""
    text = " ".join(clean(value).split("\n"))
    if not text:
        return ""
    runs = [len(match) for match in _BACKTICKS.findall(text)]
    fence = "`" * ((max(runs) if runs else 0) + 1)
    if text.startswith(("`", " ")) or text.endswith(("`", " ")):
        text = f" {text} "
    if table:
        text = text.replace("|", "\\|")
    return f"{fence}{text}{fence}"


def md_fence(value: object, info: str = "text") -> str:
    """Return a fenced code block for untrusted text."""
    text = clean(value).rstrip("\n")
    runs = [len(match) for match in _BACKTICKS.findall(text)]
    fence = "`" * max(3, (max(runs) if runs else 0) + 1)
    return f"{fence}{info}\n{text}\n{fence}"


def _paragraphs(value: object) -> list[str]:
    text = md_text(value)
    return [part for part in re.split(r"\n{2,}", text) if part.strip()]


class _Doc:
    """A Markdown document as a list of blocks separated by blank lines."""

    def __init__(self, lang: str, run_lang: str, model: ReportModel | None = None) -> None:
        self.lang = lang
        self.run_lang = run_lang
        self.model = model
        self.blocks: list[str] = []

    def add(self, block: str) -> None:
        if block:
            self.blocks.append(block)

    def labeled(self, label: str, value: object, *, note: bool = False) -> None:
        parts = _paragraphs(value)
        if not parts:
            return
        parts[0] = f"**{label}.** {parts[0]}"
        if note:
            parts[-1] += f" *{t(self.lang, 'not_translated')}*"
        self.blocks.extend(parts)

    def table(self, headers: Sequence[str], rows: Iterable[Sequence[str]]) -> None:
        rows = list(rows)
        if not rows:
            return
        lines = [
            "| " + " | ".join(headers) + " |",
            "|" + "|".join("---" for _ in headers) + "|",
        ]
        lines.extend("| " + " | ".join(cell or "—" for cell in row) + " |" for row in rows)
        self.blocks.append("\n".join(lines))

    def bullets(self, items: Iterable[str]) -> None:
        items = [item for item in items if item]
        if items:
            self.blocks.append("\n".join(f"- {item}" for item in items))

    def text(self) -> str:
        return "\n\n".join(self.blocks) + "\n"


def _join_codes(values: Iterable[object], *, table: bool = True) -> str:
    return ", ".join(code for code in (md_code(v, table=table) for v in values) if code)


def _severity_text(lang: str, severity: str | None) -> str:
    return i18n.severity_label(lang, severity) if severity else "—"


def _poc_text(lang: str, poc: object) -> str:
    if not isinstance(poc, Mapping):
        return t(lang, "poc_none")
    status = i18n.poc_status_label(lang, poc.get("status"))
    level = i18n.poc_level_label(lang, poc.get("level"))
    return f"{status} · {level}" if level else status


def _class_text(lang: str, slug: object) -> str:
    if not isinstance(slug, str) or not slug:
        return "—"
    return f"{md_inline(class_title(slug, lang))} ({md_code(slug, table=True)})"


def _location_code(file: object, line: object) -> str:
    text = clean(file)
    if isinstance(line, int) and not isinstance(line, bool):
        text = f"{text}:{line}"
    return md_code(text, table=True)


# ---------------------------------------------------------------------------------------------
# Sections


def _meta(doc: _Doc, model: ReportModel) -> None:
    lang = doc.lang
    title = t(lang, "doc_title")
    name = clean(model.target_source).rstrip("/").rsplit("/", 1)[-1]
    doc.add(f"# {title}: {md_inline(name)}" if name else f"# {title}")
    status = (
        t(lang, "status_complete")
        if model.complete
        else t(lang, "status_incomplete")
        if model.state_available
        else t(lang, "status_unknown")
    )
    kind = {"path": t(lang, "kind_path"), "git": t(lang, "kind_git")}.get(model.target_kind, "")
    rows = [
        (t(lang, "meta_run_id"), md_code(model.run_id, table=True)),
        (t(lang, "meta_target"), md_code(model.target_source, table=True)),
        (t(lang, "meta_target_kind"), md_inline(kind)),
        (t(lang, "meta_git_ref"), md_code(model.git_ref or "", table=True)),
        (t(lang, "meta_profile"), md_inline(i18n.profile_label(lang, model.profile))),
        (t(lang, "meta_lang"), md_inline(model.run_lang)),
        (t(lang, "meta_created"), md_inline(fmt_ts(model.created_at))),
        (t(lang, "meta_updated"), md_inline(fmt_ts(model.updated_at))),
        (t(lang, "meta_generated"), md_inline(fmt_ts(model.generated_at))),
        (t(lang, "meta_phase"), md_inline(i18n.phase_label(lang, model.phase))),
        (t(lang, "meta_status"), status),
    ]
    if model.tech:
        rows.append((t(lang, "meta_tech"), _join_codes(model.tech)))
    doc.table((t(lang, "meta_field"), t(lang, "meta_value")), rows)


def _summary(doc: _Doc, model: ReportModel) -> None:
    lang = doc.lang
    doc.add(f"## 1. {t(lang, 'sec_summary')}")
    verdicts = model.verdict_counts()
    sentences = []
    if not model.findings_available:
        sentences.append(t(lang, "summary_findings_missing"))
    if verdicts["confirmed"]:
        sentences.append(t(lang, "summary_confirmed", n=verdicts["confirmed"]))
        highest = model.highest_severity()
        if highest:
            sentences.append(t(lang, "summary_highest", label=i18n.severity_label(lang, highest)))
    else:
        sentences.append(t(lang, "summary_confirmed_none"))
    if verdicts["needs_validation"]:
        sentences.append(t(lang, "summary_needs_validation", n=verdicts["needs_validation"]))
    if verdicts["rejected"]:
        sentences.append(t(lang, "summary_rejected", n=verdicts["rejected"]))
    if model.tool_results:
        sentences.append(t(lang, "summary_tool_results", n=len(model.tool_results)))
    malicious = model.sca_malicious()
    if malicious:
        sentences.append(t(lang, "summary_malicious", n=len(malicious)))
    if model.sca:
        sentences.append(t(lang, "summary_sca", n=len(model.sca), reachable=model.sca_reachable()))
    if model.unvalidated:
        sentences.append(t(lang, "summary_unvalidated", n=len(model.unvalidated)))
    if model.duplicates:
        sentences.append(t(lang, "summary_duplicates", n=len(model.duplicates)))
    doc.add(" ".join(sentences))
    if model.partial_reasons:
        doc.add(f"> **{t(lang, 'partial_title')}.** {t(lang, 'summary_partial')}")
    severities = model.severity_counts()
    rows = [(t(lang, "kpi_confirmed"), str(verdicts["confirmed"]))]
    rows += [
        (f"{t(lang, 'f_severity')}: {i18n.severity_label(lang, name)}", str(severities[name]))
        for name in SEVERITY_ORDER
    ]
    rows += [
        (t(lang, "kpi_needs_validation"), str(verdicts["needs_validation"])),
        (t(lang, "kpi_rejected"), str(verdicts["rejected"])),
        (t(lang, "kpi_tool_results"), str(len(model.tool_results))),
        (t(lang, "kpi_sca"), str(len(model.sca))),
    ]
    if malicious:
        rows.append((t(lang, "kpi_sca_malicious"), str(len(malicious))))
    doc.table((t(lang, "count_table_metric"), t(lang, "count_table_count")), rows)
    doc.add(f"*{t(lang, 'kpi_severity_note')}*")
    listed = [*model.confirmed, *model.needs_validation, *model.rejected]
    if listed:
        doc.add(f"### 1.1 {t(lang, 'sub_findings_table')}")
        rows = []
        for finding in listed:
            title, _ = localized(finding, "title", lang, model.run_lang)
            rows.append(
                (
                    md_code(finding.get("id", ""), table=True),
                    md_inline(title),
                    _severity_text(lang, severity_of(finding)),
                    md_inline(i18n.verdict_label(lang, finding["verdict"])),
                    md_code(location_of(finding), table=True),
                )
            )
        doc.table(
            (
                t(lang, "col_id"),
                t(lang, "col_title"),
                t(lang, "col_severity"),
                t(lang, "col_verdict"),
                t(lang, "col_location"),
            ),
            rows,
        )
    if model.unvalidated:
        _unvalidated(doc, model, "1.2" if listed else "1.1")


def _suggested_text(lang: str, impact: str | None, likelihood: str | None) -> str:
    if not impact and not likelihood:
        return "—"
    labels = [i18n.severity_label(lang, value) or "—" for value in (impact, likelihood)]
    return md_inline(" / ".join(labels))


def _unvalidated(doc: _Doc, model: ReportModel, number: str) -> None:
    """List the hunter candidates without a verify task (Cloudflare: the first section of a
    partial report lists every unvalidated fingerprint and its units)."""
    lang = doc.lang
    doc.add(f"### {number} {t(lang, 'sub_unvalidated')}")
    doc.add(t(lang, "unvalidated_intro"))
    doc.table(
        (
            t(lang, "col_fingerprint"),
            t(lang, "col_title"),
            t(lang, "col_class"),
            t(lang, "col_suggested"),
            t(lang, "col_location"),
            t(lang, "col_units"),
        ),
        [
            (
                md_code(row.fingerprint, table=True),
                md_inline(row.title),
                _class_text(lang, row.slug),
                _suggested_text(lang, row.impact, row.likelihood),
                _location_code(row.file, row.line),
                md_inline("; ".join(row.units)) if row.units else "—",
            )
            for row in model.unvalidated
        ],
    )


def _scope(doc: _Doc, model: ReportModel) -> None:
    lang = doc.lang
    doc.add(f"## 2. {t(lang, 'sec_scope')}")
    if model.partial_reasons:
        lines = [f"> **{t(lang, 'partial_title')}.** {t(lang, 'partial_intro')}", ">"]
        for key, values in model.partial_reasons:
            safe = {name: md_inline(value) for name, value in values.items()}
            if key == "partial_not_done":
                safe["phase"] = md_inline(i18n.phase_label(lang, values.get("phase")))
            lines.append(f"> - {t(lang, key, **safe)}")
        doc.add("\n".join(lines))
    else:
        doc.add(t(lang, "partial_full"))

    doc.add(f"### 2.1 {t(lang, 'sub_profile_budget')}")
    parts = []
    if model.profile:
        parts.append(
            t(lang, "scope_profile", profile=md_inline(i18n.profile_label(lang, model.profile)))
        )
    if model.budget:
        parts.append(t(lang, "scope_budget", used=model.budget["used"], max=model.budget["max"]))
    else:
        parts.append(t(lang, "scope_budget_missing"))
    doc.add(" ".join(parts))

    doc.add(f"### 2.2 {t(lang, 'sub_phases')}")
    if model.phases:
        doc.table(
            (
                t(lang, "col_phase"),
                t(lang, "col_status"),
                t(lang, "col_started"),
                t(lang, "col_finished"),
            ),
            [
                (
                    md_inline(i18n.phase_label(lang, phase["name"])),
                    md_inline(i18n.phase_status_label(lang, phase["status"])),
                    md_inline(fmt_ts(phase["started_at"])),
                    md_inline(fmt_ts(phase["finished_at"])),
                )
                for phase in model.phases
            ],
        )
    else:
        doc.add(t(lang, "phases_missing"))

    doc.add(f"### 2.3 {t(lang, 'sub_engines')}")
    if model.engines:
        doc.table(
            (
                t(lang, "col_engine"),
                t(lang, "col_group"),
                t(lang, "col_status"),
                t(lang, "col_version"),
                t(lang, "col_duration"),
                t(lang, "col_message"),
            ),
            [
                (
                    md_code(engine.engine, table=True),
                    t(lang, "group_scans") if engine.group == "scans" else t(lang, "group_sca"),
                    md_inline(i18n.engine_status_label(lang, engine.status)),
                    md_code(engine.tool_version or "", table=True),
                    t(lang, "seconds", s=f"{engine.duration_seconds:.1f}")
                    if engine.duration_seconds is not None
                    else "",
                    md_inline(engine.message),
                )
                for engine in model.engines
            ],
        )
    else:
        doc.add(t(lang, "engines_missing"))

    doc.add(f"### 2.4 {t(lang, 'sub_ledger')}")
    if model.ledger is None:
        doc.add(t(lang, "ledger_missing"))
    elif not model.ledger:
        doc.add(t(lang, "ledger_empty"))
    else:
        rows = [
            (md_inline(i18n.ledger_status_label(lang, status)), str(count))
            for status, count in model.ledger.items()
        ]
        rows.append((f"**{t(lang, 'col_total')}**", f"**{model.ledger_total}**"))
        doc.table((t(lang, "col_ledger_status"), t(lang, "col_count")), rows)
        if model.ledger_sibling_closed:
            doc.add(t(lang, "ledger_sibling_closed", n=model.ledger_sibling_closed))
    _review_note(doc, model)

    doc.add(f"### 2.5 {t(lang, 'sub_missing')}")
    if model.missing:
        doc.add(t(lang, "missing_intro"))
        doc.bullets(md_code(name) for name in model.missing)
    else:
        doc.add(t(lang, "missing_none"))
    if model.has_coverage_gaps:
        _gaps(doc, model)


def _review_note(doc: _Doc, model: ReportModel) -> None:
    lang = doc.lang
    if model.profile == "fast":
        doc.add(f"**{t(lang, 'f_review')}.** {t(lang, 'review_fast')}")
    elif model.findings_available:
        doc.add(f"**{t(lang, 'f_review')}.** {t(lang, 'review_counts', **model.review_counts())}")


def _review_text(lang: str, finding: Mapping[str, Any]) -> str:
    review = finding.get("review")
    if not isinstance(review, Mapping):
        return md_inline(t(lang, "review_none"))
    label = md_inline(i18n.review_label(lang, review.get("decision")))
    return f"{label}: {md_inline(review.get('reason'))}"


def _manifest_reason(lang: str, reason: str) -> str:
    key = manifest_reason_key(reason)
    return t(lang, key) if key else reason


def _path_list(doc: _Doc, paths: Sequence[str], total: int) -> None:
    doc.bullets(md_code(path) for path in paths)
    if total > len(paths):
        doc.add(t(doc.lang, "gaps_more", n=total - len(paths)))


def _gaps(doc: _Doc, model: ReportModel) -> None:
    lang = doc.lang
    doc.add(f"### 2.6 {t(lang, 'sub_gaps')}")
    doc.add(t(lang, "gaps_intro"))
    if model.unchecked_manifests:
        doc.add(t(lang, "gaps_manifests"))
        doc.table(
            (
                t(lang, "col_file"),
                t(lang, "col_ecosystem"),
                t(lang, "col_exact_pins"),
                t(lang, "col_ranges"),
                t(lang, "col_reason"),
            ),
            [
                (
                    md_code(item.file, table=True),
                    md_inline(item.ecosystem),
                    "" if item.exact_pins is None else str(item.exact_pins),
                    "" if item.ranges is None else str(item.ranges),
                    md_inline(_manifest_reason(lang, item.reason)),
                )
                for item in model.unchecked_manifests
            ],
        )
    if model.database_gaps:
        doc.add(t(lang, "gaps_databases"))
        doc.table(
            (t(lang, "col_engine"), t(lang, "col_ecosystem"), t(lang, "col_reason")),
            [
                (
                    md_code(item.engine, table=True),
                    md_inline(item.ecosystem or t(lang, "gaps_db_all")),
                    md_inline(item.reason),
                )
                for item in model.database_gaps
            ],
        )
    for gap in model.scan_gaps:
        engine = md_code(gap.engine)
        if gap.partial_count:
            doc.add(t(lang, "gaps_partial", engine=engine, n=gap.partial_count))
            _path_list(doc, gap.partial_paths, gap.partial_count)
        if gap.skipped_count:
            doc.add(t(lang, "gaps_skipped", engine=engine, n=gap.skipped_count))
            doc.add(f"{t(lang, 'gaps_reasons')}:")
            doc.bullets(f"{md_inline(reason)}: {count}" for reason, count in gap.skipped_reasons)
            if gap.skipped_paths:
                doc.add(f"{t(lang, 'gaps_files')}:")
            _path_list(doc, gap.skipped_paths, gap.skipped_count)
        if gap.package_count:
            line, fix = i18n.package_gap_keys(gap.engine)
            doc.add(t(lang, line, engine=engine, n=gap.package_count))
            doc.bullets(
                f"{md_code(item.package)}: "
                + md_inline(i18n.package_reason(lang, item.missing_imports, gap.packages_local))
                for item in gap.packages
            )
            if gap.package_count > len(gap.packages):
                doc.add(t(lang, "gaps_packages_more", n=gap.package_count - len(gap.packages)))
            if fix:
                doc.add(t(lang, fix))
    if model.long_paths:
        info = model.long_paths
        parts = [t(lang, "gaps_long_paths", n=info["count"], limit=info["limit"])]
        enabled = info.get("long_paths_enabled")
        if enabled is not None:
            value = t(lang, "value_on" if enabled else "value_off")
            parts.append(t(lang, "gaps_long_paths_registry", value=value))
        parts.append(t(lang, "gaps_long_paths_fix"))
        doc.add(" ".join(parts))
        if not any(gap.engine == "opengrep" for gap in model.scan_gaps):
            _path_list(doc, info["paths"][:20], info["count"])


def _trace_and_evidence(doc: _Doc, finding: Mapping[str, Any]) -> None:
    lang = doc.lang
    trace = finding.get("trace") or []
    if trace:
        doc.add(f"**{t(lang, 'f_trace')}**")
        doc.table(
            (
                t(lang, "col_step"),
                t(lang, "col_kind"),
                t(lang, "col_location"),
                t(lang, "col_scope"),
                t(lang, "col_description"),
            ),
            [
                (
                    str(index),
                    md_inline(i18n.trace_kind_label(lang, step.get("kind"))),
                    _location_code(step.get("file"), step.get("line")),
                    md_code(step.get("scope", ""), table=True),
                    md_inline(step.get("description")),
                )
                for index, step in enumerate(trace, start=1)
            ],
        )
    evidence = finding.get("evidence") or []
    if evidence:
        doc.add(f"**{t(lang, 'f_evidence')}**")
        doc.bullets(
            f"{_location_code(item.get('file'), item.get('line'))}: "
            f"{md_inline(item.get('description'))}"
            for item in evidence
        )


def _answers(doc: _Doc, finding: Mapping[str, Any]) -> None:
    lang = doc.lang
    answers = finding.get("audit_answers")
    if not isinstance(answers, Mapping):
        return
    rows = []
    for question in ("attacker_control", "privilege_boundary", "unmitigated"):
        answer = answers.get(question)
        if not isinstance(answer, Mapping):
            continue
        quotes = " · ".join(
            f"{_location_code(item.get('file'), item.get('line'))} "
            f"{md_code(item.get('quote'), table=True)}"
            for item in answer.get("evidence") or []
        )
        rows.append(
            (
                md_inline(i18n.question_label(lang, question)),
                md_inline(i18n.answer_label(lang, answer.get("status"))),
                md_inline(answer.get("reason")),
                quotes,
            )
        )
    if rows:
        doc.add(f"**{t(lang, 'f_answers')}**")
        doc.table(
            (
                t(lang, "col_question"),
                t(lang, "col_answer"),
                t(lang, "col_reason"),
                t(lang, "col_quotes"),
            ),
            rows,
        )


def _deploy_scope(doc: _Doc, finding: Mapping[str, Any]) -> str | None:
    return doc.model.scope_of(finding) if doc.model else None


def _poc_block(doc: _Doc, finding: Mapping[str, Any]) -> None:
    lang = doc.lang
    poc = finding.get("poc")
    if not isinstance(poc, Mapping):
        return
    doc.labeled(
        f"{t(lang, 'f_poc_detail')} ({_poc_text(lang, poc)})",
        i18n.poc_observed(lang, poc.get("observed_result")),
    )
    artifacts = poc.get("artifacts") or []
    if artifacts:
        doc.add(f"{t(lang, 'f_poc_artifacts')}: {_join_codes(artifacts, table=False)}")


def _related_text(doc: _Doc, finding: Mapping[str, Any]) -> str:
    """Return the records that consolidation folded into ``finding``: ``ID title; ...``."""
    items = finding.get("related")
    parts = []
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, Mapping):
            continue
        record = doc.model.finding_by_id(item.get("id")) if doc.model else None
        title = (
            localized(record, "title", doc.lang, doc.run_lang)[0]
            if record is not None
            else clean(item.get("title"))
        )
        parts.append(f"{md_code(item.get('id'), table=True)} {md_inline(title)}")
    return "; ".join(parts)


def _fact_rows(
    lang: str, finding: Mapping[str, Any], related: str = "", scope: str | None = None
) -> list[tuple[str, str]]:
    rows = [(t(lang, "f_id"), md_code(finding.get("id", ""), table=True))]
    severity = finding.get("severity")
    if isinstance(severity, Mapping):
        rows.append(
            (
                t(lang, "f_severity"),
                t(
                    lang,
                    "f_severity_detail",
                    overall=i18n.severity_label(lang, severity.get("overall_severity")),
                    likelihood=i18n.severity_label(
                        lang, (severity.get("likelihood") or {}).get("score")
                    ),
                    impact=i18n.severity_label(lang, (severity.get("impact") or {}).get("score")),
                ),
            )
        )
    cvss = finding.get("cvss")
    if isinstance(cvss, Mapping):
        rows.append(
            (
                t(lang, "f_cvss"),
                f"{clean(cvss.get('score'))} · {md_code(cvss.get('vector'), table=True)}",
            )
        )
    confidence = finding.get("confidence")
    if isinstance(confidence, Mapping):
        rows.append(
            (
                t(lang, "f_confidence"),
                md_inline(i18n.confidence_label(lang, confidence.get("score"))),
            )
        )
    rows.append((t(lang, "f_class"), _class_text(lang, finding.get("class"))))
    rows.append((t(lang, "f_cwe"), md_inline(", ".join(finding.get("cwe") or []))))
    if finding.get("owasp"):
        rows.append((t(lang, "f_owasp"), md_inline(", ".join(finding["owasp"]))))
    rows.append((t(lang, "f_location"), md_code(location_of(finding), table=True)))
    rows.append((t(lang, "f_engines"), _join_codes(finding.get("engines") or [])))
    rows.append((t(lang, "f_review"), _review_text(lang, finding)))
    if related:
        rows.append((t(lang, "f_related"), related))
    if finding.get("candidates"):
        rows.append((t(lang, "f_candidates"), _join_codes(finding["candidates"])))
    rows.append((t(lang, "f_poc"), md_inline(_poc_text(lang, finding.get("poc")))))
    runtime = i18n.runtime_validation(lang, finding.get("poc"), finding.get("related"))
    rows.append((t(lang, "f_runtime"), md_inline(runtime)))
    if scope:
        rows.append((t(lang, "f_deploy"), md_inline(t(lang, f"deploy_scope_{scope}"))))
    sca = finding.get("sca")
    if isinstance(sca, Mapping):
        rows.append(
            (
                t(lang, "f_sca"),
                f"{md_code(sca.get('package'), table=True)} "
                f"{md_code(sca.get('version'), table=True)} · "
                f"{md_inline(i18n.reachability_label(lang, sca.get('reachability')))}",
            )
        )
    return rows


def _finding_heading(doc: _Doc, number: str, finding: Mapping[str, Any], prefix: str) -> None:
    title, note = localized(finding, "title", doc.lang, doc.run_lang)
    suffix = f" {t(doc.lang, 'not_translated')}" if note else ""
    doc.add(f"### {number} {prefix}{md_inline(title)}{suffix}")


def _confirmed_finding(doc: _Doc, number: str, finding: Mapping[str, Any]) -> None:
    lang = doc.lang
    severity = severity_of(finding)
    _finding_heading(doc, number, finding, f"{_severity_text(lang, severity)} · ")
    doc.table(
        (t(lang, "meta_field"), t(lang, "meta_value")),
        _fact_rows(lang, finding, _related_text(doc, finding), _deploy_scope(doc, finding)),
    )
    description, note = localized(finding, "description", lang, doc.run_lang)
    doc.labeled(t(lang, "f_description"), description, note=note)
    doc.labeled(t(lang, "f_root_cause"), finding.get("root_cause"))
    doc.labeled(t(lang, "f_intended"), finding.get("intended_behavior"))
    _trace_and_evidence(doc, finding)
    _answers(doc, finding)
    conditions = finding.get("conditions") or []
    if conditions:
        doc.add(f"**{t(lang, 'f_conditions')}**")
        doc.bullets(
            f"{md_inline(i18n.condition_label(lang, item.get('kind')))}: "
            f"{md_inline(item.get('description'))}"
            for item in conditions
        )
    execution = finding.get("execution")
    if isinstance(execution, Mapping):
        doc.add(f"**{t(lang, 'f_execution')}**")
        doc.labeled(t(lang, "f_attacker"), execution.get("attacker_perspective"))
        steps = execution.get("instructions") or []
        if steps:
            doc.add(f"{t(lang, 'f_steps')}:")
            doc.add("\n".join(f"{i}. {md_inline(step)}" for i, step in enumerate(steps, 1)))
        payloads = execution.get("payloads") or []
        if payloads:
            doc.add(f"{t(lang, 'f_payloads')}:")
            for payload in payloads:
                doc.add(md_fence(payload))
        doc.labeled(t(lang, "f_observed"), execution.get("observed_result"))
    _poc_block(doc, finding)
    strategy, note = localized(finding, "remediation_strategy", lang, doc.run_lang)
    doc.labeled(t(lang, "f_remediation"), strategy, note=note)
    remediation = finding.get("remediation")
    if isinstance(remediation, Mapping):
        for change in remediation.get("code_changes") or []:
            doc.add(t(lang, "f_code_change", file=md_code(change.get("file_name"))))
            doc.add(md_fence(change.get("fixed_code")))


def _blocker_text(blocker: object, lang: str = "tr") -> str:
    text = clean(blocker)
    if not _CODE_LIKE.fullmatch(text):
        return md_inline(text)
    note = i18n.blocker_note(lang, text)
    return f"{md_code(text)}: {md_inline(note)}" if note else md_code(text)


def _needs_validation_finding(doc: _Doc, number: str, finding: Mapping[str, Any]) -> None:
    lang = doc.lang
    _finding_heading(doc, number, finding, "")
    doc.table(
        (t(lang, "meta_field"), t(lang, "meta_value")),
        _fact_rows(lang, finding, _related_text(doc, finding), _deploy_scope(doc, finding)),
    )
    description, note = localized(finding, "description", lang, doc.run_lang)
    doc.labeled(t(lang, "f_description"), description, note=note)
    doc.labeled(t(lang, "f_claimed_root_cause"), finding.get("claimed_root_cause"))
    blockers = finding.get("blockers") or []
    if blockers:
        doc.add(f"**{t(lang, 'f_blockers')}**")
        doc.bullets(_blocker_text(item, lang) for item in blockers)
    plan = finding.get("validation_plan")
    if isinstance(plan, Mapping):
        items = []
        if plan.get("local"):
            items.append(f"{t(lang, 'f_plan_local')}: {md_inline(plan['local'])}")
        if plan.get("deployment"):
            items.append(f"{t(lang, 'f_plan_deployment')}: {md_inline(plan['deployment'])}")
        if items:
            doc.add(f"**{t(lang, 'f_validation_plan')}**")
            doc.bullets(items)
    _trace_and_evidence(doc, finding)
    _answers(doc, finding)
    _poc_block(doc, finding)


def _findings(doc: _Doc, model: ReportModel) -> None:
    lang = doc.lang
    doc.add(f"## 3. {t(lang, 'sec_confirmed')}")
    if model.confirmed:
        doc.add(t(lang, "confirmed_intro"))
        if lang != model.run_lang:
            doc.add(f"*{t(lang, 'translation_scope')}*")
        for index, finding in enumerate(model.confirmed, start=1):
            _confirmed_finding(doc, f"3.{index}", finding)
    else:
        doc.add(t(lang, "findings_none_confirmed"))

    doc.add(f"## 4. {t(lang, 'sec_needs_validation')}")
    if model.needs_validation:
        doc.add(t(lang, "needs_validation_intro"))
        for index, finding in enumerate(model.needs_validation, start=1):
            _needs_validation_finding(doc, f"4.{index}", finding)
    else:
        doc.add(t(lang, "findings_none_needs_validation"))

    doc.add(f"## 5. {t(lang, 'sec_rejected')}")
    if model.rejected:
        doc.add(t(lang, "rejected_intro"))
        rows = []
        for finding in model.rejected:
            title, note = localized(finding, "title", lang, model.run_lang)
            suffix = f" {t(lang, 'not_translated')}" if note else ""
            rows.append(
                (
                    md_code(finding.get("id", ""), table=True),
                    md_inline(title) + suffix,
                    md_code(finding.get("class", ""), table=True),
                    md_code(location_of(finding), table=True),
                    _rejected_reason(lang, finding),
                )
            )
        doc.table(
            (
                t(lang, "col_id"),
                t(lang, "col_title"),
                t(lang, "col_class"),
                t(lang, "col_location"),
                t(lang, "col_reason"),
            ),
            rows,
        )
    else:
        doc.add(t(lang, "findings_none_rejected"))


def _rejected_reason(lang: str, finding: Mapping[str, Any]) -> str:
    review = finding.get("review")
    reason = md_inline(finding.get("reason"))
    if isinstance(review, Mapping) and review.get("decision") == "reject":
        return f"{md_inline(t(lang, 'f_review'))}: {reason}"
    return reason


def _hardening(doc: _Doc, model: ReportModel) -> None:
    lang = doc.lang
    doc.add(f"## 6. {t(lang, 'sec_hardening')}")
    if model.hardening:
        doc.add(t(lang, "hardening_intro"))
        doc.table(
            (t(lang, "col_title"), t(lang, "col_location"), t(lang, "col_note")),
            [
                (md_inline(note.title), _location_code(note.file, note.line), md_inline(note.note))
                for note in model.hardening
            ],
        )
    elif model.hunt_done:
        doc.add(t(lang, "hardening_none"))
    else:
        doc.add(t(lang, "hardening_missing"))


def severity_counts_text(lang: str, candidates: Iterable[Mapping[str, Any]]) -> str:
    """Return ``Yüksek 2 · Orta 1`` for a list of candidates."""
    counts = dict.fromkeys(SEVERITY_ORDER, 0)
    for candidate in candidates:
        severity = candidate.get("severity")
        counts[severity if severity in counts else "info"] += 1
    return " · ".join(
        f"{i18n.severity_label(lang, name)} {count}" for name, count in counts.items() if count
    )


def _tool_results(doc: _Doc, model: ReportModel) -> None:
    lang = doc.lang
    doc.add(f"## 7. {t(lang, 'sec_tool_results')}")
    if not model.candidates_available:
        doc.add(t(lang, "tool_results_missing"))
        return
    if not model.tool_results:
        doc.add(t(lang, "tool_results_none"))
        return
    doc.add(f"> {t(lang, 'tool_results_intro')}")
    for index, (engine, items) in enumerate(model.tool_results_by_engine().items(), start=1):
        doc.add(f"### 7.{index} {md_inline(engine)} ({len(items)})")
        doc.add(severity_counts_text(lang, items))
        shown = items[:MAX_TOOL_ROWS_PER_ENGINE]
        doc.table(
            (
                t(lang, "col_severity"),
                t(lang, "col_rule"),
                t(lang, "col_title"),
                t(lang, "col_location"),
                t(lang, "col_class"),
            ),
            [
                (
                    _severity_text(lang, item.get("severity")),
                    md_code(item.get("rule_id"), table=True),
                    md_inline(item.get("title")),
                    _location_code(item.get("file"), item.get("start_line")),
                    md_code(item.get("class") or "", table=True),
                )
                for item in shown
            ],
        )
        if len(items) > len(shown):
            doc.add(t(lang, "tool_results_truncated", n=len(items) - len(shown)))


def _sca(doc: _Doc, model: ReportModel) -> None:
    lang = doc.lang
    doc.add(f"## 8. {t(lang, 'sec_sca')}")
    if model.sca_source is None:
        doc.add(t(lang, "sca_missing"))
        return
    if model.sca_source == "candidates":
        doc.add(t(lang, "sca_from_candidates"))
    if model.unchecked_manifests:
        doc.add(f"> {t(lang, 'sca_unchecked', n=len(model.unchecked_manifests))}")
    sbom = text_values(model, lang)
    if not model.sca:
        doc.add(t(lang, "sca_none"))
        if sbom is not None:
            doc.add(t(lang, "sca_sbom", **sbom))
        return
    malicious = model.sca_malicious()
    records = model.sca_vulnerable()
    if malicious:
        _malicious(doc, malicious)
        if records:
            doc.add(f"### 8.2 {t(lang, 'sca_known_title')}")
    if not records:
        if sbom is not None:
            doc.add(t(lang, "sca_sbom", **sbom))
        return
    doc.add(t(lang, "sca_intro"))
    pins = sum(1 for record in records if record.pin_source == "manifest")
    if pins:
        doc.add(t(lang, "sca_pin_note", n=pins))
    vendored = [record for record in records if record.vendored_files]
    if vendored:
        doc.add(t(lang, "sca_vendored_note", n=len(vendored)))
        doc.bullets(
            f"{md_code(path)} ({md_code(f'{package} {version}')})"
            for path, package, version in _vendored_files(vendored)
        )
    doc.table(
        (
            t(lang, "col_package"),
            t(lang, "col_version"),
            t(lang, "col_ecosystem"),
            t(lang, "col_vuln_ids"),
            t(lang, "col_severity"),
            t(lang, "col_fixed"),
            t(lang, "col_reachability"),
        ),
        [
            (
                md_code(record.package, table=True),
                md_code(record.version, table=True) + _pin_text(lang, record),
                md_inline(record.ecosystem),
                _join_codes(record.ids),
                _severity_text(lang, record.severity),
                _join_codes(record.fixed_versions),
                md_inline(i18n.reachability_label(lang, record.reachability)),
            )
            for record in records
        ],
    )
    if sbom is not None:
        doc.add(t(lang, "sca_sbom", **sbom))


#: The malicious package actions (keys ``sca_malicious_action_<n>``).
MALICIOUS_ACTIONS: Final = 4


def _malicious(doc: _Doc, records: Sequence[ScaRecord]) -> None:
    """The box of the known malicious package versions (ENGINE-SPEC 16), before the ordinary
    SCA table: a GitHub alert block with the reason and the actions, then one row per record."""
    lang = doc.lang
    doc.add(f"### 8.1 {t(lang, 'sca_malicious_title')}")
    lines = [
        "> [!CAUTION]",
        f"> **{t(lang, 'sca_malicious_intro', n=len(records))}**",
        ">",
        f"> {t(lang, 'sca_malicious_actions')}",
        ">",
    ]
    lines += [
        f"> {index}. {t(lang, f'sca_malicious_action_{index}')}"
        for index in range(1, MALICIOUS_ACTIONS + 1)
    ]
    doc.add("\n".join(lines))
    doc.table(
        (
            t(lang, "col_package"),
            t(lang, "col_version"),
            t(lang, "col_ecosystem"),
            t(lang, "col_record_ids"),
            t(lang, "col_severity"),
            t(lang, "col_location"),
        ),
        [
            (
                md_code(record.package, table=True),
                md_code(record.version, table=True) + _pin_text(lang, record),
                md_inline(record.ecosystem),
                _join_codes(record.ids),
                _severity_text(lang, record.severity),
                _join_codes(record.locations),
            )
            for record in records
        ],
    )


#: The vendored file list of the SCA section shows at most this many files.
MAX_VENDORED_FILES: Final = 20


def _vendored_files(records: Sequence[ScaRecord]) -> list[tuple[str, str, str]]:
    """Return ``(file, package, version)`` once per vendored file, at most
    :data:`MAX_VENDORED_FILES`."""
    found: dict[str, tuple[str, str, str]] = {}
    for record in records:
        for path in record.vendored_files:
            found.setdefault(path, (path, record.package, record.version))
    return list(found.values())[:MAX_VENDORED_FILES]


def _pin_text(lang: str, record: ScaRecord) -> str:
    if record.pin_source == "manifest":
        return f" ({t(lang, 'pin_label')})"
    if record.vendored_files:
        return f" ({t(lang, 'pin_label_vendored')})"
    return ""


def _appendix(doc: _Doc, model: ReportModel) -> None:
    lang = doc.lang
    doc.add(f"## {t(lang, 'sec_appendix')}")
    doc.add(f"### A.1 {t(lang, 'sub_method')}")
    doc.bullets(t(lang, f"method_{index}") for index in range(1, 7))
    doc.add(f"### A.2 {t(lang, 'sub_tool_versions')}")
    if model.tool_versions:
        doc.table(
            (t(lang, "col_tool"), t(lang, "col_version"), t(lang, "col_kind_tool")),
            [
                (md_code(name, table=True), md_code(version, table=True), md_inline(kind))
                for name, version, kind in model.tool_versions
            ],
        )
    else:
        doc.add(t(lang, "tool_versions_missing"))
    doc.add(f"### A.3 {t(lang, 'sub_run')}")
    rows = [
        (t(lang, "meta_run_id"), md_code(model.run_id, table=True)),
        (t(lang, "run_kalkan_version"), md_code(model.kalkan_version, table=True)),
        (t(lang, "meta_generated"), md_inline(fmt_ts(model.generated_at))),
    ]
    if model.outputs:
        rows.append((t(lang, "run_report_files"), _join_codes(model.outputs)))
    doc.table((t(lang, "meta_field"), t(lang, "meta_value")), rows)
    if model.warnings:
        doc.add(f"### A.4 {t(lang, 'warnings_title')}")
        doc.bullets(md_inline(warning) for warning in model.warnings)
    if model.duplicates:
        _duplicates(doc, model, "A.5" if model.warnings else "A.4")


def _duplicates(doc: _Doc, model: ReportModel, number: str) -> None:
    """List every record that consolidation folded, with its primary finding and the reason."""
    lang = doc.lang
    doc.add(f"### {number} {t(lang, 'sub_duplicates')}")
    doc.add(t(lang, "duplicates_intro"))
    rows = []
    for finding in model.duplicates:
        title, note = localized(finding, "title", lang, model.run_lang)
        suffix = f" {t(lang, 'not_translated')}" if note else ""
        primary = model.finding_by_id(finding.get("duplicate_of"))
        primary_title = localized(primary, "title", lang, model.run_lang)[0] if primary else ""
        rows.append(
            (
                md_code(finding.get("id", ""), table=True),
                md_inline(title) + suffix,
                md_code(finding.get("class", ""), table=True),
                f"{md_code(finding.get('duplicate_of'), table=True)} {md_inline(primary_title)}",
                md_inline(finding.get("duplicate_reason")),
            )
        )
    doc.table(
        (
            t(lang, "col_id"),
            t(lang, "col_title"),
            t(lang, "col_class"),
            t(lang, "col_primary"),
            t(lang, "col_reason"),
        ),
        rows,
    )


def render_markdown(model: ReportModel, lang: str = "tr") -> str:
    """Return the Markdown report for ``model`` in ``lang`` (``tr`` or ``en``).

    The last line tells the reader how to ask for the English version (Turkish report) or where
    the Turkish version is (English report).
    """
    doc = _Doc(lang, model.run_lang, model)
    _meta(doc, model)
    _summary(doc, model)
    _scope(doc, model)
    _findings(doc, model)
    _hardening(doc, model)
    _tool_results(doc, model)
    _sca(doc, model)
    _appendix(doc, model)
    doc.add("---")
    doc.add(t(lang, "english_hint"))
    return doc.text()
