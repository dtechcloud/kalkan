# SPDX-License-Identifier: MIT
"""CLI command ``report`` (docs/ENGINE-SPEC.md, sections 9 and 16).

``report [--run <run-id>] [--lang tr|en] [--formats md,html,sarif,json,exec,sbom]
[--include-candidates] [--json]`` writes into ``runs/<run-id>/report/``:

- ``md``: ``REPORT.md`` (``--lang tr``) or ``REPORT.en.md`` (``--lang en``);
- ``html``: ``REPORT.html`` or ``REPORT.en.html``;
- ``exec``: ``EXECUTIVE.html`` or ``EXECUTIVE.en.html``, the one-page executive summary (its
  finding links point into ``REPORT.html`` or ``REPORT.en.html``);
- ``sarif``: ``findings.sarif`` (findings and SCA records; unverified tool candidates only with
  ``--include-candidates``);
- ``sbom``: ``sbom.cdx.json`` (CycloneDX 1.6) and ``sbom.spdx.json`` (SPDX 2.3), the joined SBOM
  of :mod:`kalkan.report.sbom`; written only when the run has an SBOM input;
- ``json``: ``findings.json`` (a copy of the merged findings) and ``summary.json``.

The default is every format. Every file is written atomically. ``summary.json`` lists the
report files that exist after the command, and the renderers list them too
(:attr:`kalkan.report.model.ReportModel.outputs`). Machine output (``--json``) goes to stdout;
human messages go to stderr.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, Final

from kalkan.report.model import ReportModel, build_model
from kalkan.report.render_exec import render_executive
from kalkan.report.render_html import render_html
from kalkan.report.render_md import render_markdown
from kalkan.report.sbom import CYCLONEDX_FILE, SPDX_FILE, cyclonedx, spdx
from kalkan.report.summary import build_sarif, build_summary
from kalkan.run.ids import resolve_run
from kalkan.sarif.emit import write_sarif
from kalkan.util.safe_io import atomic_write_json, atomic_write_text

EXIT_OK = 0
EXIT_USAGE = 2

REPORT_HELP = "Render the report as Markdown, JSON, SARIF, HTML, an executive summary and SBOMs."
REPORT_DIRNAME: Final = "report"
FORMATS: Final = ("md", "html", "sarif", "json", "exec", "sbom")

#: Output key -> file name in report/. The order is the order in summary.json.
OUTPUT_FILES: Final = {
    "report_md": "REPORT.md",
    "report_html": "REPORT.html",
    "report_en_md": "REPORT.en.md",
    "report_en_html": "REPORT.en.html",
    "executive_html": "EXECUTIVE.html",
    "executive_en_html": "EXECUTIVE.en.html",
    "findings_sarif": "findings.sarif",
    "findings_json": "findings.json",
    "sbom_cyclonedx": CYCLONEDX_FILE,
    "sbom_spdx": SPDX_FILE,
    "summary_json": "summary.json",
}


def register(subparsers: argparse._SubParsersAction) -> None:
    """Add the ``report`` parser to the top-level subparsers."""
    parser = subparsers.add_parser(
        "report",
        help=REPORT_HELP,
        description=(
            "Write the report of a run into runs/<run-id>/report/: REPORT.md, REPORT.html and "
            "the executive summary EXECUTIVE.html (Turkish) or REPORT.en.md, REPORT.en.html "
            "and EXECUTIVE.en.html (English), findings.sarif, findings.json, summary.json and "
            "the SBOMs sbom.cdx.json (CycloneDX) and sbom.spdx.json (SPDX)."
        ),
    )
    parser.add_argument("--run", metavar="RUN_ID", help="run ID (default: runs/LATEST)")
    parser.add_argument(
        "--lang", choices=("tr", "en"), default="tr", help="report language (default: tr)"
    )
    parser.add_argument(
        "--formats",
        default=",".join(FORMATS),
        metavar="LIST",
        help="comma-separated output formats: md, html, sarif, json, exec, sbom (default: all)",
    )
    parser.add_argument(
        "--include-candidates",
        action="store_true",
        help="also put the unverified tool candidates into findings.sarif",
    )
    parser.add_argument("--json", action="store_true", help="print the result as JSON")
    parser.set_defaults(func=_cmd_report, parser=parser)


def parse_formats(text: str) -> list[str]:
    """Return the formats of a comma-separated list, in the canonical order.

    Raises ValueError for an empty list or an unknown format.
    """
    wanted = {item.strip().lower() for item in text.split(",") if item.strip()}
    unknown = sorted(wanted - set(FORMATS))
    if unknown:
        raise ValueError(f"unknown format(s): {', '.join(unknown)} (known: {', '.join(FORMATS)})")
    if not wanted:
        raise ValueError("name at least one format")
    return [name for name in FORMATS if name in wanted]


def write_report(
    run_dir: Path,
    model: ReportModel,
    *,
    lang: str = "tr",
    formats: Sequence[str] = FORMATS,
    include_candidates: bool = False,
) -> list[Path]:
    """Write the report files of ``model`` into ``<run_dir>/report`` and return their paths."""
    out = run_dir / REPORT_DIRNAME
    out.mkdir(parents=True, exist_ok=True)
    suffix = ".en" if lang == "en" else ""
    written: list[Path] = []
    with_sbom = "sbom" in formats and model.sbom is not None and bool(model.sbom.components)
    planned = {
        f"REPORT{suffix}.md": "md" in formats,
        f"REPORT{suffix}.html": "html" in formats,
        f"EXECUTIVE{suffix}.html": "exec" in formats,
        "findings.sarif": "sarif" in formats,
        CYCLONEDX_FILE: with_sbom,
        SPDX_FILE: with_sbom,
        "findings.json": "json" in formats,
        "summary.json": "json" in formats,
    }
    model = dataclasses.replace(
        model,
        outputs=tuple(
            name for name in OUTPUT_FILES.values() if planned.get(name) or (out / name).is_file()
        ),
    )

    def put(name: str, writer: Callable[[Path], None]) -> None:
        path = out / name
        writer(path)
        written.append(path)

    if "md" in formats:
        text = render_markdown(model, lang)
        put(f"REPORT{suffix}.md", lambda path: atomic_write_text(path, text))
    if "html" in formats:
        page = render_html(model, lang)
        put(f"REPORT{suffix}.html", lambda path: atomic_write_text(path, page))
    if "exec" in formats:
        summary_page = render_executive(model, lang)
        put(f"EXECUTIVE{suffix}.html", lambda path: atomic_write_text(path, summary_page))
    if "sarif" in formats:
        sarif = build_sarif(model, include_candidates=include_candidates)
        put("findings.sarif", lambda path: write_sarif(path, sarif))
    if with_sbom and model.sbom is not None:
        inventory = model.sbom
        put(CYCLONEDX_FILE, lambda path: atomic_write_json(path, cyclonedx(model, inventory)))
        put(SPDX_FILE, lambda path: atomic_write_json(path, spdx(model, inventory)))
    if "json" in formats:
        put("findings.json", lambda path: atomic_write_json(path, model.findings))
        paths = {
            key: f"{REPORT_DIRNAME}/{name}"
            for key, name in OUTPUT_FILES.items()
            if (out / name).is_file() or key == "summary_json"
        }
        summary = build_summary(model, lang=lang, paths=paths)
        put("summary.json", lambda path: atomic_write_json(path, summary))
    return written


def refresh_report(run_dir: Path) -> list[Path]:
    """Write the report of a finished run again and return the paths written.

    The report step runs inside the last agent round, so the cost of that round reaches
    ``usage.jsonl`` only after the report exists (:mod:`kalkan.run.usage`). ``kalkan audit``
    calls this after the last round: the run language gets every format except the SBOMs (they
    do not change), and English gets its pages when ``REPORT.en.md`` exists.
    """
    model = build_model(run_dir)
    run_lang = model.run_lang if model.run_lang in ("tr", "en") else "tr"
    written = write_report(
        run_dir, model, lang=run_lang, formats=("md", "html", "exec", "sarif", "json")
    )
    if run_lang != "en" and (run_dir / REPORT_DIRNAME / "REPORT.en.md").is_file():
        written += write_report(run_dir, model, lang="en", formats=("md", "html", "exec"))
    return written


def _cmd_report(args: argparse.Namespace) -> int:
    parser: argparse.ArgumentParser = args.parser
    try:
        formats = parse_formats(args.formats)
    except ValueError as exc:
        parser.print_usage(sys.stderr)
        print(f"{parser.prog}: error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    run_dir = resolve_run(args.run)
    model = build_model(run_dir)
    written = write_report(
        run_dir,
        model,
        lang=args.lang,
        formats=formats,
        include_candidates=args.include_candidates,
    )
    files = [
        {"path": path.relative_to(run_dir).as_posix(), "bytes": path.stat().st_size}
        for path in written
    ]
    if args.json:
        verdicts = model.verdict_counts()
        _print_json(
            {
                "run_id": model.run_id,
                "lang": args.lang,
                "files": files,
                "findings": verdicts,
                "tool_results": len(model.tool_results),
                "sca": len(model.sca),
                "partial": bool(model.partial_reasons),
                "missing_inputs": model.missing,
                "warnings": model.warnings,
            }
        )
    for warning in model.warnings:
        _say(f"warning: {warning}")
    if not args.json:
        for item in files:
            _say(f"wrote {item['path']} ({item['bytes']} bytes)")
    return EXIT_OK


def _say(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def _print_json(obj: Any) -> None:
    """Write JSON to stdout as UTF-8, also when Windows gives a pipe an ANSI code page."""
    text = json.dumps(obj, ensure_ascii=False, indent=2) + "\n"
    stream = sys.stdout
    encoding = (getattr(stream, "encoding", None) or "").lower().replace("-", "").replace("_", "")
    buffer = getattr(stream, "buffer", None)
    if encoding != "utf8" and buffer is not None:
        stream.flush()
        buffer.write(text.encode("utf-8"))
        buffer.flush()
        return
    stream.write(text)
