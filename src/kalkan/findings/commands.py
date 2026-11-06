# SPDX-License-Identifier: MIT
"""CLI commands of ``kalkan.findings`` (docs/ENGINE-SPEC.md, sections 9 and 15).

- ``merge [--run <run-id>] [--json]``: merge the task outputs into ``findings.json``.

Each command has one ``_register_<name>`` function and one ``_cmd_<name>`` handler. To add a
command (``verify``, ``ledger validate``), write both functions and call the register function
from :func:`register`. Machine output (``--json``) goes to stdout; human messages go to stderr.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from kalkan.findings.merge import merge_run
from kalkan.run.ids import resolve_run
from kalkan.run.lock import run_lock

EXIT_OK = 0

MERGE_HELP = "Deduplicate and merge the findings of all engines."


def register(subparsers: argparse._SubParsersAction) -> None:
    """Add the ``kalkan.findings`` command parsers to the top-level subparsers."""
    _register_merge(subparsers)


# ---------------------------------------------------------------------------------------------
# merge


def _register_merge(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(
        "merge",
        help=MERGE_HELP,
        description=(
            "Merge the findings, PoC results and translations of the done tasks of a run into "
            "findings.json, and link the deterministic candidates."
        ),
    )
    parser.add_argument("--run", metavar="RUN_ID", help="run ID (default: runs/LATEST)")
    parser.add_argument("--json", action="store_true", help="print the summary as JSON")
    parser.set_defaults(func=_cmd_merge)


def _cmd_merge(args: argparse.Namespace) -> int:
    run_dir = resolve_run(args.run)
    with run_lock(run_dir):
        summary = merge_run(run_dir)
    if args.json:
        _print_json(summary)
    for warning in summary["warnings"]:
        _say(f"warning: {warning}")
    if not args.json:
        verdicts = summary["by_verdict"]
        candidates = summary["candidates"]
        _say(
            f"merged {summary['findings']} findings into {summary['findings_file']}: "
            f"{verdicts['confirmed']} confirmed, {verdicts['needs_validation']} need validation, "
            f"{verdicts['rejected']} rejected; {summary['merged_duplicates']} duplicates merged; "
            f"{candidates['linked']} of {candidates['total']} candidates linked"
        )
    return EXIT_OK


# ---------------------------------------------------------------------------------------------
# Output helpers


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
