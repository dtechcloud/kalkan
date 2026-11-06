# SPDX-License-Identifier: MIT
"""CLI command ``scan <engine|all>`` (docs/ENGINE-SPEC.md, sections 9 and 13.1).

``kalkan scan all`` runs the scanners of :data:`kalkan.scanners.registry.SCANNERS` in order;
``kalkan scan <engine>`` runs one adapter (a scanner or an SCA tool). Each SARIF output becomes
candidates in ``candidates.json``. The result table (or ``--json``) goes to stdout; progress
lines go to stderr.

No tool uses the network unless ``--online`` is given (docs/SECURITY.md). ``--offline`` is
accepted for older scripts and changes nothing.

Exit codes: 0 when every engine ended ``ok`` or ``skipped``; 1 when an engine ended ``failed``
or ``timeout``; 5 when a single named engine was skipped because its tool is missing.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from kalkan.scanners import registry
from kalkan.scanners.base import ScanResult, load_scan_context, run_adapter

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_TOOL_MISSING = 5

SCAN_HELP = "Run the deterministic scanners, collect candidates."
_TOOL_MISSING_PREFIX = "tool not found:"


def register(subparsers: argparse._SubParsersAction) -> None:
    """Add the ``scan`` parser to the top-level subparsers."""
    engines = ", ".join(registry.names())
    scan = subparsers.add_parser(
        "scan",
        help=SCAN_HELP,
        description=(f"{SCAN_HELP} 'all' runs the scanners in order. Engines: {engines}."),
    )
    scan.add_argument("engine", metavar="ENGINE", help="an engine name, or 'all'")
    scan.add_argument("--run", dest="run_id", metavar="RUN_ID", help="the run (default: LATEST)")
    scan.add_argument(
        "--timeout",
        type=int,
        default=None,
        metavar="N",
        help="time limit per engine in seconds (default: the adapter limit; 0: no limit)",
    )
    network = scan.add_mutually_exclusive_group()
    network.add_argument(
        "--online",
        action="store_true",
        help=(
            "opt in to network use: database and check updates, module downloads, online "
            "matching (by default no tool uses the network; docs/SECURITY.md)"
        ),
    )
    network.add_argument("--offline", action="store_true", help=argparse.SUPPRESS)
    scan.add_argument(
        "--allow-path-tools",
        action="store_true",
        help="accept tools on PATH whose version differs from the manifest",
    )
    scan.add_argument(
        "--honor-suppressions",
        action="store_true",
        help=(
            "let the target suppress results (inline comments, ignore and config files); "
            "by default they are ignored (ADR-0003)"
        ),
    )
    scan.add_argument("--json", action="store_true", help="print the results as JSON on stdout")
    scan.set_defaults(func=_cmd_scan, parser=scan)


def _resolve_run(run_id: str | None) -> Path:
    """Return the run folder. Tests replace this function."""
    from kalkan.run.ids import resolve_run

    return resolve_run(run_id)


def _cmd_scan(args: argparse.Namespace) -> int:
    parser: argparse.ArgumentParser = args.parser
    if args.engine != "all" and args.engine not in registry.names():
        parser.print_usage(sys.stderr)
        print(
            f"kalkan scan: error: unknown engine {args.engine!r} "
            f"(choose 'all' or one of: {', '.join(registry.names())})",
            file=sys.stderr,
        )
        return EXIT_USAGE
    if args.timeout is not None and args.timeout < 0:
        parser.print_usage(sys.stderr)
        print("kalkan scan: error: --timeout must be 0 or a positive number", file=sys.stderr)
        return EXIT_USAGE

    run_dir = _resolve_run(args.run_id)
    ctx = load_scan_context(
        run_dir,
        offline=not args.online,
        allow_path_tools=args.allow_path_tools,
        honor_suppressions=args.honor_suppressions,
    )
    adapters = registry.SCANNERS if args.engine == "all" else (registry.get(args.engine),)
    results: list[ScanResult] = []
    for adapter in adapters:
        print(f"kalkan scan: running {adapter.name} ...", file=sys.stderr, flush=True)
        results.append(run_adapter(adapter, ctx, timeout_seconds=args.timeout))

    if args.json:
        payload = {"run": ctx.run_dir.name, "results": [r.to_dict(ctx.run_dir) for r in results]}
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        _print_table(results)
    return _exit_code(results, single=args.engine != "all")


def _exit_code(results: Sequence[ScanResult], *, single: bool) -> int:
    if any(result.status in ("failed", "timeout") for result in results):
        return EXIT_ERROR
    if single and results and results[0].status == "skipped":
        if results[0].message.startswith(_TOOL_MISSING_PREFIX):
            return EXIT_TOOL_MISSING
    return EXIT_OK


def _print_table(results: Sequence[ScanResult]) -> None:
    rows = [
        (
            result.engine,
            result.status,
            f"{result.duration_seconds:.1f}s",
            "-" if result.candidates is None else str(result.candidates),
            result.message,
        )
        for result in results
    ]
    header = ("ENGINE", "STATUS", "TIME", "CAND", "MESSAGE")
    widths = [max(len(row[i]) for row in [header, *rows]) for i in range(4)]
    for row in [header, *rows]:
        cells = [row[i].ljust(widths[i]) for i in range(4)]
        print("  ".join([*cells, row[4]]).rstrip())
