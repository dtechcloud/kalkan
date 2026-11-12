# SPDX-License-Identifier: MIT
"""Command-line entry point for kalkan.

The top-level parser loads command modules lazily (docs/ENGINE-SPEC.md, section 9).
A command whose module does not exist yet reports the phase that implements it.
"""

from __future__ import annotations

import argparse
import importlib
import sys
from collections.abc import Callable, Sequence

from kalkan import __version__
from kalkan.errors import KalkanError, ToolError, ValidationError

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_NOT_IMPLEMENTED = 3
EXIT_VALIDATION = 4
EXIT_TOOL_MISSING = 5

# Top-level command -> (command module, help text, phase that implements it). The one-command
# entry ``audit`` comes first in ``kalkan --help`` (docs/ENGINE-SPEC.md, section 25).
COMMANDS: dict[str, tuple[str, str, int]] = {
    "audit": (
        "kalkan.audit.commands",
        "Audit a folder or a git URL end to end: setup check, audit and report.",
        10,
    ),
    "doctor": (
        "kalkan.tools.commands",
        "Check the environment, the tool versions and the Claude login.",
        2,
    ),
    "tools": ("kalkan.tools.commands", "Install, verify or list the pinned scanner tools.", 2),
    "clean": (
        "kalkan.tools.commands",
        "Show the disk usage of kalkan; delete its runs, caches, databases or tools.",
        2,
    ),
    "run": (
        "kalkan.run.commands",
        "Manage audit runs: init, status, next, step, resume, clean.",
        3,
    ),
    "task": ("kalkan.run.commands", "Manage agent tasks: claim, complete, fail, prompt.", 3),
    "scan": ("kalkan.scanners.commands", "Run the deterministic scanners, collect candidates.", 2),
    "sca": ("kalkan.sca.commands", "Software composition analysis: sbom, match, reach.", 4),
    "verify": (
        "kalkan.findings.check_commands",
        "Check an agent result: schema, quotes and verdict.",
        1,
    ),
    "ledger": ("kalkan.findings.check_commands", "Validate a coverage ledger.", 1),
    "merge": ("kalkan.findings.commands", "Deduplicate and merge the findings of all engines.", 2),
    "report": ("kalkan.report.commands", "Render the report as Markdown, JSON, SARIF and HTML.", 2),
    "sandbox": ("kalkan.sandbox.commands", "Run PoC validation in a Docker sandbox.", 7),
    "unattended": (
        "kalkan.unattended.commands",
        "Run or resume an audit headless and wait through usage-limit resets.",
        6,
    ),
}


def _not_implemented(name: str, phase: int) -> Callable[[argparse.Namespace], int]:
    def handler(_args: argparse.Namespace) -> int:
        print(
            f"kalkan {name}: not implemented yet (planned for phase {phase}).",
            file=sys.stderr,
        )
        return EXIT_NOT_IMPLEMENTED

    return handler


def _import_command_module(module_name: str):
    """Import a command module, or return None when it or its package does not exist yet."""
    try:
        return importlib.import_module(module_name)
    except ModuleNotFoundError as exc:
        missing = exc.name or ""
        if missing == module_name or module_name.startswith(missing + "."):
            return None
        raise


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kalkan",
        description="Resumable, AI-assisted security audit toolkit driven by Claude Code.",
    )
    parser.add_argument("--version", action="version", version=f"kalkan {__version__}")
    subparsers = parser.add_subparsers(dest="command", metavar="<command>")

    for module_name in dict.fromkeys(module for module, _, _ in COMMANDS.values()):
        module = _import_command_module(module_name)
        if module is not None:
            module.register(subparsers)

    for name, (_, help_text, phase) in COMMANDS.items():
        if name in subparsers.choices:
            continue
        stub = subparsers.add_parser(name, help=help_text, description=help_text)
        stub.add_argument("args", nargs=argparse.REMAINDER, help=argparse.SUPPRESS)
        stub.set_defaults(func=_not_implemented(name, phase))
    return parser


def _use_utf8_streams() -> None:
    """Write UTF-8 on stdout and stderr; a Windows pipe defaults to the ANSI code page."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="backslashreplace")
        except (OSError, ValueError):
            pass


def main(argv: Sequence[str] | None = None) -> int:
    _use_utf8_streams()
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return EXIT_USAGE
    handler = getattr(args, "func", None)
    if handler is None:
        parser.parse_args([args.command, "--help"])
        return EXIT_USAGE
    try:
        return int(handler(args) or EXIT_OK)
    except ValidationError as exc:
        _print_error(exc)
        return EXIT_VALIDATION
    except ToolError as exc:
        _print_error(exc)
        return EXIT_TOOL_MISSING
    except KalkanError as exc:
        _print_error(exc)
        return EXIT_ERROR


def _print_error(exc: KalkanError) -> None:
    print(f"kalkan: error: {exc}", file=sys.stderr)
    for line in getattr(exc, "errors", [])[:100]:
        print(f"  - {line}", file=sys.stderr)
