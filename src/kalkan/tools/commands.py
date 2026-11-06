# SPDX-License-Identifier: MIT
"""CLI commands ``doctor``, ``tools install|verify|list`` and ``clean`` (docs/ENGINE-SPEC.md,
sections 9, 12).

Machine output (``--json``) goes to stdout. Progress messages go to stderr. ``clean`` without a
deletion flag prints the disk usage of kalkan; with one it lists what it deletes and asks first
(:mod:`kalkan.tools.cleanup`).
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from kalkan.errors import KalkanError, ToolError
from kalkan.tools import doctor as doctor_mod
from kalkan.tools import install as install_mod
from kalkan.tools.manifest import ASSET_KINDS, load_manifest
from kalkan.tools.platform import platform_key
from kalkan.tools.resolve import default_repo_root, entry_path, read_installed

EXIT_OK = 0
EXIT_USAGE = 2

DOCTOR_HELP = "Check the environment, the tool versions and the Claude login."
TOOLS_HELP = "Install, verify or list the pinned scanner tools."
CLEAN_HELP = "Show the disk usage of kalkan; delete its runs, caches, databases or tools."


def register(subparsers: argparse._SubParsersAction) -> None:
    """Add the ``doctor`` and ``tools`` parsers to the top-level subparsers."""
    doctor = subparsers.add_parser("doctor", help=DOCTOR_HELP, description=DOCTOR_HELP)
    doctor.add_argument("--json", action="store_true", help="print the report as JSON on stdout")
    doctor.set_defaults(func=_cmd_doctor)

    tools = subparsers.add_parser("tools", help=TOOLS_HELP, description=TOOLS_HELP)
    tools.set_defaults(func=_group_help(tools))
    sub = tools.add_subparsers(dest="tools_command", metavar="<subcommand>")

    install = sub.add_parser(
        "install",
        help="Download, verify and install pinned tools.",
        description="Download the pinned tools, check the SHA-256 and install them in .tools/.",
    )
    install.add_argument("names", nargs="*", metavar="NAME", help="tools to install")
    install.add_argument("--all", action="store_true", help="install every tool in the manifest")
    install.add_argument(
        "--force", action="store_true", help="install again even when the tool is present"
    )
    install.add_argument("--json", action="store_true", help="print the results as JSON")
    install.set_defaults(func=_cmd_install, parser=install)

    verify = sub.add_parser(
        "verify",
        help="Re-hash the installed tools.",
        description="Re-hash the installed tools against the pinned SHA-256 values.",
    )
    verify.add_argument("names", nargs="*", metavar="NAME", help="tools to verify (default: all)")
    verify.add_argument(
        "--quick",
        action="store_true",
        help="for a toolchain (Go), hash only the executable and count the files instead of "
        "re-hashing the whole tree",
    )
    verify.add_argument("--json", action="store_true", help="print the results as JSON")
    verify.set_defaults(func=_cmd_verify, parser=verify)

    listing = sub.add_parser(
        "list",
        help="List the pinned tools and their install state.",
        description="List the pinned tools, their versions and their install state.",
    )
    listing.add_argument("--json", action="store_true", help="print the list as JSON")
    listing.set_defaults(func=_cmd_list)

    clean = subparsers.add_parser(
        "clean",
        help=CLEAN_HELP,
        description=(
            "Without a deletion flag: the disk usage of kalkan per part (engine, tools, "
            "databases, caches, runs). With one: the list of what goes and its size, then a "
            "question (y deletes; -y skips the question). Only fixed names below the kalkan home "
            "and run folders of the runs root are deleted; links and junctions are removed as "
            "links. The engine that runs the command is never deleted."
        ),
    )
    flags = (
        ("--runs", "delete every run folder of the runs root and its LATEST file"),
        ("--caches", "delete .tools/cache, .tools/go-build and .tools/.tmp"),
        ("--databases", "delete the vulnerability databases .tools/vulndb"),
        ("--tools", "delete the pinned tools in .tools (without databases and caches)"),
        ("--all", "delete runs, caches, databases and tools: everything except the engine"),
    )
    for flag, text in flags:
        clean.add_argument(flag, action="store_true", help=text)
    clean.add_argument(
        "--keep-reports",
        action="store_true",
        help="with --runs or --all: keep the report/ folder of every run",
    )
    clean.add_argument(
        "--dry-run", action="store_true", help="show what would be deleted and how much"
    )
    clean.add_argument("-y", "--yes", action="store_true", help="delete without the question")
    clean.add_argument("--json", action="store_true", help="print the result as JSON")
    clean.set_defaults(func=_cmd_clean, parser=clean)


def _repo_root() -> Path:
    """Return the repository root. Tests replace this function."""
    return default_repo_root()


def _group_help(parser: argparse.ArgumentParser) -> Callable[[argparse.Namespace], int]:
    def handler(_args: argparse.Namespace) -> int:
        parser.print_help()
        return EXIT_USAGE

    return handler


# ---------------------------------------------------------------------------------------------
# doctor


def _cmd_doctor(args: argparse.Namespace) -> int:
    report = doctor_mod.run_doctor(_repo_root())
    if args.json:
        _print_json(report.to_dict())
    else:
        rows = [(c.status, c.name, c.detail) for c in report.checks]
        _print_table(("STATUS", "CHECK", "DETAIL"), rows)
        counts = report.counts
        summary = ", ".join(f"{counts[s]} {s}" for s in doctor_mod.STATUSES)
        print(f"\nSummary: {summary}. Exit code {report.exit_code}.")
    return report.exit_code


# ---------------------------------------------------------------------------------------------
# tools install, verify, list


def _cmd_install(args: argparse.Namespace) -> int:
    parser: argparse.ArgumentParser = args.parser
    if args.all and args.names:
        return _usage(parser, "use either --all or tool names, not both")
    if not args.all and not args.names:
        return _usage(parser, "name the tools to install, or use --all")
    manifest = load_manifest()
    unknown = [name for name in args.names if name not in manifest]
    if unknown:
        known = ", ".join(manifest.names())
        return _usage(parser, f"unknown tool(s): {', '.join(unknown)} (known tools: {known})")
    names: Sequence[str] | str = "all" if args.all else args.names
    results = install_mod.install(
        names, repo_root=_repo_root(), force=args.force, manifest=manifest, log=_say
    )
    if args.json:
        _print_json({"results": [r.to_dict() for r in results]})
    else:
        rows = [(r.name, r.version, r.status, r.path or "", r.message) for r in results]
        _print_table(("TOOL", "VERSION", "STATUS", "PATH", "MESSAGE"), rows)
    failed = [r.name for r in results if r.status == install_mod.STATUS_FAILED]
    if failed:
        raise ToolError(f"{len(failed)} tool(s) failed to install: {', '.join(failed)}")
    return EXIT_OK


def _cmd_verify(args: argparse.Namespace) -> int:
    parser: argparse.ArgumentParser = args.parser
    manifest = load_manifest()
    unknown = [name for name in args.names if name not in manifest]
    if unknown:
        known = ", ".join(manifest.names())
        return _usage(parser, f"unknown tool(s): {', '.join(unknown)} (known tools: {known})")
    names: Sequence[str] | str = args.names or "all"
    results = install_mod.verify(
        names, repo_root=_repo_root(), manifest=manifest, deep=not args.quick
    )
    if args.json:
        _print_json({"results": [r.to_dict() for r in results]})
    else:
        rows = [(r.name, r.version, r.status, r.path or "", r.message) for r in results]
        _print_table(("TOOL", "VERSION", "STATUS", "PATH", "MESSAGE"), rows)
    mismatch = [r.name for r in results if r.status == install_mod.VERIFY_MISMATCH]
    missing = [r.name for r in results if r.status == install_mod.VERIFY_MISSING]
    if mismatch:
        raise ToolError(
            f"{len(mismatch)} tool(s) differ from the pinned values: {', '.join(mismatch)}. "
            "Reinstall them with: kalkan tools install --force <name>"
        )
    if missing:
        raise ToolError(
            f"{len(missing)} tool(s) are not installed: {', '.join(missing)}. "
            "Install them with: kalkan tools install --all"
        )
    return EXIT_OK


def _cmd_list(args: argparse.Namespace) -> int:
    manifest = load_manifest()
    root = _repo_root()
    try:
        key: str | None = platform_key()
    except KalkanError:
        key = None
    installed = read_installed(root)["tools"]
    items: list[dict[str, Any]] = []
    for tool in manifest:
        entry = installed.get(tool.name) if isinstance(installed.get(tool.name), dict) else None
        path = entry_path(root, entry) if entry else None
        is_installed = bool(
            entry and entry.get("version") == tool.version and path is not None and path.is_file()
        )
        has_assets = tool.kind in ASSET_KINDS
        available = not has_assets or (key is not None and tool.asset(key) is not None)
        items.append(
            {
                "name": tool.name,
                "version": tool.version,
                "kind": tool.kind,
                "license": tool.license,
                "requires_go": tool.requires_go,
                "platforms": sorted(tool.platforms) if has_assets else [],
                "available": available,
                "installed": is_installed,
                "path": entry.get("path") if is_installed and entry else None,
                "notes": tool.notes,
            }
        )
    if args.json:
        _print_json({"platform": key, "tools": items})
    else:
        rows = [
            (
                item["name"],
                item["version"],
                item["kind"],
                item["license"],
                "yes" if item["installed"] else "no",
                "yes" if item["available"] else "no",
            )
            for item in items
        ]
        _print_table(("TOOL", "VERSION", "KIND", "LICENSE", "INSTALLED", "AVAILABLE"), rows)
    return EXIT_OK


# ---------------------------------------------------------------------------------------------
# clean


def _cmd_clean(args: argparse.Namespace) -> int:
    from kalkan.tools import cleanup  # lazy: only this command needs it

    parser: argparse.ArgumentParser = args.parser
    parts = [name for name in cleanup.DELETABLE if args.all or getattr(args, name)]
    if args.keep_reports and "runs" not in parts:
        return _usage(parser, "--keep-reports works only with --runs or --all")
    if (args.dry_run or args.yes) and not parts:
        return _usage(parser, "name what to delete: --runs, --caches, --databases, --tools, --all")
    found = cleanup.usage()
    if not parts:
        if args.json:
            _print_json({"usage": found.to_dict()})
        else:
            _print_usage(found)
        return EXIT_OK
    items = cleanup.plan(found, parts, keep_reports=args.keep_reports)
    size = _size(sum(item.stats.bytes for item in items))
    files = sum(item.stats.files for item in items)
    document: dict[str, Any] = {
        "usage": found.to_dict(),
        "delete": {
            "parts": parts,
            "keep_reports": args.keep_reports,
            "dry_run": args.dry_run,
            "items": [item.to_dict() for item in items],
            "deleted": False,
            "errors": [],
        },
        "next_steps": [],
    }
    out = sys.stderr if args.json else sys.stdout
    verb = "would delete" if args.dry_run else "deletes"
    header = f"kalkan clean {_flags(args)}: {verb} {len(items)} items, {size} in {files:,} files"
    print(header, file=out)
    for item in items:
        note = f"  ({item.note})" if item.note else ""
        print(f"  {_size(item.stats.bytes):>10}  {item.path.as_posix()}{note}", file=out)
    if args.dry_run or not items:
        if not items:
            print("Nothing to delete.", file=out)
        return _finish_clean(args, document)
    if not args.yes:
        if not _interactive():
            print(
                "kalkan clean: nothing was deleted: stdin is not a terminal; pass --yes to delete",
                file=sys.stderr,
            )
            return 1
        from kalkan.audit.preflight import ask_yes_no  # the same question as kalkan audit

        if not ask_yes_no(f"Delete these {len(items)} items ({size})?"):
            print("Nothing was deleted.", file=out)
            return _finish_clean(args, document)
    done = cleanup.delete(items)
    errors = [f"{item.path.as_posix()}: {error}" for item in done for error in item.errors]
    removed = sum(item.stats.bytes for item in done)
    removed_files = sum(item.stats.files for item in done)
    document["delete"].update({"deleted": True, "errors": errors})
    document["delete"]["items"] = [item.to_dict() for item in done]
    print(f"Deleted {_size(removed)} in {removed_files:,} files.", file=out)
    for error in errors[:20]:
        print(f"error: {error}", file=sys.stderr)
    if args.all:
        document["next_steps"] = cleanup.next_steps(found)
        print("Next:", file=out)
        for step in document["next_steps"]:
            print(f"  {step}", file=out)
    code = _finish_clean(args, document)
    return 1 if errors else code


def _finish_clean(args: argparse.Namespace, document: dict[str, Any]) -> int:
    if args.json:
        _print_json(document)
    return EXIT_OK


def _flags(args: argparse.Namespace) -> str:
    names = ("runs", "keep_reports", "caches", "databases", "tools", "all", "dry_run")
    return " ".join("--" + name.replace("_", "-") for name in names if getattr(args, name))


def _interactive() -> bool:
    try:
        return sys.stdin.isatty()
    except (AttributeError, ValueError, OSError):
        return False


def _size(size: int) -> str:
    from kalkan.util.fs import size_text

    return size_text(size)


def _print_usage(found: Any) -> None:
    home = found.home
    print(
        f"kalkan clean: what kalkan keeps on this machine (home {home.as_posix()}, "
        f"{found.home_source})"
    )
    rows = []
    for name in ("engine", "tools", "databases", "caches", "runs"):
        part = found.parts[name]
        stats = part.stats
        where = ", ".join(_shown(folder, home) for folder in part.folders)
        if name == "engine":
            where += " (runs this command; never deleted)"
        if name == "runs":
            noun = "run" if found.runs == 1 else "runs"
            where += f" ({found.runs} {noun})"
        rows.append((part.label, _size(stats.bytes), f"{stats.files:,}", where))
    total = found.total
    rows.append(("Total", _size(total.bytes), f"{total.files:,}", ""))
    _print_table(("PART", "SIZE", "FILES", "FOLDER"), rows)
    for item in found.other:
        print(f"Not kalkan's (not deleted): {item.path.as_posix()} ({_size(item.stats.bytes)})")
    print(
        "Delete with: kalkan clean --runs [--keep-reports] | --caches | --databases | --tools | "
        "--all  (--dry-run lists, -y skips the question)"
    )


def _shown(folder: Path, home: Path) -> str:
    try:
        return folder.relative_to(home).as_posix()
    except ValueError:
        return folder.as_posix()


# ---------------------------------------------------------------------------------------------
# Output helpers


def _usage(parser: argparse.ArgumentParser, message: str) -> int:
    parser.print_usage(sys.stderr)
    print(f"{parser.prog}: error: {message}", file=sys.stderr)
    return EXIT_USAGE


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


def _print_table(headers: Sequence[str], rows: Sequence[Sequence[str]]) -> None:
    widths = [len(h) for h in headers]
    for row in rows:
        for index, cell in enumerate(row[:-1]):
            widths[index] = max(widths[index], len(str(cell)))
    lines = [headers, *rows]
    for line in lines:
        cells = [str(cell).ljust(widths[i]) for i, cell in enumerate(line[:-1])]
        print("  ".join([*cells, str(line[-1])]).rstrip())
