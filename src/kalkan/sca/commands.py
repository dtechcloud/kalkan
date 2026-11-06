# SPDX-License-Identifier: MIT
"""CLI commands ``kalkan sca sbom``, ``sca match`` and ``sca reach`` (ENGINE-SPEC 9 and 17).

Each command acts on a run (``--run <run-id>``, default ``runs/LATEST``), accepts
``--online`` and ``--json``, and starts the tools only through
``kalkan.scanners.base.run_adapter`` with the adapters of ``kalkan.scanners.registry``.

Network (docs/SECURITY.md): by default no SCA tool uses the network. The matchers read the
local databases of :mod:`kalkan.sca.vulndb`; a missing database gives a ``database_gaps`` entry
in ``sca/vulns.json``, never an online query. ``--online`` (opt-in) allows the online matching
of OSV-Scanner (api.osv.dev), the Grype database update and the online database of govulncheck
(vuln.go.dev) with Go module downloads.
``sca update-db`` is the explicit network step that downloads the databases. The
step functions :func:`run_sbom`, :func:`run_match` and :func:`run_reach` hold the logic, so that
the run engine can call them without the CLI.

- ``sca sbom``: Syft, with Trivy (``trivy-sbom``) as the fallback. The CycloneDX file is
  ``sca/sbom.cdx.json``.
- ``sca match``: OSV-Scanner and Grype, normalized, merged and written to ``sca/vulns.json``;
  one candidate per record (source ``sca``). When one engine fails (for example a missing
  local database: a ``database_gaps`` entry), a warning is recorded and the other engine
  continues. Earlier reachability decisions carry over to the new records. Manifests without
  a lockfile (:mod:`kalkan.sca.manifests`) go to ``unchecked_manifests`` and the warnings;
  their exact pins are written to ``sca/manifest-pins.cdx.json`` and matched by
  ``osv-scanner-pins`` and ``grype-pins``. Those records carry ``pin_source: "manifest"`` and
  the manifest location. Vendored JavaScript libraries (:mod:`kalkan.sca.vendored`, the local
  RetireJS repository) give records of the engine ``retirejs`` and join the same pins file;
  their records carry ``pin_source: "vendored"``, the JavaScript file as location and
  ``vendored``. The detector writes ``sca/vendored.json`` and ``sca/retirejs.status.json``.
  Known malicious package versions (an OSV ``MAL-`` ID, a GitHub malware advisory of Grype)
  become ``class: malicious-dependency`` records, critical and without a reachability step
  (:func:`kalkan.sca.normalize.mark_malicious`); the summary lists their refs (``malicious``).
- ``sca update-db``: download the OSV offline databases, the Grype database, the Go
  vulnerability database and the RetireJS repository (:func:`kalkan.sca.vulndb.update`); the
  only SCA command that uses the network by default.
- ``sca reach``: govulncheck for Go records (with Go; in local mode it reads the local Go
  database, ``govulncheck -db file:///...``); then the selection of records for ``sca_reach``
  agent tasks within the budget. The run engine creates the tasks; this command lists the
  selected refs.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from kalkan.errors import KalkanError, StateError, ToolError, UnsafeInputError, ValidationError
from kalkan.findings import severity as sev
from kalkan.sca import vendored, vulndb
from kalkan.sca.manifests import REASON_UNREADABLE, ManifestScan, pins_sbom, scan_manifests
from kalkan.sca.merge import (
    carry_over,
    merge_records,
    read_vulns,
    vulns_path,
    write_candidates,
    write_vulns,
)
from kalkan.sca.normalize import (
    is_malicious,
    parse_govulncheck_text,
    parse_grype,
    parse_osv_scanner,
)
from kalkan.sca.reach import apply_govulncheck, select_for_agents
from kalkan.sca.sbom import (
    MAX_JSON_BYTES,
    load_json_file,
    package_key,
    read_sbom,
    version_key,
)
from kalkan.util.safe_io import (
    atomic_write_json,
    atomic_write_text,
    read_bounded,
    read_text_bounded,
)

__all__ = [
    "DEFAULT_MAX_REACH_TASKS",
    "SBOM_FILE",
    "register",
    "run_match",
    "run_reach",
    "run_sbom",
    "scan_context",
]

#: The SBOM path relative to the run folder.
SBOM_FILE = "sca/sbom.cdx.json"
#: Default cap of ``sca_reach`` tasks per ``sca reach`` call.
DEFAULT_MAX_REACH_TASKS = 20
_SBOM_TOOLS = ("syft", "trivy-sbom")
_MATCHERS: tuple[tuple[str, Callable[..., Any]], ...] = (
    ("osv-scanner", parse_osv_scanner),
    ("grype", parse_grype),
)
#: The matchers of the exact manifest pins, with the engine name of their records.
_PIN_MATCHERS: tuple[tuple[str, str, Callable[..., Any]], ...] = (
    ("osv-scanner-pins", "osv-scanner", parse_osv_scanner),
    ("grype-pins", "grype", parse_grype),
)
#: ``sca/manifest-pins.cdx.json`` relative to the run folder.
PINS_SBOM_FILE = "sca/manifest-pins.cdx.json"
#: vulns.json lists at most this many manifests without a lockfile (the validator limit).
MAX_UNCHECKED_LISTED = 1000


# --- CLI ---------------------------------------------------------------------------------------


def register(subparsers: argparse._SubParsersAction) -> None:
    """Add the ``sca`` command group with ``sbom``, ``match`` and ``reach``."""
    group = subparsers.add_parser(
        "sca",
        help="Software composition analysis: sbom, match, reach.",
        description="Software composition analysis: SBOM, vulnerability matching, reachability.",
    )

    def group_help(_args: argparse.Namespace) -> int:
        group.print_help(sys.stderr)
        return 2

    group.set_defaults(func=group_help)
    steps = group.add_subparsers(dest="sca_command", metavar="<step>")
    commands = (
        ("sbom", "Build the CycloneDX SBOM (Syft, Trivy as the fallback).", _cmd_sbom),
        ("match", "Match vulnerabilities (OSV-Scanner, Grype) and write candidates.", _cmd_match),
        ("reach", "Run govulncheck for Go and select records for sca_reach tasks.", _cmd_reach),
    )
    for name, text, handler in commands:
        parser = steps.add_parser(name, help=text, description=text)
        parser.add_argument("--run", metavar="RUN_ID", help="run ID (default: runs/LATEST)")
        network = parser.add_mutually_exclusive_group()
        network.add_argument(
            "--online",
            action="store_true",
            help=(
                "opt in to network use: online matching sends the package names and versions "
                "of the target to the database services (default: local databases only)"
            ),
        )
        network.add_argument("--offline", action="store_true", help=argparse.SUPPRESS)
        parser.add_argument("--json", action="store_true", help="print the result as JSON")
        parser.add_argument(
            "--timeout",
            type=int,
            default=None,
            metavar="SECONDS",
            help="time limit per tool (default: the adapter default; 0 removes the limit)",
        )
        if name == "reach":
            parser.add_argument(
                "--max-tasks",
                type=int,
                default=DEFAULT_MAX_REACH_TASKS,
                metavar="N",
                help=f"cap of selected sca_reach records (default {DEFAULT_MAX_REACH_TASKS})",
            )
        parser.set_defaults(func=handler)

    text = (
        "Download the local vulnerability databases (network: sends only ecosystem names, "
        "the Grype database request and the request for the Go database archive, never a "
        "package of a target)."
    )
    update = steps.add_parser("update-db", help=text, description=text)
    update.add_argument(
        "--ecosystems",
        metavar="LIST",
        help="comma-separated OSV ecosystems (default: "
        + ", ".join(vulndb.DEFAULT_ECOSYSTEMS)
        + ")",
    )
    update.add_argument("--no-osv", action="store_true", help="skip the OSV databases")
    update.add_argument("--no-grype", action="store_true", help="skip the Grype database")
    update.add_argument(
        "--no-go", action="store_true", help="skip the Go vulnerability database (govulncheck)"
    )
    update.add_argument(
        "--no-retire",
        action="store_true",
        help="skip the RetireJS repository (vendored JavaScript libraries)",
    )
    update.add_argument(
        "--go-source",
        choices=("auto", "official", "osv"),
        default="auto",
        help=(
            "source of the Go database: auto (default: the vuln.go.dev archive, else built "
            "from the OSV Go database), official, or osv"
        ),
    )
    update.add_argument(
        "--timeout",
        type=int,
        default=vulndb.DEFAULT_TIMEOUT_SECONDS,
        metavar="SECONDS",
        help=f"time limit per tool (default {vulndb.DEFAULT_TIMEOUT_SECONDS}; 0 removes it)",
    )
    update.add_argument(
        "--max-age",
        type=_hours,
        default=vulndb.DEFAULT_MAX_AGE_HOURS,
        metavar="HOURS",
        help=(
            "keep a database whose files are valid, whose last download ended ok and that is "
            f"younger than this (default {vulndb.DEFAULT_MAX_AGE_HOURS}; the installers use "
            f"{vulndb.SETUP_MAX_AGE_HOURS}, the stale limit of kalkan doctor)"
        ),
    )
    update.add_argument(
        "--force", action="store_true", help="download every selected database, also a fresh one"
    )
    update.add_argument("--json", action="store_true", help="print the result as JSON")
    update.set_defaults(func=_cmd_update_db)


def _hours(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError("expected a whole number of hours") from None
    if value < 0:
        raise argparse.ArgumentTypeError("expected 0 or more hours")
    return value


def _cmd_sbom(args: argparse.Namespace) -> int:
    run_dir = _run_dir(args.run)
    summary = run_sbom(run_dir, offline=not args.online, timeout_seconds=args.timeout)
    _print(args, summary, _sbom_lines(summary))
    return 0


def _cmd_match(args: argparse.Namespace) -> int:
    run_dir = _run_dir(args.run)
    summary = run_match(run_dir, offline=not args.online, timeout_seconds=args.timeout)
    _print(args, summary, _match_lines(summary))
    return 0


def _cmd_reach(args: argparse.Namespace) -> int:
    run_dir = _run_dir(args.run)
    summary = run_reach(
        run_dir,
        offline=not args.online,
        max_tasks=args.max_tasks,
        timeout_seconds=args.timeout,
    )
    _print(args, summary, _reach_lines(summary))
    return 0


def _cmd_update_db(args: argparse.Namespace) -> int:
    ecosystems = None
    if args.ecosystems:
        ecosystems = [item.strip() for item in args.ecosystems.split(",") if item.strip()]
    if args.timeout < 0:
        raise ValidationError("--timeout must be 0 or a positive number")
    max_age = getattr(args, "max_age", vulndb.DEFAULT_MAX_AGE_HOURS)
    force = bool(getattr(args, "force", False))
    try:
        summary = vulndb.update(
            ecosystems=ecosystems,
            osv=not args.no_osv,
            grype=not args.no_grype,
            go=not args.no_go,
            retire=not args.no_retire,
            go_source=args.go_source,
            timeout_seconds=args.timeout,
            max_age_hours=max_age,
            force=force,
        )
    except ValueError as exc:
        raise ValidationError(str(exc)) from None
    wanted = (
        ("osv", not args.no_osv),
        ("grype", not args.no_grype),
        ("go", not args.no_go),
        ("retire", not args.no_retire),
    )
    parts = [name for name, on in wanted if on]
    rule = (
        "--force: every selected database is downloaded"
        if force
        else f"a database younger than {max_age} hours is kept; --force downloads it"
    )
    lines = [f"sca update-db: {summary['root']} ({rule})"]
    lines.extend(f"  {name}: {update_line(name, summary.get(name) or {})}" for name in parts)
    _print(args, summary, lines)
    statuses = [(summary.get(name) or {}).get("status") for name in parts]
    if statuses and all(status == "skipped" for status in statuses):
        return 5
    return 1 if any(status != "ok" for status in statuses) else 0


def update_line(name: str, info: dict[str, Any]) -> str:
    """Return the ``sca update-db`` line of one database (without the name).

    A kept database: ``kept, 3 hours old (13 ecosystems)``. A download: the status and the
    facts, then why it ran: ``ok 13 ecosystems (download reason: no local database for npm)``.
    """
    status = info.get("status")
    known: list[str] = []
    if name == "osv":
        known.append(f"{len(info.get('ecosystems') or [])} ecosystems")
    elif name == "grype" and info.get("built"):
        known.append(f"built {info.get('built')}")
    elif name == "go" and status == "ok":
        known.append(f"source {info.get('go_source') or info.get('source')}")
        known.append(f"modified {info.get('modified') or info.get('version')}")
        known.append(f"{info.get('entries')} entries" if info.get("entries") is not None else "")
    elif name == "retire" and status == "ok":
        for key in ("libraries", "vulnerabilities"):
            known.append(f"{info.get(key)} {key}" if info.get(key) is not None else "")
        digest = info.get("sha256") or info.get("version")
        known.append(f"sha256 {str(digest)[:12]}" if digest else "")
    facts = ", ".join(item for item in known if item)
    if info.get("action") == "kept":
        age = vulndb.age_text(float(info.get("age_hours") or 0.0) * 3600)
        return f"kept, {age} old" + (f" ({facts})" if facts else "")
    text = f"{status} {facts} {info.get('message') or ''}".strip()
    reason = info.get("reason")
    return f"{text} (download reason: {reason})" if reason else text


def _print(args: argparse.Namespace, summary: dict[str, Any], lines: list[str]) -> None:
    for line in lines:
        print(line, file=sys.stderr)
    for warning in summary.get("warnings", [])[:50]:
        print(f"  warning: {warning}", file=sys.stderr)
    if args.json:
        print(json.dumps(summary, ensure_ascii=False, indent=2))


def _sbom_lines(summary: dict[str, Any]) -> list[str]:
    counts = ", ".join(f"{k} {v}" for k, v in summary["by_ecosystem"].items()) or "none"
    return [
        f"sca sbom: {summary['engine']} ok, {summary['components']} components ({counts})",
        f"  sbom: {summary['sbom']}",
    ]


def _match_lines(summary: dict[str, Any]) -> list[str]:
    lines = [
        f"sca match: {summary['records']} records, {summary['merged']} after merge, "
        f"{summary['candidates']} candidates"
    ]
    for name, info in summary["engines"].items():
        lines.append(f"  {name}: {info['status']} ({info['records']} records) {info['message']}")
    severities = ", ".join(f"{k} {v}" for k, v in summary["by_severity"].items() if v)
    lines.append(f"  severity: {severities or 'none'}")
    malicious = summary.get("malicious") or []
    if malicious:
        lines.append(
            f"  malicious packages: {len(malicious)} (class malicious-dependency, critical, "
            "no reachability step): " + ", ".join(malicious[:5])
        )
    for gap in summary.get("database_gaps") or []:
        lines.append(f"  database gap: {gap['engine']}: {gap['reason']}")
    unchecked = summary.get("unchecked_manifests") or []
    if unchecked:
        lines.append(
            f"  manifests without a lockfile: {len(unchecked)} "
            f"({summary.get('manifest_pins', 0)} exact pins checked, version ranges not checked)"
        )
    libraries = summary.get("vendored_libraries") or []
    if libraries:
        files = len({item.get("path") for item in libraries})
        lines.append(
            f"  vendored JavaScript libraries: {len(libraries)} in {files} files "
            f"({summary.get('vendored_records', 0)} records)"
        )
    return lines


def _reach_lines(summary: dict[str, Any]) -> list[str]:
    gv = summary["govulncheck"]
    states = summary["reachability"]
    return [
        f"sca reach: govulncheck {gv['status']} {gv['message']}".rstrip(),
        f"  reachable {states['reachable']}, not_reachable {states['not_reachable']}, "
        f"unknown {states['unknown']}",
        f"  selected for sca_reach tasks: {len(summary['selected_for_agents'])}",
    ]


# --- run context -------------------------------------------------------------------------------


def _run_dir(run_id: str | None) -> Path:
    from kalkan.run.ids import resolve_run

    return resolve_run(run_id)


def _target_dir(run_dir: Path) -> Path:
    target = run_dir / "target"
    try:
        from kalkan.run.state import RunContext

        target = RunContext.load(run_dir).target_dir
    except (ImportError, KalkanError, KeyError, OSError, ValueError):
        pass
    if not target.is_dir():
        raise StateError(f"the run has no target folder: {target.name}")
    return target


def _tech(run_dir: Path, target_dir: Path) -> frozenset[str]:
    manifest = run_dir / "target-manifest.json"
    try:
        data = json.loads(read_text_bounded(manifest))
        tech = data.get("tech") if isinstance(data, dict) else None
        if isinstance(tech, list):
            return frozenset(t for t in tech if isinstance(t, str))
    except (KalkanError, OSError, ValueError):
        pass
    try:
        from kalkan.run.tech import detect

        return frozenset(detect(target_dir))
    except (ImportError, KalkanError, OSError, ValueError, TypeError):
        return frozenset()


def scan_context(run_dir: str | os.PathLike[str], *, offline: bool = True) -> Any:
    """Return the ``kalkan.scanners.base.ScanContext`` of a run.

    ``kalkan.scanners.base.load_scan_context`` reads ``target-manifest.json``. A run folder
    without a manifest (made by hand) gets a context from ``state.json`` and the target folder.
    """
    base = _scanners_base()
    directory = Path(run_dir)
    loader = getattr(base, "load_scan_context", None)
    if loader is not None and (directory / "target-manifest.json").is_file():
        return loader(directory, offline=offline)
    target = _target_dir(directory)
    source = None
    try:
        from kalkan.run.state import RunContext

        source = RunContext.load(directory).source_dir
    except (ImportError, KalkanError, KeyError, OSError, ValueError):
        source = None
    return base.ScanContext(
        run_dir=directory,
        target_dir=target,
        source_dir=source,
        tech=_tech(directory, target),
        offline=offline,
    )


def _scanners_base() -> Any:
    try:
        from kalkan.scanners import base
    except ImportError as exc:
        raise ToolError(f"kalkan.scanners is not available: {exc}") from exc
    return base


def _adapter(name: str) -> Any:
    try:
        from kalkan.scanners import registry
    except ImportError as exc:
        raise ToolError(f"kalkan.scanners.registry is not available: {exc}") from exc
    return registry.get(name)


def _run(name: str, ctx: Any, timeout_seconds: int | None) -> Any:
    base = _scanners_base()
    if timeout_seconds is None:
        return base.run_adapter(_adapter(name), ctx)
    return base.run_adapter(_adapter(name), ctx, timeout_seconds=timeout_seconds)


def _output(result: Any) -> Path | None:
    path = getattr(result, "output_path", None)
    if path is None:
        return None
    path = Path(path)
    return path if path.is_file() else None


def _relative(run_dir: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(run_dir.resolve()).as_posix()
    except ValueError:
        return path.name


# --- steps -------------------------------------------------------------------------------------


def run_sbom(
    run_dir: str | os.PathLike[str], *, offline: bool = True, timeout_seconds: int | None = None
) -> dict[str, Any]:
    """Build ``sca/sbom.cdx.json`` with Syft, else Trivy. Return a summary dict.

    Raise :class:`~kalkan.errors.ToolError` when neither tool gives a CycloneDX SBOM.
    """
    directory = Path(run_dir)
    ctx = scan_context(directory, offline=offline)
    (directory / "sca").mkdir(parents=True, exist_ok=True)
    attempts: list[dict[str, Any]] = []
    warnings: list[str] = []
    for name in _SBOM_TOOLS:
        result = _run(name, ctx, timeout_seconds)
        attempts.append({"engine": name, "status": result.status, "message": result.message})
        output = _output(result)
        if result.status != "ok" or output is None:
            warnings.append(f"{name}: {result.status}: {result.message}".rstrip(": "))
            continue
        try:
            sbom = read_sbom(output, ctx.target_dir)
        except ValidationError as exc:
            warnings.append(f"{name}: {exc}")
            continue
        destination = directory / SBOM_FILE
        if output.resolve() != destination.resolve():
            _copy_text(output, destination)
        return {
            "step": "sbom",
            "engine": name,
            "status": "ok",
            "sbom": SBOM_FILE,
            "tool": sbom.tool,
            "spec_version": sbom.spec_version,
            "components": len(sbom.components),
            "by_ecosystem": sbom.by_ecosystem(),
            "attempts": attempts,
            "warnings": warnings + sbom.warnings,
        }
    raise ToolError("no SBOM tool produced a CycloneDX SBOM: " + "; ".join(warnings))


def _copy_text(source: Path, destination: Path) -> None:
    data = read_bounded(source, MAX_JSON_BYTES)
    atomic_write_text(destination, data.decode("utf-8-sig"))


def run_match(
    run_dir: str | os.PathLike[str], *, offline: bool = True, timeout_seconds: int | None = None
) -> dict[str, Any]:
    """Run OSV-Scanner and Grype, merge their records, write vulns.json and the candidates.

    ``offline`` (the default) uses only the local databases; a missing database becomes a
    ``database_gaps`` entry. Raise :class:`~kalkan.errors.ToolError` when no matcher gives a
    result for another reason (for example a missing tool); vulns.json then stays as it was.
    """
    directory = Path(run_dir)
    ctx = scan_context(directory, offline=offline)
    (directory / "sca").mkdir(parents=True, exist_ok=True)
    records: list[dict[str, Any]] = []
    warnings: list[str] = []
    engines: dict[str, dict[str, Any]] = {}
    for name, parse in _MATCHERS:
        result = _run(name, ctx, timeout_seconds)
        info = {"status": result.status, "message": result.message, "records": 0, "output": None}
        engines[name] = info
        output = _output(result)
        if result.status != "ok" or output is None:
            warnings.append(f"{name}: {result.status}: {result.message}".rstrip(": "))
            info["status"] = result.status if result.status != "ok" else "failed"
            continue
        relative = _relative(directory, output)
        try:
            parsed = parse(load_json_file(output), ctx.target_dir, relative)
        except (UnsafeInputError, ValidationError) as exc:
            warnings.append(f"{name}: {exc}")
            info["status"] = "failed"
            continue
        records.extend(parsed.records)
        warnings.extend(f"{name}: {w}" for w in parsed.warnings)
        info["records"] = len(parsed.records)
        info["output"] = relative
    if not any(info["status"] == "ok" for info in engines.values()):
        if not _database_gaps(directory, engines):
            raise ToolError("no vulnerability matcher produced a result: " + "; ".join(warnings))
        warnings.append(
            "no vulnerability matcher ran: a local vulnerability database is missing "
            "(run: kalkan sca update-db); no package was checked"
        )
    manifests = scan_manifests(ctx.target_dir)
    warnings.extend(manifests.warnings)
    warnings.extend(_unchecked_warnings(manifests))
    found = _scan_vendored(directory, ctx, engines, warnings, timeout_seconds)
    records.extend(vendored.retire_records(found.detections, found.repository))
    engines[vendored.ENGINE]["records"] = sum(
        1 for record in records if record["engines"] == [vendored.ENGINE]
    )
    records.extend(
        _match_pins(directory, ctx, manifests, engines, warnings, timeout_seconds, found.detections)
    )
    merged = merge_records(records)
    try:
        previous = read_vulns(directory)["records"]
    except ValidationError as exc:
        warnings.append(f"the earlier sca/vulns.json is not valid and was replaced: {exc}")
        previous = []
    carried = carry_over(merged, previous)
    gaps = _database_gaps(directory, engines)
    unchecked = manifests.unchecked[:MAX_UNCHECKED_LISTED]
    if len(manifests.unchecked) > len(unchecked):
        warnings.append(
            f"{len(manifests.unchecked)} manifests without a lockfile; vulns.json lists the "
            f"first {MAX_UNCHECKED_LISTED}"
        )
    with _lock(directory):
        write_vulns(directory, merged, warnings, unchecked, gaps)
    count = write_candidates(directory, merged, warnings, target_dir=ctx.target_dir)
    return {
        "step": "match",
        "records": len(records),
        "merged": len(merged),
        "carried_over": carried,
        "by_severity": _by_severity(merged),
        "engines": engines,
        "vulns": "sca/vulns.json",
        "candidates": count,
        "unchecked_manifests": unchecked,
        "database_gaps": gaps,
        "manifest_pins": len({(p.ecosystem, p.name, p.version) for p in manifests.pins}),
        "pin_records": sum(1 for record in merged if record.get("pin_source") == "manifest"),
        "vendored_libraries": found.libraries(),
        "vendored_records": sum(1 for record in merged if record.get("vendored")),
        "malicious": [record["ref"] for record in merged if is_malicious(record)],
        "examples": [record["ref"] for record in merged[:5]],
        "warnings": warnings,
    }


def _scan_vendored(
    run_dir: Path,
    ctx: Any,
    engines: dict[str, dict[str, Any]],
    warnings: list[str],
    timeout_seconds: int | None,
) -> vendored.VendoredScan:
    """Run the vendored JavaScript check and write its outputs (:mod:`kalkan.sca.vendored`).

    The local RetireJS repository is the only source; a missing repository gives a skip
    whose message starts with ``no local`` (a database gap) when the target has JavaScript
    files. ``timeout_seconds`` is the limit of the whole check (0 removes it).
    """
    if timeout_seconds is None:
        total: float | None = vendored.DEFAULT_TOTAL_SECONDS
    else:
        total = float(timeout_seconds) if timeout_seconds > 0 else None
    root = vulndb.db_root()
    found = vendored.scan(
        ctx.target_dir,
        vulndb.retire_file(root),
        work_dir=run_dir / "sca" / ".work" / vendored.ENGINE,
        total_seconds=total,
        repository_info=vulndb.retire_info(root),
    )
    vendored.write_outputs(run_dir, found)
    engines[vendored.ENGINE] = {
        "status": found.status,
        "message": found.message,
        "records": 0,
        "output": vendored.VENDORED_FILE,
    }
    warnings.extend(f"{vendored.ENGINE}: {warning}" for warning in found.warnings)
    if found.status not in ("ok", "skipped") or (
        found.status == "skipped" and found.message.startswith("no local ")
    ):
        warnings.append(f"{vendored.ENGINE}: {found.status}: {found.message}")
    return found


def _database_gaps(run_dir: Path, engines: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Return the ``database_gaps`` entries of the matchers that ran (or were skipped) now.

    A matcher skipped for a missing local database gives one entry with ``ecosystem`` null;
    each ecosystem that OSV-Scanner reported without a database (``missing_databases`` in its
    status file) gives one entry.
    """
    gaps: dict[tuple[str, str | None], dict[str, Any]] = {}
    for name, info in engines.items():
        message = str(info.get("message") or "")
        if info.get("status") == "skipped" and message.startswith("no local "):
            gaps[(name, None)] = {"engine": name, "ecosystem": None, "reason": message}
        path = run_dir / "sca" / f"{name}.status.json"
        try:
            status = json.loads(read_text_bounded(path, 4 * 1024 * 1024))
        except (KalkanError, OSError, ValueError):
            continue
        missing = status.get("missing_databases") if isinstance(status, dict) else None
        if not isinstance(missing, list):
            continue
        for ecosystem in missing:
            if not isinstance(ecosystem, str) or not ecosystem.strip():
                continue
            reason = (
                f"no local OSV database for {ecosystem}, so this OSV-Scanner run checked no "
                f'package (run: kalkan sca update-db --ecosystems "{ecosystem}")'
            )
            gaps[(name, ecosystem)] = {"engine": name, "ecosystem": ecosystem, "reason": reason}
    return list(gaps.values())


def _unchecked_warnings(manifests: ManifestScan) -> list[str]:
    """Return one warning per manifest without a lockfile."""
    lines = []
    for item in manifests.unchecked:
        detail = item["reason"]
        if item["reason"] != REASON_UNREADABLE:
            detail += (
                f" ({item['ranges']} version ranges not checked, {item['exact_pins']} exact "
                "pins checked)"
            )
        lines.append(
            f"{item['file']}: {item['ecosystem']} manifest without a lockfile; SCA coverage is "
            f"partial: {detail}"
        )
    return lines


def _match_pins(
    run_dir: Path,
    ctx: Any,
    manifests: ManifestScan,
    engines: dict[str, dict[str, Any]],
    warnings: list[str],
    timeout_seconds: int | None,
    detections: list[Any] | None = None,
) -> list[dict[str, Any]]:
    """Write the pins SBOM, run the pin matchers and return their records.

    Each record of a manifest pin gets the manifest paths as ``locations`` and
    ``pin_source: "manifest"``. Each record of a vendored JavaScript library (``detections``,
    :mod:`kalkan.sca.vendored`) gets the JavaScript files as ``locations``,
    ``pin_source: "vendored"`` and the ``vendored`` entries; a package that is both gives one
    record of each kind, which the merge joins. Without pins and detections, an old pins SBOM
    and the old status files of the pin matchers are removed, and no tool runs.
    """
    sbom = run_dir / PINS_SBOM_FILE
    detections = list(detections or [])
    if not manifests.pins and not detections:
        sbom.unlink(missing_ok=True)
        for name, _engine, _parse in _PIN_MATCHERS:
            (run_dir / "sca" / f"{name}.status.json").unlink(missing_ok=True)
        return []
    atomic_write_json(sbom, pins_sbom(manifests.pins, detections))
    files = manifests.pin_files()
    copies = vendored.pin_locations(detections)
    found: list[dict[str, Any]] = []
    for name, engine, parse in _PIN_MATCHERS:
        result = _run(name, ctx, timeout_seconds)
        info = {"status": result.status, "message": result.message, "records": 0, "output": None}
        engines[name] = info
        output = _output(result)
        if result.status != "ok" or output is None:
            warnings.append(f"{name}: {result.status}: {result.message}".rstrip(": "))
            info["status"] = result.status if result.status != "ok" else "failed"
            continue
        relative = _relative(run_dir, output)
        try:
            # The tools name the pins SBOM as the location. The sca folder is the root here;
            # the manifest paths replace the location below.
            parsed = parse(load_json_file(output), run_dir / "sca", relative)
        except (UnsafeInputError, ValidationError) as exc:
            warnings.append(f"{name}: {exc}")
            info["status"] = "failed"
            continue
        kept = 0
        for record in parsed.records:
            key = (
                record["ecosystem"],
                package_key(record["ecosystem"], record["package"]),
                version_key(record["ecosystem"], record["version"]),
            )
            if record["engines"] != [engine] or (key not in files and key not in copies):
                warnings.append(
                    f"{name}: {record['ref']} matches no manifest pin and no vendored library; "
                    "skipped"
                )
                continue
            if key in files:
                found.append({**record, "locations": list(files[key]), "pin_source": "manifest"})
            if key in copies:
                found.append(
                    {
                        **record,
                        "locations": list(dict.fromkeys(item.path for item in copies[key])),
                        "pin_source": "vendored",
                        "vendored": vendored.vendored_entries(copies[key]),
                    }
                )
            kept += 1
        warnings.extend(f"{name}: {w}" for w in parsed.warnings)
        info["records"] = kept
        info["output"] = relative
    return found


def run_reach(
    run_dir: str | os.PathLike[str],
    *,
    offline: bool = True,
    max_tasks: int = DEFAULT_MAX_REACH_TASKS,
    timeout_seconds: int | None = None,
) -> dict[str, Any]:
    """Run govulncheck for the Go records and select the records for ``sca_reach`` tasks.

    Raise :class:`~kalkan.errors.StateError` when ``sca/vulns.json`` does not exist.
    """
    directory = Path(run_dir)
    if not vulns_path(directory).is_file():
        raise StateError("sca/vulns.json does not exist; run: kalkan sca match")
    doc = read_vulns(directory)
    records = doc["records"]
    warnings = list(doc["warnings"])
    govulncheck: dict[str, Any] = {"status": "skipped", "message": "no Go records", "counts": {}}
    target_dir = _target_dir(directory)
    if any(record["ecosystem"] == "Go" for record in records):
        ctx = scan_context(directory, offline=offline)
        result = _run("govulncheck", ctx, timeout_seconds)
        govulncheck = {"status": result.status, "message": result.message, "counts": {}}
        output = _output(result)
        if result.status == "ok" and output is not None:
            module_dir = _module_dir(records)
            try:
                text = read_bounded(output, MAX_JSON_BYTES).decode("utf-8-sig")
            except (UnsafeInputError, UnicodeDecodeError) as exc:
                warnings.append(f"govulncheck: the output cannot be read: {exc}")
            else:
                parsed = parse_govulncheck_text(text, module_dir, _relative(directory, output))
                warnings.extend(f"govulncheck: {w}" for w in parsed.warnings)
                govulncheck["counts"] = apply_govulncheck(records, parsed, target_dir)
                govulncheck["module_dir"] = module_dir
        elif result.status != "ok":
            partial = _govulncheck_partial(directory)
            if partial:
                govulncheck["partial_packages"] = partial["count"]
                govulncheck["message"] = (
                    f"{partial['count']} Go packages could not load: "
                    f"{partial['packages'][0]['reason']} ({partial['hint']})"
                )
            warnings.append(f"govulncheck: {result.status}: {govulncheck['message']}".rstrip(": "))
    gaps = _reach_database_gaps(doc.get("database_gaps"), govulncheck)
    remaining = _remaining_budget(directory, max_tasks)
    selected = select_for_agents(records, remaining_budget=remaining, max_tasks=max_tasks)
    warnings = list(dict.fromkeys(warnings))
    with _lock(directory):
        write_vulns(directory, records, warnings, doc.get("unchecked_manifests"), gaps)
    count = write_candidates(directory, records, warnings, target_dir=target_dir)
    states = {"reachable": 0, "not_reachable": 0, "unknown": 0}
    for record in records:
        states[record["reachability"]] += 1
    return {
        "step": "reach",
        "govulncheck": govulncheck,
        "reachability": states,
        "remaining_budget": remaining,
        "selected_for_agents": [record["ref"] for record in selected],
        "candidates": count,
        "warnings": warnings,
    }


def _govulncheck_partial(run_dir: Path) -> dict[str, Any] | None:
    """Return ``partial_packages`` of ``sca/govulncheck.status.json``, or None."""
    try:
        status = json.loads(read_text_bounded(run_dir / "sca" / "govulncheck.status.json"))
    except (KalkanError, OSError, ValueError):
        return None
    partial = status.get("partial_packages") if isinstance(status, dict) else None
    if not isinstance(partial, dict) or not partial.get("packages"):
        return None
    return partial


def _reach_database_gaps(
    gaps: list[dict[str, Any]] | None, govulncheck: dict[str, Any]
) -> list[dict[str, Any]]:
    """Return the database gaps of ``vulns.json`` with the govulncheck gap of this run.

    govulncheck skipped in local mode for a missing local Go database gives one gap (Go
    reachability not checked); a run that found its database removes an earlier one.
    """
    kept = [dict(gap) for gap in gaps or [] if gap.get("engine") != "govulncheck"]
    if (
        govulncheck.get("status") == "skipped"
        and govulncheck.get("message") == vulndb.GO_DB_MISSING
    ):
        kept.append(
            {
                "engine": "govulncheck",
                "ecosystem": "Go",
                "reason": (
                    "no local Go vulnerability database, so govulncheck did not check the "
                    "reachability of the Go records (run: kalkan sca update-db)"
                ),
            }
        )
    return kept


def _module_dir(records: list[dict[str, Any]]) -> str:
    """Return the folder of the shallowest ``go.mod`` among the Go record locations."""
    folders = {
        location.rsplit("/", 1)[0] if "/" in location else ""
        for record in records
        if record["ecosystem"] == "Go"
        for location in record["locations"]
        if location.rsplit("/", 1)[-1] == "go.mod"
    }
    if not folders:
        return ""
    return sorted(folders, key=lambda folder: (folder.count("/") if folder else -1, folder))[0]


def _remaining_budget(run_dir: Path, default: int) -> int:
    try:
        from kalkan.run.budget import available
        from kalkan.run.state import load_state

        return int(available(load_state(run_dir), "sca_reach"))
    except (ImportError, KalkanError, KeyError, OSError, TypeError, ValueError):
        return max(int(default), 0)


def _by_severity(records: list[dict[str, Any]]) -> dict[str, int]:
    counts = dict.fromkeys(sev.SEVERITIES, 0)
    for record in records:
        counts[record["severity"]] += 1
    return counts


class _NoLock:
    def __enter__(self) -> None:
        return None

    def __exit__(self, *_exc: object) -> None:
        return None


def _lock(run_dir: Path) -> Any:
    try:
        from kalkan.run.lock import run_lock
    except ImportError:
        return _NoLock()
    return run_lock(run_dir)
