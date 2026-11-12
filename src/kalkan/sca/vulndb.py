# SPDX-License-Identifier: MIT
"""Local vulnerability databases of the SCA matchers (docs/ENGINE-SPEC.md 17, docs/SECURITY.md).

By default ``sca match`` never queries an online API: package names and versions of the audited
project never leave the machine. OSV-Scanner runs with ``--offline`` and reads the OSV offline
databases; Grype reads its own database with the update check off. Both live in the kalkan home:

    <home>/.tools/vulndb/osv/osv-scalibr/<ecosystem>/all.zip    (OSV-Scanner 2.6.0 layout)
    <home>/.tools/vulndb/grype/<schema>/vulnerability.db        (Grype 0.119.0 layout)
    <home>/.tools/vulndb/go/index/modules.json, ID/<id>.json    (govulncheck -db file:///...)
    <home>/.tools/vulndb/retire/jsrepository-v5.json            (vendored JavaScript check)
    <home>/.tools/vulndb/status.json                            (the last update-db result)

``kalkan sca update-db`` (:func:`update`) is the explicit network step that fills them. It sends
only ecosystem names (OSV) and the Grype database listing request, never a package of the
project. It downloads a database only when it must (:func:`check_fresh`): a database whose
files are present and valid, whose last download ended ``ok`` and that is younger than
``max_age_hours`` (default :data:`DEFAULT_MAX_AGE_HOURS`) is kept. ``force`` downloads every
database. The installers pass :data:`SETUP_MAX_AGE_HOURS` (the stale limit of ``kalkan
doctor``), so a new setup within a week downloads nothing. ``status.json`` records per database
its name, ``status``, ``action`` (``kept``, ``downloaded``, ``failed`` or ``skipped``), ``source``,
``version`` (the
newest archive time for OSV, ``built`` for Grype, ``modified`` for Go, the SHA-256 for RetireJS)
and ``downloaded_at``; :func:`read_status` also reads the older format, whose parts carry only
``updated_at``. The databases:

- OSV: ``osv-scanner scan source -L <probe> --offline-vulnerabilities
  --download-offline-databases --no-resolve`` on a probe CycloneDX file with one made-up package
  per ecosystem (:data:`PROBE_PURLS`). OSV-Scanner downloads ``<ecosystem>/all.zip`` from the
  OSV bucket into ``OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY`` and matches the probe locally. Tested
  on 2026-10-16 with the 13 default ecosystems (about 290 MB, npm 209 MB). An ecosystem that
  the bucket does not have (``ConanCenter`` gave HTTP 404) stops the download of the others, so
  the default list holds only ecosystems that exist.
- Grype: ``grype db update`` with ``GRYPE_DB_CACHE_DIR``, then ``grype db status -o json``.
- Go (govulncheck): the official archive ``https://vuln.go.dev/vulndb.zip``, else a database
  built from the ``GO-*.json`` entries of the OSV Go archive (:mod:`kalkan.sca.govulndb`), in
  ``<home>/.tools/vulndb/go/``. ``govulncheck -db file:///...`` reads it in local mode.
- RetireJS: the library repository ``jsrepository-v5.json`` of RetireJS/retire.js (a GET request
  to raw.githubusercontent.com, :mod:`kalkan.sca.retiredb`) in ``<home>/.tools/vulndb/retire/``.
  The vendored JavaScript check of ``sca match`` (:mod:`kalkan.sca.vendored`) reads it.

A missing database is never fetched during a match: the matcher is skipped or reports the
missing ecosystem, and ``sca match`` records a ``database_gaps`` entry in ``sca/vulns.json``.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import zipfile
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

__all__ = [
    "DATABASES",
    "DEFAULT_ECOSYSTEMS",
    "DEFAULT_MAX_AGE_HOURS",
    "GO_DB_MISSING",
    "OSV_LAYOUT",
    "PROBE_PURLS",
    "SETUP_MAX_AGE_HOURS",
    "STALE_DAYS",
    "Freshness",
    "age_text",
    "check_fresh",
    "db_root",
    "describe",
    "downloaded_at",
    "files_problem",
    "go_db_info",
    "go_db_ready",
    "go_db_uri",
    "go_dir",
    "grype_dir",
    "grype_env",
    "grype_ready",
    "missing_from_stderr",
    "osv_dir",
    "osv_ecosystems",
    "osv_env",
    "read_status",
    "retire_file",
    "retire_info",
    "update",
]

#: The folder below ``osv_dir`` where OSV-Scanner 2.6.0 keeps one ``all.zip`` per ecosystem.
OSV_LAYOUT: Final = "osv-scalibr"
#: The ecosystems that ``update-db`` downloads by default (all exist in the OSV bucket).
DEFAULT_ECOSYSTEMS: Final = (
    "npm",
    "PyPI",
    "Go",
    "Maven",
    "RubyGems",
    "Packagist",
    "crates.io",
    "NuGet",
    "Pub",
    "Hex",
    "CRAN",
    "SwiftURL",
    "GitHub Actions",
)
#: One made-up package per ecosystem. OSV-Scanner downloads the database of each ecosystem of
#: the scanned packages; the names never leave the machine (the match is local).
PROBE_PURLS: Final = {
    "npm": "pkg:npm/kalkan-probe@0.0.0",
    "PyPI": "pkg:pypi/kalkan-probe@0.0.0",
    "Go": "pkg:golang/example.com/kalkan-probe@v0.0.0",
    "Maven": "pkg:maven/org.example/kalkan-probe@0.0.0",
    "RubyGems": "pkg:gem/kalkan-probe@0.0.0",
    "Packagist": "pkg:composer/kalkan/probe@0.0.0",
    "crates.io": "pkg:cargo/kalkan-probe@0.0.0",
    "NuGet": "pkg:nuget/Kalkan.Probe@0.0.0",
    "Pub": "pkg:pub/kalkan_probe@0.0.0",
    "Hex": "pkg:hex/kalkan_probe@0.0.0",
    "CRAN": "pkg:cran/kalkanprobe@0.0.0",
    "SwiftURL": "pkg:swift/github.com/kalkan/probe@0.0.0",
    "GitHub Actions": "pkg:github/kalkan/probe@v0",
}
#: The skip reason of govulncheck in local mode without a local Go database.
GO_DB_MISSING: Final = "no local Go vulnerability database (run: kalkan sca update-db)"
#: ``doctor`` warns when the databases are older than this.
STALE_DAYS: Final = 7
#: ``update-db`` keeps a database that is younger than this (hours; ``--max-age``).
DEFAULT_MAX_AGE_HOURS: Final = 24
#: The limit of the installers and setup scripts: the stale limit of ``doctor`` in hours, so a
#: new setup or a plugin update within a week downloads nothing.
SETUP_MAX_AGE_HOURS: Final = STALE_DAYS * 24
#: The databases of ``update-db``, in the order of the download.
DATABASES: Final = ("osv", "grype", "go", "retire")
DEFAULT_TIMEOUT_SECONDS: Final = 1800
STATUS_NAME: Final = "status.json"
#: 2: one record per database with ``database``, ``action``, ``source``, ``version`` and
#: ``downloaded_at``. Version 1 (no ``schema_version``) had only ``status`` and ``updated_at``.
STATUS_SCHEMA_VERSION: Final = 2
#: Where OSV-Scanner downloads ``<ecosystem>/all.zip`` (the OSV bucket).
OSV_SOURCE: Final = "https://osv-vulnerabilities.storage.googleapis.com"
#: The Grype database listing; ``grype/<schema>/import.json`` names the exact archive.
GRYPE_SOURCE: Final = "https://grype.anchore.io/databases"
#: A download time further in the future than this (a changed clock) counts as unknown.
_CLOCK_SLACK_SECONDS: Final = 3600
_SQLITE_MAGIC: Final = b"SQLite format 3\x00"
_MISSING_DB: Final = re.compile(r"could not load db for (.+?) ecosystem")


def db_root(home: Path | None = None) -> Path:
    """Return ``<home>/.tools/vulndb`` (the home of :func:`kalkan.resources.home`)."""
    if home is None:
        from kalkan.resources import home as kalkan_home  # lazy: keeps imports small

        home = kalkan_home()
    return Path(home) / ".tools" / "vulndb"


def osv_dir(root: Path | None = None) -> Path:
    """Return the ``OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY`` folder."""
    return (root or db_root()) / "osv"


def grype_dir(root: Path | None = None) -> Path:
    """Return the ``GRYPE_DB_CACHE_DIR`` folder."""
    return (root or db_root()) / "grype"


def go_dir(root: Path | None = None) -> Path:
    """Return the folder of the local Go vulnerability database (``govulncheck -db``)."""
    from kalkan.sca import govulndb

    return govulndb.folder(root or db_root())


def go_db_ready(root: Path | None = None) -> bool:
    """Return True when the local Go vulnerability database has its index files."""
    from kalkan.sca import govulndb

    return govulndb.ready(root or db_root())


def go_db_info(root: Path | None = None) -> dict[str, Any] | None:
    """Return the source record of the local Go database (``kalkan-source.json``), or None."""
    from kalkan.sca import govulndb

    return govulndb.info(root or db_root())


def go_db_uri(root: Path | None = None) -> str:
    """Return the ``file:///`` URL of the local Go database for ``govulncheck -db``."""
    from kalkan.sca import govulndb

    return govulndb.db_uri(root or db_root())


def retire_file(root: Path | None = None) -> Path | None:
    """Return the local RetireJS repository file, or None when it is missing."""
    from kalkan.sca import retiredb

    return retiredb.repository_file(root or db_root())


def retire_info(root: Path | None = None) -> dict[str, Any] | None:
    """Return the source record of the RetireJS repository (``kalkan-source.json``), or None."""
    from kalkan.sca import retiredb

    return retiredb.info(root or db_root())


def osv_ecosystems(root: Path | None = None) -> list[str]:
    """Return the ecosystems that have a non-empty local OSV database, sorted."""
    folder = osv_dir(root) / OSV_LAYOUT
    try:
        entries = list(os.scandir(folder))
    except OSError:
        return []
    found = []
    for entry in entries:
        archive = Path(entry.path) / "all.zip"
        try:
            if entry.is_dir(follow_symlinks=False) and archive.stat().st_size > 0:
                found.append(entry.name)
        except OSError:
            continue
    return sorted(found)


def grype_ready(root: Path | None = None) -> bool:
    """Return True when a non-empty Grype database file exists."""
    folder = grype_dir(root)
    try:
        return any(path.stat().st_size > 0 for path in folder.glob("*/vulnerability.db"))
    except OSError:
        return False


def osv_env(root: Path | None = None) -> dict[str, str]:
    """Return the OSV-Scanner environment: the local database folder."""
    return {"OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": str(osv_dir(root))}


def grype_env(root: Path | None = None, *, online: bool = False) -> dict[str, str]:
    """Return the Grype environment.

    Always: the kalkan database folder, no application update check, no external sources
    (Maven Central lookups). Without ``online`` also no database update, no update check and no
    age check (an old database is used, never a download).
    """
    env = {
        "GRYPE_DB_CACHE_DIR": str(grype_dir(root)),
        "GRYPE_CHECK_FOR_APP_UPDATE": "false",
        "GRYPE_EXTERNAL_SOURCES_ENABLE": "false",
    }
    if not online:
        env["GRYPE_DB_AUTO_UPDATE"] = "false"
        env["GRYPE_DB_VALIDATE_AGE"] = "false"
        env["GRYPE_DB_REQUIRE_UPDATE_CHECK"] = "false"
    return env


def missing_from_stderr(text: str) -> list[str]:
    """Return the ecosystems that OSV-Scanner reported without a local database."""
    return sorted({match.group(1).strip() for match in _MISSING_DB.finditer(text)})


def read_status(root: Path | None = None) -> dict[str, Any] | None:
    """Return the last ``update-db`` result (``status.json``), or None."""
    path = (root or db_root()) / STATUS_NAME
    try:
        from kalkan.util.safe_io import read_text_bounded

        data = json.loads(read_text_bounded(path, 1024 * 1024))
    except Exception:  # missing or broken: no status
        return None
    return data if isinstance(data, dict) else None


def _probe_sbom(ecosystems: Iterable[str]) -> dict[str, Any]:
    components = []
    for index, ecosystem in enumerate(ecosystems):
        purl = PROBE_PURLS[ecosystem]
        name = purl.rsplit("@", 1)[0].rsplit("/", 1)[-1]
        version = purl.rsplit("@", 1)[1]
        components.append(
            {
                "type": "library",
                "bom-ref": f"probe-{index}",
                "name": name,
                "version": version,
                "purl": purl,
            }
        )
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "components": components}


def _run_tool(
    argv: list[str],
    *,
    env: dict[str, str],
    cwd: Path,
    log: Path,
    timeout_seconds: int,
    runner: Callable[..., Any],
) -> tuple[int | None, str]:
    """Run one tool; return ``(exit code or None, stderr text)``."""
    from kalkan.scanners.base import minimal_env

    log.parent.mkdir(parents=True, exist_ok=True)
    out_log = log.with_suffix(".stdout.txt")
    err_log = log.with_suffix(".stderr.txt")
    with open(out_log, "wb") as stdout, open(err_log, "wb") as stderr:
        outcome = runner(
            argv,
            cwd=cwd,
            env=minimal_env(env),
            timeout=timeout_seconds or None,
            stdout=stdout,
            stderr=stderr,
        )
    text = err_log.read_bytes()[-65536:].decode("utf-8", errors="replace")
    if outcome.error:
        return None, outcome.error
    if outcome.timed_out:
        return None, f"timed out after {timeout_seconds} s"
    return outcome.exit_code, text


def _last_line(text: str) -> str:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return re.sub(r"\x1b\[[0-9;]*m", "", lines[-1])[:300] if lines else ""


def _update_osv(
    root: Path,
    ecosystems: list[str],
    *,
    timeout_seconds: int,
    runner: Callable[..., Any],
    resolver: Callable[..., Any],
) -> dict[str, Any]:
    tool = resolver("osv-scanner")
    if tool is None:
        return {
            "status": "skipped",
            "message": "tool not found: osv-scanner (run: kalkan tools install osv-scanner)",
            "ecosystems": osv_ecosystems(root),
            "requested": ecosystems,
        }
    work = root / "work"
    work.mkdir(parents=True, exist_ok=True)
    probe = work / "probe.cdx.json"
    probe.write_text(json.dumps(_probe_sbom(ecosystems)), encoding="utf-8", newline="\n")
    config = work / "osv-scanner.toml"
    config.write_text("", encoding="utf-8", newline="\n")
    argv = [
        *[str(arg) for arg in tool.argv],
        "scan",
        "source",
        "-L",
        str(probe),
        "--offline-vulnerabilities",
        "--download-offline-databases",
        "--no-resolve",
        "--config",
        str(config),
        "--format",
        "json",
        "--output-file",
        str(work / "probe-result.json"),
    ]
    code, stderr = _run_tool(
        argv,
        env=osv_env(root),
        cwd=work,
        log=root / "logs" / "osv-update",
        timeout_seconds=timeout_seconds,
        runner=runner,
    )
    present = osv_ecosystems(root)
    missing = [name for name in ecosystems if name not in present]
    ok = code in (0, 1) and not missing
    message = "" if ok else (_last_line(stderr) or f"exit code {code}")
    return {
        "status": "ok" if ok else "failed",
        "message": message,
        "ecosystems": present,
        "requested": ecosystems,
        "missing": missing,
        "exit_code": code,
    }


def _update_grype(
    root: Path,
    *,
    timeout_seconds: int,
    runner: Callable[..., Any],
    resolver: Callable[..., Any],
) -> dict[str, Any]:
    tool = resolver("grype")
    if tool is None:
        return {
            "status": "skipped",
            "message": "tool not found: grype (run: kalkan tools install grype)",
        }
    folder = grype_dir(root)
    folder.mkdir(parents=True, exist_ok=True)
    env = grype_env(root, online=True)
    base = [str(arg) for arg in tool.argv]
    code, stderr = _run_tool(
        [*base, "db", "update"],
        env=env,
        cwd=folder,
        log=root / "logs" / "grype-update",
        timeout_seconds=timeout_seconds,
        runner=runner,
    )
    if code != 0:
        return {"status": "failed", "message": _last_line(stderr) or f"exit code {code}"}
    code, _ = _run_tool(
        [*base, "db", "status", "-o", "json"],
        env=grype_env(root),
        cwd=folder,
        log=root / "logs" / "grype-status",
        timeout_seconds=120,
        runner=runner,
    )
    status_file = root / "logs" / "grype-status.stdout.txt"
    detail: dict[str, Any] = {}
    try:
        detail = json.loads(status_file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        detail = {}
    built = detail.get("built") if isinstance(detail, dict) else None
    if code != 0 or not grype_ready(root):
        return {"status": "failed", "message": "grype db status reports no valid database"}
    return {"status": "ok", "message": "", "built": built if isinstance(built, str) else None}


def update(
    root: Path | None = None,
    *,
    ecosystems: Iterable[str] | None = None,
    osv: bool = True,
    grype: bool = True,
    go: bool = True,
    retire: bool = True,
    go_source: str = "auto",
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    max_age_hours: float = DEFAULT_MAX_AGE_HOURS,
    force: bool = False,
    now: datetime | None = None,
    runner: Callable[..., Any] | None = None,
    resolver: Callable[..., Any] | None = None,
    fetch: Callable[..., Any] | None = None,
    retire_fetch: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Download the local databases that need it (network). Return the summary and write
    ``status.json``.

    Each selected database is checked first (:func:`check_fresh`): a fresh one is kept
    (``action: kept``), any other one is downloaded (``action: downloaded``, with the
    ``reason``). ``force`` downloads every selected database; ``max_age_hours`` 0 has the same
    effect. A database that is not selected keeps its last record. ``ecosystems`` defaults to
    :data:`DEFAULT_ECOSYSTEMS`; a name without a probe package raises :class:`ValueError`.
    ``go_source`` is ``auto`` (the official archive, else the OSV build), ``official`` or
    ``osv`` (:mod:`kalkan.sca.govulndb`). ``retire`` downloads the RetireJS repository
    (:mod:`kalkan.sca.retiredb`). ``now`` replaces the clock; ``runner``, ``resolver``,
    ``fetch`` and ``retire_fetch`` replace :func:`kalkan.scanners.base.run_process`,
    :func:`kalkan.tools.resolve.resolve`, :func:`kalkan.sca.govulndb.download` and
    :func:`kalkan.sca.retiredb.download` (tests).
    """
    from kalkan.sca import govulndb, retiredb
    from kalkan.scanners.base import run_process
    from kalkan.tools.resolve import resolve

    folder = root or db_root()
    folder.mkdir(parents=True, exist_ok=True)
    wanted = list(dict.fromkeys(ecosystems or DEFAULT_ECOSYSTEMS))
    unknown = [name for name in wanted if name not in PROBE_PURLS]
    if unknown:
        raise ValueError(
            f"unknown ecosystem(s): {', '.join(unknown)} (known: {', '.join(PROBE_PURLS)})"
        )
    if go_source not in govulndb.SOURCES:
        raise ValueError(
            f"unknown Go database source: {go_source} (known: {', '.join(govulndb.SOURCES)})"
        )
    if max_age_hours < 0:
        raise ValueError("the maximum age must be 0 or more hours")
    run = runner or run_process
    find = resolver or resolve

    def clock() -> datetime:
        return now if now is not None else datetime.now(UTC)

    previous = read_status(folder) or {}
    selected = {"osv": osv, "grype": grype, "go": go, "retire": retire}
    summary: dict[str, Any] = {
        "schema_version": STATUS_SCHEMA_VERSION,
        "root": folder.as_posix(),
        "checked_at": _iso(clock()),
        "updated_at": downloaded_at(previous),
        "max_age_hours": max_age_hours,
        "force": force,
    }
    for name in DATABASES:
        part = previous.get(name)
        summary[name] = part if not selected[name] and isinstance(part, dict) else None

    def download(name: str) -> dict[str, Any]:
        if name == "osv":
            return _update_osv(
                folder, wanted, timeout_seconds=timeout_seconds, runner=run, resolver=find
            )
        if name == "grype":
            return _update_grype(folder, timeout_seconds=timeout_seconds, runner=run, resolver=find)
        if name == "go":
            return govulndb.update(
                folder,
                osv_dir(folder) / OSV_LAYOUT / "Go" / "all.zip",
                source=go_source,
                timeout_seconds=timeout_seconds,
                fetch=fetch,
            )
        return retiredb.update(folder, timeout_seconds=timeout_seconds, fetch=retire_fetch)

    for name in DATABASES:
        if not selected[name]:
            continue
        state = check_fresh(
            folder, name, previous, max_age_hours=max_age_hours, now=clock(), ecosystems=wanted
        )
        if state.fresh and not force:
            summary[name] = {**state.record, "action": "kept", "reason": ""}
            summary[name]["age_hours"] = round((state.age_seconds or 0.0) / 3600, 1)
            continue
        reason = "--force" if force else state.reason
        summary[name] = _downloaded(folder, name, download(name), state, reason, clock())
        if summary[name]["status"] == "ok":
            summary["updated_at"] = summary[name]["downloaded_at"]
    from kalkan.util.safe_io import atomic_write_json

    atomic_write_json(folder / STATUS_NAME, summary)
    return summary


# --- freshness and the records of status.json ----------------------------------------------


@dataclass(frozen=True)
class Freshness:
    """Whether ``update-db`` can keep one local database (:func:`check_fresh`).

    ``reason`` says why the database must be downloaded (empty when it is fresh).
    ``age_seconds`` is the age of the last download, or None when it is unknown. ``record`` is
    the status record of the database: the last one, completed with the facts of the files
    (``database``, ``source``, ``version``, ``downloaded_at``), also for the older format.
    """

    name: str
    fresh: bool
    reason: str
    age_seconds: float | None = None
    record: dict[str, Any] = field(default_factory=dict)


def check_fresh(
    root: Path,
    name: str,
    status: Mapping[str, Any] | None,
    *,
    max_age_hours: float = DEFAULT_MAX_AGE_HOURS,
    now: datetime | None = None,
    ecosystems: Iterable[str] | None = None,
) -> Freshness:
    """Check one database: its files are present and valid, its last download ended ``ok``,
    and it is younger than ``max_age_hours``.

    ``status`` is :func:`read_status` (either format). ``ecosystems`` are the OSV ecosystems
    that must be present (default: :data:`DEFAULT_ECOSYSTEMS`).
    """
    if name not in DATABASES:
        raise ValueError(f"unknown database: {name} (known: {', '.join(DATABASES)})")
    moment = now or datetime.now(UTC)
    raw = status.get(name) if isinstance(status, Mapping) else None
    part = dict(raw) if isinstance(raw, Mapping) else {}
    record = {**part, **describe(root, name, part)}
    problem = files_problem(root, name, ecosystems)
    if problem:
        return Freshness(name, False, problem, None, record)
    if not part:
        return Freshness(name, False, "no record of an earlier download", None, record)
    if part.get("status") != "ok":
        return Freshness(name, False, f"the last download ended {part.get('status')}", None, record)
    downloaded = _parse_time(record.get("downloaded_at"))
    if downloaded is None:
        return Freshness(name, False, "the time of the last download is unknown", None, record)
    age = (moment - downloaded).total_seconds()
    if age < -_CLOCK_SLACK_SECONDS:
        reason = "the time of the last download is in the future"
        return Freshness(name, False, reason, None, record)
    age = max(age, 0.0)
    if age >= max_age_hours * 3600:
        return Freshness(name, False, f"{age_text(age)} old", age, record)
    return Freshness(name, True, "", age, record)


def files_problem(root: Path, name: str, ecosystems: Iterable[str] | None = None) -> str:
    """Return why the files of a database are missing or broken, or an empty string."""
    if name == "osv":
        missing = []
        for ecosystem in list(ecosystems or DEFAULT_ECOSYSTEMS):
            problem = _zip_problem(osv_dir(root) / OSV_LAYOUT / ecosystem / "all.zip")
            if problem == "missing":
                missing.append(ecosystem)
            elif problem:
                return f"broken: {ecosystem}/all.zip {problem}"
        return f"no local database for {', '.join(missing)}" if missing else ""
    if name == "grype":
        files = _grype_files(root)
        if not files:
            return "no local database"
        if not any(_has_prefix(path, _SQLITE_MAGIC) for path in files):
            return "broken: vulnerability.db is not an SQLite database"
        return ""
    if name == "go":
        return _go_problem(root)
    from kalkan.sca import retiredb

    path = retiredb.repository_file(root)
    if path is None:
        return "no local database"
    recorded = (retire_info(root) or {}).get("sha256")
    if not isinstance(recorded, str):
        return "broken: kalkan-source.json records no SHA-256"
    if _sha256(path) != recorded:
        return "broken: the repository file differs from its recorded SHA-256"
    return ""


def describe(root: Path, name: str, part: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Return the facts of a database for its status record: ``database``, ``source``,
    ``version`` and ``downloaded_at``, from the files and the record ``part`` (either format)."""
    part = part or {}
    facts: dict[str, Any] = {"database": name, "downloaded_at": downloaded_at(part)}
    if name == "osv":
        present = osv_ecosystems(root)
        stamps = []
        for ecosystem in present:
            try:
                stamps.append((osv_dir(root) / OSV_LAYOUT / ecosystem / "all.zip").stat().st_mtime)
            except OSError:
                continue
        facts["source"] = OSV_SOURCE
        facts["version"] = _iso(datetime.fromtimestamp(max(stamps), UTC)) if stamps else None
        facts["ecosystems"] = present
    elif name == "grype":
        built = part.get("built")
        facts["source"] = _grype_source(root)
        facts["version"] = built if isinstance(built, str) else None
    elif name == "go":
        info = go_db_info(root) or {}
        kinds = ("official", "osv")  # kalkan.sca.govulndb.SOURCES without "auto"
        kind = next(
            (
                value
                for value in (info.get("source"), part.get("go_source"), part.get("source"))
                if value in kinds
            ),
            None,
        )
        facts["go_source"] = kind
        facts["source"] = (
            info.get("url") or info.get("built_from") or part.get("url") or part.get("built_from")
        )
        facts["version"] = info.get("modified") or part.get("modified")
    else:
        info = retire_info(root) or {}
        source = info.get("source")
        facts["source"] = source if isinstance(source, str) and source != "unknown" else None
        facts["version"] = info.get("sha256") or part.get("sha256")
    return facts


def downloaded_at(part: Mapping[str, Any] | None) -> str | None:
    """Return the time of the last download of a status record: ``downloaded_at``, else the
    ``updated_at`` of the older format. None when the record has neither."""
    if not isinstance(part, Mapping):
        return None
    for key in ("downloaded_at", "updated_at"):
        value = part.get(key)
        if isinstance(value, str) and _parse_time(value) is not None:
            return value
    return None


def age_text(seconds: float) -> str:
    """Return an age as text: ``45 minutes``, ``3 hours``, ``8 days``."""
    minutes = int(seconds // 60)
    if minutes < 60:
        return f"{minutes} minute{'' if minutes == 1 else 's'}"
    hours = int(seconds // 3600)
    if hours < 48:
        return f"{hours} hour{'' if hours == 1 else 's'}"
    return f"{int(seconds // 86400)} days"


def _downloaded(
    root: Path,
    name: str,
    result: dict[str, Any],
    state: Freshness,
    reason: str,
    moment: datetime,
) -> dict[str, Any]:
    """Return the status record of a database after a download attempt.

    A successful download gets ``downloaded_at`` now. An OSV download of fewer ecosystems than
    the folder holds keeps the earlier time (the other archives are as old as before). A failed
    download keeps the time of the data that stays, or None.
    """
    record = {**result, **describe(root, name, result)}
    earlier = state.record.get("downloaded_at")
    stamp: str | None = _iso(moment)
    if result.get("status") == "ok":
        others = set(osv_ecosystems(root)) - set(result.get("requested") or [])
        if name == "osv" and others and isinstance(earlier, str):
            stamp = min(stamp, earlier)
    else:
        stamp = earlier if not files_problem(root, name, result.get("requested")) else None
    record.update(
        {"action": _outcome(result), "reason": reason, "downloaded_at": stamp, "updated_at": stamp}
    )
    return record


def _outcome(result: Mapping[str, Any]) -> str:
    """Return the ``action`` of a download attempt: ``downloaded``, ``failed`` or ``skipped`` (the
    tool is missing)."""
    status = result.get("status")
    if status == "ok":
        return "downloaded"
    return "skipped" if status == "skipped" else "failed"


def _go_problem(root: Path) -> str:
    from kalkan.sca import govulndb
    from kalkan.util.safe_io import read_text_bounded

    if not govulndb.ready(root):
        return "no local database"
    index = go_dir(root) / "index"
    try:
        meta = json.loads(read_text_bounded(index / "db.json", 1024 * 1024))
        modules = json.loads(read_text_bounded(index / "modules.json", 64 * 1024 * 1024))
    except Exception:  # unreadable or not JSON
        return "broken: the index files cannot be read"
    if not isinstance(meta, dict) or _parse_time(meta.get("modified")) is None:
        return "broken: index/db.json has no valid modified time"
    if not isinstance(modules, list):
        return "broken: index/modules.json is not a list"
    return ""


def _zip_problem(path: Path) -> str:
    """Return ``missing``, why the archive is broken, or an empty string."""
    try:
        if path.stat().st_size <= 0:
            return "missing"
    except OSError:
        return "missing"
    try:
        return "" if zipfile.is_zipfile(path) else "is not a zip archive"
    except OSError:
        return "cannot be read"


def _grype_files(root: Path) -> list[Path]:
    try:
        return [path for path in grype_dir(root).glob("*/vulnerability.db") if path.is_file()]
    except OSError:
        return []


def _grype_source(root: Path) -> str:
    """Return the archive URL in ``import.json`` of the Grype database (without the query)."""
    try:
        files = sorted(grype_dir(root).glob("*/import.json"), reverse=True)
    except OSError:
        files = []
    for path in files:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        source = data.get("source") if isinstance(data, dict) else None
        if isinstance(source, str) and source.startswith("https://"):
            return source.split("?", 1)[0]
    return GRYPE_SOURCE


def _has_prefix(path: Path, prefix: bytes) -> bool:
    try:
        with open(path, "rb") as handle:
            return handle.read(len(prefix)) == prefix
    except OSError:
        return False


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def _iso(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_time(text: object) -> datetime | None:
    """Return the aware time of an ISO 8601 text with a zone (``...Z``), or None."""
    if not isinstance(text, str) or not text:
        return None
    try:
        moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return moment.astimezone(UTC) if moment.tzinfo is not None else None
