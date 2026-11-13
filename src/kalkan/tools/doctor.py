# SPDX-License-Identifier: MIT
"""Environment checks for kalkan: ``kalkan doctor`` (docs/ENGINE-SPEC.md, section 12).

Each check has a status:

- ``ok``: works.
- ``warn``: an optional part is missing or degraded (no Docker engine: only the PoC sandbox
  needs it; no git; no Claude Code CLI; low disk space), or a tool has no pinned build for
  this platform (nothing can install it here).
- ``fail``: kalkan cannot run as promised: old Python, an invalid manifest, a manifest tool
  that is missing, broken (does not run, wrong or blocked version, hash mismatch) or without
  the Go toolchain it needs, or no write access to ``runs/``. Every failing row names the one
  command (or action) that fixes it: ``kalkan tools install <name>``, with ``--force`` for a
  damaged copy, ``kalkan tools install go`` for a missing Go, ``KALKAN_RUNS_DIR`` for a runs
  folder without write access. In the plugin venv the command names the engine path
  (:func:`kalkan.resources.engine_command`), because ``kalkan`` is not on PATH there.
- ``info``: informational only (Node.js; ``footprint``, the disk space of the tools, the
  databases, the caches and the runs, which ``kalkan clean`` shows and deletes).

The tool rows come from the manifest: every tool of ``kalkan/tools/manifest.json`` gets the row
``tool:<name>``, so a new tool needs no doctor change. The ``claude`` check also reads the login
state (``claude auth status --json``): a CLI that is not signed in is a ``warn`` that names
``claude auth login``. With an API login in the environment (:mod:`kalkan.unattended.auth`:
Claude API key, Microsoft Foundry, Amazon Bedrock or Google Vertex) the sign-in state does not
matter: the check names the API mode and is a ``warn`` only when a required variable of that
mode is missing. It names variables, never their values. ``kalkan audit`` runs the doctor
without the checks it does not need (:func:`run_doctor` ``skip``).

The exit code is 0 when no check has the status ``fail``. ``scripts/bootstrap.*`` install every
tool first and then stop with a non-zero exit code on any ``fail``.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import sys
import sysconfig
import tempfile
from collections.abc import Callable, Collection, Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from kalkan import __version__
from kalkan.errors import KalkanError
from kalkan.tools.golang import GoToolchain, resolve_go
from kalkan.tools.install import (
    VERIFY_MISMATCH,
    VERIFY_MISSING,
    VERIFY_OK,
    VERIFY_SKIPPED,
    verify,
)
from kalkan.tools.manifest import ASSET_KINDS, Manifest, Tool, load_manifest
from kalkan.tools.platform import Finder, Runner, find_on_path, platform_key, run_command
from kalkan.tools.resolve import (
    blocked_version_in,
    default_repo_root,
    first_version,
    go_toolchain_version,
    probe_tool_version,
    pyenv_command,
    pyenv_script,
    required_go_version,
    toolchain_root,
    version_in_output,
    version_tuple,
)
from kalkan.unattended.auth import detect_auth

STATUS_OK = "ok"
STATUS_WARN = "warn"
STATUS_FAIL = "fail"
STATUS_INFO = "info"
STATUSES = (STATUS_OK, STATUS_WARN, STATUS_FAIL, STATUS_INFO)

REPORT_SCHEMA_VERSION = 1
MIN_PYTHON = (3, 11)
MIN_FREE_BYTES = 5 * 1000**3
COMMAND_TIMEOUT_SECONDS = 20.0
DOCKER_ENGINE_TIMEOUT_SECONDS = 10.0
TOOL_VERSION_TIMEOUT_SECONDS = 90.0
CHECK_WORKERS = 8
#: Check groups that :func:`run_doctor` can leave out: ``docker`` (docker-client,
#: docker-engine and sandbox-images), ``node``, ``claude`` (claude and the unattended checks)
#: and ``tools`` (the ``tool:<name>`` rows, ``vulndb`` and ``footprint``).
SKIP_GROUPS = ("docker", "node", "claude", "tools")

DiskUsage = Callable[[str], Any]
AttributeReader = Callable[[Path], str]

#: The extended attribute that marks the root folder of a File Provider domain on macOS. On a
#: folder that iCloud Drive syncs (~/Desktop, ~/Documents) its value starts with
#: :data:`ICLOUD_DOMAIN`; below that root the folders do not carry it.
FILE_PROVIDER_ATTRIBUTE = "com.apple.file-provider-domain-id"
ICLOUD_DOMAIN = "com.apple.CloudDocs"
XATTR = "/usr/bin/xattr"


def _kalkan(arguments: str) -> str:
    """Return the engine command with ``arguments``, for a fix hint (``kalkan tools install
    trivy``; the engine path in the plugin venv)."""
    from kalkan.resources import engine_command

    return f"{engine_command()} {arguments}"


@dataclass(frozen=True)
class Check:
    """The result of one doctor check."""

    name: str
    status: str
    detail: str
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-ready dict."""
        return {"name": self.name, "status": self.status, "detail": self.detail, "data": self.data}


@dataclass(frozen=True)
class DoctorReport:
    """All doctor checks in a fixed order."""

    checks: tuple[Check, ...]
    platform: str | None
    repo_root: str

    @property
    def exit_code(self) -> int:
        """Return 0 when no check failed, else 1."""
        return 1 if any(check.status == STATUS_FAIL for check in self.checks) else 0

    @property
    def counts(self) -> dict[str, int]:
        """Return the number of checks per status."""
        return {status: sum(c.status == status for c in self.checks) for status in STATUSES}

    def check(self, name: str) -> Check | None:
        """Return the check with this name, or None."""
        return next((c for c in self.checks if c.name == name), None)

    def to_dict(self) -> dict[str, Any]:
        """Return the JSON document that ``kalkan doctor --json`` prints."""
        return {
            "schema_version": REPORT_SCHEMA_VERSION,
            "kalkan_version": __version__,
            "platform": self.platform,
            "repo_root": self.repo_root,
            "ok": self.exit_code == 0,
            "exit_code": self.exit_code,
            "summary": self.counts,
            "checks": [check.to_dict() for check in self.checks],
        }


def run_doctor(
    repo_root: str | os.PathLike[str] | None = None,
    *,
    manifest: Manifest | None = None,
    runner: Runner | None = None,
    finder: Finder | None = None,
    key: str | None = None,
    disk_usage: DiskUsage | None = None,
    python_version: tuple[int, int, int] | None = None,
    skip: Collection[str] = (),
    environ: Mapping[str, str] | None = None,
) -> DoctorReport:
    """Run every check and return the report.

    ``skip`` leaves out check groups of :data:`SKIP_GROUPS` (``kalkan audit`` needs no Docker
    or Node.js check, no Claude Code check in tools-only mode, and no tool check for a resumed
    run after its scanners). The other keyword arguments exist for tests. Raises ValueError
    for an unknown group.
    """
    unknown = sorted(set(skip) - set(SKIP_GROUPS))
    if unknown:
        raise ValueError(f"unknown doctor check group(s): {', '.join(unknown)}")
    root = Path(repo_root).resolve() if repo_root is not None else default_repo_root()
    run = runner or run_command
    find = finder or find_on_path
    env = os.environ if environ is None else environ
    platform_check, key = _check_platform(key)
    manifest_check, manifest = _check_manifest(manifest)
    with_tools = "tools" not in skip
    tools = list(manifest) if manifest is not None and with_tools else []
    go: GoToolchain | None = None
    if tools and key is not None:
        go = resolve_go(root, manifest=manifest, key=key, runner=run, finder=find)

    # The checks start processes (version probes, hashing). They run in parallel, but the
    # report keeps a fixed order.
    with ThreadPoolExecutor(max_workers=CHECK_WORKERS) as pool:
        tool_checks = [
            pool.submit(_check_tool, tool, root, key, manifest, run, find, go)
            for tool in sorted(tools, key=lambda t: t.kind != "pip")  # slowest first
        ]
        git = pool.submit(_check_git, run, find)
        docker = None if "docker" in skip else pool.submit(_check_docker, run, find)
        node = None if "node" in skip else pool.submit(_check_node, run, find)
        claude = None if "claude" in skip else pool.submit(_check_claude, run, find, env)
        footprint = pool.submit(_check_footprint, root) if with_tools else None
        by_name = {future.result().name: future.result() for future in tool_checks}

    checks: list[Check] = [
        _check_python(python_version),
        platform_check,
        git.result(),
        *(docker.result() if docker is not None else []),
        manifest_check,
        *([node.result()] if node is not None else []),
        *([claude.result(), *_unattended_checks(run, find)] if claude is not None else []),
        *(by_name[f"tool:{tool.name}"] for tool in tools),
        _check_paths(),
        _check_location(root, run),
        *([_check_vulndb(root)] if with_tools else []),
        _check_disk(root, disk_usage or shutil.disk_usage),
        *([footprint.result()] if footprint is not None else []),
        _check_runs_writable(root),
    ]
    return DoctorReport(tuple(checks), key, root.as_posix())


def _unattended_checks(run: Runner, find: Finder) -> list[Check]:
    """Checks of unattended mode (headless Claude Code); `claude` itself is checked above."""
    from kalkan.unattended import doctor_checks

    try:
        found = doctor_checks(runner=run, finder=find)
    except Exception as exc:  # a probe must never break the doctor report
        return [Check("unattended", STATUS_WARN, f"unattended checks failed: {exc}")]
    return [Check(**item) for item in found if item.get("name") != "unattended:claude"]


def _check_vulndb(root: Path, now: float | None = None) -> Check:
    """The local vulnerability databases of ``sca match`` and govulncheck (kalkan.sca.vulndb).

    ``warn`` when a database is missing or older than ``STALE_DAYS``: ``sca match`` then records
    a database gap, and ``sca reach`` skips govulncheck in local mode; neither queries an online
    API. The Go database line names its source (the official vuln.go.dev archive or the OSV
    build) and its ``modified`` time. The RetireJS repository (vendored JavaScript libraries,
    kalkan.sca.retiredb) counts as one more database.
    """
    import time

    from kalkan.sca import vulndb

    folder = vulndb.db_root(root)
    ecosystems = vulndb.osv_ecosystems(folder)
    grype = vulndb.grype_ready(folder)
    go = vulndb.go_db_info(folder)
    retire = vulndb.retire_info(folder)
    status = vulndb.read_status(folder) or {}
    data: dict[str, Any] = {
        "root": folder.as_posix(),
        "osv_ecosystems": ecosystems,
        "grype": grype,
        "go": go,
        "retire": retire,
    }
    fix = f"run: {_kalkan('sca update-db')}"
    missing = [name for name in vulndb.DEFAULT_ECOSYSTEMS if name not in ecosystems]
    if not ecosystems and not grype and go is None and retire is None:
        detail = f"no local vulnerability databases; sca match records gaps instead ({fix})"
        return Check("vulndb", STATUS_WARN, detail, data)
    problems = []
    if missing:
        problems.append(f"no OSV database for {', '.join(missing)}")
    if not grype:
        problems.append("no Grype database")
    if go is None:
        problems.append("no Go database (govulncheck is skipped in local mode)")
    if retire is None:
        problems.append("no RetireJS repository (vendored JavaScript libraries are not checked)")
    moments = [
        _parse_utc(vulndb.downloaded_at(part))  # downloaded_at, or updated_at (older format)
        for part in (status.get("osv"), status.get("grype"))
        if isinstance(part, dict)
    ]
    for part in (go, retire):
        if part is not None:
            moments.append(_parse_utc(part.get("updated_at")))
    if not any(moment is not None for moment in moments):
        moments.append(_parse_utc(status.get("updated_at")))
    known = [moment for moment in moments if moment is not None]
    age_days = int(((now or time.time()) - min(known)) // 86400) if known else None
    data["age_days"] = age_days
    if age_days is not None and age_days > vulndb.STALE_DAYS:
        problems.append(f"the databases are {age_days} days old")
    if problems:
        return Check("vulndb", STATUS_WARN, "; ".join(problems) + f" ({fix})", data)
    detail = f"OSV: {len(ecosystems)} ecosystems, Grype: ready, Go: {_go_source(go)}"
    detail += f", RetireJS: {_retire_source(retire)}"
    updated = status.get("updated_at")
    if isinstance(updated, str):
        detail += f"; updated {updated}"
    return Check("vulndb", STATUS_OK, detail, data)


def _check_footprint(root: Path) -> Check:
    """The disk space of the kalkan parts (kalkan.tools.cleanup; ``kalkan clean`` shows them
    with the engine and deletes them). Always ``info``. On a kalkan checkout of
    2026-10-29 (43,936 files, 5.64 GB) the measurement took 0.6 s; it runs in parallel with the
    tool checks."""
    from kalkan.tools import cleanup
    from kalkan.util.fs import size_text

    try:
        found = cleanup.usage(home=root, runs_root=runs_root(root), with_engine=False)
    except (KalkanError, OSError) as exc:
        return Check("footprint", STATUS_INFO, f"the disk usage cannot be measured: {exc}")
    sizes = {name: found.parts[name].stats for name in cleanup.DELETABLE}
    shown = ", ".join(
        f"{name} {size_text(sizes[name].bytes)}" for name in ("tools", "databases", "caches")
    )
    noun = "run" if found.runs == 1 else "runs"
    detail = (
        f"{size_text(found.total.bytes)} in {found.total.files:,} files: {shown}, runs "
        f"{size_text(sizes['runs'].bytes)} ({found.runs} {noun}); details and cleanup: "
        f"{_kalkan('clean')}"
    )
    data = {name: {"bytes": stats.bytes, "files": stats.files} for name, stats in sizes.items()}
    return Check("footprint", STATUS_INFO, detail, {**data, "runs_count": found.runs})


def _go_source(info: dict[str, Any] | None) -> str:
    """Return the doctor text of the Go database source (kalkan.sca.govulndb)."""
    if not info:
        return "missing"
    names = {
        "official": "the vuln.go.dev archive",
        "osv": "built from the OSV Go database",
    }
    source = names.get(str(info.get("source")), "unknown source")
    modified = info.get("modified")
    return f"{source}, modified {modified}" if isinstance(modified, str) else source


def _retire_source(info: dict[str, Any] | None) -> str:
    """Return the doctor text of the RetireJS repository (kalkan.sca.retiredb)."""
    if not info:
        return "missing"
    libraries = info.get("libraries")
    updated = info.get("updated_at")
    text = f"{libraries} libraries" if isinstance(libraries, int) else "ready"
    return f"{text}, updated {updated}" if isinstance(updated, str) else text


def _parse_utc(text: object) -> float | None:
    """Return the POSIX time of ``YYYY-MM-DDTHH:MM:SSZ``, or None."""
    from datetime import UTC, datetime

    if not isinstance(text, str):
        return None
    try:
        return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC).timestamp()
    except ValueError:
        return None


def _check_paths() -> Check:
    """The home folder and the source of the knowledge and rules data (kalkan.resources)."""
    from kalkan.resources import doctor_check

    return Check(**doctor_check())


def runs_root(repo_root: str | os.PathLike[str]) -> Path:
    """Return the runs root: ``KALKAN_RUNS_DIR`` when set, else the runs root of the plugin
    marker (kalkan.resources), else ``<repo>/runs``."""
    from kalkan.resources import marker_runs_root

    override = os.environ.get("KALKAN_RUNS_DIR")
    if override:
        return Path(override)
    try:
        marked = marker_runs_root()
    except KalkanError:  # the paths check reports a bad marker
        marked = None
    return marked if marked is not None else Path(repo_root) / "runs"


# ---------------------------------------------------------------------------------------------
# Host checks


def icloud_folder(path: Path, read_attribute: AttributeReader) -> Path | None:
    """Return ``path`` or the first parent of it that iCloud Drive syncs, else None.

    Only ``path`` and its parents are read: reading another folder such as ~/Documents
    directly can open a macOS privacy dialog (seen on 2026-11-13).
    """
    for folder in (path, *path.parents):
        if read_attribute(folder).startswith(ICLOUD_DOMAIN):
            return folder
    return None


def hidden_pth_files(site: Path) -> list[Path]:
    """Return the ``*kalkan*.pth`` files in ``site`` that carry the macOS hidden flag."""
    hidden: list[Path] = []
    for path in sorted(site.glob("*kalkan*.pth")):
        try:
            flags = getattr(path.stat(), "st_flags", 0)
        except OSError:
            continue
        if flags & getattr(stat, "UF_HIDDEN", 0x8000):
            hidden.append(path)
    return hidden


def _xattr_reader(run: Runner) -> AttributeReader:
    def read(folder: Path) -> str:
        try:
            proc = run(
                [XATTR, "-p", FILE_PROVIDER_ATTRIBUTE, str(folder)],
                timeout=COMMAND_TIMEOUT_SECONDS,
            )
        except Exception:  # no xattr tool, a timeout: the folder counts as not synced
            return ""
        return (proc.stdout or "").strip() if proc.returncode == 0 else ""

    return read


def _check_location(
    root: Path,
    run: Runner,
    *,
    platform: str | None = None,
    read_attribute: AttributeReader | None = None,
    site: Path | None = None,
) -> Check:
    """macOS: kalkan (its home and its Python) must not live in a folder that iCloud syncs.

    iCloud Drive marks the files of the dot folders there (.venv, .git, .tools) hidden a few
    minutes after they appear. Python 3.13 and later skip a hidden ``.pth`` file, so the
    editable install of a checkout stops working: "No module named kalkan.cli" (macOS 26.7.1,
    2026-11-13; the flag came about 4 minutes after ``pip install -e .``).
    """
    if (platform or sys.platform) != "darwin":
        return Check("location", STATUS_OK, "not macOS: no iCloud Drive check")
    read = read_attribute or _xattr_reader(run)
    fix = "Clone the repository into a folder outside Desktop and Documents, for example ~/kalkan"
    for folder in dict.fromkeys((root, Path(sys.prefix).resolve())):
        synced = icloud_folder(folder, read)
        if synced is not None:
            detail = (
                f"{folder.as_posix()} is in {synced.as_posix()}, a folder that iCloud Drive "
                "syncs. iCloud marks the files of .venv hidden after a few minutes, and Python "
                f"then cannot import kalkan. {fix}, and run the bootstrap there."
            )
            return Check("location", STATUS_FAIL, detail, {"icloud_folder": synced.as_posix()})
    hidden = hidden_pth_files(site or Path(sysconfig.get_paths()["purelib"]))
    if hidden:
        names = ", ".join(path.name for path in hidden)
        detail = (
            f"macOS marks {names} hidden, and Python 3.13 and later skip a hidden .pth file: "
            f"kalkan can stop importing at any time. {fix}."
        )
        return Check("location", STATUS_FAIL, detail, {"hidden": [p.as_posix() for p in hidden]})
    return Check("location", STATUS_OK, "not in a folder that iCloud Drive syncs")


def _check_python(version: tuple[int, int, int] | None) -> Check:
    found = version or tuple(sys.version_info[:3])
    text = ".".join(str(part) for part in found)
    data = {"version": text, "executable": Path(sys.executable).as_posix()}
    if tuple(found[:2]) >= MIN_PYTHON:
        return Check("python", STATUS_OK, f"Python {text}", data)
    need = ".".join(str(part) for part in MIN_PYTHON)
    return Check("python", STATUS_FAIL, f"Python {text} is too old; kalkan needs {need}+", data)


def _check_platform(key: str | None) -> tuple[Check, str | None]:
    try:
        found = key or platform_key()
    except KalkanError as exc:
        return Check("platform", STATUS_WARN, f"{exc}; no pinned tool builds"), None
    return Check("platform", STATUS_OK, found, {"key": found}), found


def _check_git(run: Runner, find: Finder) -> Check:
    git = find("git")
    if git is None:
        detail = "git not found: git URL targets and secret history scans are unavailable"
        return Check("git", STATUS_WARN, detail)
    output = _version_output(run, [git, "--version"])
    if output is None:
        return Check(
            "git", STATUS_WARN, f"{git.as_posix()} --version failed", {"path": git.as_posix()}
        )
    return Check(
        "git", STATUS_OK, output, {"path": git.as_posix(), "version": first_version(output)}
    )


def _check_docker(run: Runner, find: Finder) -> list[Check]:
    docker = find("docker")
    if docker is None:
        detail = "Docker not found: the PoC sandbox is unavailable"
        return [
            Check("docker-client", STATUS_WARN, detail),
            Check("docker-engine", STATUS_WARN, "skipped: no Docker client"),
            _check_sandbox_images(run, None, False),
        ]
    data = {"path": docker.as_posix()}
    output = _version_output(run, [docker, "--version"])
    if output is None:
        client = Check("docker-client", STATUS_WARN, "docker --version failed", data)
    else:
        client = Check(
            "docker-client", STATUS_OK, output, {**data, "version": first_version(output)}
        )
    try:
        proc = run(
            [str(docker), "version", "--format", "{{.Server.Version}}"],
            timeout=DOCKER_ENGINE_TIMEOUT_SECONDS,
        )
    except Exception as exc:  # timeout or OSError: the engine is not usable
        engine = Check("docker-engine", STATUS_WARN, f"Docker engine not reachable: {exc}")
    else:
        server = (proc.stdout or "").strip()
        if proc.returncode == 0 and server:
            engine = Check("docker-engine", STATUS_OK, f"engine {server}", {"version": server})
        else:
            reason = _first_line(proc.stderr) or "no server version"
            detail = f"Docker engine is not running ({reason}); PoC validation is unavailable"
            engine = Check("docker-engine", STATUS_WARN, detail)
    return [client, engine, _check_sandbox_images(run, docker, engine.status == STATUS_OK)]


def _check_sandbox_images(run: Runner, docker: Path | None, engine_up: bool) -> Check:
    """The base images of the PoC sandbox (``kalkan sandbox pull``). A PoC whose stack image
    is missing ends as ``sandbox_image_missing``: an audit of 2026-11-13 lost 2 of 4 PoCs."""
    from kalkan.sandbox.runner import allowed_images

    if docker is None or not engine_up:
        return Check("sandbox-images", STATUS_INFO, "skipped: the Docker engine is not running")
    missing: list[str] = []
    allowed = allowed_images()
    for name in allowed:
        try:
            proc = run(
                [str(docker), "image", "inspect", "--format", "{{.Id}}", name],
                timeout=DOCKER_ENGINE_TIMEOUT_SECONDS,
            )
        except Exception:  # a timeout or OSError: count the image as missing
            missing.append(name)
            continue
        if proc.returncode != 0:
            missing.append(name)
    data = {"images": allowed, "missing": missing}
    if not missing:
        return Check("sandbox-images", STATUS_OK, f"all {len(allowed)} base images present", data)
    detail = (
        f"{len(missing)} of {len(allowed)} base images missing ({', '.join(missing)}): a PoC "
        f"of these stacks cannot run. Run: {_kalkan('sandbox pull')} (about 1 GB per image)"
    )
    return Check("sandbox-images", STATUS_WARN, detail, data)


def _check_node(run: Runner, find: Finder) -> Check:
    node = find("node")
    if node is None:
        return Check("node", STATUS_INFO, "Node.js not found (optional)")
    output = _version_output(run, [node, "--version"])
    data = {"path": node.as_posix(), "version": first_version(output or "")}
    return Check(
        "node", STATUS_OK if output else STATUS_INFO, output or "node --version failed", data
    )


def _check_claude(run: Runner, find: Finder, env: Mapping[str, str] | None = None) -> Check:
    auth = detect_auth(os.environ if env is None else env)
    claude = find("claude")
    if claude is None:
        detail = (
            "Claude Code CLI not found: the /kalkan skill and kalkan audit need it. Install "
            "Claude Code, then sign in: claude auth login"
        )
        return Check("claude", STATUS_WARN, detail, {"path": None, "logged_in": None})
    output = _version_output(run, [claude, "--version"])
    data: dict[str, Any] = {
        "path": claude.as_posix(),
        "version": first_version(output or ""),
        "auth": auth.mode,
        "auth_source": auth.source,
    }
    if output is None:
        return Check("claude", STATUS_WARN, "claude --version failed", data)
    if auth.api:
        notes = "; ".join(auth.notes)
        detail = f"{output}; {auth.describe()}" + (f"; {notes}" if notes else "")
        if auth.missing:
            missing = ", ".join(auth.missing)
            return Check("claude", STATUS_WARN, f"{detail}; set {missing}", data)
        return Check("claude", STATUS_OK, detail, data)
    logged_in = _claude_logged_in(run, claude)
    data["logged_in"] = logged_in
    if logged_in is False:
        detail = f"{output}; not signed in: run: claude auth login"
        return Check("claude", STATUS_WARN, detail, data)
    return Check("claude", STATUS_OK, f"{output}; signed in" if logged_in else output, data)


def _claude_logged_in(run: Runner, claude: Path) -> bool | None:
    """Return the ``loggedIn`` value of ``claude auth status --json``, or None when the command
    fails or prints no such value (an older Claude Code)."""
    try:
        proc = run([str(claude), "auth", "status", "--json"], timeout=COMMAND_TIMEOUT_SECONDS)
    except Exception:  # OSError, timeout: unknown
        return None
    try:
        document = json.loads(proc.stdout or "")
    except ValueError:
        return None
    value = document.get("loggedIn") if isinstance(document, dict) else None
    return value if isinstance(value, bool) else None


def _check_manifest(manifest: Manifest | None) -> tuple[Check, Manifest | None]:
    try:
        loaded = manifest or load_manifest()
    except KalkanError as exc:
        errors = list(getattr(exc, "errors", []))[:20]
        detail = f"{exc}; reinstall kalkan (in a checkout: git checkout -- src/kalkan/tools)"
        return Check("manifest", STATUS_FAIL, detail, {"errors": errors}), None
    detail = f"{len(loaded.tools)} tools pinned"
    return Check("manifest", STATUS_OK, detail, {"source": Path(loaded.source).name}), loaded


def _check_disk(root: Path, disk_usage: DiskUsage) -> Check:
    probe = root
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    try:
        free = int(disk_usage(str(probe)).free)
    except OSError as exc:
        return Check("disk", STATUS_WARN, f"cannot read the free disk space: {exc}")
    data = {"free_bytes": free, "min_free_bytes": MIN_FREE_BYTES}
    text = f"{free / 1000**3:.1f} GB free"
    if free < MIN_FREE_BYTES:
        return Check("disk", STATUS_WARN, f"{text}; kalkan needs about 5 GB", data)
    return Check("disk", STATUS_OK, text, data)


def _check_runs_writable(root: Path) -> Check:
    runs = runs_root(root)
    data = {"path": runs.as_posix()}
    try:
        runs.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(prefix=".doctor-", suffix=".tmp", dir=runs)
        os.close(fd)
        os.unlink(name)
    except OSError as exc:
        detail = (
            f"cannot write to {runs.as_posix()}: {exc}; set KALKAN_RUNS_DIR to a folder that "
            "you can write"
        )
        return Check("runs-writable", STATUS_FAIL, detail, data)
    return Check("runs-writable", STATUS_OK, f"{runs.as_posix()} is writable", data)


# ---------------------------------------------------------------------------------------------
# Tool checks


def _check_tool(
    tool: Tool,
    root: Path,
    key: str | None,
    manifest: Manifest,
    run: Runner,
    find: Finder,
    go: GoToolchain | None,
) -> Check:
    name = f"tool:{tool.name}"
    data: dict[str, Any] = {"version": tool.version, "kind": tool.kind, "installed": False}
    if key is None:
        return Check(name, STATUS_WARN, "unsupported platform", data)
    if tool.kind in ASSET_KINDS and tool.asset(key) is None:
        detail = f"no pinned {tool.version} build for {key}; kalkan cannot run it on this platform"
        return Check(name, STATUS_WARN, detail, data)
    try:
        (result,) = verify(
            [tool.name],
            repo_root=root,
            manifest=manifest,
            key=key,
            runner=run,
            finder=find,
            deep=False,
        )
    except (KalkanError, OSError) as exc:
        reinstall = _kalkan(f"tools install --force {tool.name}")
        detail = f"verification error: {exc}; reinstall: {reinstall}"
        return Check(name, STATUS_FAIL, detail, data)
    data["path"] = result.path
    if result.status in (VERIFY_MISSING, VERIFY_SKIPPED):
        if tool.kind == "toolchain":
            return _check_toolchain_on_path(tool, name, data, manifest, run, find, go)
        check = _check_tool_on_path(tool, name, data, run, find)
        return _needs_go(tool, check, go, manifest)
    data["installed"] = True
    reinstall = f"reinstall: {_kalkan(f'tools install --force {tool.name}')}"
    if result.status == VERIFY_MISMATCH:
        detail = f"{result.message}; {reinstall}"
        return Check(name, STATUS_FAIL, detail, {**data, "hash_ok": False})
    data["hash_ok"] = result.status == VERIFY_OK
    if tool.kind == "toolchain":
        exe = root / str(result.path)
        found = go_toolchain_version(
            exe,
            runner=run,
            goroot=toolchain_root(root, tool, key),
            timeout=TOOL_VERSION_TIMEOUT_SECONDS,
        )
        if found is None:
            detail = f"installed, SHA-256 ok, but {tool.executable} does not run; {reinstall}"
            return Check(name, STATUS_FAIL, detail, data)
        data["reported_version"] = found
        if found != tool.version or tool.is_blocked(found):
            detail = (
                f"{tool.executable} reports version {found}, pinned {tool.version}; {reinstall}"
            )
            return Check(name, STATUS_FAIL, detail, data)
        detail = f"{tool.version} installed, {result.message}"
        return Check(name, STATUS_OK, detail, {**data, "source": "kalkan"})
    command = _local_command(root, tool, result.path)
    output = None
    if command:
        output = probe_tool_version(command, tool, runner=run, timeout=TOOL_VERSION_TIMEOUT_SECONDS)
    if output is None:
        detail = f"installed, SHA-256 ok, but {tool.executable} does not run; {reinstall}"
        return Check(name, STATUS_FAIL, detail, data)
    data["reported_version"] = first_version(output)
    blocked = blocked_version_in(tool, output)
    if blocked is not None or not version_in_output(output, tool.version):
        reported = blocked or data["reported_version"] or "unknown"
        detail = f"{tool.executable} reports version {reported}, pinned {tool.version}; {reinstall}"
        return Check(name, STATUS_FAIL, detail, data)
    check = Check(name, STATUS_OK, f"{tool.version} installed, SHA-256 ok", data)
    return _needs_go(tool, check, go, manifest)


def _needs_go(tool: Tool, check: Check, go: GoToolchain | None, manifest: Manifest) -> Check:
    """Turn an ``ok`` check of a tool that needs Go into ``fail`` when no usable Go exists."""
    if not tool.requires_go or check.status != STATUS_OK:
        return check
    if go is None:
        need = required_go_version(manifest)
        what = f"Go {need} or later" if need else "Go"
        detail = (
            f"{check.detail}; but it needs {what} at run time and none is installed; "
            f"run: {_kalkan('tools install go')}"
        )
        return Check(check.name, STATUS_FAIL, detail, {**check.data, "go": None})
    detail = f"{check.detail}; runs with Go {go.version} ({go.source})"
    return Check(check.name, check.status, detail, {**check.data, "go": go.to_dict()})


def _local_command(root: Path, tool: Tool, rel_path: str | None) -> list[str] | None:
    if tool.kind == "pip":
        script = pyenv_script(root, tool.executable)
        return pyenv_command(root, script) if script is not None else None
    return [str(root / rel_path)] if rel_path else None


def _check_toolchain_on_path(
    tool: Tool,
    name: str,
    data: dict[str, Any],
    manifest: Manifest,
    run: Runner,
    find: Finder,
    go: GoToolchain | None,
) -> Check:
    """A toolchain that kalkan did not install: a system Go of the required version is ok."""
    need = required_go_version(manifest)
    hint = f"run: {_kalkan(f'tools install {tool.name}')}"
    if go is not None and go.source != "kalkan":
        if go.version == tool.version:
            detail = f"not in .tools, but {go.path.as_posix()} is the pinned Go {tool.version}"
        else:
            detail = (
                f"not in .tools, but {go.path.as_posix()} has Go {go.version} "
                f"(at least {need}); for the pinned {tool.version}: {hint}"
            )
        return Check(name, STATUS_OK, detail, {**data, "source": "path", **go.to_dict()})
    found = find(tool.executable)
    if found is None:
        return Check(name, STATUS_FAIL, f"not installed; {hint}", data)
    version = go_toolchain_version(found, runner=run, timeout=TOOL_VERSION_TIMEOUT_SECONDS)
    data = {**data, "path_binary": found.as_posix(), "path_version": version}
    if version is None:
        detail = f"not installed; {found.as_posix()} does not run; {hint}"
    elif tool.is_blocked(version):
        detail = f"not installed; {found.as_posix()} is the blocked version {version}; {hint}"
    else:
        older = (
            f", older than {need}" if need and version_tuple(version) < version_tuple(need) else ""
        )
        detail = f"not installed; {found.as_posix()} has Go {version}{older}; {hint}"
    return Check(name, STATUS_FAIL, detail, data)


def _check_tool_on_path(
    tool: Tool, name: str, data: dict[str, Any], run: Runner, find: Finder
) -> Check:
    hint = f"run: {_kalkan(f'tools install {tool.name}')}"
    found = find(tool.executable)
    if found is None:
        return Check(name, STATUS_FAIL, f"not installed; {hint}", data)
    output = probe_tool_version(found, tool, runner=run, timeout=TOOL_VERSION_TIMEOUT_SECONDS)
    data = {**data, "path_binary": found.as_posix()}
    if output is None:
        return Check(
            name, STATUS_FAIL, f"not installed; {found.as_posix()} does not run; {hint}", data
        )
    blocked = blocked_version_in(tool, output)
    if blocked is not None:
        detail = f"{found.as_posix()} is the blocked version {blocked}; remove it and {hint}"
        return Check(name, STATUS_FAIL, detail, data)
    if version_in_output(output, tool.version):
        detail = f"not in .tools, but {found.as_posix()} has the pinned version {tool.version}"
        return Check(name, STATUS_OK, detail, {**data, "source": "path"})
    reported = first_version(output) or "unknown"
    detail = f"not installed; {found.as_posix()} has version {reported} (not pinned); {hint}"
    return Check(name, STATUS_FAIL, detail, data)


# ---------------------------------------------------------------------------------------------
# Helpers


def _version_output(run: Runner, argv: list[Any]) -> str | None:
    try:
        proc = run([str(arg) for arg in argv], timeout=COMMAND_TIMEOUT_SECONDS)
    except Exception:  # OSError, timeout: treat as "does not run"
        return None
    if proc.returncode != 0:
        return None
    return _first_line(proc.stdout) or _first_line(proc.stderr)


def _first_line(text: str | None) -> str:
    for line in (text or "").splitlines():
        if line.strip():
            return line.strip()
    return ""
