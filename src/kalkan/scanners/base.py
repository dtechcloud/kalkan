# SPDX-License-Identifier: MIT
"""Scanner adapter runtime: context, result, process handling and status files.

This module implements the Python API of docs/ENGINE-SPEC.md, sections 13 and 13.1.

:func:`run_adapter` runs one adapter and never raises for a tool failure:

1. ``adapter.applies(ctx)`` decides; ``False`` gives ``skipped`` with the reason.
2. A built-in adapter (``tool is None``, output ``candidates``) runs in process through
   ``adapter.collect(ctx)``.
3. :func:`kalkan.tools.resolve.resolve` finds the tool. A missing tool gives ``skipped``.
4. Each invocation starts with ``shell=False``, ``stdin`` closed, a minimal environment
   (:func:`minimal_env`) and an explicit timeout. The first argument of the adapter command is
   the tool path; :func:`run_adapter` replaces it with ``ResolvedTool.argv``, so that a pip tool
   whose entry point is a plain script (checkov on Windows) runs through the tool venv Python.
5. stdout and stderr go to files, never to memory: ``<output_dir>/<engine>.stdout.txt`` and
   ``.stderr.txt``, each cut to :data:`MAX_LOG_BYTES` after the run (the head stays). For the
   ``*-stdout`` outputs, stdout is the output file itself and is not cut.
6. On a timeout the whole process tree is killed: ``taskkill /T /F /PID`` on Windows, the
   process group (the child starts a new session) on Linux and macOS.
7. A SARIF output goes through :func:`kalkan.sarif.ingest.ingest_file` and
   :func:`kalkan.scanners.candidates.merge_candidates`. A malformed or empty SARIF gives
   ``failed`` with the message.
8. ``<output_dir>/<engine>.status.json`` records the result.

Choices that the specification leaves open:

- ``timeout_seconds=None`` uses ``adapter.timeout_seconds``; ``0`` removes the limit. Built-in
  adapters run in process and have no wall-clock limit.
- The working directory of a tool is the run-owned output folder (``scans/`` or ``sca/``)
  unless the adapter says otherwise. Configuration files that tools read from their working
  directory (``trivy.yaml``, ``.trivyignore``, ``.hadolint.yaml``, ``.gitleaksignore``) are
  therefore never taken from the target.
- An adapter can split its work into several invocations (one per Go module, batches of
  Dockerfiles). Each invocation writes a part; the parts of a SARIF engine become one SARIF
  file with one run per part, the parts of a ``json-stdout`` engine one JSON stream. When some
  invocations fail, the status is ``failed`` and the parts of the successful invocations are
  still ingested.
- A tool writes into ``<output_dir>/.work/<engine>/`` first. The final output file is replaced
  only after a successful run and a check of the output (valid JSON, SARIF 2.1.0), so a failed
  run never destroys the last good output: Syft and the Trivy fallback share
  ``sca/sbom.cdx.json``. ``ScanResult.output_path`` is set only for a successful run; read the
  status file before an output. Candidates of earlier runs stay in ``candidates.json`` until
  the engine produces new results.
- Suppressions (ADR-0003): by default the audited target cannot hide results. Each adapter
  turns off the inline and config suppressions of the target that its tool allows to turn off.
  SARIF results that a tool still marks as suppressed are kept and tagged
  ``suppressed-in-source``. ``ScanContext.honor_suppressions`` restores the tool suppressions
  and drops the suppressed results. The status file records which sources were ignored or
  honored (``suppressions``) and how many results were suppressed (``suppressed_results``).
- The minimal environment also keeps the Windows variables that tools need for their caches
  and child processes (``PATHEXT``, ``COMSPEC``, ``WINDIR``, ``SYSTEMDRIVE``, ``LOCALAPPDATA``,
  ``APPDATA``), ``TMPDIR``, ``LC_ALL``, ``LC_CTYPE`` and ``XDG_CACHE_HOME`` on Linux and macOS,
  and the proxy and certificate variables (``HTTP_PROXY``, ``HTTPS_PROXY``, ``NO_PROXY``,
  ``SSL_CERT_FILE``, ``SSL_CERT_DIR``) that database downloads need behind a proxy.
- Every tool run gets ``TEMP`` and ``TMP`` (and ``TMPDIR`` on Linux and macOS) that name the
  folder ``tmp`` in its work folder (:func:`kalkan.tools.toolhome.temp_env`), so a temporary
  file that a tool leaves behind stays in the run: opengrep left its rule files and its core
  input and output in the temporary folder of the user (docs/SECURITY.md). An adapter value
  wins. The work folder is removed with :func:`kalkan.util.fs.remove_tree`.
"""

from __future__ import annotations

import contextlib
import dataclasses
import json
import locale
import os
import posixpath
import re
import signal
import subprocess
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, BinaryIO, Protocol
from urllib.parse import quote

from kalkan.errors import KalkanError, StateError, UnsafeInputError, ValidationError
from kalkan.tools.toolhome import TEMP_DIRNAME, temp_env
from kalkan.util.fs import remove_tree
from kalkan.util.paths import is_safe_relative_path
from kalkan.util.safe_io import atomic_write_json, atomic_write_text, read_bounded

__all__ = [
    "DEFAULT_TIMEOUT_SECONDS",
    "MANIFEST_NAME",
    "MAX_LOG_BYTES",
    "OUTPUT_KINDS",
    "PYTHON_TOOL_ENV",
    "STATUSES",
    "SUPPRESSED_TAG",
    "Adapter",
    "BuiltinOutcome",
    "Invocation",
    "ProcessOutcome",
    "ScanContext",
    "ScanResult",
    "ToolAdapter",
    "cap_file",
    "kill_process_tree",
    "load_scan_context",
    "minimal_env",
    "part_path",
    "run_adapter",
    "run_process",
    "status_path",
    "work_dir",
]

#: Output kinds of ENGINE-SPEC 13.1.
OUTPUT_KINDS = ("sarif-file", "sarif-stdout", "json-file", "json-stdout", "candidates")
SARIF_OUTPUTS = frozenset({"sarif-file", "sarif-stdout"})
STDOUT_OUTPUTS = frozenset({"sarif-stdout", "json-stdout"})
OUTPUT_DIRS = ("scans", "sca")
STATUSES = ("ok", "skipped", "failed", "timeout")

#: stdout and stderr log files are cut to this size after the run.
MAX_LOG_BYTES = 1024 * 1024
#: The largest part file that is merged or checked (the SARIF ingest limit).
MAX_OUTPUT_BYTES = 50 * 1024 * 1024
DEFAULT_TIMEOUT_SECONDS = 900
#: Seconds to wait for a killed process tree to exit.
KILL_WAIT_SECONDS = 10.0
#: The run file that names the target copy, the source folder and the tech tags.
MANIFEST_NAME = "target-manifest.json"
#: Folder under ``scans/`` and ``sca/`` where tools write before the output is checked.
WORK_DIRNAME = ".work"
#: Tag of a candidate whose SARIF result the target suppressed (kept by default, ADR-0003).
SUPPRESSED_TAG = "suppressed-in-source"
_MANIFEST_MAX_BYTES = 4 * 1024 * 1024

#: Environment of the Python tools (checkov, bandit): UTF-8 I/O on every platform, no user
#: site-packages in the tool venv.
PYTHON_TOOL_ENV: Mapping[str, str] = {
    "PYTHONUTF8": "1",
    "PYTHONIOENCODING": "utf-8",
    "PYTHONNOUSERSITE": "1",
}

_BASE_ENV_KEYS = ("PATH", "SYSTEMROOT", "TEMP", "TMP", "HOME", "USERPROFILE", "LANG")
_WINDOWS_ENV_KEYS = ("PATHEXT", "COMSPEC", "WINDIR", "SYSTEMDRIVE", "LOCALAPPDATA", "APPDATA")
_POSIX_ENV_KEYS = ("TMPDIR", "LC_ALL", "LC_CTYPE", "XDG_CACHE_HOME")
_NETWORK_ENV_KEYS = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "no_proxy",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
)

_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_NAME = re.compile(r"[a-z0-9][a-z0-9-]*")
_TRUNCATED_NOTE = "\n[kalkan: output cut to the first {limit} bytes of {size}]\n"


# ---------------------------------------------------------------------------------------------
# Data types


@dataclass(frozen=True)
class ScanContext:
    """What every adapter needs to know about the run (ENGINE-SPEC 13.1)."""

    run_dir: Path
    target_dir: Path
    source_dir: Path | None  # the history copy <run>/source; None when the run has none
    tech: frozenset[str]
    #: True (default): local mode. No tool may use the network: local databases only, no
    #: update or version checks, no module or dependency downloads (docs/SECURITY.md). False
    #: only with the opt-in --online flag of scan and sca.
    offline: bool = True
    allow_path_tools: bool = False
    #: False (default, ADR-0003): the audited target cannot hide results. Inline and config
    #: suppressions of the target are ignored. True restores the suppressions of the tools.
    honor_suppressions: bool = False


@dataclass
class ScanResult:
    """The result of one adapter run (ENGINE-SPEC 13.1).

    ``candidates`` is an addition: the number of candidates that the engine contributed to
    ``candidates.json``, or None when the engine produced no candidates (skipped, failed or a
    JSON output).
    """

    engine: str
    status: str  # ok | skipped | failed | timeout
    output_path: Path | None  # the SARIF or JSON output, when produced
    message: str
    duration_seconds: float
    exit_code: int | None
    tool_version: str | None
    candidates: int | None = None

    def to_dict(self, run_dir: Path | None = None) -> dict[str, Any]:
        """Return a JSON-ready dict. ``output`` is relative to ``run_dir`` when given."""
        return {
            "engine": self.engine,
            "status": self.status,
            "output": _display_path(self.output_path, run_dir),
            "message": self.message,
            "duration_seconds": self.duration_seconds,
            "exit_code": self.exit_code,
            "tool_version": self.tool_version,
            "candidates": self.candidates,
        }


class Adapter(Protocol):
    """An engine adapter (ENGINE-SPEC 13.1).

    Optional members that :func:`run_adapter` uses when present:

    - ``cwd(ctx) -> Path``: the working directory (default: the output folder).
    - ``invocations(ctx, tool_path, out) -> list[Invocation]``: several tool runs.
    - ``collect(ctx) -> BuiltinOutcome``: the in-process run of a built-in engine.
    - ``prepare(ctx, stage) -> None``: called before the invocations with the staging output
      path; writes helper files (for example an empty config) next to it.
    - ``suppression_sources(ctx) -> (ignored, honored)``: the suppression sources of the
      target that this run ignores or honors (ADR-0003), recorded in the status file.
    - ``after_run(ctx, invocation) -> None``: called after a run with an expected exit code,
      before the output check (gosec converts its JSON report to SARIF here). A
      :class:`~kalkan.errors.KalkanError` marks the run as failed.
    - ``status_details(ctx, stdout_log, stderr_log, outputs) -> dict``: called once after the
      invocations, before the logs are cut, with the log paths and the staged outputs of the
      successful invocations. The returned keys go into the status file (Opengrep records its
      partially analyzed and skipped files here). An exception never fails the run; it is
      recorded as ``details_error``.
    """

    name: str  # engine name: trivy, gitleaks-history, syft, osv-scanner, ...
    tool: str | None  # manifest tool name; None for built-in engines (matcher)
    output: str  # sarif-file | sarif-stdout | json-file | json-stdout | candidates
    output_dir: str  # "scans" or "sca"
    output_name: str  # for example "trivy.sarif", "osv.json", "sbom.cdx.json"
    ok_exit_codes: tuple[int, ...]
    timeout_seconds: int

    def applies(self, ctx: ScanContext) -> tuple[bool, str]: ...  # (applies, reason if not)

    def command(self, ctx: ScanContext, tool_path: Path, out: Path) -> list[str]: ...

    def env(self, ctx: ScanContext) -> dict[str, str]: ...


@dataclass(frozen=True)
class Invocation:
    """One tool run of an adapter.

    ``output`` is the file that the run produces: the file the tool writes for a ``*-file``
    output, or the file that receives stdout for a ``*-stdout`` output. ``base`` is the
    target-relative folder that relative SARIF URIs of this run are relative to (gosec writes
    paths relative to its module folder); None means the target root. ``env`` holds variables
    that replace the adapter environment for this run only (``GOFLAGS=-mod=vendor`` for a Go
    module with a ``vendor`` folder). ``setup`` marks a run that only prepares the input of a
    later run of the same adapter (``helm template`` before Checkov, ``helm-checkov``): it must
    end with an expected exit code and its ``after_run`` hook runs, but ``output`` need not exist
    and is never part of the engine output.
    """

    argv: tuple[str, ...]
    cwd: Path
    output: Path
    base: str | None = None
    label: str = ""
    env: tuple[tuple[str, str], ...] = ()
    setup: bool = False


@dataclass(frozen=True)
class ProcessOutcome:
    """How a process ended. ``error`` is set when it could not start."""

    exit_code: int | None
    timed_out: bool = False
    error: str | None = None


@dataclass
class BuiltinOutcome:
    """The in-process result of a built-in engine (the matcher)."""

    candidates: list[dict[str, Any]]
    warnings: list[str] = field(default_factory=list)
    message: str = ""
    #: Extra keys for the status file, for example ``stats`` and ``skipped``.
    details: dict[str, Any] = field(default_factory=dict)


#: ``runner(argv, *, cwd, env, timeout, stdout, stderr) -> ProcessOutcome``. Tests replace it.
ProcessRunner = Callable[..., ProcessOutcome]
#: ``resolver(name, allow_path=...) -> ResolvedTool | None``. Tests replace it.
ToolResolver = Callable[..., Any]


class ToolAdapter:
    """Defaults for the adapters of external tools. Subclasses set the class attributes and
    implement :meth:`arguments` (or :meth:`command` or :meth:`invocations`)."""

    name: str = ""
    tool: str | None = None
    output: str = "sarif-file"
    output_dir: str = "scans"
    output_name: str = ""
    ok_exit_codes: tuple[int, ...] = (0,)
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS

    def applies(self, ctx: ScanContext) -> tuple[bool, str]:
        """Return ``(True, "")``: the adapter runs on every target."""
        return True, ""

    def arguments(self, ctx: ScanContext, out: Path) -> list[str]:
        """Return the tool arguments (without the tool itself)."""
        raise NotImplementedError

    def command(self, ctx: ScanContext, tool_path: Path, out: Path) -> list[str]:
        """Return the full command line: the tool path, then :meth:`arguments`."""
        return [str(tool_path), *self.arguments(ctx, out)]

    def env(self, ctx: ScanContext) -> dict[str, str]:
        """Return the environment variables that the adapter adds to the minimal environment."""
        return {}

    def cwd(self, ctx: ScanContext) -> Path:
        """Return the working directory: the run-owned output folder."""
        return ctx.run_dir / self.output_dir

    def invocations(self, ctx: ScanContext, tool_path: Path, out: Path) -> list[Invocation]:
        """Return the tool runs: one run of :meth:`command` by default."""
        return [Invocation(tuple(self.command(ctx, tool_path, out)), self.cwd(ctx), out)]

    def __repr__(self) -> str:
        return f"<{type(self).__name__} {self.name}>"


# ---------------------------------------------------------------------------------------------
# Small helpers


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _display_path(path: Path | None, run_dir: Path | None) -> str | None:
    if path is None:
        return None
    if run_dir is not None:
        with contextlib.suppress(ValueError):
            return path.relative_to(run_dir).as_posix()
    return path.as_posix()


def status_path(run_dir: Path, adapter: Adapter) -> Path:
    """Return ``<run>/<output_dir>/<engine>.status.json``."""
    return Path(run_dir) / adapter.output_dir / f"{adapter.name}.status.json"


def part_path(out: Path, index: int) -> Path:
    """Return the path of part ``index`` of the output ``out``:
    ``<dir>/<output name>.parts/<index>.<suffix>``."""
    suffix = "".join(out.suffixes[-1:]) or ".out"
    return out.parent / f"{out.name}.parts" / f"{index:03d}{suffix}"


def minimal_env(
    extra: Mapping[str, str] | None = None, *, environ: Mapping[str, str] | None = None
) -> dict[str, str]:
    """Return the minimal tool environment (module docstring), plus ``extra``."""
    source = os.environ if environ is None else environ
    keys = list(_BASE_ENV_KEYS)
    keys += _WINDOWS_ENV_KEYS if os.name == "nt" else _POSIX_ENV_KEYS
    keys += _NETWORK_ENV_KEYS
    if os.name == "nt":  # names are case-insensitive on Windows: keep one spelling
        keys = [key.upper() for key in keys]
    env: dict[str, str] = {}
    for key in dict.fromkeys(keys):
        value = source.get(key)
        if value:
            env[key] = value
    for key, value in (extra or {}).items():
        env[str(key)] = str(value)
    return env


def cap_file(path: Path, limit: int = MAX_LOG_BYTES) -> bool:
    """Cut ``path`` to its first ``limit`` bytes (a note included). Return True when cut."""
    try:
        size = path.stat().st_size
    except OSError:
        return False
    if size <= limit:
        return False
    note = _TRUNCATED_NOTE.format(limit=limit, size=size).encode("utf-8")
    keep = max(0, limit - len(note))
    with open(path, "r+b") as handle:
        head = handle.read(keep)
        # Do not cut inside a UTF-8 sequence: drop continuation bytes at the end.
        cut = len(head)
        while cut > 0 and head[cut - 1] & 0xC0 == 0x80:
            cut -= 1
        if cut > 0 and head[cut - 1] >= 0xC0:
            cut -= 1
        handle.seek(cut)
        handle.truncate()
        handle.write(note)
    return True


def _last_line(path: Path, limit: int = 300) -> str:
    """Return the last non-empty line of a log file, without ANSI and control characters."""
    try:
        with open(path, "rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - 16384))
            tail = handle.read().decode("utf-8", errors="replace")
    except OSError:
        return ""
    for line in reversed(tail.splitlines()):
        text = _CONTROL.sub("", _ANSI.sub("", line)).strip()
        if text and not text.startswith("[kalkan:"):
            return text[:limit]
    return ""


def _unlink(path: Path) -> None:
    with contextlib.suppress(FileNotFoundError):
        path.unlink()


def work_dir(run_dir: Path, adapter: Adapter) -> Path:
    """Return ``<run>/<output_dir>/.work/<engine>``, where the tool writes before the output
    is checked and moved into place."""
    return Path(run_dir) / adapter.output_dir / WORK_DIRNAME / adapter.name


def _clear(folder: Path) -> None:
    """Remove a work folder (:func:`kalkan.util.fs.remove_tree`: links and junctions inside are
    removed as links, never followed; read-only files and long paths are removed too)."""
    remove_tree(folder)
    parent = folder.parent
    if parent.name == WORK_DIRNAME:
        with contextlib.suppress(OSError):
            parent.rmdir()  # only when empty


# ---------------------------------------------------------------------------------------------
# Processes


def run_process(
    argv: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    timeout: float | None,
    stdout: BinaryIO,
    stderr: BinaryIO,
) -> ProcessOutcome:
    """Run ``argv`` without a shell, stdout and stderr into the given files.

    ``timeout=None`` waits without a limit. On a timeout or an interrupt the process tree is
    killed (:func:`kill_process_tree`).
    """
    options: dict[str, Any] = {}
    if os.name != "nt":
        options["start_new_session"] = True  # own process group, killed as a whole
    try:
        process = subprocess.Popen(
            [str(arg) for arg in argv],
            shell=False,
            cwd=str(cwd),
            env=dict(env),
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
            **options,
        )
    except (OSError, ValueError) as exc:
        reason = getattr(exc, "strerror", None) or str(exc)
        return ProcessOutcome(None, error=f"cannot start {Path(str(argv[0])).name}: {reason}")
    try:
        code = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        kill_process_tree(process)
        return ProcessOutcome(process.returncode, timed_out=True)
    except BaseException:
        kill_process_tree(process)
        raise
    return ProcessOutcome(code)


def kill_process_tree(process: subprocess.Popen[Any]) -> None:
    """Kill ``process`` and its children, then wait for it.

    Windows: ``%SYSTEMROOT%\\System32\\taskkill.exe /T /F /PID <pid>`` (absolute path, so a
    planted ``taskkill`` on PATH is never used). Linux and macOS: ``SIGKILL`` to the process
    group that :func:`run_process` created.
    """
    if os.name == "nt":
        root = os.environ.get("SYSTEMROOT") or r"C:\Windows"
        taskkill = Path(root) / "System32" / "taskkill.exe"
        with contextlib.suppress(OSError, subprocess.SubprocessError):
            subprocess.run(
                [str(taskkill), "/T", "/F", "/PID", str(process.pid)],
                shell=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=30,
                check=False,
            )
    else:
        with contextlib.suppress(OSError):
            os.killpg(process.pid, signal.SIGKILL)  # type: ignore[attr-defined]
    with contextlib.suppress(OSError):
        process.kill()
    with contextlib.suppress(subprocess.TimeoutExpired):
        process.wait(timeout=KILL_WAIT_SECONDS)


# ---------------------------------------------------------------------------------------------
# Run context


def load_scan_context(
    run_dir: str | os.PathLike[str],
    *,
    offline: bool = True,
    allow_path_tools: bool = False,
    honor_suppressions: bool = False,
) -> ScanContext:
    """Build the :class:`ScanContext` of a run from ``target-manifest.json`` (ENGINE-SPEC 10).

    The manifest gives ``copy`` (the target folder name, default ``target``), ``source_dir``
    (kept only when it is an existing folder inside the run folder: the private history copy
    ``<run>/source``, never the original folder) and ``tech``. Raises
    :class:`~kalkan.errors.StateError` when the manifest or the target folder is missing or
    invalid.
    """
    run = Path(run_dir).resolve()
    path = run / MANIFEST_NAME
    try:
        data = json.loads(read_bounded(path, _MANIFEST_MAX_BYTES))
    except UnsafeInputError as exc:
        raise StateError(f"cannot read {MANIFEST_NAME} of the run: {exc}") from None
    except ValueError as exc:
        raise StateError(f"{MANIFEST_NAME} is not valid JSON: {exc}") from None
    if not isinstance(data, dict):
        raise StateError(f"{MANIFEST_NAME} must hold a JSON object")
    copy = data.get("copy", "target")
    if not isinstance(copy, str) or not is_safe_relative_path(copy):
        raise StateError(f"{MANIFEST_NAME}: 'copy' must be a safe relative folder name")
    target = run / copy
    if not target.is_dir() or target.is_symlink():
        raise StateError(f"the target copy {copy}/ of the run is missing")
    source: Path | None = None
    raw_source = data.get("source_dir")
    if isinstance(raw_source, str) and raw_source.strip():
        candidate = Path(raw_source)
        if candidate.is_absolute() and candidate.is_dir() and not candidate.is_symlink():
            resolved = candidate.resolve()
            # Only the private copy inside the run: a scanner never gets the original folder
            # (an older manifest named it here).
            if resolved != run and resolved.is_relative_to(run):
                source = resolved
    tech = data.get("tech", [])
    tags = (
        frozenset(item.strip().lower() for item in tech if isinstance(item, str) and item.strip())
        if isinstance(tech, list)
        else frozenset()
    )
    return ScanContext(
        run_dir=run,
        target_dir=target.resolve(),
        source_dir=source,
        tech=tags,
        offline=offline,
        allow_path_tools=allow_path_tools,
        honor_suppressions=honor_suppressions,
    )


# ---------------------------------------------------------------------------------------------
# run_adapter


@dataclass
class _Record:
    """Everything that goes into the status file."""

    engine: str
    started_at: str
    started: float
    status: str = "failed"
    message: str = ""
    exit_code: int | None = None
    tool_version: str | None = None
    output_path: Path | None = None
    candidates: int | None = None
    commands: list[list[str]] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)


def run_adapter(
    adapter: Adapter,
    ctx: ScanContext,
    *,
    timeout_seconds: int | None = None,
    runner: ProcessRunner | None = None,
    resolver: ToolResolver | None = None,
    ingest: bool = True,
) -> ScanResult:
    """Run one adapter and return its result (ENGINE-SPEC 13.1; module docstring).

    ``timeout_seconds`` overrides ``adapter.timeout_seconds``; ``0`` removes the limit.
    ``runner`` and ``resolver`` replace :func:`run_process` and
    :func:`kalkan.tools.resolve.resolve` (tests). With ``ingest=False`` a SARIF output is not
    turned into candidates. The function never raises for a tool failure; an unexpected
    exception inside an adapter also gives ``failed``.
    """
    if timeout_seconds is not None and timeout_seconds < 0:
        raise ValueError("timeout_seconds must be 0 (no limit) or a positive number")
    record = _Record(engine=adapter.name, started_at=_now(), started=time.monotonic())
    ctx = dataclasses.replace(
        ctx,
        run_dir=Path(ctx.run_dir).resolve(),
        target_dir=Path(ctx.target_dir).resolve(),
        source_dir=Path(ctx.source_dir).resolve() if ctx.source_dir is not None else None,
    )
    try:
        _check_adapter(adapter)
        (ctx.run_dir / adapter.output_dir).mkdir(parents=True, exist_ok=True)
        _run(adapter, ctx, record, timeout_seconds, runner, resolver, ingest)
    except Exception as exc:  # never raise for one engine: record the failure
        record.status = "failed"
        record.message = f"internal error: {type(exc).__name__}: {exc}"
    return _finish(adapter, ctx, record)


def _check_adapter(adapter: Adapter) -> None:
    if not isinstance(adapter.name, str) or not _NAME.fullmatch(adapter.name):
        raise ValueError(f"invalid engine name: {adapter.name!r}")
    if adapter.output not in OUTPUT_KINDS:
        raise ValueError(f"{adapter.name}: unknown output kind {adapter.output!r}")
    if adapter.output_dir not in OUTPUT_DIRS:
        raise ValueError(f"{adapter.name}: output_dir must be one of {', '.join(OUTPUT_DIRS)}")
    if adapter.output != "candidates" and (
        not adapter.output_name or "/" in adapter.output_name or "\\" in adapter.output_name
    ):
        raise ValueError(f"{adapter.name}: output_name must be a plain file name")


def _run(
    adapter: Adapter,
    ctx: ScanContext,
    record: _Record,
    timeout_seconds: int | None,
    runner: ProcessRunner | None,
    resolver: ToolResolver | None,
    ingest: bool,
) -> None:
    applies, reason = adapter.applies(ctx)
    if not applies:
        record.status, record.message = "skipped", reason or "not applicable"
        return
    if adapter.tool is None or adapter.output == "candidates":
        _run_builtin(adapter, ctx, record)
        return

    resolve = resolver or _default_resolver
    resolved = resolve(adapter.tool, allow_path=ctx.allow_path_tools)
    if resolved is None:
        record.status = "skipped"
        record.message = (
            f"tool not found: {adapter.tool} is not installed (run: kalkan tools install "
            f"{adapter.tool})"
        )
        return
    record.tool_version = str(resolved.version) if resolved.version else None

    out = ctx.run_dir / adapter.output_dir / adapter.output_name
    work = work_dir(ctx.run_dir, adapter)
    _clear(work)
    work.mkdir(parents=True, exist_ok=True)
    temp = work / TEMP_DIRNAME
    temp.mkdir(exist_ok=True)
    stage = work / adapter.output_name
    prepare = getattr(adapter, "prepare", None)
    if callable(prepare):
        prepare(ctx, stage)
    invocations = _invocations(adapter, ctx, resolved, stage)
    if not invocations:
        record.status, record.message = "skipped", "nothing to scan"
        return
    record.details["suppressions"] = _suppression_record(adapter, ctx)
    record.commands = [list(item.argv) for item in invocations]
    own_env = {
        item.label or str(i): dict(item.env) for i, item in enumerate(invocations) if item.env
    }
    if own_env:
        record.details["invocation_env"] = own_env
    for item in invocations:
        _unlink(item.output)
        item.output.parent.mkdir(parents=True, exist_ok=True)

    limit = adapter.timeout_seconds if timeout_seconds is None else timeout_seconds
    env = minimal_env({**temp_env(temp), **adapter.env(ctx)})
    done, failures, timed_out = _execute(
        adapter, ctx, invocations, env, limit or None, runner or run_process, record
    )

    if done:
        try:
            _combine(adapter, done, out)
        except KalkanError as exc:
            failures.append(f"cannot use the output: {exc}")
            done = []
    if done:
        _clear(work)
        record.output_path = out
        if adapter.output in SARIF_OUTPUTS and ingest:
            problem = _ingest(adapter, ctx, out, record)
            if problem:
                failures.append(problem)

    if timed_out:
        record.status = "timeout"
        record.message = f"timed out after {limit} s" + (
            f"; {len(done)} of {len(invocations)} runs finished" if len(invocations) > 1 else ""
        )
    elif failures:
        record.status = "failed"
        prefix = (
            f"{len(done)} of {len(invocations)} runs succeeded; "
            if len(invocations) > 1 and done
            else ""
        )
        record.message = prefix + "; ".join(failures[:3])
    else:
        record.status = "ok"
        record.message = _ok_message(adapter, ctx, out, record)


def _default_resolver(name: str, *, allow_path: bool = False) -> Any:
    from kalkan.tools.resolve import resolve  # lazy: keeps the import graph small

    return resolve(name, allow_path=allow_path)


def _invocations(adapter: Adapter, ctx: ScanContext, resolved: Any, out: Path) -> list[Invocation]:
    tool_path = Path(resolved.path)
    make = getattr(adapter, "invocations", None)
    if callable(make):
        items = list(make(ctx, tool_path, out))
    else:
        cwd_of = getattr(adapter, "cwd", None)
        cwd = cwd_of(ctx) if callable(cwd_of) else ctx.run_dir / adapter.output_dir
        items = [Invocation(tuple(adapter.command(ctx, tool_path, out)), cwd, out)]
    prefix = [str(arg) for arg in resolved.argv]
    fixed: list[Invocation] = []
    for item in items:
        argv = [str(arg) for arg in item.argv]
        if argv and argv[0] == str(tool_path):
            argv = prefix + argv[1:]
        fixed.append(dataclasses.replace(item, argv=tuple(argv)))
    return fixed


def _execute(
    adapter: Adapter,
    ctx: ScanContext,
    invocations: list[Invocation],
    env: Mapping[str, str],
    limit: float | None,
    runner: ProcessRunner,
    record: _Record,
) -> tuple[list[Invocation], list[str], bool]:
    """Run the invocations. Return the successful ones, the failure messages and whether the
    time limit was hit."""
    folder = ctx.run_dir / adapter.output_dir
    stdout_log = folder / f"{adapter.name}.stdout.txt"
    stderr_log = folder / f"{adapter.name}.stderr.txt"
    to_stdout = adapter.output in STDOUT_OUTPUTS
    deadline = None if limit is None else record.started + limit
    done: list[Invocation] = []
    failures: list[str] = []
    codes: list[int] = []
    timed_out = False
    many = len(invocations) > 1
    with open(stdout_log, "wb") as out_log, open(stderr_log, "wb") as err_log:
        if to_stdout:
            names = ", ".join(_display_path(item.output, ctx.run_dir) or "" for item in invocations)
            out_log.write(f"[kalkan: stdout is the output file: {names}]\n".encode())
        for index, item in enumerate(invocations, start=1):
            where = f" ({item.label})" if many and item.label else ""
            if many:
                header = f"== kalkan: run {index}/{len(invocations)}{where} ==\n".encode()
                err_log.write(header)
                if not to_stdout:
                    out_log.write(header)
                err_log.flush()
                out_log.flush()
            remaining = None if deadline is None else deadline - time.monotonic()
            if remaining is not None and remaining <= 0:
                timed_out = True
                break
            run_env = {**env, **dict(item.env)} if item.env else env
            if to_stdout:
                with open(item.output, "wb") as target:
                    outcome = runner(
                        item.argv,
                        cwd=item.cwd,
                        env=run_env,
                        timeout=remaining,
                        stdout=target,
                        stderr=err_log,
                    )
            else:
                outcome = runner(
                    item.argv,
                    cwd=item.cwd,
                    env=run_env,
                    timeout=remaining,
                    stdout=out_log,
                    stderr=err_log,
                )
            out_log.flush()
            err_log.flush()
            if outcome.error:
                failures.append(outcome.error + where)
                continue
            if outcome.exit_code is not None:
                codes.append(outcome.exit_code)
            if outcome.timed_out:
                timed_out = True
                break
            if outcome.exit_code not in adapter.ok_exit_codes:
                expected = ", ".join(str(code) for code in adapter.ok_exit_codes)
                detail = _last_line(stderr_log)
                failures.append(
                    f"exit code {outcome.exit_code} (expected {expected}){where}"
                    + (f": {detail}" if detail else "")
                )
                continue
            after = getattr(adapter, "after_run", None)
            if callable(after):
                try:
                    after(ctx, item)
                except KalkanError as exc:
                    failures.append(f"{exc}{where}")
                    continue
            if item.setup:
                continue  # a setup run: its output is the input of a later run (Invocation)
            if not item.output.is_file():
                failures.append(f"no output file {item.output.name}{where}")
                continue
            if item.output.stat().st_size == 0 and adapter.output != "json-stdout":
                failures.append(f"empty output file {item.output.name}{where}")
                continue
            done.append(item)
    details = getattr(adapter, "status_details", None)
    if callable(details):
        try:
            extra = details(ctx, stdout_log, stderr_log, [item.output for item in done])
            record.details.update(extra or {})
        except Exception as exc:  # details never fail a run
            record.details["details_error"] = f"{type(exc).__name__}: {exc}"
    cap_file(stdout_log)
    cap_file(stderr_log)
    unexpected = [code for code in codes if code not in adapter.ok_exit_codes]
    record.exit_code = unexpected[0] if unexpected else (codes[-1] if codes else None)
    return done, failures, timed_out


def _combine(adapter: Adapter, done: list[Invocation], out: Path) -> None:
    """Turn the staged outputs of the successful invocations into ``out``.

    ``out`` changes only here, after a check of the staged output, so a failed run never
    replaces the last good output (Syft and the Trivy fallback share ``sbom.cdx.json``).
    """
    if adapter.output in SARIF_OUTPUTS:
        docs: list[tuple[Invocation, dict[str, Any]]] = []
        for item in done:
            if adapter.output == "sarif-stdout":
                _repair_encoding(item.output)
            docs.append((item, _sarif_document(item.output)))
        if len(done) == 1 and done[0].base is None:
            os.replace(done[0].output, out)
            return
        runs: list[Any] = []
        for item, doc in docs:
            for run in doc["runs"]:
                if item.base and isinstance(run, dict):
                    _rebase_uris(run, item.base)
                runs.append(run)
        sarif = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": runs,
        }
        atomic_write_json(out, sarif)
    elif adapter.output == "json-stdout":
        chunks: list[str] = []
        for index, item in enumerate(done):
            marker = {"kalkan_invocation": {"index": index, "label": item.label, "dir": item.base}}
            chunks.append(json.dumps(marker, ensure_ascii=False))
            text = read_bounded(item.output, MAX_OUTPUT_BYTES).decode("utf-8", errors="replace")
            chunks.append(text.strip())
        atomic_write_text(out, "\n".join(chunk for chunk in chunks if chunk) + "\n")
    else:
        if len(done) != 1:
            raise ValidationError(f"{adapter.name}: several {adapter.output} outputs")
        if done[0].output.stat().st_size <= MAX_OUTPUT_BYTES:
            _load_json(done[0].output)  # a larger file is left to its reader
        os.replace(done[0].output, out)


def _sarif_document(path: Path) -> dict[str, Any]:
    doc = _load_json(path)
    if not isinstance(doc, dict) or doc.get("version") != "2.1.0":
        raise ValidationError(f"{path.name} is not a SARIF 2.1.0 document")
    if not isinstance(doc.get("runs"), list):
        raise ValidationError(f"{path.name}: 'runs' is not an array")
    return doc


def _load_json(path: Path) -> Any:
    try:
        return json.loads(read_bounded(path, MAX_OUTPUT_BYTES))
    except ValueError as exc:
        raise ValidationError(f"{path.name} is not valid JSON: {exc}") from None


def _repair_encoding(path: Path) -> None:
    """Rewrite a stdout JSON document in the ANSI code page as UTF-8 (old Windows consoles)."""
    try:
        data = read_bounded(path, MAX_OUTPUT_BYTES)
        json.loads(data)
        return
    except UnicodeDecodeError:
        pass
    except (ValueError, KalkanError):
        return
    encoding = locale.getpreferredencoding(False)
    try:
        text = data.decode(encoding)
        json.loads(text)
    except (UnicodeDecodeError, ValueError, LookupError):
        return
    atomic_write_text(path, text)


def _rebase_uris(run: dict[str, Any], base: str) -> None:
    """Prefix the relative artifact URIs of a SARIF run with ``base`` (a target-relative
    folder). URIs with a scheme, absolute paths and URIs with a known ``uriBaseId`` stay."""
    known = run.get("originalUriBaseIds")
    known_ids = set(known) if isinstance(known, dict) else set()
    prefix = quote(base.strip("/"), safe="/")

    def fix(location: Any) -> None:
        if not isinstance(location, dict):
            return
        artifact = location.get("artifactLocation")
        if not isinstance(artifact, dict):
            return
        uri = artifact.get("uri")
        if not isinstance(uri, str) or not uri.strip():
            return
        if artifact.get("uriBaseId") in known_ids:
            return
        text = uri.strip().replace("\\", "/")
        if re.match(r"[A-Za-z][A-Za-z0-9+.-]*:", text) or text.startswith("/"):
            return
        artifact["uri"] = posixpath.normpath(posixpath.join(prefix, text))

    for result in run.get("results") or []:
        if not isinstance(result, dict):
            continue
        for key in ("locations", "relatedLocations"):
            for location in result.get(key) or []:
                if isinstance(location, dict):
                    fix(location.get("physicalLocation"))
    for artifact in run.get("artifacts") or []:
        if isinstance(artifact, dict):
            fix({"artifactLocation": artifact.get("location")})


def _ingest(adapter: Adapter, ctx: ScanContext, out: Path, record: _Record) -> str | None:
    """Ingest the SARIF output and merge the candidates. Return a failure message or None."""
    from kalkan.sarif.ingest import ingest_file  # lazy: phase 1 module
    from kalkan.scanners.candidates import merge_candidates

    relative = _display_path(out, ctx.run_dir) or out.as_posix()
    try:
        result = ingest_file(out, adapter.name, ctx.target_dir)
    except KalkanError as exc:
        return f"cannot ingest {relative}: {exc}"
    suppressed = _suppressed_results(out)
    candidates: list[dict[str, Any]] = []
    marked = 0
    for candidate in result.candidates:
        raw = candidate.get("raw")
        if isinstance(raw, dict):
            raw["sarif_file"] = relative
            key = (raw.get("run_index"), raw.get("result_index"))
            if key in suppressed:
                marked += 1
                if ctx.honor_suppressions:
                    continue
                tags = candidate.setdefault("tags", [])
                if isinstance(tags, list) and SUPPRESSED_TAG not in tags:
                    tags.append(SUPPRESSED_TAG)
        candidates.append(candidate)
    if marked:
        record.details["suppressed_results"] = {
            "count": marked,
            "action": "dropped" if ctx.honor_suppressions else f"kept, tagged {SUPPRESSED_TAG}",
        }
    try:
        record.candidates = merge_candidates(ctx.run_dir, adapter.name, candidates, result.warnings)
    except KalkanError as exc:
        return f"cannot update candidates.json: {exc}"
    if result.warnings:
        record.details["ingest_warnings"] = len(result.warnings)
    return None


def _suppression_record(adapter: Adapter, ctx: ScanContext) -> dict[str, Any]:
    """Return the ``suppressions`` entry of the status file (ADR-0003)."""
    ignored: list[str] = []
    honored: list[str] = []
    sources = getattr(adapter, "suppression_sources", None)
    if callable(sources):
        more_ignored, more_honored = sources(ctx)
        ignored += list(more_ignored)
        honored += list(more_honored)
    if adapter.output in SARIF_OUTPUTS:
        note = "results that the tool marks as suppressed in the SARIF"
        if ctx.honor_suppressions:
            honored.append(f"{note} (dropped)")
        else:
            ignored.append(f"{note} (kept, tagged {SUPPRESSED_TAG})")
    return {
        "mode": "honor" if ctx.honor_suppressions else "ignore",
        "ignored": ignored,
        "honored": honored,
    }


def _suppressed_results(out: Path) -> set[tuple[int, int]]:
    """Return ``(run_index, result_index)`` of the SARIF results with an accepted suppression
    (no ``status``, or ``status`` ``accepted``)."""
    try:
        doc = _load_json(out)
    except KalkanError:
        return set()
    found: set[tuple[int, int]] = set()
    runs = doc.get("runs") if isinstance(doc, dict) else None
    for run_index, run in enumerate(runs if isinstance(runs, list) else []):
        results = run.get("results") if isinstance(run, dict) else None
        for result_index, item in enumerate(results if isinstance(results, list) else []):
            suppressions = item.get("suppressions") if isinstance(item, dict) else None
            if not isinstance(suppressions, list):
                continue
            if any(
                isinstance(entry, dict) and entry.get("status", "accepted") == "accepted"
                for entry in suppressions
            ):
                found.add((run_index, result_index))
    return found


def _ok_message(adapter: Adapter, ctx: ScanContext, out: Path, record: _Record) -> str:
    if record.candidates is not None:
        text = f"{record.candidates} candidate{'s' if record.candidates != 1 else ''}"
        warnings = record.details.get("ingest_warnings")
        suppressed = record.details.get("suppressed_results")
        if suppressed:
            text += f" ({suppressed['count']} suppressed by the target: {suppressed['action']})"
        return text + (f", {warnings} ingest warnings" if warnings else "")
    if record.output_path is not None:
        size = record.output_path.stat().st_size
        return f"output written: {_display_path(record.output_path, ctx.run_dir)} ({size} bytes)"
    return "done"


def _run_builtin(adapter: Adapter, ctx: ScanContext, record: _Record) -> None:
    from kalkan.scanners.candidates import merge_candidates

    collect = getattr(adapter, "collect", None)
    if not callable(collect):
        raise ValueError(f"{adapter.name}: a built-in adapter needs collect(ctx)")
    folder = ctx.run_dir / adapter.output_dir
    for name in (f"{adapter.name}.stdout.txt", f"{adapter.name}.stderr.txt"):
        _unlink(folder / name)
    try:
        outcome: BuiltinOutcome = collect(ctx)
    except KalkanError as exc:
        details = getattr(exc, "errors", [])
        record.status = "failed"
        record.message = str(exc) + (f": {details[0]}" if details else "")
        return
    record.details.update(outcome.details)
    record.candidates = merge_candidates(
        ctx.run_dir, adapter.name, outcome.candidates, outcome.warnings
    )
    record.status = "ok"
    count = f"{record.candidates} candidate{'s' if record.candidates != 1 else ''}"
    record.message = f"{count}; {outcome.message}" if outcome.message else count


def _finish(adapter: Adapter, ctx: ScanContext, record: _Record) -> ScanResult:
    duration = round(time.monotonic() - record.started, 3)
    result = ScanResult(
        engine=adapter.name,
        status=record.status,
        output_path=record.output_path,
        message=record.message,
        duration_seconds=duration,
        exit_code=record.exit_code,
        tool_version=record.tool_version,
        candidates=record.candidates,
    )
    status = {
        "engine": adapter.name,
        "status": record.status,
        "message": record.message,
        "duration_seconds": duration,
        "exit_code": record.exit_code,
        "tool_version": record.tool_version,
        "started_at": record.started_at,
        "finished_at": _now(),
        "command": record.commands[0] if record.commands else [],
        "output": _display_path(record.output_path, ctx.run_dir),
        "candidates": record.candidates,
    }
    if len(record.commands) > 1:
        status["commands"] = record.commands
    for key, value in record.details.items():
        status.setdefault(key, value)
    with contextlib.suppress(OSError, ValueError):
        target = status_path(ctx.run_dir, adapter)
        target.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_json(target, status)
    return result
