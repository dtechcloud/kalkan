# SPDX-License-Identifier: MIT
"""Vendored JavaScript libraries: detection and matching (docs/ENGINE-SPEC.md 17, ADR-0005).

Syft, OSV-Scanner and Grype read manifests and lockfiles. A JavaScript library that a project
copies into its tree (``wwwroot/lib/bootstrap/js/bootstrap.bundle.min.js``,
``public/vendor/jquery.min.js``) has neither, so no SCA tool sees it. :func:`scan` finds such
files with the extractors of the RetireJS repository (:mod:`kalkan.sca.retirejs`), which
``kalkan sca update-db`` stores locally (:mod:`kalkan.sca.retiredb`).

1. **Files** (:func:`list_files`). Every ``.js``, ``.mjs`` and ``.cjs`` file of the target copy
   in sorted order, at most :data:`MAX_FILES`. The walk never follows a link or a junction and
   skips the folders of :data:`SKIP_DIRS`. ``node_modules`` is skipped on purpose: run init
   does not copy it (ENGINE-SPEC 10); its packages come from a package manager, the lockfile
   lists them and Syft catalogs them from their ``package.json``, so a second record per
   package under a JavaScript path would only add noise. ``vendor``, ``bower_components``,
   ``jspm_packages``, ``wwwroot/lib``, ``public`` and ``dist`` stay in: vendored copies live
   there, and no SCA tool catalogs them. A file larger than :data:`MAX_FILE_BYTES` is not read.
2. **Process and time limits.** The extractors are third-party regexes and the files are
   target data; Python ``re`` has no timeout. The check therefore runs in a child process
   (``python -I`` with the same kalkan package, working folder ``work_dir``, no shell) that
   reports each file before and after its check on stdout. When one file takes longer than
   ``file_seconds`` (default :data:`FILE_SECONDS`), the parent kills the process tree, records
   the file as timed out and starts a new process for the remaining files. The scan stops after
   ``total_seconds`` (default :data:`DEFAULT_TOTAL_SECONDS`; None removes the limit) or after
   :data:`MAX_TIMEOUTS` files that timed out or stopped the child; every file left over is
   recorded as not checked, with the reason. The child reads each file with
   :func:`kalkan.util.safe_io.read_bounded`.
3. **Result** (:class:`VendoredScan`): one :class:`kalkan.sca.retirejs.Detection` per (library,
   version, file), the files that were not checked with their reasons, warnings and the
   repository facts. ``sca match`` writes ``sca/vendored.json`` (:meth:`VendoredScan.document`)
   and the engine status ``sca/retirejs.status.json`` (:meth:`VendoredScan.status_document`;
   the files that were not checked are its ``skipped_files``, a scan gap of the report).
4. **Matching.** (a) The vulnerability ranges of the repository itself
   (:func:`retire_records`, engine :data:`ENGINE`). (b) The local OSV and Grype databases: the
   detections join ``sca/manifest-pins.cdx.json`` as ``pkg:npm/<npm name>@<version>``
   components with one ``kalkan:vendored:path`` property per file
   (:func:`kalkan.sca.manifests.pins_sbom`), so that ``osv-scanner-pins`` and ``grype-pins``
   check them. Every record carries ``pin_source: "vendored"``, the vendored files as
   ``locations`` and :func:`vendored_entries` (file, line, library, version, extractor); the
   merge joins the records of the three engines by their advisory IDs.
5. **Missing repository.** Without the local repository no library is detected and no online
   source is asked. When the target has JavaScript files, the status is ``skipped`` with a
   message that starts with ``no local``, and ``sca match`` records the database gap
   ``{engine: "retirejs", ecosystem: null}``.
"""

from __future__ import annotations

import json
import os
import queue
import shutil
import stat
import subprocess
import sys
import threading
import time
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import IO, Any, Final

from kalkan.errors import UnsafeInputError, ValidationError
from kalkan.sca import retirejs
from kalkan.sca.normalize import new_record
from kalkan.sca.sbom import package_key, version_key
from kalkan.scanners.base import kill_process_tree, minimal_env
from kalkan.util.safe_io import DEFAULT_MAX_BYTES, atomic_write_json, read_bounded

__all__ = [
    "DEFAULT_TOTAL_SECONDS",
    "ENGINE",
    "EXTENSIONS",
    "FILE_SECONDS",
    "MAX_FILES",
    "MAX_FILE_BYTES",
    "MAX_TIMEOUTS",
    "NO_FILES",
    "NO_REPOSITORY",
    "SKIP_DIRS",
    "STATUS_FILE",
    "VENDORED_FILE",
    "VendoredScan",
    "check_file",
    "list_files",
    "pin_locations",
    "retire_records",
    "scan",
    "vendored_entries",
    "worker_main",
    "write_outputs",
]

#: The engine name of the records from the repository ranges and of the status file.
ENGINE: Final = "retirejs"
#: The detector output and the engine status, relative to the run folder.
VENDORED_FILE: Final = "sca/vendored.json"
STATUS_FILE: Final = f"sca/{ENGINE}.status.json"
EXTENSIONS: Final = (".js", ".mjs", ".cjs")
SKIP_DIRS: Final = frozenset({".git", "node_modules", ".venv", "venv"})
MAX_FILES: Final = 20_000
MAX_FILE_BYTES: Final = DEFAULT_MAX_BYTES
FILE_SECONDS: Final = 20.0
DEFAULT_TOTAL_SECONDS: Final = 900.0
MAX_TIMEOUTS: Final = 5
#: The child process must load the repository and report ``ready`` within this time.
STARTUP_SECONDS: Final = 120.0
#: At most this many detections per file (a file is one library build, not a catalog).
MAX_DETECTIONS_PER_FILE: Final = 50
MAX_LISTED_PATHS: Final = 50
SCHEMA_VERSION: Final = 1
NO_REPOSITORY: Final = "no local RetireJS repository (run: kalkan sca update-db)"
NO_FILES: Final = "no JavaScript file outside node_modules"
REASON_LARGE: Final = f"larger than {MAX_FILE_BYTES // (1024 * 1024)} MiB"
REASON_LINK: Final = "a link or not a regular file"
REASON_UNREADABLE: Final = "cannot be read safely"
REASON_TOO_MANY: Final = f"more than {MAX_FILES} JavaScript files"
REASON_TOTAL: Final = "not checked: the time limit of the scan was used up"
_BOOT: Final = (
    "import sys\n"
    "sys.path.insert(0, sys.argv[1])\n"
    "from kalkan.sca.vendored import worker_main\n"
    "raise SystemExit(worker_main(sys.argv[2:]))\n"
)


# --- result --------------------------------------------------------------------------------------


@dataclass
class VendoredScan:
    """The result of :func:`scan` (module docstring, item 3)."""

    status: str = "skipped"  # ok | skipped | failed | timeout
    message: str = ""
    detections: list[retirejs.Detection] = field(default_factory=list)
    files_total: int = 0
    files_checked: int = 0
    #: Reason -> target-relative paths of the files that were not checked.
    skipped: dict[str, list[str]] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    repository: retirejs.Repository | None = None
    #: ``kalkan-source.json`` of the repository (:func:`kalkan.sca.retiredb.info`).
    repository_info: dict[str, Any] | None = None
    started_at: str = ""
    finished_at: str = ""
    duration_seconds: float = 0.0

    def skip(self, reason: str, paths: Iterable[str]) -> None:
        """Record files that were not checked."""
        self.skipped.setdefault(reason, []).extend(paths)

    def skipped_count(self) -> int:
        """Return the number of files that were not checked."""
        return sum(len(paths) for paths in self.skipped.values())

    def tool_version(self) -> str | None:
        """Return the repository version text: its update date and SHA-256 prefix."""
        info = self.repository_info or {}
        sha = info.get("sha256")
        updated = info.get("updated_at")
        if not isinstance(sha, str) or not sha:
            return None
        day = updated[:10] if isinstance(updated, str) else "?"
        return f"jsrepository-v5 {day} sha256:{sha[:12]}"

    def libraries(self) -> list[dict[str, Any]]:
        """Return the detections as JSON-ready dicts (with the package URL)."""
        from kalkan.sca.manifests import pin_purl

        return [
            {**item.to_dict(), "purl": pin_purl("npm", item.npm_name, item.version)}
            for item in self.detections
        ]

    def skipped_files(self) -> dict[str, Any] | None:
        """Return ``skipped_files`` of the status file, or None when every file was checked."""
        count = self.skipped_count()
        if not count:
            return None
        paths = [path for items in self.skipped.values() for path in items]
        return {
            "count": count,
            "reasons": {reason: len(items) for reason, items in self.skipped.items()},
            "paths": paths[:MAX_LISTED_PATHS],
            "truncated": count > MAX_LISTED_PATHS,
        }

    def document(self) -> dict[str, Any]:
        """Return ``sca/vendored.json``."""
        repository = None
        if self.repository is not None or self.repository_info is not None:
            info = self.repository_info or {}
            repository = {
                key: info.get(key)
                for key in ("source", "sha256", "updated_at", "license", "upstream")
                if info.get(key) is not None
            }
            if self.repository is not None:
                repository["stats"] = self.repository.stats()
        return {
            "schema_version": SCHEMA_VERSION,
            "engine": ENGINE,
            "status": self.status,
            "message": self.message,
            "repository": repository,
            "files_total": self.files_total,
            "files_checked": self.files_checked,
            "libraries": self.libraries(),
            "skipped_files": {reason: list(paths) for reason, paths in self.skipped.items()},
            "warnings": list(self.warnings),
        }

    def status_document(self) -> dict[str, Any]:
        """Return ``sca/retirejs.status.json`` (the shape of the adapter status files)."""
        status: dict[str, Any] = {
            "engine": ENGINE,
            "status": self.status,
            "message": self.message,
            "duration_seconds": round(self.duration_seconds, 3),
            "exit_code": None,
            "tool_version": self.tool_version(),
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "command": [],
            "output": VENDORED_FILE,
            "candidates": None,
            "files_checked": self.files_checked,
            "libraries": len(self.detections),
        }
        skipped = self.skipped_files()
        if skipped is not None:
            status["skipped_files"] = skipped
        return status


def write_outputs(run_dir: str | os.PathLike[str], result: VendoredScan) -> None:
    """Write ``sca/vendored.json`` and ``sca/retirejs.status.json`` atomically."""
    directory = Path(run_dir)
    (directory / "sca").mkdir(parents=True, exist_ok=True)
    atomic_write_json(directory / VENDORED_FILE, result.document())
    atomic_write_json(directory / STATUS_FILE, result.status_document())


# --- files ---------------------------------------------------------------------------------------


def _is_link(path: Path) -> bool:
    if path.is_symlink():
        return True
    isjunction = getattr(os.path, "isjunction", None)
    return bool(isjunction and isjunction(path))


def list_files(root: str | os.PathLike[str]) -> tuple[list[str], dict[str, list[str]]]:
    """Return the JavaScript files to check and the files that are not checked (by reason).

    Paths are target-relative POSIX paths in sorted order (module docstring, item 1).
    """
    base_root = Path(root)
    found: list[str] = []
    skipped: dict[str, list[str]] = {}
    for current, dirs, files in os.walk(base_root, followlinks=False):
        base = Path(current)
        dirs[:] = sorted(
            name for name in dirs if name.casefold() not in SKIP_DIRS and not _is_link(base / name)
        )
        for name in sorted(files):
            if not name.casefold().endswith(EXTENSIONS):
                continue
            path = base / name
            relative = path.relative_to(base_root).as_posix()
            try:
                info = os.lstat(path)
            except OSError:
                skipped.setdefault(REASON_UNREADABLE, []).append(relative)
                continue
            attributes = getattr(info, "st_file_attributes", 0) or 0
            if not stat.S_ISREG(info.st_mode) or attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
                skipped.setdefault(REASON_LINK, []).append(relative)
            elif info.st_size > MAX_FILE_BYTES:
                skipped.setdefault(REASON_LARGE, []).append(relative)
            else:
                found.append(relative)
    return sorted(found), skipped


def check_file(
    repository: retirejs.Repository, root: Path, relative: str, max_bytes: int = MAX_FILE_BYTES
) -> tuple[list[retirejs.Detection], str | None]:
    """Return the detections of one file and the reason when it could not be read.

    The name and the path first; the content only when they give nothing
    (``retire.scanJsFile``).
    """
    found = retirejs.detect_name(repository, relative)
    if not found:
        try:
            data = read_bounded(root / relative, max_bytes)
        except UnsafeInputError as exc:
            return [], REASON_LARGE if "exceeds" in str(exc) else REASON_UNREADABLE
        found = retirejs.detect_content(repository, relative, data)
    return found[:MAX_DETECTIONS_PER_FILE], None


# --- the child process ---------------------------------------------------------------------------


def worker_main(argv: Sequence[str]) -> int:
    """Check the files of a job file and report on stdout (the child of :func:`scan`).

    The job file (``argv[0]``) holds ``repository``, ``root``, ``files`` and ``max_bytes``.
    Each stdout line is one ASCII JSON object: ``{"ready": stats}`` or ``{"fatal": reason}``,
    then per file ``{"start": i}`` and ``{"done": i, "detections": [...], "skipped": reason}``,
    and ``{"end": true}``.
    """
    out = sys.stdout.buffer

    def emit(message: Mapping[str, Any]) -> None:
        line = json.dumps(message, ensure_ascii=True, separators=(",", ":"))
        out.write(line.encode("ascii") + b"\n")
        out.flush()

    try:
        job = json.loads(Path(argv[0]).read_text(encoding="utf-8"))
        repository = retirejs.load_repository(Path(job["repository"]))
        root = Path(job["root"])
        files = [str(item) for item in job["files"]]
        max_bytes = int(job.get("max_bytes") or MAX_FILE_BYTES)
    except (IndexError, KeyError, TypeError, OSError, ValueError, ValidationError) as exc:
        emit({"fatal": " ".join(str(exc).split())[:300] or type(exc).__name__})
        return 3
    emit({"ready": repository.stats()})
    for index, relative in enumerate(files):
        emit({"start": index})
        try:
            found, reason = check_file(repository, root, relative, max_bytes)
        except (OSError, ValueError, RecursionError, MemoryError) as exc:
            found, reason = [], f"check failed: {type(exc).__name__}"
        emit({"done": index, "detections": [item.to_dict() for item in found], "skipped": reason})
    emit({"end": True})
    return 0


def _package_root() -> str:
    import kalkan

    return str(Path(kalkan.__file__).resolve().parent.parent)


def _pump(stream: IO[bytes], lines: queue.Queue[bytes | None]) -> None:
    try:
        for raw in iter(stream.readline, b""):
            lines.put(raw)
    finally:
        lines.put(None)


@dataclass
class _Run:
    """What one child process reported."""

    done: dict[int, tuple[list[retirejs.Detection], str | None]] = field(default_factory=dict)
    stop: str = "end"  # end | file-timeout | total-timeout | startup-timeout | crashed | fatal
    current: int | None = None
    detail: str = ""


def _run_child(
    files: Sequence[str],
    *,
    root: Path,
    repository_path: Path,
    work_dir: Path,
    file_seconds: float,
    deadline: float | None,
    python: str,
) -> _Run:
    """Start one child process for ``files`` and follow its reports (module docstring, 2)."""
    work_dir.mkdir(parents=True, exist_ok=True)
    job = work_dir / "job.json"
    job.write_text(
        json.dumps(
            {
                "repository": str(repository_path),
                "root": str(root),
                "files": list(files),
                "max_bytes": MAX_FILE_BYTES,
            }
        ),
        encoding="utf-8",
    )
    argv = [python, "-I", "-c", _BOOT, _package_root(), str(job)]
    options: dict[str, Any] = {}
    if os.name != "nt":
        options["start_new_session"] = True
    run = _Run()
    with open(work_dir / "child.stderr.txt", "wb") as stderr:
        try:
            process = subprocess.Popen(
                argv,
                shell=False,
                cwd=str(work_dir),
                env=minimal_env(),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=stderr,
                **options,
            )
        except (OSError, ValueError) as exc:
            run.stop, run.detail = "fatal", f"cannot start the detection process: {exc}"
            return run
        lines: queue.Queue[bytes | None] = queue.Queue()
        assert process.stdout is not None
        reader = threading.Thread(target=_pump, args=(process.stdout, lines), daemon=True)
        reader.start()
        started = time.monotonic()
        try:
            _follow(run, lines, started, file_seconds, deadline)
        finally:
            if run.stop != "end":
                kill_process_tree(process)
            else:
                try:
                    process.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    kill_process_tree(process)
            process.stdout.close()
            reader.join(timeout=5)
    if run.stop == "crashed" and not run.detail:
        run.detail = _last_line(work_dir / "child.stderr.txt")
    return run


def _follow(
    run: _Run,
    lines: queue.Queue[bytes | None],
    started: float,
    file_seconds: float,
    deadline: float | None,
) -> None:
    """Read the reports of the child until it ends or a limit stops it."""
    ready = False
    file_started = started
    while True:
        now = time.monotonic()
        # Before "ready": the start-up limit. After it: the file limit, which also bounds the
        # time between two files. Always: the limit of the whole scan.
        limits = [
            (started + STARTUP_SECONDS - now, "startup-timeout")
            if not ready
            else (file_started + file_seconds - now, "file-timeout")
        ]
        if deadline is not None:
            limits.append((deadline - now, "total-timeout"))
        wait, reason = min(limits)
        try:
            raw = lines.get(timeout=max(wait, 0.0))
        except queue.Empty:
            run.stop = reason
            return
        if raw is None:
            run.stop = "crashed"
            return
        try:
            message = json.loads(raw.decode("ascii"))
        except (UnicodeDecodeError, ValueError):
            continue
        if not isinstance(message, dict):
            continue
        if "fatal" in message:
            run.stop, run.detail = "fatal", str(message["fatal"])[:300]
            return
        if "ready" in message:
            ready = True
            file_started = time.monotonic()
        elif "start" in message and isinstance(message["start"], int):
            run.current = message["start"]
            file_started = time.monotonic()
        elif "done" in message and isinstance(message["done"], int):
            found: list[retirejs.Detection] = []
            for item in message.get("detections") or []:
                try:
                    found.append(retirejs.Detection.from_dict(item))
                except (ValueError, AttributeError):
                    continue
            skipped = message.get("skipped")
            run.done[message["done"]] = (found, skipped if isinstance(skipped, str) else None)
            run.current = None
            file_started = time.monotonic()
        elif message.get("end") is True:
            run.stop = "end"
            return


def _last_line(path: Path) -> str:
    try:
        tail = path.read_bytes()[-4096:].decode("utf-8", errors="replace")
    except OSError:
        return ""
    lines = [line.strip() for line in tail.splitlines() if line.strip()]
    return lines[-1][:300] if lines else ""


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


# --- the scan ------------------------------------------------------------------------------------


def scan(
    target_dir: str | os.PathLike[str],
    repository_path: str | os.PathLike[str] | None,
    *,
    work_dir: str | os.PathLike[str],
    file_seconds: float = FILE_SECONDS,
    total_seconds: float | None = DEFAULT_TOTAL_SECONDS,
    repository_info: Mapping[str, Any] | None = None,
    python: str | None = None,
) -> VendoredScan:
    """Find the vendored JavaScript libraries of ``target_dir`` (module docstring).

    ``repository_path`` is the local repository file (None when it is missing). ``work_dir``
    is a run-owned folder for the job file and the child's stderr; it is removed afterwards.
    ``python`` replaces :data:`sys.executable` (tests). The function never raises for target
    content or a broken repository: the result carries the status and the message.
    """
    clock = time.monotonic()
    result = VendoredScan(started_at=_now())
    result.repository_info = dict(repository_info) if repository_info else None
    root = Path(target_dir)
    try:
        files, listed = _files(root)
        if not files and not listed:
            result.status, result.message = "skipped", NO_FILES
        elif repository_path is None or not Path(repository_path).is_file():
            # The database gap names the cause; the files are not listed one by one.
            result.files_total = len(files) + sum(len(paths) for paths in listed.values())
            result.status = "skipped"
            result.message = (
                f"{NO_REPOSITORY}; {result.files_total} JavaScript files were not checked for "
                "vendored libraries"
            )
        else:
            for reason, paths in listed.items():
                result.skip(reason, paths)
            result.files_total = len(files) + result.skipped_count()
            if listed.get(REASON_TOO_MANY):
                result.warnings.append(
                    f"{result.files_total} JavaScript files; only the first {MAX_FILES} were "
                    "checked for vendored libraries"
                )
            limits = _Limits(file_seconds, total_seconds, clock)
            _check(result, root, Path(repository_path), files, Path(work_dir), limits, python)
    finally:
        result.finished_at = _now()
        result.duration_seconds = time.monotonic() - clock
        _remove(Path(work_dir))
    return result


@dataclass(frozen=True)
class _Limits:
    file_seconds: float
    total_seconds: float | None
    start: float

    def deadline(self) -> float | None:
        if self.total_seconds is None:
            return None
        return self.start + max(float(self.total_seconds), 0.0)


def _files(root: Path) -> tuple[list[str], dict[str, list[str]]]:
    files, listed = list_files(root)
    if len(files) > MAX_FILES:
        listed[REASON_TOO_MANY] = files[MAX_FILES:]
        files = files[:MAX_FILES]
    return files, listed


def _check(
    result: VendoredScan,
    root: Path,
    repository_path: Path,
    files: list[str],
    work_dir: Path,
    limits: _Limits,
    python: str | None,
) -> None:
    try:
        result.repository = retirejs.load_repository(repository_path)
    except ValidationError as exc:
        result.status, result.message = "failed", f"the RetireJS repository cannot be used: {exc}"
        return
    if result.repository.skipped:
        result.warnings.append(
            f"{len(result.repository.skipped)} RetireJS extractors cannot run in Python and "
            "were skipped"
        )
    executable = python or sys.executable
    if not files:
        result.status = "ok"
        result.message = _summary(result)
        return
    if not executable:
        result.status, result.message = "failed", "no Python interpreter for the check"
        result.skip("not checked: no Python interpreter", files)
        return
    file_seconds = limits.file_seconds
    pending = list(range(len(files)))
    timeouts = 0
    result.status = "ok"
    while pending:
        run = _run_child(
            [files[index] for index in pending],
            root=root,
            repository_path=repository_path,
            work_dir=work_dir,
            file_seconds=file_seconds,
            deadline=limits.deadline(),
            python=executable,
        )
        for local, (found, reason) in sorted(run.done.items()):
            relative = files[pending[local]]
            if reason is not None:
                result.skip(reason, [relative])
            else:
                result.files_checked += 1
                result.detections.extend(found)
        current = pending[run.current] if run.current is not None else None
        finished = {pending[local] for local in run.done}
        if current is not None:
            finished.add(current)
        remaining = [index for index in pending if index not in finished]
        if run.stop == "end":
            pending = remaining
            if pending:  # an end without a report for every file: never loop on it
                result.skip(
                    "not checked: the detection process ended early", _paths(files, pending)
                )
            break
        if run.stop in ("file-timeout", "crashed") and current is not None:
            timeouts += 1
            if run.stop == "file-timeout":
                result.skip(f"timed out after {file_seconds:g} s", [files[current]])
            else:
                detail = f": {run.detail}" if run.detail else ""
                result.skip(f"the detection process stopped{detail}", [files[current]])
            if timeouts >= MAX_TIMEOUTS:
                result.skip(
                    f"not checked: {timeouts} files stopped the check", _paths(files, remaining)
                )
                result.warnings.append(
                    f"{timeouts} JavaScript files timed out or stopped the detection process; "
                    "the vendored library check stopped"
                )
                break
            pending = remaining
            continue
        if run.stop == "total-timeout":
            result.status = "timeout"
            if current is not None:
                result.skip(REASON_TOTAL, [files[current]])
            result.skip(REASON_TOTAL, _paths(files, remaining))
            break
        result.status = "failed"
        result.message = run.detail or f"the detection process stopped ({run.stop})"
        lost = ([current] if current is not None else []) + remaining
        result.skip("not checked: the detection process failed", _paths(files, lost))
        break
    if not result.message:
        result.message = _summary(result)


def _paths(files: Sequence[str], indexes: Iterable[int]) -> list[str]:
    return [files[index] for index in indexes]


def _summary(result: VendoredScan) -> str:
    libraries = len({(item.library, item.version) for item in result.detections})
    files = len({item.path for item in result.detections})
    text = (
        f"JavaScript files checked: {result.files_checked}; vendored library versions: "
        f"{libraries} (files: {files})"
    )
    if result.skipped_count():
        text += f"; files not checked: {result.skipped_count()}"
    if result.status == "timeout":
        text = "the time limit was used up; " + text
    return text


def _remove(folder: Path) -> None:
    if folder.is_dir() and not folder.is_symlink():
        shutil.rmtree(folder, ignore_errors=True)
    parent = folder.parent
    if parent.name == ".work":
        try:
            parent.rmdir()
        except OSError:
            pass


# --- matching ------------------------------------------------------------------------------------


def vendored_entries(detections: Iterable[retirejs.Detection]) -> list[dict[str, Any]]:
    """Return the ``vendored`` record field: ``{file, line, library, version, extractor}``."""
    entries: list[dict[str, Any]] = []
    for item in detections:
        entry = {
            "file": item.path,
            "line": item.line,
            "library": item.library,
            "version": item.version,
            "extractor": item.extractor,
        }
        if entry not in entries:
            entries.append(entry)
    return entries


def pin_locations(
    detections: Iterable[retirejs.Detection],
) -> dict[tuple[str, str, str], list[retirejs.Detection]]:
    """Map ``(ecosystem, package key, version key)`` to the detections of that npm package."""
    found: dict[tuple[str, str, str], list[retirejs.Detection]] = {}
    for item in detections:
        key = ("npm", package_key("npm", item.npm_name), version_key("npm", item.version))
        found.setdefault(key, []).append(item)
    return found


def retire_records(
    detections: Iterable[retirejs.Detection], repository: retirejs.Repository | None
) -> list[dict[str, Any]]:
    """Return one record per (detection, affecting repository vulnerability).

    The records use the engine :data:`ENGINE`, the npm package of the library, the vendored
    file as location, ``pin_source: "vendored"``, the ``vendored`` entry and the repository
    info links as ``references``. ``below`` is the fixed version unless it is the retire
    placeholder of an unknown fix.
    """
    if repository is None:
        return []
    records: list[dict[str, Any]] = []
    for item in detections:
        library = repository.libraries.get(item.library)
        if library is None:
            continue
        for vulnerability in library.affecting(item.version):
            fixed = vulnerability.fixed_version()
            record = new_record(
                ecosystem="npm",
                package=item.npm_name,
                version=item.version,
                ids=vulnerability.ids,
                summary=vulnerability.summary,
                label=vulnerability.severity,
                cwe=vulnerability.cwe,
                fixed_versions=[fixed] if fixed else [],
                locations=[item.path],
                engine=ENGINE,
                vulnerable_ranges=[vulnerability.range_text()],
                fallback_id=vulnerability.ids[0],
            )
            record["pin_source"] = "vendored"
            record["vendored"] = vendored_entries([item])
            if vulnerability.info:
                record["references"] = list(vulnerability.info)
            records.append(record)
    return records
