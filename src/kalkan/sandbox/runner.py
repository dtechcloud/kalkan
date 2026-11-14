# SPDX-License-Identifier: MIT
"""Isolated container runner for finding verification (docs/ENGINE-SPEC.md section 23).

The engine passes a harness that an audit subagent produced (``harness.json``: files, a
command, a base image from the allowlist, a success pattern). :func:`run_poc` writes the files
into the run folder, starts one container under a fixed isolation profile, captures its output,
compares it with the success pattern and copies the result files into the run evidence folder.
It returns a ``poc.json`` record (docs/ENGINE-SPEC.md section 18) for :mod:`kalkan.findings.merge`.

Isolation profile (unit level): no network, read-only root filesystem, a non-root user, dropped
Linux capabilities, ``no-new-privileges``, a CPU, memory and PID limit, a wall-clock timeout, the
target mounted read-only and only ``/out`` and ``/tmp`` writable. The engine never pulls an image
during an audit: a missing image is reported, not fetched (``kalkan sandbox pull``).

Host resources: the engine reads the container output as a stream and keeps at most
:data:`OUTPUT_CAP_BYTES` of each stream (the rest is read and dropped, so a noisy harness cannot
fill the engine memory). ``/out`` is a host folder, so a watchdog checks its size and entry count
every :data:`WATCH_INTERVAL_SECONDS` and stops the container above :data:`OUT_MAX_BYTES` or
:data:`OUT_MAX_FILES` (blocker ``sandbox_output_limit``); the raw folder is then deleted. The
container output, the observation and the evidence files are redacted
(:mod:`kalkan.sandbox.redact`) before the engine writes them.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from kalkan.matchers.safety import MAX_LINE_LENGTH, regex_safety_error
from kalkan.resources import home
from kalkan.sandbox.evidence import promote
from kalkan.sandbox.redact import redact, redact_file
from kalkan.util.paths import is_safe_relative_path

__all__ = ["allowed_images", "docker_available", "docker_path", "run_poc"]

#: Set by the test suite to force :func:`docker_available` to False, so the generic tests never
#: start a container. Production never sets it.
FORCE_UNAVAILABLE_ENV: Final = "KALKAN_SANDBOX_FORCE_UNAVAILABLE"
#: Override the docker executable (tests, an unusual install).
DOCKER_ENV: Final = "KALKAN_DOCKER"

UNIT_TIMEOUT_SECONDS: Final = 180
ENGINE_TIMEOUT_SECONDS: Final = 25
OUTPUT_CAP_CHARS: Final = 256 * 1024
#: Bytes kept of each container output stream; the rest is read and dropped.
OUTPUT_CAP_BYTES: Final = 256 * 1024
#: Limits of the host folder behind ``/out``: the watchdog stops the container above them.
OUT_MAX_BYTES: Final = 64 * 1024 * 1024
OUT_MAX_FILES: Final = 1000
WATCH_INTERVAL_SECONDS: Final = 0.2
OBSERVATION_CAP_CHARS: Final = 400
_MOUNT_TARGET: Final = "/target"
_MOUNT_POC: Final = "/poc"
_MOUNT_OUT: Final = "/out"

_IMAGES_FILE: Final = Path(__file__).with_name("images.json")
#: Extra environment per base image prefix. The .NET SDK keeps its caches in ``/tmp``, never
#: sends telemetry, never starts a build server and never checks for workload updates. ``/tmp``
#: is ``noexec``, so a C# harness runs its DLL with ``dotnet`` (``-p:UseAppHost=false``).
_IMAGE_ENV: Final = {
    "mcr.microsoft.com/dotnet/": (
        "DOTNET_CLI_HOME=/tmp",
        "DOTNET_NOLOGO=1",
        "DOTNET_CLI_TELEMETRY_OPTOUT=1",
        "DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1",
        "DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE=1",
        "DOTNET_CLI_USE_MSBUILD_SERVER=0",
        "MSBUILDDISABLENODEREUSE=1",
        "NUGET_PACKAGES=/tmp/.nuget",
    ),
}


def unit_limits() -> dict[str, int]:
    """Return the unit-level limits that a harness must fit (the ``poc_build`` task input)."""
    return {
        "cpus": 1,
        "memory_mb": 512,
        "pids": 256,
        "timeout_seconds": UNIT_TIMEOUT_SECONDS,
        "tmp_mb": 64,
        "out_mb": OUT_MAX_BYTES // (1024 * 1024),
        "output_kb_per_stream": OUTPUT_CAP_BYTES // 1024,
    }


def image_env(base_image: str) -> list[str]:
    """Return the extra ``--env`` values of ``base_image`` (:data:`_IMAGE_ENV`)."""
    for prefix, values in _IMAGE_ENV.items():
        if base_image.startswith(prefix):
            return list(values)
    return []


@dataclass
class _Capture:
    exit_code: int | None
    stdout: str
    stderr: str
    timed_out: bool = False
    error: str | None = None
    truncated: bool = False
    out_limit: str | None = None


def allowed_images() -> list[str]:
    """Return the base image allowlist (``images.json``)."""
    data = json.loads(_IMAGES_FILE.read_text(encoding="utf-8"))
    images = data.get("images")
    return [str(name) for name in images] if isinstance(images, list) else []


def docker_path() -> Path | None:
    """Return the docker executable, from :data:`DOCKER_ENV` or PATH, or None."""
    override = os.environ.get(DOCKER_ENV)
    if override:
        candidate = Path(override)
        return candidate if candidate.exists() else None
    found = shutil.which("docker")
    return Path(found) if found else None


def _pin_file() -> Path:
    return home() / ".tools" / "sandbox" / "pinned.json"


def _pinned_ref(base_image: str) -> str:
    """Return the pinned digest reference of ``base_image`` (``kalkan sandbox pull``), else the
    tag. The digest form ``name@sha256:...`` is reproducible; the tag is a fallback."""
    try:
        pinned = json.loads(_pin_file().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return base_image
    ref = pinned.get(base_image) if isinstance(pinned, dict) else None
    return ref if isinstance(ref, str) and ref else base_image


def _capture(argv: list[str], *, timeout: int, cleanup: str | None = None) -> _Capture:
    """Run ``argv`` without a shell, capture its output, enforce ``timeout``."""
    try:
        proc = subprocess.run(
            argv,
            shell=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        return _Capture(None, "", "", error=f"docker could not start: {exc}")
    except subprocess.TimeoutExpired as exc:
        if cleanup:
            _force_remove(cleanup)
        return _Capture(None, _text(exc.stdout), _text(exc.stderr), timed_out=True)
    return _Capture(proc.returncode, _text(proc.stdout), _text(proc.stderr))


def _text(raw: object) -> str:
    if not isinstance(raw, (bytes, bytearray)):
        return ""
    return bytes(raw).decode("utf-8", errors="replace")[:OUTPUT_CAP_CHARS]


def _force_remove(name: str) -> None:
    docker = docker_path()
    if docker is None:
        return
    with_timeout = {"timeout": 30, "check": False, "shell": False}
    for args in (["kill", name], ["rm", "-f", name]):
        try:
            subprocess.run(
                [str(docker), *args],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                **with_timeout,
            )
        except (OSError, subprocess.SubprocessError):
            pass


class _Drain(threading.Thread):
    """Read a stream to its end and keep only its first ``cap`` bytes."""

    def __init__(self, stream: Any, cap: int) -> None:
        super().__init__(daemon=True)
        self._stream = stream
        self._cap = cap
        self.kept = bytearray()
        self.dropped = 0

    def run(self) -> None:
        try:
            while chunk := self._stream.read1(65536):
                room = max(0, self._cap - len(self.kept))
                self.kept += chunk[:room]
                self.dropped += max(0, len(chunk) - room)
        except (OSError, ValueError):
            pass


def out_usage(folder: Path, max_bytes: int, max_files: int) -> str | None:
    """Return why ``folder`` is over a limit (bytes or entries), else None.

    The walk never follows a link and stops as soon as a limit is passed.
    """
    total, count = 0, 0
    pending = [folder]
    while pending:
        try:
            entries = list(os.scandir(pending.pop()))
        except OSError:
            continue
        for entry in entries:
            count += 1
            if count > max_files:
                return f"more than {max_files} files"
            try:
                if entry.is_dir(follow_symlinks=False):
                    pending.append(Path(entry.path))
                else:
                    total += entry.stat(follow_symlinks=False).st_size
            except OSError:
                continue
            if total > max_bytes:
                return f"more than {max_bytes // (1024 * 1024)} MiB"
    return None


def _run_bounded(argv: list[str], *, timeout: int, name: str, out_dir: Path) -> _Capture:
    """Run the container, stream its output with a cap and watch ``out_dir``."""
    try:
        proc = subprocess.Popen(
            argv,
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as exc:
        return _Capture(None, "", "", error=f"docker could not start: {exc}")
    drains = [_Drain(proc.stdout, OUTPUT_CAP_BYTES), _Drain(proc.stderr, OUTPUT_CAP_BYTES)]
    for drain in drains:
        drain.start()
    deadline = time.monotonic() + timeout
    timed_out, out_limit = False, None
    while proc.poll() is None:
        if time.monotonic() > deadline:
            timed_out = True
        else:
            out_limit = out_usage(out_dir, OUT_MAX_BYTES, OUT_MAX_FILES)
        if timed_out or out_limit:
            _force_remove(name)
            proc.kill()
            break
        time.sleep(WATCH_INTERVAL_SECONDS)
    try:
        proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        proc.kill()
    for drain in drains:
        drain.join(timeout=10)
    if out_limit is None and not timed_out:
        out_limit = out_usage(out_dir, OUT_MAX_BYTES, OUT_MAX_FILES)
    stdout, stderr = (bytes(drain.kept).decode("utf-8", errors="replace") for drain in drains)
    return _Capture(
        None if timed_out or out_limit else proc.returncode,
        stdout,
        stderr,
        timed_out=timed_out,
        truncated=any(drain.dropped for drain in drains),
        out_limit=out_limit,
    )


def docker_available() -> bool:
    """Return True when a docker client is on PATH and its engine answers."""
    if os.environ.get(FORCE_UNAVAILABLE_ENV):
        return False
    docker = docker_path()
    if docker is None:
        return False
    result = _capture(
        [str(docker), "version", "--format", "{{.Server.Version}}"],
        timeout=ENGINE_TIMEOUT_SECONDS,
    )
    return (
        result.error is None
        and not result.timed_out
        and result.exit_code == 0
        and bool(result.stdout.strip())
    )


def _image_present(docker: Path, ref: str) -> bool:
    result = _capture([str(docker), "image", "inspect", ref], timeout=ENGINE_TIMEOUT_SECONDS)
    return result.error is None and not result.timed_out and result.exit_code == 0


def _reset_dir(path: Path) -> None:
    if path.is_symlink():
        path.unlink()
    elif path.is_dir():
        shutil.rmtree(path, ignore_errors=True)
    path.mkdir(parents=True, exist_ok=True)


def _write_harness_files(poc_dir: Path, files: list[dict[str, Any]]) -> str | None:
    for item in files:
        rel = item.get("path")
        if not isinstance(rel, str) or not is_safe_relative_path(rel):
            return f"unsafe harness path: {rel!r}"
        target = poc_dir / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        content = item.get("content")
        target.write_text(content if isinstance(content, str) else "", encoding="utf-8")
    return None


def _result(
    finding_id: str,
    level: str,
    status: str,
    observed: str,
    *,
    artifacts: list[str] | None = None,
    blocker: str | None = None,
    run: dict[str, Any] | None = None,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "finding_id": finding_id,
        "level": level,
        "status": status,
        "observed_result": redact(observed),
        "artifacts": artifacts or [],
    }
    if blocker:
        record["blocker"] = blocker
    if run:
        record.update(run)
    return record


def success_pattern(text: object) -> tuple[re.Pattern[str] | None, str]:
    """Compile the ``success_regex`` of a harness, or return why it cannot be used.

    The pattern comes from an agent. It passes the checks of the matcher regexes
    (:func:`kalkan.matchers.safety.regex_safety_error`: no nested quantifiers, no
    backreferences, a bounded length) before it runs in the engine process; a plain
    ``re.compile`` let a crafted pattern backtrack without a bound (self-audit of 2026-11-13).
    """
    if not isinstance(text, str) or not text:
        return None, "The harness has no success pattern."
    error = regex_safety_error(text)
    if error:
        return None, f"The success pattern is not safe: {error}"
    try:
        return re.compile(text), ""
    except re.error as exc:
        return None, f"The success pattern is not a valid expression: {exc}"


def _match_line(pattern: re.Pattern[str], *texts: str) -> str | None:
    for text in texts:
        for line in text.splitlines():
            if len(line) <= MAX_LINE_LENGTH and pattern.search(line):
                return line.strip()[:OBSERVATION_CAP_CHARS]
    return None


def _fail_observation(stdout: str, stderr: str, exit_code: int | None) -> str:
    for text in (stdout, stderr):
        for line in text.splitlines():
            if "KALKAN_POC_FAIL" in line:
                return line.strip()[:OBSERVATION_CAP_CHARS]
    return f"The harness did not report success (exit code {exit_code}); see the evidence files."


def _save_logs(dest: Path, capture: _Capture, argv: list[str]) -> list[Path]:
    saved: list[Path] = []
    dest.mkdir(parents=True, exist_ok=True)
    entries = {
        "command.txt": " ".join(argv),
        "stdout.txt": redact(capture.stdout),
        "stderr.txt": redact(capture.stderr),
    }
    for name, body in entries.items():
        if not body:
            continue
        path = dest / name
        path.write_text(body, encoding="utf-8")
        saved.append(path)
    return saved


def _mount(source: Path, target: str, *, read_only: bool) -> str:
    spec = f"type=bind,source={source.resolve().as_posix()},target={target}"
    return spec + ",readonly" if read_only else spec


def _unit_argv(
    docker: Path,
    ref: str,
    name: str,
    target_dir: Path,
    poc_dir: Path,
    out_dir: Path,
    command: list[str],
    base_image: str = "",
) -> list[str]:
    extra = [part for value in image_env(base_image) for part in ("--env", value)]
    return [
        str(docker),
        "run",
        "--rm",
        "--name",
        name,
        "--network",
        "none",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,size=64m,mode=1777",
        "--user",
        "65534:65534",
        "--cpus",
        "1",
        "--memory",
        "512m",
        "--memory-swap",
        "512m",
        "--pids-limit",
        "256",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--env",
        "HOME=/tmp",
        "--env",
        "PYTHONDONTWRITEBYTECODE=1",
        *extra,
        "--mount",
        _mount(target_dir, _MOUNT_TARGET, read_only=True),
        "--mount",
        _mount(poc_dir, _MOUNT_POC, read_only=True),
        "--mount",
        _mount(out_dir, _MOUNT_OUT, read_only=False),
        "--workdir",
        _MOUNT_POC,
        ref,
        *command,
    ]


def _container_name(run_id: str, task_id: str) -> str:
    safe = re.sub(r"[^0-9A-Za-z_.-]", "-", f"{run_id}-{task_id}")
    return f"kalkan-poc-{safe}"[:120]


def run_poc(ctx: Any, task_id: str, harness: dict[str, Any]) -> dict[str, Any]:
    """Run one harness in an isolated container and return its ``poc.json`` record.

    The function never raises: any error becomes a ``blocked`` record, so the ``poc:run`` step
    always writes a result for the task.
    """
    finding_id = str(harness.get("finding_id") or "")
    level = harness.get("level") if harness.get("level") in ("unit", "app") else "unit"
    try:
        return _run_poc(ctx, task_id, harness, finding_id, level)
    except Exception as exc:  # fail closed: a blocked record, never a crashed step
        return _result(
            finding_id,
            level,
            "blocked",
            f"The verification sandbox stopped with an internal error: {exc}",
            blocker="sandbox_error",
        )


def _run_poc(
    ctx: Any, task_id: str, harness: dict[str, Any], finding_id: str, level: str
) -> dict[str, Any]:
    docker = docker_path()
    if docker is None or not docker_available():
        return _result(
            finding_id,
            level,
            "blocked",
            "The Docker engine did not answer, so the verification did not run.",
            blocker="sandbox_unavailable",
        )
    if level == "app":
        from kalkan.sandbox.app import run_app_poc  # noqa: PLC0415 - app imports this module

        return run_app_poc(ctx, task_id, harness, docker)
    base_image = harness.get("base_image")
    if base_image not in allowed_images():
        return _result(
            finding_id,
            "unit",
            "blocked",
            f"The base image {base_image!r} is not in the allowlist.",
            blocker="sandbox_image_not_allowed",
        )
    ref = _pinned_ref(base_image)
    if not _image_present(docker, ref):
        return _result(
            finding_id,
            "unit",
            "blocked",
            f"The base image {base_image} is not present. Run: kalkan sandbox pull {base_image}",
            blocker="sandbox_image_missing",
        )
    files = harness.get("files")
    command = harness.get("command")
    pattern_text = harness.get("success_regex")
    if not isinstance(files, list) or not isinstance(command, list) or not command:
        return _result(
            finding_id, "unit", "blocked", "The harness is incomplete.", blocker="sandbox_error"
        )
    pattern, problem = success_pattern(pattern_text)
    if pattern is None:
        return _result(finding_id, "unit", "blocked", problem, blocker="sandbox_error")

    poc_root = ctx.run_dir / "poc" / finding_id
    poc_files = poc_root / "poc"
    out_dir = poc_root / "out"
    _reset_dir(poc_files)
    _reset_dir(out_dir)
    unsafe = _write_harness_files(poc_files, files)
    if unsafe is not None:
        return _result(finding_id, "unit", "blocked", unsafe, blocker="sandbox_error")

    name = _container_name(str(ctx.run_id), task_id)
    argv = _unit_argv(
        docker,
        ref,
        name,
        ctx.target_dir,
        poc_files,
        out_dir,
        [str(part) for part in command],
        base_image,
    )
    started = datetime.now(UTC)
    clock = time.monotonic()
    capture = _run_bounded(argv, timeout=UNIT_TIMEOUT_SECONDS, name=name, out_dir=out_dir)
    run: dict[str, Any] = {
        "started_at": started.isoformat(timespec="seconds").replace("+00:00", "Z"),
        "duration_ms": int((time.monotonic() - clock) * 1000),
        "output_truncated": capture.truncated,
    }
    if capture.exit_code is not None:
        run["exit_code"] = capture.exit_code

    evidence_dir = ctx.run_dir / "evidence" / finding_id
    saved = _save_logs(evidence_dir, capture, argv)
    if capture.out_limit is None:
        promoted = promote(out_dir, evidence_dir)
        for path in promoted:
            redact_file(path)
        saved += promoted
    else:
        shutil.rmtree(out_dir, ignore_errors=True)
    artifacts = sorted(
        path.relative_to(ctx.run_dir).as_posix()
        for path in saved
        if is_safe_relative_path(path.relative_to(ctx.run_dir).as_posix())
    )

    if capture.error is not None:
        return _result(
            finding_id,
            "unit",
            "blocked",
            f"The container did not start: {capture.error}",
            artifacts=artifacts,
            blocker="sandbox_error",
        )
    if capture.timed_out:
        return _result(
            finding_id,
            "unit",
            "blocked",
            f"The harness did not finish within {UNIT_TIMEOUT_SECONDS} seconds.",
            artifacts=artifacts,
            blocker="sandbox_timeout",
            run=run,
        )
    if capture.out_limit is not None:
        return _result(
            finding_id,
            "unit",
            "blocked",
            f"The harness wrote {capture.out_limit} into /out, so the engine stopped it.",
            artifacts=artifacts,
            blocker="sandbox_output_limit",
            run=run,
        )
    matched = _match_line(pattern, capture.stdout, capture.stderr)
    if matched is not None:
        return _result(finding_id, "unit", "passed", matched, artifacts=artifacts, run=run)
    return _result(
        finding_id,
        "unit",
        "failed",
        _fail_observation(capture.stdout, capture.stderr, capture.exit_code),
        artifacts=artifacts,
        run=run,
    )
