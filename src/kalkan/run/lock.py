# SPDX-License-Identifier: MIT
"""Short-lived mutation lock ``runs/<run-id>/run.lock`` (docs/ENGINE-SPEC.md, section 11).

:func:`run_lock` wraps every read-modify-write of the run state. It creates ``run.lock`` with
``os.open(O_CREAT | O_EXCL)`` and writes ``{pid, host, created_at, token}`` as JSON. The
``token`` lets the holder remove only its own lock. Other processes retry with a short sleep
until the timeout, then get :class:`~kalkan.errors.StateError`. The lock is not re-entrant: a
process that already holds it waits for itself and times out. Keep the locked block short.

Stale rule: a lock older than 120 seconds is stale when its holder PID is not alive on this
host, or when it comes from another host. A lock file without readable content counts as a
lock of an unknown holder; its age comes from the file modification time.

Only one process breaks a stale lock at a time: it first creates the guard file
``run.lock.break`` (exclusive create), checks the lock again, removes it and removes the guard.
A guard older than 10 seconds is left over from a crash and is removed.

Liveness: :func:`pid_alive` uses ``OpenProcess`` and ``GetExitCodeProcess`` through ctypes on
Windows (``os.kill(pid, 0)`` terminates the process there) and ``os.kill(pid, 0)`` on Linux and
macOS.
"""

from __future__ import annotations

import contextlib
import errno
import functools
import json
import os
import secrets
import socket
import time
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Final

from kalkan.errors import StateError, UnsafeInputError
from kalkan.run.ids import format_ts, parse_ts, utc_now
from kalkan.util.safe_io import read_bounded

__all__ = [
    "DEFAULT_TIMEOUT_SECONDS",
    "LOCK_NAME",
    "STALE_AFTER_SECONDS",
    "LockInfo",
    "hostname",
    "is_stale",
    "pid_alive",
    "read_lock_info",
    "run_lock",
]

LOCK_NAME: Final = "run.lock"
STALE_AFTER_SECONDS: Final = 120.0
DEFAULT_TIMEOUT_SECONDS: Final = 30.0

_GUARD_SUFFIX: Final = ".break"
_GUARD_STALE_SECONDS: Final = 10.0
_POLL_SECONDS: Final = 0.05
_LOCK_MAX_BYTES: Final = 4096
_RELEASE_ATTEMPTS: Final = 40
_RELEASE_DELAY_SECONDS: Final = 0.025
_CREATE_FLAGS: Final = (
    os.O_WRONLY
    | os.O_CREAT
    | os.O_EXCL
    | getattr(os, "O_BINARY", 0)
    | getattr(os, "O_NOINHERIT", 0)
    | getattr(os, "O_CLOEXEC", 0)
)

# Module attribute so that tests can exercise both liveness paths.
_IS_WINDOWS = os.name == "nt"

# Windows API constants.
_PROCESS_QUERY_LIMITED_INFORMATION: Final = 0x1000
_STILL_ACTIVE: Final = 259
_ERROR_ACCESS_DENIED: Final = 5


@functools.cache
def hostname() -> str:
    """Return the host name recorded in lock files."""
    return socket.gethostname()


# ---------------------------------------------------------------------------------------------
# Process liveness


@functools.cache
def _kernel32() -> Any:  # pragma: no cover - Windows only
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.GetExitCodeProcess.argtypes = (wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD))
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    return kernel32


def _pid_alive_windows(pid: int) -> bool:  # pragma: no cover - Windows only
    import ctypes
    from ctypes import wintypes

    kernel32 = _kernel32()
    handle = kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        # Access denied: the process exists but belongs to another user. Any other error
        # (normally ERROR_INVALID_PARAMETER) means that no such process exists.
        return ctypes.get_last_error() == _ERROR_ACCESS_DENIED
    try:
        code = wintypes.DWORD()
        if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
            return True  # cannot tell: keep the lock
        return code.value == _STILL_ACTIVE
    finally:
        kernel32.CloseHandle(handle)


def _pid_alive_posix(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError as exc:
        return exc.errno == errno.EPERM
    return True


def pid_alive(pid: int) -> bool:
    """Return True when process ``pid`` runs on this host.

    Never calls ``os.kill`` on Windows, where ``os.kill(pid, 0)`` terminates the process. A
    process that exited with code 259 (``STILL_ACTIVE``) looks alive on Windows.
    """
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        return False
    if pid == os.getpid():
        return True
    if _IS_WINDOWS:
        return _pid_alive_windows(pid)
    return _pid_alive_posix(pid)


# ---------------------------------------------------------------------------------------------
# Lock file content


@dataclass(frozen=True)
class LockInfo:
    """The content of a lock file. Fields are None when the content is missing or malformed."""

    pid: int | None
    host: str | None
    created_at: datetime | None
    token: str | None
    modified_at: float

    def age_seconds(self, now: datetime | None = None) -> float:
        """Return the age of the lock: from ``created_at``, else from the file time."""
        moment = now if now is not None else utc_now()
        if self.created_at is not None:
            return (moment - self.created_at).total_seconds()
        return moment.timestamp() - self.modified_at


def read_lock_info(path: str | os.PathLike[str]) -> LockInfo | None:
    """Return the content of the lock file ``path``, or None when it does not exist."""
    try:
        modified_at = os.lstat(path).st_mtime
    except FileNotFoundError:
        return None
    except OSError:
        return LockInfo(None, None, None, None, time.time())
    data: Any = None
    with contextlib.suppress(UnsafeInputError, ValueError):
        data = json.loads(read_bounded(path, _LOCK_MAX_BYTES).decode("utf-8"))
    if not isinstance(data, dict):
        return LockInfo(None, None, None, None, modified_at)
    pid = data.get("pid")
    host = data.get("host")
    token = data.get("token")
    created: datetime | None = None
    with contextlib.suppress(ValueError):
        created = parse_ts(data.get("created_at"))
    return LockInfo(
        pid if isinstance(pid, int) and not isinstance(pid, bool) else None,
        host if isinstance(host, str) else None,
        created,
        token if isinstance(token, str) else None,
        modified_at,
    )


def is_stale(info: LockInfo, now: datetime | None = None) -> bool:
    """Apply the stale rule (module docstring) to the lock ``info``."""
    if info.age_seconds(now) <= STALE_AFTER_SECONDS:
        return False
    if info.host == hostname() and info.pid is not None:
        return not pid_alive(info.pid)
    return True


# ---------------------------------------------------------------------------------------------
# Lock and unlock


def _unlink(path: Path) -> bool:
    """Remove ``path``; retry while Windows reports the file as in use. False on failure."""
    for attempt in range(_RELEASE_ATTEMPTS):
        try:
            os.unlink(path)
            return True
        except FileNotFoundError:
            return True
        except PermissionError:
            # Another process reads the file at this moment (Windows), or it is being deleted.
            if attempt + 1 == _RELEASE_ATTEMPTS:
                return False
            time.sleep(_RELEASE_DELAY_SECONDS)
        except OSError:
            return False
    return False  # pragma: no cover - the loop always returns


def _try_create(path: Path, token: str) -> bool:
    try:
        descriptor = os.open(path, _CREATE_FLAGS, 0o600)
    except FileExistsError:
        return False
    except PermissionError:
        if _IS_WINDOWS:
            # The old lock file is still being deleted (delete pending). Try again soon.
            return False
        raise StateError("cannot create the run lock: permission denied") from None
    except FileNotFoundError:
        raise StateError("cannot create the run lock: the run folder does not exist") from None
    except OSError as exc:
        raise StateError("cannot create the run lock") from exc
    content = {"pid": os.getpid(), "host": hostname(), "created_at": format_ts(), "token": token}
    try:
        os.write(descriptor, (json.dumps(content) + "\n").encode("utf-8"))
    finally:
        os.close(descriptor)
    return True


def _remove_old_guard(guard: Path) -> None:
    with contextlib.suppress(OSError):
        if time.time() - os.lstat(guard).st_mtime > _GUARD_STALE_SECONDS:
            _unlink(guard)


def _break_if_stale(path: Path) -> bool:
    """Remove the lock ``path`` when it is stale. Return True when the caller can try again."""
    info = read_lock_info(path)
    if info is None:
        return True
    if not is_stale(info):
        return False
    guard = path.with_name(path.name + _GUARD_SUFFIX)
    try:
        descriptor = os.open(guard, _CREATE_FLAGS, 0o600)
    except (FileExistsError, PermissionError):
        _remove_old_guard(guard)
        return False
    except OSError:
        return False
    os.close(descriptor)
    try:
        # Check again: another process may have broken the lock and taken a new one.
        info = read_lock_info(path)
        if info is None:
            return True
        if not is_stale(info):
            return False
        return _unlink(path)
    finally:
        _unlink(guard)


def _busy_message(path: Path) -> str:
    info = read_lock_info(path)
    if info is None:
        return "the run lock could not be created in time (access denied). Try again."
    holder = ""
    if info is not None and info.pid is not None:
        holder = f" (pid {info.pid}"
        if info.host:
            holder += f" on {json.dumps(info.host, ensure_ascii=True)}"
        holder += ")"
    return (
        f"the run is locked by another kalkan process{holder}. Try again. If no kalkan process "
        f"is running, delete the file {path.as_posix()}"
    )


def _release(path: Path, token: str) -> None:
    info = read_lock_info(path)
    if info is None:
        return
    if info.token is not None and info.token != token:
        return  # our lock was broken as stale and another process holds a new one
    _unlink(path)


@contextlib.contextmanager
def run_lock(
    run_dir: str | os.PathLike[str], timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
) -> Iterator[None]:
    """Hold ``<run_dir>/run.lock`` for the duration of the ``with`` block.

    Retries every 50 ms. Raises :class:`~kalkan.errors.StateError` when the lock stays busy for
    ``timeout_seconds`` or when the run folder does not exist. The lock file is removed in a
    ``finally`` clause.
    """
    path = Path(run_dir) / LOCK_NAME
    token = secrets.token_hex(8)
    deadline = time.monotonic() + max(0.0, float(timeout_seconds))
    while True:
        if _try_create(path, token):
            break
        if _break_if_stale(path) and _try_create(path, token):
            break
        if time.monotonic() >= deadline:
            raise StateError(_busy_message(path))
        time.sleep(_POLL_SECONDS)
    try:
        yield
    finally:
        _release(path, token)
