# SPDX-License-Identifier: MIT
"""Platform keys for the tool manifest and small host helpers (docs/ENGINE-SPEC.md, section 12).

A platform key is ``<os>-<arch>``: ``windows-amd64``, ``windows-arm64``, ``linux-amd64``,
``linux-arm64``, ``darwin-amd64`` or ``darwin-arm64``.

The host helpers find executables on PATH (never in the current directory) and run processes
with ``shell=False`` and an explicit timeout.
"""

from __future__ import annotations

import os
import platform as _platform
import subprocess
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

from kalkan.errors import ToolError

PLATFORMS: tuple[str, ...] = (
    "windows-amd64",
    "windows-arm64",
    "linux-amd64",
    "linux-arm64",
    "darwin-amd64",
    "darwin-arm64",
)

_OS_NAMES = {"windows": "windows", "linux": "linux", "darwin": "darwin"}
_ARCH_NAMES = {
    "amd64": "amd64",
    "x86_64": "amd64",
    "x64": "amd64",
    "arm64": "arm64",
    "aarch64": "arm64",
}

# A runner takes an argument list and a timeout in seconds and returns the finished process.
# Tests replace it with a fake. It must raise OSError or subprocess.TimeoutExpired on failure.
Runner = Callable[..., "subprocess.CompletedProcess[str]"]
# A finder takes an executable name and returns its path on PATH, or None.
Finder = Callable[[str], "Path | None"]


def normalize_os(system: str) -> str:
    """Map a ``platform.system()`` value to ``windows``, ``linux`` or ``darwin``."""
    key = system.strip().lower()
    if key not in _OS_NAMES:
        raise ToolError(f"unsupported operating system: {system!r}")
    return _OS_NAMES[key]


def normalize_arch(machine: str) -> str:
    """Map a ``platform.machine()`` value (AMD64, x86_64, ARM64, aarch64) to amd64 or arm64."""
    key = machine.strip().lower()
    if key not in _ARCH_NAMES:
        raise ToolError(f"unsupported CPU architecture: {machine!r}")
    return _ARCH_NAMES[key]


def platform_key(system: str | None = None, machine: str | None = None) -> str:
    """Return the manifest platform key of this machine, or of the given system and machine."""
    os_name = normalize_os(_platform.system() if system is None else system)
    arch = normalize_arch(_platform.machine() if machine is None else machine)
    return f"{os_name}-{arch}"


def is_windows(key: str) -> bool:
    """Return True when the platform key names a Windows platform."""
    return key.startswith("windows-")


def exe_suffix(key: str) -> str:
    """Return the executable file suffix for the platform key (``.exe`` on Windows)."""
    return ".exe" if is_windows(key) else ""


def find_on_path(executable: str, *, path_env: str | None = None) -> Path | None:
    """Return the first matching executable in the PATH directories, or None.

    Only absolute PATH entries are searched. The current directory is never searched, so a
    planted binary in a target folder cannot shadow a real tool. On Windows the PATHEXT
    extensions are tried; a name that already has one of them is also tried as given.
    """
    search = os.environ.get("PATH", "") if path_env is None else path_env
    if os.name == "nt":
        pathext = os.environ.get("PATHEXT", ".COM;.EXE;.BAT;.CMD")
        extensions = [ext.lower() for ext in pathext.split(";") if ext.strip()]
        if Path(executable).suffix.lower() in extensions:
            names = [executable]
        else:
            names = [executable + ext for ext in extensions]
    else:
        names = [executable]
    for entry in search.split(os.pathsep):
        entry = entry.strip().strip('"')
        if not entry or not os.path.isabs(entry):
            continue
        for name in names:
            candidate = Path(entry) / name
            if candidate.is_file() and (os.name == "nt" or os.access(candidate, os.X_OK)):
                return candidate
    return None


def run_command(
    argv: Sequence[str],
    *,
    timeout: float,
    env: Mapping[str, str] | None = None,
    cwd: str | os.PathLike[str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run a process without a shell, capture text output and enforce the timeout."""
    return subprocess.run(
        [str(arg) for arg in argv],
        shell=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        env=dict(env) if env is not None else None,
        cwd=cwd,
        stdin=subprocess.DEVNULL,
        check=False,
    )
