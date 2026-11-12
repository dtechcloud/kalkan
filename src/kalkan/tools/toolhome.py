# SPDX-License-Identifier: MIT
"""Kalkan-owned folders for the files that tools write besides their output (docs/SECURITY.md).

Measured on Windows 11 on 2026-10-29: the user profile was snapshotted (names, modification
times, sizes) before and after ``kalkan doctor``, ``kalkan scan all`` and ``kalkan sca sbom``,
``match`` and ``reach`` on a run of ``tests/fixtures/vulnapp``. Without this module:

- **opengrep 1.30.1** is a self-extracting program. It unpacks its runtime (277 MB in 84
  files) into ``%USERPROFILE%\\AppData\\Local\\opengrep\\v1.30.1`` and stops with exit code
  0xC0000409 when the ``AppData\\Local`` folder of ``USERPROFILE`` is missing. It writes its log
  to ``%USERPROFILE%\\.opengrep\\semgrep.log`` (``HOME`` does not move it); a scan logs the
  paths of the target files and code of the matches there (262 KB for vulnapp). A scan leaves
  its temporary rule files and its core input and output (``semgrep-*.rules``, ``tmp*.json``:
  58 files, 5.4 MB for vulnapp) in the temporary folder. ``SEMGREP_LOG_FILE`` and
  ``XDG_CONFIG_HOME`` move the log (``OPENGREP_LOG_FILE`` does not).
- **gosec and govulncheck** start ``go list``, which fills the Go build cache
  ``%LOCALAPPDATA%\\go-build`` (gosec on vulnapp: 1,464 files, 93 MB).
- **Go telemetry**: once ``%APPDATA%\\go\\telemetry`` exists, the Go command, the compiler and
  govulncheck add counters there (``local`` mode, the default). A folder whose
  ``go/telemetry/mode`` file says ``off`` gets none (tested with ``go list`` and govulncheck).
- **pip** keeps its downloads in ``%LOCALAPPDATA%\\pip\\cache`` (``--no-cache-dir`` stops it).

The functions here give each tool a kalkan-owned place instead. Persistent data that is not
about a target lives below :func:`cache_root` (``<home>/.tools/cache``); everything that can
hold target data lives in the work folder of the run (removed after a successful run,
``kalkan run clean`` removes the rest):

- :func:`temp_env`: ``TEMP`` and ``TMP`` (and ``TMPDIR`` on Linux and macOS) for every tool run
  of an adapter (``<run>/<scans|sca>/.work/<engine>/tmp``) and every version probe (its empty
  working folder).
- :func:`opengrep_env`: ``USERPROFILE`` and ``HOME`` name :func:`opengrep_home` (the unpacked
  runtime stays there, once per version), ``XDG_CACHE_HOME`` its ``.cache`` (where the Linux
  build unpacks), ``SEMGREP_LOG_FILE`` and ``XDG_CONFIG_HOME`` the work folder.
- :func:`go_config_env`: the folder that the Go command reads as the user configuration folder
  (``APPDATA`` on Windows, ``XDG_CONFIG_HOME`` on Linux), with :func:`go_telemetry_off` in it.
  macOS takes it from ``HOME`` (``$HOME/Library/Application Support``), so a Go program gets the
  folder as its ``HOME`` there, and ``GOPATH`` keeps its default in the real home folder (the
  module cache of the user stays readable, as on Windows and Linux). Measured on macOS 27 arm64
  on 2026-11-12: without it, the Go command and the compiler of gosec and govulncheck wrote
  telemetry counters into ``~/Library/Application Support/go/telemetry``. ``GOTELEMETRY=off``
  does not help: Go shows ``GOTELEMETRY`` in ``go env`` but does not read it from the
  environment.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Final

__all__ = [
    "CACHE_DIRNAME",
    "GO_CONFIG_DIRNAME",
    "OPENGREP_HOME_DIRNAME",
    "TEMP_DIRNAME",
    "cache_root",
    "go_config_env",
    "go_telemetry_off",
    "go_user_config_dir",
    "user_gopath",
    "opengrep_env",
    "opengrep_home",
    "prepare_home",
    "temp_env",
]

#: ``<home>/.tools/cache``: persistent tool data that holds nothing of a target.
CACHE_DIRNAME: Final = "cache"
#: ``<home>/.tools/cache/opengrep``: ``USERPROFILE`` and ``HOME`` of the opengrep processes.
OPENGREP_HOME_DIRNAME: Final = "opengrep"
#: The temporary folder of a tool run inside its work folder.
TEMP_DIRNAME: Final = "tmp"
#: The Go configuration folder of a Go tool run inside its work folder.
GO_CONFIG_DIRNAME: Final = "go-config"


def cache_root(repo_root: str | os.PathLike[str]) -> Path:
    """Return ``<home>/.tools/cache``."""
    return Path(repo_root) / ".tools" / CACHE_DIRNAME


def opengrep_home(repo_root: str | os.PathLike[str]) -> Path:
    """Return ``<home>/.tools/cache/opengrep``, the profile folder of the opengrep processes."""
    return cache_root(repo_root) / OPENGREP_HOME_DIRNAME


def prepare_home(folder: str | os.PathLike[str]) -> Path:
    """Create a profile folder with ``AppData/Local`` and ``AppData/Roaming`` and return it.

    opengrep unpacks its runtime below ``AppData/Local`` of ``USERPROFILE`` and stops when that
    folder is missing (module docstring).
    """
    home = Path(folder)
    for part in (("AppData", "Local"), ("AppData", "Roaming")):
        home.joinpath(*part).mkdir(parents=True, exist_ok=True)
    return home


def temp_env(folder: str | os.PathLike[str], *, platform: str | None = None) -> dict[str, str]:
    """Return ``TEMP`` and ``TMP`` (and ``TMPDIR`` outside Windows) that name ``folder``.

    ``platform`` replaces ``sys.platform`` (tests).
    """
    path = os.fspath(folder)
    env = {"TEMP": path, "TMP": path}
    if (platform or sys.platform) != "win32":
        env["TMPDIR"] = path
    return env


def opengrep_env(home: str | os.PathLike[str], work: str | os.PathLike[str]) -> dict[str, str]:
    """Return the variables that keep opengrep inside the kalkan folders (module docstring).

    ``home`` holds the unpacked runtime (:func:`opengrep_home`, prepared with
    :func:`prepare_home`); ``work`` gets the log, which can hold target paths and code.
    """
    profile = os.fspath(home)
    folder = Path(work)
    return {
        "USERPROFILE": profile,
        "HOME": profile,
        "XDG_CACHE_HOME": os.fspath(Path(home) / ".cache"),
        "XDG_CONFIG_HOME": os.fspath(folder),
        "SEMGREP_LOG_FILE": os.fspath(folder / "opengrep.log"),
    }


def go_config_env(folder: str | os.PathLike[str], *, platform: str | None = None) -> dict[str, str]:
    """Return the variable that makes ``folder`` the user configuration folder of Go.

    Go reads its telemetry mode and its ``go env -w`` file from there (``os.UserConfigDir``):
    ``APPDATA`` on Windows, ``XDG_CONFIG_HOME`` on Linux. macOS derives it from ``HOME``: there
    the function returns ``HOME`` (the configuration folder is then
    :func:`go_user_config_dir`). Go then also derives its default ``GOPATH`` from that folder; a
    scanner run sets :func:`user_gopath` (module docstring). ``platform`` replaces
    ``sys.platform`` (tests).
    """
    name = platform or sys.platform
    if name == "win32":
        return {"APPDATA": os.fspath(folder)}
    if name == "darwin":
        return {"HOME": os.fspath(folder)}
    return {"XDG_CONFIG_HOME": os.fspath(folder)}


def user_gopath() -> str:
    """Return the ``GOPATH`` of the user: the variable, else the Go default ``~/go``."""
    return os.environ.get("GOPATH") or os.fspath(Path.home() / "go")


def go_user_config_dir(folder: str | os.PathLike[str], *, platform: str | None = None) -> Path:
    """Return the folder that Go reads as ``os.UserConfigDir`` with :func:`go_config_env`.

    That is ``folder`` itself, on macOS ``folder/Library/Application Support``.
    """
    if (platform or sys.platform) == "darwin":
        return Path(folder) / "Library" / "Application Support"
    return Path(folder)


def go_telemetry_off(folder: str | os.PathLike[str], *, platform: str | None = None) -> Path:
    """Write ``go/telemetry/mode`` with ``off`` into the Go configuration folder of ``folder``
    (:func:`go_user_config_dir`) and return the file.

    With it, the Go command, the compiler and govulncheck write no telemetry counters into
    the folder (module docstring).
    """
    mode = go_user_config_dir(folder, platform=platform) / "go" / "telemetry" / "mode"
    mode.parent.mkdir(parents=True, exist_ok=True)
    mode.write_text("off", encoding="utf-8")
    return mode
