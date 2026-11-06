# SPDX-License-Identifier: MIT
"""Windows path length limits that scanners hit (docs/ENGINE-SPEC.md, sections 10 and 13).

Measured on Windows 11 with Opengrep 1.30.1 (2026-10-16): ``opengrep.exe`` is a wrapper whose
manifest declares ``longPathAware``; it lists every file and counts it as scanned. The analysis
program ``opengrep-core.exe`` does not declare it, so the classic ``MAX_PATH`` limit applies to
it: a file whose absolute path has 260 or more UTF-16 characters (Python ``len()``) is treated
as missing and skipped without a warning, an error or a SARIF notification. The limit counts
the path string that Opengrep receives (kalkan passes the resolved target folder, so an 8.3
short name such as ``DEVKUC~1`` is expanded). The folder length, the file name length, the
UTF-8 byte length, non-ASCII characters and the language do not matter, and
``HKLM\\SYSTEM\\CurrentControlSet\\Control\\FileSystem\\LongPathsEnabled = 1`` does not lift the
limit (the core program does not opt in).

Other systems have no such limit: :func:`find_long_paths` returns an empty list there.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Final

__all__ = [
    "LONG_PATH_CONDITION",
    "WINDOWS_PATH_LIMIT",
    "find_long_paths",
    "long_paths_enabled",
]

#: An absolute path of this many characters or more is skipped by Opengrep on Windows.
WINDOWS_PATH_LIMIT: Final = 260
#: The measured condition, for status files and reports.
LONG_PATH_CONDITION: Final = (
    "absolute Windows path of 260 or more characters; opengrep-core.exe is not long-path aware "
    "and skips such files without a warning, also with LongPathsEnabled=1"
)


def find_long_paths(
    root: str | os.PathLike[str], *, limit: int = WINDOWS_PATH_LIMIT, windows: bool | None = None
) -> list[str]:
    """Return the sorted root-relative POSIX paths of files whose absolute path under the
    resolved ``root`` has ``limit`` or more characters.

    ``windows`` defaults to ``os.name == "nt"``; on other systems the result is empty. The root
    is resolved as the scanner adapters resolve the target folder, so the measured string is
    the one that the tools receive.
    """
    if not (os.name == "nt" if windows is None else windows):
        return []
    base = Path(root).resolve()
    text = str(base)
    found: list[str] = []
    for current, _dirs, files in os.walk(text):
        for name in files:
            full = os.path.join(current, name)
            if len(full) >= limit:
                found.append(Path(full).relative_to(base).as_posix())
    return sorted(found)


def long_paths_enabled() -> bool | None:
    """Return the ``LongPathsEnabled`` registry value of Windows as a bool, or None elsewhere or
    when the value cannot be read."""
    if os.name != "nt":
        return None
    try:
        import winreg

        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\FileSystem"
        ) as key:
            value, _kind = winreg.QueryValueEx(key, "LongPathsEnabled")
    except (ImportError, OSError):
        return None
    return bool(value) if isinstance(value, int) else None
