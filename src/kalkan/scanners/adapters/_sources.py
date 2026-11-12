# SPDX-License-Identifier: MIT
"""Helpers of the file-list adapters (ShellCheck, flawfinder, gixy, Kingfisher).

1. :func:`source_files` lists target files for a predicate. It uses the walk of
   :func:`kalkan.scanners.adapters._common.target_files` (no links; ``.git``, ``node_modules``,
   ``.venv``, ``venv``, ``dist`` and ``build`` are not entered) and also skips the vendored
   folders of :data:`VENDOR_DIRS`: third-party code that the target copied in is not its own
   code, and on C projects it multiplies the tool results.
2. :func:`target_relative` turns a path that a tool printed into a target-relative POSIX path,
   or None when the path is not inside the target. Tools print the path in the form they were
   given (kalkan passes absolute paths), sometimes with a ``\\\\?\\`` prefix or percent-encoded.
3. :func:`read_line` returns one line of a target file for a SARIF snippet (bounded read, no
   links followed); :func:`read_head` returns the first bytes of a file (shebang lines).
4. :func:`batches` splits a file list, so that a long list never exceeds the Windows command
   line limit (32,767 characters).
"""

from __future__ import annotations

import os
import stat
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path, PurePosixPath
from typing import Final
from urllib.parse import unquote

from kalkan.errors import KalkanError
from kalkan.scanners.adapters._common import target_files
from kalkan.util.safe_io import read_bounded

__all__ = [
    "BATCH_SIZE",
    "MAX_SOURCE_BYTES",
    "VENDOR_DIRS",
    "batches",
    "is_vendored",
    "read_head",
    "read_line",
    "read_lines",
    "source_files",
    "target_relative",
]

#: Folder names of copied third-party code (compared case-insensitively).
VENDOR_DIRS: Final = frozenset({"vendor", "vendors", "third_party", "third-party", "thirdparty"})
#: Files per tool run (ShellCheck, flawfinder, gixy).
BATCH_SIZE: Final = 100
#: The largest file that :func:`read_lines` reads; ``run init`` copies no larger file.
MAX_SOURCE_BYTES: Final = 5 * 1024 * 1024


def is_vendored(rel: str) -> bool:
    """Return True when a target-relative path is inside a folder of :data:`VENDOR_DIRS`."""
    parts = PurePosixPath(rel).parts[:-1]
    return any(part.casefold() in VENDOR_DIRS for part in parts)


def source_files(target: Path, predicate: Callable[[str], bool]) -> list[str]:
    """Return the sorted target-relative paths that ``predicate`` accepts, vendored ones left
    out."""
    return [rel for rel in target_files(target) if not is_vendored(rel) and predicate(rel)]


def batches(items: Sequence[str], size: int = BATCH_SIZE) -> Iterator[list[str]]:
    """Yield the items in lists of at most ``size``."""
    for start in range(0, len(items), size):
        yield list(items[start : start + size])


def target_relative(text: str, target: Path, *, base: Path | None = None) -> str | None:
    """Return a tool path as a target-relative POSIX path, or None when it is outside.

    ``text`` may be absolute, start with ``\\\\?\\``, use backslashes or be percent-encoded
    (``C%3A/...``). A relative path is relative to ``base`` (default: the target).
    """
    raw = text.strip()
    if not raw:
        return None
    if "%" in raw:
        raw = unquote(raw)
    if raw.startswith(("\\\\?\\", "//?/")):
        raw = raw[4:]
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = (base or target) / candidate
    root = Path(os.path.abspath(target))
    try:
        rel = Path(os.path.abspath(candidate)).relative_to(root)
    except ValueError:
        try:
            rel = candidate.resolve().relative_to(target.resolve())
        except (OSError, ValueError):
            return None
    posix = rel.as_posix()
    if posix in ("", ".") or posix.startswith("../"):
        return None
    return posix


def read_head(path: Path, size: int = 256) -> bytes:
    """Return the first ``size`` bytes of a regular file (``b""`` for anything else)."""
    try:
        if not stat.S_ISREG(os.lstat(path).st_mode):
            return b""
        with open(path, "rb") as handle:
            return handle.read(size)
    except OSError:
        return b""


def read_lines(path: Path) -> list[str] | None:
    """Return the lines of a file (UTF-8, undecodable bytes replaced), or None."""
    try:
        data = read_bounded(path, MAX_SOURCE_BYTES)
    except (KalkanError, OSError):
        return None
    return data.decode("utf-8", errors="replace").split("\n")


def read_line(path: Path, line: int | None) -> str:
    """Return line ``line`` (1-based) of a file without its line ending, or ``""``."""
    if line is None or line < 1:
        return ""
    lines = read_lines(path)
    if lines is None or line > len(lines):
        return ""
    return lines[line - 1].rstrip("\r")
