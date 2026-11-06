# SPDX-License-Identifier: MIT
"""Safe reads of target source lines for quote verification (docs/PHASES.md section 4).

:func:`make_get_lines` returns the ``get_lines(path)`` callable that
:mod:`kalkan.findings.quote_verify` and :mod:`kalkan.findings.fingerprint` expect. It accepts only
safe target-relative paths, never follows a symlink or reparse point, reads at most
:data:`MAX_SOURCE_BYTES` per file and caches the split lines per path.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path

from kalkan.errors import KalkanError
from kalkan.util.paths import is_safe_relative_path
from kalkan.util.safe_io import read_text_bounded

MAX_SOURCE_BYTES = 5 * 1024 * 1024  # run init skips larger files

GetLines = Callable[[str], "list[str] | None"]


def make_get_lines(target_dir: str | os.PathLike[str]) -> GetLines:
    """Return ``get_lines(path) -> list[str] | None`` for files under ``target_dir``.

    The callable returns ``text.split("\\n")`` (the split that ``numbered_source`` uses), or None
    for an unsafe path, a path outside the target, a link, a missing file, a file over the size
    limit or a file that is not valid UTF-8.
    """
    root = Path(target_dir).resolve()
    cache: dict[str, list[str] | None] = {}

    def get_lines(path: str) -> list[str] | None:
        if path in cache:
            return cache[path]
        cache[path] = _read_lines(root, path)
        return cache[path]

    return get_lines


def _read_lines(root: Path, path: str) -> list[str] | None:
    if not isinstance(path, str):
        return None
    relative = path[2:] if path.startswith("./") else path
    if not is_safe_relative_path(relative):
        return None
    candidate = root.joinpath(*relative.split("/"))
    current = root
    for part in relative.split("/"):
        current = current / part
        try:
            if current.is_symlink() or _is_reparse_point(current):
                return None
        except OSError:
            return None
    try:
        if not candidate.resolve().is_relative_to(root):
            return None
        text = read_text_bounded(candidate, MAX_SOURCE_BYTES)
    except (KalkanError, OSError, UnicodeDecodeError, ValueError):
        return None
    return text.split("\n")


def _is_reparse_point(path: Path) -> bool:
    attributes = getattr(os.lstat(path), "st_file_attributes", 0)
    return bool(attributes & 0x400)  # FILE_ATTRIBUTE_REPARSE_POINT
