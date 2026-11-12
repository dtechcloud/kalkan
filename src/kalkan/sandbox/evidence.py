# SPDX-License-Identifier: MIT
"""Safe copy of sandbox output files into the run evidence folder (docs/ENGINE-SPEC.md 23).

The container writes into a host folder (``/out``). That folder is untrusted: the harness
code ran there. :func:`promote` copies only what is safe to keep:

- regular files (``os.lstat``): links, junctions, devices and pipes are skipped, and a linked
  folder is never entered;
- at most :data:`MAX_FILES` files, each at most :data:`MAX_FILE_BYTES`, together at most
  :data:`MAX_TOTAL_BYTES`;
- names that pass :func:`kalkan.util.paths.is_safe_relative_path`.

The copy reads the source with ``O_NOFOLLOW`` where the platform has it and checks again
that the open file is the regular file that ``lstat`` saw.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Final

from kalkan.util.paths import is_safe_relative_path

__all__ = ["MAX_FILES", "MAX_FILE_BYTES", "MAX_TOTAL_BYTES", "promote"]

MAX_FILES: Final = 50
MAX_FILE_BYTES: Final = 2 * 1024 * 1024
MAX_TOTAL_BYTES: Final = 8 * 1024 * 1024
_CHUNK: Final = 64 * 1024


def _copy_regular(source: Path, target: Path, expected: os.stat_result) -> bool:
    """Copy ``source`` to ``target`` when it is still the regular file of ``expected``."""
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        handle = os.open(source, flags)
    except OSError:
        return False
    try:
        opened = os.fstat(handle)
        if not stat.S_ISREG(opened.st_mode) or opened.st_size != expected.st_size:
            return False
        if (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino):
            return False
        target.parent.mkdir(parents=True, exist_ok=True)
        left = expected.st_size
        with open(target, "wb") as out:
            while left > 0:
                chunk = os.read(handle, min(_CHUNK, left))
                if not chunk:
                    break
                out.write(chunk)
                left -= len(chunk)
        return True
    finally:
        os.close(handle)


def promote(
    out_dir: Path,
    dest_dir: Path,
    *,
    max_files: int = MAX_FILES,
    max_file_bytes: int = MAX_FILE_BYTES,
    max_total_bytes: int = MAX_TOTAL_BYTES,
) -> list[Path]:
    """Copy the safe regular files of ``out_dir`` into ``dest_dir``; return the copies.

    The walk never follows a link. Files over the size limits, unsafe names and every file
    after the count or total limit are left out (sorted walk, so the choice is stable).
    """
    written: list[Path] = []
    if out_dir.is_symlink() or not out_dir.is_dir():
        return written
    total = 0
    for root, dirs, files in os.walk(out_dir, followlinks=False):
        here = Path(root)
        dirs[:] = sorted(d for d in dirs if not (here / d).is_symlink())
        for name in sorted(files):
            if len(written) >= max_files:
                return written
            source = here / name
            try:
                info = os.lstat(source)
            except OSError:
                continue
            if not stat.S_ISREG(info.st_mode) or info.st_size > max_file_bytes:
                continue
            if total + info.st_size > max_total_bytes:
                return written
            relative = source.relative_to(out_dir).as_posix()
            if not is_safe_relative_path(relative):
                continue
            target = dest_dir / relative
            if _copy_regular(source, target, info):
                total += info.st_size
                written.append(target)
    return written
