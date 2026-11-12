# SPDX-License-Identifier: MIT
# Ported from cloudflare/security-audit-skill@c1c8a8c: skills/security-audit/validate-findings.cjs
# Copyright (c) 2025-2026 Cloudflare, Inc. Changes: readFileWithinLimit rewritten in Python for
# Windows, Linux and macOS (lstat and reparse point checks, identity check after open, bounded
# chunked read); atomic text and JSON writes added.
"""Bounded, symlink-safe file reads and atomic file writes.

The Cloudflare ``readFileWithinLimit`` opens its input with ``O_NOFOLLOW | O_NONBLOCK``. Node
defines neither flag on Windows, so the upstream validators reject every input there.
:func:`read_bounded` gives the same protection on every platform:

1. ``os.lstat`` the path. Reject a symlink, a Windows reparse point (junction, mount point,
   symlink) and anything that is not a regular file.
2. Open the file. On Linux and macOS the open uses ``O_NOFOLLOW | O_NONBLOCK``, so a symlink or a
   FIFO swapped in after step 1 cannot be followed or block the read.
3. ``os.fstat`` the open file and compare ``st_dev`` and ``st_ino`` with step 1. A file that was
   replaced between the two steps is rejected.
4. Enforce the byte limit before the read and again during a chunked read.

Only the final path component is checked. The parent directories are trusted, as upstream.

Error messages never contain the path, so a hostile file name cannot inject terminal control
characters into the output. The original ``OSError`` stays available as ``__cause__``.

Encoding: :func:`read_text_bounded` decodes strict UTF-8 and keeps a byte order mark as U+FEFF,
like the upstream ``TextDecoder("utf-8", {fatal: true, ignoreBOM: true})``. A JSON document that
starts with a byte order mark therefore fails to parse, as upstream.
"""

from __future__ import annotations

import contextlib
import errno
import json
import os
import re
import stat
import tempfile
import time
from pathlib import Path
from typing import Final

from kalkan.errors import UnsafeInputError

__all__ = [
    "DEFAULT_MAX_BYTES",
    "atomic_write_json",
    "atomic_write_text",
    "dumps_json",
    "read_bounded",
    "read_text_bounded",
]

DEFAULT_MAX_BYTES: Final = 5 * 1024 * 1024
_CHUNK_BYTES: Final = 64 * 1024
_UNREADABLE: Final = "input could not be opened or read safely"
_OPEN_FLAGS: Final = (
    os.O_RDONLY
    | getattr(os, "O_BINARY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_NONBLOCK", 0)
)
_REPLACE_ATTEMPTS: Final = 5
_REPLACE_DELAY_SECONDS: Final = 0.05
_LONE_SURROGATE: Final = re.compile(r"[\ud800-\udfff]")

# Module attribute so that tests can exercise the Windows retry path on any platform.
_IS_WINDOWS = os.name == "nt"


def _path_text(path: str | os.PathLike[str]) -> str:
    text = os.fspath(path)
    if not isinstance(text, str):
        raise TypeError("path must be str or os.PathLike[str]")
    return text


def _reject_links(info: os.stat_result) -> None:
    if stat.S_ISLNK(info.st_mode):
        raise UnsafeInputError("input must not be a symlink")
    attributes = getattr(info, "st_file_attributes", 0) or 0  # Windows only
    if attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
        raise UnsafeInputError("input must not be a symlink or other reparse point")


def read_bounded(path: str | os.PathLike[str], max_bytes: int = DEFAULT_MAX_BYTES) -> bytes:
    """Return the bytes of the regular file ``path``, at most ``max_bytes`` of them.

    Raises :class:`~kalkan.errors.UnsafeInputError` when the path is a symlink or a reparse
    point, is not a regular file, changes while it is opened, is larger than ``max_bytes``, or
    cannot be opened or read.
    """
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 0:
        raise ValueError("max_bytes must be a non-negative integer")
    target = _path_text(path)
    try:
        before = os.lstat(target)
    except (OSError, ValueError) as exc:
        raise UnsafeInputError(_UNREADABLE) from exc
    _reject_links(before)
    if not stat.S_ISREG(before.st_mode):
        raise UnsafeInputError("input must be a regular file")
    if before.st_size > max_bytes:
        raise UnsafeInputError(f"input exceeds {max_bytes} byte limit")

    try:
        descriptor = os.open(target, _OPEN_FLAGS)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.EMLINK):
            raise UnsafeInputError("input must not be a symlink") from exc
        raise UnsafeInputError(_UNREADABLE) from exc
    except ValueError as exc:
        raise UnsafeInputError(_UNREADABLE) from exc
    try:
        after = os.fstat(descriptor)
        if not stat.S_ISREG(after.st_mode):
            raise UnsafeInputError("input must be a regular file")
        if (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino):
            raise UnsafeInputError("input changed while it was being opened")
        if after.st_size > max_bytes:
            raise UnsafeInputError(f"input exceeds {max_bytes} byte limit")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(_CHUNK_BYTES, max_bytes + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise UnsafeInputError(f"input exceeds {max_bytes} byte limit")
            chunks.append(chunk)
        return b"".join(chunks)
    except OSError as exc:
        raise UnsafeInputError(_UNREADABLE) from exc
    finally:
        os.close(descriptor)


def read_text_bounded(path: str | os.PathLike[str], max_bytes: int = DEFAULT_MAX_BYTES) -> str:
    """Return the strict UTF-8 text of ``path`` (see :func:`read_bounded`).

    A byte order mark stays in the text as U+FEFF. Invalid UTF-8 (including encoded surrogates
    and overlong forms) raises :class:`~kalkan.errors.UnsafeInputError` with the message
    ``input is not valid UTF-8``.
    """
    data = read_bounded(path, max_bytes)
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise UnsafeInputError("input is not valid UTF-8") from None


def _replace(source: str, target: str) -> None:
    attempts = _REPLACE_ATTEMPTS if _IS_WINDOWS else 1
    for attempt in range(1, attempts + 1):
        try:
            os.replace(source, target)
            return
        except PermissionError:
            # On Windows a reader, an indexer or a virus scanner can hold the target open for a
            # short time. Retry a few times before giving up.
            if attempt == attempts:
                raise
            time.sleep(_REPLACE_DELAY_SECONDS * attempt)


def _fsync_directory(directory: str) -> None:
    if _IS_WINDOWS:
        return
    with contextlib.suppress(OSError):
        descriptor = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def atomic_write_text(path: str | os.PathLike[str], text: str) -> None:
    """Write ``text`` to ``path`` as UTF-8 with ``\\n`` line endings, atomically.

    The data goes to a temporary file in the same directory first. The function flushes and
    fsyncs it, then moves it over ``path`` with ``os.replace``. Readers see the old or the new
    content, never a mix. The parent directory must exist. A new file gets mode 0600 on Linux and
    macOS. A replaced regular file keeps its permission bits.
    """
    target = Path(_path_text(path))
    data = text.encode("utf-8")
    directory = str(target.parent)
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{target.name[:64]}.", suffix=".tmp", dir=directory
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if not _IS_WINDOWS:
            with contextlib.suppress(OSError):
                existing = os.lstat(target)
                if stat.S_ISREG(existing.st_mode):
                    os.chmod(temporary, stat.S_IMODE(existing.st_mode))
        _replace(temporary, str(target))
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(temporary)
        raise
    _fsync_directory(directory)


def _escape_lone_surrogate(match: re.Match[str]) -> str:
    return f"\\u{ord(match.group()):04x}"


def dumps_json(obj: object) -> str:
    """Return ``obj`` in the kalkan JSON file format.

    The format is ``json.dumps(obj, ensure_ascii=False, indent=2) + "\\n"`` (ENGINE-SPEC
    section 1) with two additions: NaN and infinities raise ``ValueError`` (they are not JSON),
    and a lone surrogate is written as a ``\\uXXXX`` escape, as ``JSON.stringify`` does, because
    UTF-8 cannot store it.
    """
    text = json.dumps(obj, ensure_ascii=False, indent=2, allow_nan=False)
    return _LONE_SURROGATE.sub(_escape_lone_surrogate, text) + "\n"


def atomic_write_json(path: str | os.PathLike[str], obj: object) -> None:
    """Write ``obj`` to ``path`` in the kalkan JSON file format (:func:`dumps_json`),
    atomically (:func:`atomic_write_text`)."""
    atomic_write_text(path, dumps_json(obj))
