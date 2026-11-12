# SPDX-License-Identifier: MIT
"""Measure and remove folder trees without following links (docs/ENGINE-SPEC.md 11 and 12).

:func:`remove_tree` deletes a file or a folder tree. ``kalkan tools install`` uses it for the
Go build folder, ``kalkan run clean`` for the work files of a finished run:

- It never follows a symlink or a Windows reparse point (a junction, a mount point, a folder
  symlink). It removes such an entry as a link, and the folder that the link names stays.
- It makes a read-only entry writable before it deletes it. Go marks the files and folders of
  its module cache read-only, and git marks its pack files read-only on Windows.
- It tries a folder again for a short time when Windows still reports it as in use or not
  empty (a virus scanner or the search indexer can hold a handle for a moment).
- It counts the regular files and their bytes (``st_size`` of ``os.lstat``) and the links.
- With ``dry_run`` it only counts.
- On Windows it works with the extended-length form of the path (``\\\\?\\C:\\...``), so a file
  whose path has 260 or more characters is removed too.

The function goes on after an error and returns the errors in :attr:`TreeStats.errors`. Error
texts name the path relative to the start path.
"""

from __future__ import annotations

import contextlib
import errno
import os
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

__all__ = ["TreeStats", "is_link", "remove_tree", "size_text", "tree_size"]

#: How often and how long :func:`remove_tree` tries a folder that Windows reports as busy.
_RMDIR_ATTEMPTS: Final = 20
_RMDIR_DELAY_SECONDS: Final = 0.05
#: At most this many error texts are kept.
_MAX_ERRORS: Final = 20


@dataclass
class TreeStats:
    """What :func:`remove_tree` or :func:`tree_size` found: regular files, their bytes, links
    (removed as links, never followed), folders and errors."""

    files: int = 0
    bytes: int = 0
    links: int = 0
    folders: int = 0
    errors: list[str] = field(default_factory=list)

    def add(self, other: TreeStats) -> None:
        """Add the counts and the errors of ``other``."""
        self.files += other.files
        self.bytes += other.bytes
        self.links += other.links
        self.folders += other.folders
        self.errors.extend(other.errors[: max(0, _MAX_ERRORS - len(self.errors))])

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-ready dict."""
        return {
            "files": self.files,
            "bytes": self.bytes,
            "links": self.links,
            "folders": self.folders,
            "errors": list(self.errors),
        }


def is_link(info: os.stat_result) -> bool:
    """Return True for a symlink or a Windows reparse point (``os.lstat`` result)."""
    if stat.S_ISLNK(info.st_mode):
        return True
    attributes = getattr(info, "st_file_attributes", 0) or 0  # Windows only
    return bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def tree_size(path: str | os.PathLike[str]) -> TreeStats:
    """Return the counts of :func:`remove_tree` without removing anything."""
    return remove_tree(path, dry_run=True)


def size_text(size: int) -> str:
    """Return a byte count in decimal units: ``0 B``, ``512 B``, ``4.2 KB``, ``88.0 MB``,
    ``3.40 GB``."""
    if size < 1000:
        return f"{size} B"
    for unit, scale in (("KB", 1e3), ("MB", 1e6)):
        value = size / scale
        if round(value, 1) < 1000:
            return f"{value:.1f} {unit}"
    return f"{size / 1e9:.2f} GB"


def remove_tree(path: str | os.PathLike[str], *, dry_run: bool = False) -> TreeStats:
    """Remove the file, link or folder tree ``path`` (module docstring). A missing path gives
    empty counts."""
    stats = TreeStats()
    start = _long(Path(path))
    _remove(start, start, stats, dry_run)
    return stats


def _long(path: Path) -> Path:
    """Return ``path`` as an absolute path; on Windows in the extended-length form.

    ``os.path.abspath`` works on the text only: it follows no link.
    """
    text = os.path.abspath(os.fspath(path))
    if os.name != "nt" or text.startswith("\\\\?\\"):
        return Path(text)
    if text.startswith("\\\\"):
        return Path("\\\\?\\UNC\\" + text[2:])
    return Path("\\\\?\\" + text)


def _note(stats: TreeStats, start: Path, path: Path, exc: OSError) -> None:
    if len(stats.errors) >= _MAX_ERRORS:
        return
    try:
        shown = path.relative_to(start).as_posix()
    except ValueError:
        shown = path.as_posix()
    reason = exc.strerror or type(exc).__name__
    stats.errors.append(f"{shown or '.'}: {reason}")


def _remove(start: Path, path: Path, stats: TreeStats, dry_run: bool) -> None:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return
    except OSError as exc:
        _note(stats, start, path, exc)
        return
    if is_link(info):
        stats.links += 1
        if not dry_run:
            _remove_link(start, path, info, stats)
        return
    if not stat.S_ISDIR(info.st_mode):
        stats.files += 1
        stats.bytes += info.st_size
        if not dry_run:
            _remove_file(start, path, stats)
        return
    if not dry_run:
        _make_writable(path, info, folder=True)
    try:
        with os.scandir(path) as entries:
            names = [entry.name for entry in entries]
    except OSError as exc:
        _note(stats, start, path, exc)
        return
    for name in names:
        _remove(start, path / name, stats, dry_run)
    stats.folders += 1
    if not dry_run:
        _remove_folder(start, path, stats)


def _make_writable(path: Path, info: os.stat_result | None = None, *, folder: bool) -> None:
    """Clear the read-only attribute (Windows) or add the owner write bit (Linux, macOS)."""
    with contextlib.suppress(OSError):
        if info is None:
            info = os.lstat(path)
        if is_link(info):
            return
        if os.name == "nt":
            attributes = getattr(info, "st_file_attributes", 0) or 0
            if attributes & stat.FILE_ATTRIBUTE_READONLY:
                os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
            return
        wanted = stat.S_IRWXU if folder else stat.S_IRUSR | stat.S_IWUSR
        mode = stat.S_IMODE(info.st_mode)
        if mode & wanted != wanted:
            os.chmod(path, mode | wanted)


def _remove_file(start: Path, path: Path, stats: TreeStats) -> None:
    try:
        os.unlink(path)
        return
    except FileNotFoundError:
        return
    except PermissionError:
        _make_writable(path, folder=False)
        if os.name != "nt":
            _make_writable(path.parent, folder=True)
    except OSError as exc:
        _note(stats, start, path, exc)
        return
    try:
        os.unlink(path)
    except FileNotFoundError:
        return
    except OSError as exc:
        _note(stats, start, path, exc)


def _remove_link(start: Path, path: Path, info: os.stat_result, stats: TreeStats) -> None:
    """Remove a symlink or a reparse point itself; the folder that it names stays."""
    attributes = getattr(info, "st_file_attributes", 0) or 0
    try:
        if attributes & stat.FILE_ATTRIBUTE_DIRECTORY:
            os.rmdir(path)  # a junction or a folder symlink on Windows: the link only
        else:
            os.unlink(path)
    except FileNotFoundError:
        return
    except OSError as exc:
        _note(stats, start, path, exc)


def _remove_folder(start: Path, path: Path, stats: TreeStats) -> None:
    # Only Windows needs the wait: a deleted file stays "delete pending" while another process
    # holds a handle to it. Elsewhere a folder that is not empty kept a file that failed.
    attempts = _RMDIR_ATTEMPTS if os.name == "nt" else 2
    last: OSError | None = None
    for attempt in range(attempts):
        try:
            os.rmdir(path)
            return
        except FileNotFoundError:
            return
        except PermissionError as exc:
            _make_writable(path, folder=True)
            last = exc
        except OSError as exc:
            if exc.errno not in (errno.ENOTEMPTY, errno.EEXIST, errno.EACCES, errno.EBUSY):
                _note(stats, start, path, exc)
                return
            last = exc
        if attempt + 1 < attempts:
            time.sleep(_RMDIR_DELAY_SECONDS)
    if last is not None:
        _note(stats, start, path, last)
