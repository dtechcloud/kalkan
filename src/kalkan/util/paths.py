# SPDX-License-Identifier: MIT
# Ported from cloudflare/security-audit-skill@c1c8a8c: skills/security-audit/validate-findings.cjs
# Ported from cloudflare/security-audit-skill@c1c8a8c: skills/security-audit/validate-coverage-ledger.cjs  # noqa: E501
# Copyright (c) 2025-2026 Cloudflare, Inc. Changes: translated from JavaScript to Python; merged the
# identical isSafeRelativeSourcePath and isSafeRelativePath; added to_posix and repo_root.
"""Safe repository-relative path checks, POSIX path conversion and the kalkan repository root.

A safe relative path is a non-empty, forward-slash path that cannot leave its root and that
every supported operating system can store. :func:`is_safe_relative_path` rejects:

- absolute paths, drive letters, ``~`` prefixes, backslashes and colons;
- empty, ``.`` and ``..`` segments, and segments that end with a space or a dot;
- Windows device names (``CON``, ``NUL.txt``, ``COM1``, ``LPT`` with a superscript digit,
  ``CLOCK$`` and others);
- control, format, separator and default-ignorable characters, lone surrogates, and
  surrounding whitespace.
"""

from __future__ import annotations

import os
import re
import tomllib
from pathlib import Path, PurePath
from typing import Final

from kalkan.errors import KalkanError
from kalkan.util.text import (
    PATH_FORBIDDEN_CHARACTER,
    has_valid_unicode_scalar_values,
    js_trim,
)

__all__ = [
    "KALKAN_HOME_ENV",
    "PATH_FORBIDDEN_CHARACTER",
    "WINDOWS_RESERVED_COMPONENT",
    "find_repo_root",
    "is_safe_relative_path",
    "is_safe_relative_source_path",
    "repo_root",
    "to_posix",
]

#: Port of the upstream expression with flags ``iu``. Under ``iu`` JavaScript folds only two
#: non-ASCII characters onto ASCII letters: U+212A (KELVIN SIGN) onto ``k`` and U+017F onto ``s``.
#: The class ``[k`` + U+212A ``]`` carries that fold, ``re.ASCII`` keeps every other comparison
#: ASCII-only, and ``\Z`` replaces ``$`` (JavaScript ``$`` never matches before a trailing
#: newline). The superscript digits U+00B9, U+00B2 and U+00B3 follow COM and LPT.
WINDOWS_RESERVED_COMPONENT: Final = re.compile(
    r"^(?:con|prn|aux|nul|cloc[k\U0000212a]\$|conin\$|conout\$"
    r"|com[1-9\U000000b9\U000000b2\U000000b3]|lpt[1-9\U000000b9\U000000b2\U000000b3])(?:\.|\Z)",
    re.IGNORECASE | re.ASCII,
)
_DRIVE_PREFIX: Final = re.compile(r"[A-Za-z]:")

#: Environment variable that overrides :func:`repo_root`.
KALKAN_HOME_ENV: Final = "KALKAN_HOME"


def is_safe_relative_path(value: object) -> bool:
    """Return True when ``value`` is a safe repository-relative path (port of
    ``isSafeRelativePath`` and ``isSafeRelativeSourcePath``)."""
    if (
        not isinstance(value, str)
        or not value
        or not has_valid_unicode_scalar_values(value)
        or js_trim(value) != value
        or PATH_FORBIDDEN_CHARACTER.search(value) is not None
        or "\\" in value
        or ":" in value
    ):
        return False
    # path.posix.isAbsolute and path.win32.isAbsolute: a leading separator, or a drive letter
    # with a colon and a separator (the colon check above already rejects the second form).
    if value.startswith(("/", "\\")) or _DRIVE_PREFIX.match(value) or value.startswith("~"):
        return False
    return all(
        segment not in ("", ".", "..")
        and not segment.endswith((" ", "."))
        and WINDOWS_RESERVED_COMPONENT.search(segment) is None
        for segment in value.split("/")
    )


#: The findings validator name of :func:`is_safe_relative_path` (the two upstream checks are
#: identical).
is_safe_relative_source_path = is_safe_relative_path


def to_posix(path: str | os.PathLike[str]) -> str:
    """Return ``path`` as a string with forward slashes.

    The conversion follows :mod:`pathlib` on the running system: on Windows a backslash is a
    separator, on Linux and macOS it is part of a name. ``pathlib`` also drops ``.`` segments,
    repeated slashes and a trailing slash. An empty string stays empty.
    """
    if isinstance(path, PurePath):
        return path.as_posix()
    text = os.fspath(path)
    if not isinstance(text, str):
        raise TypeError("path must be str or os.PathLike[str]")
    if not text:
        return ""
    return PurePath(text).as_posix()


def _declares_kalkan(pyproject: Path) -> bool:
    try:
        if not pyproject.is_file():
            return False
        with pyproject.open("rb") as handle:
            data = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError):
        return False
    project = data.get("project")
    return isinstance(project, dict) and project.get("name") == "kalkan"


def find_repo_root(start: str | os.PathLike[str]) -> Path | None:
    """Return the first directory at or above ``start`` whose ``pyproject.toml`` declares
    ``name = "kalkan"``, or None."""
    directory = Path(start).resolve()
    for candidate in (directory, *directory.parents):
        if _declares_kalkan(candidate / "pyproject.toml"):
            return candidate
    return None


def repo_root() -> Path:
    """Return the kalkan repository root.

    The ``KALKAN_HOME`` environment variable wins when it is set and not empty. Otherwise the
    function walks up from this file to the first directory whose ``pyproject.toml`` declares
    ``name = "kalkan"``. Raises :class:`~kalkan.errors.KalkanError` when neither gives a
    directory.
    """
    override = os.environ.get(KALKAN_HOME_ENV)
    if override:
        root = Path(override).expanduser().resolve()
        if not root.is_dir():
            raise KalkanError(f"{KALKAN_HOME_ENV} does not name a directory")
        return root
    found = find_repo_root(Path(__file__).parent)
    if found is None:
        raise KalkanError(f"cannot find the kalkan repository root; set {KALKAN_HOME_ENV}")
    return found
