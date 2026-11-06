# SPDX-License-Identifier: MIT
"""Run IDs, the runs root, ``runs/LATEST`` and UTC timestamps (docs/ENGINE-SPEC.md, section 10).

A run ID has the form ``<UTC yyyymmddThhmmssZ>-<slug>-<4 hex>``. The slug is the target folder
name in lower case, reduced to ``[a-z0-9-]``, at most 24 characters (:func:`slugify`). A run ID
must match :data:`RUN_ID_PATTERN` before it becomes a path, so it can never name a parent folder,
a drive, a device or a link target.

The runs root is ``<home>/runs`` (:func:`kalkan.resources.runs_root`; the plugin marker can
name another folder). The environment variable ``KALKAN_RUNS_DIR`` overrides it.
``<runs root>/LATEST`` holds the ID of the newest run; :func:`write_latest` replaces it
atomically.

Timestamps are UTC ISO 8601 text with a ``Z`` suffix and second precision
(``2026-10-15T22:43:00Z``). :func:`parse_ts` also accepts up to six fraction digits.
"""

from __future__ import annotations

import os
import re
import secrets
import stat
import unicodedata
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from kalkan import resources
from kalkan.errors import StateError, UnsafeInputError
from kalkan.util.safe_io import atomic_write_text, read_text_bounded

__all__ = [
    "LATEST_NAME",
    "RUNS_DIR_ENV",
    "RUN_ID_PATTERN",
    "SLUG_MAX_LENGTH",
    "TIMESTAMP_PATTERN",
    "as_utc",
    "format_ts",
    "is_run_id",
    "new_run_id",
    "parse_ts",
    "read_latest",
    "resolve_run",
    "run_dir_path",
    "runs_root",
    "slugify",
    "utc_now",
    "write_latest",
]

#: Environment variable that overrides the runs root.
RUNS_DIR_ENV: Final = "KALKAN_RUNS_DIR"
#: File in the runs root that holds the newest run ID.
LATEST_NAME: Final = "LATEST"
SLUG_MAX_LENGTH: Final = 24
#: The only accepted run ID form. The slug starts and ends with a letter or a digit.
RUN_ID_PATTERN: Final = re.compile(
    r"\A[0-9]{8}T[0-9]{6}Z-[a-z0-9](?:[a-z0-9-]{0,22}[a-z0-9])?-[0-9a-f]{4}\Z"
)
#: UTC timestamp text: second precision, optional fraction, ``Z`` suffix.
TIMESTAMP_PATTERN: Final = re.compile(
    r"\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z\Z"
)

_SLUG_FALLBACK: Final = "target"
_LATEST_MAX_BYTES: Final = 1024
_NOT_SLUG: Final = re.compile(r"[^a-z0-9]+")
# Letters that Unicode decomposition does not reduce to ASCII.
_TRANSLITERATION: Final = str.maketrans(
    {"ı": "i", "ß": "ss", "æ": "ae", "œ": "oe", "ø": "o", "đ": "d", "ð": "d", "ł": "l", "þ": "th"}
)


# ---------------------------------------------------------------------------------------------
# Timestamps


def utc_now() -> datetime:
    """Return the current time as an aware UTC datetime."""
    return datetime.now(UTC)


def as_utc(moment: datetime | None = None) -> datetime:
    """Return ``moment`` as an aware UTC datetime; None means now. A naive value counts as UTC."""
    if moment is None:
        return utc_now()
    if moment.tzinfo is None:
        return moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC)


def format_ts(moment: datetime | None = None) -> str:
    """Return ``moment`` (default: now) as ``YYYY-MM-DDTHH:MM:SSZ``."""
    return as_utc(moment).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_ts(text: object) -> datetime:
    """Parse a kalkan timestamp. Raises ``ValueError`` for any other text."""
    if not isinstance(text, str) or TIMESTAMP_PATTERN.fullmatch(text) is None:
        raise ValueError("not a UTC timestamp of the form YYYY-MM-DDTHH:MM:SSZ")
    base = datetime.strptime(text[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=UTC)
    fraction = text[19:-1]
    if fraction:
        base = base.replace(microsecond=int(fraction[1:].ljust(6, "0")))
    return base


# ---------------------------------------------------------------------------------------------
# Run IDs


def slugify(name: str) -> str:
    """Return the run ID slug of a target folder name.

    The name is lower-cased, accents are removed (``Gölge`` becomes ``golge``), every run of
    other characters becomes one ``-``, and the result is cut to 24 characters. A name without
    letters or digits gives ``target``.
    """
    folded = unicodedata.normalize("NFKD", name.lower().translate(_TRANSLITERATION))
    ascii_text = folded.encode("ascii", "ignore").decode("ascii")
    slug = _NOT_SLUG.sub("-", ascii_text).strip("-")
    slug = slug[:SLUG_MAX_LENGTH].strip("-")
    return slug or _SLUG_FALLBACK


def is_run_id(value: object) -> bool:
    """Return True when ``value`` is a well-formed run ID."""
    return isinstance(value, str) and RUN_ID_PATTERN.fullmatch(value) is not None


def new_run_id(slug: str, now: datetime | None = None) -> str:
    """Return a new run ID for ``slug`` (passed through :func:`slugify`) at ``now``."""
    stamp = as_utc(now).strftime("%Y%m%dT%H%M%SZ")
    run_id = f"{stamp}-{slugify(slug)}-{secrets.token_hex(2)}"
    if not is_run_id(run_id):  # pragma: no cover - slugify guarantees the form
        raise StateError("could not build a valid run ID")
    return run_id


# ---------------------------------------------------------------------------------------------
# Runs root and LATEST


def runs_root() -> Path:
    """Return the runs root: ``KALKAN_RUNS_DIR`` when set and not empty, else the runs root of
    the plugin marker, else ``<home>/runs`` (:func:`kalkan.resources.runs_root`)."""
    override = os.environ.get(RUNS_DIR_ENV)
    if override:
        return Path(override).expanduser().resolve()
    return resources.runs_root()


def run_dir_path(run_id: str, root: Path | None = None) -> Path:
    """Return ``<runs root>/<run_id>`` without checking that it exists.

    Raises :class:`~kalkan.errors.StateError` when ``run_id`` is not a well-formed run ID.
    """
    if not is_run_id(run_id):
        raise StateError("invalid run ID (expected <yyyymmddThhmmssZ>-<slug>-<4 hex>)")
    return (root if root is not None else runs_root()) / run_id


def write_latest(run_id: str, root: Path | None = None) -> None:
    """Record ``run_id`` in ``<runs root>/LATEST`` (atomic write)."""
    if not is_run_id(run_id):
        raise StateError("invalid run ID (expected <yyyymmddThhmmssZ>-<slug>-<4 hex>)")
    base = root if root is not None else runs_root()
    base.mkdir(parents=True, exist_ok=True)
    atomic_write_text(base / LATEST_NAME, run_id + "\n")


def read_latest(root: Path | None = None) -> str | None:
    """Return the run ID in ``<runs root>/LATEST``, or None when the file does not exist.

    Raises :class:`~kalkan.errors.StateError` when the file cannot be read safely or does not
    hold a well-formed run ID.
    """
    path = (root if root is not None else runs_root()) / LATEST_NAME
    try:
        os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise StateError("runs/LATEST cannot be read") from exc
    try:
        text = read_text_bounded(path, _LATEST_MAX_BYTES)
    except UnsafeInputError as exc:
        raise StateError(f"runs/LATEST cannot be read safely: {exc}") from None
    run_id = text.strip()
    if not is_run_id(run_id):
        raise StateError("runs/LATEST does not hold a valid run ID")
    return run_id


def resolve_run(run_id: str | None = None, root: Path | None = None) -> Path:
    """Return the folder of run ``run_id``; None means the run named in ``runs/LATEST``.

    Raises :class:`~kalkan.errors.StateError` when no run is recorded, when the run ID is not
    well-formed, or when the run folder does not exist, is a link or is not a folder.
    """
    base = root if root is not None else runs_root()
    if run_id is None:
        run_id = read_latest(base)
        if run_id is None:
            raise StateError("no run found; start one with: kalkan run init <target>")
    directory = run_dir_path(run_id, base)
    try:
        info = os.lstat(directory)
    except FileNotFoundError:
        raise StateError(f"run not found: {run_id}") from None
    except OSError as exc:
        raise StateError(f"run folder cannot be read: {run_id}") from exc
    if stat.S_ISLNK(info.st_mode) or (
        getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
    ):
        raise StateError(f"run folder must not be a link: {run_id}")
    if not stat.S_ISDIR(info.st_mode):
        raise StateError(f"run folder is not a folder: {run_id}")
    return directory
