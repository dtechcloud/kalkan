# SPDX-License-Identifier: MIT
"""``candidates.json``: the candidates of all deterministic engines (ENGINE-SPEC 4, 10, 13.1).

File format::

    {
      "schema_version": 1,
      "candidates": [<candidate record>, ...],
      "warnings": ["<source>: <warning>", ...],
      "sources": {"<source>": {"count": 3, "ids": ["CAND-...", ...], "updated_at": "..."}}
    }

:func:`merge_candidates` updates the file under the run lock (:func:`kalkan.run.lock.run_lock`)
and writes it atomically:

- A source is an engine name (``trivy``, ``matcher``) or another producer (``sca``). Running a
  source again replaces its earlier candidates and warnings.
- Candidates are deduplicated by ``id``. Two sources can report the same ID; the record stays
  while any source still reports it. The newest record of an ID wins.
- Candidate records stay schema-clean: no source field is added to them. ``sources`` records
  which IDs came from which source.
- A record without a valid ``CAND-`` ID is skipped with a warning. Each source keeps at most
  :data:`MAX_WARNINGS_PER_SOURCE` warnings.
- Candidates are sorted by engine, file, start line, rule ID and ID, so the file is stable.

Do not call :func:`merge_candidates` while holding the run lock: the lock is not re-entrant.
"""

from __future__ import annotations

import copy
import json
import os
import re
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from kalkan.errors import StateError, UnsafeInputError
from kalkan.util.safe_io import atomic_write_json, read_bounded

__all__ = [
    "CANDIDATES_NAME",
    "MAX_WARNINGS_PER_SOURCE",
    "SCHEMA_VERSION",
    "candidates_path",
    "load_candidates",
    "merge_candidates",
]

CANDIDATES_NAME = "candidates.json"
SCHEMA_VERSION = 1
MAX_WARNINGS_PER_SOURCE = 500
#: The largest candidates.json that is read.
MAX_CANDIDATES_BYTES = 256 * 1024 * 1024

_ID = re.compile(r"CAND-[0-9A-F]{16}")
_SOURCE = re.compile(r"[a-z0-9][a-z0-9-]*")


def candidates_path(run_dir: str | os.PathLike[str]) -> Path:
    """Return ``<run>/candidates.json``."""
    return Path(run_dir) / CANDIDATES_NAME


def _empty() -> dict[str, Any]:
    return {"schema_version": SCHEMA_VERSION, "candidates": [], "warnings": [], "sources": {}}


def load_candidates(run_dir: str | os.PathLike[str]) -> dict[str, Any]:
    """Return the ``candidates.json`` document of a run; an empty document when it is missing.

    Raises :class:`~kalkan.errors.StateError` when the file exists but cannot be read safely or
    is not a candidates document.
    """
    path = candidates_path(run_dir)
    try:
        os.lstat(path)
    except FileNotFoundError:
        return _empty()
    except OSError as exc:
        raise StateError(f"{CANDIDATES_NAME} cannot be read: {exc}") from None
    try:
        doc = json.loads(read_bounded(path, MAX_CANDIDATES_BYTES))
    except UnsafeInputError as exc:
        raise StateError(f"{CANDIDATES_NAME} cannot be read safely: {exc}") from None
    except ValueError as exc:
        raise StateError(
            f"{CANDIDATES_NAME} is not valid JSON ({exc}); delete it and run the scanners again"
        ) from None
    if (
        not isinstance(doc, dict)
        or not isinstance(doc.get("candidates"), list)
        or not isinstance(doc.get("warnings", []), list)
        or not isinstance(doc.get("sources", {}), dict)
    ):
        raise StateError(f"{CANDIDATES_NAME} is not a candidates document")
    result = _empty()
    result["candidates"] = [item for item in doc["candidates"] if _valid(item)]
    result["warnings"] = [item for item in doc.get("warnings", []) if isinstance(item, str)]
    for name, entry in doc.get("sources", {}).items():
        if isinstance(name, str) and isinstance(entry, dict):
            ids = [item for item in entry.get("ids", []) if isinstance(item, str)]
            result["sources"][name] = {
                "count": len(ids),
                "ids": ids,
                "updated_at": entry.get("updated_at"),
            }
    return result


def _valid(candidate: object) -> bool:
    return (
        isinstance(candidate, dict)
        and isinstance(candidate.get("id"), str)
        and _ID.fullmatch(candidate["id"]) is not None
    )


def _sort_key(candidate: dict[str, Any]) -> tuple[str, str, int, str, str]:
    line = candidate.get("start_line")
    return (
        str(candidate.get("engine", "")),
        str(candidate.get("file", "")),
        line if isinstance(line, int) and not isinstance(line, bool) else 0,
        str(candidate.get("rule_id", "")),
        candidate["id"],
    )


def merge_candidates(
    run_dir: Path, source: str, candidates: list[dict], warnings: list[str]
) -> int:
    """Replace the candidates and warnings of ``source`` in ``candidates.json``.

    Return the number of distinct candidates of ``source``. Raises ``ValueError`` for an
    invalid source name and :class:`~kalkan.errors.StateError` when the file is corrupt or the
    run lock stays busy.
    """
    from kalkan.run.lock import run_lock  # lazy: the run package is optional for imports

    if not isinstance(source, str) or not _SOURCE.fullmatch(source):
        raise ValueError(f"invalid candidate source name: {source!r}")
    run = Path(run_dir)
    if not run.is_dir():
        raise StateError(f"run folder not found: {run.as_posix()}")
    new_records, new_warnings = _prepare(source, candidates, warnings)
    with run_lock(run):
        doc = load_candidates(run)
        by_id = {item["id"]: item for item in doc["candidates"]}
        sources: dict[str, dict[str, Any]] = doc["sources"]
        previous = set(sources.get(source, {}).get("ids", []))
        others: set[str] = set()
        for name, entry in sources.items():
            if name != source:
                others.update(entry["ids"])
        new_ids = [item["id"] for item in new_records]
        for stale in previous - set(new_ids) - others:
            by_id.pop(stale, None)
        for item in new_records:
            by_id[item["id"]] = item
        sources[source] = {
            "count": len(new_ids),
            "ids": new_ids,
            "updated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        prefix = f"{source}: "
        kept = [item for item in doc["warnings"] if not item.startswith(prefix)]
        result = {
            "schema_version": SCHEMA_VERSION,
            "candidates": sorted(by_id.values(), key=_sort_key),
            "warnings": kept + new_warnings,
            "sources": dict(sorted(sources.items())),
        }
        atomic_write_json(candidates_path(run), result)
    return len(new_ids)


def _prepare(
    source: str, candidates: Iterable[object], warnings: Iterable[object]
) -> tuple[list[dict[str, Any]], list[str]]:
    """Deduplicate the new candidates by ID and prefix the warnings with the source."""
    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    notes = [str(item) for item in warnings]
    skipped = 0
    for item in candidates:
        if not _valid(item):
            skipped += 1
            continue
        assert isinstance(item, dict)
        if item["id"] in seen:
            continue
        seen.add(item["id"])
        records.append(copy.deepcopy(item))
    if skipped:
        notes.append(f"{skipped} record(s) without a valid candidate ID skipped")
    if len(notes) > MAX_WARNINGS_PER_SOURCE:
        extra = len(notes) - MAX_WARNINGS_PER_SOURCE + 1
        notes = notes[: MAX_WARNINGS_PER_SOURCE - 1] + [f"{extra} more warning(s) not recorded"]
    return records, [f"{source}: {note}" for note in notes]
