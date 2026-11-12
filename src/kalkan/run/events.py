# SPDX-License-Identifier: MIT
"""Append-only engine event log ``runs/<run-id>/events.jsonl`` (docs/ENGINE-SPEC.md, section 11).

Each line is one compact JSON object ``{"ts": ..., "kind": ..., <fields>}``. Call
:func:`append_event` while holding the run lock (:func:`kalkan.run.lock.run_lock`), so that the
lines of two processes never mix. The log is informational: the state file is the source of
truth, and a crash between a state save and its event loses only the event.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Final

from kalkan.run.ids import format_ts
from kalkan.util.safe_io import read_text_bounded

__all__ = ["EVENTS_NAME", "append_event", "read_events"]

EVENTS_NAME: Final = "events.jsonl"
_READ_MAX_BYTES: Final = 64 * 1024 * 1024
_KIND: Final = re.compile(r"[a-z][a-z0-9_]{0,63}")
_LONE_SURROGATE: Final = re.compile(r"[\ud800-\udfff]")


def _escape_surrogate(match: re.Match[str]) -> str:
    return f"\\u{ord(match.group()):04x}"


def append_event(run_dir: str | os.PathLike[str], kind: str, **fields: Any) -> dict[str, Any]:
    """Append one event line to ``<run_dir>/events.jsonl`` and return the record.

    ``kind`` is a lower-case identifier such as ``task_completed``. ``fields`` must be JSON
    values and must not contain ``ts``. The line is flushed and fsynced before the call returns.
    """
    if not isinstance(kind, str) or _KIND.fullmatch(kind) is None:
        raise ValueError("event kind must be a lower-case identifier")
    if "ts" in fields:
        raise ValueError("event fields must not contain 'ts'")
    record: dict[str, Any] = {"ts": format_ts(), "kind": kind, **fields}
    line = json.dumps(record, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    line = _LONE_SURROGATE.sub(_escape_surrogate, line) + "\n"
    with open(Path(run_dir) / EVENTS_NAME, "a", encoding="utf-8", newline="\n") as handle:
        handle.write(line)
        handle.flush()
        os.fsync(handle.fileno())
    return record


def read_events(run_dir: str | os.PathLike[str]) -> list[dict[str, Any]]:
    """Return the events of a run in file order. Malformed lines are skipped.

    Returns an empty list when the log does not exist. Raises
    :class:`~kalkan.errors.UnsafeInputError` when the log is a link or larger than 64 MiB.
    """
    path = Path(run_dir) / EVENTS_NAME
    try:
        os.lstat(path)
    except FileNotFoundError:
        return []
    text = read_text_bounded(path, _READ_MAX_BYTES)
    events: list[dict[str, Any]] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if isinstance(record, dict):
            events.append(record)
    return events
