# SPDX-License-Identifier: MIT
"""``kalkan run clean <run-id>``: remove the bulky parts of a finished run (docs/ENGINE-SPEC.md,
section 10).

The parts (:data:`PARTS`) have fixed names below the run folder; nothing comes from the state:

- ``target/``: the filtered copy of the target.
- ``source/``: the private history copy (a git mirror).
- ``scans/.work/`` and ``sca/.work/``: the work folders of the scanners and the SCA tools (the
  staging copies, the temporary folders of the tools, the logs and outputs of failed tool runs).

Everything else stays: ``report/`` (the deliverables), ``state.json``, ``events.jsonl``,
``target-manifest.json``, the scanner and SCA results, ``candidates.json``, ``tasks/``,
``findings.json``, ``poc/`` and ``evidence/``.

Rules:

- A run outside the phase ``done`` is refused; ``force`` removes the parts anyway (the run
  cannot continue after that).
- Each part must lie in the run folder after the parent folders are resolved (a ``scans`` link
  that points elsewhere is skipped, never followed). :func:`kalkan.util.fs.remove_tree` removes
  the part: a link or a Windows junction inside it is removed as a link, the folder it points
  at stays. Read-only files and paths of 260 or more characters are removed too.
- The removal holds the run lock. ``cleaned.json`` records what was removed and when, and
  ``events.jsonl`` gets the event ``run_cleaned``. A cleaned run refuses the commands that would
  run it again (``run next``, ``run step``, ``run resume``, ``run reopen``, ``run answer``):
  :func:`refuse_cleaned`.
- ``dry_run`` only measures (:func:`kalkan.util.fs.tree_size`).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

from kalkan import __version__
from kalkan.errors import KalkanError, StateError
from kalkan.run import events
from kalkan.run.ids import format_ts
from kalkan.run.lock import run_lock
from kalkan.run.state import load_state
from kalkan.util.fs import TreeStats, remove_tree, tree_size
from kalkan.util.safe_io import atomic_write_json, read_text_bounded

__all__ = [
    "CLEANED_NAME",
    "PARTS",
    "CleanResult",
    "PartResult",
    "clean_run",
    "read_cleaned",
    "refuse_cleaned",
]

#: The record of a cleaned run in its folder.
CLEANED_NAME: Final = "cleaned.json"
#: The parts that ``run clean`` removes: relative path and what it is.
PARTS: Final = (
    ("target", "the copy of the target"),
    ("source", "the private history copy"),
    ("scans/.work", "the work folders of the scanners"),
    ("sca/.work", "the work folders of the SCA tools"),
)
FINISHED_PHASE: Final = "done"


@dataclass
class PartResult:
    """One part: its path relative to the run, what it is, whether it was there, the counts."""

    path: str
    what: str
    present: bool
    stats: TreeStats = field(default_factory=TreeStats)
    skipped: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-ready dict."""
        return {
            "path": self.path,
            "what": self.what,
            "present": self.present,
            "skipped": self.skipped or None,
            **self.stats.to_dict(),
        }


@dataclass
class CleanResult:
    """The outcome of :func:`clean_run`."""

    run_id: str
    run_dir: Path
    phase: str | None
    forced: bool
    dry_run: bool
    parts: list[PartResult]
    kept_bytes: int
    kept_files: int

    @property
    def total(self) -> TreeStats:
        """Return the counts of every part."""
        total = TreeStats()
        for part in self.parts:
            total.add(part.stats)
        return total

    @property
    def errors(self) -> list[str]:
        """Return the errors of every part (``<part>/<path>: <reason>``)."""
        return [f"{part.path}/{error}" for part in self.parts for error in part.stats.errors]

    def to_dict(self) -> dict[str, Any]:
        """Return the JSON document of ``run clean --json``."""
        total = self.total
        return {
            "run_id": self.run_id,
            "run_dir": self.run_dir.absolute().as_posix(),
            "phase": self.phase,
            "finished": self.phase == FINISHED_PHASE,
            "forced": self.forced,
            "dry_run": self.dry_run,
            "parts": [part.to_dict() for part in self.parts],
            "total": {"files": total.files, "bytes": total.bytes, "links": total.links},
            "kept": {"files": self.kept_files, "bytes": self.kept_bytes},
            "errors": self.errors,
        }


def read_cleaned(run_dir: str | os.PathLike[str]) -> dict[str, Any] | None:
    """Return ``cleaned.json`` of a run, or None when the run was never cleaned."""
    path = Path(run_dir) / CLEANED_NAME
    if not path.is_file():
        return None
    try:
        data = json.loads(read_text_bounded(path, 1024 * 1024))
    except (KalkanError, OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def refuse_cleaned(run_dir: str | os.PathLike[str], command: str) -> None:
    """Raise :class:`~kalkan.errors.StateError` when the run was cleaned (its target copy is
    gone, so ``command`` cannot work on it)."""
    record = read_cleaned(run_dir)
    if record is None:
        return
    when = record.get("cleaned_at") or "an earlier time"
    raise StateError(
        f"the run was cleaned at {when} (kalkan run clean): its target copy and work files are "
        f"gone, so {command} cannot run it again. Its report stays; start a new run for a new "
        "audit."
    )


def clean_run(
    run_dir: str | os.PathLike[str], *, force: bool = False, dry_run: bool = False
) -> CleanResult:
    """Remove the parts of :data:`PARTS` from the run folder ``run_dir`` (module docstring).

    Raises :class:`~kalkan.errors.StateError` for a run that is not finished (without
    ``force``) and when the run lock cannot be taken. Returns a :class:`CleanResult`; removal
    errors are in :attr:`CleanResult.errors`.
    """
    folder = Path(run_dir)
    run_id = folder.name
    try:
        phase: str | None = load_state(folder)["phase"]
    except StateError:
        phase = None
    if phase != FINISHED_PHASE and not force:
        shown = f"in the phase {phase}" if phase else "without a readable state"
        raise StateError(
            f"the run {run_id} is not finished ({shown}); its target copy may still be needed. "
            "Pass --force to clean it anyway (the run cannot continue after that)."
        )
    parts = [_part(folder, path, what) for path, what in PARTS]
    if dry_run:
        for part in parts:
            if part.present and not part.skipped:
                part.stats = tree_size(folder / part.path)
    else:
        with run_lock(folder):
            for part in parts:
                if part.present and not part.skipped:
                    part.stats = remove_tree(folder / part.path)
            if read_cleaned(folder) is None or any(p.present and not p.skipped for p in parts):
                _record(folder, parts, force)  # a clean that removed nothing keeps the record
    kept = _kept(folder, parts, dry_run)
    return CleanResult(run_id, folder, phase, force, dry_run, parts, kept.bytes, kept.files)


def _part(run_dir: Path, path: str, what: str) -> PartResult:
    candidate = run_dir / path
    present = os.path.lexists(candidate)
    if not present:
        return PartResult(path, what, False)
    if not _inside(run_dir, candidate.parent):
        return PartResult(path, what, True, skipped="its parent folder is a link out of the run")
    return PartResult(path, what, True)


def _inside(root: Path, folder: Path) -> bool:
    """True when ``folder``, with every link resolved, is ``root`` or below it."""
    base = os.path.normcase(os.path.realpath(root))
    real = os.path.normcase(os.path.realpath(folder))
    return real == base or real.startswith(base.rstrip(os.sep) + os.sep)


def _record(run_dir: Path, parts: list[PartResult], force: bool) -> None:
    removed = [part.to_dict() for part in parts if part.present and not part.skipped]
    total = TreeStats()
    for part in parts:
        total.add(part.stats)
    record = {
        "cleaned_at": format_ts(),
        "kalkan_version": __version__,
        "forced": force,
        "parts": removed,
        "files": total.files,
        "bytes": total.bytes,
        "errors": [error for part in parts for error in part.stats.errors][:20],
    }
    atomic_write_json(run_dir / CLEANED_NAME, record)
    events.append_event(
        run_dir,
        "run_cleaned",
        parts=[part["path"] for part in removed],
        files=total.files,
        bytes=total.bytes,
        forced=force,
    )


def _kept(run_dir: Path, parts: list[PartResult], dry_run: bool) -> TreeStats:
    """Return the size of what stays in the run folder."""
    whole = tree_size(run_dir)
    if not dry_run:
        return whole
    kept = TreeStats(whole.files, whole.bytes, whole.links, whole.folders)
    for part in parts:
        kept.files -= part.stats.files
        kept.bytes -= part.stats.bytes
        kept.links -= part.stats.links
    return kept
