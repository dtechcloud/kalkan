# SPDX-License-Identifier: MIT
"""The coverage ledger of a run: ``coverage-ledger.json`` (docs/PHASES.md sections 3 and 4).

The ledger uses the Cloudflare format (:mod:`kalkan.findings.ledger`). Every write sorts the
units by ``coverage_id`` and runs :func:`kalkan.findings.ledger.validate_ledger` first; an invalid
ledger is never written. Every read-modify-write runs in :func:`ledger_transaction`, which holds
the run lock (through :func:`kalkan.run.state.transaction`), so concurrent ``task complete``
handlers never lose an update.

Unit state changes follow the Cloudflare state table:

- :func:`assign`: ``in_progress`` with a fresh owner and empty live evidence.
- :func:`defer`: unassigned ``deferred`` with empty evidence and a reason in ``unresolved``.
- :func:`reset_to_planned`: unassigned ``planned`` (a failed assignment, Cloudflare "leaves that
  unit planned for reassignment").
- :func:`archive_attempt`: append the live terminal state to ``attempts`` with the critic's
  reason, raise ``wave`` and return the unit to ``planned`` with empty live evidence. The
  live sibling closure (``kalkan.closure``) goes with it: its check stays in the attempt.

Each unit carries one bookkeeping field ``kalkan`` (allowed by the Cloudflare format, outside the
semantic fields): the recon surface IDs, the surface kind, the weakest auth, the number of
deterministic hints, the batching group and the origin of the unit. A ``blocked`` unit that the
critic closed from sibling coverage also has ``kalkan.closure`` (:mod:`kalkan.run.handlers.critic`,
:func:`live_closure`).
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterator
from typing import Any, Final

from kalkan.errors import ValidationError
from kalkan.findings.ledger import canonical_coverage_id, is_canonical_ref, validate_ledger
from kalkan.run.cleaning import clean_text, safe_paths, unique
from kalkan.run.runfiles import LEDGER_NAME, read_json, write_json
from kalkan.run.state import RunContext, Transaction, transaction
from kalkan.util.safe_io import dumps_json
from kalkan.util.text import utf16_key

__all__ = [
    "CLOSURE_KEY",
    "MAX_REF_UNITS",
    "FAST_BOUNDARY",
    "FAST_SUBSYSTEM",
    "archive_attempt",
    "assign",
    "attack_class_ref",
    "defer",
    "drop_closure",
    "ledger_transaction",
    "live_closure",
    "load_ledger",
    "make_unit",
    "reset_to_planned",
    "save_ledger",
    "sort_units",
]

#: The fixed subsystem identity of the fast profile (Cloudflare rule). The identity strings keep
#: the profile name of kalkan before 1.6.0 (``quick``), so that the coverage IDs of a run stay the
#: same when a newer engine resumes it.
FAST_SUBSYSTEM: Final = "profile/quick/all-in-scope-subsystems"
#: The coarsened boundary identity of a fast unit (all boundaries of one subsystem).
FAST_BOUNDARY: Final = "profile/quick/all-trust-boundaries"
#: Canonical references stay well below the 1024 UTF-16 code unit limit.
MAX_REF_UNITS: Final = 900
_MAX_STARTING_PATHS: Final = 50
#: Bookkeeping key of a closure from sibling coverage (``unit["kalkan"]``).
CLOSURE_KEY: Final = "closure"
_LIVE_FIELDS: Final = ("reviewed_paths", "local_checks", "result_fingerprints", "unresolved")


def attack_class_ref(class_slug: str) -> str:
    """Return the attack-class block reference ``knowledge/classes/<slug>.md#Summary``."""
    return f"knowledge/classes/{class_slug}.md#Summary"


def load_ledger(ctx: RunContext) -> list[dict[str, Any]]:
    """Return the units of ``coverage-ledger.json`` (an empty list when there is none)."""
    document = read_json(ctx.run_dir / LEDGER_NAME, 5 * 1024 * 1024)
    if not isinstance(document, list):
        return []
    return [unit for unit in document if isinstance(unit, dict)]


def sort_units(units: list[dict[str, Any]]) -> None:
    """Sort units in place by ``coverage_id`` in UTF-16 order (the validator's order)."""
    units.sort(key=lambda unit: utf16_key(str(unit.get("coverage_id", ""))))


def save_ledger(ctx: RunContext, units: list[dict[str, Any]]) -> None:
    """Sort, validate and write the ledger atomically.

    Raises :class:`~kalkan.errors.ValidationError` (with the validator messages) and writes
    nothing when the ledger is invalid.
    """
    sort_units(units)
    errors = validate_ledger(units)
    if errors:
        raise ValidationError("the coverage ledger update would make the ledger invalid", errors)
    write_json(ctx.run_dir / LEDGER_NAME, units)


@contextlib.contextmanager
def ledger_transaction(ctx: RunContext) -> Iterator[tuple[Transaction, list[dict[str, Any]]]]:
    """Yield ``(tx, units)`` under the run lock; save the ledger when the units changed.

    ``tx`` is the state :class:`~kalkan.run.state.Transaction` of the same lock; a state change
    in the block is saved after the ledger. When the block or the ledger validation raises,
    neither the ledger nor the state is written.
    """
    with transaction(ctx) as tx:
        units = load_ledger(ctx)
        before = dumps_json(units)
        yield tx, units
        if dumps_json(units) != before:
            save_ledger(ctx, units)


def _ref(value: object) -> str:
    text = clean_text(value, MAX_REF_UNITS)
    return text if is_canonical_ref(text) else ""


def make_unit(
    *,
    surface: str,
    boundary: str,
    subsystem: str,
    class_slug: str,
    starting_paths: list[str],
    companion_blocks: list[str],
    wave: int,
    bookkeeping: dict[str, Any],
) -> dict[str, Any] | None:
    """Return a new ``planned`` unit, or None when a reference or the paths are unusable.

    The human fields equal the canonical references (the attack class uses the slug), so one
    semantic tuple always maps to one ``coverage_id``.
    """
    refs = {
        "surface": _ref(surface),
        "boundary": _ref(boundary),
        "subsystem": _ref(subsystem),
        "attack_class": attack_class_ref(class_slug),
    }
    paths = safe_paths(starting_paths)[:_MAX_STARTING_PATHS]
    if not all(refs.values()) or not paths:
        return None
    return {
        "coverage_id": canonical_coverage_id(refs),
        "canonical_refs": refs,
        "surface": refs["surface"],
        "boundary": refs["boundary"],
        "subsystem": refs["subsystem"],
        "attack_class": class_slug,
        "starting_paths": paths,
        "ordinary_attack_class_block": refs["attack_class"],
        "selected_companion_blocks": unique(
            block for block in companion_blocks if clean_text(block) == block
        ),
        "excluded_blocks": [],
        "prior_status": "none",
        "attempts": [],
        "wave": max(1, int(wave)),
        "status": "planned",
        "agent_id": None,
        "reviewed_paths": [],
        "local_checks": [],
        "result_fingerprints": [],
        "unresolved": [],
        "kalkan": bookkeeping,
    }


def _clear_live(unit: dict[str, Any]) -> None:
    for name in _LIVE_FIELDS:
        unit[name] = []


def assign(unit: dict[str, Any], agent_id: str, wave: int) -> None:
    """Give a unit to a fresh owner: ``in_progress`` with empty live evidence."""
    _clear_live(unit)
    unit["status"] = "in_progress"
    unit["agent_id"] = agent_id
    unit["wave"] = max(int(unit.get("wave", 1)), int(wave))


def defer(unit: dict[str, Any], reason: str) -> None:
    """Make a unit unassigned ``deferred`` with empty evidence and ``reason``."""
    _clear_live(unit)
    unit["status"] = "deferred"
    unit["agent_id"] = None
    unit["unresolved"] = [clean_text(reason) or "deferred"]


def reset_to_planned(unit: dict[str, Any]) -> None:
    """Return a unit to unassigned ``planned`` with empty evidence (a failed assignment)."""
    _clear_live(unit)
    unit["status"] = "planned"
    unit["agent_id"] = None


def live_closure(unit: dict[str, Any]) -> dict[str, Any] | None:
    """Return ``kalkan.closure`` of a ``covered`` unit whose live checks hold the check of that
    critic, else None (no closure, or the hunter's result replaced the closed state)."""
    bookkeeping = unit.get("kalkan")
    closure = bookkeeping.get(CLOSURE_KEY) if isinstance(bookkeeping, dict) else None
    if unit.get("status") != "covered" or not isinstance(closure, dict):
        return None
    task = closure.get("task")
    if not isinstance(task, str):
        return None
    checks = unit.get("local_checks")
    agent = task.lower()
    found = any(
        isinstance(check, dict) and check.get("agent_id") == agent
        for check in (checks if isinstance(checks, list) else [])
    )
    return closure if found else None


def drop_closure(unit: dict[str, Any]) -> None:
    """Remove ``kalkan.closure``: the live state that it described is gone."""
    if isinstance(unit.get("kalkan"), dict):
        unit["kalkan"].pop(CLOSURE_KEY, None)


def archive_attempt(unit: dict[str, Any], reason: str, new_wave: int) -> bool:
    """Archive the live terminal state of a unit for reassignment (Cloudflare rules).

    Only ``covered``, ``candidate`` and ``blocked`` units with an owner are archived. The unit
    then has ``wave = new_wave`` (above every archived wave), unassigned ``planned`` state and
    empty live evidence. Returns False (and changes nothing) for other units or when
    ``new_wave`` does not exceed the current wave.
    """
    if unit.get("status") not in ("covered", "candidate", "blocked") or not unit.get("agent_id"):
        return False
    wave = int(unit.get("wave", 1))
    if new_wave <= wave:
        return False
    unit.setdefault("attempts", []).append(
        {
            "wave": wave,
            "status": unit["status"],
            "agent_id": unit["agent_id"],
            "reviewed_paths": list(unit.get("reviewed_paths", [])),
            "local_checks": [dict(check) for check in unit.get("local_checks", [])],
            "result_fingerprints": list(unit.get("result_fingerprints", [])),
            "unresolved": list(unit.get("unresolved", [])),
            "reassignment_reason": clean_text(reason) or "reassigned by the coverage critic",
        }
    )
    reset_to_planned(unit)
    unit["wave"] = new_wave
    drop_closure(unit)
    return True
