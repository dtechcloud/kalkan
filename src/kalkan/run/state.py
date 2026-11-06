# SPDX-License-Identifier: MIT
"""Run state ``runs/<run-id>/state.json``: shape, checks, atomic save and the run context
(docs/ENGINE-SPEC.md, section 11).

``kalkan/schemas/state.schema.json`` covers the top-level shape. :func:`check_state` adds the
checks that the restricted schema language cannot express: the ``phases`` and ``tasks`` maps,
upper bounds, real dates, task ID and sequence consistency, and dependencies that point only to
older tasks (so the dependency graph has no cycles). Unknown fields are rejected everywhere; a
new field needs a change to the schema and to :func:`check_state` in the same commit.

Every save is atomic and sets ``updated_at``. Every read-modify-write runs in
:func:`transaction`, which holds the run lock, loads a fresh state, saves it only when it
changed, appends the recorded events and refreshes :attr:`RunContext.state`.

Task record (one value of ``tasks``)::

    {"seq": 1, "type": "recon", "phase": "recon", "status": "pending", "priority": 50,
     "attempts": 0, "max_attempts": 3, "lease": null, "created_at": "...", "updated_at": "...",
     "completed_at": null, "result_sha256": null, "error": null, "depends_on": [],
     "counts_against_budget": true, "dedupe_key": null, "completing": null, "meta": {}}

- ``lease`` is ``{owner, expires_at}`` exactly when ``status`` is ``leased``.
- ``error`` is null or ``{kind, message, details (at most 20 strings), at}``.
- ``completing`` is null or ``{pid, host, token, started_at}`` while ``task complete`` runs the
  type handler (see :mod:`kalkan.run.queue`).

Step record (one value of ``phases.<phase>.steps``): ``{status, detail}`` plus the optional
``started_at``, ``finished_at`` and the phase-engine fields ``pid``, ``host``,
``timeout_seconds``, ``attempts`` and ``duration_seconds`` (docs/PHASES.md section 2). A
``running`` step carries the ``pid`` of the process that runs it. The optional top-level
``incomplete_pending`` holds a reason that makes the run incomplete once the report is written
(docs/PHASES.md section 7).

Run mode: the optional ``options.mode`` is ``agents`` or ``tools-only`` (:data:`RUN_MODES`). A
state without it is an ``agents`` run (:func:`run_mode`). A ``tools-only`` run skips the agent
phases (``kalkan audit --tools-only``, docs/PHASES.md section 3).
"""

from __future__ import annotations

import contextlib
import os
import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Final

from kalkan.errors import StateError, UnsafeInputError
from kalkan.run import budget, events, ids
from kalkan.run.lock import DEFAULT_TIMEOUT_SECONDS, run_lock
from kalkan.schema.loader import shared_schema
from kalkan.schema.validator import JsonStructureError, parse_json_text, property_path, validate
from kalkan.util.safe_io import atomic_write_json, dumps_json, read_text_bounded
from kalkan.util.text import safe_quote

__all__ = [
    "DOCKER_MODES",
    "LANGUAGES",
    "MAX_PARALLEL_LIMIT",
    "MODE_AGENTS",
    "MODE_TOOLS_ONLY",
    "PHASES",
    "PHASE_STATUSES",
    "RUN_MODES",
    "SCHEMA_VERSION",
    "SETTLED_TASK_STATUSES",
    "SOURCE_DIRNAME",
    "STATE_NAME",
    "STEP_STATUSES",
    "TARGET_DIRNAME",
    "TASKS_DIRNAME",
    "TASK_ID_PATTERN",
    "TASK_STATUSES",
    "TASK_TYPES",
    "RunContext",
    "Transaction",
    "check_state",
    "load_context",
    "load_state",
    "new_phases",
    "parse_task_id",
    "run_mode",
    "save_state",
    "task_id_for",
    "transaction",
]

#: Phases in order.
PHASES: Final = (
    "prep",
    "deterministic",
    "sca",
    "recon",
    "plan",
    "hunt",
    "validate",
    "poc",
    "merge",
    "report",
    "done",
)
PHASE_STATUSES: Final = ("pending", "running", "done", "skipped", "failed")
STEP_STATUSES: Final = ("pending", "running", "done", "skipped", "failed")
TASK_TYPES: Final = (
    "recon",
    "hunt",
    "critic",
    "verify",
    "review",
    "consolidate",
    "polish",
    "sca_reach",
    "poc_build",
    "translate",
)
TASK_STATUSES: Final = ("pending", "leased", "done", "failed", "dead", "skipped")
#: A dependency in one of these statuses no longer blocks a task.
SETTLED_TASK_STATUSES: Final = frozenset({"done", "dead", "skipped"})
LANGUAGES: Final = ("tr", "en")
DOCKER_MODES: Final = ("auto", "on", "off")
#: ``options.mode``: ``agents`` (the default; a state without the field) or ``tools-only``.
MODE_AGENTS: Final = "agents"
MODE_TOOLS_ONLY: Final = "tools-only"
RUN_MODES: Final = (MODE_AGENTS, MODE_TOOLS_ONLY)
MAX_PARALLEL_LIMIT: Final = 32
SCHEMA_VERSION: Final = 1

STATE_NAME: Final = "state.json"
TARGET_DIRNAME: Final = "target"
SOURCE_DIRNAME: Final = "source"
TASKS_DIRNAME: Final = "tasks"

#: ``T<at least 4 digits>-<type>``.
TASK_ID_PATTERN: Final = re.compile(r"\AT([0-9]{4,})-(" + "|".join(TASK_TYPES) + r")\Z")
_STEP_NAME: Final = re.compile(r"\A[a-z0-9][a-z0-9_.:-]{0,63}\Z")
_SHA256: Final = re.compile(r"\A[0-9a-f]{64}\Z")
_STATE_MAX_BYTES: Final = 32 * 1024 * 1024
_MAX_ERRORS: Final = 100
_ERROR_DETAILS_MAX: Final = 20
_DEDUPE_KEY_MAX: Final = 512

_PHASE_KEYS: Final = frozenset({"status", "started_at", "finished_at", "steps"})
_STEP_REQUIRED: Final = frozenset({"status", "detail"})
#: Optional step fields of the phase engine (docs/PHASES.md section 2): the process that runs the
#: step, its time limit, the number of starts and the duration of the last run.
_STEP_KEYS: Final = _STEP_REQUIRED | {
    "started_at",
    "finished_at",
    "pid",
    "host",
    "timeout_seconds",
    "attempts",
    "duration_seconds",
}
_TASK_KEYS: Final = frozenset(
    {
        "seq",
        "type",
        "phase",
        "status",
        "priority",
        "attempts",
        "max_attempts",
        "lease",
        "created_at",
        "updated_at",
        "completed_at",
        "result_sha256",
        "error",
        "depends_on",
        "counts_against_budget",
        "dedupe_key",
        "completing",
        "meta",
    }
)
_LEASE_KEYS: Final = frozenset({"owner", "expires_at"})
_ERROR_KEYS: Final = frozenset({"kind", "message", "details", "at"})
_COMPLETING_KEYS: Final = frozenset({"pid", "host", "token", "started_at"})


# ---------------------------------------------------------------------------------------------
# Task IDs and the initial phase map


def task_id_for(seq: int, task_type: str) -> str:
    """Return the task ID ``T<seq, at least 4 digits>-<task_type>``."""
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
        raise ValueError("task sequence must be a positive integer")
    if task_type not in TASK_TYPES:
        raise ValueError(f"unknown task type: {safe_quote(task_type)}")
    return f"T{seq:04d}-{task_type}"


def parse_task_id(value: object) -> tuple[int, str] | None:
    """Return ``(seq, type)`` of a well-formed task ID, else None."""
    if not isinstance(value, str):
        return None
    match = TASK_ID_PATTERN.fullmatch(value)
    if match is None:
        return None
    return int(match.group(1)), match.group(2)


def new_phases() -> dict[str, dict[str, Any]]:
    """Return a phase map with every phase ``pending`` and no steps."""
    return {
        name: {"status": "pending", "started_at": None, "finished_at": None, "steps": {}}
        for name in PHASES
    }


def run_mode(state: Mapping[str, Any]) -> str:
    """Return the run mode of ``state``: ``options.mode``, else ``agents``."""
    options = state.get("options")
    mode = options.get("mode") if isinstance(options, Mapping) else None
    return mode if mode in RUN_MODES else MODE_AGENTS


# ---------------------------------------------------------------------------------------------
# Checks


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_ts(value: object) -> bool:
    try:
        ids.parse_ts(value)
    except ValueError:
        return False
    return True


def _check_keys(
    record: dict[str, Any],
    path: str,
    allowed: frozenset[str],
    required: frozenset[str],
    errors: list[str],
) -> None:
    for key in sorted(required - set(record)):
        errors.append(f"{path}: missing required field {safe_quote(key)}")
    for key in record:
        if key not in allowed:
            errors.append(f"{path}: unexpected field {safe_quote(key)}")


def _check_optional_ts(value: object, path: str, errors: list[str]) -> None:
    if value is not None and not _is_ts(value):
        errors.append(f"{path}: expected null or a UTC timestamp")


def _check_phases(phases: dict[str, Any], errors: list[str]) -> None:
    if set(phases) != set(PHASES):
        errors.append(f"$state.phases: must hold exactly the phases {', '.join(PHASES)}")
    for name in PHASES:
        if name not in phases:
            continue
        record = phases[name]
        path = f"$state.phases.{name}"
        if not isinstance(record, dict):
            errors.append(f"{path}: expected object")
            continue
        _check_keys(record, path, _PHASE_KEYS, _PHASE_KEYS, errors)
        if record.get("status") not in PHASE_STATUSES:
            errors.append(f"{path}.status: expected one of {', '.join(PHASE_STATUSES)}")
        _check_optional_ts(record.get("started_at"), f"{path}.started_at", errors)
        _check_optional_ts(record.get("finished_at"), f"{path}.finished_at", errors)
        steps = record.get("steps")
        if not isinstance(steps, dict):
            errors.append(f"{path}.steps: expected object")
            continue
        for step_name, step in steps.items():
            step_path = property_path(f"{path}.steps", step_name)
            if not isinstance(step_name, str) or _STEP_NAME.fullmatch(step_name) is None:
                errors.append(f"{step_path}: invalid step name")
            if not isinstance(step, dict):
                errors.append(f"{step_path}: expected object")
                continue
            _check_keys(step, step_path, _STEP_KEYS, _STEP_REQUIRED, errors)
            if step.get("status") not in STEP_STATUSES:
                errors.append(f"{step_path}.status: expected one of {', '.join(STEP_STATUSES)}")
            if not isinstance(step.get("detail"), str):
                errors.append(f"{step_path}.detail: expected string")
            _check_optional_ts(step.get("started_at"), f"{step_path}.started_at", errors)
            _check_optional_ts(step.get("finished_at"), f"{step_path}.finished_at", errors)
            _check_step_extras(step, step_path, errors)


def _check_step_extras(step: dict[str, Any], path: str, errors: list[str]) -> None:
    """Check the optional phase-engine fields of a step record."""
    pid = step.get("pid")
    if pid is not None and (not _is_int(pid) or pid < 0):
        errors.append(f"{path}.pid: expected null or a non-negative integer")
    host = step.get("host")
    if host is not None and not isinstance(host, str):
        errors.append(f"{path}.host: expected null or string")
    for name in ("timeout_seconds", "attempts"):
        value = step.get(name)
        if value is not None and (not _is_int(value) or value < 0):
            errors.append(f"{path}.{name}: expected null or a non-negative integer")
    duration = step.get("duration_seconds")
    if duration is not None and (
        isinstance(duration, bool) or not isinstance(duration, int | float) or duration < 0
    ):
        errors.append(f"{path}.duration_seconds: expected null or a non-negative number")
    if step.get("status") == "running" and not _is_int(pid):
        errors.append(f"{path}.pid: a running step needs the pid of its process")


def _check_task(
    task_id: str,
    task: dict[str, Any],
    seq: int,
    task_type: str,
    tasks: dict[str, Any],
    errors: list[str],
) -> None:
    path = property_path("$state.tasks", task_id)
    _check_keys(task, path, _TASK_KEYS, _TASK_KEYS, errors)
    if task.get("seq") != seq or not _is_int(task.get("seq")):
        errors.append(f"{path}.seq: must equal the sequence number in the task ID")
    if task.get("type") != task_type:
        errors.append(f"{path}.type: must equal the type in the task ID")
    if task.get("phase") not in PHASES or task.get("phase") == "done":
        errors.append(f"{path}.phase: expected a phase other than done")
    status = task.get("status")
    if status not in TASK_STATUSES:
        errors.append(f"{path}.status: expected one of {', '.join(TASK_STATUSES)}")
    priority = task.get("priority")
    if not _is_int(priority) or not 0 <= priority <= 100:
        errors.append(f"{path}.priority: expected an integer from 0 to 100")
    attempts = task.get("attempts")
    if not _is_int(attempts) or attempts < 0:
        errors.append(f"{path}.attempts: expected a non-negative integer")
    max_attempts = task.get("max_attempts")
    if not _is_int(max_attempts) or max_attempts < 1:
        errors.append(f"{path}.max_attempts: expected a positive integer")

    lease = task.get("lease")
    if status == "leased":
        if not isinstance(lease, dict):
            errors.append(f"{path}.lease: a leased task needs {{owner, expires_at}}")
        else:
            _check_keys(lease, f"{path}.lease", _LEASE_KEYS, _LEASE_KEYS, errors)
            if not isinstance(lease.get("owner"), str) or not lease.get("owner"):
                errors.append(f"{path}.lease.owner: expected a non-empty string")
            if not _is_ts(lease.get("expires_at")):
                errors.append(f"{path}.lease.expires_at: expected a UTC timestamp")
    elif lease is not None:
        errors.append(f"{path}.lease: must be null unless the task is leased")

    for name in ("created_at", "updated_at"):
        if not _is_ts(task.get(name)):
            errors.append(f"{path}.{name}: expected a UTC timestamp")
    _check_optional_ts(task.get("completed_at"), f"{path}.completed_at", errors)
    digest = task.get("result_sha256")
    if digest is not None and (not isinstance(digest, str) or not _SHA256.fullmatch(digest)):
        errors.append(f"{path}.result_sha256: expected null or 64 lower-case hex characters")

    error = task.get("error")
    if error is not None:
        if not isinstance(error, dict):
            errors.append(f"{path}.error: expected null or object")
        else:
            _check_keys(error, f"{path}.error", _ERROR_KEYS, _ERROR_KEYS, errors)
            for name in ("kind", "message"):
                if not isinstance(error.get(name), str):
                    errors.append(f"{path}.error.{name}: expected string")
            details = error.get("details")
            if (
                not isinstance(details, list)
                or len(details) > _ERROR_DETAILS_MAX
                or not all(isinstance(item, str) for item in details)
            ):
                errors.append(f"{path}.error.details: expected at most 20 strings")
            if not _is_ts(error.get("at")):
                errors.append(f"{path}.error.at: expected a UTC timestamp")

    depends_on = task.get("depends_on")
    if not isinstance(depends_on, list):
        errors.append(f"{path}.depends_on: expected array")
    else:
        if len(set(map(str, depends_on))) != len(depends_on):
            errors.append(f"{path}.depends_on: entries must be unique")
        for dependency in depends_on:
            parsed = parse_task_id(dependency)
            if parsed is None or dependency not in tasks:
                errors.append(f"{path}.depends_on: unknown task {safe_quote(dependency)}")
            elif parsed[0] >= seq:
                errors.append(f"{path}.depends_on: {dependency} is not an older task")

    if not isinstance(task.get("counts_against_budget"), bool):
        errors.append(f"{path}.counts_against_budget: expected boolean")
    key = task.get("dedupe_key")
    if key is not None and (not isinstance(key, str) or not 0 < len(key) <= _DEDUPE_KEY_MAX):
        errors.append(f"{path}.dedupe_key: expected null or a string of 1 to 512 characters")
    if not isinstance(task.get("meta"), dict):
        errors.append(f"{path}.meta: expected object")

    completing = task.get("completing")
    if completing is not None:
        if not isinstance(completing, dict):
            errors.append(f"{path}.completing: expected null or object")
        else:
            _check_keys(
                completing, f"{path}.completing", _COMPLETING_KEYS, _COMPLETING_KEYS, errors
            )
            if not _is_int(completing.get("pid")):
                errors.append(f"{path}.completing.pid: expected integer")
            for name in ("host", "token"):
                if not isinstance(completing.get(name), str):
                    errors.append(f"{path}.completing.{name}: expected string")
            if not _is_ts(completing.get("started_at")):
                errors.append(f"{path}.completing.started_at: expected a UTC timestamp")


def check_state(state: object) -> list[str]:
    """Return the errors of a run state; an empty list means valid (at most 100 errors)."""
    errors = validate(state, shared_schema("state"), "$state")
    if errors:
        return errors
    assert isinstance(state, dict)  # the schema requires an object
    found: list[str] = []
    if state["options"]["max_parallel"] > MAX_PARALLEL_LIMIT:
        found.append(f"$state.options.max_parallel: must be at most {MAX_PARALLEL_LIMIT}")
    if state["budget"]["reserve_validation_ratio"] > 1:
        found.append("$state.budget.reserve_validation_ratio: must be at most 1")
    for name in ("created_at", "updated_at"):
        if not _is_ts(state[name]):
            found.append(f"$state.{name}: not a valid date and time")
    _check_phases(state["phases"], found)
    next_seq = state["next_task_seq"]
    tasks = state["tasks"]
    for task_id, task in tasks.items():
        parsed = parse_task_id(task_id)
        if parsed is None:
            found.append(f"{property_path('$state.tasks', task_id)}: invalid task ID")
            continue
        if not isinstance(task, dict):
            found.append(f"{property_path('$state.tasks', task_id)}: expected object")
            continue
        if parsed[0] >= next_seq:
            found.append(
                f"{property_path('$state.tasks', task_id)}: sequence must be below next_task_seq"
            )
        _check_task(task_id, task, parsed[0], parsed[1], tasks, found)
        if len(found) >= _MAX_ERRORS:
            break
    return found[:_MAX_ERRORS]


def _invalid(errors: list[str], message: str = "state.json is invalid") -> StateError:
    shown = "; ".join(errors[:3])
    more = f" (and {len(errors) - 3} more)" if len(errors) > 3 else ""
    return StateError(f"{message}: {shown}{more}")


# ---------------------------------------------------------------------------------------------
# Load and save


def load_state(run_dir: str | os.PathLike[str]) -> dict[str, Any]:
    """Read and check ``<run_dir>/state.json``.

    Raises :class:`~kalkan.errors.StateError` when the file is missing, cannot be read safely,
    is not JSON, or fails :func:`check_state`.
    """
    path = Path(run_dir) / STATE_NAME
    try:
        os.lstat(path)
    except FileNotFoundError:
        raise StateError(f"the run state is missing: {path.as_posix()}") from None
    except OSError as exc:
        raise StateError("the run state cannot be read") from exc
    try:
        text = read_text_bounded(path, _STATE_MAX_BYTES)
    except UnsafeInputError as exc:
        raise StateError(f"state.json cannot be read safely: {exc}") from None
    try:
        state = parse_json_text(text)
    except JsonStructureError:
        raise StateError("state.json is not valid JSON") from None
    errors = check_state(state)
    if errors:
        raise _invalid(errors)
    _normalize_profile(state)
    return state


def _normalize_profile(state: dict[str, Any]) -> None:
    """Turn a profile name from before 1.6.0 (``quick``) into its canonical name (``fast``)."""
    options = state.get("options")
    if isinstance(options, dict) and isinstance(options.get("profile"), str):
        options["profile"] = budget.PROFILE_ALIASES.get(options["profile"], options["profile"])


def save_state(
    run_dir: str | os.PathLike[str], state: dict[str, Any], *, now: datetime | None = None
) -> None:
    """Set ``updated_at``, check the state and write ``<run_dir>/state.json`` atomically.

    Raises :class:`~kalkan.errors.StateError` and writes nothing when the state is invalid.
    """
    state["updated_at"] = ids.format_ts(now)
    errors = check_state(state)
    if errors:
        raise _invalid(errors, "refusing to save an invalid run state")
    atomic_write_json(Path(run_dir) / STATE_NAME, state)


# ---------------------------------------------------------------------------------------------
# Run context and transactions


@dataclass
class RunContext:
    """A run folder and a snapshot of its state.

    The snapshot is refreshed by :meth:`reload` and by every :func:`transaction`. Mutations
    never change :attr:`state` directly; they run in :func:`transaction`.
    """

    run_dir: Path
    state: dict[str, Any]

    @classmethod
    def load(cls, run_dir: str | os.PathLike[str]) -> RunContext:
        """Return the context of the run in ``run_dir``."""
        directory = Path(run_dir)
        return cls(directory, load_state(directory))

    def reload(self) -> dict[str, Any]:
        """Read the state again and return it."""
        self.state = load_state(self.run_dir)
        return self.state

    @property
    def run_id(self) -> str:
        return self.state["run_id"]

    @property
    def phase(self) -> str:
        return self.state["phase"]

    @property
    def target_dir(self) -> Path:
        """The filtered, neutralized copy of the target: ``<run>/target``."""
        return self.run_dir / self.state["target"]["copy"]

    @property
    def source_dir(self) -> Path:
        """The private history copy ``<run>/source`` (a URL clone, or a mirror of a local work
        tree; docs/ENGINE-SPEC.md section 10). It may not exist. Never the original folder."""
        return self.run_dir / SOURCE_DIRNAME

    @property
    def options(self) -> dict[str, Any]:
        return self.state["options"]

    @property
    def lang(self) -> str:
        return self.state["options"]["lang"]

    @property
    def tasks_dir(self) -> Path:
        return self.run_dir / TASKS_DIRNAME

    def task_dir(self, task_id: str) -> Path:
        """Return ``<run>/tasks/<task_id>``. Raises StateError for a malformed task ID."""
        if parse_task_id(task_id) is None:
            raise StateError("invalid task ID (expected T<number>-<type>)")
        return self.tasks_dir / task_id


def load_context(run_id: str | None = None, *, root: Path | None = None) -> RunContext:
    """Return the context of run ``run_id`` (None: the run in ``runs/LATEST``)."""
    return RunContext.load(ids.resolve_run(run_id, root))


class Transaction:
    """The fresh state inside :func:`transaction`, and the events to append after the save."""

    def __init__(self, state: dict[str, Any]) -> None:
        self.state = state
        self._events: list[tuple[str, dict[str, Any]]] = []

    def event(self, kind: str, **fields: Any) -> None:
        """Record an event. It is appended to ``events.jsonl`` after the state is saved."""
        self._events.append((kind, fields))

    @property
    def pending_events(self) -> list[tuple[str, dict[str, Any]]]:
        return list(self._events)


@contextlib.contextmanager
def transaction(
    ctx: RunContext,
    *,
    now: datetime | None = None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
) -> Iterator[Transaction]:
    """Run a read-modify-write of the state under the run lock.

    Yields a :class:`Transaction` with a freshly loaded state. When the block ends normally, the
    state is saved (only when it changed), the recorded events are appended and ``ctx.state`` is
    replaced. When the block raises, nothing is saved and no event is written.
    """
    with run_lock(ctx.run_dir, timeout_seconds):
        state = load_state(ctx.run_dir)
        before = dumps_json(state)
        tx = Transaction(state)
        yield tx
        if dumps_json(state) != before:
            save_state(ctx.run_dir, state, now=now)
        for kind, fields in tx.pending_events:
            events.append_event(ctx.run_dir, kind, **fields)
        ctx.state = state
