# SPDX-License-Identifier: MIT
"""Agent task queue with leases (docs/ENGINE-SPEC.md, sections 11 and 18).

Files of a task live in ``runs/<run-id>/tasks/<task-id>/``: the engine writes ``input.json``
and ``prompt.md``, the agent writes ``result.json``.

- :func:`create_task` adds a ``pending`` task. A budget-counted task needs a free budget slot.
- :func:`claim` first returns expired leases to ``pending``. It then leases up to ``limit``
  pending tasks of the current phase (or of ``phases``) whose dependencies are settled
  (``done``, ``dead`` or ``skipped``), highest priority first, then by sequence.
- :func:`complete` validates ``result.json``, runs the type handler and marks the task
  ``done``. The same result again is a no-op (status ``unchanged``). An invalid result counts
  an attempt, is renamed to ``result.rejected-<attempt>.json`` (so a retry starts clean and the
  same file never counts twice), and the task goes back to ``pending``, or to ``dead`` after
  ``max_attempts``. A dead task stays dead.
- :func:`fail` counts an attempt for a task the agent could not do.
- :func:`release`, :func:`release_owner` and :func:`expire_leases` return leases without
  counting an attempt. :func:`resume` recovers a run after a crash.

Concurrent-complete guard. :func:`complete` runs the handler outside the run lock, in three
steps: (1) under the lock it reads the result, decides about a no-op and sets the marker
``completing = {pid, host, token, started_at}`` in the task record; (2) without the lock it
validates the result and runs the handler; (3) under the lock it checks that the marker still
carries its token, records the outcome and clears the marker. A second ``complete`` of the same
task, ``fail``, ``release``, ``claim`` and lease expiry leave a task with a live marker alone.
A marker is stale (a crashed completer) when its PID is not alive on this host, or when it is
older than 30 minutes; a stale marker is replaced, and the handler runs again. Handlers are
idempotent, so the repeated run is safe.
"""

from __future__ import annotations

import contextlib
import copy
import hashlib
import os
import re
import secrets
import time
from collections.abc import Iterable
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Final

from kalkan.errors import KalkanError, StateError, UnsafeInputError, ValidationError
from kalkan.run import budget, handlers, ids, lock
from kalkan.run.state import (
    PHASES,
    SETTLED_TASK_STATUSES,
    TASK_STATUSES,
    TASK_TYPES,
    RunContext,
    Transaction,
    parse_task_id,
    task_id_for,
    transaction,
)
from kalkan.schema.loader import shared_schema
from kalkan.schema.validator import enforce_json_text_limits, parse_json_text, validate
from kalkan.util.safe_io import atomic_write_json, atomic_write_text, read_text_bounded

__all__ = [
    "AGENTS",
    "COMPLETING_STALE_SECONDS",
    "DEFAULT_LEASE_TTL_SECONDS",
    "ERROR_DETAILS_MAX",
    "INPUT_NAME",
    "PROMPT_NAME",
    "RESULT_MAX_BYTES",
    "RESULT_NAME",
    "agent_for",
    "claim",
    "complete",
    "create_task",
    "expire_leases",
    "fail",
    "get_task",
    "is_valid_owner",
    "release",
    "release_owner",
    "resume",
    "task_counts",
]

DEFAULT_LEASE_TTL_SECONDS: Final = 45 * 60
COMPLETING_STALE_SECONDS: Final = 30 * 60
RESULT_MAX_BYTES: Final = 5 * 1024 * 1024
ERROR_DETAILS_MAX: Final = 20
INPUT_NAME: Final = "input.json"
PROMPT_NAME: Final = "prompt.md"
RESULT_NAME: Final = "result.json"

#: Claude Code subagent name per task type (``.claude/agents/<name>.md``).
AGENTS: Final = {
    "recon": "kalkan-recon",
    "hunt": "kalkan-hunter",
    "critic": "kalkan-critic",
    "verify": "kalkan-verifier",
    "review": "kalkan-reviewer",
    "consolidate": "kalkan-consolidator",
    "polish": "kalkan-polisher",
    "sca_reach": "kalkan-sca-reach",
    "poc_build": "kalkan-poc-builder",
    "translate": "kalkan-translator",
}

_OWNER: Final = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._@:-]{0,63}\Z")
_REASON_MAX: Final = 2000
_DEDUPE_KEY_MAX: Final = 512
_RENAME_ATTEMPTS: Final = 5
_RENAME_DELAY_SECONDS: Final = 0.05


# ---------------------------------------------------------------------------------------------
# Small helpers


def agent_for(task_type: str) -> str:
    """Return the subagent name for ``task_type``."""
    if task_type not in AGENTS:
        raise ValueError("unknown task type")
    return AGENTS[task_type]


def is_valid_owner(owner: object) -> bool:
    """Return True for a lease owner name: 1 to 64 of ``A-Z a-z 0-9 . _ @ : -``."""
    return isinstance(owner, str) and _OWNER.fullmatch(owner) is not None


def _check_task_id(task_id: object) -> tuple[int, str]:
    parsed = parse_task_id(task_id)
    if parsed is None:
        raise StateError("invalid task ID (expected T<number>-<type>)")
    return parsed


def _get(state: dict[str, Any], task_id: str) -> dict[str, Any]:
    task = state["tasks"].get(task_id)
    if task is None:
        raise StateError(f"unknown task: {task_id}")
    return task


def get_task(ctx: RunContext, task_id: str) -> dict[str, Any]:
    """Return a copy of the task record from the context snapshot, with an ``id`` field."""
    _check_task_id(task_id)
    view = copy.deepcopy(_get(ctx.state, task_id))
    view["id"] = task_id
    return view


def _seq_order(state: dict[str, Any]) -> list[str]:
    return sorted(state["tasks"], key=lambda task_id: state["tasks"][task_id]["seq"])


def _marker_live(task: dict[str, Any]) -> bool:
    """Return True while another ``complete`` of this task is in progress (module docstring)."""
    marker = task.get("completing")
    if not isinstance(marker, dict):
        return False
    try:
        started = ids.parse_ts(marker.get("started_at"))
    except ValueError:
        return False
    if (ids.utc_now() - started).total_seconds() > COMPLETING_STALE_SECONDS:
        return False
    if marker.get("host") == lock.hostname():
        return lock.pid_alive(marker.get("pid"))
    return True


def _busy(task_id: str, task: dict[str, Any]) -> StateError:
    pid = task["completing"].get("pid")
    return StateError(f"task {task_id} is being completed by another process (pid {pid})")


def _exists(path: Path) -> bool:
    try:
        os.lstat(path)
    except FileNotFoundError:
        return False
    return True


def _sha256_of_file(path: Path) -> str | None:
    try:
        return hashlib.sha256(read_text_bounded(path, RESULT_MAX_BYTES).encode("utf-8")).hexdigest()
    except UnsafeInputError:
        return None


def _set_aside(result_path: Path, attempt: int, digest: str | None) -> str | None:
    """Rename a rejected result to ``result.rejected-<attempt>.json``; return the new name."""
    if not _exists(result_path):
        return None
    if digest is not None and _sha256_of_file(result_path) != digest:
        return None  # the agent wrote a new result meanwhile: keep it for the next attempt
    name = f"result.rejected-{attempt}.json"
    for count in range(1, _RENAME_ATTEMPTS + 1):
        try:
            os.replace(result_path, result_path.with_name(name))
            return name
        except PermissionError:
            if count == _RENAME_ATTEMPTS:
                return None
            time.sleep(_RENAME_DELAY_SECONDS * count)
        except OSError:
            return None
    return None  # pragma: no cover - the loop always returns


def _settled(state: dict[str, Any], task: dict[str, Any]) -> bool:
    return all(
        state["tasks"][dependency]["status"] in SETTLED_TASK_STATUSES
        for dependency in task["depends_on"]
    )


def _claim_item(ctx: RunContext, task_id: str, task_type: str) -> dict[str, str]:
    directory = ctx.task_dir(task_id).absolute()
    return {
        "id": task_id,
        "type": task_type,
        "agent": AGENTS[task_type],
        "prompt_file": (directory / PROMPT_NAME).as_posix(),
        "result_file": (directory / RESULT_NAME).as_posix(),
    }


def task_counts(state: dict[str, Any]) -> dict[str, Any]:
    """Return ``{total, by_status, by_type}``; ``by_type`` lists only types that have tasks."""
    by_status = dict.fromkeys(TASK_STATUSES, 0)
    by_type: dict[str, dict[str, int]] = {}
    for task in state["tasks"].values():
        by_status[task["status"]] += 1
        counts = by_type.setdefault(task["type"], dict.fromkeys(TASK_STATUSES, 0))
        counts[task["status"]] += 1
    return {
        "total": len(state["tasks"]),
        "by_status": by_status,
        "by_type": {name: by_type[name] for name in TASK_TYPES if name in by_type},
    }


# ---------------------------------------------------------------------------------------------
# Create


def create_task(
    ctx: RunContext,
    type: str,  # noqa: A002 - the documented parameter name
    phase: str,
    input: dict[str, Any],  # noqa: A002 - the documented parameter name
    *,
    priority: int = 50,
    depends_on: Iterable[str] = (),
    prompt_text: str | None = None,
    max_attempts: int = 3,
    counts_against_budget: bool = True,
    dedupe_key: str | None = None,
    meta: dict[str, Any] | None = None,
    now: datetime | None = None,
) -> str:
    """Create a ``pending`` task and return its ID ``T<seq>-<type>``.

    Writes ``tasks/<id>/input.json`` and, when ``prompt_text`` is given, ``tasks/<id>/prompt.md``.
    A budget-counted task increments ``budget.used_agent_tasks``; when no budget is left the call
    raises :class:`~kalkan.errors.StateError` (the planner checks
    :func:`kalkan.run.budget.available` first). With ``dedupe_key``, an existing task with the
    same key is returned instead of a new one (handlers use it to stay idempotent). ``meta`` is
    a small JSON object for the planner (for example the critic wave). Raises ``ValueError`` for
    invalid arguments and StateError for an unknown dependency.
    """
    task_type, task_input = type, input
    if task_type not in TASK_TYPES:
        raise ValueError("unknown task type")
    if phase not in PHASES or phase == "done":
        raise ValueError("phase must be a phase other than done")
    if not isinstance(task_input, dict):
        raise ValueError("task input must be a JSON object")
    if isinstance(priority, bool) or not isinstance(priority, int) or not 0 <= priority <= 100:
        raise ValueError("priority must be an integer from 0 to 100")
    if isinstance(max_attempts, bool) or not isinstance(max_attempts, int) or max_attempts < 1:
        raise ValueError("max_attempts must be a positive integer")
    if prompt_text is not None and not isinstance(prompt_text, str):
        raise ValueError("prompt_text must be a string")
    if dedupe_key is not None and (
        not isinstance(dedupe_key, str) or not 0 < len(dedupe_key) <= _DEDUPE_KEY_MAX
    ):
        raise ValueError("dedupe_key must be a string of 1 to 512 characters")
    if meta is not None and not isinstance(meta, dict):
        raise ValueError("meta must be a JSON object")
    dependencies = list(dict.fromkeys(depends_on))
    for dependency in dependencies:
        _check_task_id(dependency)

    with transaction(ctx, now=now) as tx:
        state = tx.state
        if dedupe_key is not None:
            for task_id in _seq_order(state):
                if state["tasks"][task_id]["dedupe_key"] == dedupe_key:
                    return task_id
        for dependency in dependencies:
            _get(state, dependency)
        if counts_against_budget and budget.remaining(state) < 1:
            maximum = state["budget"]["max_agent_tasks"]
            raise StateError(f"the agent task budget is used up ({maximum} tasks)")
        seq = state["next_task_seq"]
        task_id = task_id_for(seq, task_type)
        directory = ctx.task_dir(task_id)
        directory.mkdir(parents=True, exist_ok=True)
        # A crash between these writes and the state save can leave files of an unsaved task
        # with the same ID. Remove what this task does not write.
        for stale in (RESULT_NAME, *(() if prompt_text is not None else (PROMPT_NAME,))):
            if _exists(directory / stale):
                os.unlink(directory / stale)
        atomic_write_json(directory / INPUT_NAME, task_input)
        if prompt_text is not None:
            atomic_write_text(directory / PROMPT_NAME, prompt_text)
        timestamp = ids.format_ts(now)
        state["tasks"][task_id] = {
            "seq": seq,
            "type": task_type,
            "phase": phase,
            "status": "pending",
            "priority": priority,
            "attempts": 0,
            "max_attempts": max_attempts,
            "lease": None,
            "created_at": timestamp,
            "updated_at": timestamp,
            "completed_at": None,
            "result_sha256": None,
            "error": None,
            "depends_on": dependencies,
            "counts_against_budget": bool(counts_against_budget),
            "dedupe_key": dedupe_key,
            "completing": None,
            "meta": copy.deepcopy(meta) if meta is not None else {},
        }
        state["next_task_seq"] = seq + 1
        if counts_against_budget:
            state["budget"]["used_agent_tasks"] += 1
        tx.event("task_created", task=task_id, type=task_type, phase=phase)
    return task_id


# ---------------------------------------------------------------------------------------------
# Leases


def _expire(tx: Transaction, moment: datetime) -> list[str]:
    state = tx.state
    expired: list[str] = []
    timestamp = ids.format_ts(moment)
    for task_id in _seq_order(state):
        task = state["tasks"][task_id]
        if task["status"] != "leased":
            continue
        if ids.parse_ts(task["lease"]["expires_at"]) > moment or _marker_live(task):
            continue
        owner = task["lease"]["owner"]
        task.update(status="pending", lease=None, updated_at=timestamp)
        tx.event("lease_expired", task=task_id, owner=owner)
        expired.append(task_id)
    return expired


def expire_leases(ctx: RunContext, *, now: datetime | None = None) -> list[str]:
    """Return expired leases to ``pending`` and return their task IDs (no attempt counted)."""
    moment = ids.as_utc(now)
    with transaction(ctx, now=now) as tx:
        return _expire(tx, moment)


def claim(
    ctx: RunContext,
    owner: str,
    limit: int,
    *,
    types: Iterable[str] | None = None,
    phases: Iterable[str] | None = None,
    now: datetime | None = None,
    ttl_seconds: int | None = None,
) -> list[dict[str, str]]:
    """Lease up to ``limit`` ready tasks to ``owner`` and return them.

    Expired leases go back to ``pending`` first. A ready task is ``pending``, has no live
    completion marker, has only settled dependencies and its ``phase`` is the current run phase
    (or one of ``phases`` when given). ``types`` limits the task types. Order: priority (high
    first), then sequence. The lease lasts ``ttl_seconds`` (default: ``options.lease_ttl_seconds``
    or 45 minutes).

    Each item is ``{id, type, agent, prompt_file, result_file}`` with absolute POSIX paths.
    """
    if not is_valid_owner(owner):
        raise ValueError("owner must be 1 to 64 characters of A-Z a-z 0-9 . _ @ : -")
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 0:
        raise ValueError("limit must be a non-negative integer")
    type_filter = None if types is None else frozenset(types)
    if type_filter is not None and not type_filter <= set(TASK_TYPES):
        raise ValueError("unknown task type in types")
    phase_filter = None if phases is None else frozenset(phases)
    if phase_filter is not None and not phase_filter <= set(PHASES):
        raise ValueError("unknown phase in phases")
    if ttl_seconds is not None and (
        isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int) or ttl_seconds < 1
    ):
        raise ValueError("ttl_seconds must be a positive integer")
    moment = ids.as_utc(now)

    with transaction(ctx, now=now) as tx:
        state = tx.state
        _expire(tx, moment)
        wanted = phase_filter if phase_filter is not None else frozenset({state["phase"]})
        ready: list[tuple[int, int, str]] = []
        for task_id, task in state["tasks"].items():
            if (
                task["status"] == "pending"
                and (type_filter is None or task["type"] in type_filter)
                and task["phase"] in wanted
                and not _marker_live(task)
                and _settled(state, task)
            ):
                ready.append((-task["priority"], task["seq"], task_id))
        ready.sort()
        ttl = ttl_seconds or state["options"].get("lease_ttl_seconds", DEFAULT_LEASE_TTL_SECONDS)
        expires_at = ids.format_ts(moment + timedelta(seconds=ttl))
        timestamp = ids.format_ts(moment)
        items: list[dict[str, str]] = []
        for _, _, task_id in ready[:limit]:
            task = state["tasks"][task_id]
            task.update(
                status="leased",
                lease={"owner": owner, "expires_at": expires_at},
                completing=None,
                updated_at=timestamp,
            )
            tx.event("task_leased", task=task_id, owner=owner, expires_at=expires_at)
            items.append(_claim_item(ctx, task_id, task["type"]))
    return items


def release(ctx: RunContext, task_id: str, *, now: datetime | None = None) -> bool:
    """Return a leased task to ``pending`` without counting an attempt.

    Returns False when the task is not leased. Raises StateError while another process
    completes the task.
    """
    _check_task_id(task_id)
    with transaction(ctx, now=now) as tx:
        task = _get(tx.state, task_id)
        if task["status"] != "leased":
            return False
        if _marker_live(task):
            raise _busy(task_id, task)
        owner = task["lease"]["owner"]
        task.update(status="pending", lease=None, updated_at=ids.format_ts(now))
        tx.event("task_released", task=task_id, owner=owner)
    return True


def release_owner(ctx: RunContext, owner: str, *, now: datetime | None = None) -> list[str]:
    """Return every task leased by ``owner`` to ``pending``; return their IDs.

    Tasks that another process is completing keep their lease.
    """
    released: list[str] = []
    with transaction(ctx, now=now) as tx:
        timestamp = ids.format_ts(now)
        for task_id in _seq_order(tx.state):
            task = tx.state["tasks"][task_id]
            if task["status"] != "leased" or task["lease"]["owner"] != owner:
                continue
            if _marker_live(task):
                continue
            task.update(status="pending", lease=None, updated_at=timestamp)
            tx.event("task_released", task=task_id, owner=owner)
            released.append(task_id)
    return released


# ---------------------------------------------------------------------------------------------
# Complete and fail


def _read_result(path: Path, task_id: str) -> tuple[str | None, str | None, str | None]:
    """Return ``(text, sha256, read_error)``. Raises StateError when the file does not exist."""
    if not _exists(path):
        raise StateError(f"result file not found: tasks/{task_id}/{RESULT_NAME}")
    try:
        text = read_text_bounded(path, RESULT_MAX_BYTES)
    except UnsafeInputError as exc:
        return None, None, str(exc)
    return text, hashlib.sha256(text.encode("utf-8")).hexdigest(), None


def _check_result(task_id: str, task_type: str, text: str) -> dict[str, Any]:
    enforce_json_text_limits(text)
    result = parse_json_text(text)
    errors = validate(result, shared_schema(f"task-{task_type}"), "$result")
    if errors:
        raise ValidationError(
            f"the result of {task_id} does not match task-{task_type}.schema.json", errors
        )
    if result.get("task_id") != task_id:
        raise ValidationError(
            f"the result of {task_id} names another task",
            [f"$result.task_id: must be {task_id}"],
        )
    return result


def _clear_marker(ctx: RunContext, task_id: str, token: str) -> None:
    with transaction(ctx) as tx:
        task = tx.state["tasks"].get(task_id)
        marker = task.get("completing") if task else None
        if isinstance(marker, dict) and marker.get("token") == token:
            task["completing"] = None


def complete(ctx: RunContext, task_id: str, *, now: datetime | None = None) -> dict[str, Any]:
    """Validate ``tasks/<id>/result.json``, run the type handler and mark the task ``done``.

    Returns ``{id, type, status, result_sha256}`` with status ``done``, or ``unchanged`` when
    the task is already done with the same result hash. Raises
    :class:`~kalkan.errors.ValidationError` for an invalid result (after recording the failed
    attempt, see the module docstring) and :class:`~kalkan.errors.StateError` when the result
    file is missing, the task is dead or skipped, another process completes it, or the task is
    done with a different result.
    """
    task_type = _check_task_id(task_id)[1]
    result_path = ctx.task_dir(task_id) / RESULT_NAME
    token = secrets.token_hex(8)

    # Step 1: decide under the lock and set the completion marker.
    with transaction(ctx, now=now) as tx:
        task = _get(tx.state, task_id)
        status = task["status"]
        if status in ("dead", "skipped"):
            raise StateError(f"task {task_id} is {status}; it does not accept results")
        if _marker_live(task):
            raise _busy(task_id, task)
        try:
            text, digest, read_error = _read_result(result_path, task_id)
        except StateError:
            if status != "leased":
                raise
            # The agent that held the lease returned without a result (for example its Write
            # was denied). Count the attempt, so that the task cannot be retried forever.
            text, digest, read_error = None, None, f"result file not found: tasks/{task_id}/"
            read_error += RESULT_NAME
        if status == "done":
            if digest is not None and digest == task["result_sha256"]:
                return {
                    "id": task_id,
                    "type": task_type,
                    "status": "unchanged",
                    "result_sha256": digest,
                }
            raise StateError(f"task {task_id} is already done with a different result")
        if task["completing"] is not None:
            tx.event("completion_marker_replaced", task=task_id, pid=task["completing"]["pid"])
        task["completing"] = {
            "pid": os.getpid(),
            "host": lock.hostname(),
            "token": token,
            "started_at": ids.format_ts(),
        }
        task["updated_at"] = ids.format_ts(now)
        view = copy.deepcopy(task)
        view["id"] = task_id

    # Step 2: validate and run the handler without the lock.
    failure: ValidationError | None = None
    try:
        if read_error is not None or text is None:
            raise ValidationError(f"the result file of {task_id} cannot be used", [str(read_error)])
        result = _check_result(task_id, task_type, text)
        handlers.get_handler(task_type)(ctx, view, result)
    except ValidationError as exc:
        failure = exc
    except BaseException:
        # Keep the original error. A marker that cannot be cleared becomes stale when this
        # process ends.
        with contextlib.suppress(KalkanError):
            _clear_marker(ctx, task_id, token)
        raise

    # Step 3: record the outcome under the lock.
    with transaction(ctx, now=now) as tx:
        task = _get(tx.state, task_id)
        marker = task.get("completing")
        if not isinstance(marker, dict) or marker.get("token") != token:
            raise StateError(f"another process took over the completion of task {task_id}")
        timestamp = ids.format_ts(now)
        task.update(completing=None, lease=None, updated_at=timestamp)
        if failure is None:
            task.update(status="done", error=None, result_sha256=digest, completed_at=timestamp)
            tx.event("task_completed", task=task_id, type=task_type, sha256=digest)
        else:
            details = [str(item) for item in failure.errors[:ERROR_DETAILS_MAX]] or [str(failure)]
            task["attempts"] += 1
            task["status"] = "dead" if task["attempts"] >= task["max_attempts"] else "pending"
            task["error"] = {
                "kind": "invalid_result",
                "message": str(failure),
                "details": details,
                "at": timestamp,
            }
            moved = _set_aside(result_path, task["attempts"], digest)
            tx.event(
                "task_rejected",
                task=task_id,
                type=task_type,
                attempts=task["attempts"],
                status=task["status"],
                errors=details[:5],
                moved_to=moved,
            )
            attempts, max_attempts, new_status = (
                task["attempts"],
                task["max_attempts"],
                task["status"],
            )
    if failure is not None:
        raise ValidationError(
            f"{failure} (attempt {attempts} of {max_attempts}; the task is {new_status} now)",
            failure.errors,
        )
    return {"id": task_id, "type": task_type, "status": "done", "result_sha256": digest}


def fail(
    ctx: RunContext, task_id: str, reason: str, *, now: datetime | None = None
) -> dict[str, Any]:
    """Record that the agent could not do the task: count an attempt, then ``pending`` or
    ``dead``.

    Returns ``{id, status, attempts, max_attempts}``. A dead task stays dead (no attempt is
    counted). Raises StateError for a ``done`` or ``skipped`` task and while another process
    completes the task.
    """
    _check_task_id(task_id)
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError("reason must be a non-empty string")
    message = reason.strip()[:_REASON_MAX]
    with transaction(ctx, now=now) as tx:
        task = _get(tx.state, task_id)
        if task["status"] in ("done", "skipped"):
            raise StateError(f"task {task_id} is {task['status']}; it cannot fail")
        if task["status"] != "dead":
            if _marker_live(task):
                raise _busy(task_id, task)
            timestamp = ids.format_ts(now)
            task["attempts"] += 1
            task["status"] = "dead" if task["attempts"] >= task["max_attempts"] else "pending"
            task["error"] = {
                "kind": "agent_failure",
                "message": message,
                "details": [],
                "at": timestamp,
            }
            task.update(lease=None, completing=None, updated_at=timestamp)
            _set_aside(ctx.task_dir(task_id) / RESULT_NAME, task["attempts"], None)
            tx.event(
                "task_failed",
                task=task_id,
                attempts=task["attempts"],
                status=task["status"],
                reason=message[:200],
            )
        outcome = {
            "id": task_id,
            "status": task["status"],
            "attempts": task["attempts"],
            "max_attempts": task["max_attempts"],
        }
    return outcome


# ---------------------------------------------------------------------------------------------
# Resume


def resume(ctx: RunContext, *, now: datetime | None = None) -> dict[str, list[Any]]:
    """Recover a run after a crash.

    For each leased task: when ``result.json`` exists, :func:`complete` it; otherwise
    :func:`release` it. Then return expired leases to ``pending``. Returns
    ``{completed, unchanged, rejected, released, busy, expired}``. ``rejected`` items are
    ``{id, status, attempts, errors}``; ``busy`` items are ``{id, reason}``.
    """
    report: dict[str, list[Any]] = {
        "completed": [],
        "unchanged": [],
        "rejected": [],
        "released": [],
        "busy": [],
        "expired": [],
    }
    state = ctx.reload()
    leased = [
        task_id for task_id in _seq_order(state) if state["tasks"][task_id]["status"] == "leased"
    ]
    for task_id in leased:
        try:
            if _exists(ctx.task_dir(task_id) / RESULT_NAME):
                outcome = complete(ctx, task_id, now=now)
                key = "completed" if outcome["status"] == "done" else "unchanged"
                report[key].append(task_id)
            elif release(ctx, task_id, now=now):
                report["released"].append(task_id)
        except ValidationError as exc:
            task = ctx.state["tasks"][task_id]
            report["rejected"].append(
                {
                    "id": task_id,
                    "status": task["status"],
                    "attempts": task["attempts"],
                    "errors": [str(item) for item in exc.errors[:ERROR_DETAILS_MAX]],
                }
            )
        except StateError as exc:
            report["busy"].append({"id": task_id, "reason": str(exc)})
    report["expired"] = expire_leases(ctx, now=now)
    return report
