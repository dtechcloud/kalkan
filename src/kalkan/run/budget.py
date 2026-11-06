# SPDX-License-Identifier: MIT
"""Agent task budget: profiles, counters and reserve rules (docs/ENGINE-SPEC.md, section 11).

A profile sets ``max_agent_tasks``, the number of critic waves and the hunt batch size (the
most ledger units of one group in one hunt task):

| Profile (aliases) | max_agent_tasks | critic waves | hunt batch size | final review |
|---|---|---|---|---|
| ``fast`` (``quick``, ``hizli``) | 40 | 1 | 6 | no |
| ``standard`` (``standart``) | 150 | 2 | 4 | yes |
| ``deep`` (``derin``) | 400 | 3 | 3 | yes |

The aliases are the names before 1.6.0. They stay valid, and :func:`canonical_profile` turns
them into the canonical name.

``budget.reserve_critic`` equals the number of critic waves: one critic task per wave stays
reserved. ``budget.reserve_validation_ratio`` (default 0.45) reserves
``ceil(max_agent_tasks * ratio)`` tasks for the validation types ``verify``, ``review``,
``consolidate``, ``polish``, ``sca_reach`` and ``poc_build``. ``consolidate`` and ``polish``
tasks have no reserve of their own: the steps :data:`CONSOLIDATE_STEP` and :data:`POLISH_STEP`
run last in ``validate`` and use what is left (a group without budget stays unchecked, a batch
without budget keeps its text; docs/PHASES.md section 3). Inside that reserve, ``sca_reach``
tasks and verify tasks for deterministic tool results each get at most one quarter
(:func:`sca_reach_cap`, :func:`deterministic_verify_cap`). In profiles with a final review, one
quarter more is the review reserve (:func:`review_reserve`): the other validation types cannot
use it, so the
``review`` tasks after the verify tasks always find room. When the step :data:`REVIEW_STEP`
or the ``validate`` phase has finished, the unused part of the review reserve is free again
(for ``poc_build``). Hunter candidates keep at least one quarter of the reserve, plus the free
pool.

Hunt waves (:func:`hunt_wave_cap`): one hunt task expects :data:`VERIFY_PER_HUNT` verify tasks,
so a wave plans at most ``(remaining - critic reserve left - review reserve left) //
(1 + VERIFY_PER_HUNT)`` hunt tasks, and never more than :func:`available` allows for ``hunt``.

Only tasks with ``counts_against_budget: true`` count. ``used_agent_tasks`` grows when such a
task is created and never shrinks: a dead task still used agent runs.

Reserve rule (:func:`available`): a task type can use the free pool plus its own reserve. The
free pool is ``remaining`` minus what is left of both reserves. A reserve shrinks as tasks of its
types are created. :func:`kalkan.run.queue.create_task` enforces only ``remaining``; the planner
applies the reserves with :func:`available` or :func:`can_create`.
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Final

__all__ = [
    "CONSOLIDATE_STEP",
    "POLISH_STEP",
    "PROFILES",
    "PROFILE_ALIASES",
    "RESERVE_SHARE_DIVISOR",
    "RESERVE_VALIDATION_RATIO",
    "REVIEW_STEP",
    "VALIDATION_TASK_TYPES",
    "VERIFY_PER_HUNT",
    "Profile",
    "available",
    "batch_size",
    "can_create",
    "canonical_profile",
    "counted_tasks",
    "critic_reserve_left",
    "critic_waves",
    "deterministic_verify_cap",
    "hunt_wave_cap",
    "initial_budget",
    "remaining",
    "review_reserve",
    "review_reserve_left",
    "reviews_enabled",
    "sca_reach_cap",
    "validation_reserve",
    "validation_reserve_left",
]


@dataclass(frozen=True)
class Profile:
    """An audit depth profile."""

    name: str
    max_agent_tasks: int
    critic_waves: int
    batch_size: int
    #: The final review (``review`` tasks) runs; the Cloudflare quick profile (kalkan ``fast``)
    #: merges it into
    #: the validation (verify) pass.
    review: bool = True


PROFILES: Final[Mapping[str, Profile]] = {
    "fast": Profile("fast", 40, 1, 6, review=False),
    "standard": Profile("standard", 150, 2, 4),
    "deep": Profile("deep", 400, 3, 3),
}
#: Accepted profile names and their canonical name. ``quick`` and the Turkish names are the
#: names before 1.6.0.
PROFILE_ALIASES: Final[Mapping[str, str]] = {
    "fast": "fast",
    "quick": "fast",
    "hizli": "fast",
    "hızlı": "fast",
    "standart": "standard",
    "standard": "standard",
    "derin": "deep",
    "deep": "deep",
}
RESERVE_VALIDATION_RATIO: Final = 0.45
#: ``sca_reach`` and deterministic verify tasks each use at most ``reserve // 4``; the review
#: reserve is ``reserve // 4`` too.
RESERVE_SHARE_DIVISOR: Final = 4
#: The verify tasks that one hunt task is expected to need.
VERIFY_PER_HUNT: Final = 2
#: PoC reserve of a run whose sandbox will run: one tenth of the budget, at least two tasks.
POC_RESERVE_DIVISOR: Final = 10
POC_RESERVE_MIN: Final = 2
_POC_TYPES: Final = frozenset({"poc_build"})
#: Task types that the validation reserve protects.
VALIDATION_TASK_TYPES: Final = frozenset(
    {"verify", "review", "consolidate", "polish", "sca_reach", "poc_build"}
)
_REVIEW_TYPES: Final = frozenset({"review"})
#: The validate step that creates the ``review`` tasks (docs/PHASES.md section 3, validate).
REVIEW_STEP: Final = "review:tasks"
#: The validate step after the review: it creates the ``consolidate`` tasks (docs/PHASES.md
#: section 3).
CONSOLIDATE_STEP: Final = "consolidate"
#: The last validate step: it creates the ``polish`` tasks of a Turkish run (docs/PHASES.md
#: section 3).
POLISH_STEP: Final = "polish"
_FINISHED: Final = frozenset({"done", "skipped", "failed"})
_CRITIC_TYPES: Final = frozenset({"critic"})


def canonical_profile(name: str) -> str:
    """Return the canonical profile name (``fast``, ``standard`` or ``deep``) of an accepted
    name. Raises ``ValueError`` for an unknown name."""
    key = name.strip().lower() if isinstance(name, str) else ""
    if key not in PROFILE_ALIASES:
        raise ValueError(f"unknown profile {name!r} (use {', '.join(PROFILES)})")
    return PROFILE_ALIASES[key]


def initial_budget(profile: str, *, poc: bool = False) -> dict[str, Any]:
    """Return the ``budget`` object of a new run with ``profile`` (any accepted name).

    ``poc`` True (the PoC sandbox will run) adds ``reserve_poc`` (:func:`poc_reserve`).
    """
    chosen = PROFILES[canonical_profile(profile)]
    budget: dict[str, Any] = {
        "max_agent_tasks": chosen.max_agent_tasks,
        "used_agent_tasks": 0,
        "reserve_critic": chosen.critic_waves,
        "reserve_validation_ratio": RESERVE_VALIDATION_RATIO,
    }
    if poc:
        budget["reserve_poc"] = max(POC_RESERVE_MIN, chosen.max_agent_tasks // POC_RESERVE_DIVISOR)
    return budget


def critic_waves(state: Mapping[str, Any]) -> int:
    """Return the number of critic waves of the run's profile."""
    return PROFILES[state["options"]["profile"]].critic_waves


def batch_size(state: Mapping[str, Any]) -> int:
    """Return the most ledger units of one group in one hunt task (profile table)."""
    return PROFILES[state["options"]["profile"]].batch_size


def reviews_enabled(state: Mapping[str, Any]) -> bool:
    """Return True when the run's profile has the final review (``review`` tasks)."""
    return PROFILES[state["options"]["profile"]].review


def remaining(state: Mapping[str, Any]) -> int:
    """Return the number of budget-counted tasks that can still be created."""
    budget = state["budget"]
    return max(0, budget["max_agent_tasks"] - budget["used_agent_tasks"])


def counted_tasks(state: Mapping[str, Any], task_types: Iterable[str]) -> int:
    """Return the number of budget-counted tasks of ``task_types`` (any status)."""
    wanted = frozenset(task_types)
    return sum(
        1
        for task in state["tasks"].values()
        if task["counts_against_budget"] and task["type"] in wanted
    )


def critic_reserve_left(state: Mapping[str, Any]) -> int:
    """Return the critic reserve that no critic task has used yet."""
    return max(0, state["budget"]["reserve_critic"] - counted_tasks(state, _CRITIC_TYPES))


def validation_reserve(state: Mapping[str, Any]) -> int:
    """Return the size of the validation reserve: ``ceil(max_agent_tasks * ratio)``."""
    budget = state["budget"]
    return math.ceil(budget["max_agent_tasks"] * budget["reserve_validation_ratio"])


def validation_reserve_left(state: Mapping[str, Any]) -> int:
    """Return the validation reserve that no validation task has used yet."""
    used = counted_tasks(state, VALIDATION_TASK_TYPES)
    return max(0, validation_reserve(state) - used)


def review_reserve(state: Mapping[str, Any]) -> int:
    """Return the review reserve: one quarter of the validation reserve, 0 without a final
    review (``quick``)."""
    if not reviews_enabled(state):
        return 0
    return validation_reserve(state) // RESERVE_SHARE_DIVISOR


def review_reserve_left(state: Mapping[str, Any]) -> int:
    """Return the review reserve that no ``review`` task has used yet; 0 after the step
    :data:`REVIEW_STEP` or the ``validate`` phase finished."""
    phases = state.get("phases")
    validate = phases.get("validate") if isinstance(phases, Mapping) else None
    validate = validate if isinstance(validate, Mapping) else {}
    steps = validate.get("steps")
    step = steps.get(REVIEW_STEP) if isinstance(steps, Mapping) else None
    if validate.get("status") in _FINISHED or (
        isinstance(step, Mapping) and step.get("status") in _FINISHED
    ):
        return 0
    return max(0, review_reserve(state) - counted_tasks(state, _REVIEW_TYPES))


def poc_reserve_left(state: Mapping[str, Any]) -> int:
    """Return the PoC reserve (``budget.reserve_poc``, part of the validation reserve) that no
    ``poc_build`` task has used yet; 0 without the key (older runs, no sandbox) and after the
    ``poc`` phase."""
    reserve = state["budget"].get("reserve_poc", 0)
    phases = state.get("phases")
    poc = phases.get("poc") if isinstance(phases, Mapping) else None
    if not isinstance(reserve, int) or reserve <= 0:
        return 0
    if isinstance(poc, Mapping) and poc.get("status") in _FINISHED:
        return 0
    return max(0, reserve - counted_tasks(state, _POC_TYPES))


def sca_reach_cap(state: Mapping[str, Any]) -> int:
    """Return the most ``sca_reach`` tasks of the run: one quarter of the validation reserve."""
    return validation_reserve(state) // RESERVE_SHARE_DIVISOR


def deterministic_verify_cap(state: Mapping[str, Any]) -> int:
    """Return the most verify tasks for deterministic tool results: one quarter of the
    validation reserve."""
    return validation_reserve(state) // RESERVE_SHARE_DIVISOR


def hunt_wave_cap(state: Mapping[str, Any]) -> int:
    """Return the most new hunt tasks that one wave may plan now.

    Every hunt task keeps room for :data:`VERIFY_PER_HUNT` verify tasks:
    ``(remaining - critic_reserve_left - review_reserve_left) // (1 + VERIFY_PER_HUNT)``, never
    above ``available(state, "hunt")``.
    """
    room = max(
        0,
        remaining(state)
        - critic_reserve_left(state)
        - review_reserve_left(state)
        - poc_reserve_left(state),
    )
    return min(available(state, "hunt"), room // (1 + VERIFY_PER_HUNT))


def available(state: Mapping[str, Any], task_type: str) -> int:
    """Return how many budget-counted tasks of ``task_type`` the planner can create now.

    The free pool is ``remaining - critic_reserve_left - validation_reserve_left``. A critic
    task can also use the critic reserve; a validation task (``verify``, ``review``,
    ``consolidate``, ``polish``, ``sca_reach``, ``poc_build``) can also use the validation
    reserve, but only a ``review`` task can use what is left of the review reserve and only a
    ``poc_build`` task what is left of the PoC reserve. The result never exceeds
    :func:`remaining`.
    """
    left = remaining(state)
    critic = critic_reserve_left(state)
    validation = validation_reserve_left(state)
    pool = max(0, left - critic - validation)
    if task_type in _CRITIC_TYPES:
        pool += critic
    if task_type in VALIDATION_TASK_TYPES:
        pool += validation
        if task_type not in _REVIEW_TYPES:
            pool -= review_reserve_left(state)
        if task_type not in _POC_TYPES:
            pool -= poc_reserve_left(state)
    return max(0, min(left, pool))


def can_create(state: Mapping[str, Any], n: int = 1, task_type: str | None = None) -> bool:
    """Return True when ``n`` more budget-counted tasks fit.

    Without ``task_type`` only :func:`remaining` counts. With it, the reserve rule of
    :func:`available` applies.
    """
    if n <= 0:
        return True
    if task_type is None:
        return remaining(state) >= n
    return available(state, task_type) >= n
