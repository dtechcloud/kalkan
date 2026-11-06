# SPDX-License-Identifier: MIT
"""The phase engine: the decision loop of ``run next``, phase entry and progression, and
``run answer`` (docs/PHASES.md sections 1 and 3).

:func:`next_action` returns exactly one action object:

- in phase ``done``: ``{"kind": "done", "report"}``, or ``{"kind": "incomplete", "reason",
  "report"}`` when ``incomplete_reason`` is set (an incomplete reason never stops the run
  early: validation, merge and the partial report still run, docs/PHASES.md section 7);
- ``{"kind": "engine_step", "phase", "step"}`` for the first open step of the phase, when the
  phase has no open tasks (steps wait for the tasks of their phase);
- ``{"kind": "agent_tasks", "phase", "tasks": [{id, type, agent, prompt_file, result_file}]}``
  with the tasks already leased to the owner;
- ``{"kind": "wait", "retry_after_seconds": 60, "reason"}`` while other owners hold leases (or a
  live process runs the open step);
- ``{"kind": "ask_user", "question": "english_report"}`` after the report step;
- otherwise the phase is complete: a phase hook may add work (the hunt critic, the translation
  tasks), else the phase becomes ``done`` and the next phase is entered.

Entering a phase (:func:`ensure_entered`) only writes state and task files; it never runs a long
step. Every entry hook is idempotent (dedupe keys), so a crash during the entry repeats it
safely. A running phase of an older run state gets the steps that its version did not know.

Tools-only runs (``options.mode`` = ``tools-only``, ``kalkan audit --tools-only``): the engine
never creates an agent task. :func:`ensure_entered` marks each agent phase of
:data:`AGENT_PHASES` ``skipped`` with the one step :data:`TOOLS_ONLY_STEP` (status ``skipped``,
detail :data:`TOOLS_ONLY_REASON`) and moves on; the step ``sca:reach_tasks`` is ``skipped``
too; the run asks no question. The report shows the reason as a partial pass reason.

``run reopen`` (:func:`reopen`) puts a run after ``validate`` back before the step
``consolidate`` or ``polish``; ``run answer`` (:func:`answer`) records the English-report
answer.
"""

from __future__ import annotations

import importlib
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Final

from kalkan.errors import StateError, ValidationError
from kalkan.run import budget, ids, queue
from kalkan.run.inputs import recon_input, translate_input
from kalkan.run.plan import hunt_idle
from kalkan.run.recon_merge import RECON_KINDS
from kalkan.run.runfiles import FINDINGS_NAME, read_json, run_compose_files, run_tech
from kalkan.run.state import (
    MODE_TOOLS_ONLY,
    PHASES,
    SETTLED_TASK_STATUSES,
    RunContext,
    run_mode,
    transaction,
)
from kalkan.run.steps import first_open_step, open_tasks, step_is_live
from kalkan.run.tasks import ensure_prompt, new_task

__all__ = [
    "AGENT_PHASES",
    "ANSWER_VALUES",
    "QUESTIONS",
    "REOPEN_PHASES",
    "REOPEN_STEPS",
    "TOOLS_ONLY_REACH",
    "TOOLS_ONLY_REASON",
    "TOOLS_ONLY_STEP",
    "VALIDATE_STEPS",
    "WAIT_SECONDS",
    "answer",
    "ensure_entered",
    "next_action",
    "pending_question",
    "reopen",
    "sandbox_status",
    "tools_only",
]

WAIT_SECONDS: Final = 60
QUESTIONS: Final = ("english_report",)
#: Accepted answers (English and Turkish) and their stored value.
ANSWER_VALUES: Final = {
    "yes": "yes",
    "y": "yes",
    "evet": "yes",
    "e": "yes",
    "no": "no",
    "n": "no",
    "hayır": "no",
    "hayir": "no",
    "h": "no",
}
TRANSLATE_BATCH: Final = 20
#: Steps that ``run reopen`` can put back (docs/PHASES.md section 3).
REOPEN_STEPS: Final = (budget.CONSOLIDATE_STEP, budget.POLISH_STEP)
#: The steps of ``validate`` in their order. A reopened step also puts back the steps after it
#: (``polish`` follows ``consolidate``).
VALIDATE_STEPS: Final = (budget.REVIEW_STEP, budget.CONSOLIDATE_STEP, budget.POLISH_STEP)
#: Phases after ``validate`` that ``run reopen`` moves back to ``validate``.
REOPEN_PHASES: Final = ("poc", "merge", "report", "done")
#: Phases whose work is agent tasks. A tools-only run skips them (module docstring).
AGENT_PHASES: Final = ("recon", "plan", "hunt", "validate", "poc")
#: The one step of a phase that a tools-only run skipped, and its detail.
TOOLS_ONLY_STEP: Final = "tools-only"
TOOLS_ONLY_REASON: Final = (
    "tools-only mode: no agent validation; all results are unverified tool results"
)
#: The detail of the step ``sca:reach_tasks`` in a tools-only run.
TOOLS_ONLY_REACH: Final = "tools-only mode: no agent reachability check (sca_reach)"
_MAX_ROUNDS: Final = 50
_RECON_REASON: Final = "budget_cannot_fund_reconnaissance_and_reserves"
_QUICK_REVIEW: Final = (
    "fast profile: no separate final review (the Cloudflare quick profile merges the record "
    "checks into the verify task)"
)


# ---------------------------------------------------------------------------------------------
# Phase entry


def _pending(detail: str = "") -> dict[str, Any]:
    return {"status": "pending", "detail": detail}


def _skipped(detail: str) -> dict[str, Any]:
    return {"status": "skipped", "detail": detail}


def tools_only(state: dict[str, Any]) -> bool:
    """Return True for a tools-only run (``options.mode`` = ``tools-only``)."""
    return run_mode(state) == MODE_TOOLS_ONLY


def _enter_deterministic(ctx: RunContext) -> dict[str, dict[str, Any]]:
    try:
        registry = importlib.import_module("kalkan.scanners.registry")
        base = importlib.import_module("kalkan.scanners.base")
    except ImportError:
        return {"scan": _skipped("module_unavailable: kalkan.scanners.registry")}
    steps: dict[str, dict[str, Any]] = {}
    try:
        scan_ctx = base.load_scan_context(ctx.run_dir)
    except Exception:  # the scan step reports the real error
        scan_ctx = None
    for adapter in registry.SCANNERS:
        name = f"scan:{adapter.name}"
        applies, reason = True, ""
        if scan_ctx is not None:
            try:
                applies, reason = adapter.applies(scan_ctx)
            except Exception:  # let run_adapter decide
                applies, reason = True, ""
        steps[name] = _pending() if applies else _skipped(reason or "does not apply")
    return steps


def _enter_sca(ctx: RunContext) -> dict[str, dict[str, Any]]:
    reach = _skipped(TOOLS_ONLY_REACH) if tools_only(ctx.state) else _pending()
    return {name: _pending() for name in ("sca:sbom", "sca:match", "sca:govulncheck")} | {
        "sca:reach_tasks": reach
    }


def _enter_recon(ctx: RunContext) -> dict[str, dict[str, Any]]:
    state = ctx.reload()
    existing = [task for task in state["tasks"].values() if task["type"] == "recon"]
    if not existing and budget.available(state, "recon") < len(RECON_KINDS):
        with transaction(ctx) as tx:
            if not tx.state.get("incomplete_pending"):
                tx.state["incomplete_pending"] = _RECON_REASON
                tx.event("incomplete_pending", reason=_RECON_REASON)
        return {"recon:merge": _pending("no reconnaissance task: the budget cannot fund it")}
    for kind in RECON_KINDS:
        new_task(
            ctx,
            "recon",
            "recon",
            recon_input(ctx, kind),
            priority=90,
            dedupe_key=f"recon:{kind}",
            meta={"kind": kind},
        )
    return {"recon:merge": _pending()}


def _enter_validate(ctx: RunContext) -> dict[str, dict[str, Any]]:
    review = _pending() if budget.reviews_enabled(ctx.reload()) else _skipped(_QUICK_REVIEW)
    return {
        budget.REVIEW_STEP: review,
        budget.CONSOLIDATE_STEP: _pending(),
        budget.POLISH_STEP: _pending(),
    }


def sandbox_status(ctx: RunContext) -> tuple[bool, str]:
    """Return ``(available, reason)`` for the PoC sandbox (docs/PHASES.md section 3, poc).

    The sandbox runs when ``kalkan.sandbox`` has its runner (ADR-0006), ``--docker`` is not
    ``off`` and the Docker engine answers. The reason is English text for the operator.
    """
    missing = "the kalkan.sandbox module has no PoC runner (incomplete install)"
    try:
        sandbox = importlib.import_module("kalkan.sandbox")
    except ImportError:
        return False, missing
    run_poc = getattr(sandbox, "run_poc", None)
    available = getattr(sandbox, "docker_available", None)
    if not callable(run_poc) or not callable(available):
        return False, missing
    if ctx.options["docker"] == "off":
        return False, "the PoC sandbox is off (--docker off)"
    try:
        if not available():
            return False, "the Docker engine does not answer"
    except Exception:
        return False, "the Docker engine does not answer"
    return True, ""


def sandbox_facts(ctx: RunContext) -> dict[str, Any]:
    """Return what a ``poc_build`` task needs to know about the sandbox: the allowed base images,
    the unit-level limits and the compose files of the target (app level, ENGINE-SPEC 23)."""
    from kalkan.sandbox import runner  # noqa: PLC0415 - the sandbox loads only for the poc phase

    return {
        "base_images": runner.allowed_images(),
        "limits": runner.unit_limits(),
        "compose_files": run_compose_files(ctx),
    }


def _enter_poc(ctx: RunContext) -> dict[str, dict[str, Any]]:
    ready, _ = sandbox_status(ctx)
    if not ready:
        return {"poc:skip": _pending()}
    from kalkan.run.steps import code_findings  # noqa: PLC0415 - avoids a long import chain

    for task_id, finding in code_findings(ctx):
        if budget.available(ctx.state, "poc_build") < 1:
            break
        new_task(
            ctx,
            "poc_build",
            "poc",
            {
                "finding_id": finding["id"],
                "finding": finding,
                "verify_task": task_id,
                "tech": run_tech(ctx),
                **sandbox_facts(ctx),
            },
            priority=60,
            dedupe_key=f"poc:{finding['id']}",
            meta={"finding": finding["id"]},
        )
    return {"poc:run": _pending()}


def _enter_report(ctx: RunContext) -> dict[str, dict[str, Any]]:
    return {f"report:{ctx.lang}": _pending()}


_ENTRY: Final = {
    "deterministic": _enter_deterministic,
    "sca": _enter_sca,
    "recon": _enter_recon,
    "plan": lambda ctx: {"plan:ledger": _pending(), "plan:tasks": _pending()},
    "hunt": lambda ctx: {},
    "validate": _enter_validate,
    "poc": _enter_poc,
    "merge": lambda ctx: {"merge": _pending()},
    "report": _enter_report,
}


#: Steps that a newer kalkan version added to a phase: a run that entered the phase before the
#: version gets them as ``pending`` when it resumes there (docs/PHASES.md section 3, validate).
_LATE_STEPS: Final = {"validate": (budget.CONSOLIDATE_STEP, budget.POLISH_STEP)}
#: The step order of a phase with late steps: an added step takes its place in this order.
_STEP_ORDER: Final = {"validate": VALIDATE_STEPS}


def _ordered_steps(phase: str, steps: dict[str, Any]) -> dict[str, Any]:
    """Return ``steps`` in the order of :data:`_STEP_ORDER` (other steps keep their order, after
    the known ones)."""
    order = _STEP_ORDER.get(phase, ())
    known = [name for name in order if name in steps]
    return {name: steps[name] for name in [*known, *(n for n in steps if n not in order)]}


def _add_late_steps(ctx: RunContext, state: dict[str, Any], *, now: datetime | None) -> None:
    """Add the :data:`_LATE_STEPS` that a running phase of an older run does not have."""
    phase = state["phase"]
    missing = [
        name for name in _LATE_STEPS.get(phase, ()) if name not in state["phases"][phase]["steps"]
    ]
    if not missing or state["phases"][phase]["status"] != "running":
        return
    with transaction(ctx, now=now) as tx:
        record = tx.state["phases"][phase]
        if tx.state["phase"] != phase or record["status"] != "running":
            return
        for name in missing:
            if name not in record["steps"]:
                record["steps"][name] = _pending()
                tx.event("step_added", phase=phase, step=name, reason="older run state")
        record["steps"] = _ordered_steps(phase, record["steps"])


def _skip_agent_phase(ctx: RunContext, state: dict[str, Any], *, now: datetime | None) -> bool:
    """Skip the current phase of a tools-only run when it is a pending agent phase.

    The phase becomes ``skipped`` with the one step :data:`TOOLS_ONLY_STEP`, and the next
    phase becomes current (still ``pending``). Returns True when the state changed (or another
    process moved the run on), so that the caller reads the state again.
    """
    phase = state["phase"]
    if (
        phase not in AGENT_PHASES
        or state["phases"][phase]["status"] != "pending"
        or not tools_only(state)
    ):
        return False
    with transaction(ctx, now=now) as tx:
        record = tx.state["phases"][phase]
        if tx.state["phase"] != phase or record["status"] != "pending":
            return True
        timestamp = ids.format_ts(now)
        record.update(
            status="skipped",
            started_at=timestamp,
            finished_at=timestamp,
            steps={TOOLS_ONLY_STEP: _skipped(TOOLS_ONLY_REASON)},
        )
        following = PHASES[PHASES.index(phase) + 1]
        tx.state["phase"] = following
        tx.event("phase_skipped", phase=phase, next=following, reason=TOOLS_ONLY_REASON)
    return True


def ensure_entered(ctx: RunContext, *, now: datetime | None = None) -> None:
    """Run the entry hook of the current phase once (status ``pending`` → ``running``).

    A running phase of a run that an older kalkan version created gets the steps that the
    version did not know (:data:`_LATE_STEPS`) as ``pending``. A tools-only run first skips
    every pending agent phase in a row (:data:`AGENT_PHASES`), then enters the next phase.
    """
    state = ctx.reload()
    while _skip_agent_phase(ctx, state, now=now):
        state = ctx.reload()
    phase = state["phase"]
    if phase == "done":
        return
    if state["phases"][phase]["status"] != "pending":
        _add_late_steps(ctx, state, now=now)
        return
    hook = _ENTRY.get(phase)
    steps = hook(ctx) if hook is not None else {}
    with transaction(ctx, now=now) as tx:
        record = tx.state["phases"][phase]
        if tx.state["phase"] != phase or record["status"] != "pending":
            return
        for name, step in steps.items():
            record["steps"].setdefault(name, step)
        record["status"] = "running"
        record["started_at"] = ids.format_ts(now)
        tx.event("phase_entered", phase=phase, steps=list(steps))


# ---------------------------------------------------------------------------------------------
# Questions and phase hooks


def pending_question(state: dict[str, Any]) -> str | None:
    """Return the open question of the run, or None (docs/PHASES.md section 3, report).

    A tools-only run asks nothing: no person drives it (``run answer english_report yes``
    still works and gives the English report without translation tasks).
    """
    if state["phase"] != "report" or state["options"]["lang"] == "en" or tools_only(state):
        return None
    step = state["phases"]["report"]["steps"].get(f"report:{state['options']['lang']}")
    if step is None or step["status"] != "done":
        return None
    if "english_report" in (state.get("answers") or {}):
        return None
    return "english_report"


def _report_idle(ctx: RunContext) -> bool:
    """Create the translation tasks and ``report:en`` after a ``yes``; True when work was added.

    A tools-only run gets ``report:en`` without translation tasks (it creates no agent task).
    """
    state = ctx.reload()
    if state["options"]["lang"] == "en":
        return False
    if (state.get("answers") or {}).get("english_report") != "yes":
        return False
    if "report:en" in state["phases"]["report"]["steps"]:
        return False
    document = read_json(ctx.run_dir / FINDINGS_NAME, 64 * 1024 * 1024)
    items = document if isinstance(document, list) else []
    findings = [
        item for item in items if isinstance(item, dict) and isinstance(item.get("id"), str)
    ]
    if tools_only(state):
        findings = []
    for start in range(0, len(findings), TRANSLATE_BATCH):
        batch = findings[start : start + TRANSLATE_BATCH]
        new_task(
            ctx,
            "translate",
            "report",
            translate_input(batch),
            priority=50,
            dedupe_key=f"translate:{start // TRANSLATE_BATCH + 1}:{batch[0]['id']}",
            counts_against_budget=False,
        )
    with transaction(ctx) as tx:
        steps = tx.state["phases"]["report"]["steps"]
        if "report:en" not in steps:
            steps["report:en"] = _pending()
            tx.event("step_added", phase="report", step="report:en")
    return True


_IDLE: Final = {"hunt": hunt_idle, "report": _report_idle}


def _advance(ctx: RunContext, phase: str, *, now: datetime | None = None) -> None:
    with transaction(ctx, now=now) as tx:
        state = tx.state
        if state["phase"] != phase:
            return
        timestamp = ids.format_ts(now)
        record = state["phases"][phase]
        record["status"] = "done"
        record["started_at"] = record["started_at"] or timestamp
        record["finished_at"] = timestamp
        following = PHASES[PHASES.index(phase) + 1]
        state["phase"] = following
        if following == "done":
            final = state["phases"]["done"]
            final.update(status="done", started_at=timestamp, finished_at=timestamp)
            pending = state.get("incomplete_pending")
            if pending and not state["incomplete_reason"]:
                state["incomplete_reason"] = pending
        tx.event("phase_done", phase=phase, next=following)


# ---------------------------------------------------------------------------------------------
# The decision loop


def _report_path(ctx: RunContext) -> str:
    path = ctx.run_dir / "report" / "REPORT.md"
    try:
        return path.resolve().relative_to(Path(os.getcwd()).resolve()).as_posix()
    except ValueError:
        return path.absolute().as_posix()


def _claimable(state: dict[str, Any], task_ids: list[str]) -> bool:
    for task_id in task_ids:
        task = state["tasks"][task_id]
        if task["status"] == "pending" and all(
            state["tasks"][dep]["status"] in SETTLED_TASK_STATUSES for dep in task["depends_on"]
        ):
            return True
    return False


def _wait(reason: str) -> dict[str, Any]:
    return {"kind": "wait", "retry_after_seconds": WAIT_SECONDS, "reason": reason}


def next_action(
    ctx: RunContext, owner: str, limit: int | None = None, *, now: datetime | None = None
) -> dict[str, Any]:
    """Return the next action of the run (module docstring)."""
    queue.expire_leases(ctx, now=now)
    for _ in range(_MAX_ROUNDS):
        ensure_entered(ctx, now=now)
        state = ctx.reload()
        phase = state["phase"]
        if phase == "done":
            if state["incomplete_reason"]:
                return {
                    "kind": "incomplete",
                    "reason": state["incomplete_reason"],
                    "report": _report_path(ctx),
                }
            return {"kind": "done", "report": _report_path(ctx)}
        step = first_open_step(state, phase)
        open_ids = open_tasks(state, phase)
        if step is not None:
            if step_is_live(state["phases"][phase]["steps"][step], now):
                return _wait("an engine step runs in another process")
            if not open_ids:
                return {"kind": "engine_step", "phase": phase, "step": step}
        if open_ids:
            wanted = state["options"]["max_parallel"] if limit is None else limit
            if wanted > 0 and _claimable(state, open_ids):
                items = queue.claim(ctx, owner, wanted, now=now)
                if items:
                    for item in items:
                        ensure_prompt(ctx, item["id"])
                    return {"kind": "agent_tasks", "phase": phase, "tasks": items}
            return _wait("agent tasks of this phase are leased")
        question = pending_question(state)
        if question is not None:
            return {"kind": "ask_user", "question": question}
        hook = _IDLE.get(phase)
        if hook is not None and hook(ctx):
            continue
        _advance(ctx, phase, now=now)
    return _wait("the engine made no progress in this call")


# ---------------------------------------------------------------------------------------------
# run answer


def answer(ctx: RunContext, question: str, value: str) -> dict[str, Any]:
    """Record the user's answer to ``question`` and return ``{question, value, previous,
    reopened}``.

    ``english_report yes`` after the run reached ``done`` (also an incomplete run, which has a
    partial report) puts the run back into the report phase, so that ``run next`` creates the
    translation tasks and the step ``report:en``.
    """
    if question not in QUESTIONS:
        raise ValidationError(
            "unknown question", [f"question: expected one of {', '.join(QUESTIONS)}"]
        )
    normalized = ANSWER_VALUES.get(value.strip().casefold()) if isinstance(value, str) else None
    if normalized is None:
        raise ValidationError("invalid answer", ["value: expected yes or no (evet or hayır)"])
    reopened = False
    with transaction(ctx) as tx:
        state = tx.state
        answers = state.setdefault("answers", {})
        previous = answers.get(question)
        answers[question] = normalized
        if (
            normalized == "yes"
            and state["phase"] == "done"
            and state["options"]["lang"] != "en"
            and "report:en" not in state["phases"]["report"]["steps"]
        ):
            state["phase"] = "report"
            state["phases"]["report"].update(status="running", finished_at=None)
            state["phases"]["done"].update(status="pending", started_at=None, finished_at=None)
            reopened = True
        tx.event("question_answered", question=question, value=normalized, reopened=reopened)
    return {"question": question, "value": normalized, "previous": previous, "reopened": reopened}


# ---------------------------------------------------------------------------------------------
# run reopen


def reopen(ctx: RunContext, step: str, *, now: datetime | None = None) -> dict[str, Any]:
    """Put a finished run back before ``step`` and return ``{run_id, step, previous_phase,
    phase, reopened}`` (docs/PHASES.md section 3, ``run reopen``).

    ``step`` is one of :data:`REOPEN_STEPS` (the validate steps ``consolidate`` and
    ``polish``). The run lock is held throughout:

    1. A leased task, or a step that a live process runs, refuses the call
       (:class:`~kalkan.errors.StateError`; finish or ``run resume`` first).
    2. A run in a phase of :data:`REOPEN_PHASES` goes back to ``validate``: the phase is
       ``running`` again with ``step`` and every step after it in :data:`VALIDATE_STEPS`
       ``pending`` (``consolidate`` also puts back ``polish``; a missing step is added in its
       place); the later phases (``poc``, ``merge``, ``report``, ``done``) are ``pending``
       without steps, so their entry hooks add them again. Tasks, answers and the incomplete
       reason stay. The event ``run_reopened`` records it.
    3. Any other phase changes nothing (``reopened: false``): a run before or in ``validate``
       runs the step anyway, so a second call is a no-op.
    """
    if step not in REOPEN_STEPS:
        raise ValidationError("unknown step", [f"step: expected one of {', '.join(REOPEN_STEPS)}"])
    with transaction(ctx, now=now) as tx:
        state = tx.state
        leased = sorted(
            task_id for task_id, task in state["tasks"].items() if task["status"] == "leased"
        )
        if leased:
            raise StateError(
                f"cannot reopen the run while tasks are leased ({', '.join(leased[:5])}); "
                "complete them or run kalkan run resume first"
            )
        live = [
            name
            for record in state["phases"].values()
            for name, item in record["steps"].items()
            if step_is_live(item, now)
        ]
        if live:
            raise StateError(
                f"cannot reopen the run while the engine step {live[0]} runs in another process"
            )
        previous = state["phase"]
        reopened = previous in REOPEN_PHASES
        if reopened:
            timestamp = ids.format_ts(now)
            validate = state["phases"]["validate"]
            validate.update(
                status="running", started_at=validate["started_at"] or timestamp, finished_at=None
            )
            for name in VALIDATE_STEPS[VALIDATE_STEPS.index(step) :]:
                validate["steps"][name] = _pending()
            validate["steps"] = _ordered_steps("validate", validate["steps"])
            for later in PHASES[PHASES.index("validate") + 1 :]:
                state["phases"][later].update(
                    status="pending", started_at=None, finished_at=None, steps={}
                )
            state["phase"] = "validate"
            tx.event("run_reopened", step=step, previous_phase=previous)
    return {
        "run_id": ctx.state["run_id"],
        "step": step,
        "previous_phase": previous,
        "phase": ctx.state["phase"],
        "reopened": reopened,
    }
