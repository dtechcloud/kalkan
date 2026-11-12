# SPDX-License-Identifier: MIT
"""Engine steps and ``run step`` (docs/PHASES.md sections 2 and 3).

:func:`run_step` runs the first open step of the current phase:

1. Under the run lock it picks the first step whose status is ``pending``, or ``running`` with a
   dead process (or older than its timeout plus 120 seconds). A step waits while its phase has
   pending or leased tasks. It records ``running`` with the PID, the host, the start time, the
   time limit and the start count. A step that started three times without finishing becomes
   ``failed`` (a step that crashes its process never loops forever).
2. Without the lock it runs the step function. A missing module (an optional part of kalkan
   that is not installed yet) gives ``skipped`` with ``module_unavailable: <name>``; a
   :class:`~kalkan.errors.KalkanError` or any other exception gives ``failed``. A failed step
   never stops the run.
3. Under the lock it records the outcome, when the step still carries this process's PID.

Steps are idempotent: running one again after a crash produces the same files. Scanner steps
pass ``timeout_seconds = min(adapter.timeout_seconds, max_seconds - 20)`` to ``run_adapter``;
the SBOM and match steps give each of their two tools half of that time.

Output of :func:`run_step`: ``{"phase", "step", "status", "detail", "duration_seconds"}`` with
status ``done``, ``failed`` or ``skipped``; ``idle`` when no step can run now (no open step, or
the phase still has open tasks) and ``busy`` when another live process runs the step.
"""

from __future__ import annotations

import importlib
import os
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final

from kalkan.errors import KalkanError
from kalkan.run import budget, ids, lock
from kalkan.run.cleaning import clean_text, dedupe_key
from kalkan.run.consolidate import create_consolidate_tasks
from kalkan.run.plan import NON_CODE_CLASSES, plan_ledger, plan_tasks
from kalkan.run.polish import create_polish_tasks
from kalkan.run.recon_merge import merge_recon
from kalkan.run.review import create_review_tasks, rejected_verify_tasks
from kalkan.run.runfiles import VULNS_NAME, load_vulns, read_task_json, tasks_of_type, write_json
from kalkan.run.runfiles import verify_findings as _verify_findings
from kalkan.run.state import RunContext, transaction
from kalkan.run.tasks import find_by_dedupe_key, new_task

__all__ = [
    "DEFAULT_MAX_SECONDS",
    "MAX_STEP_STARTS",
    "STALE_GRACE_SECONDS",
    "StepLimits",
    "StepOutcome",
    "first_open_step",
    "open_tasks",
    "run_step",
    "step_function",
    "step_is_live",
]

DEFAULT_MAX_SECONDS: Final = 480
#: A running step older than its timeout plus this grace counts as crashed.
STALE_GRACE_SECONDS: Final = 120
#: A step that started this many times without finishing becomes ``failed``.
MAX_STEP_STARTS: Final = 3
_DETAIL_MAX: Final = 2000
_TERMINAL: Final = frozenset({"done", "skipped", "failed"})
SANDBOX_UNAVAILABLE: Final = "sandbox_unavailable"


@dataclass(frozen=True)
class StepLimits:
    """The time budget of one ``run step`` call."""

    max_seconds: int

    def tool_timeout(self, adapter_timeout: int | None = None, share: int = 1) -> int:
        """Return a tool timeout that fits the step budget (at least 5 seconds)."""
        room = max(5, (self.max_seconds - 20) // max(1, share))
        if adapter_timeout:
            room = min(room, adapter_timeout)
        return max(5, room)


@dataclass(frozen=True)
class StepOutcome:
    """The result of a step function."""

    status: str  # done | skipped | failed
    detail: str = ""


class ModuleUnavailable(Exception):
    """An optional kalkan module or function that a step needs is not available."""


StepFunction = Callable[[RunContext, str, StepLimits], StepOutcome]


def _need(module: str, attribute: str | None = None) -> Any:
    try:
        loaded = importlib.import_module(module)
    except ImportError:
        raise ModuleUnavailable(module) from None
    if attribute is None:
        return loaded
    value = getattr(loaded, attribute, None)
    if value is None:
        raise ModuleUnavailable(f"{module}.{attribute}")
    return value


# ---------------------------------------------------------------------------------------------
# Step functions


def _scan(ctx: RunContext, name: str, limits: StepLimits) -> StepOutcome:
    engine = name.split(":", 1)[1]
    registry = _need("kalkan.scanners.registry")
    base = _need("kalkan.scanners.base")
    run_adapter = getattr(base, "run_adapter", None)
    if run_adapter is None:
        raise ModuleUnavailable("kalkan.scanners.base.run_adapter")
    adapter = registry.get(engine)
    scan_ctx = base.load_scan_context(ctx.run_dir)
    timeout = limits.tool_timeout(getattr(adapter, "timeout_seconds", None))
    result = run_adapter(adapter, scan_ctx, timeout_seconds=timeout)
    status = {"ok": "done", "skipped": "skipped"}.get(result.status, "failed")
    detail = f"{result.status}: {result.message}".strip()
    count = getattr(result, "candidates", None)
    if isinstance(count, int):
        detail += f" ({count} candidates)"
    return StepOutcome(status, detail)


def _sca_sbom(ctx: RunContext, name: str, limits: StepLimits) -> StepOutcome:
    _need("kalkan.scanners.registry")
    run_sbom = _need("kalkan.sca.commands", "run_sbom")
    summary = run_sbom(ctx.run_dir, timeout_seconds=limits.tool_timeout(share=2))
    return StepOutcome(
        "done", f"{summary.get('engine')}: {summary.get('components', 0)} components"
    )


def _sca_match(ctx: RunContext, name: str, limits: StepLimits) -> StepOutcome:
    _need("kalkan.scanners.registry")
    run_match = _need("kalkan.sca.commands", "run_match")
    summary = run_match(ctx.run_dir, timeout_seconds=limits.tool_timeout(share=2))
    counts = ", ".join(f"{key} {value}" for key, value in summary.get("by_severity", {}).items())
    return StepOutcome("done", f"{summary.get('merged', 0)} vulnerability records ({counts})")


def _sca_govulncheck(ctx: RunContext, name: str, limits: StepLimits) -> StepOutcome:
    if not (ctx.run_dir / VULNS_NAME).is_file():
        return StepOutcome("skipped", "no vulnerability records")
    if not any(record.get("ecosystem") == "Go" for record in load_vulns(ctx)):
        return StepOutcome("skipped", "no Go records")
    run_reach = _need("kalkan.sca.commands", "run_reach")
    summary = run_reach(ctx.run_dir, max_tasks=0, timeout_seconds=limits.tool_timeout())
    info = summary.get("govulncheck") or {}
    status = {"ok": "done", "skipped": "skipped"}.get(str(info.get("status")), "failed")
    return StepOutcome(status, f"govulncheck {info.get('status')}: {info.get('message', '')}")


def _sca_reach_tasks(ctx: RunContext, name: str, limits: StepLimits) -> StepOutcome:
    if not (ctx.run_dir / VULNS_NAME).is_file():
        return StepOutcome("skipped", "no vulnerability records")
    reach = _need("kalkan.sca.reach")
    read_vulns = _need("kalkan.sca.merge", "read_vulns")
    records = read_vulns(ctx.run_dir)["records"]
    state = ctx.reload()
    cap = budget.sca_reach_cap(state)
    selected = reach.select_for_agents(
        records, remaining_budget=budget.available(state, "sca_reach"), max_tasks=cap
    )
    assignments: dict[str, str] = {}
    for record in selected:
        key = dedupe_key("sca_reach", str(record["ref"]))
        task_id = find_by_dedupe_key(ctx.state, key)
        if task_id is None:
            if budget.available(ctx.state, "sca_reach") < 1:
                break
            task_id = new_task(
                ctx,
                "sca_reach",
                "validate",
                reach.build_reach_input(record, ctx.target_dir),
                priority=80 if record.get("severity") == "critical" else 70,
                dedupe_key=key,
                meta={"vuln_ref": record["ref"]},
            )
        assignments[record["ref"]] = task_id
    reach.mark_reach_tasks(ctx.run_dir, assignments)
    return StepOutcome("done", f"{len(assignments)} sca_reach tasks (cap {cap})")


def _recon_merge(ctx: RunContext, name: str, limits: StepLimits) -> StepOutcome:
    ctx.reload()
    summary = merge_recon(ctx)
    return StepOutcome(
        "done",
        f"{summary['results']} recon results, {summary['surfaces']} surfaces "
        f"({summary['dropped']} dropped), {summary['classes']} classes",
    )


def _plan_ledger(ctx: RunContext, name: str, limits: StepLimits) -> StepOutcome:
    summary = plan_ledger(ctx)
    return StepOutcome(
        "done",
        f"{summary['units']} units ({summary['level']} level): {summary['planned']} planned, "
        f"{summary['deferred']} deferred (hunt budget {summary['hunt_budget']})",
    )


def _plan_tasks(ctx: RunContext, name: str, limits: StepLimits) -> StepOutcome:
    hunt = plan_tasks(ctx)["hunt"]
    return StepOutcome(
        "done",
        f"{hunt['tasks']} hunt tasks for {hunt['units']} units ({hunt['deferred']} deferred)",
    )


def _review_tasks(ctx: RunContext, name: str, limits: StepLimits) -> StepOutcome:
    if not budget.reviews_enabled(ctx.reload()):
        return StepOutcome("skipped", "fast profile: no separate final review")
    summary = create_review_tasks(ctx)
    tasks = summary["created"] + summary["reused"]
    unfunded = summary["unfunded_confirmed"] + summary["unfunded_needs_validation"]
    detail = f"{tasks} review tasks for {summary['records']} records"
    if unfunded:
        detail += (
            f"; {unfunded} without budget ({summary['unfunded_confirmed']} confirmed, "
            f"{summary['unfunded_needs_validation']} needs_validation)"
        )
    return StepOutcome("done", detail)


def _consolidate(ctx: RunContext, name: str, limits: StepLimits) -> StepOutcome:
    summary = create_consolidate_tasks(ctx)
    if not summary["groups"]:
        return StepOutcome("done", f"no candidate group ({summary['records']} records)")
    tasks = summary["created"] + summary["reused"]
    detail = (
        f"{tasks} consolidate tasks for {summary['groups']} candidate groups "
        f"({summary['records']} records)"
    )
    if summary["unfunded"]:
        detail += f"; {summary['unfunded']} groups without budget (their records stay separate)"
    return StepOutcome("done", detail)


def _polish(ctx: RunContext, name: str, limits: StepLimits) -> StepOutcome:
    if ctx.reload()["options"]["lang"] != "tr":
        return StepOutcome("done", "not a Turkish run")
    summary = create_polish_tasks(ctx)
    if not summary["batches"]:
        return StepOutcome(
            "done", f"no record needs the Turkish letters ({summary['records']} records)"
        )
    tasks = summary["created"] + summary["reused"]
    if not tasks:
        return StepOutcome(
            "skipped",
            f"no budget: {summary['batches']} polish batches ({summary['selected']} records) "
            "keep their text",
        )
    detail = (
        f"{tasks} polish tasks for {summary['selected']} of {summary['records']} records "
        f"({summary['fields']} fields)"
    )
    if summary["unfunded"]:
        detail += f"; {summary['unfunded']} batches without budget (their records keep their text)"
    return StepOutcome("done", detail)


def code_findings(ctx: RunContext) -> list[tuple[str, dict[str, Any]]]:
    """Return ``(verify task, finding)`` of the confirmed and needs_validation code findings.

    A finding whose final record a review rejected is left out.
    """
    ctx.reload()
    rejected = rejected_verify_tasks(ctx)
    return [
        (task_id, finding)
        for task_id, finding in _verify_findings(ctx)
        if task_id not in rejected
        and finding.get("verdict") in ("confirmed", "needs_validation")
        and finding.get("class") not in NON_CODE_CLASSES
        and isinstance(finding.get("id"), str)
    ]


def _poc_skip(ctx: RunContext, name: str, limits: StepLimits) -> StepOutcome:
    from kalkan.run.phases import sandbox_status  # noqa: PLC0415 - phases imports this module

    _, why = sandbox_status(ctx)
    findings = code_findings(ctx)
    for task_id, finding in findings:
        write_json(
            ctx.task_dir(task_id) / "poc.json",
            {
                "finding_id": finding["id"],
                "level": "unit",
                "status": "blocked",
                # The report localizes this key (i18n.poc_observed); the English reason ``why``
                # stays in the step detail and in poc/skip.json for the operator.
                "observed_result": SANDBOX_UNAVAILABLE,
                "artifacts": [],
                "blocker": SANDBOX_UNAVAILABLE,
            },
        )
    write_json(
        ctx.run_dir / "poc" / "skip.json",
        {
            "reason": why,
            "blocker": SANDBOX_UNAVAILABLE,
            "findings": [{"finding_id": f["id"], "task": t} for t, f in findings],
        },
    )
    return StepOutcome("done", f"{why} ({len(findings)} code findings)")


def _poc_run(ctx: RunContext, name: str, limits: StepLimits) -> StepOutcome:
    run_poc = _need("kalkan.sandbox", "run_poc")
    ran = 0
    for task_id, _ in tasks_of_type(ctx.reload(), "poc_build", statuses=("done",)):
        harness = read_task_json(ctx, task_id, "harness.json")
        if not isinstance(harness, dict) or (ctx.task_dir(task_id) / "poc.json").is_file():
            continue
        poc = run_poc(ctx, task_id, harness)
        write_json(ctx.task_dir(task_id) / "poc.json", poc)
        ran += 1
    lost = _record_dead_pocs(ctx)
    detail = f"{ran} PoC harnesses ran"
    return StepOutcome("done", f"{detail}; {lost} PoC tasks without a result" if lost else detail)


def _record_dead_pocs(ctx: RunContext) -> int:
    """Write a ``blocked`` poc.json for each dead ``poc_build`` task and return their count.

    A dead task used all its attempts without a usable result, for example because a safety
    classifier stopped its agent. Without this record the report shows no PoC line at all and
    the reader cannot tell a lost PoC from a finding without a PoC task.
    """
    count = 0
    for task_id, task in tasks_of_type(ctx.reload(), "poc_build", statuses=("dead",)):
        path = ctx.task_dir(task_id) / "poc.json"
        finding_id = (task.get("meta") or {}).get("finding")
        if path.is_file() or not isinstance(finding_id, str):
            continue
        error = task.get("error") if isinstance(task.get("error"), dict) else {}
        reason = str(error.get("message") or "the agent returned no usable result")
        write_json(
            path,
            {
                "finding_id": finding_id,
                "level": "unit",
                "status": "blocked",
                "observed_result": f"{reason} ({task.get('attempts', 0)} attempts)",
                "artifacts": [],
                "blocker": "agent_failed",
            },
        )
        count += 1
    return count


def _merge(ctx: RunContext, name: str, limits: StepLimits) -> StepOutcome:
    merge_run = _need("kalkan.findings.merge", "merge_run")
    with lock.run_lock(ctx.run_dir):
        summary = merge_run(ctx.run_dir)
    verdicts = ", ".join(f"{key} {value}" for key, value in summary.get("by_verdict", {}).items())
    return StepOutcome("done", f"{summary.get('findings', 0)} findings ({verdicts})")


def _report(ctx: RunContext, name: str, limits: StepLimits) -> StepOutcome:
    lang = name.split(":", 1)[1]
    run_lang = ctx.lang
    if lang == run_lang:
        with transaction(ctx) as tx:
            pending = tx.state.get("incomplete_pending")
            if pending and not tx.state["incomplete_reason"]:
                tx.state["incomplete_reason"] = pending
                tx.event("run_incomplete", reason=pending)
    build_model = _need("kalkan.report.model", "build_model")
    write_report = _need("kalkan.report.commands", "write_report")
    notes = []
    if lang != run_lang:
        try:
            merge_run = _need("kalkan.findings.merge", "merge_run")
        except ModuleUnavailable:
            merge_run = None
        if merge_run is not None:
            with lock.run_lock(ctx.run_dir):
                merge_run(ctx.run_dir)  # applies the translations as i18n.en
            notes.append("findings merged again with the translations")
    model = build_model(ctx.run_dir)
    if lang == run_lang:
        written = write_report(
            ctx.run_dir, model, lang=lang, formats=("md", "html", "exec", "sarif", "json", "sbom")
        )
    else:
        written = write_report(ctx.run_dir, model, lang=lang, formats=("md", "html", "exec"))
        written += write_report(ctx.run_dir, model, lang=run_lang, formats=("sarif", "json"))
    files = ", ".join(sorted(path.name for path in written))
    return StepOutcome("done", "; ".join([f"wrote {files}", *notes]))


_STEPS: Final[dict[str, StepFunction]] = {
    "sca:sbom": _sca_sbom,
    "sca:match": _sca_match,
    "sca:govulncheck": _sca_govulncheck,
    "sca:reach_tasks": _sca_reach_tasks,
    "recon:merge": _recon_merge,
    "plan:ledger": _plan_ledger,
    "plan:tasks": _plan_tasks,
    budget.REVIEW_STEP: _review_tasks,
    budget.CONSOLIDATE_STEP: _consolidate,
    budget.POLISH_STEP: _polish,
    "poc:skip": _poc_skip,
    "poc:run": _poc_run,
    "merge": _merge,
}


def step_function(name: str) -> StepFunction | None:
    """Return the function of a step name, or None for an unknown name."""
    if name.startswith("scan:"):
        return _scan
    if name in ("report:tr", "report:en"):
        return _report
    return _STEPS.get(name)


# ---------------------------------------------------------------------------------------------
# Selection and liveness


def step_is_live(record: dict[str, Any], now: datetime | None = None) -> bool:
    """Return True when a ``running`` step still belongs to a live process."""
    if record.get("status") != "running":
        return False
    try:
        started = ids.parse_ts(record.get("started_at"))
    except ValueError:
        return False
    limit = int(record.get("timeout_seconds") or DEFAULT_MAX_SECONDS) + STALE_GRACE_SECONDS
    if (ids.as_utc(now) - started).total_seconds() > limit:
        return False
    if record.get("host") == lock.hostname():
        return lock.pid_alive(record.get("pid"))
    return True


def first_open_step(state: dict[str, Any], phase: str) -> str | None:
    """Return the first step of ``phase`` that is not done, skipped or failed."""
    for name, record in state["phases"][phase]["steps"].items():
        if record["status"] not in _TERMINAL:
            return name
    return None


def open_tasks(state: dict[str, Any], phase: str) -> list[str]:
    """Return the IDs of ``pending`` or ``leased`` tasks of ``phase``."""
    return [
        task_id
        for task_id, task in state["tasks"].items()
        if task["phase"] == phase and task["status"] in ("pending", "leased")
    ]


# ---------------------------------------------------------------------------------------------
# run step


def _result(phase: str, step: str | None, status: str, detail: str, duration: float) -> dict:
    return {
        "phase": phase,
        "step": step,
        "status": status,
        "detail": detail,
        "duration_seconds": round(duration, 3),
    }


def run_step(
    ctx: RunContext, max_seconds: int = DEFAULT_MAX_SECONDS, *, now: datetime | None = None
) -> dict[str, Any]:
    """Run the first open engine step of the current phase (module docstring)."""
    from kalkan.run.phases import ensure_entered  # noqa: PLC0415 - phases imports this module

    ensure_entered(ctx, now=now)
    limits = StepLimits(max(1, int(max_seconds)))
    pid = os.getpid()
    picked: tuple[str, str] | None = None
    early: dict[str, Any] | None = None
    with transaction(ctx, now=now) as tx:
        state = tx.state
        phase = state["phase"]
        name = first_open_step(state, phase)
        if phase == "done" or name is None:
            early = _result(phase, None, "idle", "no engine step is open", 0.0)
        else:
            record = state["phases"][phase]["steps"][name]
            if step_is_live(record, now):
                early = _result(
                    phase, name, "busy", f"process {record.get('pid')} runs this step", 0.0
                )
            elif open_tasks(state, phase):
                early = _result(phase, name, "idle", "the phase still has open agent tasks", 0.0)
            else:
                starts = int(record.get("attempts") or 0) + 1
                timestamp = ids.format_ts(now)
                if starts > MAX_STEP_STARTS:
                    detail = (
                        f"the step started {MAX_STEP_STARTS} times without finishing "
                        "(crash or timeout)"
                    )
                    record.update(status="failed", detail=detail, finished_at=timestamp)
                    record.pop("pid", None)
                    record.pop("host", None)
                    tx.event("step_failed", phase=phase, step=name, detail=detail)
                    early = _result(phase, name, "failed", detail, 0.0)
                else:
                    record.update(
                        status="running",
                        pid=pid,
                        host=lock.hostname(),
                        started_at=timestamp,
                        finished_at=None,
                        timeout_seconds=limits.max_seconds,
                        attempts=starts,
                    )
                    tx.event("step_started", phase=phase, step=name, attempt=starts)
                    picked = (phase, name)
    if early is not None:
        return early
    assert picked is not None
    phase, name = picked
    started = time.monotonic()
    function = step_function(name)
    try:
        if function is None:
            outcome = StepOutcome("failed", f"unknown step {name!r}")
        else:
            outcome = function(ctx, name, limits)
    except ModuleUnavailable as exc:
        outcome = StepOutcome("skipped", f"module_unavailable: {exc}")
    except KalkanError as exc:
        outcome = StepOutcome("failed", clean_text(str(exc), _DETAIL_MAX) or type(exc).__name__)
    except Exception as exc:  # a failed step never stops the run
        outcome = StepOutcome(
            "failed", clean_text(f"internal error: {type(exc).__name__}: {exc}", _DETAIL_MAX)
        )
    duration = time.monotonic() - started
    detail = clean_text(outcome.detail, _DETAIL_MAX)
    with transaction(ctx) as tx:
        record = tx.state["phases"][phase]["steps"].get(name)
        if record is not None and record.get("status") == "running" and record.get("pid") == pid:
            record.update(
                status=outcome.status,
                detail=detail,
                finished_at=ids.format_ts(),
                duration_seconds=round(duration, 3),
            )
            record.pop("pid", None)
            record.pop("host", None)
            tx.event("step_finished", phase=phase, step=name, status=outcome.status)
    return _result(phase, name, outcome.status, detail, duration)
