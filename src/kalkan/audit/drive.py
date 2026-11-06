# SPDX-License-Identifier: MIT
"""Engine steps in this process and the progress of agent rounds (docs/ENGINE-SPEC.md,
section 25).

:func:`drive_steps` runs the engine steps of a run in this process, as the skill does with
``run next`` and ``run step``:

1. It asks :func:`kalkan.run.phases.next_action` for the next action with a claim limit of 0,
   so it never leases an agent task.
2. An ``engine_step`` of an allowed phase runs with :func:`kalkan.run.steps.run_step` and a time
   budget of :data:`STEP_SECONDS` (no host tool timeout limits this process; each scanner keeps
   its own limit). Every step gives one progress line; a new phase gives one line first.
3. A ``wait`` action whose reason is a step in another process sleeps :data:`WAIT_SECONDS` and
   asks again. Any other action ends the drive and is returned: ``done`` or ``incomplete``, an
   engine step of a phase that is not allowed, or a ``wait`` for agent tasks.

The allowed phases: :data:`DETERMINISTIC_PHASES` in agent mode (the scanners and SCA; the agent
rounds take over at ``recon``), every phase in tools-only mode (the phase engine skips the agent
phases, docs/PHASES.md section 3). A step failure never stops the drive: the run records it and
the report shows it.

:class:`RunWatcher` follows a run while agent rounds work on it. A daemon thread reads
``state.json`` every :data:`WATCH_SECONDS` seconds without the run lock (state writes are
atomic) and prints a line when the phase changes, and the task counts at most every
:data:`TASK_LINE_SECONDS` seconds while they change. A read error skips that read.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Collection
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from kalkan.errors import KalkanError
from kalkan.run import phases, steps
from kalkan.run.state import SETTLED_TASK_STATUSES, RunContext, load_state

__all__ = [
    "DETERMINISTIC_PHASES",
    "OWNER",
    "STEP_SECONDS",
    "TASK_LINE_SECONDS",
    "WAIT_SECONDS",
    "WATCH_SECONDS",
    "RunWatcher",
    "Snapshot",
    "drive_steps",
    "snapshot",
]

#: The phases of the scanners and SCA. In agent mode ``kalkan audit`` runs them itself.
DETERMINISTIC_PHASES: Final = ("deterministic", "sca")
#: The time budget of one engine step in this process (seconds).
STEP_SECONDS: Final = 3600
#: The pause after a ``wait`` action (another process runs a step of the run).
WAIT_SECONDS: Final = 15.0
#: The owner name of ``run next`` (no task is ever leased with the claim limit 0).
OWNER: Final = "kalkan-audit"
#: The poll interval of :class:`RunWatcher`, and the shortest time between two task lines.
WATCH_SECONDS: Final = 30.0
TASK_LINE_SECONDS: Final = 120.0
#: A drive stops after this many actions (a guard against a phase engine that never settles).
MAX_ACTIONS: Final = 10_000
_DETAIL_CHARS: Final = 160
_STEP_WAIT_REASON: Final = "engine step"

Say = Callable[[str], None]


def _short(text: str, limit: int = _DETAIL_CHARS) -> str:
    flat = " ".join(str(text).split())
    return flat if len(flat) <= limit else flat[: limit - 3] + "..."


def drive_steps(
    ctx: RunContext,
    *,
    allowed: Collection[str] | None,
    say: Say,
    max_seconds: int = STEP_SECONDS,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    """Run the engine steps of ``ctx`` (see the module docstring) and return the action that
    ended the drive. ``allowed`` None allows every phase (tools-only mode)."""
    shown_phase: str | None = None
    for _ in range(MAX_ACTIONS):
        action = phases.next_action(ctx, OWNER, 0)
        kind = action["kind"]
        if kind == "engine_step":
            phase = action["phase"]
            if allowed is not None and phase not in allowed:
                return action
            if phase != shown_phase:
                say(f"phase {phase}")
                shown_phase = phase
            outcome = steps.run_step(ctx, max_seconds)
            status = str(outcome["status"])
            line = f"  {outcome['step']}: {status} ({outcome['duration_seconds']:.1f} s)"
            detail = _short(str(outcome.get("detail") or "").removeprefix(f"{status}: "))
            say(f"{line}: {detail}" if detail else line)
            continue
        if kind == "wait" and _STEP_WAIT_REASON in str(action.get("reason", "")):
            say(f"waiting: {action['reason']}")
            sleep(WAIT_SECONDS)
            continue
        return action
    raise KalkanError(f"the engine made no progress in {MAX_ACTIONS} actions")


@dataclass(frozen=True)
class Snapshot:
    """The progress of a run: its phase, its agent tasks and its budget."""

    phase: str
    finished: int
    total: int
    running: int
    used: int
    budget: int

    def line(self) -> str:
        """Return ``phase hunt: 14 of 31 agent tasks finished, 6 running; budget 45 of 150``."""
        if self.total == 0:
            return f"phase {self.phase}"
        return (
            f"phase {self.phase}: {self.finished} of {self.total} agent tasks finished, "
            f"{self.running} running; budget {self.used} of {self.budget} used"
        )


def snapshot(state: dict[str, Any]) -> Snapshot:
    """Return the :class:`Snapshot` of a run state."""
    tasks = [task for task in state["tasks"].values() if isinstance(task, dict)]
    budget = state.get("budget") or {}
    return Snapshot(
        phase=str(state.get("phase")),
        finished=sum(1 for task in tasks if task.get("status") in SETTLED_TASK_STATUSES),
        total=len(tasks),
        running=sum(1 for task in tasks if task.get("status") == "leased"),
        used=int(budget.get("used_agent_tasks") or 0),
        budget=int(budget.get("max_agent_tasks") or 0),
    )


class RunWatcher:
    """Print the progress of the run in ``run_dir`` while agent rounds work on it.

    Use it as a context manager around the rounds, or call :meth:`poll` directly (tests).
    ``clock`` gives monotonic seconds.
    """

    def __init__(
        self,
        run_dir: str | Path,
        say: Say,
        *,
        interval: float = WATCH_SECONDS,
        task_interval: float = TASK_LINE_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.run_dir = Path(run_dir)
        self._say = say
        self._interval = interval
        self._task_interval = task_interval
        self._clock = clock
        self._printed: Snapshot | None = None
        self._printed_at = 0.0
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def poll(self) -> str | None:
        """Read the state once and return the line that it printed, or None.

        A new phase always prints. Changed task counts print when the last line is at least the
        task interval old; until then the change waits for a later poll.
        """
        try:
            current = snapshot(load_state(self.run_dir))
        except (KalkanError, OSError, ValueError, KeyError, TypeError):
            return None
        now = self._clock()
        printed = self._printed
        if printed is not None and current.phase == printed.phase:
            same = (current.finished, current.total) == (printed.finished, printed.total)
            if same or now - self._printed_at < self._task_interval:
                return None
        self._printed, self._printed_at = current, now
        line = current.line()
        self._say(line)
        return line

    def _run(self) -> None:
        while not self._stop.wait(self._interval):
            self.poll()

    def start(self) -> RunWatcher:
        """Start the watcher thread (it reads the state at once, then every interval)."""
        self.poll()
        self._thread = threading.Thread(target=self._run, name="kalkan-audit-watch", daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        """Stop the watcher thread."""
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None

    def __enter__(self) -> RunWatcher:
        return self.start()

    def __exit__(self, *_exc: object) -> None:
        self.stop()
