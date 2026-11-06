# SPDX-License-Identifier: MIT
"""The unattended round loop (docs/ENGINE-SPEC.md, section 22).

:class:`UnattendedLoop` runs the kalkan skill headless in rounds until the run is done. The
skill prefix comes from the host: ``/kalkan`` for Claude Code, ``$kalkan`` for Codex.

1. The loop binds to one run ID before the first round and never changes it. For a new audit
   it creates the run itself (:func:`init_command`: ``<python> -m kalkan run init <target>
   --profile <profile> --json``, plus ``--no-latest`` when asked) and binds to the ``run_id``
   of the output. A failed ``run init`` stops the loop (``init_failed``, exit code 1).
   ``devam`` with a run ID binds to that run. ``devam`` without one reads ``runs/LATEST`` once,
   at the start. After that the loop never reads ``runs/LATEST`` again, so a parallel
   ``run init`` (which moves ``runs/LATEST``) cannot touch this loop.
2. Every round sends ``/kalkan devam <run-id> --headless`` (:func:`resume_prompt`), so the
   skill passes ``--run <run-id>`` to every engine command. A round starts the host command
   without a shell, from the repository root. Its stdout goes line by line into the log, its
   stderr too, with the prefix ``[stderr] ``. A round that runs longer than the round limit
   (default 6 hours) loses its whole process tree: ``taskkill /T /F`` on Windows, the process
   group on Linux and macOS.
3. After each round the loop checks that the folder of the bound run still exists
   (:func:`run_checker`). A run that is gone stops the loop (``run_changed``, exit code 1).
   Then it reads ``kalkan run status --run <run-id> --json`` in a subprocess of the same
   Python. Phase ``done`` stops the loop: exit code 0, or exit code 1 when the run finished
   incomplete (``incomplete_reason`` set; the partial report lists the gap). An incomplete
   reason before phase ``done`` does not stop the loop: the engine still runs validation,
   merge and the report. The exit code of the host is logged, but no decision uses it.
4. A limit that waiting cannot clear (:meth:`~kalkan.unattended.hosts.Host.parse_fatal`, for
   example depleted Codex credits) stops the loop with exit code 1, unless the round also
   reports a reset time.
5. Otherwise the loop waits. A usage limit with a reset time (:mod:`kalkan.unattended.limits`)
   gives a wait until the reset plus :data:`RESET_MARGIN`. A round with progress (a later
   phase, or more finished tasks or steps) starts the next round at once and resets the
   backoff. A round without progress waits 5, 10, 20, 40, 60, then 60 minutes.
6. The loop sleeps in chunks of at most 5 minutes and logs every wake-up. It never sleeps past
   ``--max-hours``. When the next round would start after that limit, it stops with exit
   code 1 and says how to resume.
7. ``--max-usd`` caps the cost of the run (the sum of ``total_cost_usd`` in ``usage.jsonl``,
   over every session). Before each round the loop stops (``max_usd``, exit code 1) when the
   cap is reached, or when the last round ended with the result ``error_max_budget_usd``.
   Otherwise a host with ``budget_args`` (Claude Code: ``--max-budget-usd``) gets the rest of
   the cap, so one round cannot pass it. The cost is the estimate of Claude Code at list
   prices; the bill of the API account is the authority.

The process starter, the clock, the sleep function, the run creator, the run checker, the
status reader and the process-tree killer are parameters, so that tests never start the real
host or the engine.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import math
import os
import shlex
import signal
import stat
import subprocess
import sys
import threading
import time
from collections import deque
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import IO, Any, Final, Protocol, TextIO

from kalkan import __version__
from kalkan.errors import KalkanError, ToolError, UnsafeInputError
from kalkan.run import budget, ids
from kalkan.run import usage as usage_mod
from kalkan.unattended import auth as auth_mod
from kalkan.unattended.hosts import Host
from kalkan.unattended.limits import LimitInfo

__all__ = [
    "BACKOFF_MINUTES",
    "DEFAULT_COMMAND",
    "DEFAULT_MAX_HOURS",
    "DEFAULT_PROFILE",
    "DEFAULT_ROUND_HOURS",
    "INIT_TIMEOUT_SECONDS",
    "PHASES",
    "PROFILES",
    "profile_arg",
    "RESET_MARGIN",
    "DEFAULT_SKILL",
    "RESUME_WORDS",
    "SLEEP_CHUNK_SECONDS",
    "Backoff",
    "RoundResult",
    "RunCreation",
    "RunLog",
    "RunStatus",
    "StatusReading",
    "TailBuffer",
    "UnattendedLoop",
    "UnattendedOptions",
    "UnattendedResult",
    "format_command",
    "init_command",
    "kill_process_tree",
    "log_file_name",
    "made_progress",
    "parse_status",
    "popen_options",
    "resume_hint",
    "resume_prompt",
    "run_checker",
    "status_command",
    "subprocess_run_creator",
    "subprocess_status_reader",
]

EXIT_OK: Final = 0
EXIT_ERROR: Final = 1

DEFAULT_MAX_HOURS: Final = 24.0
DEFAULT_ROUND_HOURS: Final = 6.0
#: The loop wakes up this long after a reported reset time.
RESET_MARGIN: Final = timedelta(minutes=2)
#: The longest single sleep. The loop checks the wall clock after each one.
SLEEP_CHUNK_SECONDS: Final = 300.0
#: Waits after rounds without progress and without a reset time. The last value repeats.
BACKOFF_MINUTES: Final = (5, 10, 20, 40, 60)
#: The loop starts no round when less time than this is left before ``--max-hours``.
MIN_ROUND_SECONDS: Final = 60.0
STATUS_TIMEOUT_SECONDS: Final = 120.0
#: The longest ``run init`` of a new audit (a git clone stops by itself after 540 seconds; a
#: large local folder takes longer to copy).
INIT_TIMEOUT_SECONDS: Final = 1800.0
KILL_WAIT_SECONDS: Final = 30.0
READER_JOIN_SECONDS: Final = 30.0
TERM_GRACE_SECONDS: Final = 5.0
#: The loop keeps at most this much of the newest round output for the limit parser.
TAIL_MAX_CHARS: Final = 8 * 1024 * 1024

PROFILES: Final = ("fast", "standard", "deep")
DEFAULT_PROFILE: Final = "standard"
RESUME_WORDS: Final = ("devam", "resume")
#: The skill prefix of Claude Code prompts. A host gives its own prefix in ``Host.skill``.
DEFAULT_SKILL: Final = "/kalkan"
#: The command that the stop messages name for a restart (the plugin uses ``kalkan-unattended``).
DEFAULT_COMMAND: Final = "kalkan unattended"


#: The help text of ``--max-usd`` (``kalkan unattended`` and ``kalkan audit``).
MAX_USD_HELP: Final = (
    "stop before a round when the recorded cost of the run reaches N US dollars (the estimate "
    "of Claude Code at list prices, over every session); each Claude Code round gets the rest "
    "as --max-budget-usd. Advised with an API key (Claude API, Microsoft Foundry, Bedrock, "
    "Vertex)"
)


def usd_arg(text: str) -> float:
    """Return a positive amount of US dollars for ``--max-usd``."""
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a number: {text!r}") from None
    if not math.isfinite(value) or value <= 0:
        raise argparse.ArgumentTypeError("must be more than 0 US dollars")
    return value


def profile_arg(value: str) -> str:
    """The argparse type of ``--profile``: an accepted name (also a name before 1.6.0, such as
    ``derin``), turned into its canonical name."""
    try:
        return budget.canonical_profile(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


#: Run phases in order (docs/ENGINE-SPEC.md, section 11).
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
#: Task statuses that end a task (``kalkan.run.state.SETTLED_TASK_STATUSES``).
_FINISHED_TASKS: Final = frozenset({"done", "dead", "skipped"})
_TASK_STATUS_WORDS: Final = _FINISHED_TASKS | {"pending", "leased", "failed", "total"}
_FINISHED_STEPS: Final = frozenset({"done", "skipped", "failed"})
_FINISHED_PHASES: Final = frozenset({"done", "skipped"})
_TASK_COUNT_KEYS: Final = (
    "tasks_done",
    "done_tasks",
    "finished_tasks",
    "completed_tasks",
    "tasks_finished",
)
_TASK_MAP_KEYS: Final = ("tasks", "task_counts", "tasks_by_status", "counts")
#: Keys that change without progress. The status digest leaves them out.
_VOLATILE_KEYS: Final = frozenset(
    {
        "updated_at",
        "now",
        "ts",
        "timestamp",
        "generated_at",
        "checked_at",
        "expires_at",
        "lease",
        "heartbeat",
        "elapsed_seconds",
        "age_seconds",
    }
)

REASON_DONE: Final = "done"
REASON_INCOMPLETE: Final = "incomplete"
REASON_MAX_HOURS: Final = "max_hours"
REASON_NO_RUN: Final = "no_run"
#: The bound run is gone (its folder was removed or replaced). Another run that moves
#: ``runs/LATEST`` never gives this reason.
REASON_RUN_CHANGED: Final = "run_changed"
REASON_HOST_BLOCKED: Final = "host_blocked"
REASON_INIT_FAILED: Final = "init_failed"
REASON_MAX_USD: Final = "max_usd"
#: The result subtype of a Claude Code round that hit ``--max-budget-usd``.
BUDGET_SUBTYPE: Final = "error_max_budget_usd"

_IS_WINDOWS: Final = os.name == "nt"

Clock = Callable[[], datetime]
Sleep = Callable[[float], None]
Say = Callable[[str], None]


class Process(Protocol):
    """The part of :class:`subprocess.Popen` that the loop uses."""

    pid: int
    stdout: IO[bytes] | None
    stderr: IO[bytes] | None

    def wait(self, timeout: float | None = None) -> int: ...

    def poll(self) -> int | None: ...

    def kill(self) -> None: ...


PopenFactory = Callable[..., Process]
KillTree = Callable[[Process], None]


# ---------------------------------------------------------------------------------------------
# Prompts, command lines and file names


def resume_prompt(run_id: str, skill: str = DEFAULT_SKILL) -> str:
    """Return the prompt of every round: ``<skill> devam <run-id> --headless``.

    ``skill`` is ``/kalkan`` (Claude Code in a checkout), ``/kalkan:kalkan`` (the plugin) or
    ``$kalkan`` (Codex). The caller passes a checked run ID (:func:`kalkan.run.ids.is_run_id`);
    a dry run passes a placeholder.
    """
    return f"{skill} devam {run_id} --headless"


def init_command(
    target: str, profile: str, *, latest: bool = True, python: str | None = None
) -> list[str]:
    """Return the command that creates the run of a new audit:
    ``<python> -m kalkan run init <target> --profile <profile> [--no-latest] --json``.

    The caller passes a normalized target (an absolute folder or a git URL, never text that
    starts with ``-``).
    """
    argv = [python or sys.executable, "-m", "kalkan", "run", "init", target, "--profile", profile]
    if not latest:
        argv.append("--no-latest")
    return [*argv, "--json"]


def resume_hint(
    command: str,
    host_name: str,
    run_id: str | None,
    target: str | None = None,
    profile: str = DEFAULT_PROFILE,
) -> str:
    """Return the command that continues the audit.

    ``<command> devam <run-id>`` when the run exists, else ``<command> <target> --profile
    <profile>`` (the run was not created), else ``<command> devam``. A host other than Claude
    Code adds ``--host <name>``.
    """
    host = "" if host_name == "claude" else f" --host {host_name}"
    if run_id is not None:
        return f"{command} devam {run_id}{host}"
    if target is not None:
        shown = f'"{target}"' if any(ch.isspace() for ch in target) else target
        return f"{command} {shown} --profile {profile}{host}"
    return f"{command} devam{host}"


def format_command(argv: Sequence[str]) -> str:
    """Return ``argv`` as one command line for display (Windows or POSIX quoting)."""
    if _IS_WINDOWS:
        return subprocess.list2cmdline([str(arg) for arg in argv])
    return shlex.join(str(arg) for arg in argv)


def log_file_name(moment: datetime) -> str:
    """Return ``unattended-<UTC yyyymmddThhmmssZ>.log``."""
    return f"unattended-{ids.as_utc(moment).strftime('%Y%m%dT%H%M%SZ')}.log"


def status_command(run_id: str, python: str | None = None) -> list[str]:
    """Return the command that reads the status of the bound run:
    ``<python> -m kalkan run status --run <run-id> --json``."""
    return [python or sys.executable, "-m", "kalkan", "run", "status", "--run", run_id, "--json"]


def _local_text(moment: datetime) -> str:
    local = moment.astimezone()
    offset = local.strftime("%z") or "+0000"
    return f"{local:%Y-%m-%d %H:%M} (UTC{offset[:3]}:{offset[3:5]})"


def _hours_text(hours: float) -> str:
    return f"{hours:g}"


# ---------------------------------------------------------------------------------------------
# Run status


@dataclass(frozen=True)
class RunStatus:
    """The parts of ``kalkan run status --json`` that the loop uses.

    ``finished_tasks`` counts tasks with status ``done``, ``dead`` or ``skipped``.
    ``finished_steps`` counts finished engine steps plus finished phases. Each is None when the
    status has no such data. ``digest`` is a hash of the status without volatile fields such as
    timestamps and leases.
    """

    run_id: str | None
    phase: str | None
    incomplete: bool
    incomplete_reason: str | None
    finished_tasks: int | None
    finished_steps: int | None
    digest: str

    @property
    def done(self) -> bool:
        """True when the phase is ``done``."""
        return self.phase == "done"

    @property
    def finished_incomplete(self) -> bool:
        """True when the run ended incomplete: phase ``done`` (or a status without a known
        phase) with an incomplete marker."""
        return self.incomplete and (self.done or self.phase not in PHASES)

    @property
    def countable(self) -> bool:
        """True when the status has task or step counts."""
        return self.finished_tasks is not None or self.finished_steps is not None

    def progress_key(self) -> tuple[int, int, int]:
        """Return (phase rank, finished tasks, finished steps)."""
        rank = PHASES.index(self.phase) if self.phase in PHASES else -1
        return rank, self.finished_tasks or 0, self.finished_steps or 0

    def summary(self) -> str:
        """Return a short text such as ``phase hunt, 12 tasks finished, 9 steps finished``."""
        parts = [f"phase {self.phase or 'unknown'}"]
        if self.finished_tasks is not None:
            parts.append(f"{self.finished_tasks} tasks finished")
        if self.finished_steps is not None:
            parts.append(f"{self.finished_steps} steps finished")
        if self.incomplete:
            parts.append("incomplete")
        return ", ".join(parts)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-ready dict."""
        return {
            "run_id": self.run_id,
            "phase": self.phase,
            "incomplete": self.incomplete,
            "incomplete_reason": self.incomplete_reason,
            "finished_tasks": self.finished_tasks,
            "finished_steps": self.finished_steps,
        }


def _is_count(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _finished_in(value: object) -> int | None:
    """Count finished tasks in a task map, a status-count map or a task list."""
    if isinstance(value, list):
        statuses = [item.get("status") for item in value if isinstance(item, Mapping)]
        if statuses:
            return sum(status in _FINISHED_TASKS for status in statuses)
        return 0 if not value else None
    if not isinstance(value, Mapping):
        return None
    for key in ("by_status", "counts"):
        nested = value.get(key)
        if isinstance(nested, Mapping):
            value = nested
            break
    if not value:
        return 0
    records = [item for item in value.values() if isinstance(item, Mapping) and "status" in item]
    if records:
        return sum(item.get("status") in _FINISHED_TASKS for item in records)
    counts = {key: item for key, item in value.items() if _is_count(item)}
    if any(key in counts for key in _TASK_STATUS_WORDS):
        return sum(counts.get(key, 0) for key in _FINISHED_TASKS)
    return None


def _finished_tasks(body: Mapping[str, Any]) -> int | None:
    for key in _TASK_COUNT_KEYS:
        if _is_count(body.get(key)):
            return int(body[key])
    for key in _TASK_MAP_KEYS:
        found = _finished_in(body.get(key))
        if found is not None:
            return found
    return None


def _finished_steps(body: Mapping[str, Any]) -> int | None:
    phases = body.get("phases")
    if not isinstance(phases, Mapping):
        return None
    total = 0
    for phase in phases.values():
        if isinstance(phase, str):
            total += phase in _FINISHED_PHASES
            continue
        if not isinstance(phase, Mapping):
            continue
        total += phase.get("status") in _FINISHED_PHASES
        steps = phase.get("steps")
        if isinstance(steps, Mapping):
            for step in steps.values():
                status = step.get("status") if isinstance(step, Mapping) else step
                total += status in _FINISHED_STEPS
    return total


def _stable(value: object, depth: int = 0) -> object:
    if depth > 32:
        return None
    if isinstance(value, Mapping):
        return {
            str(key): _stable(item, depth + 1)
            for key, item in value.items()
            if key not in _VOLATILE_KEYS
        }
    if isinstance(value, list):
        return [_stable(item, depth + 1) for item in value]
    return value


def _reason_text(value: object) -> str | None:
    if value is None or value is False:
        return None
    if isinstance(value, str):
        text = " ".join(value.split())
        return text[:500] or None
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True)[:500]
    except (TypeError, ValueError):
        return str(value)[:500]


def parse_status(document: object) -> RunStatus | None:
    """Return the :class:`RunStatus` of a ``run status --json`` document, or None.

    The output format of ``run status`` is not fixed yet, so the parser accepts several shapes:
    the state fields at the top level or under ``state``, ``run`` or ``status``; task counts as
    ``tasks`` (a task map, a task list or ``{total, by_status}``), ``task_counts``,
    ``tasks_by_status`` or ``counts``; steps under ``phases``. The run is incomplete when
    ``incomplete_reason`` is set, or when ``status``, ``state``, ``kind`` or ``phase`` is
    ``incomplete``.
    """
    if not isinstance(document, Mapping):
        return None
    body: Mapping[str, Any] = document
    if "phase" not in document:
        for key in ("state", "run", "status"):
            inner = document.get(key)
            if isinstance(inner, Mapping) and "phase" in inner:
                body = inner
                break
    run_id = body.get("run_id", document.get("run_id"))
    phase = body.get("phase")
    reason = _reason_text(body.get("incomplete_reason", document.get("incomplete_reason")))
    markers = [body.get(key) for key in ("status", "state", "kind")]
    markers += [document.get(key) for key in ("status", "state", "kind")]
    incomplete = reason is not None or phase == "incomplete" or "incomplete" in markers
    try:
        canonical = json.dumps(_stable(document), sort_keys=True, ensure_ascii=True, default=str)
    except (TypeError, ValueError):
        canonical = repr(document)
    return RunStatus(
        run_id=run_id if isinstance(run_id, str) and run_id else None,
        phase=phase if isinstance(phase, str) and phase else None,
        incomplete=incomplete,
        incomplete_reason=reason,
        finished_tasks=_finished_tasks(body),
        finished_steps=_finished_steps(body),
        digest=hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
    )


def made_progress(before: RunStatus | None, after: RunStatus | None) -> bool:
    """Return True when ``after`` shows progress over ``before``.

    Progress is a later phase, more finished tasks or more finished steps. A run that appears
    (``before`` is None) or changes its ID also counts. When a status has no counts, any change
    of the status digest counts.
    """
    if after is None:
        return False
    if before is None:
        return True
    if before.run_id and after.run_id and before.run_id != after.run_id:
        return True
    if any(a > b for a, b in zip(after.progress_key(), before.progress_key(), strict=True)):
        return True
    if not (before.countable and after.countable):
        return after.digest != before.digest
    return False


@dataclass(frozen=True)
class StatusReading:
    """The result of one status read: a status, or None and an error message."""

    status: RunStatus | None
    error: str | None = None


@dataclass(frozen=True)
class RunCreation:
    """The result of ``run init``: the new run ID, or None and an error message."""

    run_id: str | None
    error: str | None = None


#: Reads the status of the run with the given ID.
StatusReader = Callable[[str], StatusReading]
LatestReader = Callable[[], "str | None"]
#: Creates the run of a new audit: ``(target, profile, latest, timeout seconds)``.
RunCreator = Callable[[str, str, bool, float], RunCreation]
#: Returns None when the run with the given ID exists, else the reason.
RunChecker = Callable[[str], "str | None"]

_ENGINE_ERROR_PREFIX: Final = "kalkan: error:"


def _decode(data: object) -> str:
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    return data if isinstance(data, str) else ""


def _first_line(text: str) -> str:
    for line in text.splitlines():
        if line.strip():
            return " ".join(line.split())[:300]
    return ""


def _error_line(text: str) -> str:
    """Return the engine error line (``kalkan: error: ...``) of stderr, else its last line."""
    lines = [" ".join(line.split()) for line in text.splitlines() if line.strip()]
    for line in reversed(lines):
        if line.startswith(_ENGINE_ERROR_PREFIX):
            return line[len(_ENGINE_ERROR_PREFIX) :].strip()[:300]
    return lines[-1][:300] if lines else ""


def _json_document(text: str) -> object:
    stripped = text.strip()
    try:
        return json.loads(stripped)
    except ValueError:
        start = stripped.find("{")
        if start < 0:
            return None
        try:
            return json.JSONDecoder().raw_decode(stripped[start:])[0]
        except ValueError:
            return None


def subprocess_status_reader(
    cwd: str | os.PathLike[str],
    *,
    python: str | None = None,
    timeout: float = STATUS_TIMEOUT_SECONDS,
    runner: Callable[..., Any] = subprocess.run,
) -> StatusReader:
    """Return a reader that runs ``<python> -m kalkan run status --run <run-id> --json`` in
    ``cwd`` (:func:`status_command`).

    The child process writes UTF-8 (``PYTHONIOENCODING``). A non-zero exit code, a timeout or
    output without a JSON object gives a :class:`StatusReading` with an error.
    """
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}

    def read(run_id: str) -> StatusReading:
        try:
            proc = runner(
                status_command(run_id, python),
                cwd=os.fspath(cwd),
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                check=False,
                shell=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return StatusReading(None, f"kalkan run status did not run: {exc}")
        if proc.returncode != 0:
            message = _first_line(_decode(proc.stderr)) or "no message"
            return StatusReading(
                None, f"kalkan run status exited with code {proc.returncode}: {message}"
            )
        status = parse_status(_json_document(_decode(proc.stdout)))
        if status is None:
            return StatusReading(None, "kalkan run status --json printed no JSON object")
        return StatusReading(status)

    return read


def subprocess_run_creator(
    cwd: str | os.PathLike[str],
    *,
    python: str | None = None,
    runner: Callable[..., Any] = subprocess.run,
) -> RunCreator:
    """Return a creator that runs ``run init`` (:func:`init_command`) in ``cwd``.

    The run ID comes from the ``run_id`` field of the JSON output and must be well-formed. A
    non-zero exit code (the message is the engine error line), a timeout or output without a
    valid run ID gives a :class:`RunCreation` with an error.
    """
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}

    def create(target: str, profile: str, latest: bool, timeout: float) -> RunCreation:
        try:
            proc = runner(
                init_command(target, profile, latest=latest, python=python),
                cwd=os.fspath(cwd),
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                check=False,
                shell=False,
            )
        except subprocess.TimeoutExpired:
            minutes = f"{timeout / 60:.0f}"
            return RunCreation(None, f"kalkan run init did not finish in {minutes} minutes")
        except (OSError, subprocess.SubprocessError) as exc:
            return RunCreation(None, f"kalkan run init did not run: {exc}")
        if proc.returncode != 0:
            message = _error_line(_decode(proc.stderr)) or "no message"
            return RunCreation(
                None, f"kalkan run init exited with code {proc.returncode}: {message}"
            )
        document = _json_document(_decode(proc.stdout))
        run_id = document.get("run_id") if isinstance(document, Mapping) else None
        if not ids.is_run_id(run_id):
            return RunCreation(None, "kalkan run init --json printed no valid run ID")
        return RunCreation(str(run_id))

    return create


def run_checker(runs_dir: str | os.PathLike[str] | None = None) -> RunChecker:
    """Return a checker that finds the folder of a run in ``runs_dir`` (None: the runs root).

    The checker returns None when :func:`kalkan.run.ids.resolve_run` accepts the run, else its
    error message (an invalid ID, a missing folder, a link or a file).
    """
    root = Path(runs_dir) if runs_dir is not None else None

    def check(run_id: str) -> str | None:
        try:
            ids.resolve_run(run_id, root)
        except KalkanError as exc:
            return str(exc)
        return None

    return check


def read_latest_run_id() -> str | None:
    """Return the run ID in ``runs/LATEST``, or None (:func:`kalkan.run.ids.read_latest`)."""
    return ids.read_latest()


# ---------------------------------------------------------------------------------------------
# Backoff, output tail and log


class Backoff:
    """Waits after rounds without progress: 5, 10, 20, 40, 60, then 60 minutes."""

    def __init__(self, minutes: Sequence[int] = BACKOFF_MINUTES) -> None:
        if not minutes:
            raise ValueError("the backoff needs at least one step")
        self._minutes = tuple(minutes)
        self._index = 0

    def next_delay(self) -> timedelta:
        """Return the next wait and move to the step after it."""
        value = self._minutes[min(self._index, len(self._minutes) - 1)]
        self._index += 1
        return timedelta(minutes=value)

    def reset(self) -> None:
        """Start again at the first step."""
        self._index = 0


class TailBuffer:
    """The newest output lines of a round, at most ``max_chars`` characters (thread safe)."""

    def __init__(self, max_chars: int = TAIL_MAX_CHARS) -> None:
        self._max = max_chars
        self._lines: deque[str] = deque()
        self._size = 0
        self._lock = threading.Lock()

    def add(self, line: str) -> None:
        """Append a line. A line longer than the limit is dropped."""
        size = len(line)
        if size > self._max:
            return
        with self._lock:
            self._lines.append(line)
            self._size += size
            while self._size > self._max:
                self._size -= len(self._lines.popleft())

    def lines(self) -> list[str]:
        """Return the kept lines, oldest first."""
        with self._lock:
            return list(self._lines)


class RunLog:
    """The append-only log of one ``kalkan unattended`` invocation (thread safe).

    Host stdout lines go in unchanged. Host stderr lines get the prefix ``[stderr] ``. Messages
    of the loop look like ``[kalkan 2026-10-16T09:00:00Z] message``. Every line is flushed at
    once. The file must be a regular file. A link is refused.
    """

    STDERR_PREFIX: Final = "[stderr] "

    def __init__(self, path: str | os.PathLike[str], *, clock: Clock = ids.utc_now) -> None:
        self.path = Path(path)
        self._clock = clock
        self._lock = threading.Lock()
        self._handle: TextIO | None = None

    def open(self) -> RunLog:
        """Create the folder when needed and open the file for appending."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            info: os.stat_result | None = os.lstat(self.path)
        except FileNotFoundError:
            info = None
        if info is not None:
            attributes = getattr(info, "st_file_attributes", 0) or 0
            if (
                stat.S_ISLNK(info.st_mode)
                or attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT
                or not stat.S_ISREG(info.st_mode)
            ):
                raise UnsafeInputError("the log file must be a regular file, not a link")
        flags = (
            os.O_WRONLY
            | os.O_APPEND
            | os.O_CREAT
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_BINARY", 0)
        )
        descriptor = os.open(self.path, flags, 0o600)
        self._handle = os.fdopen(descriptor, "a", encoding="utf-8", newline="\n", errors="replace")
        return self

    def close(self) -> None:
        """Close the file."""
        with self._lock:
            if self._handle is not None:
                self._handle.close()
                self._handle = None

    def __enter__(self) -> RunLog:
        return self if self._handle is not None else self.open()

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def line(self, text: str) -> None:
        """Append one line unchanged."""
        with self._lock:
            if self._handle is None:
                raise KalkanError("the unattended log is not open")
            self._handle.write(text + "\n")
            self._handle.flush()

    def stderr(self, text: str) -> None:
        """Append one stderr line of the host."""
        self.line(self.STDERR_PREFIX + text)

    def note(self, message: str) -> None:
        """Append one message of the loop with a UTC timestamp."""
        self.line(f"[kalkan {ids.format_ts(self._clock())}] {message}")


# ---------------------------------------------------------------------------------------------
# Processes


def popen_options() -> dict[str, Any]:
    """Return the platform options for the host process.

    On Linux and macOS the host gets its own session and process group, so that
    :func:`kill_process_tree` can stop the host and every process it started.
    """
    return {} if _IS_WINDOWS else {"start_new_session": True}


def _taskkill() -> str:
    root = os.environ.get("SystemRoot") or r"C:\Windows"
    return str(Path(root) / "System32" / "taskkill.exe")


def kill_process_tree(process: Process) -> None:
    """Stop ``process`` and its child processes.

    Windows: ``taskkill /T /F /PID <pid>`` (by its absolute path in System32), then
    ``Popen.kill`` when the process still runs. Linux and macOS: SIGTERM to the process group,
    up to 5 seconds of grace, then SIGKILL.
    """
    if _IS_WINDOWS:
        with contextlib.suppress(OSError, subprocess.SubprocessError):
            subprocess.run(
                [_taskkill(), "/T", "/F", "/PID", str(process.pid)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=60,
                check=False,
                shell=False,
            )
        if process.poll() is None:
            with contextlib.suppress(OSError):
                process.kill()
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except OSError:
        if process.poll() is None:
            with contextlib.suppress(OSError):
                process.kill()
        return
    with contextlib.suppress(subprocess.TimeoutExpired):
        process.wait(timeout=TERM_GRACE_SECONDS)
    with contextlib.suppress(OSError):
        os.killpg(process.pid, signal.SIGKILL)


# ---------------------------------------------------------------------------------------------
# Loop


@dataclass(frozen=True)
class UnattendedOptions:
    """Options of one ``kalkan unattended`` invocation.

    ``target`` starts a new audit: the loop creates the run with ``run init``, and ``latest``
    False adds ``--no-latest``. ``target`` None means ``devam``: ``run_id`` names the run to
    resume, and None binds to the run in ``runs/LATEST`` once at the start. ``command`` is the
    command that the stop messages tell the user to run again.
    """

    target: str | None
    profile: str = DEFAULT_PROFILE
    max_hours: float = DEFAULT_MAX_HOURS
    round_hours: float = DEFAULT_ROUND_HOURS
    command: str = DEFAULT_COMMAND
    run_id: str | None = None
    latest: bool = True
    max_usd: float | None = None

    def __post_init__(self) -> None:
        try:
            object.__setattr__(self, "profile", budget.canonical_profile(self.profile))
        except ValueError:
            raise KalkanError(
                f"unknown profile {self.profile!r} (use {', '.join(PROFILES)})"
            ) from None
        for name in ("max_hours", "round_hours"):
            value = getattr(self, name)
            if not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
                raise KalkanError(f"{name} must be a positive number of hours")
        cap = self.max_usd
        if cap is not None and (
            isinstance(cap, bool)
            or not isinstance(cap, (int, float))
            or not math.isfinite(cap)
            or cap <= 0
        ):
            raise KalkanError("max_usd must be a positive number of US dollars")
        if self.run_id is not None:
            if self.target is not None:
                raise KalkanError("a run ID resumes a run; it cannot go with a target")
            if not ids.is_run_id(self.run_id):
                raise KalkanError("invalid run ID (expected <yyyymmddThhmmssZ>-<slug>-<4 hex>)")

    @property
    def resume(self) -> bool:
        """True for ``devam``: resume ``run_id``, or the run in ``runs/LATEST``."""
        return self.target is None


@dataclass(frozen=True)
class RoundResult:
    """One host round."""

    number: int
    prompt: str
    argv: list[str]
    returncode: int | None
    timed_out: bool
    lines: list[str]
    started_at: datetime
    finished_at: datetime
    error: str | None = None


@dataclass
class UnattendedResult:
    """The outcome of :meth:`UnattendedLoop.run`."""

    exit_code: int
    reason: str
    message: str
    rounds: int
    run_id: str | None
    status: RunStatus | None
    log_file: str
    started_at: datetime
    finished_at: datetime
    limits: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Return the JSON document of ``kalkan unattended --json``."""
        return {
            "exit_code": self.exit_code,
            "reason": self.reason,
            "message": self.message,
            "rounds": self.rounds,
            "run_id": self.run_id,
            "phase": self.status.phase if self.status else None,
            "status": self.status.to_dict() if self.status else None,
            "log_file": self.log_file,
            "started_at": ids.format_ts(self.started_at),
            "finished_at": ids.format_ts(self.finished_at),
            "limits": self.limits,
        }


def _say_stderr(message: str) -> None:
    print(f"kalkan unattended: {message}", file=sys.stderr, flush=True)


class UnattendedLoop:
    """Run the ``/kalkan`` skill headless in rounds (see the module docs)."""

    def __init__(
        self,
        options: UnattendedOptions,
        *,
        host: Host,
        cwd: str | os.PathLike[str],
        log: RunLog,
        read_status: StatusReader,
        read_latest: LatestReader = read_latest_run_id,
        popen: PopenFactory = subprocess.Popen,
        clock: Clock = ids.utc_now,
        sleep: Sleep = time.sleep,
        kill_tree: KillTree = kill_process_tree,
        say: Say | None = None,
        runs_dir: str | os.PathLike[str] | None = None,
        create_run: RunCreator | None = None,
        check_run: RunChecker | None = None,
        environ: Mapping[str, str] | None = None,
    ) -> None:
        self.options = options
        self._host = host
        self._cwd = Path(cwd)
        self._log = log
        self._read_status = read_status
        self._read_latest = read_latest
        self._create_run = create_run or subprocess_run_creator(cwd)
        self._check_run = check_run or run_checker(runs_dir)
        self._popen = popen
        self._clock = clock
        self._sleep = sleep
        self._kill_tree = kill_tree
        self._say = say or _say_stderr
        self._runs_dir = Path(runs_dir) if runs_dir is not None else None
        self._rounds = 0
        self._started_processes = 0
        self._run_id: str | None = None
        self._limits: list[dict[str, Any]] = []
        self._started = clock()
        self._deadline = self._started
        self._auth = auth_mod.detect_auth(os.environ if environ is None else environ)

    # -- public ---------------------------------------------------------------------------

    @property
    def run_id(self) -> str | None:
        """The bound run ID; None before the loop has bound a run."""
        return self._run_id

    def run(self) -> UnattendedResult:
        """Run rounds until a stop rule applies. Returns the result with its exit code.

        Raises :class:`~kalkan.errors.ToolError` when the first host process cannot start.
        KeyboardInterrupt stops the running host process tree and propagates.
        """
        options = self.options
        self._started = self._clock()
        self._deadline = self._started + timedelta(hours=options.max_hours)
        self._log.note(f"start: {self._describe()}")
        backoff = Backoff()
        previous: RunStatus | None = None
        if options.target is not None:
            stop = self._create(options.target)
            if stop is not None:
                return stop
        else:
            stop = self._bind_existing()
            if stop is not None:
                return stop
            previous = self._own(self._read_status_logged())
            if previous is not None and previous.finished_incomplete:
                return self._finish(
                    EXIT_ERROR, REASON_INCOMPLETE, self._incomplete_message(previous), previous
                )
            if previous is not None and previous.done:
                return self._finish(
                    EXIT_OK,
                    REASON_DONE,
                    f"run {self._run_id} is already done. Nothing to resume.",
                    previous,
                )
        run_id = self._run_id
        assert run_id is not None  # _create and _bind_existing bind a run or stop
        prompt = resume_prompt(run_id, self._host.skill)
        while True:
            remaining = (self._deadline - self._clock()).total_seconds()
            if remaining < MIN_ROUND_SECONDS:
                return self._stop_max_hours(previous)
            budget_left: float | None = None
            if options.max_usd is not None:
                spent, hit = self._spent_usd()
                if hit or spent >= options.max_usd:
                    return self._stop_max_usd(spent, previous)
                budget_left = options.max_usd - spent
            self._rounds += 1
            timeout = min(options.round_hours * 3600.0, remaining)
            result = self._run_round(self._rounds, prompt, timeout, budget_left)

            problem = self._check_run(run_id)
            if problem is not None:
                return self._finish(
                    EXIT_ERROR,
                    REASON_RUN_CHANGED,
                    f"run {run_id} cannot be resumed any more: {problem}. Start a new run "
                    f"with: {options.command} <target>{self._host_option()}",
                    previous,
                )

            status = self._own(self._read_status_logged())
            if status is not None:
                if status.finished_incomplete:
                    return self._finish(
                        EXIT_ERROR, REASON_INCOMPLETE, self._incomplete_message(status), status
                    )
                if status.done:
                    return self._finish(EXIT_OK, REASON_DONE, self._done_message(), status)
            progress = made_progress(previous, status)
            if status is not None:
                previous = status
            if progress:
                backoff.reset()
            now = self._clock()
            limit = self._host.parse_limit(result.lines, now=now)
            blocked = self._host.parse_fatal(result.lines)
            if blocked and (limit is None or limit.reset_at + RESET_MARGIN <= now):
                return self._finish(
                    EXIT_ERROR,
                    REASON_HOST_BLOCKED,
                    f"{self._host.name} reports a limit that waiting does not clear: {blocked} "
                    "Fix it (for example add credits or raise the spend cap), then resume "
                    f"with: {self._resume_hint()}",
                    previous,
                )
            wake, why = self._plan_wait(limit, progress, backoff, now)
            if wake is None:
                continue
            if wake > self._deadline:
                return self._stop_before_wait(wake, limit, previous)
            self._sleep_until(wake, why)

    # -- rounds ---------------------------------------------------------------------------

    def _run_round(
        self, number: int, prompt: str, timeout: float, budget_left: float | None = None
    ) -> RoundResult:
        argv = self._host.build_command(prompt)
        budget_args = getattr(self._host, "budget_args", None)
        if budget_left is not None and callable(budget_args):
            argv += budget_args(budget_left)
        self._log.note(
            f"round {number} start: {format_command(argv)} "
            f"(cwd {self._cwd.as_posix()}, time limit {timeout / 3600:.2f} h)"
        )
        self._say(f"round {number} started: {prompt}")
        started = self._clock()
        try:
            process = self._popen(
                argv,
                cwd=os.fspath(self._cwd),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                **popen_options(),
            )
        except OSError as exc:
            self._log.note(f"round {number}: {self._host.name} did not start: {exc}")
            if self._started_processes == 0:
                raise ToolError(f"{self._host.name} did not start: {exc}") from exc
            self._say(f"round {number}: {self._host.name} did not start: {exc}")
            return RoundResult(
                number, prompt, argv, None, False, [], started, self._clock(), str(exc)
            )
        self._started_processes += 1
        tail = TailBuffer()
        results: list[dict[str, Any]] = []
        inits: list[dict[str, Any]] = []
        readers = [
            threading.Thread(
                target=self._pump,
                args=(process.stdout, False, tail, results, inits),
                daemon=True,
            ),
            threading.Thread(target=self._pump, args=(process.stderr, True, tail), daemon=True),
        ]
        for reader in readers:
            reader.start()
        timed_out = False
        try:
            returncode: int | None = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            self._log.note(
                f"round {number}: time limit reached. Stopping the process tree (PID "
                f"{process.pid})."
            )
            self._say(f"round {number}: time limit reached. The host process tree stops.")
            self._kill_tree(process)
            returncode = self._wait_quietly(process)
        except BaseException:
            self._log.note(f"round {number}: interrupted. Stopping the process tree.")
            self._kill_tree(process)
            self._wait_quietly(process)
            raise
        for reader in readers:
            reader.join(READER_JOIN_SECONDS)
        if any(reader.is_alive() for reader in readers):
            self._log.note(
                f"round {number}: output pipes stay open after the host ended. "
                "Stopping the process tree."
            )
            self._kill_tree(process)
            for reader in readers:
                reader.join(5.0)
        finished = self._clock()
        minutes = (finished - started).total_seconds() / 60
        self._log.note(
            f"round {number} end: host exit code {returncode} (logged, not used), "
            f"{'timed out, ' if timed_out else ''}{minutes:.1f} minutes"
        )
        self._say(f"round {number} ended after {minutes:.1f} minutes")
        self._record_usage(number, started, finished, timed_out, results, inits)
        return RoundResult(
            number, prompt, argv, returncode, timed_out, tail.lines(), started, finished
        )

    def _pump(
        self,
        stream: IO[bytes] | None,
        is_stderr: bool,
        tail: TailBuffer,
        results: list[dict[str, Any]] | None = None,
        inits: list[dict[str, Any]] | None = None,
    ) -> None:
        if stream is None:
            return
        try:
            for raw in iter(stream.readline, b""):
                text = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                if is_stderr:
                    self._log.stderr(text)
                else:
                    self._log.line(text)
                    if results is not None:
                        parsed = usage_mod.parse_result(text)
                        if parsed is not None:
                            results.append(parsed)
                    if inits is not None and not inits:
                        init = usage_mod.parse_init(text)
                        if init is not None:
                            inits.append(init)
                tail.add(text)
        except (OSError, ValueError):
            pass  # the pipe closed (for example after the process tree was stopped)
        finally:
            with contextlib.suppress(OSError, ValueError):
                stream.close()

    def _record_usage(
        self,
        number: int,
        started: datetime,
        finished: datetime,
        timed_out: bool,
        results: list[dict[str, Any]],
        inits: list[dict[str, Any]] | None = None,
    ) -> None:
        """Add the round to ``usage.jsonl`` of the bound run (:mod:`kalkan.run.usage`).

        ``round`` counts the rounds of the run over every ``devam`` session, and ``session_round``
        is ``number``, the round of this session (the log line). ``auth`` and ``auth_source``
        name the login of the environment (:func:`kalkan.unattended.auth.detect_auth`, never a
        value); the init event of the round adds ``api_key_source``, ``model`` and
        ``claude_code_version``.
        """
        if self._run_id is None:
            return
        try:
            run_dir = ids.resolve_run(self._run_id, self._runs_dir)
            run_round = len(usage_mod.load(run_dir)) + 1
        except (OSError, KalkanError) as exc:
            self._log.note(f"round {number}: usage not recorded: {exc}")
            return
        entry: dict[str, Any] = {
            "round": run_round,
            "session_round": number,
            "host": self._host.name,
            "started_at": ids.format_ts(started),
            "finished_at": ids.format_ts(finished),
            "wall_seconds": round((finished - started).total_seconds()),
            "timed_out": timed_out,
            "auth": self._auth.mode,
            "auth_source": self._auth.source,
            **(inits[0] if inits else {}),
            **(results[-1] if results else {"result_event": False}),
        }
        try:
            usage_mod.append(run_dir, entry)
        except (OSError, KalkanError) as exc:
            self._log.note(f"round {number}: usage not recorded: {exc}")
            return
        cost = entry.get("total_cost_usd")
        if isinstance(cost, (int, float)):
            self._log.note(f"round {number}: cost USD {cost:.2f} (round {run_round} of the run)")

    def _wait_quietly(self, process: Process) -> int | None:
        try:
            return process.wait(timeout=KILL_WAIT_SECONDS)
        except subprocess.TimeoutExpired:
            return None

    # -- state ----------------------------------------------------------------------------

    def _create(self, target: str) -> UnattendedResult | None:
        """Create the run of a new audit and bind to it. Return a result when it failed."""
        options = self.options
        left = (self._deadline - self._clock()).total_seconds()
        timeout = max(MIN_ROUND_SECONDS, min(INIT_TIMEOUT_SECONDS, left))
        latest = "records" if options.latest else "leaves unchanged"
        self._log.note(
            f"run init: target {target}, profile {options.profile}, time limit "
            f"{timeout / 60:.0f} minutes; it {latest} runs/LATEST"
        )
        self._say(f"run init: {target} ({options.profile})")
        created = self._create_run(target, options.profile, options.latest, timeout)
        if created.run_id is None:
            return self._finish(
                EXIT_ERROR,
                REASON_INIT_FAILED,
                f"the run was not created: {created.error or 'no detail'}. Fix the cause, "
                f"then start again with: {self._resume_hint()}",
                None,
            )
        self._run_id = created.run_id
        self._log.note(f"run created: {created.run_id}. Every round names this run.")
        self._say(f"run {created.run_id} created")
        return None

    def _bind_existing(self) -> UnattendedResult | None:
        """Bind to the run of ``devam``. Return a result when there is no run to resume."""
        options = self.options
        run_id = options.run_id
        if run_id is None:
            run_id = self._latest()
            if run_id is None:
                return self._finish(
                    EXIT_ERROR,
                    REASON_NO_RUN,
                    "no run to resume: runs/LATEST names no run. "
                    f"Start one with: {options.command} <target>{self._host_option()}",
                    None,
                )
            self._log.note(f"devam without a run ID: bound to {run_id} from runs/LATEST")
            self._say(f"devam: the newest run {run_id} (runs/LATEST)")
        problem = self._check_run(run_id)
        if problem is not None:
            return self._finish(
                EXIT_ERROR,
                REASON_NO_RUN,
                f"no run to resume: {problem}. "
                f"Start one with: {options.command} <target>{self._host_option()}",
                None,
            )
        self._run_id = run_id
        return None

    def _latest(self) -> str | None:
        try:
            return self._read_latest()
        except KalkanError as exc:
            self._log.note(f"runs/LATEST cannot be read: {exc}")
            return None

    def _read_status_logged(self) -> StatusReading:
        assert self._run_id is not None  # the loop reads the status of its bound run only
        reading = self._read_status(self._run_id)
        if reading.status is None:
            self._log.note(f"status: not available ({reading.error or 'no detail'})")
        else:
            self._log.note(f"status: {reading.status.summary()}")
        return reading

    def _own(self, reading: StatusReading) -> RunStatus | None:
        """Return the status when it belongs to the run of this loop."""
        status = reading.status
        if status is None:
            return None
        if status.run_id and self._run_id and status.run_id != self._run_id:
            self._log.note(
                f"status: belongs to run {status.run_id}, not to {self._run_id}. Ignored."
            )
            return None
        return status

    # -- waits ----------------------------------------------------------------------------

    def _plan_wait(
        self, limit: LimitInfo | None, progress: bool, backoff: Backoff, now: datetime
    ) -> tuple[datetime | None, str]:
        if limit is not None:
            self._limits.append(limit.to_dict())
            wake = limit.reset_at + RESET_MARGIN
            if wake > now:
                self._log.note(
                    f"usage limit ({limit.source}: {limit.detail}). Reset at "
                    f"{ids.format_ts(limit.reset_at)}."
                )
                return wake, f"usage limit, reset at {_local_text(limit.reset_at)}"
            self._log.note(
                f"usage limit ({limit.source}: {limit.detail}), but its reset time "
                f"{ids.format_ts(limit.reset_at)} has passed. The loop ignores it."
            )
        if progress:
            self._log.note("progress: the next round starts now")
            return None, ""
        delay = backoff.next_delay()
        minutes = int(delay.total_seconds() // 60)
        self._log.note(f"no progress and no reset time: backoff of {minutes} minutes")
        return now + delay, f"no progress, backoff of {minutes} minutes"

    def _sleep_until(self, wake: datetime, why: str) -> None:
        self._say(f"waiting until {_local_text(wake)} ({why})")
        self._log.note(f"sleep until {ids.format_ts(wake)} ({why})")
        while True:
            left = (wake - self._clock()).total_seconds()
            if left <= 0:
                return
            self._sleep(min(left, SLEEP_CHUNK_SECONDS))
            rest = max(0.0, (wake - self._clock()).total_seconds())
            self._log.note(f"wake-up: {rest / 60:.1f} minutes left until {ids.format_ts(wake)}")

    # -- results --------------------------------------------------------------------------

    def _host_option(self) -> str:
        return "" if self._host.name == "claude" else f" --host {self._host.name}"

    def _resume_hint(self) -> str:
        options = self.options
        return resume_hint(
            options.command, self._host.name, self._run_id, options.target, options.profile
        )

    def _spent_usd(self) -> tuple[float, bool]:
        """Return the recorded cost of the bound run and whether its last round hit the cap."""
        if self._run_id is None:
            return 0.0, False
        try:
            rounds = usage_mod.load(ids.resolve_run(self._run_id, self._runs_dir))
        except (OSError, KalkanError):
            return 0.0, False
        totals = usage_mod.summarize(rounds) or {}
        hit = bool(rounds) and rounds[-1].get("subtype") == BUDGET_SUBTYPE
        return float(totals.get("cost_usd") or 0.0), hit

    def _stop_max_usd(self, spent: float, status: RunStatus | None) -> UnattendedResult:
        cap = self.options.max_usd or 0.0
        message = (
            f"stopped: --max-usd {cap:.2f} reached (recorded cost USD {spent:.2f}, the "
            "estimate of Claude Code at list prices). The run is resumable. To spend more, "
            f"resume with a higher cap: {self._resume_hint()} --max-usd <USD>"
        )
        return self._finish(EXIT_ERROR, REASON_MAX_USD, message, status)

    def _stop_max_hours(self, status: RunStatus | None) -> UnattendedResult:
        message = (
            f"stopped: --max-hours {_hours_text(self.options.max_hours)} passed after "
            f"{self._rounds} rounds. The run is resumable. Resume with: "
        )
        return self._finish(EXIT_ERROR, REASON_MAX_HOURS, message + self._resume_hint(), status)

    def _stop_before_wait(
        self, wake: datetime, limit: LimitInfo | None, status: RunStatus | None
    ) -> UnattendedResult:
        deadline = _local_text(self._deadline)
        if limit is not None and limit.reset_at + RESET_MARGIN == wake:
            message = (
                f"stopped: the usage limit resets at {_local_text(limit.reset_at)}, after the "
                f"--max-hours limit ({deadline}). After the reset, resume with: "
            )
        else:
            message = (
                f"stopped: the next round would start after the --max-hours limit "
                f"({deadline}). Resume with: "
            )
        return self._finish(EXIT_ERROR, REASON_MAX_HOURS, message + self._resume_hint(), status)

    def _incomplete_message(self, status: RunStatus) -> str:
        reason = status.incomplete_reason or "no reason given"
        message = (
            f"run {status.run_id or self._run_id} finished incomplete: {reason}. The partial "
            "report lists the gap. A new run with a larger profile can close it."
        )
        if self._runs_dir is not None and (status.run_id or self._run_id):
            report = self._runs_dir / str(status.run_id or self._run_id) / "report" / "REPORT.md"
            message += f" Report: {report.as_posix()}"
        return message

    def _done_message(self) -> str:
        message = f"the audit is done: run {self._run_id}."
        if self._runs_dir is not None and self._run_id:
            report = self._runs_dir / self._run_id / "report" / "REPORT.md"
            message += f" Report: {report.as_posix()}"
        return message

    def _finish(
        self, exit_code: int, reason: str, message: str, status: RunStatus | None
    ) -> UnattendedResult:
        finished = self._clock()
        self._log.note(f"stop ({reason}, exit code {exit_code}): {message}")
        return UnattendedResult(
            exit_code=exit_code,
            reason=reason,
            message=message,
            rounds=self._rounds,
            run_id=self._run_id,
            status=status,
            log_file=self._log.path.as_posix(),
            started_at=self._started,
            finished_at=finished,
            limits=list(self._limits),
        )

    def _describe(self) -> str:
        options = self.options
        if options.target is not None:
            what = f"new run of target {options.target}, profile {options.profile}"
            if not options.latest:
                what += ", runs/LATEST unchanged"
        elif options.run_id is not None:
            what = f"resume run {options.run_id} (devam)"
        else:
            what = "resume the run in runs/LATEST (devam)"
        return (
            f"kalkan {__version__}, {what}, max {_hours_text(options.max_hours)} h, "
            f"{_hours_text(options.round_hours)} h per round, host {self._host.name}, "
            f"login {self._auth.describe()}"
            + (f", max USD {options.max_usd:.2f}" if options.max_usd is not None else "")
            + f", cwd {self._cwd.as_posix()}, deadline {ids.format_ts(self._deadline)}"
        )
