# SPDX-License-Identifier: MIT
"""Tests for kalkan.unattended.loop with a fake host process, clock, sleep and engine.

No test starts Claude Code or the engine. Only test_kill_process_tree_stops_a_real_child starts
a process: a Python interpreter that sleeps.
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

from kalkan.errors import KalkanError, ToolError, UnsafeInputError
from kalkan.unattended import loop as loop_mod
from kalkan.unattended.hosts import PLUGIN_SKILL, ClaudeHost
from kalkan.unattended.loop import (
    Backoff,
    RunCreation,
    RunLog,
    RunStatus,
    StatusReading,
    TailBuffer,
    UnattendedLoop,
    UnattendedOptions,
    init_command,
    log_file_name,
    made_progress,
    parse_status,
    resume_hint,
    resume_prompt,
    run_checker,
    subprocess_run_creator,
    subprocess_status_reader,
)

START = datetime(2026, 10, 15, 12, 0, tzinfo=UTC)
PLUS3 = timezone(timedelta(hours=3))
RUN = "20261015T120000Z-app-ab12"
OLD = "20261001T080000Z-old-cd34"
OTHER = "20261015T130000Z-other-ef56"
TARGET = "C:/code/app"
#: The prompt of every Claude Code round of the run RUN.
PROMPT = f"/kalkan devam {RUN} --headless"
KEEP = object()


def status_doc(phase="hunt", done=0, *, run_id=RUN, reason=None, steps=None) -> dict:
    by_status = {"pending": 5, "leased": 0, "done": done, "failed": 0, "dead": 0, "skipped": 0}
    doc = {
        "run_id": run_id,
        "phase": phase,
        "incomplete_reason": reason,
        "updated_at": "2026-10-15T12:00:00Z",
        "tasks": {"total": 5 + done, "by_status": by_status, "by_type": {}},
    }
    if steps is not None:
        doc["phases"] = steps
    return doc


def rate_limit_line(reset: datetime) -> str:
    info = {"status": "rejected", "resetsAt": int(reset.timestamp()), "rateLimitType": "five_hour"}
    return json.dumps({"type": "rate_limit_event", "rate_limit_info": info})


class FakeClock:
    def __init__(self, start: datetime = START) -> None:
        self.now = start
        self.sleeps: list[float] = []

    def __call__(self) -> datetime:
        return self.now

    def sleep(self, seconds: float) -> None:
        assert seconds > 0
        self.sleeps.append(seconds)
        self.now += timedelta(seconds=seconds)

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


@dataclass
class Round:
    stdout: list[str] = field(default_factory=list)
    stderr: list[str] = field(default_factory=list)
    code: int = 0
    status: object = KEEP
    #: runs/LATEST after the round, for example a parallel run init that moves it.
    latest: object = KEEP
    #: A run whose folder disappears during the round.
    gone: str | None = None
    hang: bool = False
    fail: bool = False
    interrupt: bool = False
    duration: float = 60.0


class FakeProcess:
    def __init__(self, spec: Round, clock: FakeClock) -> None:
        self.pid = 4242
        self.stdout = io.BytesIO("".join(f"{line}\n" for line in spec.stdout).encode("utf-8"))
        self.stderr = io.BytesIO("".join(f"{line}\r\n" for line in spec.stderr).encode("utf-8"))
        self.spec = spec
        self.clock = clock
        self.killed = False
        self.finished = False
        self.wait_timeouts: list[float | None] = []

    def wait(self, timeout: float | None = None) -> int:
        self.wait_timeouts.append(timeout)
        if self.spec.interrupt:
            raise KeyboardInterrupt
        if self.spec.hang and not self.killed:
            self.clock.advance(timeout or 0)
            raise subprocess.TimeoutExpired("claude", timeout or 0)
        if not self.finished and not self.killed:
            self.clock.advance(self.spec.duration)
        self.finished = True
        return -9 if self.killed else self.spec.code

    def poll(self) -> int | None:
        if self.killed:
            return -9
        return self.spec.code if self.finished else None

    def kill(self) -> None:
        self.killed = True


class Harness:
    """A fake engine (run init, runs/LATEST, run folders and run status), host process starter
    and tree killer.

    ``run init`` creates ``created`` (and records it in runs/LATEST unless ``--no-latest``), or
    fails with ``init_error``. Every run exists unless it is in ``gone``.
    """

    def __init__(self, rounds, *, latest=None, status=None, created=RUN, init_error=None) -> None:
        self.rounds = list(rounds)
        self.latest = latest
        self.status = status
        self.created = created
        self.init_error = init_error
        self.gone: set[str] = set()
        self.clock = FakeClock()
        self.calls: list[tuple[list[str], dict]] = []
        self.started_at: list[datetime] = []
        self.processes: list[FakeProcess] = []
        self.killed: list[int] = []
        self.messages: list[str] = []
        self.init_calls: list[tuple[str, str, bool, float]] = []
        self.status_reads: list[str] = []
        self.latest_reads = 0

    def popen(self, argv, **kwargs):
        self.calls.append((list(argv), kwargs))
        self.started_at.append(self.clock.now)
        assert self.rounds, "the loop started more rounds than the test planned"
        spec = self.rounds.pop(0)
        if spec.fail:
            raise FileNotFoundError(2, "not found", argv[0])
        if spec.latest is not KEEP:
            self.latest = spec.latest
        if spec.status is not KEEP:
            self.status = spec.status
        if spec.gone is not None:
            self.gone.add(spec.gone)
        process = FakeProcess(spec, self.clock)
        self.processes.append(process)
        return process

    def create_run(self, target, profile, latest, timeout) -> RunCreation:
        self.init_calls.append((target, profile, latest, timeout))
        if self.init_error is not None:
            return RunCreation(None, self.init_error)
        if latest:
            self.latest = self.created
        return RunCreation(self.created)

    def check_run(self, run_id) -> str | None:
        return f"run not found: {run_id}" if run_id in self.gone else None

    def read_status(self, run_id) -> StatusReading:
        self.status_reads.append(run_id)
        if self.status is None:
            return StatusReading(None, "no run")
        return StatusReading(parse_status(self.status))

    def read_latest(self):
        self.latest_reads += 1
        return self.latest

    def kill_tree(self, process) -> None:
        self.killed.append(process.pid)
        process.killed = True

    def prompts(self) -> list[str]:
        return [argv[2] for argv, _ in self.calls]

    def waits(self) -> list[str]:
        return [m for m in self.messages if m.startswith("waiting until")]


def make_loop(
    tmp_path: Path, harness: Harness, *, target=TARGET, host=None, environ=None, **options
) -> UnattendedLoop:
    log = RunLog(tmp_path / "unattended.log", clock=harness.clock).open()
    return UnattendedLoop(
        UnattendedOptions(target=target, **options),
        host=host or ClaudeHost("claude", local_tz=PLUS3),
        cwd=tmp_path,
        log=log,
        read_status=harness.read_status,
        read_latest=harness.read_latest,
        popen=harness.popen,
        clock=harness.clock,
        sleep=harness.clock.sleep,
        kill_tree=harness.kill_tree,
        say=harness.messages.append,
        runs_dir=tmp_path / "runs",
        create_run=harness.create_run,
        check_run=harness.check_run,
        environ={} if environ is None else environ,  # never the developer's API keys
    )


def run(tmp_path: Path, harness: Harness, **kwargs):
    unattended = make_loop(tmp_path, harness, **kwargs)
    try:
        return unattended.run()
    finally:
        unattended._log.close()


def log_text(tmp_path: Path) -> str:
    return (tmp_path / "unattended.log").read_text(encoding="utf-8")


# ---------------------------------------------------------------------------------------------
# Prompts


def test_a_new_audit_creates_the_run_and_every_round_names_it(tmp_path):
    harness = Harness(
        [Round(status=status_doc("hunt", 1)), Round(status=status_doc("done", 6))],
        latest=OLD,
        status=status_doc("done", 9, run_id=OLD),
    )
    result = run(tmp_path, harness, profile="deep")
    assert result.exit_code == 0 and result.reason == "done" and result.run_id == RUN
    assert harness.init_calls == [(TARGET, "deep", True, loop_mod.INIT_TIMEOUT_SECONDS)]
    assert harness.prompts() == [PROMPT, PROMPT]
    argv, kwargs = harness.calls[0]
    assert argv == [
        "claude",
        "-p",
        PROMPT,
        "--permission-mode",
        "dontAsk",
        "--output-format",
        "stream-json",
        "--verbose",
    ]
    assert kwargs["shell"] is False
    assert kwargs["cwd"] == os.fspath(tmp_path)
    assert kwargs["stdin"] is subprocess.DEVNULL
    assert kwargs["stdout"] is subprocess.PIPE and kwargs["stderr"] is subprocess.PIPE
    assert harness.status_reads == [RUN, RUN]  # the done run OLD in LATEST never counts
    assert harness.latest_reads == 0  # a new audit never reads runs/LATEST
    assert harness.clock.sleeps == []  # progress after round 1: round 2 starts at once
    assert "runs/" in result.message and "REPORT.md" in result.message
    assert f"run created: {RUN}" in log_text(tmp_path)
    assert f"round 1 started: {PROMPT}" in harness.messages


def test_a_usage_limit_in_the_first_round_resends_the_same_run(tmp_path):
    reset = START + timedelta(hours=1)
    harness = Harness(
        [Round(stdout=[rate_limit_line(reset)]), Round(status=status_doc("done", 3))],
        latest=OLD,
        status=status_doc("done", 9, run_id=OLD),
    )
    result = run(tmp_path, harness)
    assert harness.prompts() == [PROMPT, PROMPT]
    assert result.exit_code == 0 and result.rounds == 2 and len(harness.init_calls) == 1
    assert harness.started_at[1] == reset + timedelta(minutes=2)


def test_no_latest_reaches_run_init_and_leaves_latest(tmp_path):
    harness = Harness([Round(status=status_doc("done", 2))], latest=OLD)
    result = run(tmp_path, harness, latest=False)
    assert harness.init_calls[0][2] is False and harness.latest == OLD
    assert result.exit_code == 0 and harness.prompts() == [PROMPT]
    assert "runs/LATEST unchanged" in log_text(tmp_path)


def test_a_failed_run_init_stops_before_any_round(tmp_path):
    error = "kalkan run init exited with code 1: the target folder does not exist: C:/code/app"
    harness = Harness([], init_error=error)
    result = run(tmp_path, harness, profile="fast")
    assert result.exit_code == 1 and result.reason == "init_failed" and result.run_id is None
    assert harness.calls == [] and harness.status_reads == []
    assert error in result.message
    assert f"start again with: kalkan unattended {TARGET} --profile fast" in result.message


def test_the_run_init_time_limit_never_passes_max_hours(tmp_path):
    harness = Harness([Round(status=status_doc("done", 2))])
    run(tmp_path, harness, max_hours=0.25)
    assert harness.init_calls[0][3] == 900


def test_prompt_command_and_hint_helpers():
    assert resume_prompt(RUN) == PROMPT
    assert resume_prompt(RUN, "$kalkan") == f"$kalkan devam {RUN} --headless"
    argv = init_command("C:/My Code/app", "fast", latest=False, python="py")
    assert argv == [
        "py",
        "-m",
        "kalkan",
        "run",
        "init",
        "C:/My Code/app",
        "--profile",
        "fast",
        "--no-latest",
        "--json",
    ]
    assert init_command(TARGET, "deep")[-3:] == ["--profile", "deep", "--json"]
    assert resume_hint("kalkan unattended", "claude", RUN) == f"kalkan unattended devam {RUN}"
    assert resume_hint("kalkan unattended", "codex", RUN).endswith(f"devam {RUN} --host codex")
    spaced = resume_hint("kalkan-unattended", "claude", None, "C:/My Code/app", "deep")
    assert spaced == 'kalkan-unattended "C:/My Code/app" --profile deep'
    assert resume_hint("kalkan unattended", "claude", None) == "kalkan unattended devam"


# ---------------------------------------------------------------------------------------------
# Stop rules


def test_done_stops_with_exit_0_whatever_the_host_exit_code(tmp_path):
    harness = Harness([Round(code=1, status=status_doc("done", 4))])
    result = run(tmp_path, harness)
    assert result.exit_code == 0 and result.reason == "done"
    assert "host exit code 1 (logged, not used)" in log_text(tmp_path)


def test_incomplete_stops_with_exit_1(tmp_path):
    harness = Harness([Round(status=status_doc("done", 2, reason="validation_budget_exhausted"))])
    result = run(tmp_path, harness)
    assert result.exit_code == 1 and result.reason == "incomplete"
    assert "finished incomplete: validation_budget_exhausted" in result.message
    assert "report/REPORT.md" in result.message


def test_an_incomplete_reason_before_done_does_not_stop_the_loop(tmp_path):
    reason = "validation_budget_exhausted"
    harness = Harness(
        [
            Round(status=status_doc("report", 2, reason=reason)),
            Round(status=status_doc("done", 3, reason=reason)),
        ]
    )
    result = run(tmp_path, harness)
    assert len(harness.prompts()) == 2
    assert result.exit_code == 1 and result.reason == "incomplete"


def test_devam_without_a_run_stops_before_any_round(tmp_path):
    harness = Harness([])
    result = run(tmp_path, harness, target=None)
    assert result.exit_code == 1 and result.reason == "no_run" and harness.calls == []


def test_devam_with_a_done_run_stops_before_any_round(tmp_path):
    harness = Harness([], latest=RUN, status=status_doc("done", 4))
    result = run(tmp_path, harness, target=None)
    assert result.exit_code == 0 and result.reason == "done" and harness.calls == []


def test_devam_with_an_incomplete_run_stops_before_any_round(tmp_path):
    harness = Harness([], latest=RUN, status=status_doc("done", 4, reason="tool missing"))
    result = run(tmp_path, harness, target=None)
    assert harness.calls == []
    assert result.exit_code == 1 and result.reason == "incomplete"


def test_devam_with_a_pending_reason_runs_until_done(tmp_path):
    harness = Harness(
        [Round(status=status_doc("done", 5, reason="tool missing"))],
        latest=RUN,
        status=status_doc("hunt", 4, reason="tool missing"),
    )
    result = run(tmp_path, harness, target=None)
    assert harness.prompts() == [PROMPT]
    assert result.exit_code == 1 and result.reason == "incomplete"


# ---------------------------------------------------------------------------------------------
# Run binding: parallel audits move runs/LATEST, the loop keeps its run


def test_a_parallel_run_init_does_not_stop_a_loop_bound_to_its_new_run(tmp_path):
    """Another audit starts while this one runs: its run init moves runs/LATEST to OTHER. The
    loop keeps sending its own run ID and reads only the status of its own run."""
    harness = Harness(
        [Round(latest=OTHER, status=status_doc("hunt", 2)), Round(status=status_doc("done", 3))]
    )
    result = run(tmp_path, harness)
    assert result.exit_code == 0 and result.reason == "done" and result.run_id == RUN
    assert harness.latest == OTHER
    assert harness.prompts() == [PROMPT, PROMPT]
    assert harness.status_reads == [RUN, RUN]
    assert harness.latest_reads == 0
    assert OTHER not in log_text(tmp_path)


def test_devam_binds_once_to_latest_and_ignores_a_later_change(tmp_path):
    harness = Harness(
        [Round(latest=OTHER), Round(status=status_doc("done", 2))],
        latest=RUN,
        status=status_doc("hunt", 1),
    )
    result = run(tmp_path, harness, target=None)
    assert result.exit_code == 0 and result.reason == "done" and result.run_id == RUN
    assert harness.prompts() == [PROMPT, PROMPT]
    assert harness.latest_reads == 1  # devam reads runs/LATEST once, at the start
    assert harness.status_reads == [RUN, RUN, RUN]
    assert f"bound to {RUN} from runs/LATEST" in log_text(tmp_path)
    assert f"devam: the newest run {RUN} (runs/LATEST)" in harness.messages


def test_devam_with_a_run_id_never_reads_latest(tmp_path):
    harness = Harness(
        [Round(status=status_doc("done", 2))], latest=OTHER, status=status_doc("hunt", 1)
    )
    result = run(tmp_path, harness, target=None, run_id=RUN)
    assert result.exit_code == 0 and result.run_id == RUN
    assert harness.prompts() == [PROMPT] and harness.latest_reads == 0
    assert harness.status_reads == [RUN, RUN] and harness.init_calls == []


def test_devam_with_a_missing_run_stops_before_any_round(tmp_path):
    harness = Harness([], latest=OTHER)
    harness.gone.add(RUN)
    result = run(tmp_path, harness, target=None, run_id=RUN)
    assert result.exit_code == 1 and result.reason == "no_run" and harness.calls == []
    assert f"run not found: {RUN}" in result.message


def test_a_removed_run_stops_the_loop(tmp_path):
    harness = Harness([Round(gone=RUN)], latest=RUN, status=status_doc("hunt", 1))
    result = run(tmp_path, harness, target=None)
    assert result.exit_code == 1 and result.reason == "run_changed"
    assert f"run {RUN} cannot be resumed any more: run not found: {RUN}" in result.message


def test_a_status_of_another_run_is_ignored(tmp_path):
    harness = Harness(
        [
            Round(status=status_doc("done", 1, run_id=OTHER)),
            Round(status=status_doc("done", 2)),
        ],
        latest=RUN,
        status=status_doc("hunt", 1),
    )
    result = run(tmp_path, harness, target=None)
    assert result.rounds == 2 and result.exit_code == 0
    assert "belongs to run" in log_text(tmp_path)


def test_max_hours_stops_with_exit_1_and_a_resume_hint(tmp_path):
    harness = Harness([Round(), Round(), Round()], latest=RUN, status=status_doc("hunt", 1))
    result = run(tmp_path, harness, target=None, max_hours=0.5)
    # 1 min round, 5 min wait, 1 min round, 10 min wait, 1 min round: 18 minutes. The next wait
    # (20 minutes) ends after the 30-minute limit, so the loop stops at once.
    assert result.exit_code == 1 and result.reason == "max_hours" and result.rounds == 3
    assert f"Resume with: kalkan unattended devam {RUN}" in result.message
    assert harness.clock.now == START + timedelta(minutes=18)


def test_max_hours_before_a_round(tmp_path):
    harness = Harness([Round(duration=29.5 * 60)], latest=RUN, status=status_doc("hunt", 1))
    result = run(tmp_path, harness, target=None, max_hours=0.5)
    assert result.reason == "max_hours" and result.rounds == 1


def test_max_hours_of_a_new_audit_names_its_run(tmp_path):
    harness = Harness([Round(), Round(), Round()])
    result = run(tmp_path, harness, max_hours=0.5)
    assert result.reason == "max_hours" and result.run_id == RUN
    assert f"kalkan unattended devam {RUN}" in result.message


def test_a_reset_after_the_deadline_stops_at_once(tmp_path):
    reset = START + timedelta(hours=5)
    harness = Harness(
        [Round(stdout=[rate_limit_line(reset)])], latest=RUN, status=status_doc("hunt", 1)
    )
    result = run(tmp_path, harness, target=None, max_hours=1)
    assert result.exit_code == 1 and result.reason == "max_hours"
    assert "usage limit resets at" in result.message
    assert harness.clock.sleeps == []
    assert result.limits and result.limits[0]["source"] == "event"


# ---------------------------------------------------------------------------------------------
# Waits


def test_a_usage_limit_sleeps_until_the_reset_plus_margin_in_chunks(tmp_path):
    reset = START + timedelta(hours=1, minutes=1)
    harness = Harness(
        [Round(stdout=[rate_limit_line(reset)]), Round(status=status_doc("done", 2))],
        latest=RUN,
        status=status_doc("hunt", 1),
    )
    result = run(tmp_path, harness, target=None)
    assert result.exit_code == 0
    assert harness.started_at[1] == reset + timedelta(minutes=2)
    assert all(0 < chunk <= 300 for chunk in harness.clock.sleeps)
    assert sum(harness.clock.sleeps) == pytest.approx(62 * 60)  # 1:03 after the round end
    assert log_text(tmp_path).count("wake-up:") == len(harness.clock.sleeps)
    assert "usage limit" in harness.waits()[0]


def test_a_limit_in_stderr_text(tmp_path):
    harness = Harness(
        [
            Round(stderr=["Error: usage limit reached · resets 5pm"]),
            Round(status=status_doc("done", 2)),
        ],
        latest=RUN,
        status=status_doc("hunt", 1),
    )
    run(tmp_path, harness, target=None)
    # 17:00 at UTC+03:00 is 14:00 UTC, plus the two-minute margin.
    assert harness.started_at[1] == datetime(2026, 10, 15, 14, 2, tzinfo=UTC)


def test_backoff_sequence_without_progress(tmp_path):
    rounds = [Round() for _ in range(6)] + [Round(status=status_doc("done", 2))]
    harness = Harness(rounds, latest=RUN, status=status_doc("hunt", 1))
    result = run(tmp_path, harness, target=None, max_hours=48)
    assert result.exit_code == 0 and result.rounds == 7
    gaps = [
        (b - a).total_seconds() / 60 - 1
        for a, b in zip(harness.started_at, harness.started_at[1:], strict=False)
    ]
    assert gaps == [5, 10, 20, 40, 60, 60]
    assert all(0 < chunk <= 300 for chunk in harness.clock.sleeps)


def test_progress_resets_the_backoff(tmp_path):
    rounds = [
        Round(),  # no progress: 5 minutes
        Round(),  # no progress: 10 minutes
        Round(status=status_doc("hunt", 2)),  # progress: next round at once
        Round(),  # no progress: 5 minutes again
        Round(status=status_doc("validate", 2)),  # a later phase is progress too
        Round(status=status_doc("done", 3)),
    ]
    harness = Harness(rounds, latest=RUN, status=status_doc("hunt", 1))
    run(tmp_path, harness, target=None)
    gaps = [
        (b - a).total_seconds() / 60 - 1
        for a, b in zip(harness.started_at, harness.started_at[1:], strict=False)
    ]
    assert gaps == [5, 10, 0, 5, 0]


def test_a_past_reset_time_falls_back_to_backoff(tmp_path):
    harness = Harness(
        [
            Round(stdout=[rate_limit_line(START - timedelta(minutes=30))]),
            Round(status=status_doc("done", 2)),
        ],
        latest=RUN,
        status=status_doc("hunt", 1),
    )
    run(tmp_path, harness, target=None)
    assert harness.started_at[1] == START + timedelta(minutes=6)
    assert "has passed" in log_text(tmp_path)


# ---------------------------------------------------------------------------------------------
# Rounds


def test_a_round_over_its_time_limit_loses_its_process_tree(tmp_path):
    harness = Harness(
        [Round(hang=True), Round(status=status_doc("done", 2))],
        latest=RUN,
        status=status_doc("hunt", 1),
    )
    result = run(tmp_path, harness, target=None, round_hours=1)
    assert result.exit_code == 0
    assert harness.processes[0].wait_timeouts[0] == 3600
    assert harness.killed == [4242]
    assert harness.processes[0].killed
    text = log_text(tmp_path)
    assert "time limit reached" in text and "timed out" in text


def test_the_round_time_limit_never_passes_max_hours(tmp_path):
    harness = Harness([Round(status=status_doc("done", 2))], latest=RUN, status=status_doc())
    run(tmp_path, harness, target=None, max_hours=2, round_hours=6)
    assert harness.processes[0].wait_timeouts[0] == 7200


def test_the_first_start_failure_raises_tool_error(tmp_path):
    harness = Harness([Round(fail=True)], latest=RUN, status=status_doc())
    with pytest.raises(ToolError, match="did not start"):
        run(tmp_path, harness, target=None)


def test_a_later_start_failure_backs_off(tmp_path):
    harness = Harness(
        [Round(status=status_doc("hunt", 2)), Round(fail=True), Round(status=status_doc("done"))],
        latest=RUN,
        status=status_doc("hunt", 1),
    )
    result = run(tmp_path, harness, target=None)
    assert result.exit_code == 0 and result.rounds == 3
    assert harness.started_at[2] - harness.started_at[1] == timedelta(minutes=5)


def test_keyboard_interrupt_stops_the_process_tree(tmp_path):
    harness = Harness([Round(interrupt=True)], latest=RUN, status=status_doc())
    with pytest.raises(KeyboardInterrupt):
        run(tmp_path, harness, target=None)
    assert harness.killed == [4242]


def test_the_log_holds_stdout_unchanged_stderr_with_prefix_and_notes(tmp_path):
    (tmp_path / "unattended.log").write_text("line of an earlier run\n", encoding="utf-8")
    stdout = [json.dumps({"type": "system", "subtype": "init"}), "plain ünïcode line"]
    harness = Harness([Round(stdout=stdout, stderr=["warning: slow"], status=status_doc("done"))])
    run(tmp_path, harness)
    lines = log_text(tmp_path).splitlines()
    assert lines[0] == "line of an earlier run"
    assert lines[1].startswith("[kalkan 2026-10-15T12:00:00Z] start: ")
    assert stdout[0] in lines and stdout[1] in lines
    assert "[stderr] warning: slow" in lines
    assert any("round 1 start: claude -p" in line for line in lines)
    assert any("host exit code 0 (logged, not used)" in line for line in lines)
    assert any("stop (done, exit code 0)" in line for line in lines)


# ---------------------------------------------------------------------------------------------
# Status parsing and progress


def test_parse_status_with_task_counts():
    status = parse_status(status_doc("hunt", 4))
    assert status.run_id == RUN and status.phase == "hunt" and status.finished_tasks == 4
    assert not status.done and not status.incomplete and status.countable


@pytest.mark.parametrize(
    ("tasks", "expected"),
    [
        ({"T0001-recon": {"status": "done"}, "T0002-hunt": {"status": "dead"}}, 2),
        ([{"status": "done"}, {"status": "pending"}, {"status": "skipped"}], 2),
        ({"done": 3, "pending": 1}, 3),
        ({}, 0),
        ([], 0),
    ],
)
def test_parse_status_task_shapes(tasks, expected):
    assert parse_status({"phase": "hunt", "tasks": tasks}).finished_tasks == expected


def test_parse_status_other_shapes():
    assert parse_status({"phase": "hunt", "tasks_done": 7}).finished_tasks == 7
    assert parse_status({"phase": "hunt", "task_counts": {"done": 2}}).finished_tasks == 2
    wrapped = parse_status({"run_id": RUN, "state": {"phase": "sca", "tasks": {}}})
    assert wrapped.phase == "sca" and wrapped.run_id == RUN
    phases = {
        "prep": {"status": "done", "steps": {"copy": {"status": "done"}}},
        "deterministic": {
            "status": "running",
            "steps": {"opengrep": {"status": "done"}, "trivy": {"status": "pending"}},
        },
    }
    assert parse_status({"phase": "deterministic", "phases": phases}).finished_steps == 3
    assert parse_status({"phase": "hunt", "status": "incomplete"}).incomplete
    assert parse_status({"phase": "incomplete"}).incomplete
    assert parse_status({"phase": "x", "incomplete_reason": {"code": "budget"}}).incomplete
    assert parse_status(["not", "an", "object"]) is None
    assert not parse_status({"phase": "hunt"}).countable


def test_made_progress():
    base = parse_status(status_doc("hunt", 2))
    assert made_progress(None, base)
    assert not made_progress(base, None)
    assert not made_progress(base, parse_status(status_doc("hunt", 2)))
    assert made_progress(base, parse_status(status_doc("hunt", 3)))
    assert made_progress(base, parse_status(status_doc("validate", 2)))
    assert made_progress(base, parse_status(status_doc("hunt", 2, run_id=OTHER)))
    stepped = parse_status(status_doc("hunt", 2, steps={"hunt": {"status": "running"}}))
    more = parse_status(status_doc("hunt", 2, steps={"hunt": {"status": "done"}}))
    assert made_progress(stepped, more)


def test_progress_without_counts_uses_the_digest():
    first = parse_status({"phase": "hunt", "note": "a", "updated_at": "2026-10-15T12:00:00Z"})
    same = parse_status({"phase": "hunt", "note": "a", "updated_at": "2026-10-15T13:00:00Z"})
    changed = parse_status({"phase": "hunt", "note": "b"})
    assert not made_progress(first, same)
    assert made_progress(first, changed)


def test_run_status_summary_and_dict():
    status = parse_status(status_doc("hunt", 2, reason="x"))
    assert status.summary() == "phase hunt, 2 tasks finished, incomplete"
    assert status.to_dict()["incomplete_reason"] == "x"
    assert isinstance(status, RunStatus)


# ---------------------------------------------------------------------------------------------
# Status reader


class FakeRun:
    def __init__(self, *, stdout=b"", stderr=b"", code=0, error=None) -> None:
        self.result = subprocess.CompletedProcess([], code, stdout, stderr)
        self.error = error
        self.calls: list[tuple[list[str], dict]] = []

    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        if self.error is not None:
            raise self.error
        return self.result


def test_status_reader_runs_kalkan_run_status_of_the_run_in_a_subprocess(tmp_path):
    fake = FakeRun(stdout=json.dumps(status_doc("hunt", 3)).encode("utf-8"))
    reading = subprocess_status_reader(tmp_path, runner=fake)(RUN)
    assert reading.status is not None and reading.status.finished_tasks == 3
    argv, kwargs = fake.calls[0]
    assert argv == [sys.executable, "-m", "kalkan", "run", "status", "--run", RUN, "--json"]
    assert kwargs["cwd"] == os.fspath(tmp_path) and kwargs["shell"] is False
    assert kwargs["env"]["PYTHONIOENCODING"] == "utf-8" and kwargs["timeout"] > 0


@pytest.mark.parametrize(
    ("fake", "message"),
    [
        (FakeRun(code=1, stderr=b"kalkan: error: no run found\n"), "exited with code 1"),
        (FakeRun(stdout=b"not json"), "no JSON object"),
        (FakeRun(error=OSError("missing")), "did not run"),
        (FakeRun(error=subprocess.TimeoutExpired("kalkan", 120)), "did not run"),
    ],
)
def test_status_reader_errors(tmp_path, fake, message):
    reading = subprocess_status_reader(tmp_path, runner=fake)(RUN)
    assert reading.status is None and message in reading.error


def test_status_reader_skips_noise_before_the_json(tmp_path):
    fake = FakeRun(stdout=b"note\n" + json.dumps({"phase": "sca"}).encode("utf-8"))
    assert subprocess_status_reader(tmp_path, runner=fake)(RUN).status.phase == "sca"


# ---------------------------------------------------------------------------------------------
# Run creator and run checker


def test_run_creator_runs_run_init_and_reads_the_run_id(tmp_path):
    output = json.dumps({"run_id": RUN, "phase": "deterministic"}).encode("utf-8")
    fake = FakeRun(stdout=b"note\n" + output)
    created = subprocess_run_creator(tmp_path, runner=fake)(TARGET, "deep", False, 900.0)
    assert created == RunCreation(RUN)
    argv, kwargs = fake.calls[0]
    assert argv == [
        sys.executable,
        "-m",
        "kalkan",
        "run",
        "init",
        TARGET,
        "--profile",
        "deep",
        "--no-latest",
        "--json",
    ]
    assert kwargs["cwd"] == os.fspath(tmp_path) and kwargs["shell"] is False
    assert kwargs["timeout"] == 900.0 and kwargs["stdin"] is subprocess.DEVNULL
    assert kwargs["env"]["PYTHONIOENCODING"] == "utf-8"
    fake = FakeRun(stdout=output)
    assert subprocess_run_creator(tmp_path, runner=fake)(TARGET, "fast", True, 60.0).run_id == RUN
    assert "--no-latest" not in fake.calls[0][0]


@pytest.mark.parametrize(
    ("fake", "message"),
    [
        (
            FakeRun(code=1, stderr=b"copying\nkalkan: error: the target folder does not exist\n"),
            "exited with code 1: the target folder does not exist",
        ),
        (FakeRun(code=5, stderr=b"git is not installed\n"), "code 5: git is not installed"),
        (FakeRun(code=1), "exited with code 1: no message"),
        (FakeRun(stdout=b"{}"), "no valid run ID"),
        (FakeRun(stdout=json.dumps({"run_id": "../evil"}).encode("utf-8")), "no valid run ID"),
        (FakeRun(stdout=b"not json"), "no valid run ID"),
        (FakeRun(error=OSError("missing")), "did not run"),
        (FakeRun(error=subprocess.TimeoutExpired("kalkan", 120)), "did not finish in 2 minutes"),
    ],
)
def test_run_creator_errors(tmp_path, fake, message):
    created = subprocess_run_creator(tmp_path, runner=fake)(TARGET, "standard", True, 120.0)
    assert created.run_id is None and message in created.error


def test_run_checker_finds_the_run_folder(tmp_path):
    runs = tmp_path / "runs"
    (runs / RUN).mkdir(parents=True)
    (runs / OLD).write_text("not a folder", encoding="utf-8")
    check = run_checker(runs)
    assert check(RUN) is None
    assert check(OTHER) == f"run not found: {OTHER}"
    assert "not a folder" in check(OLD)
    assert "invalid run ID" in check("../x")


# ---------------------------------------------------------------------------------------------
# Small parts


def test_backoff_steps():
    backoff = Backoff()
    assert [backoff.next_delay().total_seconds() / 60 for _ in range(7)] == [
        5,
        10,
        20,
        40,
        60,
        60,
        60,
    ]
    backoff.reset()
    assert backoff.next_delay() == timedelta(minutes=5)
    with pytest.raises(ValueError):
        Backoff([])


def test_tail_buffer_keeps_the_newest_lines():
    tail = TailBuffer(max_chars=10)
    for line in ["aaaa", "bbbb", "cccc", "x" * 11]:
        tail.add(line)
    assert tail.lines() == ["bbbb", "cccc"]


def test_log_file_name():
    assert log_file_name(START) == "unattended-20261015T120000Z.log"


def test_options_are_checked():
    with pytest.raises(KalkanError):
        UnattendedOptions(target=TARGET, profile="medium")
    with pytest.raises(KalkanError):
        UnattendedOptions(target=TARGET, max_hours=0)
    with pytest.raises(KalkanError):
        UnattendedOptions(target=TARGET, round_hours=float("nan"))
    with pytest.raises(KalkanError, match="cannot go with a target"):
        UnattendedOptions(target=TARGET, run_id=RUN)
    with pytest.raises(KalkanError, match="invalid run ID"):
        UnattendedOptions(target=None, run_id="20261015T120000Z-app-ab12; rm -rf /")
    assert UnattendedOptions(target=None).resume
    assert UnattendedOptions(target=None, run_id=RUN).resume


def test_result_to_dict(tmp_path):
    harness = Harness([Round(status=status_doc("done", 1))])
    data = run(tmp_path, harness).to_dict()
    assert data["exit_code"] == 0 and data["reason"] == "done" and data["phase"] == "done"
    assert data["run_id"] == RUN
    assert data["log_file"].endswith("unattended.log") and data["rounds"] == 1
    assert data["started_at"] == "2026-10-15T12:00:00Z"


def test_the_log_refuses_a_link(tmp_path):
    target = tmp_path / "real.log"
    target.write_text("", encoding="utf-8")
    link = tmp_path / "link.log"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("this account cannot create symlinks")
    with pytest.raises(UnsafeInputError):
        RunLog(link).open()


def test_the_log_must_be_open():
    with pytest.raises(KalkanError):
        RunLog(Path("never-opened.log")).note("x")


def test_format_command_quotes_spaces():
    text = loop_mod.format_command(["claude", "-p", "/kalkan devam --headless"])
    assert "claude -p" in text and "/kalkan devam --headless" in text
    assert text.count('"') == 2 or text.count("'") == 2


def test_kill_process_tree_stops_a_real_child():
    process = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(120)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        shell=False,
        **loop_mod.popen_options(),
    )
    try:
        time.sleep(0.2)
        started = time.monotonic()
        loop_mod.kill_process_tree(process)
        process.wait(timeout=30)
        assert time.monotonic() - started < 30
        assert process.returncode is not None
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()


# ---------------------------------------------------------------------------------------------
# Codex host


def codex_error(message: str) -> str:
    return json.dumps({"type": "error", "message": message})


def codex_host():
    from kalkan.unattended.hosts import CodexHost

    return CodexHost("codex", local_tz=PLUS3)


def test_codex_rounds_use_the_dollar_prefix(tmp_path):
    harness = Harness([Round(status=status_doc("hunt", 1)), Round(status=status_doc("done", 2))])
    result = run(tmp_path, harness, host=codex_host())
    assert result.exit_code == 0
    prompts = [argv[-1] for argv, _ in harness.calls]
    assert prompts == [f"$kalkan devam {RUN} --headless"] * 2
    assert harness.init_calls == [(TARGET, "standard", True, loop_mod.INIT_TIMEOUT_SECONDS)]
    argv, kwargs = harness.calls[0]
    assert argv[:3] == ["codex", "exec", "--sandbox"] and "--json" in argv
    assert kwargs["stdin"] is subprocess.DEVNULL and kwargs["shell"] is False
    assert kwargs["cwd"] == os.fspath(tmp_path)


def test_codex_usage_limit_waits_until_the_reset(tmp_path):
    message = "You’ve hit your usage limit. Try again at 3:45 PM."
    harness = Harness(
        [
            Round(stdout=[codex_error(message)], code=1),
            Round(status=status_doc("done", 2)),
        ],
        latest=RUN,
        status=status_doc("hunt", 1),
    )
    run(tmp_path, harness, target=None, host=codex_host())
    # 15:45 at UTC+03:00 is 12:45 UTC, plus the two-minute margin.
    assert harness.started_at[1] == datetime(2026, 10, 15, 12, 47, tzinfo=UTC)


def test_codex_try_again_later_backs_off(tmp_path):
    harness = Harness(
        [
            Round(stdout=[codex_error("You’ve hit your usage limit. Try again later.")]),
            Round(status=status_doc("done", 2)),
        ],
        latest=RUN,
        status=status_doc("hunt", 1),
    )
    run(tmp_path, harness, target=None, host=codex_host())
    assert harness.started_at[1] == START + timedelta(minutes=6)


def test_codex_out_of_credits_stops_the_loop(tmp_path):
    harness = Harness(
        [Round(stdout=[codex_error("Your workspace is out of credits.")])],
        latest=RUN,
        status=status_doc("hunt", 1),
    )
    result = run(tmp_path, harness, target=None, host=codex_host())
    assert result.exit_code == 1 and result.reason == "host_blocked"
    assert "out of credits" in result.message
    assert f"kalkan unattended devam {RUN} --host codex" in result.message
    assert harness.clock.sleeps == []


def test_codex_spend_cap_with_a_reset_time_waits(tmp_path):
    lines = [codex_error("You hit your spend cap. Try again at 3:45 PM.")]
    harness = Harness(
        [Round(stdout=lines), Round(status=status_doc("done", 2))],
        latest=RUN,
        status=status_doc("hunt", 1),
    )
    result = run(tmp_path, harness, target=None, host=codex_host())
    assert result.exit_code == 0 and result.rounds == 2


def test_codex_item_text_does_not_stop_the_loop(tmp_path):
    planted = json.dumps(
        {
            "type": "item.completed",
            "item": {"type": "command_execution", "aggregated_output": "out of credits"},
        }
    )
    harness = Harness(
        [Round(stdout=[planted]), Round(status=status_doc("done", 2))],
        latest=RUN,
        status=status_doc("hunt", 1),
    )
    result = run(tmp_path, harness, target=None, host=codex_host())
    assert result.exit_code == 0 and harness.started_at[1] == START + timedelta(minutes=6)


def test_codex_hints_name_the_host(tmp_path):
    harness = Harness([], latest=None)
    result = run(tmp_path, harness, target=None, host=codex_host())
    assert result.reason == "no_run" and "--host codex" in result.message


# ---------------------------------------------------------------------------------------------
# Claude Code plugin


def plugin_host() -> ClaudeHost:
    return ClaudeHost("claude", local_tz=PLUS3, skill=PLUGIN_SKILL)


def test_plugin_rounds_send_the_plugin_skill_and_name_the_launcher(tmp_path):
    harness = Harness([Round(), Round(), Round()], latest=RUN, status=status_doc("hunt", 1))
    result = run(
        tmp_path,
        harness,
        target=None,
        max_hours=0.5,
        host=plugin_host(),
        command="kalkan-unattended",
    )
    assert harness.prompts() == [f"/kalkan:kalkan devam {RUN} --headless"] * 3
    assert result.reason == "max_hours"
    assert f"Resume with: kalkan-unattended devam {RUN}" in result.message
    assert "kalkan unattended" not in result.message


def test_plugin_hints_name_the_launcher(tmp_path):
    result = run(
        tmp_path, Harness([]), target=None, host=plugin_host(), command="kalkan-unattended"
    )
    assert result.reason == "no_run"
    assert "Start one with: kalkan-unattended <target>" in result.message
    harness = Harness([], init_error="kalkan run init exited with code 1: no git")
    result = run(tmp_path, harness, host=plugin_host(), command="kalkan-unattended")
    assert result.reason == "init_failed"
    assert f"start again with: kalkan-unattended {TARGET} --profile standard" in result.message
    harness = Harness([Round(status=status_doc("done", 1))])
    run(tmp_path, harness, host=plugin_host(), command="kalkan-unattended")
    assert harness.prompts() == [f"/kalkan:kalkan devam {RUN} --headless"]


def test_every_round_records_its_cost_in_the_run_folder(tmp_path):
    (tmp_path / "runs" / RUN).mkdir(parents=True)
    result_event = json.dumps(
        {
            "type": "result",
            "subtype": "success",
            "total_cost_usd": 4.25,
            "num_turns": 12,
            "duration_api_ms": 50000,
            "result": "final text that is never stored",
            "usage": {"input_tokens": 10, "output_tokens": 20},
        }
    )
    harness = Harness(
        [
            Round(stdout=['{"type": "system"}', result_event], status=status_doc("hunt", 1)),
            Round(status=status_doc("done", 6)),
        ]
    )
    outcome = run(tmp_path, harness)
    assert outcome.exit_code == 0
    lines = (tmp_path / "runs" / RUN / "usage.jsonl").read_text(encoding="utf-8").splitlines()
    first, second = (json.loads(line) for line in lines)
    assert first["round"] == 1 and first["total_cost_usd"] == 4.25 and first["wall_seconds"] == 60
    assert "never stored" not in lines[0]
    assert second["round"] == 2 and second["result_event"] is False
    assert "round 1: cost USD 4.25 (round 1 of the run)" in log_text(tmp_path)


def test_a_resumed_session_counts_the_rounds_of_the_run(tmp_path):
    run_dir = tmp_path / "runs" / RUN
    run_dir.mkdir(parents=True)
    (run_dir / "usage.jsonl").write_text('{"round": 1, "total_cost_usd": 9.0}\n', encoding="utf-8")
    harness = Harness([Round(status=status_doc("done", 6))])
    assert run(tmp_path, harness).exit_code == 0
    last = json.loads((run_dir / "usage.jsonl").read_text(encoding="utf-8").splitlines()[-1])
    assert last["round"] == 2 and last["session_round"] == 1


def result_event(cost: float, subtype: str = "success") -> str:
    return json.dumps({"type": "result", "subtype": subtype, "total_cost_usd": cost})


def test_max_usd_caps_the_run_over_every_round(tmp_path):
    run_dir = tmp_path / "runs" / RUN
    run_dir.mkdir(parents=True)
    (run_dir / "usage.jsonl").write_text('{"round": 1, "total_cost_usd": 30.0}\n', "utf-8")
    init = json.dumps(
        {"type": "system", "subtype": "init", "apiKeySource": "ANTHROPIC_API_KEY", "model": "m"}
    )
    harness = Harness(
        [
            Round(stdout=[init, result_event(15.0)], status=status_doc("hunt", 1)),
            Round(stdout=[result_event(6.0)], status=status_doc("hunt", 2)),
            Round(status=status_doc("done", 6)),
        ]
    )
    env = {"ANTHROPIC_API_KEY": "sk-secret"}
    result = run(tmp_path, harness, max_usd=50.0, environ=env)
    assert result.exit_code == 1 and result.reason == "max_usd"
    assert "--max-usd 50.00 reached (recorded cost USD 51.00" in result.message
    # Each round got the rest of the cap; the third round never started.
    argvs = [argv for argv, _ in harness.calls]
    assert len(argvs) == 2
    assert argvs[0][-2:] == ["--max-budget-usd", "20.00"]
    assert argvs[1][-2:] == ["--max-budget-usd", "5.00"]
    lines = (run_dir / "usage.jsonl").read_text(encoding="utf-8").splitlines()
    second = json.loads(lines[1])
    assert second["auth"] == "anthropic-api" and second["auth_source"] == "ANTHROPIC_API_KEY"
    assert second["api_key_source"] == "ANTHROPIC_API_KEY" and second["model"] == "m"
    assert "sk-secret" not in "\n".join(lines) + log_text(tmp_path)
    assert "login API: anthropic-api (ANTHROPIC_API_KEY), max USD 50.00" in log_text(tmp_path)


def test_a_round_that_hit_the_budget_stops_the_loop(tmp_path):
    (tmp_path / "runs" / RUN).mkdir(parents=True)
    harness = Harness(
        [
            Round(stdout=[result_event(4.0, "error_max_budget_usd")], status=status_doc("hunt", 1)),
            Round(status=status_doc("done", 6)),
        ]
    )
    result = run(tmp_path, harness, max_usd=100.0)
    assert result.reason == "max_usd" and len(harness.calls) == 1
    # Without --max-usd no round gets a budget flag.
    harness = Harness([Round(status=status_doc("done", 6))])
    run(tmp_path / "other", harness)
    assert "--max-budget-usd" not in harness.calls[0][0]
