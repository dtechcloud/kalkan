# SPDX-License-Identifier: MIT
"""CLI command ``kalkan audit`` (docs/ENGINE-SPEC.md, sections 9 and 25).

``kalkan audit <target | devam [RUN_ID]> [--profile fast|standard|deep] [--tools-only]
[--open] [--yes] [--no-latest] [--max-hours N] [--json]``

One command from a folder or a git URL to the report:

1. **Setup checks** (:mod:`kalkan.audit.preflight`). Missing tools or vulnerability databases
   are installed only with ``--yes``, or after ``y`` to the question when stdin is a terminal.
   Otherwise the command prints the fix commands and stops with exit code 5. Agent mode also
   needs a signed-in Claude Code CLI (exit code 5 otherwise) and, in a checkout, a folder that
   Claude Code trusts (exit code 1 otherwise).
2. **Run.** The command creates the run in this process (``run init``, with ``--no-latest`` when
   asked; ``--tools-only`` records ``options.mode``) and prints its ID.
3. **Scanners and SCA** run in this process (:func:`kalkan.audit.drive.drive_steps`), one line
   per step. No Claude Code round spends time or usage on them. A resumed agent run that is past
   these phases goes straight to the agent rounds.
4. **Agent mode** (the default): the unattended runner (:func:`kalkan.unattended.commands.prepare`
   and :func:`~kalkan.unattended.commands.start`) binds to the run ID and starts the Claude Code
   rounds ``/kalkan devam <run-id> --headless`` (``/kalkan:kalkan`` in the plugin). It waits
   through usage limits and prints the reset time. :class:`kalkan.audit.drive.RunWatcher` prints
   the phase changes and the task counts meanwhile. **Tools-only mode**: the phase engine skips
   the agent phases, and this process also runs merge and report. No Claude Code is needed.
5. **End**: a one-screen summary and the deliverables (:mod:`kalkan.audit.summary`) on stdout.
   ``--open`` opens ``EXECUTIVE.html`` in the default browser.

``devam [RUN_ID]`` resumes a run (default: the run in ``runs/LATEST``). The run keeps its mode
and profile. Progress messages go to stderr. ``--json`` prints one result document on stdout in
place of the summary text.

Exit codes: 0 the audit is done; 1 the run finished incomplete (the partial report exists), it
stopped (``--max-hours``, Ctrl+C) or failed, or the environment is broken (Python, manifest,
runs folder, folder trust); 2 usage; 5 setup needed (missing tools or databases without consent,
or Claude Code missing or signed out in agent mode).

Plugin install (:func:`kalkan.resources.plugin_install`): the launcher ``kalkan-audit``
(``plugins/kalkan/bin``) runs this command in the plugin venv. The runs go to ``~/kalkan-runs``,
and the messages name ``kalkan-audit``.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
import textwrap
import time
import webbrowser
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

from kalkan import resources
from kalkan.audit import preflight
from kalkan.audit import summary as summary_mod
from kalkan.errors import KalkanError
from kalkan.run import ids
from kalkan.run.init import init_run
from kalkan.run.state import MODE_AGENTS, MODE_TOOLS_ONLY, RunContext, load_context, run_mode
from kalkan.tools.doctor import DoctorReport
from kalkan.unattended import commands as unattended
from kalkan.unattended import loop as loop_mod

__all__ = ["DEFAULT_COMMAND", "EXIT_SETUP", "PLUGIN_COMMAND", "register"]

EXIT_OK: Final = 0
EXIT_ERROR: Final = 1
#: Setup needed: missing tools or databases without consent, or no signed-in Claude Code.
EXIT_SETUP: Final = 5

DEFAULT_COMMAND: Final = "kalkan audit"
#: The launcher of the plugin install (``plugins/kalkan/bin/kalkan-audit``).
PLUGIN_COMMAND: Final = "kalkan-audit"

HELP: Final = "Audit a folder or a git URL end to end: setup check, audit and report."
DESCRIPTION: Final = (
    "Audit a local folder or a git URL with one command. kalkan checks the setup (pinned "
    "tools, local vulnerability databases, Claude Code), creates the run, runs the scanners and "
    "SCA, and then lets Claude Code agents hunt, verify and review the findings in headless "
    "rounds that wait through usage limits. At the end it prints the deliverables and a short "
    "summary. With --tools-only it runs the scanners, SCA and the report without agents (no "
    "Claude Code needed). Missing tools or databases are installed only with --yes or after "
    "you answer y."
)
EPILOG: Final = (
    "examples:\n"
    "  kalkan audit C:/code/shop\n"
    "  kalkan audit https://github.com/org/repo --profile deep --open\n"
    "  kalkan audit C:/code/shop --tools-only --yes\n"
    "  kalkan audit C:/code/tool --profile fast --no-latest\n"
    "  kalkan audit devam 20261025T101500Z-shop-1a2b\n"
    "exit codes: 0 done, 1 incomplete, stopped or failed, 2 usage, 5 setup needed"
)
#: Seconds per minute and hour, for the duration text of the summary.
_MINUTE: Final = 60
_HOUR: Final = 3600


def register(subparsers: argparse._SubParsersAction) -> None:
    """Add the ``audit`` parser to the top-level subparsers."""
    parser = subparsers.add_parser(
        "audit",
        help=HELP,
        description=textwrap.fill(DESCRIPTION, 79),
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "target", metavar="TARGET", help="local folder or git URL, or 'devam' to resume a run"
    )
    parser.add_argument(
        "run_arg",
        nargs="?",
        type=_run_id,
        metavar="RUN_ID",
        help="with devam: the run to resume (default: the run in runs/LATEST)",
    )
    parser.add_argument(
        "--profile",
        type=loop_mod.profile_arg,
        choices=loop_mod.PROFILES,
        default=None,
        help=f"audit depth of a new run (default: {loop_mod.DEFAULT_PROFILE})",
    )
    parser.add_argument(
        "--tools-only",
        action="store_true",
        help="no agents and no Claude Code: the scanners, SCA and the report only (for CI or a "
        "quick look); every result stays an unverified tool result",
    )
    parser.add_argument(
        "--open",
        dest="open_report",
        action="store_true",
        help="open EXECUTIVE.html in the default browser at the end",
    )
    parser.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="install missing tools and vulnerability databases without asking (network)",
    )
    parser.add_argument(
        "--no-latest",
        action="store_true",
        help="new run only: do not record it in runs/LATEST (a side audit next to another one)",
    )
    parser.add_argument(
        "--allow-build-network",
        action="store_true",
        help="new run only: let the app-level PoC sandbox build and pull the images of the "
        "target's compose stack with network access (the stack itself never gets internet)",
    )
    parser.add_argument(
        "--live",
        action="append",
        default=None,
        metavar="PATH",
        help="new run only: a folder or file of the deployment that runs in production "
        "(repeatable); findings only in other deployment files count as template only",
    )
    parser.add_argument(
        "--not-live",
        action="append",
        default=None,
        metavar="PATH",
        help="new run only: a folder or file with code that production does not load "
        "(repeatable); a finding whose sinks are all there counts as template only",
    )
    parser.add_argument(
        "--max-hours",
        type=_hours,
        default=loop_mod.DEFAULT_MAX_HOURS,
        metavar="N",
        help=f"agent mode: stop after N hours in total (default: {loop_mod.DEFAULT_MAX_HOURS:g}); "
        "resume with devam",
    )
    parser.add_argument(
        "--max-usd",
        type=loop_mod.usd_arg,
        default=None,
        metavar="N",
        help="agent mode: " + loop_mod.MAX_USD_HELP,
    )
    parser.add_argument(
        "--json", action="store_true", help="print the result as JSON on stdout (no summary text)"
    )
    parser.set_defaults(func=_cmd_audit)


def _run_id(text: str) -> str:
    if not ids.is_run_id(text):
        raise argparse.ArgumentTypeError(
            f"not a run ID: {text!r} (expected <yyyymmddThhmmssZ>-<slug>-<4 hex>, for example "
            "20261016T151915Z-app-5fc6)"
        )
    return text


def _hours(text: str) -> float:
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a number: {text!r}") from None
    if not math.isfinite(value) or value <= 0 or value > unattended.MAX_HOURS_LIMIT:
        raise argparse.ArgumentTypeError(
            f"must be more than 0 and at most {unattended.MAX_HOURS_LIMIT:g} hours"
        )
    return value


# ---------------------------------------------------------------------------------------------
# Seams for tests


def _plugin_install() -> bool:
    """Return True when the engine runs from the Claude Code plugin. Tests replace this."""
    return resources.plugin_install()


def _cwd() -> Path:
    """Return the current folder. Tests replace this function."""
    return Path.cwd()


def _interactive() -> bool:
    """Return True when stdin is a terminal (a person can answer). Tests replace this."""
    try:
        return sys.stdin is not None and sys.stdin.isatty()
    except (AttributeError, ValueError, OSError):
        return False


def _ask(question: str) -> bool:
    """Ask a yes or no question on the terminal. Tests replace this function."""
    return preflight.ask_yes_no(question)


def _doctor(**kwargs: Any) -> DoctorReport:
    """Run the doctor checks. Tests replace this function."""
    from kalkan.tools.doctor import run_doctor

    return run_doctor(**kwargs)


def _run_setup(commands: list[tuple[str, ...]]) -> list[preflight.SetupStep]:
    """Run the setup commands in child processes. Tests replace this function."""
    return preflight.run_setup(commands, say=_say)


def _open_in_browser(path: Path) -> bool:
    """Open ``path`` in the default browser. Tests replace this function."""
    return webbrowser.open(path.resolve().as_uri())


def _clock() -> float:
    """Return monotonic seconds. Tests replace this function."""
    return time.monotonic()


# ---------------------------------------------------------------------------------------------
# Handler


@dataclass
class _Outcome:
    """What the command did; it becomes the ``--json`` document."""

    mode: str
    exit_code: int = EXIT_OK
    reason: str = "done"
    message: str = ""
    run: RunContext | None = None
    checks: preflight.Preflight | None = None
    setup: list[preflight.SetupStep] = field(default_factory=list)
    unattended: dict[str, Any] | None = None
    summary: dict[str, Any] | None = None
    opened: bool = False

    def to_dict(self) -> dict[str, Any]:
        run = self.run
        return {
            "run_id": run.run_id if run is not None else None,
            "run_dir": run.run_dir.absolute().as_posix() if run is not None else None,
            "mode": self.mode,
            "exit_code": self.exit_code,
            "reason": self.reason,
            "message": self.message,
            "preflight": self.checks.to_dict() if self.checks is not None else None,
            "setup": [step.to_dict() for step in self.setup],
            "unattended": self.unattended,
            "summary": self.summary,
            "opened": self.opened,
        }


def _cmd_audit(args: argparse.Namespace) -> int:
    # The phase engine loads only for this command, so that every other command starts fast.
    from kalkan.audit import drive  # noqa: PLC0415
    from kalkan.run import phases  # noqa: PLC0415

    started = _clock()
    resume = args.target.strip().lower() in loop_mod.RESUME_WORDS
    plugin = _plugin_install()
    command = PLUGIN_COMMAND if plugin else DEFAULT_COMMAND
    if args.run_arg is not None and not resume:
        raise KalkanError(
            f"a run ID works only with devam: {command} devam {args.run_arg}. A target starts a "
            "new run with a new ID."
        )
    ctx: RunContext | None = None
    target: str | None = None
    if resume:
        for given, flag in (
            (args.profile, "--profile"),
            (args.no_latest, "--no-latest"),
            (args.tools_only, "--tools-only"),
        ):
            if given:
                _say(f"{flag} has no effect with devam. The run keeps its settings.")
        ctx = _resume_context(args.run_arg, command)
        tools_only = run_mode(ctx.state) == MODE_TOOLS_ONLY
    else:
        target = unattended.normalize_target(args.target, cwd=_cwd())
        tools_only = args.tools_only
        if tools_only and args.profile is not None:
            _say("--profile has no effect with --tools-only: no agent task runs.")
    outcome = _Outcome(mode=MODE_TOOLS_ONLY if tools_only else MODE_AGENTS, run=ctx)

    scanner_work = ctx is None or ctx.phase in drive.DETERMINISTIC_PHASES
    stop = _check_setup(
        outcome,
        agents=not tools_only,
        tools=scanner_work,
        yes=args.yes,
        retry=_audit_command(command, args, target, ctx, "--yes"),
        tools_only_command=_audit_command(command, args, target, None, "--tools-only"),
    )
    if stop is not None:
        return _finish(args, outcome, stop)

    if ctx is None:
        assert target is not None
        ctx = init_run(
            target,
            profile=(None if tools_only else args.profile) or loop_mod.DEFAULT_PROFILE,
            update_latest=not args.no_latest,
            mode=outcome.mode,
            live_paths=args.live,
            not_live_paths=args.not_live,
            allow_build_network=args.allow_build_network,
        )
        outcome.run = ctx
        _say(f"run {ctx.run_id} created: {ctx.run_dir.absolute().as_posix()}")
        if args.no_latest:
            _say("runs/LATEST is unchanged: resume this run only with its ID")
    else:
        _say(f"resume run {ctx.run_id} (phase {ctx.phase})")
    hint = f"{command} devam {ctx.run_id}"
    if tools_only:
        skipped = ", ".join(phases.AGENT_PHASES)
        _say(f"the agent phases ({skipped}) are skipped: {phases.TOOLS_ONLY_REASON}")

    try:
        if tools_only:
            action = drive.drive_steps(ctx, allowed=None, say=_say)
            _tools_only_result(outcome, action, hint)
        else:
            if ctx.phase in drive.DETERMINISTIC_PHASES:
                drive.drive_steps(ctx, allowed=drive.DETERMINISTIC_PHASES, say=_say)
            _agents_result(outcome, ctx, args, plugin=plugin, command=command)
    except KeyboardInterrupt:
        outcome.exit_code, outcome.reason = EXIT_ERROR, "interrupted"
        outcome.message = f"interrupted. The run is resumable. Resume with: {hint}"
        _say(outcome.message)
        return _finish(args, outcome, EXIT_ERROR)

    try:
        phase = ctx.reload()["phase"]
    except KalkanError as exc:  # the run folder is gone (the runner reported it)
        _say(f"the run state cannot be read: {exc}")
        phase = None
    if phase == "done":
        if not tools_only:
            _refresh_report(ctx.run_dir)
        outcome.summary = summary_mod.build_summary(ctx.run_dir)
        if not args.json:
            text = summary_mod.format_summary(outcome.summary, elapsed=_duration(started))
            _write_stdout(text)
        if args.open_report:
            outcome.opened = _open_report(outcome.summary)
    elif args.open_report:
        _say("--open: the run is not done yet, so there is no report to open")
    return _finish(args, outcome, outcome.exit_code)


def _resume_context(run_id: str | None, command: str) -> RunContext:
    """Return the run of ``devam``: ``run_id``, else the run in ``runs/LATEST``."""
    if run_id is None:
        try:
            run_id = ids.read_latest()
        except KalkanError:
            run_id = None
        if run_id is None:
            raise KalkanError(
                f"no run to resume: runs/LATEST names no run. Start one with: {command} <target>"
            )
        _say(f"devam: the newest run {run_id} (runs/LATEST)")
    return load_context(run_id)


def _audit_command(
    command: str,
    args: argparse.Namespace,
    target: str | None,
    ctx: RunContext | None,
    extra: str,
) -> str:
    """Return the audit command line of a retry, with ``extra`` (``--yes`` or
    ``--tools-only``)."""
    if ctx is not None:
        return f"{command} devam {ctx.run_id} {extra}"
    shown = target or "<target>"
    if any(ch.isspace() for ch in shown):
        shown = f'"{shown}"'
    parts = [command, shown]
    if args.profile and extra != "--tools-only" and not args.tools_only:
        parts += ["--profile", args.profile]
    if args.tools_only and extra != "--tools-only":
        parts.append("--tools-only")
    if args.no_latest:
        parts.append("--no-latest")
    return " ".join([*parts, extra])


def _check_setup(
    outcome: _Outcome,
    *,
    agents: bool,
    tools: bool,
    yes: bool,
    retry: str,
    tools_only_command: str,
) -> int | None:
    """Run the setup checks of the audit; return an exit code to stop, else None."""
    if not agents and not tools:
        return None
    parts = ["pinned tools", "vulnerability databases"] if tools else []
    parts += ["Claude Code"] if agents else []
    _say(f"checking the setup: {', '.join(parts)}")
    checks = preflight.evaluate(
        preflight.run_checks(agents=agents, tools=tools, doctor=_doctor), agents=agents
    )
    outcome.checks = checks
    if checks.fatal:
        for problem in checks.fatal:
            _say(f"error: {problem.check}: {problem.detail}")
        return _stop(outcome, EXIT_ERROR, "environment", "the environment is broken (see above)")
    if checks.claude is not None:
        _say(f"error: Claude Code: {checks.claude.detail}")
        _say(f"Or audit without agents and without Claude Code: {tools_only_command}")
        return _stop(outcome, EXIT_SETUP, "claude", checks.claude.detail)
    if checks.trust is not None:
        _say(f"error: {checks.trust.detail}")
        return _stop(outcome, EXIT_ERROR, "trust", checks.trust.detail)
    if checks.needs_setup:
        for line in preflight.describe(checks):
            _say(f"setup needed: {line}")
        question = (
            "Install them now? A first setup downloads about 400 MB of tools and the "
            "vulnerability databases (3.3 GB on disk) and takes 5 to 15 minutes."
        )
        if not (yes or (_interactive() and _ask(question))):
            for line in preflight.fix_lines(checks, engine=resources.engine_command(), retry=retry):
                _say(line)
            return _stop(outcome, EXIT_SETUP, "setup_needed", "setup needed")
        outcome.setup = _run_setup(preflight.setup_commands(checks))
        checks = preflight.evaluate(
            preflight.run_checks(agents=agents, tools=tools, doctor=_doctor), agents=agents
        )
        outcome.checks = checks
        if checks.tools:
            _say("the setup did not fix every tool. Each row names its fix:")
            for problem in checks.tools:
                _say(f"  {problem.check}: {problem.detail}")
            return _stop(outcome, EXIT_SETUP, "setup_failed", "the setup did not fix every tool")
        if checks.databases is not None:
            _say(
                f"warning: a vulnerability database is still missing ({checks.databases.detail})."
                " The audit goes on, and the report lists the database gaps."
            )
    if checks.stale is not None:
        _say(f"warning: vulnerability databases: {checks.stale.detail}")
    for problem in checks.warnings:
        _say(f"warning: {problem.check}: {problem.detail}")
    return None


def _stop(outcome: _Outcome, code: int, reason: str, message: str) -> int:
    outcome.exit_code, outcome.reason, outcome.message = code, reason, message
    return code


def _tools_only_result(outcome: _Outcome, action: dict[str, Any], hint: str) -> None:
    kind = action["kind"]
    if kind == "done":
        outcome.reason, outcome.message = "done", "the tools-only audit is done"
        return
    if kind == "incomplete":
        outcome.exit_code, outcome.reason = EXIT_ERROR, "incomplete"
        outcome.message = f"the run finished incomplete: {action.get('reason')}"
    else:
        outcome.exit_code, outcome.reason = EXIT_ERROR, "stopped"
        outcome.message = (
            f"the tools-only run stopped at the action {kind} ({action.get('reason', '')}). "
            f"Resume with: {hint}"
        )
    _say(outcome.message)


def _agents_result(
    outcome: _Outcome,
    ctx: RunContext,
    args: argparse.Namespace,
    *,
    plugin: bool,
    command: str,
) -> None:
    """Hand the run to the unattended runner (bound to its ID) and record its result."""
    from kalkan.audit import drive  # noqa: PLC0415

    launch = unattended.prepare(
        target=None,
        run_id=ctx.run_id,
        max_hours=args.max_hours,
        command=command,
        plugin=plugin,
        max_usd=args.max_usd,
    )
    _say("agents: Claude Code rounds start now; they wait through usage-limit resets")
    with drive.RunWatcher(ctx.run_dir, _say):
        result = unattended.start(launch, say=_say)
    if result is None:  # Ctrl+C: start() printed the resume command
        outcome.exit_code, outcome.reason = EXIT_ERROR, "interrupted"
        outcome.message = f"interrupted. The run is resumable. Resume: {command} devam {ctx.run_id}"
        return
    outcome.unattended = result.to_dict()
    outcome.exit_code, outcome.reason, outcome.message = (
        result.exit_code,
        result.reason,
        result.message,
    )
    _say(result.message)
    _say(f"log: {result.log_file}")


def _refresh_report(run_dir: Path) -> None:
    """Write the report again with the cost of the last round (``refresh_report``)."""
    from kalkan.report.commands import refresh_report  # noqa: PLC0415
    from kalkan.run.usage import USAGE_NAME  # noqa: PLC0415

    if not (run_dir / USAGE_NAME).is_file() or not (run_dir / "report").is_dir():
        return
    try:
        written = refresh_report(run_dir)
    except (KalkanError, OSError, ValueError) as exc:
        _say(f"the report keeps the cost before the last round: {exc}")
        return
    _say(f"report written again with the cost of every round ({len(written)} files)")


def _open_report(summary: dict[str, Any]) -> bool:
    executive = summary.get("open_first")
    if not executive:
        _say("--open: the run has no EXECUTIVE.html")
        return False
    try:
        opened = bool(_open_in_browser(Path(executive)))
    except Exception as exc:  # a missing browser must not fail a finished audit
        _say(f"--open: the browser did not start: {exc}")
        return False
    if not opened:
        _say(f"--open: no browser found. Open the file yourself: {executive}")
    return opened


def _finish(args: argparse.Namespace, outcome: _Outcome, code: int) -> int:
    outcome.exit_code = code
    if args.json:
        _write_stdout(json.dumps(outcome.to_dict(), ensure_ascii=False, indent=2) + "\n")
    return code


def _duration(started: float) -> str:
    seconds = max(0, int(_clock() - started))
    if seconds < _MINUTE:
        return f"{seconds} s"
    if seconds < _HOUR:
        return f"{seconds // _MINUTE} min"
    return f"{seconds // _HOUR} h {seconds % _HOUR // _MINUTE} min"


# ---------------------------------------------------------------------------------------------
# Output helpers


def _say(message: str) -> None:
    print(f"kalkan audit: {message}", file=sys.stderr, flush=True)


def _write_stdout(text: str) -> None:
    """Write to stdout as UTF-8, also when Windows gives a pipe an ANSI code page."""
    stream = sys.stdout
    encoding = (getattr(stream, "encoding", None) or "").lower().replace("-", "").replace("_", "")
    buffer = getattr(stream, "buffer", None)
    if encoding != "utf8" and buffer is not None:
        stream.flush()
        buffer.write(text.encode("utf-8"))
        buffer.flush()
        return
    stream.write(text)
    stream.flush()
