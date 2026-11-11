# SPDX-License-Identifier: MIT
"""CLI command groups ``run`` and ``task`` (docs/ENGINE-SPEC.md, sections 9 and 11).

Commands: ``run init``, ``run status``, ``run resume``, ``run next``, ``run step``, ``run set``,
``run reopen``, ``run answer``, ``run wait``, ``run clean``, ``task claim``, ``task complete``,
``task fail`` and ``task prompt``. The phase engine behind ``run next``, ``run step``,
``run reopen`` and ``run answer`` lives in :mod:`kalkan.run.phases` and :mod:`kalkan.run.steps`
(docs/PHASES.md).

With ``--json`` the machine output goes to stdout. Without it the human output goes to stdout.
Notes and warnings always go to stderr. Commands that act on a run take ``--run <run-id>``;
without it they use ``runs/LATEST``. ``run wait`` also takes ``--run``, so that an orchestrator
can name its run in every command; it only checks that the run exists. ``run init --no-latest``
creates a run without changing ``runs/LATEST`` (parallel audits and scripts). ``run init
--tools-only`` creates a run without agents: the phase engine skips the agent phases
(docs/PHASES.md section 3). ``run clean <run-id>`` removes the target copy, the history copy
and the work folders of a finished run and keeps the report (:mod:`kalkan.run.clean`); the
commands that would run a cleaned run again refuse it.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections.abc import Callable, Sequence
from typing import Any

from kalkan.errors import UnsafeInputError, ValidationError
from kalkan.run import budget, queue
from kalkan.run.clean import refuse_cleaned
from kalkan.run.ids import resolve_run
from kalkan.run.init import MANIFEST_NAME, init_run
from kalkan.run.state import (
    DOCKER_MODES,
    LANGUAGES,
    MAX_PARALLEL_LIMIT,
    MODE_AGENTS,
    MODE_TOOLS_ONLY,
    PHASES,
    TASK_STATUSES,
    TASK_TYPES,
    RunContext,
    load_context,
    parse_task_id,
    run_mode,
)
from kalkan.util.safe_io import dumps_json, read_text_bounded

__all__ = ["register", "status_summary"]

EXIT_OK = 0
EXIT_USAGE = 2

RUN_HELP = "Manage audit runs: init, status, next, step, resume, clean."
TASK_HELP = "Manage agent tasks: claim, complete, fail, prompt."
PROFILE_CHOICES = tuple(budget.PROFILE_ALIASES)
#: Steps of ``run reopen`` (kalkan.run.phases.REOPEN_STEPS; a test keeps them equal).
REOPEN_STEP_CHOICES = (budget.CONSOLIDATE_STEP, budget.POLISH_STEP)


# ---------------------------------------------------------------------------------------------
# Argument types


def _positive_int(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError("expected an integer") from None
    if value < 1:
        raise argparse.ArgumentTypeError("expected an integer of at least 1")
    return value


def _non_negative_int(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError("expected an integer") from None
    if value < 0:
        raise argparse.ArgumentTypeError("expected an integer of at least 0")
    return value


def _max_parallel(text: str) -> int:
    value = _positive_int(text)
    if value > MAX_PARALLEL_LIMIT:
        raise argparse.ArgumentTypeError(f"expected at most {MAX_PARALLEL_LIMIT}")
    return value


def _owner(text: str) -> str:
    if not queue.is_valid_owner(text):
        raise argparse.ArgumentTypeError("expected 1 to 64 characters of A-Z a-z 0-9 . _ @ : -")
    return text


def _task_id(text: str) -> str:
    if parse_task_id(text) is None:
        raise argparse.ArgumentTypeError("expected a task ID such as T0001-recon")
    return text


def _add_run_option(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--run", dest="run_id", metavar="RUN_ID", help="run ID (default: the run in runs/LATEST)"
    )


def _add_json_option(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--json", action="store_true", help="print machine output on stdout")


# ---------------------------------------------------------------------------------------------
# Registration


def register(subparsers: argparse._SubParsersAction) -> None:
    """Add the ``run`` and ``task`` parsers to the top-level subparsers."""
    run = subparsers.add_parser("run", help=RUN_HELP, description=RUN_HELP)
    run.set_defaults(func=_group_help(run))
    run_sub = run.add_subparsers(dest="run_command", metavar="<subcommand>")

    init = run_sub.add_parser(
        "init",
        help="Create a run: copy the target, neutralize instruction files, write state.json.",
        description=(
            "Create a run for a local folder or a git URL (https://, ssh:// or git@host:path). "
            "The target is copied to runs/<run-id>/target with agent instruction files "
            "neutralized."
        ),
    )
    init.add_argument("target", help="local folder or git URL")
    init.add_argument(
        "--ref",
        metavar="REF",
        help="git URL targets only: tag, branch or commit to check out (the full history stays "
        "for the history scan); the manifest records the resolved commit in git_ref",
    )
    init.add_argument(
        "--profile",
        choices=PROFILE_CHOICES,
        default="standard",
        help="audit depth: fast, standard (default) or deep",
    )
    init.add_argument(
        "--lang",
        choices=LANGUAGES,
        default="en",
        help="report language: en (default) or tr; a Turkish run also offers an English version",
    )
    init.add_argument(
        "--max-parallel",
        type=_max_parallel,
        default=6,
        metavar="N",
        help=f"parallel agent tasks, 1 to {MAX_PARALLEL_LIMIT} (default 6)",
    )
    init.add_argument("--docker", choices=DOCKER_MODES, default="auto", help="PoC sandbox mode")
    init.add_argument(
        "--allow-build-network",
        action="store_true",
        help="allow network access while the PoC sandbox builds the application",
    )
    init.add_argument(
        "--live",
        action="append",
        default=None,
        metavar="PATH",
        help="a folder or file of the target that holds the deployment running in production "
        "(repeatable, for example --live deploy/helm); findings only in other deployment files "
        "count as template only",
    )
    init.add_argument(
        "--not-live",
        action="append",
        default=None,
        metavar="PATH",
        help="a folder or file of the target with code that production does not load "
        "(repeatable, for example a plugin folder that only another product loads); a finding "
        "whose sinks are all there counts as template only",
    )
    init.add_argument(
        "--no-latest",
        dest="latest",
        action="store_false",
        help="do not record the new run in runs/LATEST; name it with --run <run-id> in every "
        "later command (parallel audits, scripts)",
    )
    init.add_argument(
        "--tools-only",
        action="store_true",
        help="a run without agents: the deterministic scanners, SCA, merge and the report; "
        "the agent phases are skipped and every result stays an unverified tool result",
    )
    _add_json_option(init)
    init.set_defaults(func=_cmd_run_init)

    status = run_sub.add_parser(
        "status",
        help="Show the phase, the tasks and the budget of a run.",
        description="Show the phase table, task counts by status and type, and the budget.",
    )
    _add_run_option(status)
    _add_json_option(status)
    status.set_defaults(func=_cmd_run_status)

    resume = run_sub.add_parser(
        "resume",
        help="Recover a run after a crash, then show its status.",
        description=(
            "For each leased task: complete it when its result file exists, else return it to "
            "pending. Then return expired leases to pending and show the status."
        ),
    )
    _add_run_option(resume)
    _add_json_option(resume)
    resume.set_defaults(func=_cmd_run_resume)

    next_parser = run_sub.add_parser(
        "next",
        help="Return the next action: an engine step, agent tasks, wait, ask the user, or done.",
        description=(
            "Return the next action of the run as one JSON object. Agent tasks are leased to "
            "--owner (at most --limit, default options.max_parallel)."
        ),
    )
    next_parser.add_argument("--owner", type=_owner, default="orchestrator", help="lease owner")
    next_parser.add_argument(
        "--limit", type=_non_negative_int, metavar="N", help="maximum tasks to claim"
    )
    _add_run_option(next_parser)
    _add_json_option(next_parser)
    next_parser.set_defaults(func=_cmd_run_next)

    step = run_sub.add_parser(
        "step",
        help="Perform the next engine step.",
        description=(
            "Perform the next engine step of the current phase. Scanner steps fit their tool "
            "timeout into --max-seconds."
        ),
    )
    step.add_argument(
        "--max-seconds", type=_positive_int, default=480, metavar="N", help="time budget"
    )
    _add_run_option(step)
    _add_json_option(step)
    step.set_defaults(func=_cmd_run_step)

    setter = run_sub.add_parser(
        "set",
        help="Change an option of a run (--max-parallel, --live, --not-live).",
        description=(
            "Change an option of an existing run under the run lock. The orchestrator uses the "
            "new max-parallel value from its next run next. --live replaces the live deployment "
            "paths and --not-live the not-live code paths; run kalkan report --run <run-id> "
            "afterwards to write the report again."
        ),
    )
    setter.add_argument(
        "--max-parallel",
        type=_max_parallel,
        default=None,
        metavar="N",
        help=f"parallel agent tasks, 1 to {MAX_PARALLEL_LIMIT}",
    )
    live = setter.add_mutually_exclusive_group()
    live.add_argument(
        "--live",
        action="append",
        default=None,
        metavar="PATH",
        help="the deployment running in production (repeatable); replaces the stored paths",
    )
    live.add_argument(
        "--no-live", action="store_true", help="forget the stored live deployment paths"
    )
    not_live = setter.add_mutually_exclusive_group()
    not_live.add_argument(
        "--not-live",
        action="append",
        default=None,
        metavar="PATH",
        help="code that production does not load (repeatable); replaces the stored paths",
    )
    not_live.add_argument(
        "--no-not-live", action="store_true", help="forget the stored not-live code paths"
    )
    _add_run_option(setter)
    _add_json_option(setter)
    setter.set_defaults(func=_cmd_run_set)

    compare = run_sub.add_parser(
        "compare",
        help="Compare the findings, time and cost of two or more runs.",
        description=(
            "Match the findings of the runs (fingerprint, else class, file and lines at most 10 "
            "apart) and print the issues found by every run, by some runs, the verdict and "
            "severity changes, and the type, time and recorded cost of each run. Use it for "
            "repeated audits of the same commit (stability) or two profiles side by side."
        ),
    )
    compare.add_argument("runs", nargs="+", metavar="RUN_ID", help="two or more run IDs")
    _add_json_option(compare)
    compare.set_defaults(func=_cmd_run_compare)

    reopen = run_sub.add_parser(
        "reopen",
        help="Put a finished run back before a validate step (consolidate or polish).",
        description=(
            "Move a run in the phase poc, merge, report or done back to validate with the step "
            "pending (consolidate also puts back polish), so that run next runs it and the run "
            "flows through merge, report and done again. Refused while a task is leased. A "
            "second call changes nothing."
        ),
    )
    reopen.add_argument(
        "--step",
        required=True,
        choices=REOPEN_STEP_CHOICES,
        help="the validate step to run again",
    )
    _add_run_option(reopen)
    _add_json_option(reopen)
    reopen.set_defaults(func=_cmd_run_reopen)

    answer = run_sub.add_parser(
        "answer",
        help="Record the user's answer to a question of the run.",
        description=(
            "Record the user's answer in state.json. english_report yes also reopens a finished "
            "run for the English report."
        ),
    )
    answer.add_argument("question", help="question key, for example english_report")
    answer.add_argument("value", help="answer, for example yes or no")
    _add_run_option(answer)
    _add_json_option(answer)
    answer.set_defaults(func=_cmd_run_answer)

    wait = run_sub.add_parser(
        "wait",
        help="Pause before the next run next (the answer to a wait action).",
        description=(
            "Sleep for the given number of seconds (at most 300), so that a host that can only "
            "run engine commands can pause after a wait action without a busy loop."
        ),
    )
    wait.add_argument("--seconds", type=_positive_int, default=60, metavar="N", help="pause")
    wait.add_argument(
        "--run",
        dest="run_id",
        metavar="RUN_ID",
        help="the run of the orchestrator; the command only checks that it exists",
    )
    _add_json_option(wait)
    wait.set_defaults(func=_cmd_run_wait)

    clean = run_sub.add_parser(
        "clean",
        help="Delete the target copy, the history copy and the work folders of a finished run.",
        description=(
            "Delete the bulky parts of a finished run: target/ (the copy of the target), "
            "source/ (the history copy), scans/.work/ and sca/.work/ (the work folders of the "
            "tools). report/, the state, the tool results and the task results stay. Links and "
            "junctions are removed as links; the folders they point at stay. A cleaned run "
            "cannot run again."
        ),
    )
    clean.add_argument("run_id", metavar="RUN_ID", help="the run to clean")
    clean.add_argument(
        "--force",
        action="store_true",
        help="also clean a run that is not finished (it cannot continue after that)",
    )
    clean.add_argument(
        "--dry-run", action="store_true", help="show what would be deleted and how much"
    )
    _add_json_option(clean)
    clean.set_defaults(func=_cmd_run_clean)

    task = subparsers.add_parser("task", help=TASK_HELP, description=TASK_HELP)
    task.set_defaults(func=_group_help(task))
    task_sub = task.add_subparsers(dest="task_command", metavar="<subcommand>")

    claim = task_sub.add_parser(
        "claim",
        help="Lease ready tasks to an owner.",
        description=(
            "Lease up to --limit ready tasks of the current phase (or of --phase), highest "
            "priority first."
        ),
    )
    claim.add_argument("--owner", type=_owner, required=True, help="lease owner name")
    claim.add_argument(
        "--limit",
        type=_non_negative_int,
        metavar="N",
        help="maximum tasks to lease (default: options.max_parallel)",
    )
    claim.add_argument(
        "--type",
        dest="types",
        action="append",
        choices=TASK_TYPES,
        help="lease only this task type (repeatable)",
    )
    claim.add_argument(
        "--phase",
        dest="phases",
        action="append",
        choices=PHASES,
        help="lease tasks of this phase instead of the current one (repeatable)",
    )
    _add_run_option(claim)
    _add_json_option(claim)
    claim.set_defaults(func=_cmd_task_claim)

    complete = task_sub.add_parser(
        "complete",
        help="Validate a task result, run its handler and mark the task done.",
        description=(
            "Read tasks/<id>/result.json, check it against its schema, run the type handler and "
            "mark the task done. Exit code 4 when the result is invalid."
        ),
    )
    complete.add_argument("task_id", type=_task_id, metavar="TASK_ID", help="task ID")
    _add_run_option(complete)
    _add_json_option(complete)
    complete.set_defaults(func=_cmd_task_complete)

    fail = task_sub.add_parser(
        "fail",
        help="Record that the agent could not do a task.",
        description="Count a failed attempt; the task becomes pending again or dead.",
    )
    fail.add_argument("task_id", type=_task_id, metavar="TASK_ID", help="task ID")
    fail.add_argument("--reason", required=True, help="short reason")
    _add_run_option(fail)
    _add_json_option(fail)
    fail.set_defaults(func=_cmd_task_fail)

    prompt = task_sub.add_parser(
        "prompt",
        help="Print the rendered prompt of a task.",
        description="Print the rendered prompt of a task; render and store it when it is missing.",
    )
    prompt.add_argument("task_id", type=_task_id, metavar="TASK_ID", help="task ID")
    _add_run_option(prompt)
    _add_json_option(prompt)
    prompt.set_defaults(func=_cmd_task_prompt)


def _group_help(parser: argparse.ArgumentParser) -> Callable[[argparse.Namespace], int]:
    def handler(_args: argparse.Namespace) -> int:
        parser.print_help()
        return EXIT_USAGE

    return handler


# ---------------------------------------------------------------------------------------------
# Status


def status_summary(ctx: RunContext) -> dict[str, Any]:
    """Return the ``run status --json`` object of a run (from the context snapshot)."""
    state = ctx.state
    report = ctx.run_dir / "report" / "REPORT.md"
    return {
        "run_id": state["run_id"],
        "run_dir": ctx.run_dir.absolute().as_posix(),
        "phase": state["phase"],
        "created_at": state["created_at"],
        "updated_at": state["updated_at"],
        "target": state["target"],
        "options": state["options"],
        "phases": [
            {
                "name": name,
                "status": state["phases"][name]["status"],
                "started_at": state["phases"][name]["started_at"],
                "finished_at": state["phases"][name]["finished_at"],
                "steps": state["phases"][name]["steps"],
            }
            for name in PHASES
        ],
        "tasks": queue.task_counts(state),
        "budget": {**state["budget"], "remaining": budget.remaining(state)},
        "incomplete_reason": state["incomplete_reason"],
        "report": report.absolute().as_posix() if report.is_file() else None,
    }


def _print_status(summary: dict[str, Any]) -> None:
    options = summary["options"]
    target = summary["target"]
    print(f"Run:     {summary['run_id']}")
    print(f"Folder:  {summary['run_dir']}")
    print(f"Target:  {target['source']} ({target['kind']})")
    mode = f", mode {options['mode']}" if options.get("mode") == MODE_TOOLS_ONLY else ""
    print(
        f"Options: profile {options['profile']}, language {options['lang']}, "
        f"max parallel {options['max_parallel']}, docker {options['docker']}{mode}"
    )
    print(f"Phase:   {summary['phase']}")
    print()
    rows = [
        (item["name"], item["status"], item["started_at"] or "-", item["finished_at"] or "-")
        for item in summary["phases"]
    ]
    _print_table(("PHASE", "STATUS", "STARTED", "FINISHED"), rows)
    tasks = summary["tasks"]
    counts = ", ".join(f"{status} {count}" for status, count in tasks["by_status"].items() if count)
    print()
    print(f"Tasks:   {tasks['total']}" + (f" ({counts})" if counts else ""))
    if tasks["by_type"]:
        rows = [
            (name, *(str(by_status[status]) for status in TASK_STATUSES))
            for name, by_status in tasks["by_type"].items()
        ]
        _print_table(("TYPE", *(status.upper() for status in TASK_STATUSES)), rows)
    spent = summary["budget"]
    print(
        f"Budget:  {spent['used_agent_tasks']} of {spent['max_agent_tasks']} agent tasks used, "
        f"{spent['remaining']} left"
    )
    if summary["incomplete_reason"]:
        print(f"Incomplete: {summary['incomplete_reason']}")
    if summary["report"]:
        print(f"Report:  {summary['report']}")


# ---------------------------------------------------------------------------------------------
# run commands


def _read_manifest(ctx: RunContext) -> dict[str, Any]:
    try:
        data = json.loads(read_text_bounded(ctx.run_dir / MANIFEST_NAME))
    except (UnsafeInputError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _cmd_run_init(args: argparse.Namespace) -> int:
    ctx = init_run(
        args.target,
        profile=args.profile,
        lang=args.lang,
        max_parallel=args.max_parallel,
        docker=args.docker,
        allow_build_network=args.allow_build_network,
        ref=args.ref,
        update_latest=args.latest,
        mode=MODE_TOOLS_ONLY if getattr(args, "tools_only", False) else MODE_AGENTS,
        live_paths=args.live,
        not_live_paths=args.not_live,
    )
    manifest = _read_manifest(ctx)
    excluded = {
        item["class"]: item["count"] for item in manifest.get("excluded", []) if item.get("count")
    }
    output = {
        "run_id": ctx.run_id,
        "run_dir": ctx.run_dir.absolute().as_posix(),
        "phase": ctx.phase,
        "target": ctx.state["target"],
        "options": ctx.options,
        "budget": ctx.state["budget"],
        "tech": manifest.get("tech", []),
        "files": manifest.get("files", {}),
        "excluded": excluded,
        "neutralized": manifest.get("neutralized_count", 0),
        "latest": args.latest,
    }
    if args.ref is not None:
        output["requested_ref"] = args.ref
    if not args.latest:
        print(
            f"kalkan: runs/LATEST is unchanged. Pass --run {ctx.run_id} to every command of "
            "this run.",
            file=sys.stderr,
        )
    if args.json:
        _print_json(output)
        return EXIT_OK
    files = output["files"]
    print(f"Run {ctx.run_id} created in {output['run_dir']}")
    if args.ref is not None:
        print(f"Ref {args.ref}: commit {ctx.state['target'].get('git_ref')}")
    print(
        f"Copied {files.get('copied', 0)} files, skipped {files.get('skipped', 0)} paths, "
        f"neutralized {output['neutralized']} instruction paths."
    )
    if excluded:
        print("Skipped: " + ", ".join(f"{name} {count}" for name, count in excluded.items()))
    print("Tech: " + (", ".join(output["tech"]) or "none detected"))
    if run_mode(ctx.state) == MODE_TOOLS_ONLY:
        print("Mode: tools-only (the agent phases are skipped; no agent task runs).")
    print(f"Phase: {ctx.phase}. Next: kalkan run next --run {ctx.run_id}")
    return EXIT_OK


def _cmd_run_status(args: argparse.Namespace) -> int:
    summary = status_summary(load_context(args.run_id))
    if args.json:
        _print_json(summary)
    else:
        _print_status(summary)
    return EXIT_OK


def _cmd_run_resume(args: argparse.Namespace) -> int:
    ctx = load_context(args.run_id)
    refuse_cleaned(ctx.run_dir, "run resume")
    report = queue.resume(ctx)
    summary = status_summary(ctx)
    if args.json:
        _print_json({"resume": report, "status": summary})
        return EXIT_OK
    for key in ("completed", "unchanged", "released", "expired"):
        if report[key]:
            print(f"{key.capitalize()}: {', '.join(report[key])}")
    for item in report["rejected"]:
        print(f"Rejected: {item['id']} (attempt {item['attempts']}, now {item['status']})")
        for line in item["errors"][:5]:
            print(f"  - {line}")
    for item in report["busy"]:
        print(f"Skipped: {item['id']}: {item['reason']}", file=sys.stderr)
    if not any(report.values()):
        print("Nothing to recover.")
    print()
    _print_status(summary)
    return EXIT_OK


def _cmd_run_next(args: argparse.Namespace) -> int:
    from kalkan.run import phases  # noqa: PLC0415 - loads the phase engine only when needed

    ctx = load_context(args.run_id)
    refuse_cleaned(ctx.run_dir, "run next")
    action = phases.next_action(ctx, args.owner, args.limit)
    if args.json:
        _print_json(action)
        return EXIT_OK
    kind = action["kind"]
    if kind == "engine_step":
        print(f"engine step {action['step']} (phase {action['phase']}): run kalkan run step")
    elif kind == "agent_tasks":
        for item in action["tasks"]:
            print(f"{item['id']}  {item['agent']}  {item['prompt_file']}")
    elif kind == "wait":
        print(f"wait {action['retry_after_seconds']} seconds: {action['reason']}")
    elif kind == "ask_user":
        print(f"ask the user: {action['question']}")
    elif kind == "done":
        print(f"done: {action['report']}")
    else:
        print(f"incomplete: {action['reason']}")
    return EXIT_OK


def _cmd_run_step(args: argparse.Namespace) -> int:
    from kalkan.run import steps  # noqa: PLC0415 - loads the phase engine only when needed

    ctx = load_context(args.run_id)
    refuse_cleaned(ctx.run_dir, "run step")
    outcome = steps.run_step(ctx, args.max_seconds)
    if args.json:
        _print_json(outcome)
    else:
        name = outcome["step"] or "-"
        print(f"{outcome['phase']} {name}: {outcome['status']} ({outcome['duration_seconds']} s)")
        if outcome["detail"]:
            print(f"  {outcome['detail']}")
    return EXIT_OK


MAX_WAIT_SECONDS = 300


def _cmd_run_wait(args: argparse.Namespace, *, sleep: Callable[[float], None] | None = None) -> int:
    run_id = getattr(args, "run_id", None)
    if run_id is not None:
        resolve_run(run_id)  # StateError for an invalid or a missing run
    seconds = min(args.seconds, MAX_WAIT_SECONDS)
    (sleep or time.sleep)(seconds)
    if args.json:
        _print_json({"waited_seconds": seconds})
    else:
        print(f"kalkan: waited {seconds} s", file=sys.stderr)
    return 0


def _cmd_run_set(args: argparse.Namespace) -> int:
    from kalkan.findings.deployment import check_live_paths  # noqa: PLC0415
    from kalkan.run.state import transaction  # noqa: PLC0415

    paths_given = args.live is not None or args.not_live is not None
    if args.max_parallel is None and not paths_given and not (args.no_live or args.no_not_live):
        raise ValidationError(
            "run set needs --max-parallel, --live, --no-live, --not-live or --no-not-live"
        )
    ctx = load_context(args.run_id)
    target = ctx.run_dir / "target"
    folder = target if target.is_dir() else None
    live: list[str] | None = None
    not_live: list[str] | None = None
    try:
        if args.live is not None:
            live = check_live_paths(args.live, folder)
        if args.not_live is not None:
            not_live = check_live_paths(args.not_live, folder, option="--not-live")
    except ValueError as exc:
        raise ValidationError(str(exc)) from None
    outcome: dict[str, Any] = {"run_id": ctx.state["run_id"]}
    with transaction(ctx) as tx:
        options = tx.state["options"]
        if args.max_parallel is not None:
            outcome["previous"] = options["max_parallel"]
            options["max_parallel"] = args.max_parallel
            outcome["max_parallel"] = args.max_parallel
            tx.event(
                "options_changed", max_parallel=args.max_parallel, previous=outcome["previous"]
            )
        if live is not None or args.no_live:
            outcome["previous_live_paths"] = options.get("live_paths", [])
            if live:
                options["live_paths"] = live
            else:
                options.pop("live_paths", None)
            outcome["live_paths"] = live or []
            tx.event("options_changed", live_paths=live or [])
        if not_live is not None or args.no_not_live:
            outcome["previous_not_live_paths"] = options.get("not_live_paths", [])
            if not_live:
                options["not_live_paths"] = not_live
            else:
                options.pop("not_live_paths", None)
            outcome["not_live_paths"] = not_live or []
            tx.event("options_changed", not_live_paths=not_live or [])
    if args.json:
        _print_json(outcome)
    else:
        if "max_parallel" in outcome:
            print(f"max_parallel: {outcome['previous']} -> {args.max_parallel}", file=sys.stderr)
        if "live_paths" in outcome:
            shown = ", ".join(outcome["live_paths"]) or "none"
            print(f"live_paths: {shown}; write the report again: kalkan report", file=sys.stderr)
        if "not_live_paths" in outcome:
            shown = ", ".join(outcome["not_live_paths"]) or "none"
            print(
                f"not_live_paths: {shown}; write the report again: kalkan report", file=sys.stderr
            )
    return EXIT_OK


def _cmd_run_compare(args: argparse.Namespace) -> int:
    from kalkan.report.compare import compare_runs, format_comparison  # noqa: PLC0415

    if len(set(args.runs)) < 2:
        raise ValidationError("run compare needs two or more different run IDs")
    result = compare_runs([resolve_run(run_id) for run_id in args.runs])
    if args.json:
        _print_json(result)
    else:
        print(format_comparison(result))
    return EXIT_OK


def _cmd_run_reopen(args: argparse.Namespace) -> int:
    from kalkan.run import phases  # noqa: PLC0415 - loads the phase engine only when needed

    ctx = load_context(args.run_id)
    refuse_cleaned(ctx.run_dir, "run reopen")
    outcome = phases.reopen(ctx, args.step)
    if args.json:
        _print_json(outcome)
    elif outcome["reopened"]:
        print(
            f"The run is back in validate ({outcome['previous_phase']} before); the step "
            f"{outcome['step']} is pending. Next: kalkan run next",
            file=sys.stderr,
        )
    else:
        print(
            f"Nothing to reopen: the run is in {outcome['phase']}; the step {outcome['step']} "
            "runs when the run reaches it.",
            file=sys.stderr,
        )
    return EXIT_OK


def _cmd_run_answer(args: argparse.Namespace) -> int:
    from kalkan.run import phases  # noqa: PLC0415 - loads the phase engine only when needed

    ctx = load_context(args.run_id)
    refuse_cleaned(ctx.run_dir, "run answer")
    outcome = phases.answer(ctx, args.question, args.value)
    if args.json:
        _print_json(outcome)
    else:
        print(f"{outcome['question']}: {outcome['value']}")
        if outcome["reopened"]:
            print("The run is back in the report phase. Next: kalkan run next")
    return EXIT_OK


def _cmd_run_clean(args: argparse.Namespace) -> int:
    from kalkan.run.clean import clean_run  # noqa: PLC0415 - loads the cleanup only when needed

    result = clean_run(resolve_run(args.run_id), force=args.force, dry_run=args.dry_run)
    if args.json:
        _print_json(result.to_dict())
    else:
        _print_clean(result)
    return 1 if result.errors else EXIT_OK


def _print_clean(result: Any) -> None:
    from kalkan.util.fs import size_text  # noqa: PLC0415

    total = result.total
    verb = "would delete" if result.dry_run else "deleted"
    state = f"phase {result.phase}" if result.phase else "no readable state"
    forced = ", --force" if result.forced and result.phase != "done" else ""
    print(
        f"Run {result.run_id} ({state}{forced}): {verb} {size_text(total.bytes)} "
        f"in {total.files} files"
    )
    rows = []
    for part in result.parts:
        if part.skipped:
            size = f"skipped: {part.skipped}"
        elif not part.present:
            size = "not there"
        else:
            size = f"{size_text(part.stats.bytes)} in {part.stats.files} files"
        rows.append((f"{part.path}/", size, part.what))
    _print_table(("PART", "SIZE", "WHAT"), rows)
    report = "report/, " if (result.run_dir / "report").is_dir() else ""
    print(
        f"Kept: {report}the state, the tool and task results and the rest of the run "
        f"({size_text(result.kept_bytes)} in {result.kept_files} files)."
    )
    for error in result.errors[:20]:
        print(f"error: {error}", file=sys.stderr)


# ---------------------------------------------------------------------------------------------
# task commands


def _cmd_task_claim(args: argparse.Namespace) -> int:
    ctx = load_context(args.run_id)
    limit = args.limit if args.limit is not None else ctx.options["max_parallel"]
    items = queue.claim(ctx, args.owner, limit, types=args.types, phases=args.phases)
    if args.json:
        _print_json({"tasks": items})
        return EXIT_OK
    if not items:
        print("No ready task.", file=sys.stderr)
        return EXIT_OK
    _print_table(
        ("TASK", "AGENT", "PROMPT"),
        [(item["id"], item["agent"], item["prompt_file"]) for item in items],
    )
    return EXIT_OK


def _cmd_task_complete(args: argparse.Namespace) -> int:
    ctx = load_context(args.run_id)
    outcome = queue.complete(ctx, args.task_id)
    if args.json:
        _print_json(outcome)
    else:
        print(f"{outcome['id']}: {outcome['status']}")
    return EXIT_OK


def _cmd_task_fail(args: argparse.Namespace) -> int:
    ctx = load_context(args.run_id)
    outcome = queue.fail(ctx, args.task_id, args.reason)
    if args.json:
        _print_json(outcome)
    else:
        print(
            f"{outcome['id']}: {outcome['status']} "
            f"(attempt {outcome['attempts']} of {outcome['max_attempts']})"
        )
    return EXIT_OK


def _cmd_task_prompt(args: argparse.Namespace) -> int:
    from kalkan.run import tasks  # noqa: PLC0415 - loads the prompt renderer only when needed

    ctx = load_context(args.run_id)
    queue.get_task(ctx, args.task_id)  # StateError for an unknown task
    path = tasks.ensure_prompt(ctx, args.task_id)
    text = read_text_bounded(path, 16 * 1024 * 1024)
    if args.json:
        prompt_file = path.absolute().as_posix()
        _print_json({"id": args.task_id, "prompt_file": prompt_file, "prompt": text})
    else:
        sys.stdout.write(text if text.endswith(chr(10)) else text + chr(10))
    return EXIT_OK


# ---------------------------------------------------------------------------------------------
# Output helpers


def _print_json(obj: Any) -> None:
    sys.stdout.write(dumps_json(obj))


def _print_table(headers: Sequence[str], rows: Sequence[Sequence[str]]) -> None:
    widths = [len(header) for header in headers]
    for row in rows:
        for index, cell in enumerate(row[:-1]):
            widths[index] = max(widths[index], len(str(cell)))
    for line in [headers, *rows]:
        cells = [str(cell).ljust(widths[index]) for index, cell in enumerate(line[:-1])]
        print("  ".join([*cells, str(line[-1])]).rstrip())
