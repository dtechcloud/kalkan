# SPDX-License-Identifier: MIT
"""CLI command ``kalkan unattended`` (docs/ENGINE-SPEC.md, sections 9 and 22).

``kalkan unattended <target | devam [RUN_ID]> [--run RUN_ID] [--profile fast|standard|deep]
[--no-latest] [--max-hours N] [--round-hours N] [--host claude|codex] [--log-dir DIR]
[--dry-run] [--json]``

Progress messages go to stderr. ``--json`` prints the result document on stdout. ``--dry-run``
prints the ``run init`` command and the command lines of the rounds on stdout and starts
nothing.

Run binding (:mod:`kalkan.unattended.loop`, point 1): a target starts a new audit, and the loop
creates the run itself (``--no-latest`` keeps ``runs/LATEST`` unchanged). ``devam <run-id>`` or
``devam --run <run-id>`` resumes that run. ``devam`` alone binds to the run in ``runs/LATEST``
once at the start. Every round prompt names the run ID, so parallel audits never collide.

Target rules: a git URL (``https://``, ``ssh://``, ``git://``, ``file://`` or ``user@host:path``)
passes unchanged. Any other target is a local folder. A relative path is relative to the
current folder, and ``run init`` gets its absolute path with forward slashes. A target must not
contain a double quote, a backtick, ``$`` or a control character. Codex runs the engine in a
sandbox without network, so ``$kalkan`` in a Codex session cannot clone a git URL; for the same
policy ``--host codex`` refuses a git URL: clone it first.

Plugin install (:func:`kalkan.resources.plugin_install`): the engine runs from the venv of the
Claude Code plugin, and no checkout exists. The rounds then send ``/kalkan:kalkan`` and run in
the runs root (``~/kalkan-runs`` or ``KALKAN_RUNS_DIR``). The plugin has the user scope, so it
loads in any folder. The runs root holds no project files of a target (``CLAUDE.md``,
``.claude/settings.json``) at its top, and every resume finds the same folder. The folder-trust
refusal does not apply: the plugin hook gives the permissions, also in an untrusted folder.
A runs root inside a ``.claude`` folder is refused, because Claude Code never lets a subagent
write there. Only ``--host claude`` works. The stop messages name ``kalkan-unattended``, the
launcher that the plugin setup installs in ``<plugin data folder>/bin`` (docs/PLUGIN.md).

Reuse (``kalkan audit``, docs/ENGINE-SPEC.md section 25): :func:`prepare` checks the options and
returns a :class:`Launch` (the options, the host, the working directory, the log file and the
round command line); :func:`start` runs it to the end. ``kalkan audit`` binds a launch to the run
that it created and passes its own message function and command name.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from kalkan import resources
from kalkan.errors import KalkanError
from kalkan.run import ids
from kalkan.unattended import hosts
from kalkan.unattended import loop as loop_mod
from kalkan.util import paths

__all__ = [
    "PLUGIN_COMMAND",
    "RUN_ID_PLACEHOLDER",
    "Launch",
    "build_loop",
    "normalize_target",
    "plugin_host",
    "plugin_workdir",
    "prepare",
    "register",
    "start",
]

EXIT_OK: Final = 0
EXIT_ERROR: Final = 1

#: The launcher of the plugin install (``plugins/kalkan/bin/kalkan-unattended``).
PLUGIN_COMMAND: Final = "kalkan-unattended"

HELP: Final = "Run or resume an audit headless and wait through usage-limit resets."
DESCRIPTION: Final = (
    "Run the kalkan skill headless in rounds. For a new audit kalkan first creates the run "
    '(run init). Every round sends "/kalkan devam <run-id> --headless", so each unattended '
    "run stays bound to its own run, also when other audits run at the same time. "
    "With --host codex the prompts start with $kalkan. After each round kalkan reads the run "
    "status. It stops when the run is done (exit code 0), when the run is incomplete (exit "
    "code 1) or after --max-hours (exit code 1). It waits through usage-limit resets. "
    "In the Claude Code plugin the prompts start with /kalkan:kalkan, and the rounds run in "
    "the runs folder."
)
EPILOG: Final = (
    "examples:\n"
    "  kalkan unattended C:/code/app --profile deep\n"
    "  kalkan unattended https://github.com/org/repo.git\n"
    "  kalkan unattended devam 20261016T151915Z-app-5fc6 --max-hours 12\n"
    "  kalkan unattended devam --run 20261016T151915Z-app-5fc6\n"
    "  kalkan unattended devam\n"
    "  kalkan unattended C:/code/app --host codex\n"
    "  kalkan unattended devam --dry-run"
)
MAX_HOURS_LIMIT: Final = 24.0 * 31
#: The run ID that a dry run shows when it does not know the run yet.
RUN_ID_PLACEHOLDER: Final = "RUN_ID"

_URL: Final = re.compile(r"\A(?:[A-Za-z][A-Za-z0-9+.-]*://|[A-Za-z0-9._-]+@[A-Za-z0-9.-]+:)")
_FORBIDDEN: Final = re.compile(r'["`$\x00-\x1f\x7f-\x9f\u2028\u2029]')


def register(subparsers: argparse._SubParsersAction) -> None:
    """Add the ``unattended`` parser to the top-level subparsers."""
    parser = subparsers.add_parser(
        "unattended",
        help=HELP,
        description=DESCRIPTION,
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "target",
        metavar="TARGET",
        help="local folder or git URL to audit, or 'devam' to resume a run",
    )
    parser.add_argument(
        "run_arg",
        nargs="?",
        type=_run_id,
        metavar="RUN_ID",
        help="with devam: the run to resume, as with --run",
    )
    parser.add_argument(
        "--run",
        dest="run_id",
        type=_run_id,
        metavar="RUN_ID",
        help="with devam: the run to resume (default: the run in runs/LATEST, read once at "
        "the start)",
    )
    parser.add_argument(
        "--profile",
        type=loop_mod.profile_arg,
        choices=loop_mod.PROFILES,
        default=None,
        help=f"audit profile of a new run (default: {loop_mod.DEFAULT_PROFILE}). "
        "A resumed run keeps its profile.",
    )
    parser.add_argument(
        "--no-latest",
        action="store_true",
        help="new run only: run init does not record the run in runs/LATEST",
    )
    parser.add_argument(
        "--lang",
        choices=("en", "tr"),
        default=None,
        help="new run only: report language, en (default) or tr",
    )
    parser.add_argument(
        "--max-hours",
        type=_hours,
        default=loop_mod.DEFAULT_MAX_HOURS,
        metavar="N",
        help=f"stop after N hours in total (default: {loop_mod.DEFAULT_MAX_HOURS:g})",
    )
    parser.add_argument(
        "--max-usd",
        type=loop_mod.usd_arg,
        default=None,
        metavar="N",
        help=loop_mod.MAX_USD_HELP,
    )
    parser.add_argument(
        "--round-hours",
        type=_hours,
        default=loop_mod.DEFAULT_ROUND_HOURS,
        metavar="N",
        help="stop one host round and its process tree after N hours "
        f"(default: {loop_mod.DEFAULT_ROUND_HOURS:g})",
    )
    parser.add_argument(
        "--host",
        choices=hosts.host_names(),
        default="claude",
        help="agent CLI that runs the rounds (default: claude)",
    )
    parser.add_argument(
        "--log-dir",
        type=Path,
        default=None,
        metavar="DIR",
        help="folder of the log file unattended-<UTC time>.log (default: the runs folder)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="print the command lines of the rounds and exit. Start nothing.",
    )
    parser.add_argument("--json", action="store_true", help="print the result as JSON on stdout")
    parser.set_defaults(func=_cmd_unattended)


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
    if not math.isfinite(value) or value <= 0 or value > MAX_HOURS_LIMIT:
        raise argparse.ArgumentTypeError(
            f"must be more than 0 and at most {MAX_HOURS_LIMIT:g} hours"
        )
    return value


# ---------------------------------------------------------------------------------------------
# Seams for tests


def _repo_root() -> Path:
    """Return the repository root. Tests replace this function."""
    return paths.repo_root()


def _plugin_install() -> bool:
    """Return True when the engine runs from the Claude Code plugin. Tests replace this
    function."""
    return resources.plugin_install()


def _runs_root() -> Path:
    """Return the runs root. Tests replace this function."""
    return ids.runs_root()


def _cwd() -> Path:
    """Return the current folder. Tests replace this function."""
    return Path.cwd()


def _workspace_trusted(repo: Path) -> bool | None:
    """Return the Claude Code trust state of the repository folder (a seam for tests)."""
    from kalkan.unattended import workspace_trusted

    return workspace_trusted(repo)


def _create_host(name: str, *, require: bool) -> hosts.Host:
    """Return the host. Tests replace this function."""
    return hosts.create_host(name, require=require)


def build_loop(
    options: loop_mod.UnattendedOptions,
    host: hosts.Host,
    workdir: Path,
    log: loop_mod.RunLog,
    runs_dir: Path,
    *,
    say: Callable[[str], None] | None = None,
) -> loop_mod.UnattendedLoop:
    """Return the loop with its real dependencies: the status reader and the run creator run
    the engine of this Python in ``workdir``. ``say`` replaces the progress printer."""
    return loop_mod.UnattendedLoop(
        options,
        host=host,
        cwd=workdir,
        log=log,
        read_status=loop_mod.subprocess_status_reader(workdir),
        runs_dir=runs_dir,
        create_run=loop_mod.subprocess_run_creator(workdir),
        check_run=loop_mod.run_checker(runs_dir),
        say=say,
    )


def _build_loop(
    options: loop_mod.UnattendedOptions,
    host: hosts.Host,
    repo: Path,
    log: loop_mod.RunLog,
    runs_dir: Path,
    say: Callable[[str], None] | None = None,
) -> loop_mod.UnattendedLoop:
    """Return the loop of :func:`build_loop`. Tests replace this function."""
    return build_loop(options, host, repo, log, runs_dir, say=say)


def _latest_run(runs_dir: Path) -> str | None:
    """Return the run ID in ``runs/LATEST`` for a dry run, or None (never raises)."""
    try:
        return ids.read_latest(runs_dir)
    except KalkanError:
        return None


# ---------------------------------------------------------------------------------------------
# Handler


def plugin_workdir(runs_dir: Path) -> Path:
    """Return the working directory of the plugin rounds: the runs root (see the module docs).

    Raises :class:`~kalkan.errors.KalkanError` when the folder is inside a ``.claude`` folder.
    """
    folder = runs_dir.expanduser()
    if not folder.is_absolute():
        folder = _cwd() / folder
    if any(part.casefold() == ".claude" for part in folder.parts):
        raise KalkanError(
            f"the runs folder {folder.as_posix()} is inside a .claude folder. Claude Code never "
            "lets a subagent write its result there. Set KALKAN_RUNS_DIR to another folder, "
            "for example ~/kalkan-runs."
        )
    return folder


def plugin_host(host: hosts.Host) -> hosts.Host:
    """Return a copy of the Claude Code host that sends the plugin skill ``/kalkan:kalkan``."""
    if not isinstance(host, hosts.ClaudeHost):
        raise KalkanError(f"the Claude Code plugin cannot run {host.name} rounds")
    return hosts.ClaudeHost(host.executable, local_tz=host.local_tz, skill=hosts.PLUGIN_SKILL)


def normalize_target(text: str, *, cwd: Path | None = None) -> str:
    """Return the target text for the first prompt.

    A git URL passes unchanged. A local folder becomes an absolute path with forward slashes.
    Raises :class:`~kalkan.errors.KalkanError` for an empty target, a forbidden character or a
    folder that does not exist.
    """
    value = text.strip()
    if not value:
        raise KalkanError("the target is empty")
    if _FORBIDDEN.search(value):
        raise KalkanError(
            'the target must not contain a double quote, a backtick, "$" or a control character'
        )
    if _URL.match(value):
        return value
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = (cwd or Path.cwd()) / path
    try:
        resolved = path.resolve()
    except OSError as exc:
        raise KalkanError(f"the target folder cannot be read: {exc}") from None
    if not resolved.is_dir():
        raise KalkanError(f"the target folder does not exist: {resolved.as_posix()}")
    folder = resolved.as_posix()
    if _FORBIDDEN.search(folder):
        raise KalkanError(
            'the target path must not contain a double quote, a backtick, "$" or a control '
            "character"
        )
    return folder


def _chosen_run(args: argparse.Namespace, resume: bool, command: str) -> str | None:
    """Return the run ID of ``devam <run-id>`` or ``--run <run-id>``, or None."""
    given = [value for value in (args.run_arg, args.run_id) if value is not None]
    if len(set(given)) > 1:
        raise KalkanError(f"two different run IDs: {given[0]} and {given[1]}. Give one.")
    run_id = given[0] if given else None
    if run_id is not None and not resume:
        raise KalkanError(
            f"a run ID works only with devam: {command} devam {run_id}. A target starts a new "
            "run with a new ID."
        )
    return run_id


@dataclass(frozen=True)
class Launch:
    """A checked unattended run that :func:`start` can begin (made by :func:`prepare`).

    ``workdir`` is the working directory of the rounds (the checkout, or the runs root of the
    plugin). ``round_argv`` is the command line of every round. ``shown_run`` is the bound run
    when it is known before the start (``devam <run-id>``; for a dry run also ``runs/LATEST``).
    """

    options: loop_mod.UnattendedOptions
    host: hosts.Host
    workdir: Path
    runs_dir: Path
    log_path: Path
    plugin: bool
    round_argv: list[str]
    shown_run: str | None


def prepare(
    *,
    target: str | None,
    run_id: str | None = None,
    profile: str | None = None,
    latest: bool = True,
    max_hours: float = loop_mod.DEFAULT_MAX_HOURS,
    round_hours: float = loop_mod.DEFAULT_ROUND_HOURS,
    host_name: str = "claude",
    log_dir: Path | None = None,
    dry_run: bool = False,
    command: str | None = None,
    plugin: bool | None = None,
    max_usd: float | None = None,
    lang: str = "en",
) -> Launch:
    """Check the options of an unattended run and return its :class:`Launch`.

    ``target`` None means ``devam``: ``run_id`` names the run, else the loop binds to the run in
    ``runs/LATEST`` at the start. ``command`` is the command that the stop messages name
    (default ``kalkan unattended``, or ``kalkan-unattended`` in the plugin). ``plugin`` None asks
    :func:`kalkan.resources.plugin_install`. Nothing is written. Raises
    :class:`~kalkan.errors.KalkanError` for a bad target or option and
    :class:`~kalkan.errors.ToolError` when the host program is missing (not for a dry run).
    """
    plugin = _plugin_install() if plugin is None else plugin
    if command is None:
        command = PLUGIN_COMMAND if plugin else loop_mod.DEFAULT_COMMAND
    if plugin and host_name != "claude":
        raise KalkanError(
            f"the Claude Code plugin runs only Claude Code rounds, not {host_name}. "
            "--host codex needs a kalkan checkout (docs/CODEX.md)."
        )
    normalized = None if target is None else normalize_target(target, cwd=_cwd())
    options = loop_mod.UnattendedOptions(
        target=normalized,
        profile=profile or loop_mod.DEFAULT_PROFILE,
        max_hours=max_hours,
        round_hours=round_hours,
        command=command,
        run_id=run_id,
        latest=latest,
        max_usd=max_usd,
        lang=lang,
    )
    runs_dir = _runs_root()
    workdir = plugin_workdir(runs_dir) if plugin else _repo_root()
    folder = log_dir.expanduser() if log_dir is not None else runs_dir
    if not folder.is_absolute():
        folder = _cwd() / folder
    log_path = folder / loop_mod.log_file_name(ids.utc_now())
    host = _create_host(host_name, require=not dry_run)
    if plugin:
        host = plugin_host(host)
    if (
        normalized is not None
        and _URL.match(normalized)
        and not getattr(host, "supports_git_urls", True)
    ):
        raise KalkanError(
            f"--host {host.name} takes only a local folder: {host.name} runs the engine in a "
            "sandbox without network, and $kalkan there cannot clone a git URL either. Clone "
            "the repository first, then give its local folder."
        )
    shown_run = run_id
    if shown_run is None and normalized is None and dry_run:
        shown_run = _latest_run(runs_dir)
    prompt = loop_mod.resume_prompt(shown_run or RUN_ID_PLACEHOLDER, host.skill)
    round_argv = host.build_command(prompt)  # checks the host and the prompt before anything
    return Launch(options, host, workdir, runs_dir, log_path, plugin, round_argv, shown_run)


def start(
    launch: Launch, *, say: Callable[[str], None] | None = None
) -> loop_mod.UnattendedResult | None:
    """Run the prepared loop to its end and return its result.

    In a checkout a Claude Code round needs a trusted folder (:class:`~kalkan.errors.KalkanError`
    otherwise); the plugin creates its runs root instead. ``say`` prints the progress messages
    (default: the ``kalkan unattended:`` prefix on stderr). Ctrl+C stops the round, prints the
    resume command and returns None.
    """
    tell = say or _say
    options, host = launch.options, launch.host
    if launch.plugin:
        launch.workdir.mkdir(parents=True, exist_ok=True)  # the working directory of the rounds
    elif host.name == "claude" and _workspace_trusted(launch.workdir) is False:
        raise KalkanError(
            "Claude Code does not trust this folder yet, so it ignores the project permissions "
            "and the subagents cannot write their results. Run `claude` in "
            f"{launch.workdir.as_posix()} once, accept the trust dialog, then start again."
        )
    with loop_mod.RunLog(launch.log_path).open() as log:
        tell(f"log: {launch.log_path.as_posix()}")
        unattended = _build_loop(options, host, launch.workdir, log, launch.runs_dir, say=say)
        try:
            return unattended.run()
        except KeyboardInterrupt:
            log.note("interrupted by the user")
            bound = unattended.run_id
            hint = loop_mod.resume_hint(
                options.command, host.name, bound, options.target, options.profile
            )
            if bound is None and options.target is not None:
                tell(f"interrupted before the run was created. Start again with: {hint}")
            else:
                tell(f"interrupted. The run is resumable. Resume with: {hint}")
            return None


def _cmd_unattended(args: argparse.Namespace) -> int:
    resume = args.target.strip().lower() in loop_mod.RESUME_WORDS
    plugin = _plugin_install()
    command = PLUGIN_COMMAND if plugin else loop_mod.DEFAULT_COMMAND
    run_id = _chosen_run(args, resume, command)
    if resume and args.profile is not None:
        _say("--profile has no effect with devam. The run keeps its profile.")
    if resume and args.no_latest:
        _say("--no-latest has no effect with devam. It applies only to a new run.")
    if resume and args.lang:
        _say("--lang has no effect with devam. The run keeps its language.")
    launch = prepare(
        target=None if resume else args.target,
        run_id=run_id,
        profile=args.profile,
        latest=not args.no_latest,
        max_hours=args.max_hours,
        round_hours=args.round_hours,
        host_name=args.host,
        log_dir=args.log_dir,
        dry_run=args.dry_run,
        command=command,
        plugin=plugin,
        max_usd=args.max_usd,
        lang=args.lang or "en",
    )
    if args.dry_run:
        return _dry_run(args, launch)
    result = start(launch)
    if result is None:
        return EXIT_ERROR
    _say(result.message)
    _say(f"log: {result.log_file}")
    if args.json:
        _print_json(result.to_dict())
    return result.exit_code


def _dry_run(args: argparse.Namespace, launch: Launch) -> int:
    """Print what a real run would do. ``launch.shown_run`` is the run of ``devam`` when known."""
    options, host, repo = launch.options, launch.host, launch.workdir
    log_path, round_argv, run_id = launch.log_path, launch.round_argv, launch.shown_run
    status_argv = loop_mod.status_command(run_id or RUN_ID_PLACEHOLDER)
    init_argv: list[str] | None = None
    if options.target is not None:
        init_argv = loop_mod.init_command(
            options.target, options.profile, latest=options.latest, lang=options.lang
        )
        run_text = f"new; run init creates it before the first round ({RUN_ID_PLACEHOLDER} below)"
    elif options.run_id is not None:
        run_text = options.run_id
    elif run_id is not None:
        run_text = f"{run_id} (from runs/LATEST, read once at the start)"
    else:
        run_text = "none: runs/LATEST names no run, so a real run stops"
    rounds: list[dict[str, Any]] = [
        {
            "when": "every round",
            "argv": round_argv,
            "command_line": loop_mod.format_command(round_argv),
        }
    ]
    install = "plugin" if launch.plugin else "checkout"
    if not Path(round_argv[0]).is_absolute():
        _say(f"{host.name} is not on PATH. A real run stops with an error.")
    init_line = loop_mod.format_command(init_argv) if init_argv is not None else None
    if args.json:
        _print_json(
            {
                "dry_run": True,
                "host": host.name,
                "install": install,
                "cwd": repo.as_posix(),
                "log_file": log_path.as_posix(),
                "max_hours": options.max_hours,
                "round_hours": options.round_hours,
                "max_usd": options.max_usd,
                "run_id": run_id,
                "init_argv": init_argv,
                "init_command_line": init_line,
                "rounds": rounds,
                "status_argv": status_argv,
                "status_command_line": loop_mod.format_command(status_argv),
            }
        )
        return EXIT_OK
    lines = [
        "kalkan unattended: dry run. Nothing starts.",
        f"install: {install}",
        f"working directory: {repo.as_posix()}",
        f"log file: {log_path.as_posix()}",
        f"run: {run_text}",
        *([f"run init: {init_line}"] if init_line is not None else []),
        *(f"{item['when']}: {item['command_line']}" for item in rounds),
        f"status after each round: {loop_mod.format_command(status_argv)}",
        f"limits: {options.max_hours:g} hours in total, {options.round_hours:g} hours per round"
        + (f", USD {options.max_usd:.2f} in total" if options.max_usd is not None else ""),
    ]
    _write_stdout("\n".join(lines) + "\n")
    return EXIT_OK


# ---------------------------------------------------------------------------------------------
# Output helpers


def _say(message: str) -> None:
    print(f"kalkan unattended: {message}", file=sys.stderr, flush=True)


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


def _print_json(obj: Any) -> None:
    _write_stdout(json.dumps(obj, ensure_ascii=False, indent=2) + "\n")
