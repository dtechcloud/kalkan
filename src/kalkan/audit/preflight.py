# SPDX-License-Identifier: MIT
"""Setup checks of ``kalkan audit`` (docs/ENGINE-SPEC.md, section 25).

1. :func:`run_checks` runs ``kalkan doctor`` (:func:`kalkan.tools.doctor.run_doctor`) without the
   checks that the audit does not need: never Docker or Node.js; Claude Code only in agent mode;
   the tools and the vulnerability databases only while the run still has scanner work.
2. :func:`evaluate` sorts the doctor rows into a :class:`Preflight`:

   - ``tools``: every ``tool:<name>`` row with the status ``fail`` (missing, broken, wrong
     version, no Go). The manifest drives these rows, so a new tool needs no change here.
   - ``databases``: the ``vulndb`` row when a local vulnerability database is missing (OSV for a
     default ecosystem, Grype or Go). ``stale``: all databases exist but are older than
     :data:`kalkan.sca.vulndb.STALE_DAYS` days; only a warning.
   - ``claude`` (agent mode): the Claude Code CLI is missing, does not run, or is not signed in.
   - ``trust`` (agent mode, checkout): Claude Code does not trust the checkout.
   - ``fatal``: every other ``fail`` row (Python, manifest, data folders, runs folder). No
     setup command fixes it.
   - ``warnings``: the other ``warn`` rows (git, disk space, ``claude -p`` options).

3. The command acts on it (:mod:`kalkan.audit.commands`): ``fatal`` and ``trust`` stop with exit
   code 1; ``claude`` stops with exit code 5. Missing tools or databases need consent: ``--yes``,
   or ``y`` to the question of :func:`ask_yes_no` when stdin is a terminal. Then
   :func:`run_setup` runs the commands of :func:`setup_commands` (``kalkan tools install --all``
   for tools, ``kalkan sca update-db --max-age 168`` for databases: it downloads the missing
   ones and keeps every database younger than the stale limit) as child processes of this
   Python, and the checks run again. Without consent the command prints :func:`fix_lines` and
   stops with exit code 5. Nothing is ever installed without consent.
"""

from __future__ import annotations

import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final, TextIO

from kalkan.sca.vulndb import SETUP_MAX_AGE_HOURS
from kalkan.tools.doctor import STATUS_FAIL, STATUS_OK, STATUS_WARN, DoctorReport

__all__ = [
    "DATABASES_COMMAND",
    "SETUP_TIMEOUT_SECONDS",
    "TOOLS_COMMAND",
    "YES_ANSWERS",
    "Preflight",
    "Problem",
    "SetupStep",
    "ask_yes_no",
    "describe",
    "evaluate",
    "fix_lines",
    "run_checks",
    "run_setup",
    "setup_commands",
]

#: The engine arguments that install every missing or damaged pinned tool.
TOOLS_COMMAND: Final = ("tools", "install", "--all")
#: The engine arguments that download the missing local vulnerability databases (network). A
#: database younger than the stale limit of ``kalkan doctor`` is kept (``--max-age``).
DATABASES_COMMAND: Final = ("sca", "update-db", "--max-age", str(SETUP_MAX_AGE_HOURS))
#: The time limit of one setup command. The downloads of a first setup took 5 to 15 minutes.
SETUP_TIMEOUT_SECONDS: Final = 3 * 3600.0
#: Answers that count as yes (English and Turkish, as ``run answer`` accepts them).
YES_ANSWERS: Final = frozenset({"y", "yes", "e", "evet"})

_TRUST_CHECK: Final = "unattended:workspace-trust"
_SHOWN_WARNINGS: Final = frozenset({"git", "disk", "platform", "unattended:print-mode"})


@dataclass(frozen=True)
class Problem:
    """One doctor row that the audit reports: the check name and its detail (with the fix)."""

    check: str
    detail: str

    def to_dict(self) -> dict[str, str]:
        """Return a JSON-ready dict."""
        return {"check": self.check, "detail": self.detail}


@dataclass(frozen=True)
class Preflight:
    """The doctor rows that matter for one audit (see the module docstring)."""

    tools: tuple[Problem, ...] = ()
    databases: Problem | None = None
    stale: Problem | None = None
    claude: Problem | None = None
    trust: Problem | None = None
    fatal: tuple[Problem, ...] = ()
    warnings: tuple[Problem, ...] = ()

    @property
    def needs_setup(self) -> bool:
        """True when a setup command can fix a problem (missing tools or databases)."""
        return bool(self.tools or self.databases)

    @property
    def tool_names(self) -> list[str]:
        """The names of the failing tools (``tool:<name>`` without the prefix)."""
        return [problem.check.removeprefix("tool:") for problem in self.tools]

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-ready dict."""
        single = {
            "databases": self.databases,
            "stale": self.stale,
            "claude": self.claude,
            "trust": self.trust,
        }
        return {
            "tools": [problem.to_dict() for problem in self.tools],
            **{key: value.to_dict() if value else None for key, value in single.items()},
            "fatal": [problem.to_dict() for problem in self.fatal],
            "warnings": [problem.to_dict() for problem in self.warnings],
        }


@dataclass(frozen=True)
class SetupStep:
    """One setup command that :func:`run_setup` ran, and its exit code."""

    arguments: tuple[str, ...]
    exit_code: int | None
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.exit_code == 0

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-ready dict."""
        return {"command": ["kalkan", *self.arguments], "exit_code": self.exit_code} | (
            {"error": self.error} if self.error else {}
        )


Doctor = Callable[..., DoctorReport]


def run_checks(
    *, agents: bool, tools: bool = True, doctor: Doctor | None = None, **kwargs: Any
) -> DoctorReport:
    """Run the doctor checks that one audit needs (see the module docstring).

    ``agents`` keeps the Claude Code checks, ``tools`` the tool and database checks. ``doctor``
    replaces :func:`kalkan.tools.doctor.run_doctor` (tests); ``kwargs`` go to it.
    """
    if doctor is None:
        from kalkan.tools.doctor import run_doctor as doctor
    skip = {"docker", "node"}
    if not agents:
        skip.add("claude")
    if not tools:
        skip.add("tools")
    return doctor(skip=frozenset(skip), **kwargs)


def _databases_missing(data: Mapping[str, Any]) -> bool:
    """True when the ``vulndb`` data misses a database (not only an old one)."""
    from kalkan.sca.vulndb import DEFAULT_ECOSYSTEMS

    ecosystems = data.get("osv_ecosystems")
    found = set(ecosystems) if isinstance(ecosystems, list) else set()
    return (
        any(name not in found for name in DEFAULT_ECOSYSTEMS)
        or not data.get("grype")
        or data.get("go") is None
    )


def evaluate(report: DoctorReport, *, agents: bool) -> Preflight:
    """Sort the rows of ``report`` into a :class:`Preflight` (see the module docstring)."""
    tools: list[Problem] = []
    fatal: list[Problem] = []
    warnings: list[Problem] = []
    databases = stale = claude = trust = None
    for check in report.checks:
        problem = Problem(check.name, check.detail)
        if check.name.startswith("tool:"):
            if check.status == STATUS_FAIL:
                tools.append(problem)
            elif check.status == STATUS_WARN:
                warnings.append(problem)
        elif check.name == "vulndb":
            if check.status != STATUS_OK and _databases_missing(check.data):
                databases = problem
            elif check.status != STATUS_OK:
                stale = problem
        elif check.name == "claude":
            if agents and check.status != STATUS_OK:
                claude = problem
        elif check.name == _TRUST_CHECK:
            if agents and check.status == STATUS_WARN:
                folder = check.data.get("repo")  # "this folder" is the checkout, not the cwd
                trust = Problem(
                    check.name, f"{check.detail} Folder: {folder}" if folder else problem.detail
                )
        elif check.status == STATUS_FAIL:
            fatal.append(problem)
        elif check.status == STATUS_WARN and check.name in _SHOWN_WARNINGS:
            warnings.append(problem)
    return Preflight(
        tools=tuple(tools),
        databases=databases,
        stale=stale,
        claude=claude,
        trust=trust,
        fatal=tuple(fatal),
        warnings=tuple(warnings),
    )


def setup_commands(preflight: Preflight) -> list[tuple[str, ...]]:
    """Return the engine arguments of the setup commands that fix ``preflight``, in order."""
    commands: list[tuple[str, ...]] = []
    if preflight.tools:
        commands.append(TOOLS_COMMAND)
    if preflight.databases is not None:
        commands.append(DATABASES_COMMAND)
    return commands


def describe(preflight: Preflight) -> list[str]:
    """Return one line per problem that a setup fixes (for the question and the stop message)."""
    lines: list[str] = []
    if preflight.tools:
        names = preflight.tool_names
        noun = "tool is" if len(names) == 1 else "tools are"
        lines.append(f"{len(names)} pinned {noun} missing or broken: {', '.join(names)}")
    if preflight.databases is not None:
        lines.append(f"local vulnerability databases: {preflight.databases.detail}")
    return lines


def fix_lines(preflight: Preflight, *, engine: str, retry: str) -> list[str]:
    """Return the stop message of a setup without consent: the fix commands (``engine`` is
    the engine command, :func:`kalkan.resources.engine_command`) and ``retry``, the audit
    command with ``--yes``. The caller printed the problems (:func:`describe`) before."""
    lines = ["Fix it with these commands, then start the audit again:"]
    lines.extend(f"  {engine} {' '.join(arguments)}" for arguments in setup_commands(preflight))
    lines.append(f"Or let the audit install them first: {retry}")
    return lines


def ask_yes_no(question: str, *, stdin: TextIO | None = None, stderr: TextIO | None = None) -> bool:
    """Ask ``question`` on stderr and read one answer line from stdin. Only ``y``, ``yes``,
    ``e`` or ``evet`` (any case) is a yes; an empty line or the end of the input is a no."""
    out = stderr or sys.stderr
    source = stdin or sys.stdin
    out.write(f"{question} [y/N] ")
    out.flush()
    try:
        answer = source.readline()
    except (OSError, ValueError):
        answer = ""
    if not answer.endswith("\n"):  # the end of the input: finish the question line
        out.write("\n")
        out.flush()
    return answer.strip().casefold() in YES_ANSWERS


Runner = Callable[..., "subprocess.CompletedProcess[Any]"]


def run_setup(
    commands: Sequence[tuple[str, ...]],
    *,
    say: Callable[[str], None],
    runner: Runner | None = None,
    python: str | None = None,
) -> list[SetupStep]:
    """Run each setup command as ``<python> -m kalkan <arguments>`` and return the steps.

    The child processes write their progress to the stderr of this process (file descriptor 2),
    so that the stdout of ``kalkan audit --json`` stays one JSON document. A failed command does
    not stop the next one: the checks after the setup show what is still missing. ``runner``
    replaces :func:`subprocess.run` (tests).
    """
    run = runner or subprocess.run
    steps: list[SetupStep] = []
    for arguments in commands:
        say(f"setup: kalkan {' '.join(arguments)}")
        argv = [python or sys.executable, "-m", "kalkan", *arguments]
        try:
            proc = run(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=2,
                stderr=2,
                timeout=SETUP_TIMEOUT_SECONDS,
                check=False,
                shell=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            steps.append(SetupStep(tuple(arguments), None, str(exc)))
            say(f"setup: kalkan {' '.join(arguments)} did not run: {exc}")
            continue
        steps.append(SetupStep(tuple(arguments), proc.returncode))
        if proc.returncode != 0:
            say(f"setup: kalkan {' '.join(arguments)} ended with exit code {proc.returncode}")
    return steps
