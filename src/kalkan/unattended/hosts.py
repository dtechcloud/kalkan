# SPDX-License-Identifier: MIT
"""Host agent CLIs for unattended runs (docs/ENGINE-SPEC.md, section 22).

A host is the agent CLI that runs one round of the kalkan skill headless. The loop needs these
members from it (the :class:`Host` protocol):

- ``name``: the host name on the command line (``--host``).
- ``skill``: the skill prefix of a prompt: ``/kalkan`` (Claude Code in a checkout),
  ``/kalkan:kalkan`` (the Claude Code plugin, :data:`PLUGIN_SKILL`) or ``$kalkan`` (Codex).
- ``build_command(prompt)``: the argument list of one round. The loop starts it without a
  shell, from the repository root (the runs root for the plugin), with an empty stdin.
- ``parse_limit(lines, now=...)``: the usage limit in the output of a round, or None.
- ``parse_fatal(lines)``: a message when the output reports a limit that waiting cannot clear
  (for example depleted credits), or None.

:class:`ClaudeHost` implements Claude Code and :class:`CodexHost` the OpenAI Codex CLI
(``codex exec``, docs/CODEX.md). A new host adds a class with the same members and an entry in
:data:`HOSTS`.

**Trusted text only.** A limit parser reads only text that the host CLI writes itself. Model
text, tool calls and tool results can quote the audit target, which is untrusted data.

**Windows command shims.** An npm install gives ``claude.cmd`` or ``codex.cmd``. Windows starts
a ``.cmd`` file through ``cmd.exe`` even without a shell, and ``cmd.exe`` reads ``%``, ``!``,
``^``, ``&``, ``|``, ``<``, ``>``, ``(`` and ``)`` in the arguments. For such a shim,
:func:`check_prompt` refuses a prompt with one of these characters. A native executable has no
such limit. The Codex flags have no inner quotes for the same reason: Codex reads a bare
``-c key=value`` value as a TOML string.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Callable, Iterable, Sequence
from datetime import datetime, tzinfo
from pathlib import PurePath
from typing import Final, Protocol, runtime_checkable

from kalkan.errors import KalkanError, ToolError
from kalkan.tools.platform import Finder, find_on_path
from kalkan.unattended import limits
from kalkan.unattended.limits import LimitInfo

__all__ = [
    "CLAUDE_FLAGS",
    "CODEX_FLAGS",
    "HOSTS",
    "PLUGIN_SKILL",
    "ClaudeHost",
    "CodexHost",
    "Host",
    "check_prompt",
    "codex_messages",
    "create_host",
    "host_names",
]

#: The fixed flags of one Claude Code round, after ``-p "<prompt>"``.
CLAUDE_FLAGS: Final = (
    "--permission-mode",
    "dontAsk",
    "--output-format",
    "stream-json",
    "--verbose",
)
#: The skill of the Claude Code plugin (``<plugin>:<skill>``). Unlike the bare ``/kalkan``, it
#: never starts another skill of the same name, for example the one of a kalkan checkout.
PLUGIN_SKILL: Final = "/kalkan:kalkan"
#: The fixed flags of one Codex round, after ``exec``. The prompt follows them.
CODEX_FLAGS: Final = (
    "--sandbox",
    "workspace-write",
    "-c",
    "approval_policy=never",
    "-c",
    "sandbox_workspace_write.network_access=false",
    "-c",
    "web_search=disabled",
    "--json",
)
#: Codex messages about limits that waiting cannot clear (depleted credits, a spend cap).
_CODEX_STOP: Final = re.compile(r"\bout\s+of\s+credits\b|\bspend(?:ing)?\s+cap\b", re.IGNORECASE)
_CODEX_HINTS: Final = ("error", "turn.failed")
_MAX_LINE_CHARS: Final = 4_000_000
_MAX_PROMPT_CHARS: Final = 4000
_CONTROL: Final = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029]")
_SHIM_SUFFIXES: Final = frozenset({".cmd", ".bat"})
_CMD_METACHARACTERS: Final = frozenset("%!^&|<>()")


@runtime_checkable
class Host(Protocol):
    """An agent CLI that runs one headless round of the kalkan skill."""

    name: str
    skill: str

    def build_command(self, prompt: str) -> list[str]:
        """Return the argument list of one round."""
        ...

    def parse_limit(self, lines: Sequence[str], *, now: datetime | None = None) -> LimitInfo | None:
        """Return the usage limit that the round output reports, or None."""
        ...

    def parse_fatal(self, lines: Sequence[str]) -> str | None:
        """Return a message when the output reports a limit that waiting cannot clear."""
        ...


def check_prompt(prompt: str, executable: str = "") -> None:
    """Raise :class:`~kalkan.errors.KalkanError` when ``prompt`` is not safe as one argument.

    A prompt must not be empty, must not start with ``-`` (it would read as a flag) and must not
    contain control characters. For a Windows ``.cmd`` or ``.bat`` executable it must not
    contain characters that ``cmd.exe`` interprets (see the module docs).
    """
    if not prompt or len(prompt) > _MAX_PROMPT_CHARS:
        raise KalkanError(f"the prompt must have 1 to {_MAX_PROMPT_CHARS} characters")
    if prompt.startswith("-"):
        raise KalkanError("the prompt must not start with '-'")
    if _CONTROL.search(prompt):
        raise KalkanError("the prompt must not contain control characters")
    program = PurePath(executable)
    if program.suffix.lower() in _SHIM_SUFFIXES:
        bad = sorted(set(prompt) & _CMD_METACHARACTERS)
        if bad:
            raise ToolError(
                f"{program.name} is a cmd.exe script, and the prompt contains "
                f"{' '.join(bad)}. cmd.exe would interpret these characters. Use a target "
                f"path without them, or install a native {program.stem} executable."
            )


class ClaudeHost:
    """Claude Code. One round is
    ``claude -p "<prompt>" --permission-mode dontAsk --output-format stream-json --verbose``.

    ``executable`` is the program to start: an absolute path from :func:`create_host`, or the
    bare name ``claude`` for a dry run. ``local_tz`` replaces the local time zone when the limit
    parser resolves a reset time without a zone (tests use it). ``skill`` replaces the skill
    prefix: :data:`PLUGIN_SKILL` for the plugin.
    """

    name: str = "claude"
    skill: str = "/kalkan"
    #: The engine runs outside a sandbox under Claude Code, so ``run init`` can clone a URL.
    supports_git_urls: bool = True

    def __init__(
        self,
        executable: str | os.PathLike[str] = "claude",
        *,
        local_tz: tzinfo | None = None,
        skill: str | None = None,
    ) -> None:
        self.executable = os.fspath(executable)
        self.local_tz = local_tz
        if skill is not None:
            self.skill = skill

    def __repr__(self) -> str:
        return f"ClaudeHost(executable={self.executable!r}, skill={self.skill!r})"

    def build_command(self, prompt: str) -> list[str]:
        """Return ``[claude, "-p", prompt, "--permission-mode", "dontAsk", ...]``."""
        check_prompt(prompt, self.executable)
        return [self.executable, "-p", prompt, *CLAUDE_FLAGS]

    def parse_limit(self, lines: Sequence[str], *, now: datetime | None = None) -> LimitInfo | None:
        """Return the usage limit in the stream-json output of a round, or None."""
        return limits.parse_limit(lines, now=now, local_tz=self.local_tz)

    def parse_fatal(self, lines: Sequence[str]) -> str | None:
        """Return None: kalkan knows no Claude Code limit that waiting cannot clear."""
        return None

    def budget_args(self, usd: float) -> list[str]:
        """Return the flags that cap the estimated cost of one round (``--max-budget-usd``,
        Claude Code 2.1.217 or later). The loop passes the rest of ``--max-usd``."""
        return ["--max-budget-usd", f"{max(usd, 0.01):.2f}"]


def codex_messages(lines: Iterable[str]) -> list[str]:
    """Return the messages that Codex itself wrote in the output of ``codex exec --json``.

    These are the ``message`` of ``error`` events, the ``error.message`` of ``turn.failed``
    events and plain-text lines (stderr). Every ``item.*`` event is skipped: ``agent_message``,
    ``reasoning``, ``command_execution`` and the other items can quote the audit target. A line
    that starts with ``{`` but does not parse is skipped.
    """
    messages: list[str] = []
    for raw in lines:
        if not isinstance(raw, str):
            continue
        line = raw.strip()
        if not line or len(line) > _MAX_LINE_CHARS:
            continue
        if not line.startswith("{"):
            messages.append(line)
            continue
        if not any(hint in line for hint in _CODEX_HINTS):
            continue
        try:
            event = json.loads(line)
        except (ValueError, RecursionError):
            continue
        if not isinstance(event, dict):
            continue
        kind = event.get("type")
        if kind == "error" and isinstance(event.get("message"), str):
            messages.append(event["message"])
        elif kind == "turn.failed":
            error = event.get("error")
            if isinstance(error, dict) and isinstance(error.get("message"), str):
                messages.append(error["message"])
            elif isinstance(error, str):
                messages.append(error)
    return messages


class CodexHost:
    """OpenAI Codex CLI. One round is ``codex exec --sandbox workspace-write
    -c approval_policy=never -c sandbox_workspace_write.network_access=false
    -c web_search=disabled --json "<prompt>"`` (docs/CODEX.md).

    Codex writes a usage limit as text, for example ``You've hit your usage limit. ... Try again
    at 3:45 PM.`` or ``Try again at Oct 17th, 2026 9:05 AM.``, in the local time zone. Its
    JSON stream has no rate-limit event. ``Try again later.`` has no time, so the loop backs
    off. A depleted-credits or spend-cap message stops the loop (:meth:`parse_fatal`).
    """

    name: str = "codex"
    skill: str = "$kalkan"
    #: ``$kalkan`` runs the engine in the Codex sandbox without network, so its ``run init``
    #: cannot clone a URL. ``kalkan unattended --host codex`` keeps the same rule.
    supports_git_urls: bool = False

    def __init__(
        self, executable: str | os.PathLike[str] = "codex", *, local_tz: tzinfo | None = None
    ) -> None:
        self.executable = os.fspath(executable)
        self.local_tz = local_tz

    def __repr__(self) -> str:
        return f"CodexHost(executable={self.executable!r})"

    def build_command(self, prompt: str) -> list[str]:
        """Return ``[codex, "exec", "--sandbox", "workspace-write", ..., "--json", prompt]``."""
        check_prompt(prompt, self.executable)
        return [self.executable, "exec", *CODEX_FLAGS, prompt]

    def parse_limit(self, lines: Sequence[str], *, now: datetime | None = None) -> LimitInfo | None:
        """Return the usage limit in the messages of :func:`codex_messages`, or None."""
        return limits.parse_limit_text(codex_messages(lines), now=now, local_tz=self.local_tz)

    def parse_fatal(self, lines: Sequence[str]) -> str | None:
        """Return the first depleted-credits or spend-cap message, or None."""
        for message in codex_messages(lines):
            if _CODEX_STOP.search(message):
                return limits.printable(message, 300)
        return None


def _claude(finder: Finder, require: bool) -> Host:
    found = finder("claude")
    if found is None:
        if require:
            raise ToolError(
                "claude (the Claude Code CLI) is not on PATH. Install Claude Code, log in, "
                "then run: kalkan doctor"
            )
        return ClaudeHost("claude")
    return ClaudeHost(found)


def _codex(finder: Finder, require: bool) -> Host:
    found = finder("codex")
    if found is None:
        if require:
            raise ToolError(
                "codex (the OpenAI Codex CLI) is not on PATH. Install the Codex CLI, log in "
                "with: codex login, then run: kalkan doctor"
            )
        return CodexHost("codex")
    return CodexHost(found)


#: Host name -> factory(finder, require). ``require=False`` gives a host with the bare program
#: name when the program is not on PATH (for ``--dry-run``).
HOSTS: Final[dict[str, Callable[[Finder, bool], Host]]] = {"claude": _claude, "codex": _codex}


def host_names() -> list[str]:
    """Return the known host names, sorted."""
    return sorted(HOSTS)


def create_host(name: str, *, finder: Finder | None = None, require: bool = True) -> Host:
    """Return the host ``name`` with its program resolved on PATH.

    PATH lookup never searches the current folder (:func:`kalkan.tools.platform.find_on_path`).
    Raises :class:`~kalkan.errors.ToolError` when ``require`` is true and the program is not
    on PATH, and :class:`~kalkan.errors.KalkanError` for an unknown host name.
    """
    factory = HOSTS.get(name)
    if factory is None:
        raise KalkanError(f"unknown host {name!r} (known hosts: {', '.join(host_names())})")
    return factory(finder or find_on_path, require)
