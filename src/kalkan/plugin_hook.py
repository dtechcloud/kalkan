# SPDX-License-Identifier: MIT
"""PreToolUse hook of the kalkan Claude Code plugin (docs/PLUGIN.md, docs/SECURITY.md,
docs/ENGINE-SPEC.md 24).

A plugin cannot ship permission rules. This hook gives the decisions that the project
``.claude/settings.json`` gives in a checkout, and it confines the kalkan subagents.

**kalkan subagents** (``agent_type`` starts with ``kalkan:``): every call gets ``allow`` or
``deny``, never the normal flow.

- ``Read``, ``Grep``, ``Glob``: ``allow`` only inside ``<runs>/<run-id>/target/`` or
  ``<runs>/<run-id>/tasks/``. The first Read of ``tasks/<task-id>/prompt.md`` binds the agent
  (``agent_id``) to that run and task (``<data>/hook/agents/<agent_id>.json``); later reads must
  stay in that run. A ``.env`` or ``.env.*`` file gets ``deny``. One more ``Read`` is allowed:
  a saved output of a tool call of the same session (:func:`is_own_tool_result`). Claude Code
  saves a large tool output as ``<config>/projects/<project>/<session>/tool-results/<name>.txt``
  and tells the agent to read it; without this the agent repeats the search in smaller pieces
  and runs out of turns (a coverage critic died at its turn limit on 2026-10-29).
- ``Write``: ``allow`` only for ``<runs>/<run-id>/tasks/<task-id>/result.json`` of the bound
  task, in an existing task folder that is not a link.
- Every other tool (Bash, PowerShell, Edit, NotebookEdit, WebFetch, WebSearch, every MCP tool,
  Agent, ...): ``deny``.

Paths are compared after ``\\`` to ``/``, MSYS drive (``/c/Users``) and, on Windows, case
folding; relative paths are joined to the event ``cwd``; ``os.path.realpath`` resolves ``..``,
symlinks, junctions and 8.3 short names (on the platform that runs the hook).

**Other calls** (the main session and other agents):

- ``Bash``: ``allow`` for one kalkan engine command, ``<data>/venv/Scripts/kalkan.exe``
  (Windows) or ``<data>/venv/bin/kalkan`` plus arguments, or the setup command
  ``sh <plugin root>/bin/kalkan-setup <data>``, without a shell operator (``;``, ``&``, ``|``,
  ``<``, ``>``, parentheses), ``$``, backtick or line break. The skill names its run in every
  engine command (``--run <run-id>``); a run ID holds only letters, digits and ``-``, so it
  passes these checks. The engine command also marks the session as an active kalkan
  orchestration: ``<data>/hook/sessions/<session_id>.json``, with the run of its ``--run``.
- While a session is marked, its network tools get ``deny``: WebFetch, WebSearch, every MCP
  tool, and Bash or PowerShell commands that name a network program, a URL or a git transfer
  (:func:`is_network_command`). A marker ends when the run reaches the phase ``done`` or
  :data:`SESSION_TTL_SECONDS` after the last engine command.
- ``Read``, ``Grep``, ``Glob``: ``allow`` inside the data folder or the runs root; a ``.env``
  file there gets ``deny``. While a session is marked, its ``Read`` of a saved output of its
  own tool calls gets ``allow`` too (:func:`is_own_tool_result`).
- Everything else gets no output, so the normal permission flow decides. Other sessions are
  never denied anything.

A deny rule of the user still wins over ``allow``. Claude Code never lets a hook approve a write
below a ``.claude`` folder, so the plugin keeps its runs in ``~/kalkan-runs``.

``<data>`` is ``CLAUDE_PLUGIN_DATA``. The runs root follows the engine
(:func:`kalkan.resources.runs_root`). Run as ``python -I -m kalkan.plugin_hook`` with the hook
input JSON on stdin. With ``KALKAN_HOOK_LOG`` set, the hook appends each input and decision to
that file. The hook never fails a tool call: on any internal error it prints nothing.
"""

from __future__ import annotations

import contextlib
import json
import ntpath
import os
import posixpath
import re
import shlex
import stat
import sys
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Final

__all__ = [
    "AGENT_NAMES",
    "PLUGIN_NAME",
    "SESSION_TTL_SECONDS",
    "canonical",
    "decide",
    "is_kalkan_agent",
    "is_network_command",
    "is_own_tool_result",
    "main",
    "normalize",
]

PLUGIN_NAME: Final = "kalkan"
#: The subagents of the plugin (``kalkan.run.queue.AGENTS`` values; a test keeps them equal).
AGENT_NAMES: Final = frozenset(
    {
        "kalkan-recon",
        "kalkan-hunter",
        "kalkan-critic",
        "kalkan-verifier",
        "kalkan-reviewer",
        "kalkan-consolidator",
        "kalkan-polisher",
        "kalkan-sca-reach",
        "kalkan-poc-builder",
        "kalkan-translator",
    }
)
READ_TOOLS: Final = frozenset({"Read", "Grep", "Glob"})
SHELL_TOOLS: Final = frozenset({"Bash", "PowerShell"})
WEB_TOOLS: Final = frozenset({"WebFetch", "WebSearch"})
ENV_DATA: Final = "CLAUDE_PLUGIN_DATA"
ENV_ROOT: Final = "CLAUDE_PLUGIN_ROOT"
ENV_LOG: Final = "KALKAN_HOOK_LOG"
#: The Claude Code configuration folder (default ``~/.claude``); its ``projects`` folder holds the
#: saved tool outputs of each session.
ENV_CONFIG: Final = "CLAUDE_CONFIG_DIR"
TOOL_RESULTS_DIR: Final = "tool-results"
#: A session marker ends this long after the last engine command of the session.
SESSION_TTL_SECONDS: Final = 6 * 3600
#: Agent bindings older than this are removed when a new one is written.
BINDING_TTL_SECONDS: Final = 3 * 24 * 3600
SESSIONS_DIR: Final = ("hook", "sessions")
AGENTS_DIR: Final = ("hook", "agents")
#: The run folders that a kalkan subagent may read.
READ_AREAS: Final = frozenset({"target", "tasks"})

# Copies of kalkan.run.ids.RUN_ID_PATTERN and kalkan.run.state.TASK_ID_PATTERN (a test keeps
# them equal). Importing those modules would slow down every hook call.
_RUN_ID: Final = re.compile(
    r"\A[0-9]{8}T[0-9]{6}Z-[a-z0-9](?:[a-z0-9-]{0,22}[a-z0-9])?-[0-9a-f]{4}\Z"
)
_TASK_ID: Final = re.compile(
    r"\AT([0-9]{4,})-(recon|hunt|critic|verify|review|consolidate|polish|sca_reach|poc_build"
    r"|translate)\Z"
)
_FORBIDDEN: Final = re.compile(r"[;&|<>()`$\n\r\x00]")
_MSYS_DRIVE: Final = re.compile(r"\A/([A-Za-z])(?=/|\Z)")
_ENV_FILE: Final = re.compile(r"\A\.env(?:\..*)?\Z", re.IGNORECASE)
_SAFE_ID: Final = re.compile(r"\A[A-Za-z0-9_-][A-Za-z0-9._-]{0,127}\Z")
#: The file name of a saved tool output (Claude Code writes ``toolu_<id>.txt``).
_TOOL_RESULT_NAME: Final = re.compile(r"\A[A-Za-z0-9_-]{1,128}\.txt\Z")
_STATE_MAX_BYTES: Final = 16 * 1024 * 1024

_NET_PROGRAM: Final = re.compile(
    r"(?i)(?:^|[\s;&|(`'\"/\\])"
    r"(?:curl|wget|nc|ncat|netcat|socat|telnet|ssh|scp|sftp|ftp|tftp|rsync|aria2c|"
    r"invoke-webrequest|invoke-restmethod|iwr|irm|start-bitstransfer|bitsadmin|certutil|"
    r"new-object\s+(?:system\.)?net\.webclient)"
    r"(?:\.exe)?(?=$|[\s;&|)`'\"])"
)
_NET_URL: Final = re.compile(r"(?i)\b(?:https?|ftps?|wss?|sftp)://")
_NET_GIT: Final = re.compile(
    r"(?i)\bgit(?:\.exe)?(?:\s+-\S+(?:\s+\S+)?)*\s+"
    r"(?:push|pull|fetch|clone|ls-remote|archive\s+--remote|remote\s+update|submodule\s+update)\b"
)
_NET_PACKAGES: Final = re.compile(
    r"(?i)\b(?:pip3?|pipx|uv|npm|npx|pnpm|yarn|bun|gem|bundle|cargo|go|composer|dotnet|nuget)"
    r"\s+(?:install|add|get|download|update|upgrade|fetch|restore|sync|exec|dlx)\b"
)


# ---------------------------------------------------------------------------------------------
# Paths


def normalize(path: str, *, windows: bool | None = None) -> str:
    """Return ``path`` with forward slashes, no ``.`` or empty segments and no trailing slash.

    For command tokens (no file system access). On Windows, an MSYS path ``/c/Users`` becomes
    ``c:/Users`` and the text is case-folded. A path with a ``..`` segment gives an empty
    string (never equal to an allowed path).
    """
    win = os.name == "nt" if windows is None else windows
    text = path.replace("\\", "/") if win else path
    if win:
        text = _MSYS_DRIVE.sub(lambda m: m.group(1) + ":", text)
    absolute = text.startswith("/")
    parts = [part for part in text.split("/") if part not in ("", ".")]
    if ".." in parts:
        return ""
    joined = "/".join(parts)
    if absolute:
        joined = "/" + joined
    return joined.casefold() if win else joined


def canonical(path: object, *, cwd: object = None, windows: bool | None = None) -> str | None:
    """Return the resolved absolute form of ``path`` with forward slashes, or None.

    A relative path is joined to ``cwd`` (None without a ``cwd``). On the platform that runs
    the hook, :func:`os.path.realpath` resolves ``..``, symlinks, junctions and 8.3 names; for
    the other platform (tests) the path is only normalized. The case is kept; compare with
    :func:`_fold`.
    """
    win = os.name == "nt" if windows is None else windows
    if not isinstance(path, str) or not path.strip() or "\x00" in path:
        return None
    text = path.strip()
    if win:
        text = _MSYS_DRIVE.sub(lambda m: m.group(1) + ":", text.replace("\\", "/"))
    flavor = ntpath if win else posixpath
    if not flavor.isabs(text):
        base = canonical(cwd, windows=win) if cwd is not None else None
        if base is None:
            return None
        text = flavor.join(base, text)
    try:
        if win == (os.name == "nt"):
            resolved = os.path.realpath(text)
        else:
            resolved = flavor.normpath(text)
    except (OSError, ValueError):
        return None
    return resolved.replace("\\", "/") if win else resolved


def _fold(path: str, windows: bool) -> str:
    return path.casefold().rstrip("/") if windows else path.rstrip("/")


def _relative_parts(path: str, folder: str, windows: bool) -> list[str] | None:
    """Return the parts of ``path`` below ``folder`` (both canonical), or None outside it."""
    child = [part for part in path.split("/") if part]
    parent = [part for part in folder.split("/") if part]
    if not parent or len(child) < len(parent):
        return None
    if any(_fold(a, windows) != _fold(b, windows) for a, b in zip(child, parent, strict=False)):
        return None
    if folder.startswith("/") != path.startswith("/"):
        return None
    return child[len(parent) :]


def _inside(path: object, folder: str, *, windows: bool, cwd: object = None) -> bool:
    child = canonical(path, cwd=cwd, windows=windows)
    parent = canonical(folder, windows=windows)
    return (
        child is not None
        and parent is not None
        and (_relative_parts(child, parent, windows) is not None)
    )


def _config_root() -> str:
    override = os.environ.get(ENV_CONFIG)
    return override if override else str(Path.home() / ".claude")


def is_own_tool_result(
    path: object,
    session_id: object,
    *,
    windows: bool | None = None,
    cwd: object = None,
    config: str | None = None,
) -> bool:
    """Return True when ``path`` is a saved output of a tool call of the session ``session_id``:
    ``<config>/projects/<project>/<session_id>/tool-results/<name>.txt``, a regular file.

    Claude Code writes a large tool output there and tells the agent to read it. The content is
    the output of a call that the hook already decided on. :func:`canonical` resolves links and
    ``..`` first, so a link cannot send the read anywhere else, and another session's outputs
    stay closed. ``config`` replaces the Claude Code configuration folder (tests).
    """
    win = os.name == "nt" if windows is None else windows
    if not isinstance(session_id, str) or not _SAFE_ID.fullmatch(session_id):
        return False
    child = canonical(path, cwd=cwd, windows=win)
    projects = canonical(f"{config or _config_root()}/projects", windows=win)
    if child is None or projects is None:
        return False
    rest = _relative_parts(child, projects, win)
    if rest is None or len(rest) != 4:
        return False
    _project, session, folder, name = rest
    if _fold(session, win) != _fold(session_id, win) or _fold(folder, win) != TOOL_RESULTS_DIR:
        return False
    if not _TOOL_RESULT_NAME.fullmatch(name):
        return False
    try:
        info = os.lstat(child)
    except (OSError, ValueError):
        return False
    return stat.S_ISREG(info.st_mode)


# ---------------------------------------------------------------------------------------------
# Event helpers


def is_kalkan_agent(event: Mapping[str, Any]) -> bool:
    """Return True when the call comes from a subagent of the kalkan plugin: ``agent_type``
    starts with ``kalkan:`` (Claude Code names plugin agents ``<plugin>:<agent>``)."""
    agent = event.get("agent_type")
    return isinstance(agent, str) and agent.startswith(PLUGIN_NAME + ":")


def is_network_command(command: object) -> bool:
    """Return True when a shell command names a network program, a URL, a git transfer or a
    package download. A heuristic: an interpreter can still reach the network without one of
    these words (docs/SECURITY.md, residual risks)."""
    if not isinstance(command, str):
        return False
    return any(
        pattern.search(command) for pattern in (_NET_PROGRAM, _NET_URL, _NET_GIT, _NET_PACKAGES)
    )


def _split(command: str) -> list[str] | None:
    if _FORBIDDEN.search(command):
        return None
    try:
        return shlex.split(command, posix=True)
    except ValueError:
        return None


def _engine_paths(data: str) -> list[str]:
    return [
        f"{data}/venv/Scripts/kalkan.exe",
        f"{data}/venv/Scripts/kalkan",
        f"{data}/venv/bin/kalkan",
    ]


def _engine_tokens(command: object, data: str, root: str | None, windows: bool) -> list[str] | None:
    """Return the tokens of an allowed engine or setup command, else None."""
    if not isinstance(command, str):
        return None
    tokens = _split(command.strip())
    if not tokens:
        return None
    first = normalize(tokens[0], windows=windows)
    if first and any(first == normalize(p, windows=windows) for p in _engine_paths(data)):
        return tokens
    if root and len(tokens) in (3, 4) and tokens[0] == "sh":
        script = normalize(f"{root}/bin/kalkan-setup", windows=windows)
        same_data = normalize(tokens[2], windows=windows) == normalize(data, windows=windows)
        flags_ok = len(tokens) == 3 or tokens[3] == "--force"
        if normalize(tokens[1], windows=windows) == script and same_data and flags_ok:
            return tokens
    return None


def _runs_root(data: str) -> str:
    override = os.environ.get("KALKAN_RUNS_DIR")
    if override:
        return override
    try:
        from kalkan.resources import runs_root  # noqa: PLC0415 (only when needed: hook speed)

        return str(runs_root())
    except Exception:  # a bad marker or home: fall back to the plain layout
        home = os.environ.get("KALKAN_HOME") or data
        return f"{home}/runs"


def _decision(kind: str, reason: str) -> dict[str, Any]:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": kind,
            "permissionDecisionReason": reason,
        }
    }


def _read_json(path: Path, limit: int = 65536) -> Any:
    try:
        if path.is_symlink() or path.stat().st_size > limit:
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(data), encoding="utf-8")
    os.replace(temporary, path)


def _prune(folder: Path, max_age: float, now: float) -> None:
    with contextlib.suppress(OSError):
        for entry in os.scandir(folder):
            with contextlib.suppress(OSError):
                if now - entry.stat(follow_symlinks=False).st_mtime > max_age:
                    os.unlink(entry.path)


# ---------------------------------------------------------------------------------------------
# kalkan subagents


def _run_location(path: str, runs: str, windows: bool) -> tuple[str, str, list[str]] | None:
    """Return ``(run id, area, the parts below the area)`` for a canonical path in a run."""
    parts = _relative_parts(path, runs, windows)
    if not parts or len(parts) < 2 or not _RUN_ID.fullmatch(parts[0]):
        return None
    return parts[0], parts[1], parts[2:]


def _binding_file(data: str, agent_id: object) -> Path | None:
    if not isinstance(agent_id, str) or not _SAFE_ID.fullmatch(agent_id):
        return None
    return Path(data, *AGENTS_DIR, f"{agent_id}.json")


def _load_binding(data: str, agent_id: object) -> dict[str, str] | None:
    file = _binding_file(data, agent_id)
    found = _read_json(file) if file is not None else None
    if isinstance(found, dict) and isinstance(found.get("run"), str):
        if isinstance(found.get("task"), str):
            return {"run": found["run"], "task": found["task"]}
    return None


def _bind(data: str, agent_id: object, run_id: str, task_id: str, now: float) -> None:
    file = _binding_file(data, agent_id)
    if file is None:
        return
    with contextlib.suppress(OSError):
        _prune(file.parent, BINDING_TTL_SECONDS, now)
        _write_json(file, {"run": run_id, "task": task_id, "at": now})


def _subagent_path(tool: str, tool_input: Mapping[str, Any], cwd: object, win: bool) -> str | None:
    if tool == "Read":
        return canonical(tool_input.get("file_path"), cwd=cwd, windows=win)
    if tool == "Glob":
        pattern = tool_input.get("pattern")
        if not isinstance(pattern, str) or ".." in pattern.replace("\\", "/").split("/"):
            return None
        if pattern.startswith(("/", "\\", "~")) or re.match(r"\A[A-Za-z]:", pattern):
            return None
    value = tool_input.get("path")
    if value is None or value == "":
        value = cwd  # Grep and Glob search the working folder without a path
    return canonical(value, cwd=cwd, windows=win)


def _deny_subagent(reason: str) -> dict[str, Any]:
    return _decision("deny", f"kalkan subagent: {reason}")


def _subagent_decision(
    event: Mapping[str, Any],
    tool: object,
    tool_input: Mapping[str, Any],
    data: str,
    runs: str,
    win: bool,
    now: float,
) -> dict[str, Any]:
    root = canonical(runs, windows=win)
    agent_id = event.get("agent_id")
    cwd = event.get("cwd")
    if root is None:
        return _deny_subagent("the kalkan runs folder is unknown")
    if tool == "Read" and is_own_tool_result(
        tool_input.get("file_path"), event.get("session_id"), windows=win, cwd=cwd
    ):
        return _decision("allow", "kalkan subagent reads a saved output of its own tool call")
    if tool in READ_TOOLS:
        path = _subagent_path(str(tool), tool_input, cwd, win)
        where = _run_location(path, root, win) if path is not None else None
        if where is None or where[1] not in READ_AREAS:
            return _deny_subagent(
                "read only inside the target/ and tasks/ folders of your run; use an absolute "
                "path below the target folder named in the prompt file"
            )
        run_id, area, rest = where
        binding = _load_binding(data, agent_id)
        if binding is not None and binding["run"] != run_id:
            return _deny_subagent("read only inside the run of your task")
        name = (path or "").rstrip("/").rsplit("/", 1)[-1]
        if tool == "Read" and _ENV_FILE.match(name):
            return _deny_subagent("kalkan never reads .env files of an audited target")
        if (
            binding is None
            and tool == "Read"
            and area == "tasks"
            and len(rest) == 2
            and rest[1].casefold() == "prompt.md"
            and _TASK_ID.fullmatch(rest[0])
        ):
            _bind(data, agent_id, run_id, rest[0], now)
        return _decision("allow", "kalkan subagent read inside its run")
    if tool == "Write":
        binding = _load_binding(data, agent_id)
        if binding is None:
            return _deny_subagent("read your prompt file first; then write only its result file")
        path = canonical(tool_input.get("file_path"), cwd=cwd, windows=win)
        task_dir = canonical(f"{root}/{binding['run']}/tasks/{binding['task']}", windows=win)
        if path is None or task_dir is None:
            return _deny_subagent("write only the result file of your task")
        if _fold(path, win) != _fold(f"{task_dir}/result.json", win):
            return _deny_subagent("write only the result file of your task")
        folder = Path(task_dir)
        target = folder / "result.json"
        if not folder.is_dir() or folder.is_symlink() or target.is_symlink() or target.is_dir():
            return _deny_subagent("the task folder is missing or not a plain folder")
        return _decision("allow", "kalkan subagent result file")
    return _deny_subagent(f"only Read, Grep, Glob and Write are allowed ({tool} is off)")


# ---------------------------------------------------------------------------------------------
# Sessions of an active kalkan orchestration


def _session_file(data: str, session_id: object) -> Path | None:
    if not isinstance(session_id, str) or not _SAFE_ID.fullmatch(session_id):
        return None
    return Path(data, *SESSIONS_DIR, f"{session_id}.json")


def _run_option(tokens: list[str]) -> str | None:
    for index, token in enumerate(tokens):
        value = None
        if token == "--run" and index + 1 < len(tokens):
            value = tokens[index + 1]
        elif token.startswith("--run="):
            value = token.split("=", 1)[1]
        if value is not None and _RUN_ID.fullmatch(value):
            return value
    return None


def _mark_session(data: str, session_id: object, tokens: list[str], now: float) -> None:
    file = _session_file(data, session_id)
    if file is None:
        return
    previous = _read_json(file)
    since = previous.get("since") if isinstance(previous, dict) else None
    run = _run_option(tokens)
    if run is None and isinstance(previous, dict) and isinstance(previous.get("run"), str):
        run = previous["run"]
    with contextlib.suppress(OSError):
        _prune(file.parent, SESSION_TTL_SECONDS, now)
        _write_json(file, {"since": since or now, "last": now, "run": run})


def _run_phase(runs: str, run_id: str | None) -> str | None:
    root = Path(runs)
    if run_id is None:
        try:
            latest = (root / "LATEST").read_text(encoding="utf-8").strip()
        except OSError:
            return None
        run_id = latest if _RUN_ID.fullmatch(latest) else None
    if run_id is None:
        return None
    state = _read_json(root / run_id / "state.json", _STATE_MAX_BYTES)
    phase = state.get("phase") if isinstance(state, dict) else None
    return phase if isinstance(phase, str) else None


def _session_active(data: str, session_id: object, runs: str, now: float) -> bool:
    file = _session_file(data, session_id)
    if file is None or not file.is_file():
        return False
    marker = _read_json(file)
    last = marker.get("last") if isinstance(marker, dict) else None
    run = marker.get("run") if isinstance(marker, dict) else None
    expired = not isinstance(last, (int, float)) or now - float(last) > SESSION_TTL_SECONDS
    if expired or _run_phase(runs, run if isinstance(run, str) else None) == "done":
        with contextlib.suppress(OSError):
            file.unlink()
        return False
    return True


def _network_tool(tool: object, tool_input: Mapping[str, Any]) -> bool:
    if tool in WEB_TOOLS:
        return True
    if isinstance(tool, str) and tool.startswith("mcp__"):
        return True
    return tool in SHELL_TOOLS and is_network_command(tool_input.get("command"))


# ---------------------------------------------------------------------------------------------
# decide


def decide(
    event: Mapping[str, Any],
    *,
    data: str | None,
    plugin_root: str | None = None,
    windows: bool | None = None,
    runs: str | None = None,
    now: float | None = None,
) -> dict[str, Any] | None:
    """Return the hook output for one PreToolUse event, or None (normal permission flow).

    ``runs`` replaces the runs root and ``now`` the clock (tests).
    """
    if not data:
        return None
    win = os.name == "nt" if windows is None else windows
    moment = time.time() if now is None else now
    tool = event.get("tool_name")
    raw_input = event.get("tool_input")
    tool_input: Mapping[str, Any] = raw_input if isinstance(raw_input, Mapping) else {}
    runs_folder = runs if runs is not None else _runs_root(data)

    if is_kalkan_agent(event):
        return _subagent_decision(event, tool, tool_input, data, runs_folder, win, moment)

    session = event.get("session_id")
    if tool == "Bash":
        tokens = _engine_tokens(tool_input.get("command"), data, plugin_root, win)
        if tokens is not None:
            if tokens[0] != "sh":
                _mark_session(data, session, tokens, moment)
                return _decision("allow", "kalkan engine command")
            return _decision("allow", "kalkan setup command")
    if _network_tool(tool, tool_input) and _session_active(data, session, runs_folder, moment):
        return _decision(
            "deny",
            "a kalkan audit runs in this session, and kalkan sends no data to the network "
            "until the run is done (docs/SECURITY.md); network tools are off for this session",
        )
    if (
        tool == "Read"
        and is_own_tool_result(
            tool_input.get("file_path"), session, windows=win, cwd=event.get("cwd")
        )
        and _session_active(data, session, runs_folder, moment)
    ):
        return _decision("allow", "a saved output of a tool call of this kalkan session")
    if tool in READ_TOOLS and isinstance(raw_input, Mapping):
        key = "file_path" if tool == "Read" else "path"
        path = tool_input.get(key)
        if tool == "Glob":
            pattern = tool_input.get("pattern")
            if not isinstance(pattern, str) or ".." in pattern.replace("\\", "/").split("/"):
                return None
            if pattern.startswith(("/", "\\")) or re.match(r"\A[A-Za-z]:", pattern):
                return None
        if not isinstance(path, str) or not path:
            return None
        if not any(_inside(path, root, windows=win) for root in (data, runs_folder)):
            return None
        name = path.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
        if tool == "Read" and _ENV_FILE.match(name):
            return _decision("deny", "kalkan never reads .env files of an audited target")
        return _decision("allow", "read inside the kalkan data or runs folder")
    return None


def _log(path: str, event: object, output: object) -> None:
    entry = {"event": event, "output": output, "data": os.environ.get(ENV_DATA)}
    try:
        with open(path, "a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError:
        pass


def main(argv: list[str] | None = None) -> int:
    """Read one hook event from stdin, print the decision JSON (or nothing), return 0."""
    del argv
    event: object = None
    try:
        raw = sys.stdin.buffer.read(4 * 1024 * 1024)
        event = json.loads(raw.decode("utf-8"))
        if not isinstance(event, dict):
            return 0
        output = decide(event, data=os.environ.get(ENV_DATA), plugin_root=os.environ.get(ENV_ROOT))
    except Exception:  # never break a tool call of the user ...
        if not (isinstance(event, dict) and is_kalkan_agent(event)):
            return 0
        # ... but a kalkan subagent fails closed.
        output = _deny_subagent("the permission check failed; the call is refused")
    log = os.environ.get(ENV_LOG)
    if log:
        _log(log, event, output)
    if output is not None:
        sys.stdout.write(json.dumps(output) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
