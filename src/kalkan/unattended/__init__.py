# SPDX-License-Identifier: MIT
"""Unattended (headless) audit runs: ``kalkan unattended`` (docs/ENGINE-SPEC.md, section 22).

- :mod:`kalkan.unattended.loop`: the round loop, the run status, the waits and the log.
- :mod:`kalkan.unattended.limits`: usage-limit detection in the host output.
- :mod:`kalkan.unattended.hosts`: the host agent CLIs (Claude Code now, Codex later).
- :mod:`kalkan.unattended.commands`: the CLI command.

:func:`doctor_checks` gives the environment checks of unattended mode for ``kalkan doctor``.
Each check is a dict ``{name, status, detail, data}`` with the status ``ok``, ``warn`` or
``info``, as :class:`kalkan.tools.doctor.Check`. The Codex check is always ``info``: Codex is an
optional host.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any, Final

from kalkan import resources
from kalkan.errors import KalkanError, UnsafeInputError
from kalkan.tools.platform import Finder, Runner, find_on_path, run_command
from kalkan.util.paths import repo_root
from kalkan.util.safe_io import read_text_bounded

__all__ = [
    "AUTO_CONTINUE_SETTING",
    "CHECK_AUTO_CONTINUE",
    "CHECK_CLAUDE",
    "CHECK_CODEX",
    "CHECK_PRINT_MODE",
    "doctor_checks",
    "user_settings_path",
]

CHECK_CLAUDE: Final = "unattended:claude"
CHECK_PRINT_MODE: Final = "unattended:print-mode"
CHECK_AUTO_CONTINUE: Final = "unattended:auto-continue"
CHECK_CODEX: Final = "unattended:codex"
AUTO_CONTINUE_SETTING: Final = "autoContinueAtUsageLimit"

_COMMAND_TIMEOUT_SECONDS: Final = 30.0
_SETTINGS_MAX_BYTES: Final = 1024 * 1024
_VERSION: Final = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")


def _check(name: str, status: str, detail: str, data: dict[str, Any] | None = None) -> dict:
    return {"name": name, "status": status, "detail": detail, "data": data or {}}


def _output(run: Runner, argv: list[str]) -> str | None:
    """Return the stdout (or stderr) of a successful command, or None."""
    try:
        proc = run(argv, timeout=_COMMAND_TIMEOUT_SECONDS)
    except Exception:  # OSError, timeout: the command does not run
        return None
    if proc.returncode != 0:
        return None
    return (proc.stdout or "").strip() or (proc.stderr or "").strip() or None


def _choices(flat_help: str, option: str) -> list[str]:
    match = re.search(re.escape(option) + r" <[a-z-]+>.{0,400}?\(choices: ([^)]*)\)", flat_help)
    return re.findall(r'"([^"]+)"', match.group(1)) if match else []


def _print_mode_check(run: Runner, claude: str) -> dict:
    text = _output(run, [claude, "-p", "--help"])
    if text is None:
        return _check(CHECK_PRINT_MODE, "warn", "claude -p --help failed")
    flat = " ".join(text.split())
    modes = _choices(flat, "--permission-mode")
    formats = _choices(flat, "--output-format")
    data = {
        "permission_mode": "--permission-mode" in flat,
        "stream_json": "stream-json" in flat,
        "dont_ask": "dontAsk" in modes if modes else "dontAsk" in flat,
        "verbose": "--verbose" in flat,
        "permission_modes": modes,
        "output_formats": formats,
    }
    missing = [
        label
        for key, label in (
            ("permission_mode", "--permission-mode"),
            ("dont_ask", "the permission mode dontAsk"),
            ("stream_json", "--output-format stream-json"),
            ("verbose", "--verbose"),
        )
        if not data[key]
    ]
    if missing:
        detail = (
            f"claude -p --help does not list {', '.join(missing)}. kalkan unattended needs "
            "them. Update Claude Code: claude update"
        )
        return _check(CHECK_PRINT_MODE, "warn", detail, data)
    detail = "claude -p supports --permission-mode dontAsk and --output-format stream-json"
    return _check(CHECK_PRINT_MODE, "ok", detail, data)


def user_settings_path() -> Path:
    """Return the Claude Code user settings file.

    ``$CLAUDE_CONFIG_DIR/settings.json`` when the variable is set, else
    ``~/.claude/settings.json``.
    """
    override = os.environ.get("CLAUDE_CONFIG_DIR")
    base = Path(override).expanduser() if override else Path.home() / ".claude"
    return base / "settings.json"


def _auto_continue_check(path: Path) -> dict:
    """Report the user setting ``autoContinueAtUsageLimit``. The file is only read."""
    shown = path.as_posix()
    data: dict[str, Any] = {"path": shown, "value": None, "state": "absent"}
    note = "kalkan unattended waits for usage-limit resets by itself and does not need it."
    if not path.exists():
        detail = f"{shown} does not exist: {AUTO_CONTINUE_SETTING} is not set. {note}"
        return _check(CHECK_AUTO_CONTINUE, "info", detail, data)
    try:
        # The file belongs to the user. A dotfile manager can make it a link, so the check
        # reads the link target, with the same size limit.
        text = read_text_bounded(path.resolve(), _SETTINGS_MAX_BYTES)
        document = json.loads(text)
    except (OSError, UnsafeInputError) as exc:
        data["state"] = "unreadable"
        return _check(CHECK_AUTO_CONTINUE, "warn", f"cannot read {shown}: {exc}", data)
    except ValueError:
        data["state"] = "invalid"
        return _check(CHECK_AUTO_CONTINUE, "warn", f"{shown} is not valid JSON", data)
    if not isinstance(document, dict):
        data["state"] = "invalid"
        return _check(CHECK_AUTO_CONTINUE, "warn", f"{shown} does not hold a JSON object", data)
    if AUTO_CONTINUE_SETTING not in document:
        detail = f"{AUTO_CONTINUE_SETTING} is not set in {shown}. {note}"
        return _check(CHECK_AUTO_CONTINUE, "info", detail, data)
    value = document[AUTO_CONTINUE_SETTING]
    if not isinstance(value, bool):
        data["state"] = "invalid"
        detail = f"{AUTO_CONTINUE_SETTING} in {shown} is not true or false"
        return _check(CHECK_AUTO_CONTINUE, "warn", detail, data)
    data["value"] = value
    data["state"] = "true" if value else "false"
    detail = f"{AUTO_CONTINUE_SETTING} is {data['state']} in {shown}. {note}"
    return _check(CHECK_AUTO_CONTINUE, "info", detail, data)


CHECK_TRUST = "unattended:workspace-trust"
_CLAUDE_JSON_MAX_BYTES = 64 * 1024 * 1024


def claude_state_path() -> Path:
    """Return the Claude Code state file that records trusted folders (``~/.claude.json``)."""
    override = os.environ.get("CLAUDE_CONFIG_DIR")
    if override:
        return Path(override).expanduser() / ".claude.json"
    return Path.home() / ".claude.json"


def workspace_trusted(repo: str | os.PathLike[str], state_path: Path | None = None) -> bool | None:
    """Return whether Claude Code trusts ``repo`` (True/False), or None when unknown.

    Claude Code ignores the ``permissions`` of a project's ``.claude/settings.json`` until the
    folder is trusted, so subagents cannot write their result files. The file is only read.
    """
    path = state_path or claude_state_path()
    try:
        document = json.loads(read_text_bounded(path.resolve(), _CLAUDE_JSON_MAX_BYTES))
    except (OSError, UnsafeInputError, ValueError):
        return None
    projects = document.get("projects") if isinstance(document, dict) else None
    if not isinstance(projects, dict):
        return False
    wanted = Path(repo).resolve().as_posix().casefold()
    for key, value in projects.items():
        if isinstance(key, str) and key.replace("\\", "/").rstrip("/").casefold() == wanted:
            return isinstance(value, dict) and value.get("hasTrustDialogAccepted") is True
    return False


def _trust_check(repo: Path, state_path: Path | None) -> dict:
    trusted = workspace_trusted(repo, state_path)
    data = {"repo": repo.as_posix(), "trusted": trusted}
    if trusted:
        return _check(CHECK_TRUST, "ok", "Claude Code trusts this folder", data)
    detail = (
        "Claude Code does not trust this folder yet, so it ignores the project permissions and "
        "subagents cannot write their results. Run `claude` in this folder once and accept the "
        "trust dialog."
    )
    if trusted is None:
        detail = "cannot read the Claude Code state file to check folder trust. " + detail
    return _check(CHECK_TRUST, "warn", detail, data)


def _workspace_check(state_path: Path | None, plugin_install: Callable[[], bool]) -> dict:
    """Return ``unattended:workspace-trust``. It is ``info`` for the plugin install and
    without a checkout."""
    unknown = {"repo": None, "trusted": None}
    if plugin_install():
        detail = (
            "Claude Code plugin: the plugin hook allows the engine calls and the result files, "
            "also in an untrusted folder. kalkan-unattended runs the rounds in the runs folder."
        )
        return _check(CHECK_TRUST, "info", detail, unknown)
    try:
        workspace = repo_root()
    except KalkanError:
        detail = (
            "no kalkan checkout: the trust check covers the project permissions of a checkout. "
            "The Claude Code plugin allows its engine calls with a hook instead."
        )
        return _check(CHECK_TRUST, "info", detail, unknown)
    return _trust_check(workspace, state_path)


def _codex_check(run: Runner, find: Finder) -> dict:
    """Report whether the optional Codex host is on PATH. The status is always ``info``."""
    found = find("codex")
    if found is None:
        detail = "codex is not on PATH. It is needed only for: kalkan unattended --host codex"
        return _check(CHECK_CODEX, "info", detail, {"path": None, "version": None})
    codex = os.fspath(found)
    data: dict[str, Any] = {"path": Path(codex).as_posix(), "version": None}
    output = _output(run, [codex, "--version"])
    if output is None:
        detail = f"codex is on PATH ({data['path']}), but codex --version failed"
        return _check(CHECK_CODEX, "info", detail, data)
    first = output.splitlines()[0].strip()
    version = _VERSION.search(first)
    data["version"] = version.group(0) if version else None
    return _check(CHECK_CODEX, "info", f"{first} ({data['path']})", data)


def doctor_checks(
    *,
    runner: Runner | None = None,
    finder: Finder | None = None,
    settings_path: str | os.PathLike[str] | None = None,
    state_path: Path | None = None,
    plugin_install: Callable[[], bool] | None = None,
) -> list[dict]:
    """Return the checks of unattended mode, in a fixed order.

    1. ``unattended:claude``: ``claude`` is on PATH, and ``claude --version`` works.
    2. ``unattended:print-mode``: ``claude -p --help`` lists ``--permission-mode`` (with
       ``dontAsk``), ``--output-format stream-json`` and ``--verbose``.
    3. ``unattended:auto-continue``: the user setting ``autoContinueAtUsageLimit`` is true,
       false or absent (:func:`user_settings_path`). The check never changes the file.
    4. ``unattended:workspace-trust``: Claude Code trusts the repository folder (read from
       ``~/.claude.json``); without trust the project permissions are ignored. For the plugin
       install (:func:`kalkan.resources.plugin_install`) and without a checkout the check is
       ``info``: the plugin hook gives the permissions.
    5. ``unattended:codex``: the optional Codex host is on PATH, with its version. Always
       ``info``, never a warning or a failure.

    The keyword arguments exist for tests.
    """
    run = runner or run_command
    find = finder or find_on_path
    checks: list[dict] = []
    found = find("claude")
    if found is None:
        detail = "claude (the Claude Code CLI) is not on PATH. kalkan unattended needs it."
        checks.append(_check(CHECK_CLAUDE, "warn", detail))
        checks.append(_check(CHECK_PRINT_MODE, "warn", "skipped: claude is not on PATH"))
    else:
        claude = os.fspath(found)
        data: dict[str, Any] = {"path": Path(claude).as_posix()}
        output = _output(run, [claude, "--version"])
        if output is None:
            checks.append(_check(CHECK_CLAUDE, "warn", "claude --version failed", data))
        else:
            first = output.splitlines()[0].strip()
            version = _VERSION.search(first)
            data["version"] = version.group(0) if version else None
            checks.append(_check(CHECK_CLAUDE, "ok", first, data))
        checks.append(_print_mode_check(run, claude))
    path = Path(settings_path) if settings_path is not None else user_settings_path()
    checks.append(_auto_continue_check(path))
    checks.append(_workspace_check(state_path, plugin_install or resources.plugin_install))
    checks.append(_codex_check(run, find))
    return checks
