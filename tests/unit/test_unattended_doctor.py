# SPDX-License-Identifier: MIT
"""Tests for kalkan.unattended.doctor_checks (fake runner and finder, no process starts)."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from kalkan.unattended import (
    CHECK_AUTO_CONTINUE,
    CHECK_CLAUDE,
    CHECK_CODEX,
    CHECK_PRINT_MODE,
    doctor_checks,
    user_settings_path,
)

CLAUDE = Path("C:/Users/me/.local/bin/claude.exe")

# An excerpt of `claude -p --help` from Claude Code 2.1.280, with its line wrapping.
HELP = """Usage: claude [options] [prompt]

Options:
  --output-format <format>              Output format (only works with --print):
                                        "text" (default), "json" (single
                                        result), or "stream-json" (realtime
                                        streaming) (choices: "text", "json",
                                        "stream-json")
  --permission-mode <mode>              Permission mode to use for the session
                                        (choices: "acceptEdits", "auto",
                                        "bypassPermissions", "manual",
                                        "dontAsk", "plan")
  -p, --print                           Print response and exit (useful for
                                        pipes).
  --verbose                             Override verbose mode setting from
                                        config
"""


class FakeRunner:
    def __init__(self, outputs: dict[tuple[str, ...], tuple[int, str]]) -> None:
        self.outputs = outputs
        self.calls: list[list[str]] = []

    def __call__(self, argv, *, timeout, **_kwargs):
        assert timeout > 0
        self.calls.append([str(arg) for arg in argv])
        code, out = self.outputs.get(tuple(str(arg) for arg in argv[1:]), (1, ""))
        return subprocess.CompletedProcess(argv, code, out, "")


def runner(help_text: str = HELP, version: tuple[int, str] = (0, "2.1.280 (Claude Code)\n")):
    return FakeRunner({("--version",): version, ("-p", "--help"): (0, help_text)})


def by_name(checks: list[dict]) -> dict[str, dict]:
    return {check["name"]: check for check in checks}


def settings(tmp_path: Path, content) -> Path:
    path = tmp_path / "settings.json"
    path.write_text(content if isinstance(content, str) else json.dumps(content), "utf-8")
    return path


def test_all_good(tmp_path):
    checks = doctor_checks(
        runner=runner(), finder=lambda name: CLAUDE, settings_path=settings(tmp_path, {})
    )
    assert [c["name"] for c in checks] == [
        CHECK_CLAUDE,
        CHECK_PRINT_MODE,
        CHECK_AUTO_CONTINUE,
        "unattended:workspace-trust",
        CHECK_CODEX,
    ]
    found = by_name(checks)
    assert found[CHECK_CLAUDE]["status"] == "ok"
    assert found[CHECK_CLAUDE]["data"] == {"path": CLAUDE.as_posix(), "version": "2.1.280"}
    mode = found[CHECK_PRINT_MODE]
    assert mode["status"] == "ok"
    assert mode["data"]["permission_modes"] == [
        "acceptEdits",
        "auto",
        "bypassPermissions",
        "manual",
        "dontAsk",
        "plan",
    ]
    assert mode["data"]["output_formats"] == ["text", "json", "stream-json"]
    for check in checks:
        assert set(check) == {"name", "status", "detail", "data"}


def test_old_claude_without_stream_json_or_dont_ask(tmp_path):
    old_help = HELP.replace('"stream-json"', '"x"').replace("stream-json", "x")
    old_help = old_help.replace('"dontAsk", ', "")
    checks = by_name(
        doctor_checks(
            runner=runner(old_help), finder=lambda n: CLAUDE, settings_path=tmp_path / "none"
        )
    )
    mode = checks[CHECK_PRINT_MODE]
    assert mode["status"] == "warn"
    assert "stream-json" in mode["detail"] and "dontAsk" in mode["detail"]
    assert "claude update" in mode["detail"]


def test_failing_commands(tmp_path):
    fake = FakeRunner({})
    checks = by_name(
        doctor_checks(runner=fake, finder=lambda n: CLAUDE, settings_path=tmp_path / "none")
    )
    assert checks[CHECK_CLAUDE]["status"] == "warn"
    assert checks[CHECK_PRINT_MODE]["status"] == "warn"


def test_runner_exceptions_are_warnings(tmp_path):
    def broken(argv, *, timeout, **_kwargs):
        raise subprocess.TimeoutExpired(argv, timeout)

    checks = by_name(
        doctor_checks(runner=broken, finder=lambda n: CLAUDE, settings_path=tmp_path / "none")
    )
    assert checks[CHECK_CLAUDE]["status"] == "warn"


def test_claude_not_on_path(tmp_path):
    fake = runner()
    checks = by_name(
        doctor_checks(runner=fake, finder=lambda n: None, settings_path=tmp_path / "none")
    )
    assert checks[CHECK_CLAUDE]["status"] == "warn"
    assert checks[CHECK_PRINT_MODE]["status"] == "warn"
    assert fake.calls == []


@pytest.mark.parametrize(
    ("content", "status", "state", "value"),
    [
        ({"autoContinueAtUsageLimit": True}, "info", "true", True),
        ({"autoContinueAtUsageLimit": False}, "info", "false", False),
        ({"model": "opus"}, "info", "absent", None),
        ({"autoContinueAtUsageLimit": "yes"}, "warn", "invalid", None),
        ("{not json", "warn", "invalid", None),
        ("[1, 2]", "warn", "invalid", None),
    ],
)
def test_auto_continue_setting(tmp_path, content, status, state, value):
    path = settings(tmp_path, content)
    before = (path.read_bytes(), os.stat(path).st_mtime_ns)
    check = by_name(doctor_checks(runner=runner(), finder=lambda n: None, settings_path=path))[
        CHECK_AUTO_CONTINUE
    ]
    assert (check["status"], check["data"]["state"], check["data"]["value"]) == (
        status,
        state,
        value,
    )
    assert (path.read_bytes(), os.stat(path).st_mtime_ns) == before  # never changed


def test_missing_settings_file(tmp_path):
    check = by_name(
        doctor_checks(runner=runner(), finder=lambda n: None, settings_path=tmp_path / "x.json")
    )[CHECK_AUTO_CONTINUE]
    assert check["status"] == "info" and check["data"]["state"] == "absent"
    assert "does not exist" in check["detail"]


def test_a_settings_file_over_the_size_limit(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text('{"a": "' + "x" * (1024 * 1024 + 10) + '"}', "utf-8")
    check = by_name(doctor_checks(runner=runner(), finder=lambda n: None, settings_path=path))[
        CHECK_AUTO_CONTINUE
    ]
    assert check["status"] == "warn" and check["data"]["state"] == "unreadable"


def test_a_linked_settings_file_is_read(tmp_path):
    real = settings(tmp_path, {"autoContinueAtUsageLimit": True})
    link = tmp_path / "linked.json"
    try:
        link.symlink_to(real)
    except (OSError, NotImplementedError):
        pytest.skip("this account cannot create symlinks")
    check = by_name(doctor_checks(runner=runner(), finder=lambda n: None, settings_path=link))[
        CHECK_AUTO_CONTINUE
    ]
    assert check["data"]["state"] == "true"


def test_user_settings_path(monkeypatch, tmp_path):
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path / "cfg"))
    assert user_settings_path() == tmp_path / "cfg" / "settings.json"
    monkeypatch.delenv("CLAUDE_CONFIG_DIR")
    assert user_settings_path() == Path.home() / ".claude" / "settings.json"


def test_codex_on_path_is_info(tmp_path):
    codex = Path("C:/Users/me/AppData/Roaming/npm/codex.cmd")
    fake = FakeRunner({("--version",): (0, "codex-cli 0.130.0\n")})
    found = by_name(
        doctor_checks(
            runner=fake,
            finder=lambda name: codex if name == "codex" else None,
            settings_path=tmp_path / "none",
        )
    )[CHECK_CODEX]
    assert found["status"] == "info"
    assert found["data"] == {"path": codex.as_posix(), "version": "0.130.0"}
    assert "codex-cli 0.130.0" in found["detail"]


@pytest.mark.parametrize("finder_result", [None, Path("C:/bin/codex.exe")])
def test_codex_check_never_warns_or_fails(tmp_path, finder_result):
    def broken(argv, *, timeout, **_kwargs):
        raise OSError("cannot start")

    checks = doctor_checks(
        runner=broken,
        finder=lambda name: finder_result if name == "codex" else None,
        settings_path=tmp_path / "none",
    )
    found = by_name(checks)[CHECK_CODEX]
    assert found["status"] == "info"
    if finder_result is None:
        assert "not on PATH" in found["detail"] and found["data"]["path"] is None
    else:
        assert "--version failed" in found["detail"]


def _state(tmp_path, projects):
    path = tmp_path / ".claude.json"
    path.write_text(json.dumps({"projects": projects}), encoding="utf-8")
    return path


def test_workspace_trust_reads_the_claude_state(tmp_path):
    from kalkan.unattended import workspace_trusted

    repo = tmp_path / "repo"
    repo.mkdir()
    key = repo.resolve().as_posix()
    assert workspace_trusted(repo, _state(tmp_path, {key: {"hasTrustDialogAccepted": True}}))
    assert workspace_trusted(repo, _state(tmp_path, {key: {}})) is False
    assert workspace_trusted(repo, _state(tmp_path, {})) is False
    assert workspace_trusted(repo, tmp_path / "missing.json") is None


def test_trust_check_warns_when_untrusted(tmp_path):
    checks = doctor_checks(
        runner=runner(),
        finder=lambda name: CLAUDE,
        settings_path=settings(tmp_path, {}),
        state_path=_state(tmp_path, {}),
    )
    trust = by_name(checks)["unattended:workspace-trust"]
    assert trust["status"] == "warn" and "trust dialog" in trust["detail"]


def test_the_plugin_install_skips_the_trust_check(tmp_path):
    checks = doctor_checks(
        runner=runner(),
        finder=lambda name: CLAUDE,
        settings_path=settings(tmp_path, {}),
        state_path=_state(tmp_path, {}),
        plugin_install=lambda: True,
    )
    trust = by_name(checks)["unattended:workspace-trust"]
    assert trust["status"] == "info" and "plugin hook" in trust["detail"]
    assert trust["data"] == {"repo": None, "trusted": None}
