# SPDX-License-Identifier: MIT
"""Tests for kalkan.unattended.hosts (no process starts)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

from kalkan.errors import KalkanError, ToolError
from kalkan.unattended import hosts
from kalkan.unattended.hosts import ClaudeHost, Host, check_prompt, create_host

NOW = datetime(2026, 10, 15, 12, 0, tzinfo=UTC)


def test_claude_command_line():
    host = ClaudeHost("C:/tools/claude.exe")
    assert host.name == "claude"
    assert host.build_command("/kalkan devam --headless") == [
        "C:/tools/claude.exe",
        "-p",
        "/kalkan devam --headless",
        "--permission-mode",
        "dontAsk",
        "--output-format",
        "stream-json",
        "--verbose",
    ]


def test_claude_host_satisfies_the_protocol():
    assert isinstance(ClaudeHost(), Host)


def test_claude_host_parses_limits():
    host = ClaudeHost(local_tz=timezone(timedelta(hours=3)))
    reset = NOW + timedelta(hours=2)
    line = json.dumps(
        {
            "type": "rate_limit_event",
            "rate_limit_info": {"status": "rejected", "resetsAt": int(reset.timestamp())},
        }
    )
    found = host.parse_limit([line], now=NOW)
    assert found is not None and found.reset_at == reset
    assert host.parse_limit(["all good"], now=NOW) is None


@pytest.mark.parametrize(
    ("prompt", "message"),
    [
        ("", "1 to"),
        ("x" * 4001, "1 to"),
        ("--dangerously-skip-permissions", "must not start"),
        ("/kalkan devam\n--headless", "control characters"),
        ("/kalkan devam\x00", "control characters"),
    ],
)
def test_unsafe_prompts_are_refused(prompt, message):
    with pytest.raises(KalkanError, match=message):
        check_prompt(prompt, "claude")


@pytest.mark.parametrize("executable", ["C:/npm/claude.cmd", "C:/npm/CLAUDE.BAT"])
def test_cmd_shims_refuse_cmd_metacharacters(executable):
    host = ClaudeHost(executable)
    for prompt in ["/kalkan C:/a&b standard --headless", "/kalkan C:/%PATH% standard --headless"]:
        with pytest.raises(ToolError, match="cmd.exe"):
            host.build_command(prompt)
    assert host.build_command('/kalkan "C:/My Code/app" standard --headless')[2].startswith(
        "/kalkan"
    )


def test_the_native_executable_accepts_cmd_metacharacters():
    assert ClaudeHost("C:/tools/claude.exe").build_command("/kalkan C:/a&b standard --headless")


def test_create_host_resolves_the_program_on_path():
    found = Path("C:/Users/me/.local/bin/claude.exe")
    host = create_host("claude", finder=lambda name: found if name == "claude" else None)
    assert host.build_command("/kalkan devam --headless")[0] == str(found)


def test_create_host_without_the_program():
    with pytest.raises(ToolError, match="not on PATH"):
        create_host("claude", finder=lambda name: None)
    host = create_host("claude", finder=lambda name: None, require=False)
    assert host.build_command("/kalkan devam --headless")[0] == "claude"


def test_unknown_host():
    with pytest.raises(KalkanError, match="unknown host"):
        create_host("gemini", finder=lambda name: None)
    assert hosts.host_names() == ["claude", "codex"]


def test_the_plugin_skill_replaces_the_prompt_prefix():
    host = ClaudeHost("C:/tools/claude.exe", skill=hosts.PLUGIN_SKILL)
    assert host.skill == "/kalkan:kalkan" and ClaudeHost().skill == "/kalkan"
    argv = host.build_command("/kalkan:kalkan devam --headless")
    assert argv[:3] == ["C:/tools/claude.exe", "-p", "/kalkan:kalkan devam --headless"]
    assert "skill='/kalkan:kalkan'" in repr(host)
    # The colon is no cmd.exe metacharacter, so an npm shim accepts the plugin prompt.
    shim = ClaudeHost("C:/npm/claude.cmd", skill=hosts.PLUGIN_SKILL)
    assert shim.build_command("/kalkan:kalkan C:/code/app fast --headless")[2].startswith("/")
