# SPDX-License-Identifier: MIT
"""Tests for the Codex host of kalkan.unattended with fake ``codex exec --json`` output.

Codex is not installed for these tests. The event shapes follow docs/CODEX.md (Codex source:
``codex-rs/exec/src/exec_events.rs`` and ``codex-rs/protocol/src/error.rs``).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

from kalkan.errors import ToolError
from kalkan.unattended.hosts import (
    ClaudeHost,
    CodexHost,
    Host,
    check_prompt,
    codex_messages,
    create_host,
)

# NOW is 15:00 at UTC+03:00, the local time zone of these tests.
NOW = datetime(2026, 10, 15, 12, 0, tzinfo=UTC)
PLUS3 = timezone(timedelta(hours=3))
FLAGS = [
    "exec",
    "--sandbox",
    "workspace-write",
    "-c",
    "approval_policy=never",
    "-c",
    "sandbox_workspace_write.network_access=false",
    "-c",
    "web_search=disabled",
    "--json",
]

LIMIT_TODAY = (
    "You’ve hit your usage limit. Upgrade to Plus to continue using Codex "
    "(https://chatgpt.com/explore/plus), or try again at 3:45 PM."
)
LIMIT_OTHER_DAY = "You’ve hit your usage limit. Try again at Oct 17th, 2026 9:05 AM."
LIMIT_LATER = "You’ve hit your usage limit. Try again later."
CREDITS = "Your workspace is out of credits. Ask a workspace owner to add credits."
SPEND_CAP = "You hit your spend cap for this billing period."


def event(**fields) -> str:
    return json.dumps(fields)


def error(message: str) -> str:
    return event(type="error", message=message)


def turn_failed(message: str) -> str:
    return event(type="turn.failed", error={"message": message})


def item(kind: str, **fields) -> str:
    return event(type="item.completed", item={"id": "item_1", "type": kind, **fields})


def at(hour: int, minute: int = 0, day: int = 15) -> datetime:
    return datetime(2026, 10, day, hour, minute, tzinfo=PLUS3).astimezone(UTC)


def host() -> CodexHost:
    return CodexHost("codex", local_tz=PLUS3)


# ---------------------------------------------------------------------------------------------
# Command line


def test_codex_command_line():
    codex = CodexHost("C:/tools/codex.exe")
    assert codex.name == "codex" and codex.skill == "$kalkan"
    argv = codex.build_command("$kalkan devam --headless")
    assert argv == ["C:/tools/codex.exe", *FLAGS, "$kalkan devam --headless"]
    assert not any('"' in arg or "'" in arg for arg in argv)  # no inner quotes for codex.cmd


def test_codex_host_satisfies_the_protocol():
    assert isinstance(CodexHost(), Host)
    assert not CodexHost.supports_git_urls and ClaudeHost.supports_git_urls


def test_a_codex_cmd_shim_takes_the_skill_prefix_but_not_cmd_metacharacters():
    shim = CodexHost("C:/npm/codex.cmd")
    assert shim.build_command("$kalkan C:/code/app standard --headless")[-1].startswith("$")
    with pytest.raises(ToolError, match="codex.cmd is a cmd.exe script"):
        shim.build_command("$kalkan C:/code/a&b standard --headless")


def test_the_shim_message_is_host_neutral():
    with pytest.raises(ToolError) as caught:
        check_prompt("$kalkan C:/a%b standard --headless", "C:/npm/codex.cmd")
    message = str(caught.value)
    assert "Claude" not in message and "native codex executable" in message
    with pytest.raises(ToolError, match="native claude executable"):
        check_prompt("/kalkan C:/a%b standard --headless", "C:/npm/claude.cmd")


def test_create_codex_host():
    found = Path("C:/Users/me/AppData/Roaming/npm/codex.cmd")
    codex = create_host("codex", finder=lambda name: found if name == "codex" else None)
    assert isinstance(codex, CodexHost) and codex.build_command("$kalkan devam --headless")[0]
    with pytest.raises(ToolError, match="codex login"):
        create_host("codex", finder=lambda name: None)
    bare = create_host("codex", finder=lambda name: None, require=False)
    assert bare.build_command("$kalkan devam --headless")[0] == "codex"


# ---------------------------------------------------------------------------------------------
# Messages and limits


def test_codex_messages_keeps_only_host_text():
    lines = [
        event(type="thread.started", thread_id="t1"),
        event(type="turn.started"),
        item("agent_message", text="usage limit, try again at 4:00 PM"),
        item("reasoning", text="spend cap"),
        item("command_execution", command="cat x", aggregated_output="out of credits"),
        item("error", message="usage limit, try again at 4:00 PM"),
        error(LIMIT_TODAY),
        turn_failed(LIMIT_OTHER_DAY),
        event(type="turn.failed", error="plain error text"),
        '{"type": "error", "message": "broken',
        "codex: warning from stderr",
        "",
    ]
    assert codex_messages(lines) == [
        LIMIT_TODAY,
        LIMIT_OTHER_DAY,
        "plain error text",
        "codex: warning from stderr",
    ]


def test_a_reset_time_today_in_an_error_event():
    found = host().parse_limit([event(type="turn.started"), error(LIMIT_TODAY)], now=NOW)
    assert found is not None and found.reset_at == at(15, 45) and found.source == "text"


def test_a_reset_on_another_day_in_turn_failed():
    found = host().parse_limit([turn_failed(LIMIT_OTHER_DAY)], now=NOW)
    assert found is not None and found.reset_at == at(9, 5, day=17)


def test_a_reset_time_in_a_plain_stderr_line():
    found = host().parse_limit(["ERROR: " + LIMIT_TODAY], now=NOW)
    assert found is not None and found.reset_at == at(15, 45)


def test_try_again_later_has_no_reset_time():
    assert host().parse_limit([error(LIMIT_LATER), turn_failed(LIMIT_LATER)], now=NOW) is None


@pytest.mark.parametrize("kind", ["agent_message", "reasoning", "command_execution"])
def test_item_text_never_counts(kind):
    """Items can quote the audit target, so a planted limit text must not count."""
    lines = [item(kind, text=LIMIT_TODAY, aggregated_output=CREDITS + " " + LIMIT_TODAY)]
    assert host().parse_limit(lines, now=NOW) is None
    assert host().parse_fatal(lines) is None


def test_the_last_message_wins():
    lines = [error(LIMIT_OTHER_DAY), turn_failed(LIMIT_TODAY)]
    assert host().parse_limit(lines, now=NOW).reset_at == at(15, 45)


@pytest.mark.parametrize("message", [CREDITS, SPEND_CAP, "You hit your spending cap."])
def test_credit_and_spend_cap_messages_are_fatal(message):
    for lines in ([error(message)], [turn_failed(message)], [message]):
        found = host().parse_fatal(lines)
        assert found is not None and found == message


def test_normal_limits_are_not_fatal():
    assert host().parse_fatal([error(LIMIT_TODAY), error(LIMIT_LATER)]) is None
    assert ClaudeHost().parse_fatal([error(CREDITS)]) is None
