# SPDX-License-Identifier: MIT
"""Promise 2 in checkout mode (docs/SECURITY.md): the project settings and the agent files.

The checkout ships no deny rule for edits outside ``runs/``: deny rules cannot be overridden,
and such a rule would block every development session in the repository. The kalkan agents
get their limits from their own tool lists instead.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SETTINGS = ROOT / ".claude" / "settings.json"
AGENT_FOLDERS = (ROOT / ".claude" / "agents", ROOT / "plugins" / "kalkan" / "agents")


def permissions() -> dict[str, list[str]]:
    return json.loads(SETTINGS.read_text(encoding="utf-8"))["permissions"]


def front_matter(path: Path) -> dict[str, str]:
    text = path.read_text(encoding="utf-8")
    block = text.split("---", 2)[1]
    return {
        key.strip(): value.strip()
        for key, _, value in (line.partition(":") for line in block.splitlines())
        if key.strip()
    }


def test_the_checkout_allows_only_engine_commands_reads_and_result_files():
    allow = permissions()["allow"]
    assert allow == [
        "Bash(.venv/Scripts/kalkan.exe *)",
        "Bash(.venv/bin/kalkan *)",
        "Read",
        "Grep",
        "Glob",
        "Edit(/runs/*/tasks/*/result.json)",
    ]


@pytest.mark.parametrize(
    "rule",
    [
        "WebFetch",
        "WebSearch",
        "Bash(curl *)",
        "Bash(wget *)",
        "Bash(git push *)",
        "PowerShell(curl *)",
        "PowerShell(Invoke-WebRequest *)",
        "PowerShell(Invoke-RestMethod *)",
        "PowerShell(git push *)",
        "Edit(/.git/**)",
        "Read(**/.env)",
    ],
)
def test_the_checkout_denies_network_tools_and_git_metadata(rule):
    assert rule in permissions()["deny"]


def test_no_deny_rule_blocks_development_edits():
    # A deny rule cannot be overridden: an Edit deny on src/, tests/ or docs/ would stop every
    # development session in this repository (docs/SECURITY.md explains the choice).
    for rule in permissions()["deny"]:
        if rule.startswith("Edit("):
            assert rule == "Edit(/.git/**)", rule


@pytest.mark.parametrize("folder", AGENT_FOLDERS, ids=lambda folder: folder.parent.name)
def test_every_kalkan_agent_has_only_read_tools_and_write(folder):
    agents = sorted(folder.glob("kalkan-*.md"))
    assert len(agents) == 10
    for path in agents:
        meta = front_matter(path)
        tools = {item.strip() for item in meta["tools"].split(",")}
        assert "Write" in tools and tools <= {"Read", "Grep", "Glob", "Write"}, path.name
        denied = {item.strip() for item in meta["disallowedTools"].split(",")}
        assert {"Bash", "WebFetch", "WebSearch", "Edit", "NotebookEdit"} <= denied, path.name
        for key in ("hooks", "mcpServers", "permissionMode"):
            assert key not in meta, path.name


def test_the_task_prompt_forbids_network_and_writes_outside_the_result():
    text = (ROOT / "src" / "kalkan" / "prompts" / "_common.md").read_text(encoding="utf-8")
    assert re.search(r"Write exactly one file", text)
    assert "No execution, no network." in text
