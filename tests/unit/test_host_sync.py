# SPDX-License-Identifier: MIT
"""Tests for scripts/sync_host_files.py: the Codex host files follow the Claude Code files."""

from __future__ import annotations

import ast
import importlib.util
import json
import re
import shlex
import shutil
import sys
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "sync_host_files.py"
CLAUDE_AGENTS = ROOT / ".claude" / "agents"
CLAUDE_SETTINGS = ROOT / ".claude" / "settings.json"
CODEX_AGENTS = ROOT / ".codex" / "agents"
CODEX_SKILL = ROOT / ".agents" / "skills" / "kalkan" / "SKILL.md"
CODEX_SKILL_POLICY = ROOT / ".agents" / "skills" / "kalkan" / "agents" / "openai.yaml"
CODEX_CONFIG = ROOT / ".codex" / "config.toml"
CODEX_RULES = ROOT / ".codex" / "rules" / "kalkan.rules"
SOURCES = ("CLAUDE.md", ".claude/skills/kalkan/SKILL.md", ".claude/agents")


@pytest.fixture(scope="module")
def sync():
    spec = importlib.util.spec_from_file_location("sync_host_files", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses resolve annotations through sys.modules
    try:
        spec.loader.exec_module(module)
        yield module
    finally:
        sys.modules.pop(spec.name, None)


@pytest.fixture
def fake_root(tmp_path: Path) -> Path:
    """A copy of the Claude Code source files in a temporary folder."""
    for relative in SOURCES:
        source = ROOT / relative
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if source.is_dir():
            shutil.copytree(source, target)
        else:
            shutil.copyfile(source, target)
    return tmp_path


def claude_agent_names() -> list[str]:
    return sorted(path.stem for path in CLAUDE_AGENTS.glob("kalkan-*.md"))


def test_codex_files_match_the_claude_files(sync):
    problems = sync.check(ROOT)
    assert problems == [], "run: python scripts/sync_host_files.py\n" + "\n".join(problems)


def test_check_mode_exits_zero_on_the_repository(sync, capsys):
    assert sync.main(["--check"]) == 0
    assert "in sync" in capsys.readouterr().err


def test_every_claude_agent_has_a_codex_agent(sync):
    names = claude_agent_names()
    assert len(names) == 10
    for name in names:
        path = CODEX_AGENTS / f"{name}.toml"
        assert path.is_file(), f"{name}: no Codex counterpart"
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        assert data["name"] == name
        assert data["description"].strip()
        assert "/kalkan" not in data["description"]
        fields, body = sync.parse_front_matter(
            (CLAUDE_AGENTS / f"{name}.md").read_text(encoding="utf-8"), name
        )
        assert fields["name"] == name
        assert body.strip() in data["developer_instructions"]
        assert "## Codex host notes" in data["developer_instructions"]
        # A custom agent file cannot override these; they must come from the parent session.
        for key in ("sandbox_mode", "approval_policy", "model_provider", "mcp_servers"):
            assert key not in data, f"{name}: {key} has no effect in a custom agent file"
        assert data["features"] == {key: False for key in sync.AGENT_FEATURES_OFF}


def test_no_codex_agent_without_a_claude_agent():
    codex = sorted(path.stem for path in CODEX_AGENTS.glob("*.toml"))
    assert codex == claude_agent_names()


def test_translator_notes_follow_its_smaller_tool_list():
    data = tomllib.loads((CODEX_AGENTS / "kalkan-translator.toml").read_text(encoding="utf-8"))
    assert "Do not list, search or read other files." in data["developer_instructions"]
    hunter = tomllib.loads((CODEX_AGENTS / "kalkan-hunter.toml").read_text(encoding="utf-8"))
    assert "rg --files" in hunter["developer_instructions"]


def test_codex_skill_has_no_claude_only_terms(sync):
    text = CODEX_SKILL.read_text(encoding="utf-8")
    fields, body = sync.parse_front_matter(text, "codex skill")
    assert fields["name"] == "kalkan"
    assert "$kalkan" in fields["description"]
    for term in ("$ARGUMENTS", "Agent tool", "Bash", "Glob", "one message"):
        assert term not in body, f"Claude-only term {term!r} in the Codex skill"
    assert not re.search(r"(?<![\w./\\-])/kalkan\b", text)
    for term in (
        "agent_type",
        "close_agent",
        "kalkan run next --run <run-id> --owner orchestrator --json",
    ):
        assert term in body


def test_codex_config_keeps_the_audit_sandbox():
    config = tomllib.loads(CODEX_CONFIG.read_text(encoding="utf-8"))
    assert config["sandbox_mode"] == "workspace-write"
    assert config["approval_policy"] == "never"
    assert config["web_search"] == "disabled"
    assert config["sandbox_workspace_write"]["network_access"] is False
    # At least the default number of parallel agent tasks per round (run init --max-parallel).
    assert config["agents"]["max_concurrent_threads_per_session"] >= 6


def test_write_then_check_in_a_fresh_folder(sync, fake_root):
    assert sorted(sync.check(fake_root))[0].endswith(": missing")
    changed = sync.write(fake_root)
    assert "AGENTS.md" in changed
    assert sync.check(fake_root) == []
    assert sync.write(fake_root) == []
    assert (fake_root / "AGENTS.md").read_text(encoding="utf-8") == (ROOT / "AGENTS.md").read_text(
        encoding="utf-8"
    )


def test_check_reports_an_edited_and_an_extra_codex_file(sync, fake_root):
    sync.write(fake_root)
    agent = fake_root / ".codex" / "agents" / "kalkan-hunter.toml"
    agent.write_text(agent.read_text(encoding="utf-8") + "# hand edit\n", encoding="utf-8")
    extra = fake_root / ".codex" / "agents" / "kalkan-extra.toml"
    shutil.copyfile(fake_root / ".codex" / "agents" / "kalkan-critic.toml", extra)
    problems = sync.check(fake_root)
    assert ".codex/agents/kalkan-hunter.toml: differs from its Claude Code source" in problems
    assert ".codex/agents/kalkan-extra.toml: no Claude Code agent produces this file" in problems
    assert sync.main(["--check", "--root", str(fake_root)]) == 1
    sync.write(fake_root)
    assert not extra.exists()
    assert sync.check(fake_root) == []


def test_write_keeps_a_hand_written_extra_agent(sync, fake_root):
    sync.write(fake_root)
    extra = fake_root / ".codex" / "agents" / "kalkan-own.toml"
    extra.write_text('name = "kalkan-own"\n', encoding="utf-8")
    with pytest.raises(sync.SyncError, match="not generated"):
        sync.write(fake_root)
    assert extra.exists()


def test_a_new_claude_agent_gets_a_codex_agent(sync, fake_root):
    source = fake_root / ".claude" / "agents" / "kalkan-critic.md"
    text = source.read_text(encoding="utf-8").replace("name: kalkan-critic", "name: kalkan-new")
    (fake_root / ".claude" / "agents" / "kalkan-new.md").write_text(text, encoding="utf-8")
    sync.write(fake_root)
    data = tomllib.loads(
        (fake_root / ".codex" / "agents" / "kalkan-new.toml").read_text(encoding="utf-8")
    )
    assert data["name"] == "kalkan-new"


def test_shared_skill_text_flows_to_codex(sync, fake_root):
    skill = fake_root / ".claude" / "skills" / "kalkan" / "SKILL.md"
    marker = "- Never decide a verdict, a severity or a finding. The engine computes them."
    text = skill.read_text(encoding="utf-8")
    assert marker in text
    skill.write_text(text.replace(marker, marker + "\n- A new shared rule."), encoding="utf-8")
    sync.write(fake_root)
    codex = (fake_root / ".agents" / "skills" / "kalkan" / "SKILL.md").read_text(encoding="utf-8")
    assert "- A new shared rule." in codex


def test_a_changed_claude_anchor_stops_the_sync(sync, fake_root):
    skill = fake_root / ".claude" / "skills" / "kalkan" / "SKILL.md"
    text = skill.read_text(encoding="utf-8")
    assert "with the Agent tool" in text
    skill.write_text(text.replace("with the Agent tool", "via the Agent tool"), encoding="utf-8")
    with pytest.raises(sync.SyncError, match="replacement table"):
        sync.write(fake_root)
    assert sync.main(["--root", str(fake_root)]) == 1


def test_agent_name_must_match_the_file_name(sync, fake_root):
    source = fake_root / ".claude" / "agents" / "kalkan-critic.md"
    text = source.read_text(encoding="utf-8").replace("name: kalkan-critic", "name: critic")
    source.write_text(text, encoding="utf-8")
    with pytest.raises(sync.SyncError, match="must be 'kalkan-critic'"):
        sync.expected_files(fake_root)


def test_replacement_counts(sync):
    item = sync.Replacement("a", "b", 2)
    assert sync.apply_replacements("a-a", [item], "x") == "b-b"
    with pytest.raises(sync.SyncError, match="expects 2"):
        sync.apply_replacements("a", [item], "x")
    assert sync.apply_replacements("none", [sync.Replacement("a", "b", "*")], "x") == "none"
    with pytest.raises(sync.SyncError, match="at least 1"):
        sync.apply_replacements("none", [sync.Replacement("q", "b", "+")], "x")


def test_skill_command_replacement_leaves_paths_alone(sync):
    text = "Run `/kalkan devam`. See src/kalkan/cli.py and .claude/skills/kalkan/SKILL.md."
    result = sync.apply_replacements(text, sync.SKILL_REPLACEMENTS[:1], "x")
    assert (
        result == "Run `$kalkan devam`. See src/kalkan/cli.py and .claude/skills/kalkan/SKILL.md."
    )


@pytest.mark.parametrize(
    "value",
    [
        "plain text\n",
        "quotes ' and '' and \" and \\ backslash\n",
        "three quotes ''' inside\n",
        "ends with a quote'",
        "tab\tand unicode İngilizce ç\n",
        "control \x01 char\n",
    ],
)
def test_toml_strings_round_trip(sync, value):
    document = f"key = {sync.toml_multiline(value)}\n"
    assert tomllib.loads(document)["key"] == value


def test_skill_policy_turns_off_implicit_invocation(sync):
    text = CODEX_SKILL_POLICY.read_text(encoding="utf-8")
    assert sync.GENERATED_MARK in text
    assert "policy:\n  allow_implicit_invocation: false\n" in text
    fields, _ = sync.parse_front_matter(
        (ROOT / ".claude" / "skills" / "kalkan" / "SKILL.md").read_text(encoding="utf-8"), "x"
    )
    assert fields["disable-model-invocation"] == "true"


def test_skill_policy_follows_the_claude_key(sync, fake_root):
    skill = fake_root / ".claude" / "skills" / "kalkan" / "SKILL.md"
    text = skill.read_text(encoding="utf-8")
    skill.write_text(text.replace("disable-model-invocation: true\n", ""), encoding="utf-8")
    assert "allow_implicit_invocation: true" in sync.build_skill_policy(fake_root)


# ---------------------------------------------------------------------------------------------
# .codex/rules/kalkan.rules
#
# Codex execpolicy rules use a Starlark subset: top-level prefix_rule(...) calls with literal
# arguments. That subset is valid Python syntax, so the tests read it with `ast`. The matcher
# follows the codex-execpolicy README: tokens match in order, a list is a set of alternatives,
# the first token matches exactly, and the strictest decision wins. String examples are split
# with shlex, as Codex does.

RULE_KEYS = {"pattern", "decision", "justification", "match", "not_match"}
SEVERITY = {"allow": 0, "prompt": 1, "forbidden": 2}


def load_rules() -> list[dict]:
    tree = ast.parse(CODEX_RULES.read_text(encoding="utf-8"), filename=str(CODEX_RULES))
    rules = []
    for node in tree.body:
        assert isinstance(node, ast.Expr) and isinstance(node.value, ast.Call), ast.dump(node)
        call = node.value
        assert isinstance(call.func, ast.Name) and call.func.id == "prefix_rule"
        assert not call.args, "prefix_rule takes keyword arguments only"
        rule = {item.arg: ast.literal_eval(item.value) for item in call.keywords}
        assert set(rule) <= RULE_KEYS, set(rule) - RULE_KEYS
        rules.append(rule)
    return rules


def tokens_of(example: str | list[str]) -> list[str]:
    return shlex.split(example) if isinstance(example, str) else list(example)


def rule_matches(rule: dict, tokens: list[str]) -> bool:
    pattern = rule["pattern"]
    if len(tokens) < len(pattern):
        return False
    for element, token in zip(pattern, tokens, strict=False):
        choices = element if isinstance(element, list) else [element]
        if token not in choices:
            return False
    return True


def decide(rules: list[dict], tokens: list[str]) -> str | None:
    decisions = [rule.get("decision", "allow") for rule in rules if rule_matches(rule, tokens)]
    return max(decisions, key=SEVERITY.__getitem__) if decisions else None


def test_rules_parse_as_expected():
    rules = load_rules()
    assert len(rules) == 5
    for rule in rules:
        pattern = rule["pattern"]
        assert isinstance(pattern, list) and pattern
        for element in pattern:
            assert isinstance(element, str) or (
                isinstance(element, list) and element and all(isinstance(e, str) for e in element)
            )
        assert rule.get("decision", "allow") in SEVERITY
        assert isinstance(rule.get("justification", "x"), str) and rule.get("justification", "x")
        assert rule.get("match"), "every rule carries match examples (Codex checks them on load)"


def test_rule_examples_hold():
    # Codex refuses to load a rules file whose match or not_match examples fail.
    for rule in load_rules():
        for example in rule.get("match", []):
            assert rule_matches(rule, tokens_of(example)), (rule["pattern"], example)
        for example in rule.get("not_match", []):
            assert not rule_matches(rule, tokens_of(example)), (rule["pattern"], example)


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        (".venv/Scripts/kalkan.exe run step --json", "allow"),
        (".venv/bin/kalkan run step --json", "allow"),
        ([r".\.venv\Scripts\kalkan.exe", "run", "step", "--json"], "allow"),
        (".venv/Scripts/kalkan.exe task complete T0001-recon --json", "allow"),
        # The skill names its run after the subcommand; the prefix rules still match.
        (".venv/Scripts/kalkan.exe run step --run 20261016T151915Z-app-5fc6 --json", "allow"),
        (
            ".venv/bin/kalkan task complete T0001-recon --run 20261016T151915Z-app-5fc6 --json",
            "allow",
        ),
        (".venv/Scripts/kalkan.exe run next --run 20261016T151915Z-app-5fc6 --json", None),
        (".venv/Scripts/kalkan.exe run init C:/code/app --no-latest --json", None),
        (".venv/Scripts/kalkan.exe run next --owner orchestrator --json", None),
        (".venv/Scripts/kalkan.exe run init https://example.com/app.git --json", None),
        (".venv/Scripts/kalkan.exe run status --json", None),
        ("kalkan run step --json", None),
        ("curl https://example.com", "forbidden"),
        ("curl.exe -s https://example.com", "forbidden"),
        ("wget https://example.com", "forbidden"),
        ("git push origin main", "forbidden"),
        ("git status", None),
        ("rg --files", None),
    ],
)
def test_rule_decisions(command, expected):
    assert decide(load_rules(), tokens_of(command)) == expected


def test_rules_follow_the_claude_settings():
    settings = json.loads(CLAUDE_SETTINGS.read_text(encoding="utf-8"))["permissions"]
    bash = re.compile(r"\ABash\((?P<command>.+?)(?: \*)?\)\Z")
    allowed = [m["command"] for e in settings["allow"] if (m := bash.match(e))]
    denied = [m["command"] for e in settings["deny"] if (m := bash.match(e))]
    assert allowed and denied
    rules = load_rules()
    for command in allowed:
        # Each engine path that Claude Code allows runs `run step` outside the Codex sandbox.
        assert decide(rules, shlex.split(command) + ["run", "step"]) == "allow", command
    for command in denied:
        assert decide(rules, shlex.split(command) + ["x"]) == "forbidden", command


# ---------------------------------------------------------------------------------------------
# Claude Code plugin files (plugins/kalkan)

PLUGIN_SKILL = ROOT / "plugins" / "kalkan" / "skills" / "kalkan" / "SKILL.md"
PLUGIN_AGENTS = ROOT / "plugins" / "kalkan" / "agents"


def test_every_claude_agent_has_a_plugin_agent(sync):
    assert sorted(path.stem for path in PLUGIN_AGENTS.glob("*.md")) == claude_agent_names()
    for name in claude_agent_names():
        source, _ = sync.parse_front_matter(
            (CLAUDE_AGENTS / f"{name}.md").read_text(encoding="utf-8"), name
        )
        text = (PLUGIN_AGENTS / f"{name}.md").read_text(encoding="utf-8")
        fields, body = sync.parse_front_matter(text, name)
        assert sync.GENERATED_MARK in body
        for key in ("name", "tools", "disallowedTools", "maxTurns"):
            assert fields[key] == source[key], f"{name}: {key}"
        assert "/kalkan:kalkan" in fields["description"]
        for key in ("hooks", "mcpServers", "permissionMode", "model"):
            assert key not in fields


def test_plugin_skill_runs_the_engine_from_the_plugin_data_folder(sync):
    text = PLUGIN_SKILL.read_text(encoding="utf-8")
    fields, body = sync.parse_front_matter(text, "plugin skill")
    assert fields["name"] == "kalkan"
    assert fields["disable-model-invocation"] == "true"
    rules = fields["allowed-tools"].split()
    assert "Bash(${CLAUDE_PLUGIN_DATA}/venv/Scripts/kalkan.exe" in rules
    assert "Bash(${CLAUDE_PLUGIN_DATA}/venv/bin/kalkan" in rules
    for term in (".venv/", "scripts/bootstrap", "repository root"):
        assert term not in text, f"checkout-only term {term!r} in the plugin skill"
    assert "sh ${CLAUDE_PLUGIN_ROOT}/bin/kalkan-setup ${CLAUDE_PLUGIN_DATA}" in body
    assert "`kalkan:kalkan-hunter`" in body
    assert "runs folder `~/kalkan-runs`" in body
    assert not re.search(r"(?<![\w./\\~-])/kalkan(?!:kalkan)\b", text)


def test_plugin_skill_prints_the_unattended_command(sync):
    fields, body = sync.parse_front_matter(PLUGIN_SKILL.read_text(encoding="utf-8"), "skill")
    assert "unattended <target>" in fields["argument-hint"]
    assert "the first argument is `unattended`, do not start an audit" in body
    # The skill copies the commands from the setup output: the labels must match.
    setup = (ROOT / "plugins" / "kalkan" / "bin" / "kalkan-setup").read_text(encoding="utf-8")
    for label in (sync.PLUGIN_AUDIT_SH, sync.PLUGIN_AUDIT_POWERSHELL):
        assert f"`{label}`" in body
        assert f"printf '{label} " in setup
    # The checkout skill and the Codex skill have no unattended request.
    assert "Unattended request" not in CODEX_SKILL.read_text(encoding="utf-8")


def test_kalkan_subagents_run_in_the_foreground():
    # A live headless run: the orchestrator started the subagents in the background and ended
    # its turn; Claude Code stopped them 10 minutes later and their work was lost.
    for path in (ROOT / ".claude" / "skills" / "kalkan" / "SKILL.md", PLUGIN_SKILL):
        text = path.read_text(encoding="utf-8")
        assert "set the Agent tool parameter `run_in_background` to `false`" in text
        assert "Never start a kalkan subagent in the background." in text
        assert "Wait until all of them have returned. Then run `kalkan task complete" in text
    codex = CODEX_SKILL.read_text(encoding="utf-8")
    assert "run_in_background" not in codex and "background" not in codex
    assert "Wait until all of them have finished (for example with `wait_agent`)" in codex


#: A backticked engine command in a skill: `kalkan run ...` or `kalkan task ...`.
_ENGINE_COMMAND = re.compile(r"`(kalkan (?:run|task) [^`]*)`")
#: The only engine commands that run before the skill knows its run ID.
_BEFORE_THE_RUN_ID = {
    "kalkan run resume --json",
    'kalkan run init "<target>" --profile <profile> --json',
}


def test_every_engine_command_after_the_start_names_the_run():
    # A live problem (2026-10-16): parallel audits move runs/LATEST, and an orchestrator that
    # relies on it drives another run. Every command after the start must carry --run.
    for path in (ROOT / ".claude" / "skills" / "kalkan" / "SKILL.md", PLUGIN_SKILL, CODEX_SKILL):
        text = path.read_text(encoding="utf-8")
        commands = _ENGINE_COMMAND.findall(text)
        assert len(commands) >= 15, path
        unbound = {command for command in commands if "--run <run-id>" not in command}
        assert unbound == _BEFORE_THE_RUN_ID, path
        assert "(`devam <run-id>` or `devam --run <run-id>`)" in text
        assert "write `--no-latest` before `--json` in the `run init` command" in text
        assert "never use an engine command without `--run`" in text


def test_the_skill_takes_the_round_prompt_of_kalkan_unattended(sync):
    # kalkan unattended sends "<skill> devam <run-id> --headless" (kalkan.unattended.loop).
    from kalkan.unattended.loop import resume_prompt

    run_id = "20261016T151915Z-billing-5fc6"
    assert resume_prompt(run_id, "/kalkan:kalkan") == f"/kalkan:kalkan devam {run_id} --headless"
    assert resume_prompt(run_id, "$kalkan") == f"$kalkan devam {run_id} --headless"
    for path in (ROOT / ".claude" / "skills" / "kalkan" / "SKILL.md", PLUGIN_SKILL):
        text = path.read_text(encoding="utf-8")
        fields, _ = sync.parse_front_matter(text, "skill")
        assert "resume [<run-id>] [--headless]" in fields["argument-hint"]
        assert "When the first argument is `devam` or `resume`" in text  # the round prompt


def test_done_summary_names_the_executive_summary():
    for path in (ROOT / ".claude" / "skills" / "kalkan" / "SKILL.md", PLUGIN_SKILL, CODEX_SKILL):
        assert "the paths of `EXECUTIVE.html`" in path.read_text(encoding="utf-8")
