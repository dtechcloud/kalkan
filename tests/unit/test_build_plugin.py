# SPDX-License-Identifier: MIT
"""Tests for scripts/build_plugin.py and the checked-in Claude Code plugin files."""

from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tomllib
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "build_plugin.py"
PLUGIN = ROOT / "plugins" / "kalkan"


@pytest.fixture(scope="module")
def build():
    spec = importlib.util.spec_from_file_location("build_plugin", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
        yield module
    finally:
        sys.modules.pop(spec.name, None)


def project() -> dict:
    with (ROOT / "pyproject.toml").open("rb") as handle:
        return tomllib.load(handle)["project"]


def test_the_plugin_files_are_current(build):
    problems = build.check(ROOT)
    assert problems == [], "run: python scripts/build_plugin.py\n" + "\n".join(problems)


def test_check_mode_exits_zero_on_the_repository(build, capsys):
    assert build.main(["--check"]) == 0
    assert "current" in capsys.readouterr().err


def test_manifests_point_at_the_plugin():
    marketplace = json.loads((ROOT / ".claude-plugin" / "marketplace.json").read_text("utf-8"))
    assert marketplace["name"] == "kalkan"
    assert marketplace["owner"]["name"]
    (entry,) = marketplace["plugins"]
    assert entry == {**entry, "name": "kalkan", "source": "./plugins/kalkan"}
    assert (ROOT / entry["source"]).is_dir()
    manifest = json.loads((PLUGIN / ".claude-plugin" / "plugin.json").read_text("utf-8"))
    assert manifest["name"] == "kalkan"
    assert manifest["version"] == project()["version"]
    assert re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", manifest["name"])


def test_hooks_run_the_launcher_through_sh():
    hooks = json.loads((PLUGIN / "hooks" / "hooks.json").read_text(encoding="utf-8"))
    entries = hooks["hooks"]["PreToolUse"]
    matchers = [entry["matcher"] for entry in entries]
    assert matchers == [
        "Bash",
        "PowerShell",
        "Write|Read|Grep|Glob|NotebookEdit|WebFetch|WebSearch",
        "mcp__.*",
    ]
    commands = []
    for entry in entries:
        for command in entry["hooks"]:
            assert command["type"] == "command"
            assert command["command"].startswith('sh "${CLAUDE_PLUGIN_ROOT}/hooks/pre-tool-use.sh"')
            assert "args" not in command  # shell form: Git Bash on Windows, sh elsewhere
            if entry["matcher"] in ("Bash", "PowerShell"):
                # Bash and PowerShell start the launcher only for commands that mention kalkan
                # or a network program (measured for Bash: echo does not start it).
                assert command["if"].startswith(entry["matcher"] + "(*")
            else:
                assert "if" not in command
            commands.append((entry["matcher"], command["command"]))
    # Unique commands per tool, so that Claude Code never merges two "if" filters.
    assert len(set(commands)) == len(commands)
    bash = [command["if"] for command in entries[0]["hooks"]]
    assert bash[0] == "Bash(*kalkan*)"
    assert {"Bash(*curl*)", "Bash(*http*)", "Bash(*git push*)"} <= set(bash)
    launcher = (PLUGIN / "hooks" / "pre-tool-use.sh").read_bytes()
    assert launcher.startswith(b"#!/bin/sh\n") and b"\r\n" not in launcher
    assert b"-I -m kalkan.plugin_hook" in launcher
    assert b"hook/sessions/*.json" in launcher


@pytest.mark.skipif(shutil.which("sh") is None, reason="needs sh")
def test_the_launcher_filters_unrelated_events(tmp_path):
    """The quick filter: no Python start for an unrelated event unless a session runs an
    audit (a marker exists)."""
    data = tmp_path / "data"
    venv = data / "venv" / ("Scripts" if os.name == "nt" else "bin")
    venv.mkdir(parents=True)
    log = tmp_path / "calls.txt"
    fake = venv / ("python.exe" if os.name == "nt" else "python")
    fake.write_text("placeholder", encoding="utf-8")
    script = (PLUGIN / "hooks" / "pre-tool-use.sh").read_text(encoding="utf-8")
    probe = tmp_path / "probe.sh"
    probe.write_text(
        script.replace('"$python" -I -m kalkan.plugin_hook', f"cat > '{log.as_posix()}'"),
        encoding="utf-8",
        newline="\n",
    )
    env = {**os.environ, "CLAUDE_PLUGIN_DATA": data.as_posix()}

    def run(event: str) -> bool:
        log.unlink(missing_ok=True)
        subprocess.run(["sh", str(probe)], input=event.encode(), env=env, timeout=60, check=True)
        return log.exists()

    assert run('{"tool_name":"WebFetch","session_id":"s1"}') is False
    assert run('{"tool_name":"Read","agent_type":"kalkan:kalkan-hunter"}') is True
    (data / "hook" / "sessions").mkdir(parents=True)
    (data / "hook" / "sessions" / "s1.json").write_text("{}", encoding="utf-8")
    assert run('{"tool_name":"WebFetch","session_id":"s1"}') is True


def test_the_setup_script_installs_the_bundled_wheel_offline():
    script = (PLUGIN / "bin" / "kalkan-setup").read_bytes()
    assert script.startswith(b"#!/bin/sh\n") and b"\r\n" not in script
    text = script.decode("utf-8")
    assert "--no-index --no-deps" in text
    assert "write_home_marker" in text
    assert "tools install --all" in text
    assert "SHA256SUMS" in text


def test_the_wheel_carries_the_data_and_no_bytecode():
    (wheel,) = sorted((PLUGIN / "engine").glob("*.whl"))
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
    assert "kalkan/_data/knowledge/methodology.md" in names
    assert "kalkan/_data/rules/opengrep/python.yaml" in names
    assert "kalkan/prompts/hunt.md" in names
    assert "kalkan/plugin_hook.py" in names
    assert not [name for name in names if name.endswith(".pyc") or "__pycache__" in name]


def test_the_wheel_carries_the_license_texts_of_the_bundled_rule_packs(build):
    (wheel,) = sorted((PLUGIN / "engine").glob("*.whl"))
    licenses = f"kalkan-{project()['version']}.dist-info/licenses/"
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
        metadata = archive.read(f"kalkan-{project()['version']}.dist-info/METADATA").decode()
    # kalkan's own code stays MIT.
    assert "License-Expression: MIT" in metadata
    assert {licenses + "LICENSE", licenses + "NOTICE"} <= names
    # Every vendored upstream project, every bundled rule pack among them, has its license text.
    folders = sorted(path for path in (ROOT / "third_party").iterdir() if path.is_dir())
    assert folders
    for folder in folders:
        assert f"{licenses}third_party/{folder.name}/LICENSE" in names, folder.name
    assert f"{licenses}third_party/gitlab-sast-rules/rules/lgpl/LICENSE" in names
    expected = build.expected_license_files(ROOT, project())
    assert "third_party/trailofbits-semgrep-rules/LICENSE" in expected


def test_a_missing_license_text_makes_the_wheel_stale(build, tmp_path):
    (wheel,) = sorted((PLUGIN / "engine").glob("*.whl"))
    root = tmp_path / "repo"
    for name in ("src", "knowledge", "rules"):
        shutil.copytree(ROOT / name, root / name, ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copyfile(ROOT / "pyproject.toml", root / "pyproject.toml")
    extra = root / "third_party" / "new-pack" / "LICENSE"
    extra.parent.mkdir(parents=True)
    extra.write_text("license\n", encoding="utf-8")
    problems = build.wheel_problems(wheel, root, project())
    assert any("licenses/third_party/new-pack/LICENSE is missing" in p for p in problems)


def test_expected_payload_maps_the_source_folders(build):
    payload = build.expected_payload(ROOT)
    assert "kalkan/cli.py" in payload
    assert any(key.startswith("kalkan/_data/rules/matchers/") for key in payload)
    assert not [key for key in payload if "__pycache__" in key or key.endswith(".pyc")]


def test_a_changed_source_file_makes_the_wheel_stale(build, tmp_path):
    (wheel,) = sorted((PLUGIN / "engine").glob("*.whl"))
    root = tmp_path / "repo"
    for name in ("src", "knowledge", "rules"):
        shutil.copytree(ROOT / name, root / name, ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copyfile(ROOT / "pyproject.toml", root / "pyproject.toml")
    assert build.wheel_problems(wheel, root, project()) == []
    cli = root / "src" / "kalkan" / "cli.py"
    cli.write_bytes(cli.read_bytes() + b"\n# changed\n")
    (root / "knowledge" / "new.md").write_text("x\n", encoding="utf-8")
    problems = build.wheel_problems(wheel, root, project())
    assert any("kalkan/cli.py differs" in p for p in problems)
    assert any("kalkan/_data/knowledge/new.md is missing" in p for p in problems)


def test_check_reports_missing_files(build, tmp_path):
    root = tmp_path / "repo"
    for name in ("src", "knowledge", "rules"):
        shutil.copytree(ROOT / name, root / name, ignore=shutil.ignore_patterns("__pycache__"))
    for name in ("pyproject.toml", "LICENSE", "NOTICE"):
        shutil.copyfile(ROOT / name, root / name)
    problems = build.check(root)
    assert ".claude-plugin/marketplace.json: missing" in problems
    assert any(p.endswith(".whl: missing") for p in problems)
    assert build.main(["--check", "--root", str(root)]) == 1


def test_the_setup_script_copies_the_unattended_launchers():
    text = (PLUGIN / "bin" / "kalkan-setup").read_text(encoding="utf-8")
    assert "install_launchers" in text and "print_launchers" in text
    for name in ("kalkan-unattended", "kalkan-unattended.cmd"):
        assert (PLUGIN / "bin" / name).is_file()
        assert name in text
    # The skill reads the engine path from the last line, so it comes after the launchers.
    tail = text[text.rindex('say "Done."') :]
    assert tail.index("print_launchers") < tail.index(r"printf 'engine: %s\n'")
