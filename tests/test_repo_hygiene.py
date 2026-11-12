"""Repository hygiene checks.

Claude Code discovers `.claude/skills` folders in subdirectories, and agent
hosts load `CLAUDE.md` and `AGENTS.md` files as instructions. Vendored upstream
content must never expose such paths.
"""

import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
THIRD_PARTY = ROOT / "third_party"
SKIP_DIRS = {".git", ".venv", "runs", ".tools", "__pycache__", ".pytest_cache", ".ruff_cache"}
AGENT_DIRS = {".claude", ".agents", ".codex"}
AGENT_FILES = {"CLAUDE.md", "AGENTS.md", "AGENTS.override.md"}


def walk(base: Path):
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        yield Path(dirpath), dirnames, filenames


def test_no_agent_directories_below_the_repository_root():
    offenders = []
    for dirpath, dirnames, _ in walk(ROOT):
        for name in dirnames:
            if name in AGENT_DIRS and dirpath != ROOT:
                offenders.append((dirpath / name).relative_to(ROOT).as_posix())
    assert offenders == []


def test_no_agent_instruction_files_in_third_party():
    offenders = []
    for dirpath, _, filenames in walk(THIRD_PARTY):
        for name in filenames:
            if name in AGENT_FILES:
                offenders.append((dirpath / name).relative_to(ROOT).as_posix())
    assert offenders == []


def test_every_vendored_component_has_license_and_provenance():
    manifest = json.loads((THIRD_PARTY / "MANIFEST.json").read_text(encoding="utf-8"))
    assert manifest["components"], "MANIFEST.json lists no components"
    for component in manifest["components"]:
        folder = THIRD_PARTY / component["name"]
        assert (folder / "UPSTREAM.md").is_file(), component["name"]
        assert (folder / "FILES.sha256").is_file(), component["name"]
        for license_file in component["license_files"]:
            assert (folder / license_file).is_file(), f"{component['name']}: {license_file}"


def test_notice_carries_the_deepsec_notice():
    notice = (ROOT / "NOTICE").read_text(encoding="utf-8")
    assert "This product includes software developed at Vercel, Inc." in notice
