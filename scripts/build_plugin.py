# SPDX-License-Identifier: MIT
"""Build the generated parts of the kalkan Claude Code plugin (docs/PLUGIN.md).

A marketplace install copies only the plugin folder `plugins/kalkan/`, so the plugin must carry
the engine. This script writes:

- `.claude-plugin/marketplace.json`: the marketplace `kalkan` with one plugin.
- `plugins/kalkan/.claude-plugin/plugin.json`: the plugin manifest (version from pyproject).
- `plugins/kalkan/engine/kalkan-<version>-py3-none-any.whl`: the engine wheel (`src/kalkan`
  plus `knowledge/` and `rules/` as package data).
- `plugins/kalkan/engine/SHA256SUMS`: the SHA-256 of the wheel; `kalkan-setup` reads it.
- `plugins/kalkan/LICENSE` and `plugins/kalkan/NOTICE`: copies of the repository files.

`scripts/sync_host_files.py` writes the plugin skill and agents. `plugins/kalkan/hooks/` and
`plugins/kalkan/bin/` are written by hand.

Usage (from the repository root):

    python scripts/build_plugin.py           write the files; build a new wheel only when needed
    python scripts/build_plugin.py --check   exit 1 when a file is missing or stale

The wheel build needs `hatchling` (`pip install hatchling`) and no network
(`pip wheel . --no-deps --no-build-isolation`). `--check` needs only the standard library: it
compares the files inside the bundled wheel with `src/kalkan`, `knowledge/` and `rules/`, so
the check does not depend on the hatchling version or on the zip timestamps. The script keeps
the bundled wheel when its content is current, so that git sees no change.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import tomllib
import zipfile
from collections.abc import Sequence
from pathlib import Path

__all__ = ["BuildError", "check", "expected_payload", "main", "wheel_problems", "write"]

ROOT = Path(__file__).resolve().parents[1]

PLUGIN_NAME = "kalkan"
MARKETPLACE_NAME = "kalkan"
PLUGIN_DIR = f"plugins/{PLUGIN_NAME}"
MARKETPLACE_FILE = ".claude-plugin/marketplace.json"
PLUGIN_FILE = f"{PLUGIN_DIR}/.claude-plugin/plugin.json"
ENGINE_DIR = f"{PLUGIN_DIR}/engine"
SUMS_FILE = f"{ENGINE_DIR}/SHA256SUMS"
COPIED_FILES = ("LICENSE", "NOTICE")
REPOSITORY_URL = "https://github.com/dtechcloud/kalkan"

#: Source folder -> folder inside the wheel. Mirrors `[tool.hatch.build.targets.wheel]` and its
#: `force-include` table in pyproject.toml.
WHEEL_SOURCES = (
    ("src/kalkan", "kalkan"),
    ("knowledge", "kalkan/_data/knowledge"),
    ("rules", "kalkan/_data/rules"),
)
#: Names that hatchling leaves out (`.gitignore`).
_SKIP_DIRS = {"__pycache__", "_data"}
_SKIP_SUFFIXES = {".pyc", ".pyo", ".pyd"}
_SKIP_NAMES = {".DS_Store", "Thumbs.db"}

PLUGIN_DESCRIPTION = (
    "Resumable security audit of a local folder or a git URL: pinned deterministic scanners "
    "plus Claude Code subagents, with engine-verified evidence and Turkish or English reports. "
    "Run /kalkan:kalkan <target> [fast|standard|deep]."
)
KEYWORDS = ["security", "audit", "sast", "sca", "code-review"]


class BuildError(Exception):
    """The plugin cannot be built. The message names the cause."""


def _project(root: Path) -> dict:
    with (root / "pyproject.toml").open("rb") as handle:
        project = tomllib.load(handle)["project"]
    if project.get("name") != PLUGIN_NAME:
        raise BuildError("pyproject.toml does not declare the kalkan project")
    return project


def _json_text(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2) + "\n"


def _author(project: dict) -> dict:
    authors = project.get("authors") or [{}]
    return {"name": authors[0].get("name", "kalkan")}


def plugin_manifest(project: dict) -> str:
    """Return `plugin.json`."""
    return _json_text(
        {
            "name": PLUGIN_NAME,
            "version": project["version"],
            "description": PLUGIN_DESCRIPTION,
            "author": _author(project),
            "homepage": REPOSITORY_URL,
            "repository": REPOSITORY_URL,
            "license": project.get("license", "MIT"),
            "keywords": KEYWORDS,
        }
    )


def marketplace_manifest(project: dict) -> str:
    """Return `marketplace.json`."""
    return _json_text(
        {
            "name": MARKETPLACE_NAME,
            "owner": _author(project),
            "metadata": {"description": "The kalkan security audit plugin for Claude Code."},
            "plugins": [
                {
                    "name": PLUGIN_NAME,
                    "source": f"./{PLUGIN_DIR}",
                    "description": PLUGIN_DESCRIPTION,
                }
            ],
        }
    )


def wheel_name(project: dict) -> str:
    """Return the file name of the engine wheel."""
    return f"{PLUGIN_NAME}-{project['version']}-py3-none-any.whl"


def _skipped(relative: Path) -> bool:
    return (
        any(part in _SKIP_DIRS for part in relative.parts[:-1])
        or relative.suffix in _SKIP_SUFFIXES
        or relative.name in _SKIP_NAMES
    )


def expected_payload(root: Path) -> dict[str, bytes]:
    """Return the files that the wheel must hold outside its `.dist-info` folder."""
    payload: dict[str, bytes] = {}
    for source, target in WHEEL_SOURCES:
        base = root / source
        if not base.is_dir():
            raise BuildError(f"{source}: the folder does not exist")
        for path in sorted(base.rglob("*")):
            relative = path.relative_to(base)
            if path.is_file() and not _skipped(relative):
                payload[f"{target}/{relative.as_posix()}"] = path.read_bytes()
    return payload


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def wheel_problems(wheel: Path, root: Path, project: dict) -> list[str]:
    """Return one message per difference between the bundled wheel and the source tree."""
    name = wheel.relative_to(root).as_posix() if wheel.is_relative_to(root) else str(wheel)
    try:
        archive = zipfile.ZipFile(wheel)
    except (OSError, zipfile.BadZipFile) as exc:
        return [f"{name}: not a readable wheel ({exc})"]
    with archive:
        members = {info.filename: info for info in archive.infolist() if not info.is_dir()}
        dist_info = f"{PLUGIN_NAME}-{project['version']}.dist-info/"
        problems = []
        expected = expected_payload(root)
        found = {key for key in members if not key.startswith(dist_info)}
        for missing in sorted(set(expected) - found):
            problems.append(f"{name}: {missing} is missing")
        for extra in sorted(found - set(expected)):
            problems.append(f"{name}: {extra} is not in the source tree")
        for key in sorted(set(expected) & found):
            if _sha256(archive.read(key)) != _sha256(expected[key]):
                problems.append(f"{name}: {key} differs from the source tree")
        entry_points = dist_info + "entry_points.txt"
        if entry_points not in members:
            problems.append(f"{name}: {entry_points} is missing")
        elif "kalkan = kalkan.cli:main" not in archive.read(entry_points).decode("utf-8"):
            problems.append(f"{name}: the kalkan console script is missing")
        if dist_info + "RECORD" not in members:
            problems.append(f"{name}: {dist_info}RECORD is missing")
    return problems


def _sums_text(wheel: Path) -> str:
    return f"{_sha256(wheel.read_bytes())}  {wheel.name}\n"


def _text_files(root: Path, project: dict) -> dict[str, str]:
    files = {
        MARKETPLACE_FILE: marketplace_manifest(project),
        PLUGIN_FILE: plugin_manifest(project),
    }
    for name in COPIED_FILES:
        files[f"{PLUGIN_DIR}/{name}"] = (root / name).read_text(encoding="utf-8")
    return files


def _read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8").replace("\r\n", "\n")
    except FileNotFoundError:
        return None


def check(root: Path = ROOT) -> list[str]:
    """Return one message per missing or stale plugin file. An empty list means current."""
    project = _project(root)
    problems = []
    for relative, content in _text_files(root, project).items():
        current = _read(root / relative)
        if current is None:
            problems.append(f"{relative}: missing")
        elif current != content:
            problems.append(f"{relative}: stale")
    engine = root / ENGINE_DIR
    wheel = engine / wheel_name(project)
    others = sorted(p.name for p in engine.glob("*.whl") if p.name != wheel.name)
    for other in others:
        problems.append(f"{ENGINE_DIR}/{other}: an old wheel")
    if not wheel.is_file():
        problems.append(f"{ENGINE_DIR}/{wheel.name}: missing")
        return problems
    problems.extend(wheel_problems(wheel, root, project))
    sums = _read(root / SUMS_FILE)
    if sums != _sums_text(wheel):
        problems.append(f"{SUMS_FILE}: does not hold the hash of {wheel.name}")
    return problems


def build_wheel(root: Path, out_dir: Path) -> Path:
    """Build the engine wheel with hatchling (no build isolation, no network)."""
    try:
        import hatchling  # noqa: F401
    except ImportError as exc:
        raise BuildError("the wheel build needs hatchling: pip install hatchling") from exc
    command = [
        sys.executable,
        "-m",
        "pip",
        "wheel",
        str(root),
        "--no-deps",
        "--no-build-isolation",
        "--no-index",
        "--disable-pip-version-check",
        "-q",
        "-w",
        str(out_dir),
    ]
    result = subprocess.run(command, shell=False, timeout=600, check=False)
    if result.returncode != 0:
        raise BuildError(f"pip wheel failed with exit code {result.returncode}")
    wheels = sorted(out_dir.glob(f"{PLUGIN_NAME}-*.whl"))
    if len(wheels) != 1:
        raise BuildError(f"pip wheel produced {len(wheels)} kalkan wheels")
    return wheels[0]


def _write_text(path: Path, content: str) -> bool:
    if _read(path) == content:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(content)
    return True


def write(root: Path = ROOT) -> list[str]:
    """Write the plugin files. Return the changed paths."""
    project = _project(root)
    changed = []
    for relative, content in _text_files(root, project).items():
        if _write_text(root / relative, content):
            changed.append(relative)
    engine = root / ENGINE_DIR
    engine.mkdir(parents=True, exist_ok=True)
    wheel = engine / wheel_name(project)
    if not wheel.is_file() or wheel_problems(wheel, root, project):
        with tempfile.TemporaryDirectory(prefix="kalkan-wheel-") as tmp:
            built = build_wheel(root, Path(tmp))
            problems = wheel_problems(built, root, project)
            if problems:
                raise BuildError("the new wheel differs from the source tree: " + problems[0])
            shutil.copyfile(built, wheel)
        changed.append(f"{ENGINE_DIR}/{wheel.name}")
    for other in sorted(engine.glob("*.whl")):
        if other.name != wheel.name:
            other.unlink()
            changed.append(f"{ENGINE_DIR}/{other.name} (removed)")
    if _write_text(root / SUMS_FILE, _sums_text(wheel)):
        changed.append(SUMS_FILE)
    return changed


def main(argv: Sequence[str] | None = None) -> int:
    """Command-line entry point. Return the exit code."""
    parser = argparse.ArgumentParser(description="Build the kalkan Claude Code plugin files.")
    parser.add_argument(
        "--check", action="store_true", help="report missing or stale files and exit 1"
    )
    parser.add_argument("--root", type=Path, default=ROOT, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    root = args.root.resolve()
    try:
        if args.check:
            problems = check(root)
            for problem in problems:
                print(f"drift: {problem}", file=sys.stderr)
            if problems:
                print(
                    "The plugin files are out of date. Run: python scripts/build_plugin.py",
                    file=sys.stderr,
                )
                return 1
            print("The plugin files are current.", file=sys.stderr)
            return 0
        changed = write(root)
    except BuildError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    for relative in changed:
        print(f"wrote {relative}", file=sys.stderr)
    if not changed:
        print("The plugin files are already current.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
