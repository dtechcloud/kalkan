# SPDX-License-Identifier: MIT
"""Gitleaks secret scan of the target copy and of the git history (ENGINE-SPEC 13).

Command lines, checked against ``gitleaks dir --help`` and ``gitleaks git --help`` of the pinned
version 8.30.1::

    gitleaks dir <target> --report-format sarif --report-path <out> --redact --no-banner
        --exit-code 0 --config <work>/gitleaks.toml --ignore-gitleaks-allow

    gitleaks git <source>/.git "--log-opts=--full-history --all --diff-filter=tuxdb
        --no-textconv --no-ext-diff" --report-format sarif --report-path <out> --redact
        --no-banner --exit-code 0 --config <work>/gitleaks.toml --ignore-gitleaks-allow

The history engine (``gitleaks-history``) reads only the private history copy of the run,
``<run>/source`` (``run init``: a clone of a git URL with its ``.git`` folder, or a bare mirror of
a local work tree), never the original folder. It runs only when that copy exists inside the
run folder and ``git`` is on PATH; otherwise the skip reason names the ``history`` entry of
``target-manifest.json``. ``gitleaks git`` runs ``git log -p``, and git runs the textconv
filter of a diff driver that the repository config names (``diff.<driver>.textconv``) for
files that ``.gitattributes`` maps to that driver: a crafted local repository would run its
own command. ``--log-opts`` keeps the Gitleaks defaults (``--full-history --all
--diff-filter=tuxdb``) and adds ``--no-textconv --no-ext-diff``. Tested: the default command
runs such a filter, this one does not, and both find a secret in a deleted file.

Suppressions (ADR-0003), all tested:

- ``--ignore-gitleaks-allow`` turns off the ``gitleaks:allow`` comments.
- ``--config`` names a kalkan file (``[extend] useDefault = true``: the default rules, no
  allowlist), so a ``.gitleaks.toml`` of the scanned folder is not loaded.
- ``.gitleaksignore``: Gitleaks always reads the file in the scanned folder, whatever
  ``--gitleaks-ignore-path`` says. For ``dir`` the fingerprints hold the absolute scanned path
  (under ``runs/<run-id>/``), so entries that the target wrote for its own paths never match.
  The history scan reads the ``.git`` folder itself (for a worktree, the folder that the
  ``gitdir:`` line of the ``.git`` file names), so the ``.gitleaksignore`` and
  ``.gitleaks.toml`` of the work tree are not read; paths in the report do not change.
- With ``honor_suppressions`` the tool defaults apply: no ``--config``, no
  ``--ignore-gitleaks-allow``, and the history scan reads the source folder (for a bare mirror
  it is the git folder itself: there is no work tree).

Environment of ``gitleaks git``: ``GIT_TERMINAL_PROMPT=0``, ``GIT_OPTIONAL_LOCKS=0`` (git
writes no lock or index file) and ``GIT_NO_LAZY_FETCH=1`` (git never fetches missing objects
from a remote).

Differences from the first section 13 draft: the ``--log-opts`` value, ``--config``,
``--ignore-gitleaks-allow`` and the ``.git`` folder as history source. The working directory is
``scans/``.
"""

from __future__ import annotations

import json
from pathlib import Path

from kalkan.errors import UnsafeInputError
from kalkan.scanners.adapters import _common
from kalkan.scanners.base import MANIFEST_NAME, ScanContext, ToolAdapter
from kalkan.util.safe_io import read_bounded

#: Gitleaks' own defaults for ``git log`` plus the two options that keep git from running
#: repository-defined programs.
HISTORY_LOG_OPTS = "--full-history --all --diff-filter=tuxdb --no-textconv --no-ext-diff"
#: The kalkan Gitleaks config: the default rules and no allowlist of the target.
CONFIG_NAME = "gitleaks.toml"
CONFIG_TEXT = 'title = "kalkan"\n\n[extend]\nuseDefault = true\n'

_REPORT_FLAGS = ("--redact", "--no-banner", "--exit-code", "0")


def _strict_flags(ctx: ScanContext, out: Path) -> list[str]:
    if ctx.honor_suppressions:
        return []
    return ["--config", str(out.parent / CONFIG_NAME), "--ignore-gitleaks-allow"]


def _write_config(ctx: ScanContext, stage: Path) -> None:
    if not ctx.honor_suppressions:
        (stage.parent / CONFIG_NAME).write_text(CONFIG_TEXT, encoding="utf-8", newline="\n")


def git_dir(source: Path) -> Path | None:
    """Return the git folder of a work tree: ``<source>/.git``, or the folder that the
    ``gitdir:`` line of a ``.git`` file names. None when neither exists."""
    entry = source / ".git"
    if entry.is_dir():
        return entry
    if entry.is_file():
        try:
            text = entry.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
        for line in text.splitlines():
            if line.startswith("gitdir:"):
                target = Path(line.split(":", 1)[1].strip())
                folder = target if target.is_absolute() else source / target
                return folder if folder.is_dir() else None
    return None


def history_git_dir(source: Path) -> Path | None:
    """Return the git folder of the history copy ``source``: ``<source>/.git`` (a URL clone with
    a work tree), or ``source`` itself (the bare mirror of a local work tree). None otherwise."""
    folder = git_dir(source)
    if folder is not None:
        return folder
    if (source / "HEAD").is_file() and (source / "objects").is_dir() and (source / "refs").is_dir():
        return source
    return None


def _inside(path: Path, folder: Path) -> bool:
    try:
        resolved = path.resolve()
    except OSError:
        return False
    base = folder.resolve()
    return resolved != base and resolved.is_relative_to(base)


def _history_detail(run_dir: Path) -> str:
    """Return the ``history.detail`` text of the run manifest, or an empty string."""
    try:
        data = json.loads(read_bounded(run_dir / MANIFEST_NAME, 4 * 1024 * 1024))
    except (UnsafeInputError, ValueError):
        return ""
    history = data.get("history") if isinstance(data, dict) else None
    detail = history.get("detail") if isinstance(history, dict) else None
    return detail.strip() if isinstance(detail, str) else ""


class GitleaksAdapter(ToolAdapter):
    """``gitleaks dir`` over the target copy."""

    name = "gitleaks"
    tool = "gitleaks"
    output = "sarif-file"
    output_dir = "scans"
    output_name = "gitleaks.sarif"
    ok_exit_codes = (0,)
    timeout_seconds = 600

    def arguments(self, ctx: ScanContext, out: Path) -> list[str]:
        return [
            "dir",
            str(ctx.target_dir),
            "--report-format",
            "sarif",
            "--report-path",
            str(out),
            *_REPORT_FLAGS,
            *_strict_flags(ctx, out),
        ]

    def prepare(self, ctx: ScanContext, stage: Path) -> None:
        """Write the kalkan Gitleaks config next to the staging output."""
        _write_config(ctx, stage)

    def suppression_sources(self, ctx: ScanContext) -> tuple[list[str], list[str]]:
        comments = "gitleaks:allow comments"
        config = ".gitleaks.toml of the target"
        ignore_file = ".gitleaksignore of the target"
        if ctx.honor_suppressions:
            return [], [comments, config, ignore_file]
        return [
            f"{comments} (--ignore-gitleaks-allow)",
            f"{config} (--config with the default rules)",
        ], [
            f"{ignore_file}: Gitleaks 8.30.1 always reads it, but the fingerprints hold the "
            "absolute path under runs/, so entries written for other paths never match"
        ]


class GitleaksHistoryAdapter(ToolAdapter):
    """``gitleaks git`` over the git history of the source folder."""

    name = "gitleaks-history"
    tool = "gitleaks"
    output = "sarif-file"
    output_dir = "scans"
    output_name = "gitleaks-history.sarif"
    ok_exit_codes = (0,)
    timeout_seconds = 1200

    def applies(self, ctx: ScanContext) -> tuple[bool, str]:
        if ctx.source_dir is None:
            detail = _history_detail(ctx.run_dir)
            reason = "the run has no private history copy (source/)"
            return False, f"{reason}: {detail}" if detail else reason
        if not _inside(ctx.source_dir, ctx.run_dir):
            return False, "the source folder is outside the run folder (only source/ is scanned)"
        folder = history_git_dir(ctx.source_dir)
        if folder is None or not _inside(folder, ctx.run_dir):
            return False, "the history copy source/ has no git folder (no history to scan)"
        if not _common.git_installed():
            return False, "git is not installed (git not on PATH)"
        return True, ""

    def scan_root(self, ctx: ScanContext) -> Path:
        """Return the folder that ``gitleaks git`` reads: the git folder of the history copy, or
        the copy itself with ``honor_suppressions`` (or when the git folder cannot be found)."""
        assert ctx.source_dir is not None  # applies() checked it
        if ctx.honor_suppressions:
            return ctx.source_dir
        return history_git_dir(ctx.source_dir) or ctx.source_dir

    def arguments(self, ctx: ScanContext, out: Path) -> list[str]:
        return [
            "git",
            str(self.scan_root(ctx)),
            f"--log-opts={HISTORY_LOG_OPTS}",
            "--report-format",
            "sarif",
            "--report-path",
            str(out),
            *_REPORT_FLAGS,
            *_strict_flags(ctx, out),
        ]

    def env(self, ctx: ScanContext) -> dict[str, str]:
        return {"GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0", "GIT_NO_LAZY_FETCH": "1"}

    def prepare(self, ctx: ScanContext, stage: Path) -> None:
        """Write the kalkan Gitleaks config next to the staging output."""
        _write_config(ctx, stage)

    def suppression_sources(self, ctx: ScanContext) -> tuple[list[str], list[str]]:
        comments = "gitleaks:allow comments"
        work_tree = ".gitleaks.toml and .gitleaksignore of the work tree"
        if ctx.honor_suppressions:
            return [], [comments, work_tree]
        ignored = [f"{comments} (--ignore-gitleaks-allow)"]
        honored: list[str] = []
        root = self.scan_root(ctx)
        if root != ctx.source_dir:
            ignored.append(f"{work_tree} (the scan reads the .git folder)")
        elif history_git_dir(ctx.source_dir) == ctx.source_dir:
            ignored.append(f"{work_tree} (the history copy is a bare mirror without a work tree)")
        else:
            honored.append(f"{work_tree} (the git folder was not found)")
        return ignored, honored
