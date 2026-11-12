# SPDX-License-Identifier: MIT
"""Bandit Python scan (ENGINE-SPEC 13). Runs only when the tech list has ``python``.

Command line, checked against ``bandit --help`` of the pinned version 1.9.4::

    bandit -r <target> -f sarif -o <run>/scans/bandit.sarif --exit-zero -q
        --ignore-nosec --ini <run>/scans/.work/bandit/kalkan.bandit

The tool starts through the tool venv (``ResolvedTool.argv``) with UTF-8 I/O
(``PYTHONUTF8=1``), so non-ASCII paths never break the report.

Suppressions (ADR-0003): ``--ignore-nosec`` turns off the ``# nosec`` comments. Without
``--ini``, Bandit searches the whole target for ``.bandit`` files and takes skips, excludes and
levels from one; two such files stop it with exit code 2. ``--ini`` names an empty kalkan file
(only a ``[bandit]`` section), so no target file is read (tested). With ``honor_suppressions``
both options are left out.

Differences from section 13: ``--ignore-nosec`` and ``--ini``.
"""

from __future__ import annotations

from pathlib import Path

from kalkan.scanners.base import PYTHON_TOOL_ENV, ScanContext, ToolAdapter

#: The empty INI file that replaces the ``.bandit`` files of the target.
INI_NAME = "kalkan.bandit"


class BanditAdapter(ToolAdapter):
    """``bandit -r <target> -f sarif``."""

    name = "bandit"
    tool = "bandit"
    output = "sarif-file"
    output_dir = "scans"
    output_name = "bandit.sarif"
    ok_exit_codes = (0,)
    timeout_seconds = 900

    def applies(self, ctx: ScanContext) -> tuple[bool, str]:
        if "python" not in ctx.tech:
            return False, "the target has no Python code (tech tag 'python' missing)"
        return True, ""

    def arguments(self, ctx: ScanContext, out: Path) -> list[str]:
        args = ["-r", str(ctx.target_dir), "-f", "sarif", "-o", str(out), "--exit-zero", "-q"]
        if not ctx.honor_suppressions:
            args += ["--ignore-nosec", "--ini", str(out.parent / INI_NAME)]
        return args

    def prepare(self, ctx: ScanContext, stage: Path) -> None:
        """Write the empty INI file next to the staging output."""
        if not ctx.honor_suppressions:
            (stage.parent / INI_NAME).write_text("[bandit]\n", encoding="utf-8", newline="\n")

    def suppression_sources(self, ctx: ScanContext) -> tuple[list[str], list[str]]:
        sources = ["# nosec comments", ".bandit files of the target"]
        if ctx.honor_suppressions:
            return [], sources
        return [f"{sources[0]} (--ignore-nosec)", f"{sources[1]} (--ini with an empty file)"], []

    def env(self, ctx: ScanContext) -> dict[str, str]:
        return dict(PYTHON_TOOL_ENV)
