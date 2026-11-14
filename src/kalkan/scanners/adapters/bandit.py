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

Test asserts: :meth:`BanditAdapter.after_run` drops the results of B101 (``assert_used``) in
test files (:func:`kalkan.scanners.adapters._sources.is_test_path`). An ``assert`` in a test is
how the test checks its result; in the code it is a finding (``python -O`` removes it). On the
repository of kalkan itself, 8,011 of 8,169 Bandit results were B101 in tests (2026-11-13).
The status records the number (``test_asserts_dropped``). Every other rule stays in tests.

Differences from section 13: ``--ignore-nosec``, ``--ini`` and the dropped test asserts.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Final

from kalkan.errors import KalkanError, ToolError
from kalkan.sarif.uri import normalize_uri
from kalkan.scanners.adapters._sources import is_test_path
from kalkan.scanners.base import PYTHON_TOOL_ENV, Invocation, ScanContext, ToolAdapter
from kalkan.util.safe_io import atomic_write_json, read_bounded

#: The empty INI file that replaces the ``.bandit`` files of the target.
INI_NAME = "kalkan.bandit"
#: The Bandit rule whose results kalkan drops in test files.
TEST_ASSERT_RULE: Final = "B101"
MAX_SARIF_BYTES: Final = 100 * 1024 * 1024


def drop_test_asserts(doc: dict[str, Any], target: Path) -> tuple[dict[str, Any], int]:
    """Return ``doc`` without the :data:`TEST_ASSERT_RULE` results in test files, and their
    number."""
    dropped = 0
    for run in doc.get("runs") or []:
        if not isinstance(run, dict) or not isinstance(run.get("results"), list):
            continue
        bases = run.get("originalUriBaseIds")
        kept = []
        for result in run["results"]:
            if isinstance(result, dict) and result.get("ruleId") == TEST_ASSERT_RULE:
                location = ((result.get("locations") or [{}])[0] or {}).get("physicalLocation")
                artifact = (location or {}).get("artifactLocation") or {}
                rel = normalize_uri(
                    artifact.get("uri", ""), target, bases, uri_base_id=artifact.get("uriBaseId")
                )
                if rel and is_test_path(rel):
                    dropped += 1
                    continue
            kept.append(result)
        run["results"] = kept
    return doc, dropped


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

    def __init__(self) -> None:
        self._test_asserts = 0

    def prepare(self, ctx: ScanContext, stage: Path) -> None:
        """Write the empty INI file next to the staging output."""
        self._test_asserts = 0
        if not ctx.honor_suppressions:
            (stage.parent / INI_NAME).write_text("[bandit]\n", encoding="utf-8", newline="\n")

    def after_run(self, ctx: ScanContext, item: Invocation) -> None:
        """Drop the B101 results in test files (module docstring)."""
        try:
            doc = json.loads(read_bounded(item.output, MAX_SARIF_BYTES))
        except (KalkanError, ValueError) as exc:
            raise ToolError(f"bandit did not write a valid SARIF file: {exc}") from None
        if not isinstance(doc, dict):
            raise ToolError("bandit did not write a SARIF object")
        doc, dropped = drop_test_asserts(doc, ctx.target_dir)
        self._test_asserts += dropped
        atomic_write_json(item.output, doc)

    def status_details(
        self, ctx: ScanContext, stdout_log: Path, stderr_log: Path, outputs: list[Path]
    ) -> dict[str, Any]:
        """Record how many B101 results in test files were dropped."""
        return {"test_asserts_dropped": self._test_asserts}

    def suppression_sources(self, ctx: ScanContext) -> tuple[list[str], list[str]]:
        sources = ["# nosec comments", ".bandit files of the target"]
        if ctx.honor_suppressions:
            return [], sources
        return [f"{sources[0]} (--ignore-nosec)", f"{sources[1]} (--ini with an empty file)"], []

    def env(self, ctx: ScanContext) -> dict[str, str]:
        return dict(PYTHON_TOOL_ENV)
