# SPDX-License-Identifier: MIT
"""The kalkan matcher engine as a built-in adapter (ENGINE-SPEC 13 and 14).

No external tool: :func:`kalkan.matchers.spec.load_specs` loads ``<repo>/rules/matchers`` and
:func:`kalkan.matchers.engine.run` runs the specs over the target with the tech list
(``include_noisy=True``, ``max_file_seconds=20.0``, ``max_total_seconds=900.0``). The
candidates go straight to ``candidates.json`` (no SARIF); their ``raw.sarif_file`` is ``""``.
``stats``, ``skipped`` (slug to reason) and ``warnings`` of the run go into
``scans/matcher.status.json``.
"""

from __future__ import annotations

from pathlib import Path

from kalkan.scanners.base import BuiltinOutcome, ScanContext

#: Warnings written into the status file at most.
MAX_STATUS_WARNINGS = 500


def default_rules_dir() -> Path:
    """Return ``<repo>/rules/matchers``."""
    from kalkan.matchers.spec import default_rules_dir as rules_dir

    return rules_dir()


class MatcherAdapter:
    """The built-in matcher engine."""

    name = "matcher"
    tool: str | None = None
    output = "candidates"
    output_dir = "scans"
    output_name = ""
    ok_exit_codes: tuple[int, ...] = (0,)
    timeout_seconds = 1200
    include_noisy = True
    max_file_seconds = 20.0
    #: The run budget; below ``timeout_seconds``, which the in-process matcher does not enforce.
    max_total_seconds = 900.0

    def __init__(self, rules_dir: Path | None = None) -> None:
        self._rules_dir = rules_dir

    def rules_dir(self) -> Path:
        """Return the matcher spec folder."""
        return self._rules_dir if self._rules_dir is not None else default_rules_dir()

    def applies(self, ctx: ScanContext) -> tuple[bool, str]:
        folder = self.rules_dir()
        if not folder.is_dir():
            return False, f"matcher specs not found: {folder.as_posix()}"
        return True, ""

    def command(self, ctx: ScanContext, tool_path: Path, out: Path) -> list[str]:
        raise NotImplementedError("the matcher runs in process; see collect()")

    def env(self, ctx: ScanContext) -> dict[str, str]:
        return {}

    def collect(self, ctx: ScanContext) -> BuiltinOutcome:
        """Run the matcher engine and return its candidates, warnings and statistics."""
        from kalkan.matchers import engine
        from kalkan.matchers.spec import load_specs

        specs = load_specs(self.rules_dir())
        result = engine.run(
            ctx.target_dir,
            sorted(ctx.tech),
            specs,
            include_noisy=self.include_noisy,
            max_file_seconds=self.max_file_seconds,
            max_total_seconds=self.max_total_seconds,
        )
        stats = result.stats.to_dict()
        applied = stats.get("matchers_applied")
        total = stats.get("matchers_total")
        scanned = stats.get("files_scanned")
        message = f"{applied} of {total} matchers applied, {scanned} files scanned"
        return BuiltinOutcome(
            candidates=list(result.candidates),
            warnings=list(result.warnings),
            message=message,
            details={
                "stats": stats,
                "skipped": dict(result.skipped),
                "warnings": list(result.warnings)[:MAX_STATUS_WARNINGS],
            },
        )

    def __repr__(self) -> str:
        return f"<MatcherAdapter {self.name}>"
