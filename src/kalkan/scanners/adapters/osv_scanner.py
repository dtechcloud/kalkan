# SPDX-License-Identifier: MIT
"""OSV-Scanner vulnerability match (ENGINE-SPEC 17, ``sca match``).

Command line, checked against ``osv-scanner scan source --help`` of the pinned version 2.6.0::

    osv-scanner scan source -r --no-ignore --allow-no-lockfiles --format json
        --output-file <run>/sca/osv.json --config <run>/sca/.work/osv-scanner/osv-scanner.toml
        [--offline] <target>

Exit code 1 means "vulnerabilities found" and counts as success when the output exists.

Differences from the brief:

- ``--output-file`` instead of ``--output`` (deprecated in v2).
- ``--no-ignore``: a run folder lies inside the kalkan repository, where ``runs/`` is in
  ``.gitignore``; without the flag OSV-Scanner skips every file and exits with 128 "No package
  sources found" (tested).
- ``--allow-no-lockfiles``: a target without manifests gives exit code 0 and an empty
  ``{"results": []}`` instead of exit code 128 and no file (tested).
- Local mode (the default; ``ScanContext.offline``) adds ``--offline``: only the local
  databases, no dependency resolution, no network (docs/SECURITY.md). The environment names
  the kalkan database folder (``OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY``,
  :mod:`kalkan.sca.vulndb`) in both modes. Without any local database the adapter is skipped;
  an ecosystem without a database stops OSV-Scanner (exit code 127, ``could not load db for
  <ecosystem> ecosystem``), and :meth:`OsvScannerAdapter.status_details` records the missing
  ecosystems as ``missing_databases`` (tested). The online mode (``--online``) queries
  api.osv.dev with the package names and versions of the target.
- ``--config`` with an empty file (ADR-0003): an ``osv-scanner.toml`` in a target folder can
  ignore vulnerabilities (``IgnoredVulns``); one such file hid all 66 results of a test target,
  and the empty ``--config`` brought them back (tested). With ``honor_suppressions`` the option
  is left out.

``osv-scanner-pins`` (:class:`OsvScannerPinsAdapter`) scans ``sca/manifest-pins.cdx.json``, the
exact pins of manifests without a lockfile (:mod:`kalkan.sca.manifests`)::

    osv-scanner scan source -L <run>/sca/manifest-pins.cdx.json --no-ignore --format json
        --output-file <run>/sca/osv-pins.json --config <empty file> [--offline]

``-L`` reads one file; a name that ends in ``.cdx.json`` selects the CycloneDX SBOM extractor
(``--sbom`` is deprecated in v2). Tested on 2026-10-16 with a minimal CycloneDX 1.5 file (npm,
Packagist and RubyGems package URLs): every pin was matched, the result ``source.type`` is
``sbom``.
"""

from __future__ import annotations

from pathlib import Path

from kalkan.sca import vulndb
from kalkan.scanners.adapters._common import PINS_SBOM_NAME
from kalkan.scanners.base import ScanContext, ToolAdapter

#: The skip reason without any local OSV database (local mode).
NO_DATABASE = "no local OSV database (run: kalkan sca update-db)"

#: The empty config file that replaces the ``osv-scanner.toml`` files of the target.
CONFIG_NAME = "osv-scanner.toml"


class OsvScannerAdapter(ToolAdapter):
    """``osv-scanner scan source -r --format json``."""

    name = "osv-scanner"
    tool = "osv-scanner"
    output = "json-file"
    output_dir = "sca"
    output_name = "osv.json"
    ok_exit_codes = (0, 1)
    timeout_seconds = 900

    def arguments(self, ctx: ScanContext, out: Path) -> list[str]:
        args = [
            "scan",
            "source",
            "-r",
            "--no-ignore",
            "--allow-no-lockfiles",
            "--format",
            "json",
            "--output-file",
            str(out),
        ]
        if not ctx.honor_suppressions:
            args += ["--config", str(out.parent / CONFIG_NAME)]
        if ctx.offline:
            args.append("--offline")
        args.append(str(ctx.target_dir))
        return args

    def applies(self, ctx: ScanContext) -> tuple[bool, str]:
        if ctx.offline and not vulndb.osv_ecosystems():
            return False, NO_DATABASE
        return True, ""

    def env(self, ctx: ScanContext) -> dict[str, str]:
        return vulndb.osv_env()

    def status_details(
        self, ctx: ScanContext, stdout_log: Path, stderr_log: Path, outputs: list[Path]
    ) -> dict[str, list[str]]:
        """Record the ecosystems that OSV-Scanner found without a local database."""
        try:
            text = stderr_log.read_bytes()[-262144:].decode("utf-8", errors="replace")
        except OSError:
            return {}
        missing = vulndb.missing_from_stderr(text)
        return {"missing_databases": missing} if missing else {}

    def prepare(self, ctx: ScanContext, stage: Path) -> None:
        """Write the empty config file next to the staging output."""
        if not ctx.honor_suppressions:
            (stage.parent / CONFIG_NAME).write_text("", encoding="utf-8", newline="\n")

    def suppression_sources(self, ctx: ScanContext) -> tuple[list[str], list[str]]:
        source = "osv-scanner.toml files of the target (IgnoredVulns, PackageOverrides)"
        if ctx.honor_suppressions:
            return [], [source]
        return [f"{source}: replaced by an empty --config"], []


class OsvScannerPinsAdapter(OsvScannerAdapter):
    """``osv-scanner scan source -L <run>/sca/manifest-pins.cdx.json``: the exact manifest pins."""

    name = "osv-scanner-pins"
    output_name = "osv-pins.json"

    def pins_path(self, ctx: ScanContext) -> Path:
        """Return ``<run>/sca/manifest-pins.cdx.json``."""
        return ctx.run_dir / self.output_dir / PINS_SBOM_NAME

    def applies(self, ctx: ScanContext) -> tuple[bool, str]:
        pins = self.pins_path(ctx)
        if not pins.is_file() or pins.stat().st_size == 0:
            return False, f"no exact manifest pins (sca/{PINS_SBOM_NAME} does not exist)"
        return super().applies(ctx)

    def arguments(self, ctx: ScanContext, out: Path) -> list[str]:
        args = [
            "scan",
            "source",
            "-L",
            str(self.pins_path(ctx)),
            "--no-ignore",
            "--format",
            "json",
            "--output-file",
            str(out),
        ]
        if not ctx.honor_suppressions:
            args += ["--config", str(out.parent / CONFIG_NAME)]
        if ctx.offline:
            args.append("--offline")
        return args
