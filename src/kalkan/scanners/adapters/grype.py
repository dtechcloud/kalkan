# SPDX-License-Identifier: MIT
"""Grype vulnerability match on the SBOM (ENGINE-SPEC 17, ``sca match``).

Command line, checked against ``grype --help`` of the pinned version 0.119.0::

    grype sbom:<run>/sca/sbom.cdx.json -o json --file <run>/sca/grype.json

Runs only when ``sca/sbom.cdx.json`` exists (Syft or the Trivy fallback wrote it). The
environment comes from :func:`kalkan.sca.vulndb.grype_env`: ``GRYPE_DB_CACHE_DIR`` (the kalkan
database folder), ``GRYPE_CHECK_FOR_APP_UPDATE=false`` and
``GRYPE_EXTERNAL_SOURCES_ENABLE=false`` always; in local mode (the default) also
``GRYPE_DB_AUTO_UPDATE=false``, ``GRYPE_DB_VALIDATE_AGE=false`` and
``GRYPE_DB_REQUIRE_UPDATE_CHECK=false``: Grype uses the local database and never downloads it
or refuses it for its age. Without a local database the adapter is skipped in local mode
(``kalkan sca update-db`` fills it). Tested: without a database Grype exits with 1 and
``failed to load vulnerability db: database does not exist``.

``grype-pins`` (:class:`GrypePinsAdapter`) runs the same command on
``sca/manifest-pins.cdx.json``: the exact pins of manifests without a lockfile, which
:mod:`kalkan.sca.manifests` writes. Output ``sca/grype-pins.json``. Tested on 2026-10-16 with a
minimal CycloneDX 1.5 file (npm, Packagist and RubyGems package URLs): Grype matched every pin.
"""

from __future__ import annotations

from pathlib import Path

from kalkan.sca import vulndb
from kalkan.scanners.adapters._common import PINS_SBOM_NAME
from kalkan.scanners.base import ScanContext, ToolAdapter

SBOM_NAME = "sbom.cdx.json"
#: The skip reason without a local Grype database (local mode).
NO_DATABASE = "no local Grype database (run: kalkan sca update-db)"


class GrypeAdapter(ToolAdapter):
    """``grype sbom:<sbom> -o json``."""

    name = "grype"
    tool = "grype"
    output = "json-file"
    output_dir = "sca"
    output_name = "grype.json"
    ok_exit_codes = (0,)
    timeout_seconds = 900

    def sbom_path(self, ctx: ScanContext) -> Path:
        """Return ``<run>/sca/sbom.cdx.json``."""
        return ctx.run_dir / self.output_dir / SBOM_NAME

    def applies(self, ctx: ScanContext) -> tuple[bool, str]:
        sbom = self.sbom_path(ctx)
        if not sbom.is_file() or sbom.stat().st_size == 0:
            return False, f"no SBOM at sca/{SBOM_NAME}; run syft or trivy-sbom first"
        if ctx.offline and not vulndb.grype_ready():
            return False, NO_DATABASE
        return True, ""

    def arguments(self, ctx: ScanContext, out: Path) -> list[str]:
        return [f"sbom:{self.sbom_path(ctx)}", "-o", "json", "--file", str(out)]

    def env(self, ctx: ScanContext) -> dict[str, str]:
        return vulndb.grype_env(online=not ctx.offline)


class GrypePinsAdapter(GrypeAdapter):
    """``grype sbom:<run>/sca/manifest-pins.cdx.json -o json``: the exact manifest pins."""

    name = "grype-pins"
    output_name = "grype-pins.json"

    def sbom_path(self, ctx: ScanContext) -> Path:
        """Return ``<run>/sca/manifest-pins.cdx.json``."""
        return ctx.run_dir / self.output_dir / PINS_SBOM_NAME

    def applies(self, ctx: ScanContext) -> tuple[bool, str]:
        sbom = self.sbom_path(ctx)
        if not sbom.is_file() or sbom.stat().st_size == 0:
            return False, f"no exact manifest pins (sca/{PINS_SBOM_NAME} does not exist)"
        if ctx.offline and not vulndb.grype_ready():
            return False, NO_DATABASE
        return True, ""
