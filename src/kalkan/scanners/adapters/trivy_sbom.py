# SPDX-License-Identifier: MIT
"""Trivy CycloneDX SBOM (ENGINE-SPEC 17): the fallback when Syft is missing or fails.

Command line, checked against ``trivy fs --help`` of the pinned version 0.75.0::

    trivy fs --format cyclonedx --output <run>/sca/sbom.cdx.json --disable-telemetry
        --skip-version-check --no-progress --offline-scan --skip-db-update
        --skip-java-db-update [--skip-check-update] <target>

``--skip-db-update`` and ``--skip-java-db-update``: no database download in any mode; without a
cached Java database Trivy names JAR files without their Maven coordinates.
``--skip-check-update`` in local mode (the default; docs/SECURITY.md).

``--format cyclonedx`` turns the security scanners off, so Trivy downloads no vulnerability
database (tested). ``--offline-scan`` stops the dependency lookups in Maven Central: without it
a rate limit answer (HTTP 429) for a ``pom.xml`` target stops Trivy with a fatal error
(tested). The SBOM then lists the declared Maven dependencies, as Syft does. Differences from
section 17: ``--no-progress``, ``--offline-scan``.
"""

from __future__ import annotations

from pathlib import Path

from kalkan.scanners.base import ScanContext, ToolAdapter


class TrivySbomAdapter(ToolAdapter):
    """``trivy fs --format cyclonedx``."""

    name = "trivy-sbom"
    tool = "trivy"
    output = "json-file"
    output_dir = "sca"
    output_name = "sbom.cdx.json"
    ok_exit_codes = (0,)
    timeout_seconds = 900

    def arguments(self, ctx: ScanContext, out: Path) -> list[str]:
        args = [
            "fs",
            "--format",
            "cyclonedx",
            "--output",
            str(out),
            "--disable-telemetry",
            "--skip-version-check",
            "--no-progress",
            "--offline-scan",
            "--skip-db-update",
            "--skip-java-db-update",
        ]
        if ctx.offline:
            args.append("--skip-check-update")
        args.append(str(ctx.target_dir))
        return args
