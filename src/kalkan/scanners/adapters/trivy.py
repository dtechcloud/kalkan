# SPDX-License-Identifier: MIT
"""Trivy misconfiguration and secret scan (ENGINE-SPEC 13). Vulnerabilities belong to SCA.

Command line, checked against ``trivy fs --help`` of the pinned version 0.75.0::

    trivy fs --scanners misconfig,secret --format sarif --output <out>
        --disable-telemetry --skip-version-check --no-progress --offline-scan --timeout 3600s
        --skip-db-update --skip-java-db-update --config "" --ignorefile "" --secret-config ""
        [--misconfig-scanners <LOCAL_MISCONFIG_SCANNERS> --skip-check-update] <target>

Network (docs/SECURITY.md): ``--disable-telemetry`` and ``--skip-version-check`` stop the
calls to Aqua, ``--offline-scan`` the dependency lookups, ``--skip-db-update`` and
``--skip-java-db-update`` any database download (the misconfig and secret scanners need none),
and in local mode (the default) ``--skip-check-update`` the checks bundle download from the OCI
registry: the cached bundle is used, else the one embedded in the binary.

Local mode also leaves Trivy's ``helm`` misconfig scanner out (``--misconfig-scanners``: the
0.75.0 default list without ``helm``): when Trivy renders a chart it validates the values
against the ``values.schema.json`` of the chart and fetches the remote ``$ref`` documents of that
schema (the proxy trap saw ``CONNECT`` to the schema host on 2026-10-25); no option turns that
off. The ``helm-checkov`` adapter renders the charts offline instead. ``--online`` keeps the
default list.

Differences from the first section 13 draft: ``--offline-scan`` (Trivy resolves ``pom.xml``
dependencies in Maven Central even for a misconfig and secret scan; a rate limit answer (HTTP
429) then stops the whole scan with a fatal error; tested), ``--no-progress`` (no progress
bars in the log), ``--timeout 3600s`` (the Trivy default of 5 minutes would stop a large scan
before the kalkan limit; the kalkan limit stays the outer bound), the empty configuration
values and, in local mode, ``--skip-check-update`` (the checks bundle embedded in the binary is used
when no bundle is cached; tested). The working directory is ``scans/``. URIs in the SARIF are
relative to the target.

Suppressions (ADR-0003): ``--config ""``, ``--ignorefile ""`` and ``--secret-config ""`` load
no ``trivy.yaml``, ``.trivyignore`` or ``trivy-secret.yaml``. Inline ``trivy:ignore`` comments
stay effective: Trivy 0.75.0 has no option to turn them off, and ``--show-suppressed`` does
not bring misconfiguration results back (tested). With ``honor_suppressions`` the
``.trivyignore`` (or ``.trivyignore.yaml``) and ``trivy-secret.yaml`` of the target root are
passed explicitly; ``trivy.yaml`` is general configuration and is never loaded.
"""

from __future__ import annotations

from pathlib import Path

from kalkan.scanners.base import ScanContext, ToolAdapter

#: Trivy's own scan timeout. The kalkan process timeout is the real limit.
INTERNAL_TIMEOUT = "3600s"
IGNORE_FILES = (".trivyignore", ".trivyignore.yaml")
SECRET_CONFIG = "trivy-secret.yaml"
#: The misconfig scanners of local mode: the Trivy 0.75.0 default list without ``helm``.
LOCAL_MISCONFIG_SCANNERS = (
    "azure-arm,cloudformation,dockerfile,kubernetes,terraform,terraformplan-json,"
    "terraformplan-snapshot,ansible"
)


def _first_file(folder: Path, names: tuple[str, ...]) -> Path | None:
    for name in names:
        path = folder / name
        if path.is_file() and not path.is_symlink():
            return path
    return None


class TrivyAdapter(ToolAdapter):
    """``trivy fs`` with the misconfig and secret scanners."""

    name = "trivy"
    tool = "trivy"
    output = "sarif-file"
    output_dir = "scans"
    output_name = "trivy.sarif"
    ok_exit_codes = (0,)
    timeout_seconds = 900

    def _honored_files(self, ctx: ScanContext) -> tuple[Path | None, Path | None]:
        if not ctx.honor_suppressions:
            return None, None
        return (
            _first_file(ctx.target_dir, IGNORE_FILES),
            _first_file(ctx.target_dir, (SECRET_CONFIG,)),
        )

    def arguments(self, ctx: ScanContext, out: Path) -> list[str]:
        ignore_file, secret_config = self._honored_files(ctx)
        args = [
            "fs",
            "--scanners",
            "misconfig,secret",
            "--format",
            "sarif",
            "--output",
            str(out),
            "--disable-telemetry",
            "--skip-version-check",
            "--no-progress",
            "--offline-scan",
            "--timeout",
            INTERNAL_TIMEOUT,
            "--skip-db-update",
            "--skip-java-db-update",
            "--config",
            "",
            "--ignorefile",
            str(ignore_file) if ignore_file else "",
            "--secret-config",
            str(secret_config) if secret_config else "",
        ]
        if ctx.offline:
            args += ["--misconfig-scanners", LOCAL_MISCONFIG_SCANNERS, "--skip-check-update"]
        args.append(str(ctx.target_dir))
        return args

    def suppression_sources(self, ctx: ScanContext) -> tuple[list[str], list[str]]:
        inline = "trivy:ignore inline comments (Trivy 0.75.0 has no option to turn them off)"
        config = "trivy.yaml of the target (general configuration, never loaded: --config '')"
        if not ctx.honor_suppressions:
            return [
                ".trivyignore and .trivyignore.yaml of the target (--ignorefile '')",
                "trivy-secret.yaml of the target (--secret-config '')",
                config,
            ], [inline]
        ignore_file, secret_config = self._honored_files(ctx)
        honored = [inline]
        if ignore_file:
            honored.append(f"{ignore_file.name} of the target root (--ignorefile)")
        if secret_config:
            honored.append(f"{SECRET_CONFIG} of the target root (--secret-config)")
        return [config], honored
