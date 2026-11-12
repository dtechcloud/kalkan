# SPDX-License-Identifier: MIT
"""Syft SBOM (ENGINE-SPEC 17, ``sca sbom``): the primary SBOM source.

Command line, checked against ``syft scan --help`` of the pinned version 1.54.0::

    syft scan dir:<target> -o cyclonedx-json=<run>/sca/sbom.cdx.json

``SYFT_CHECK_FOR_APP_UPDATE=false`` stops the update check. Syft needs no network for a
folder scan. Its network features are off by default, and :data:`NETWORK_OFF` sets each one off
explicitly, so a ``.syft.yaml`` of the user (``enrich: all``) cannot turn one on: environment
variables win over configuration files (checked against ``syft config`` of 1.54.0). Tested:
CycloneDX 1.7 output. Difference from section 17: the explicit network settings.
"""

from __future__ import annotations

from pathlib import Path

from kalkan.scanners.base import ScanContext, ToolAdapter

#: Every Syft 1.54.0 feature that can use the network, turned off (docs/SECURITY.md).
NETWORK_OFF = {
    "SYFT_CHECK_FOR_APP_UPDATE": "false",
    "SYFT_GOLANG_SEARCH_REMOTE_LICENSES": "false",
    "SYFT_JAVA_USE_NETWORK": "false",
    "SYFT_JAVA_RESOLVE_TRANSITIVE_DEPENDENCIES": "false",
    "SYFT_JAVASCRIPT_SEARCH_REMOTE_LICENSES": "false",
    "SYFT_PYTHON_SEARCH_REMOTE_LICENSES": "false",
    "SYFT_CPP_VCPKG_ALLOW_GIT_CLONE": "false",
}


class SyftAdapter(ToolAdapter):
    """``syft scan dir:<target>`` to a CycloneDX JSON SBOM."""

    name = "syft"
    tool = "syft"
    output = "json-file"
    output_dir = "sca"
    output_name = "sbom.cdx.json"
    ok_exit_codes = (0,)
    timeout_seconds = 900

    def arguments(self, ctx: ScanContext, out: Path) -> list[str]:
        return ["scan", f"dir:{ctx.target_dir}", "-o", f"cyclonedx-json={out}"]

    def env(self, ctx: ScanContext) -> dict[str, str]:
        return dict(NETWORK_OFF)
