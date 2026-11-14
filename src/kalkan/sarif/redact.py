# SPDX-License-Identifier: MIT
"""Remove the matched text of secret results (class ``hardcoded-secrets``).

A secret result keeps no matched text in any kalkan file (docs/SECURITY.md): not in a SARIF
file of ``scans/``, not in ``candidates.json`` and not in a task input. Its snippets become
:data:`REDACTED`, its message names only the rule, and its fingerprints go (a fingerprint or a
candidate ID that hashes the match would confirm a guessed value).

Before, only the Opengrep rule packs, gitleaks and kingfisher redacted their secret results.
Results of the kalkan Opengrep rules, Bandit, gosec, Trivy, Checkov and the matcher engine
kept the value (self-audit of 2026-11-13). :mod:`kalkan.sarif.ingest` now scrubs every
candidate of the class, and :mod:`kalkan.scanners.base` rewrites the SARIF file.
"""

from __future__ import annotations

import re
from typing import Any, Final

__all__ = [
    "ADAPTER_REDACTED_ENGINES",
    "REDACTED",
    "SECRET_CLASS",
    "redact_result",
    "redacted_snippet",
    "secret_message",
]

SECRET_CLASS: Final = "hardcoded-secrets"
REDACTED: Final = "REDACTED"
#: Engines whose adapter or tool already removes the matched text: gitleaks (``--redact``),
#: kingfisher (the adapter fails a run with an unredacted value) and the Opengrep rule packs
#: (``after_run``). Their message (rule, file, commit) and their fingerprints (commit, no hash
#: of the match) stay; only the snippet rule applies.
ADAPTER_REDACTED_ENGINES: Final = frozenset(
    {"gitleaks", "gitleaks-history", "kingfisher", "kingfisher-history", "opengrep-packs"}
)
#: A snippet that an adapter already redacted: ``REDACTED``, or ``REDACTED (commit <hex>)`` of
#: the history scans (kalkan.scanners.adapters.kingfisher). The commit names no secret.
_ALREADY_REDACTED: Final = re.compile(r"REDACTED(?: \(commit [0-9a-f]{7,64}\))?")


def redacted_snippet(snippet: str) -> str:
    """Return the snippet of a secret result: an adapter's redacted form stays, any other
    text becomes :data:`REDACTED`, an empty snippet stays empty."""
    if not snippet or _ALREADY_REDACTED.fullmatch(snippet):
        return snippet
    return REDACTED


def secret_message(title: str) -> str:
    """Return the message of a secret result: the rule title, no matched text."""
    return f"{title}: hardcoded credential (value redacted by kalkan)"


def redact_result(result: dict[str, Any], title: str) -> None:
    """Remove the matched text of one SARIF result: snippets, message and fingerprints."""
    result["message"] = {"text": secret_message(title)}
    result.pop("fingerprints", None)
    result.pop("partialFingerprints", None)

    def scrub(location: Any) -> None:
        physical = location.get("physicalLocation") if isinstance(location, dict) else None
        if not isinstance(physical, dict):
            return
        for key in ("region", "contextRegion"):
            region = physical.get(key)
            if isinstance(region, dict) and "snippet" in region:
                region["snippet"] = {"text": REDACTED}

    for key in ("locations", "relatedLocations"):
        for location in result.get(key) or []:
            scrub(location)
    for flow in result.get("codeFlows") or []:
        threads = flow.get("threadFlows") if isinstance(flow, dict) else None
        for thread in threads if isinstance(threads, list) else []:
            steps = thread.get("locations") if isinstance(thread, dict) else None
            for step in steps if isinstance(steps, list) else []:
                if isinstance(step, dict):
                    scrub(step.get("location"))
