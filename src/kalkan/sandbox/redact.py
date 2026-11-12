# SPDX-License-Identifier: MIT
"""Redaction of secret values in the sandbox output (docs/ENGINE-SPEC.md section 23).

A harness runs against a copy of the target, and the target can hold real secrets (a ``.env``
file, a key in a test fixture). The container output, the ``observed_result`` line and the
promoted evidence files go into the run folder and the report, so :func:`redact` replaces every
value that looks like a secret with :data:`REDACTED` before any of them is written.

The patterns are a heuristic: they cover private keys, the common provider token formats, JSON
Web Tokens, credentials in URLs and ``name=value`` pairs whose name says secret. A value that
fits none of them stays. The marker lines of the harness (``KALKAN_POC_OK``,
``KALKAN_POC_FAIL``) are never secrets and stay readable.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Final

__all__ = ["REDACTED", "redact", "redact_file"]

REDACTED: Final = "[REDACTED]"
#: Evidence files larger than this are not rewritten (the promote step caps them at 2 MiB).
_MAX_FILE_BYTES: Final = 4 * 1024 * 1024

# Each pattern replaces the whole match, or only group "v" when the pattern has it.
_PATTERNS: Final = (
    re.compile(
        r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----.*?"
        r"(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----|\Z)",
        re.DOTALL,
    ),
    re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16}\b"),
    re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{30,}\b"),
    re.compile(r"\bgithub_pat_[0-9A-Za-z_]{40,}\b"),
    re.compile(r"\bglpat-[0-9A-Za-z_-]{20,}\b"),
    re.compile(r"\bxox[abposr]-[0-9A-Za-z-]{10,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    re.compile(r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b"),
    re.compile(r"\bsk-(?:proj-|ant-)?[0-9A-Za-z_-]{20,}\b"),
    re.compile(r"\beyJ[0-9A-Za-z_-]{8,}\.eyJ[0-9A-Za-z_-]{8,}\.[0-9A-Za-z_-]{8,}\b"),
    re.compile(r"(?i)\b(?:AccountKey|SharedAccessKey|SharedAccessSignature)=(?P<v>[^;\s\"']+)"),
    re.compile(r"(?i)\bbearer\s+(?P<v>[0-9A-Za-z._~+/-]{12,}=*)"),
    re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^/\s:@\"']+:(?P<v>[^@\s\"'/]+)@"),
    re.compile(
        r"(?i)(?:^|(?<=[\s\"'{,;(]))[\"']?[a-z0-9_.-]*"
        r"(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|"
        r"client[_-]?secret|credential|connection[_-]?string)[a-z0-9_.-]*[\"']?"
        r"\s*[:=]\s*[\"']?(?P<v>[^\s\"',;}{)]{6,})"
    ),
)


def _replace(match: re.Match[str]) -> str:
    if "v" not in (match.re.groupindex or {}):
        return REDACTED
    start, end = match.span("v")
    base = match.start()
    text = match.group(0)
    return text[: start - base] + REDACTED + text[end - base :]


def redact(text: str) -> str:
    """Return ``text`` with every secret-looking value replaced by :data:`REDACTED`."""
    for pattern in _PATTERNS:
        text = pattern.sub(_replace, text)
    return text


def redact_file(path: Path) -> None:
    """Redact a promoted evidence file in place when it is UTF-8 text; leave other files."""
    try:
        if path.is_symlink() or path.stat().st_size > _MAX_FILE_BYTES:
            return
        raw = path.read_bytes()
    except OSError:
        return
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return
    cleaned = redact(text)
    if cleaned != text:
        path.write_bytes(cleaned.encode("utf-8"))
