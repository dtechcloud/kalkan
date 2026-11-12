# SPDX-License-Identifier: MIT
"""Exception types shared by all kalkan modules."""

from __future__ import annotations


class KalkanError(Exception):
    """Base class for all kalkan errors."""


class UnsafeInputError(KalkanError):
    """An input file or path failed a safety check (symlink, size, encoding or location)."""


class ValidationError(KalkanError):
    """A document failed schema or semantic validation."""

    def __init__(self, message: str, errors: list[str] | None = None) -> None:
        super().__init__(message)
        self.errors: list[str] = list(errors or [])


class ToolError(KalkanError):
    """An external tool is missing, failed, or produced output that kalkan cannot use."""


class StateError(KalkanError):
    """The run state is missing, locked, corrupt, or in an unexpected phase."""
