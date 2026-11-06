# SPDX-License-Identifier: MIT
"""Isolated container sandbox for finding verification (docs/ENGINE-SPEC.md section 23).

The engine uses this module through two names (``kalkan.run.phases`` and ``kalkan.run.steps``):
:func:`docker_available` decides whether the ``poc`` phase runs, and :func:`run_poc` executes one
verification harness in a locked container. When Docker is absent the phase takes ``poc:skip``.
"""

from __future__ import annotations

from kalkan.sandbox.runner import (
    allowed_images,
    docker_available,
    docker_path,
    run_poc,
)

__all__ = ["allowed_images", "docker_available", "docker_path", "run_poc"]
