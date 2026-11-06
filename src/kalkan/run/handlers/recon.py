# SPDX-License-Identifier: MIT
"""Handler of ``recon`` results (docs/PHASES.md section 4).

The result stays in ``tasks/<id>/result.json``; the ``recon:merge`` step reads every done recon
result. The handler only checks that the result answers the ``kind`` of its task.
"""

from __future__ import annotations

from typing import Any

from kalkan.errors import ValidationError
from kalkan.run.runfiles import task_input
from kalkan.run.state import RunContext


def handle(ctx: RunContext, task: dict[str, Any], result: dict[str, Any]) -> None:
    """Check the ``kind`` of a recon result against the task input."""
    wanted = task_input(ctx, task["id"]).get("kind")
    if isinstance(wanted, str) and result.get("kind") != wanted:
        raise ValidationError(
            f"the result of {task['id']} answers another recon kind",
            [f"$result.kind: must be {wanted}"],
        )
