# SPDX-License-Identifier: MIT
"""Create agent tasks with their rendered prompts (docs/PHASES.md sections 3 and 6).

:func:`new_task` wraps :func:`kalkan.run.queue.create_task`: it creates the task (input.json),
then renders and writes ``tasks/<id>/prompt.md``. The task ID is known only after the creation,
so the prompt is written right after it. :func:`ensure_prompt` renders a missing prompt again;
``run next`` calls it for every task it hands out and ``task prompt`` calls it before printing,
so a crash between the two writes never gives an agent a missing prompt file.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from kalkan.run import prompts, queue
from kalkan.run.runfiles import task_input, write_text
from kalkan.run.state import RunContext, parse_task_id

__all__ = ["ensure_prompt", "find_by_dedupe_key", "new_task"]


def find_by_dedupe_key(state: dict[str, Any], key: str) -> str | None:
    """Return the ID of the task with ``dedupe_key == key``, or None."""
    for task_id, task in state["tasks"].items():
        if task.get("dedupe_key") == key:
            return task_id
    return None


def ensure_prompt(ctx: RunContext, task_id: str) -> Path:
    """Render and write ``tasks/<task_id>/prompt.md`` when it is missing; return its path."""
    path = ctx.task_dir(task_id) / queue.PROMPT_NAME
    if path.is_file():
        return path
    parsed = parse_task_id(task_id)
    assert parsed is not None  # task_dir checked the ID
    text = prompts.render(ctx, parsed[1], task_id, task_input(ctx, task_id))
    write_text(path, text)
    return path


def new_task(
    ctx: RunContext,
    task_type: str,
    phase: str,
    task_input_data: dict[str, Any],
    *,
    priority: int = 50,
    dedupe_key: str | None = None,
    meta: dict[str, Any] | None = None,
    counts_against_budget: bool = True,
    depends_on: tuple[str, ...] = (),
) -> str:
    """Create a task (or return the existing one with ``dedupe_key``) and write its prompt."""
    task_id = queue.create_task(
        ctx,
        task_type,
        phase,
        task_input_data,
        priority=priority,
        depends_on=depends_on,
        counts_against_budget=counts_against_budget,
        dedupe_key=dedupe_key,
        meta=meta,
    )
    ensure_prompt(ctx, task_id)
    return task_id
