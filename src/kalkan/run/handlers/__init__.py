# SPDX-License-Identifier: MIT
"""Registry of the engine handlers that ``task complete`` runs per task type
(docs/ENGINE-SPEC.md, section 18).

A handler module is ``kalkan.run.handlers.<task type>`` and exposes
``handle(ctx, task, result) -> None``:

- ``ctx`` is the :class:`kalkan.run.state.RunContext` of the run.
- ``task`` is a copy of the task record with an added ``id`` field.
- ``result`` is the parsed result, already checked against ``task-<type>.schema.json`` and
  for its ``task_id``.

A handler raises :class:`~kalkan.errors.ValidationError` when the result fails a semantic check;
the attempt then counts as failed. It runs outside the run lock, writes its derived files
atomically and must be idempotent: after a crash, ``task complete`` runs it again for the same
result. To create follow-up tasks it calls :func:`kalkan.run.queue.create_task` with a
``dedupe_key``, so a second run does not create duplicates.

:func:`get_handler` imports the module lazily. When the module does not exist yet, it returns
:func:`default_handler`, which stores nothing extra (``result.json`` stays in place).
"""

from __future__ import annotations

import importlib
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from kalkan.errors import StateError
from kalkan.run.state import TASK_TYPES

if TYPE_CHECKING:
    from kalkan.run.state import RunContext

__all__ = ["Handler", "default_handler", "get_handler"]

Handler = Callable[["RunContext", dict[str, Any], dict[str, Any]], None]


def default_handler(ctx: RunContext, task: dict[str, Any], result: dict[str, Any]) -> None:
    """Handler for task types without a handler module: it stores nothing extra."""
    del ctx, task, result


def get_handler(task_type: str) -> Handler:
    """Return the ``handle`` function of ``kalkan.run.handlers.<task_type>``.

    Returns :func:`default_handler` when that module does not exist. Raises ``ValueError`` for
    an unknown task type, :class:`~kalkan.errors.StateError` when the module has no callable
    ``handle``, and re-raises every other import error (for example a missing dependency
    inside the module).
    """
    if task_type not in TASK_TYPES:
        raise ValueError("unknown task type")
    module_name = f"{__name__}.{task_type}"
    try:
        module = importlib.import_module(module_name)
    except ModuleNotFoundError as exc:
        if exc.name == module_name:
            return default_handler
        raise
    handle = getattr(module, "handle", None)
    if not callable(handle):
        raise StateError(f"handler module {module_name} has no handle() function")
    return handle
