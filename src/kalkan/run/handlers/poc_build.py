# SPDX-License-Identifier: MIT
"""Handler of ``poc_build`` results (docs/PHASES.md section 4).

The handler checks the finding ID against the task input and the harness paths (unique, safe,
inside the PoC folder; the compose file is a safe target path). Then:

- ``feasible: false``: ``tasks/<id>/poc.json`` = ``{finding_id, level, status: "blocked",
  observed_result: <reason>, artifacts: [], blocker: "sandbox_infeasible"}``;
- ``feasible: true``: ``tasks/<id>/harness.json`` keeps the harness for the ``poc:run`` step;
  without a sandbox (``kalkan.sandbox.run_poc`` is missing) ``poc.json`` records ``not_run`` with
  the blocker ``sandbox_unavailable``.
"""

from __future__ import annotations

import importlib
from typing import Any

from kalkan.errors import ValidationError
from kalkan.run.runfiles import task_input, write_json
from kalkan.run.state import RunContext
from kalkan.util.paths import is_safe_relative_path


def sandbox_runner() -> Any:
    """Return ``kalkan.sandbox.run_poc`` when the sandbox module provides it, else None."""
    try:
        sandbox = importlib.import_module("kalkan.sandbox")
    except ImportError:
        return None
    runner = getattr(sandbox, "run_poc", None)
    return runner if callable(runner) else None


def handle(ctx: RunContext, task: dict[str, Any], result: dict[str, Any]) -> None:
    """Check a PoC harness and record it (module docstring)."""
    data = task_input(ctx, task["id"])
    finding = data.get("finding") if isinstance(data.get("finding"), dict) else {}
    wanted = data.get("finding_id") or finding.get("id")
    errors = []
    if isinstance(wanted, str) and result["finding_id"] != wanted:
        errors.append(f"$result.finding_id: must be {wanted}")
    directory = ctx.task_dir(task["id"])
    if not result["feasible"]:
        if errors:
            raise ValidationError(f"the result of {task['id']} is not usable", errors)
        write_json(
            directory / "poc.json",
            {
                "finding_id": result["finding_id"],
                "level": "unit",
                "status": "blocked",
                "observed_result": result["reason"],
                "artifacts": [],
                "blocker": "sandbox_infeasible",
            },
        )
        return
    paths = [item["path"] for item in result["files"]]
    if len(set(paths)) != len(paths):
        errors.append("$result.files: every path must be unique")
    errors += [f"$result.files: unsafe path {p!r}" for p in paths if not is_safe_relative_path(p)]
    app = result.get("app")
    if isinstance(app, dict) and not is_safe_relative_path(app["compose_file"]):
        errors.append("$result.app.compose_file: must be a safe target-relative path")
    if errors:
        raise ValidationError(f"the result of {task['id']} is not usable", errors)
    write_json(directory / "harness.json", {key: value for key, value in result.items()})
    if sandbox_runner() is None:
        write_json(
            directory / "poc.json",
            {
                "finding_id": result["finding_id"],
                "level": result["level"],
                "status": "not_run",
                "observed_result": "sandbox_unavailable",
                "artifacts": [],
                "blocker": "sandbox_unavailable",
            },
        )
