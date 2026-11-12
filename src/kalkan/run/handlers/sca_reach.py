# SPDX-License-Identifier: MIT
"""Handler of ``sca_reach`` results (docs/PHASES.md section 4).

The handler checks ``vuln_ref`` against the task input, verifies every evidence quote with
:func:`kalkan.findings.quote_verify.verify_evidence` and applies the result with
:func:`kalkan.sca.reach.apply_reach_result` (which updates ``sca/vulns.json`` and the SCA
candidates). ``tasks/<id>/reach.json`` records the quote statuses. Without :mod:`kalkan.sca`
the handler records only ``reach.json`` (``applied: false``).
"""

from __future__ import annotations

import importlib
from typing import Any

from kalkan.errors import ValidationError
from kalkan.findings.quote_verify import Evidence, verify_evidence
from kalkan.run.runfiles import target_get_lines, task_input, write_json
from kalkan.run.state import RunContext


def handle(ctx: RunContext, task: dict[str, Any], result: dict[str, Any]) -> None:
    """Verify the quotes of a reachability result and apply it."""
    wanted = task_input(ctx, task["id"]).get("vuln_ref")
    if isinstance(wanted, str) and result["vuln_ref"] != wanted:
        raise ValidationError(
            f"the result of {task['id']} names another vulnerability record",
            [f"$result.vuln_ref: must be {wanted}"],
        )
    get_lines = target_get_lines(ctx)
    statuses = []
    verified: list[Evidence] = []
    for item in result["evidence"]:
        passed = verify_evidence([Evidence(item["file"], item["line"], item["quote"])], get_lines)
        statuses.append({**item, "quote_status": "verified" if passed else "unverified"})
        verified += passed
    applied = False
    try:
        apply_reach_result = importlib.import_module("kalkan.sca.reach").apply_reach_result
    except (ImportError, AttributeError):
        apply_reach_result = None
    if apply_reach_result is not None:
        apply_reach_result(ctx.run_dir, result, verified)
        applied = True
    write_json(
        ctx.task_dir(task["id"]) / "reach.json",
        {
            "task_id": task["id"],
            "vuln_ref": result["vuln_ref"],
            "claimed": result["reachability"],
            "evidence": statuses,
            "verified_quotes": len(verified),
            "applied": applied,
        },
    )
