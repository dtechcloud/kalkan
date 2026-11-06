# SPDX-License-Identifier: MIT
"""Handler of ``translate`` results (docs/PHASES.md section 4).

The handler checks that the result translates exactly the findings of its input and writes
``tasks/<id>/translations.json`` (``{translations: [{id, title, description,
remediation_strategy}]}``), which ``kalkan.findings.merge`` turns into ``i18n.en``.
"""

from __future__ import annotations

from typing import Any

from kalkan.errors import ValidationError
from kalkan.run.runfiles import task_input, write_json
from kalkan.run.state import RunContext


def handle(ctx: RunContext, task: dict[str, Any], result: dict[str, Any]) -> None:
    """Check the finding IDs and write ``translations.json``."""
    findings = task_input(ctx, task["id"]).get("findings")
    wanted = [item.get("id") for item in findings or [] if isinstance(item, dict)]
    got = [item["id"] for item in result["translations"]]
    errors = []
    if len(set(got)) != len(got):
        errors.append("$result.translations: every finding ID must appear once")
    missing = sorted(set(wanted) - set(got))
    extra = sorted(set(got) - set(wanted))
    if missing:
        errors.append(f"$result.translations: missing findings {', '.join(missing)}")
    if extra:
        errors.append(f"$result.translations: unknown findings {', '.join(extra)}")
    if errors:
        raise ValidationError(f"the result of {task['id']} does not match its findings", errors)
    write_json(
        ctx.task_dir(task["id"]) / "translations.json",
        {"translations": [dict(item) for item in result["translations"]]},
    )
