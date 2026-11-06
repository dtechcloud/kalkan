# SPDX-License-Identifier: MIT
"""Read and write the derived files of a run (docs/ENGINE-SPEC.md section 10, docs/PHASES.md).

Every reader here is forgiving: a missing, unsafe or malformed file gives an empty value, so a
phase step can continue when an earlier step was skipped or failed. Every writer is atomic.
"""

from __future__ import annotations

import os
from collections.abc import Iterable
from pathlib import Path
from typing import Any, Final

from kalkan.errors import KalkanError
from kalkan.findings.fingerprint import GetLines
from kalkan.run.source import make_get_lines
from kalkan.run.state import RunContext, parse_task_id
from kalkan.schema.validator import parse_json_text
from kalkan.util.safe_io import atomic_write_json, atomic_write_text, read_text_bounded

__all__ = [
    "ARCHITECTURE_NAME",
    "CANDIDATES_NAME",
    "CLASSES_NAME",
    "FINDINGS_NAME",
    "LEDGER_NAME",
    "MANIFEST_NAME",
    "RECON_DIR",
    "SURFACES_NAME",
    "VULNS_NAME",
    "architecture_text",
    "load_candidates",
    "load_classes",
    "load_surfaces",
    "load_vulns",
    "read_json",
    "read_task_json",
    "run_compose_files",
    "run_tech",
    "target_get_lines",
    "task_input",
    "tasks_of_type",
    "verify_findings",
    "write_json",
    "write_text",
]

RECON_DIR: Final = "recon"
ARCHITECTURE_NAME: Final = "recon/architecture.md"
SURFACES_NAME: Final = "recon/surfaces.json"
CLASSES_NAME: Final = "recon/classes.json"
LEDGER_NAME: Final = "coverage-ledger.json"
CANDIDATES_NAME: Final = "candidates.json"
VULNS_NAME: Final = "sca/vulns.json"
MANIFEST_NAME: Final = "target-manifest.json"
FINDINGS_NAME: Final = "findings.json"

#: Bulk files (candidates.json, vulns.json) can be large.
BULK_MAX_BYTES: Final = 64 * 1024 * 1024
DEFAULT_MAX_BYTES: Final = 8 * 1024 * 1024


def read_json(path: str | os.PathLike[str], max_bytes: int = DEFAULT_MAX_BYTES) -> Any:
    """Return the parsed JSON of ``path``, or None when it is missing, unsafe or invalid."""
    try:
        return parse_json_text(read_text_bounded(path, max_bytes))
    except (KalkanError, OSError, ValueError):
        return None


def write_json(path: str | os.PathLike[str], obj: object) -> None:
    """Write ``obj`` atomically in the kalkan JSON format; create the parent folder."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_json(target, obj)


def write_text(path: str | os.PathLike[str], text: str) -> None:
    """Write ``text`` atomically; create the parent folder."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(target, text)


def run_tech(ctx: RunContext) -> list[str]:
    """Return the detected tech tags of the run (``target-manifest.json``)."""
    manifest = read_json(ctx.run_dir / MANIFEST_NAME)
    tech = manifest.get("tech") if isinstance(manifest, dict) else None
    if not isinstance(tech, list):
        return []
    return sorted({item.strip().lower() for item in tech if isinstance(item, str) and item.strip()})


def run_compose_files(ctx: RunContext) -> list[str]:
    """Return the compose files of the target (``target-manifest.json`` ``deployments``)."""
    manifest = read_json(ctx.run_dir / MANIFEST_NAME)
    deployments = manifest.get("deployments") if isinstance(manifest, dict) else None
    sets = deployments.get("sets") if isinstance(deployments, dict) else None
    return sorted(
        item["path"]
        for item in (sets if isinstance(sets, list) else [])
        if isinstance(item, dict)
        and item.get("kind") == "compose"
        and isinstance(item.get("path"), str)
    )


def load_candidates(ctx: RunContext) -> list[dict[str, Any]]:
    """Return the deterministic candidates of ``candidates.json`` (records that are objects)."""
    document = read_json(ctx.run_dir / CANDIDATES_NAME, BULK_MAX_BYTES)
    items = document.get("candidates") if isinstance(document, dict) else document
    if not isinstance(items, list):
        return []
    return [item for item in items if isinstance(item, dict) and isinstance(item.get("id"), str)]


def load_vulns(ctx: RunContext) -> list[dict[str, Any]]:
    """Return the SCA records of ``sca/vulns.json``."""
    document = read_json(ctx.run_dir / VULNS_NAME, BULK_MAX_BYTES)
    items = document.get("records") if isinstance(document, dict) else document
    if not isinstance(items, list):
        return []
    return [item for item in items if isinstance(item, dict)]


def load_surfaces(ctx: RunContext) -> list[dict[str, Any]]:
    """Return the merged recon surfaces (``recon/surfaces.json``)."""
    document = read_json(ctx.run_dir / SURFACES_NAME)
    items = document.get("surfaces") if isinstance(document, dict) else None
    if not isinstance(items, list):
        return []
    return [item for item in items if isinstance(item, dict) and isinstance(item.get("id"), str)]


def load_classes(ctx: RunContext) -> list[str]:
    """Return the run classes (``recon/classes.json``)."""
    document = read_json(ctx.run_dir / CLASSES_NAME)
    items = document.get("classes") if isinstance(document, dict) else None
    if not isinstance(items, list):
        return []
    return [item for item in items if isinstance(item, str)]


def architecture_text(ctx: RunContext) -> str:
    """Return ``recon/architecture.md``, or an empty string."""
    try:
        return read_text_bounded(ctx.run_dir / ARCHITECTURE_NAME, 1024 * 1024)
    except (KalkanError, OSError):
        return ""


def target_get_lines(ctx: RunContext) -> GetLines:
    """Return the ``get_lines`` callable for the target copy of the run (docs/PHASES.md 4)."""
    return make_get_lines(ctx.target_dir)


def tasks_of_type(
    state: dict[str, Any],
    task_types: str | Iterable[str],
    *,
    statuses: Iterable[str] | None = None,
) -> list[tuple[str, dict[str, Any]]]:
    """Return ``(task_id, task)`` pairs of the given types (and statuses), in sequence order."""
    wanted = {task_types} if isinstance(task_types, str) else set(task_types)
    allowed = None if statuses is None else set(statuses)
    found = [
        (task["seq"], task_id, task)
        for task_id, task in state["tasks"].items()
        if task["type"] in wanted and (allowed is None or task["status"] in allowed)
    ]
    return [(task_id, task) for _, task_id, task in sorted(found, key=lambda item: item[0])]


def read_task_json(ctx: RunContext, task_id: str, name: str) -> Any:
    """Return the parsed ``tasks/<task_id>/<name>``, or None."""
    if parse_task_id(task_id) is None:
        return None
    return read_json(ctx.task_dir(task_id) / name)


def task_input(ctx: RunContext, task_id: str) -> dict[str, Any]:
    """Return ``tasks/<task_id>/input.json`` (an empty object when it cannot be read)."""
    data = read_task_json(ctx, task_id, "input.json")
    return data if isinstance(data, dict) else {}


def verify_findings(ctx: RunContext) -> list[tuple[str, dict[str, Any]]]:
    """Return ``(task_id, finding)`` for every done verify task with a ``finding.json``."""
    found: list[tuple[str, dict[str, Any]]] = []
    for task_id, _ in tasks_of_type(ctx.state, "verify", statuses=("done",)):
        finding = read_task_json(ctx, task_id, "finding.json")
        if isinstance(finding, dict):
            found.append((task_id, finding))
    return found
