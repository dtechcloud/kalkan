# SPDX-License-Identifier: MIT
"""The ``recon:merge`` step (docs/PHASES.md section 3, recon).

It reads the results of the done recon tasks and writes:

- ``recon/architecture.md``: the four summaries under headings, then a surface table; about
  1,500 words at most (each summary is cut to 275 words, the table to 60 rows);
- ``recon/surfaces.json``: ``{schema_version, surfaces, id_map}``; surfaces without duplicates
  by (kind, file, line, name), renumbered ``S001``, ``S002``, ...; ``id_map`` maps
  ``<task-id>:<original id>`` to the new ID; a surface with an unsafe file path is dropped;
- ``recon/classes.json``: ``{classes, from_recon, from_candidates}``: the union of
  ``classes_of_interest`` and the classes of deterministic candidates with severity medium or
  higher.

The step is idempotent: the same results give the same files.
"""

from __future__ import annotations

from typing import Any, Final

from kalkan.findings import severity as sev
from kalkan.findings.taxonomy import DEPENDENCY_CLASSES, get_class
from kalkan.run.cleaning import clean_text, cut_words, safe_paths
from kalkan.run.runfiles import (
    ARCHITECTURE_NAME,
    CLASSES_NAME,
    SURFACES_NAME,
    load_candidates,
    read_task_json,
    tasks_of_type,
    write_json,
    write_text,
)
from kalkan.run.state import RunContext

__all__ = ["RECON_KINDS", "merge_recon"]

RECON_KINDS: Final = ("product", "principals", "surfaces", "execution")
SURFACE_KINDS: Final = (
    "http",
    "rpc",
    "queue",
    "cron",
    "cli",
    "webhook",
    "agent-tool",
    "file",
    "other",
)
AUTH_VALUES: Final = ("none", "user", "privileged", "service", "unknown")
_SUMMARY_WORDS: Final = 275
_TABLE_ROWS: Final = 60
_HEADINGS: Final = {
    "product": "Product",
    "principals": "Principals",
    "surfaces": "Surfaces",
    "execution": "Execution",
}
#: Deterministic candidate classes that never become run classes (SCA has its own path).
_NOT_RUN_CLASSES: Final = frozenset({*DEPENDENCY_CLASSES, "code-quality"})


def _cell(value: object, limit: int = 80) -> str:
    text = clean_text(value, limit) if not isinstance(value, int) else str(value)
    return text.replace("|", "\\|") or "-"


def _surface(raw: dict[str, Any]) -> dict[str, Any] | None:
    paths = safe_paths([raw.get("file")])
    name = clean_text(raw.get("name"), 300)
    if not paths or not name:
        return None
    line = raw.get("line")
    kind = raw.get("kind") if raw.get("kind") in SURFACE_KINDS else "other"
    auth = raw.get("auth") if raw.get("auth") in AUTH_VALUES else "unknown"
    return {
        "kind": kind,
        "name": name,
        "file": paths[0],
        "line": line if isinstance(line, int) and not isinstance(line, bool) and line > 0 else None,
        "auth": auth,
        "trust_boundary": clean_text(raw.get("trust_boundary"), 300) or "unknown trust boundary",
        "subsystem": clean_text(raw.get("subsystem"), 200) or "unknown subsystem",
        "notes": clean_text(raw.get("notes"), 500),
    }


def merge_recon(ctx: RunContext) -> dict[str, Any]:
    """Write the three recon files and return ``{results, surfaces, dropped, classes}``."""
    results: dict[str, tuple[str, dict[str, Any]]] = {}
    for task_id, _ in tasks_of_type(ctx.state, "recon", statuses=("done",)):
        result = read_task_json(ctx, task_id, "result.json")
        if isinstance(result, dict) and result.get("kind") in RECON_KINDS:
            results.setdefault(result["kind"], (task_id, result))
    ordered = [(kind, *results[kind]) for kind in RECON_KINDS if kind in results]

    surfaces: list[dict[str, Any]] = []
    keys: dict[tuple[Any, ...], str] = {}
    id_map: dict[str, str] = {}
    dropped = 0
    recon_classes: list[str] = []
    for _, task_id, result in ordered:
        for raw in result.get("surfaces", []):
            if not isinstance(raw, dict):
                continue
            surface = _surface(raw)
            original = f"{task_id}:{raw.get('id')}"
            if surface is None:
                dropped += 1
                continue
            key = (surface["kind"], surface["file"], surface["line"], surface["name"])
            if key in keys:
                id_map[original] = keys[key]
                existing = next(item for item in surfaces if item["id"] == keys[key])
                existing["sources"].append(original)
                continue
            new_id = f"S{len(surfaces) + 1:03d}"
            keys[key] = new_id
            id_map[original] = new_id
            surfaces.append({"id": new_id, **surface, "sources": [original]})
        for slug in result.get("classes_of_interest", []):
            if isinstance(slug, str) and get_class(slug) and slug not in recon_classes:
                recon_classes.append(slug)

    medium = sev.rank("medium")
    candidate_classes: list[str] = []
    for candidate in load_candidates(ctx):
        slug = candidate.get("class")
        severity = candidate.get("severity")
        if (
            isinstance(slug, str)
            and get_class(slug)
            and slug not in _NOT_RUN_CLASSES
            and severity in sev.SEVERITIES
            and sev.rank(severity) >= medium
            and slug not in candidate_classes
        ):
            candidate_classes.append(slug)
    classes = sorted(set(recon_classes) | set(candidate_classes))

    write_json(
        ctx.run_dir / SURFACES_NAME,
        {"schema_version": 1, "surfaces": surfaces, "id_map": id_map},
    )
    write_json(
        ctx.run_dir / CLASSES_NAME,
        {
            "schema_version": 1,
            "classes": classes,
            "from_recon": sorted(recon_classes),
            "from_candidates": sorted(candidate_classes),
        },
    )
    write_text(ctx.run_dir / ARCHITECTURE_NAME, _architecture(ordered, surfaces))
    return {
        "results": len(ordered),
        "surfaces": len(surfaces),
        "dropped": dropped,
        "classes": len(classes),
    }


def _architecture(
    ordered: list[tuple[str, str, dict[str, Any]]], surfaces: list[dict[str, Any]]
) -> str:
    by_kind = {kind: result for kind, _, result in ordered}
    lines = ["# Architecture summary", ""]
    for kind in RECON_KINDS:
        lines.append(f"## {_HEADINGS[kind]}")
        lines.append("")
        result = by_kind.get(kind)
        summary = result.get("summary_md") if isinstance(result, dict) else None
        if isinstance(summary, str) and summary.strip():
            lines.append(cut_words(summary.strip(), _SUMMARY_WORDS))
        else:
            lines.append("(No result for this part of the reconnaissance.)")
        lines.append("")
    lines.append("## Surface table")
    lines.append("")
    if not surfaces:
        lines.append("(No entry surface was reported.)")
    else:
        lines.append("| ID | Kind | Name | File | Auth | Trust boundary | Subsystem |")
        lines.append("|---|---|---|---|---|---|---|")
        for surface in surfaces[:_TABLE_ROWS]:
            location = surface["file"] + (f":{surface['line']}" if surface["line"] else "")
            lines.append(
                f"| {surface['id']} | {surface['kind']} | {_cell(surface['name'])} | "
                f"{_cell(location, 120)} | {surface['auth']} | "
                f"{_cell(surface['trust_boundary'], 60)} | {_cell(surface['subsystem'], 40)} |"
            )
        if len(surfaces) > _TABLE_ROWS:
            lines.append("")
            lines.append(f"({len(surfaces) - _TABLE_ROWS} more surfaces in recon/surfaces.json.)")
    return "\n".join(lines) + "\n"
