# SPDX-License-Identifier: MIT
"""Build the ``input.json`` of agent tasks (docs/PHASES.md sections 3 and 4, ENGINE-SPEC 18).

The inputs follow the descriptions in the prompt templates (``kalkan/prompts/<type>.md``). They
stay compact: long text is cut and long lists are capped, so that a prompt never grows without
bound on a large target.
"""

from __future__ import annotations

import os
from collections import Counter
from pathlib import Path
from typing import Any, Final

from kalkan.findings import severity as sev
from kalkan.findings.consolidate import CHUNK_SIZE, CandidateGroup, record_view
from kalkan.findings.review import CHECKLISTS, review_record
from kalkan.findings.taxonomy import DEPENDENCY_CLASSES
from kalkan.run import budget
from kalkan.run.cleaning import clean_text, sink_of
from kalkan.run.ledger_store import live_closure
from kalkan.run.runfiles import (
    architecture_text,
    load_candidates,
    load_surfaces,
    load_vulns,
    read_task_json,
    run_tech,
    tasks_of_type,
    verify_findings,
)
from kalkan.run.state import RunContext

__all__ = [
    "MANIFEST_FILE_NAMES",
    "architecture_excerpt",
    "confirmed_root_causes",
    "consolidate_input",
    "critic_input",
    "deterministic_summary",
    "file_inventory",
    "hunt_input",
    "polish_input",
    "recon_input",
    "review_input",
    "sca_summary",
    "tool_hints",
    "translate_input",
    "verify_input_deterministic",
    "verify_input_hunter",
]

#: File names that count as manifests in the recon inventory.
MANIFEST_FILE_NAMES: Final = frozenset(
    {
        "package.json",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "pyproject.toml",
        "pipfile",
        "pipfile.lock",
        "poetry.lock",
        "setup.py",
        "setup.cfg",
        "go.mod",
        "go.sum",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "settings.gradle",
        "gemfile",
        "gemfile.lock",
        "composer.json",
        "composer.lock",
        "cargo.toml",
        "cargo.lock",
        "docker-compose.yml",
        "docker-compose.yaml",
        "compose.yml",
        "compose.yaml",
        "makefile",
    }
)
_MAX_TOP_LEVEL: Final = 100
_MAX_EXTENSIONS: Final = 60
_MAX_MANIFESTS: Final = 200
_MAX_WALK_FILES: Final = 200_000
_ARCHITECTURE_CHARS: Final = 12_000
_VERIFY_ARCHITECTURE_CHARS: Final = 4_000
_MAX_HINTS: Final = 30
_MAX_OTHER_IDS: Final = 200
_MAX_ROOT_CAUSES: Final = 50
_MAX_NEARBY: Final = 10
_SNIPPET_CHARS: Final = 1_500


def _is_manifest(name: str, parent: str) -> bool:
    lower = name.lower()
    if lower in MANIFEST_FILE_NAMES or lower.startswith("dockerfile"):
        return True
    if lower.endswith((".csproj", ".tf", ".dockerfile", ".sol")):
        return True
    if lower.startswith("requirements") and lower.endswith(".txt"):
        return True
    return parent.lower().endswith(".github/workflows") and lower.endswith((".yml", ".yaml"))


def file_inventory(target_dir: str | os.PathLike[str]) -> dict[str, Any]:
    """Return the recon file inventory of a target copy.

    ``{total_files, top_level: [{name, kind, files}], extensions: {ext: count},
    manifests: [path], truncated}``; symlinks are never followed. The lists are capped so that
    the indented JSON stays near 400 lines.
    """
    root = Path(target_dir)
    top: dict[str, dict[str, Any]] = {}
    extensions: Counter[str] = Counter()
    manifests: list[str] = []
    total = 0
    truncated = False
    stack: list[tuple[Path, str]] = [(root, "")]
    while stack:
        folder, relative = stack.pop()
        try:
            entries = sorted(os.scandir(folder), key=lambda entry: entry.name)
        except OSError:
            continue
        for entry in entries:
            path = f"{relative}/{entry.name}" if relative else entry.name
            try:
                if entry.is_symlink():
                    continue
                is_dir = entry.is_dir(follow_symlinks=False)
            except OSError:
                continue
            first = path.split("/", 1)[0]
            if is_dir:
                top.setdefault(first, {"name": first, "kind": "dir", "files": 0})
                stack.append((Path(entry.path), path))
                continue
            total += 1
            if total > _MAX_WALK_FILES:
                truncated = True
                stack.clear()
                break
            record = top.setdefault(
                first, {"name": first, "kind": "file" if not relative else "dir", "files": 0}
            )
            record["files"] += 1
            suffix = Path(entry.name).suffix.lower() or "(none)"
            extensions[suffix] += 1
            if _is_manifest(entry.name, relative) and len(manifests) < _MAX_MANIFESTS:
                manifests.append(path)
    ordered = sorted(top.values(), key=lambda item: (-item["files"], item["name"]))
    if len(ordered) > _MAX_TOP_LEVEL:
        truncated = True
    return {
        "total_files": total,
        "top_level": ordered[:_MAX_TOP_LEVEL],
        "extensions": dict(extensions.most_common(_MAX_EXTENSIONS)),
        "manifests": sorted(manifests),
        "truncated": truncated or len(extensions) > _MAX_EXTENSIONS,
    }


def deterministic_summary(candidates: list[dict[str, Any]]) -> dict[str, Any]:
    """Return candidate counts by engine, class and severity, and the 20 busiest files."""
    by_engine: Counter[str] = Counter()
    by_class: Counter[str] = Counter()
    by_severity: Counter[str] = Counter()
    by_file: Counter[str] = Counter()
    for candidate in candidates:
        by_engine[str(candidate.get("engine") or "unknown")] += 1
        by_class[str(candidate.get("class") or "unclassified")] += 1
        by_severity[str(candidate.get("severity") or "info")] += 1
        if candidate.get("file"):
            by_file[str(candidate["file"])] += 1
    return {
        "total": len(candidates),
        "by_engine": dict(sorted(by_engine.items())),
        "by_class": dict(by_class.most_common()),
        "by_severity": {name: by_severity[name] for name in sev.SEVERITIES if by_severity[name]},
        "top_files": [{"file": f, "candidates": n} for f, n in by_file.most_common(20)],
    }


def sca_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Return the SCA records by severity and the ten most severe records."""
    counts: Counter[str] = Counter(str(record.get("severity") or "info") for record in records)
    ranked = sorted(
        records,
        key=lambda r: -sev.rank(r["severity"]) if r.get("severity") in sev.SEVERITIES else 0,
    )
    return {
        "total": len(records),
        "by_severity": {name: counts[name] for name in sev.SEVERITIES if counts[name]},
        "top": [
            {
                "package": record.get("package"),
                "version": record.get("version"),
                "vuln_id": record.get("vuln_id"),
                "severity": record.get("severity"),
                "reachability": record.get("reachability"),
            }
            for record in ranked[:10]
        ],
    }


def recon_input(ctx: RunContext, kind: str) -> dict[str, Any]:
    """Return the input of a recon task of ``kind``."""
    return {
        "kind": kind,
        "tech": run_tech(ctx),
        "inventory": file_inventory(ctx.target_dir),
        "deterministic": deterministic_summary(load_candidates(ctx)),
        "sca": sca_summary(load_vulns(ctx)),
    }


def architecture_excerpt(ctx: RunContext, limit: int = _ARCHITECTURE_CHARS) -> str:
    """Return ``recon/architecture.md`` cut to ``limit`` characters."""
    text = architecture_text(ctx)
    if len(text) <= limit:
        return text
    return text[:limit].rsplit("\n", 1)[0] + "\n[...]"


def tool_hints(candidates: list[dict[str, Any]], paths: list[str]) -> list[dict[str, Any]]:
    """Return compact deterministic candidates inside ``paths`` (files or folders), at most 30."""
    if not paths:
        return []
    prefixes = tuple(path.rstrip("/") + "/" for path in paths)
    wanted = set(paths)
    hits = [
        c
        for c in candidates
        if isinstance(c.get("file"), str)
        and c["file"]
        and (c["file"] in wanted or c["file"].startswith(prefixes))
        and c.get("class") not in DEPENDENCY_CLASSES
    ]
    hits.sort(
        key=lambda c: (
            -sev.rank(c["severity"]) if c.get("severity") in sev.SEVERITIES else 0,
            str(c.get("file")),
            c.get("start_line") or 0,
        )
    )
    return [
        {
            "engine": c.get("engine"),
            "rule_id": c.get("rule_id"),
            "class": c.get("class"),
            "severity": c.get("severity"),
            "file": c.get("file"),
            "line": c.get("start_line"),
            "title": clean_text(c.get("title"), 200),
        }
        for c in hits[:_MAX_HINTS]
    ]


def confirmed_root_causes(ctx: RunContext) -> list[dict[str, Any]]:
    """Return the confirmed root causes of the run so far (from done verify tasks)."""
    causes: list[dict[str, Any]] = []
    for _, finding in verify_findings(ctx):
        if finding.get("verdict") != "confirmed":
            continue
        sink = sink_of(finding.get("trace")) or {}
        causes.append(
            {
                "title": clean_text(finding.get("title"), 200),
                "class": finding.get("class"),
                "root_cause": clean_text(finding.get("root_cause"), 300),
                "file": sink.get("file"),
                "line": sink.get("line"),
            }
        )
        if len(causes) >= _MAX_ROOT_CAUSES:
            break
    return causes


def _unit_view(unit: dict[str, Any]) -> dict[str, Any]:
    book = unit.get("kalkan") if isinstance(unit.get("kalkan"), dict) else {}
    return {
        "coverage_id": unit["coverage_id"],
        "surface": unit["surface"],
        "surface_ids": book.get("surface_ids", []),
        "surface_kind": book.get("kind"),
        "auth": book.get("auth"),
        "boundary": unit["boundary"],
        "subsystem": unit["subsystem"],
        "class": unit["attack_class"],
        "starting_paths": list(unit["starting_paths"]),
    }


def hunt_input(
    ctx: RunContext, units: list[dict[str, Any]], other_ids: list[str], wave: int
) -> dict[str, Any]:
    """Return the input of a hunt task for ``units`` (ledger units) in ``wave``."""
    candidates = load_candidates(ctx)
    paths = [path for unit in units for path in unit["starting_paths"]]
    return {
        "wave": wave,
        "profile": ctx.options["profile"],
        "architecture": architecture_excerpt(ctx),
        "units": [_unit_view(unit) for unit in units],
        "other_hunters_coverage_ids": other_ids[:_MAX_OTHER_IDS],
        "confirmed_root_causes": confirmed_root_causes(ctx),
        "tool_hints": tool_hints(candidates, sorted(set(paths))),
    }


def _surfaces_for(ctx: RunContext, files: set[str]) -> list[dict[str, Any]]:
    found = []
    for surface in load_surfaces(ctx):
        if surface.get("file") in files:
            found.append(
                {
                    key: surface.get(key)
                    for key in ("id", "kind", "name", "file", "line", "auth", "trust_boundary")
                }
            )
        if len(found) >= _MAX_NEARBY:
            break
    return found


def _nearby_claims(ctx: RunContext, file: str | None, exclude_ref: str) -> list[dict[str, Any]]:
    claims = []
    if not file:
        return claims
    for _, task in tasks_of_type(ctx.state, "verify"):
        meta = task.get("meta") or {}
        if meta.get("file") == file and meta.get("subject") != exclude_ref:
            claims.append(
                {
                    "ref": meta.get("subject"),
                    "title": meta.get("title"),
                    "fingerprint": meta.get("fingerprint"),
                }
            )
        if len(claims) >= _MAX_NEARBY:
            break
    return claims


def verify_input_hunter(
    ctx: RunContext,
    *,
    ref: str,
    candidate: dict[str, Any],
    fingerprint: str,
    quote_status: list[str],
    checks: list[dict[str, Any]],
) -> dict[str, Any]:
    """Return the input of a verify task for hunter candidate ``ref`` (``<task>#<index>``)."""
    sink = sink_of(candidate.get("trace")) or {}
    files = {item.get("file") for item in candidate.get("trace", []) if isinstance(item, dict)}
    evidence = [
        {**item, "quote_status": status}
        for item, status in zip(candidate.get("evidence", []), quote_status, strict=False)
    ]
    return {
        "subject": {"kind": "hunter", "ref": ref},
        "claim": {
            "title": candidate.get("title"),
            "class": candidate.get("class"),
            "cwe": list(candidate.get("cwe") or []),
            "description": candidate.get("description"),
            "claimed_root_cause": candidate.get("claimed_root_cause"),
            "trace": list(candidate.get("trace") or []),
            "evidence": evidence,
            "suggested_severity": candidate.get("suggested_severity"),
            "dynamic_test": candidate.get("dynamic_test", ""),
            "fingerprint": fingerprint,
        },
        "architecture": architecture_excerpt(ctx, _VERIFY_ARCHITECTURE_CHARS),
        "surfaces": _surfaces_for(ctx, {f for f in files if isinstance(f, str)}),
        "coverage_checks": checks,
        "nearby_claims": _nearby_claims(ctx, sink.get("file"), ref),
    }


def verify_input_deterministic(ctx: RunContext, candidate: dict[str, Any]) -> dict[str, Any]:
    """Return the input of a verify task for a deterministic candidate."""
    file = candidate.get("file") or ""
    line = candidate.get("start_line")
    snippet = str(candidate.get("snippet") or "")[:_SNIPPET_CHARS]
    first_line = next((row.strip() for row in snippet.split("\n") if row.strip()), "")
    evidence = []
    if file and isinstance(line, int) and line >= 1:
        evidence.append({"file": file, "line": line, "quote": first_line[:300]})
    return {
        "subject": {"kind": "deterministic", "ref": candidate["id"]},
        "claim": {
            "title": clean_text(candidate.get("title"), 300),
            "class": candidate.get("class"),
            "cwe": list(candidate.get("cwe") or []),
            "description": clean_text(candidate.get("message"), 1000),
            "engine": candidate.get("engine"),
            "rule_id": candidate.get("rule_id"),
            "severity": candidate.get("severity"),
            "file": file,
            "start_line": line,
            "end_line": candidate.get("end_line"),
            "snippet": snippet,
            "trace": [],
            "evidence": evidence,
        },
        "architecture": architecture_excerpt(ctx, _VERIFY_ARCHITECTURE_CHARS),
        "surfaces": _surfaces_for(ctx, {file} if file else set()),
        "coverage_checks": [],
        "nearby_claims": _nearby_claims(ctx, file or None, candidate["id"]),
    }


def review_input(finding: dict[str, Any]) -> dict[str, Any]:
    """Return the input of a final review task: the canonical record and its checklist.

    The reviewer gets only the canonical record (:func:`kalkan.findings.review.review_record`):
    never the verifier's audit answers, the hunter text or the architecture notes.
    """
    verdict = finding["verdict"]
    return {
        "subject": {
            "finding_id": finding["id"],
            "fingerprint": finding["fingerprint"],
            "verdict": verdict,
        },
        "checklist": list(CHECKLISTS[verdict]),
        "finding": review_record(finding),
    }


def consolidate_input(group: CandidateGroup) -> dict[str, Any]:
    """Return the input of a consolidation task: the records of one candidate group, the links
    that the engine found between them and the place of the group in its component.

    A component of more than :data:`kalkan.findings.consolidate.CHUNK_SIZE` records is split;
    ``component.note`` then says so, and the agent judges only the records of this chunk.
    """
    note = None
    if group.chunks > 1:
        note = (
            f"The engine split {group.component_size} linked records into {group.chunks} chunks "
            f"of at most {CHUNK_SIZE}. This task holds chunk {group.chunk}. Judge only these "
            "records: the records of the other chunks stay separate from them."
        )
    return {
        "records": [record_view(record) for record in group.records],
        "links": [dict(link) for link in group.links],
        "component": {
            "size": group.component_size,
            "chunk": group.chunk,
            "chunks": group.chunks,
            "note": note,
        },
    }


def polish_input(batch: list[dict[str, Any]]) -> dict[str, Any]:
    """Return the input of a polish task: per record the id, the title (for context, also when
    it needs no letters) and the prose fields that need the Turkish letters
    (:func:`kalkan.findings.polish.select_records`)."""
    return {
        "records": [
            {
                "id": record["id"],
                "title": record.get("title"),
                "fields": [
                    {"path": item["path"], "text": item["text"]} for item in record["fields"]
                ],
            }
            for record in batch
        ]
    }


def critic_input(ctx: RunContext, units: list[dict[str, Any]], wave: int) -> dict[str, Any]:
    """Return the input of the coverage critic after hunt wave ``wave``."""
    ledger = []
    for unit in units[:400]:
        ledger.append(
            {
                "coverage_id": unit["coverage_id"],
                "surface": unit["surface"],
                "boundary": unit["boundary"],
                "subsystem": unit["subsystem"],
                "class": unit["attack_class"],
                "status": unit["status"],
                "wave": unit["wave"],
                "reviewed_paths": unit["reviewed_paths"][:20],
                "checks": [
                    {
                        "invariant": clean_text(check.get("invariant"), 300),
                        "result": clean_text(check.get("result"), 300),
                    }
                    for check in unit["local_checks"][:5]
                ],
                "unresolved": unit["unresolved"][:5],
                "closed_from_siblings": live_closure(unit) is not None,
            }
        )
    candidates = []
    for task_id, _ in tasks_of_type(ctx.state, "hunt", statuses=("done",)):
        data = read_task_json(ctx, task_id, "candidates.json")
        for item in (data or {}).get("candidates", []) if isinstance(data, dict) else []:
            candidates.append(
                {
                    key: item.get(key)
                    for key in ("fingerprint", "title", "class", "file", "line", "status")
                }
            )
    surfaces = [
        {key: surface.get(key) for key in ("id", "kind", "name", "file", "auth", "subsystem")}
        for surface in load_surfaces(ctx)[:300]
    ]
    return {
        "wave": wave,
        "profile": ctx.options["profile"],
        "remaining_hunt_budget": budget.available(ctx.state, "hunt"),
        "architecture": architecture_excerpt(ctx),
        "surfaces": surfaces,
        "ledger": ledger,
        "ledger_truncated": len(units) > 400,
        "candidates": candidates[:200],
    }


def translate_input(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Return the input of a translate task for a batch of canonical findings."""
    items = []
    for finding in findings:
        remediation = finding.get("remediation")
        strategy = remediation.get("strategy") if isinstance(remediation, dict) else None
        plan = finding.get("validation_plan")
        plan_text = None
        if isinstance(plan, dict):
            plan_text = plan.get("local") or plan.get("deployment")
        items.append(
            {
                "id": finding["id"],
                "verdict": finding.get("verdict"),
                "title": finding.get("title"),
                "description": finding.get("description"),
                # Findings without remediation (needs_validation, rejected) translate their
                # validation plan or reason in this field.
                "remediation_strategy": strategy
                or plan_text
                or finding.get("reason")
                or finding.get("claimed_root_cause")
                or "",
            }
        )
    return {"findings": items}
