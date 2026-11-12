# SPDX-License-Identifier: MIT
"""Coverage planning: ledger units, hunt waves and critic tasks (docs/PHASES.md sections 3
and 5). The verify tasks come from :mod:`kalkan.run.validation`.

Groups: recon agents name one subsystem in different ways (``shop/accounts`` and ``accounts``).
:func:`subsystem_groups` joins every surface file with its subsystem label; surfaces that share
a file or a label form one group, named after its most frequent label.

Unit levels (:data:`LEVELS`, fine to coarse):

- ``surface``: one unit per (recon surface, class). Canonical references: surface
  ``<file>#<surface name>``, boundary = the surface trust boundary text, subsystem = the group.
- ``file``: one unit per (file, class); the surfaces of one file merge. Surface
  ``<file>#all-entry-surfaces``, boundary ``<file>#all-trust-boundaries``, subsystem = the group.
- ``subsystem``, ``folder`` and ``all``: one unit per (group, class), where the group is the
  subsystem group, the folder of the file (:func:`folder_of`) or :data:`ALL_GROUP`. Surface
  ``<group>#all-entry-surfaces``. ``fast`` uses the fixed subsystem identity
  ``profile/quick/all-in-scope-subsystems`` (Cloudflare rule; the identity keeps the older
  profile name ``quick``) and the boundary ``profile/quick/all-trust-boundaries``; ``standard`` and
  ``deep`` use the boundary ``<group>#all-trust-boundaries`` and the group as subsystem.

``standard`` and ``deep`` start at ``surface``, ``fast`` at ``subsystem``. The planner takes the
first level from the start whose hunt batches fit :func:`kalkan.run.budget.hunt_wave_cap`; at
the coarsest level the units that do not fit become ``deferred``. Classes of a surface: the run
classes (``recon/classes.json``) that fit the surface kind (:data:`KIND_CLASSES`), plus the
classes of deterministic candidates in the surface's file. ``vulnerable-dependency``,
``malicious-dependency`` and ``code-quality`` never become units (SCA and the report cover
them).

Priority: ``auth: none`` first, then units with deterministic hints, then the class weight
(:data:`CLASS_WEIGHT`), then ``coverage_id``. A hunt batch holds at most
:func:`kalkan.run.budget.batch_size` units (fast 6, standard 4, deep 3) of one group (the
bookkeeping ``group``).

Hunt waves: the profile's critic wave count (fast 1, standard 2, deep 3) is also its hunt wave
count. After every hunt wave the engine allocates the verify tasks of its candidates, then one
critic runs; critic ``n`` schedules hunt wave ``n + 1`` only when ``n + 1`` is within the count,
so fast has exactly one hunt wave and one final critic (Cloudflare quick rule). Task creation
is idempotent through dedupe keys, so a repeated step or handler reuses the tasks it created
before.
"""

from __future__ import annotations

import functools
from collections import Counter
from collections.abc import Iterable
from typing import Any, Final

from kalkan.findings.taxonomy import DEPENDENCY_CLASSES, get_class
from kalkan.run import budget, knowledge
from kalkan.run.cleaning import clean_text, dedupe_key, safe_paths, unique
from kalkan.run.inputs import critic_input, hunt_input
from kalkan.run.ledger_store import (
    FAST_BOUNDARY,
    FAST_SUBSYSTEM,
    assign,
    defer,
    ledger_transaction,
    load_ledger,
    make_unit,
    reset_to_planned,
    save_ledger,
)
from kalkan.run.runfiles import load_candidates, load_classes, load_surfaces, tasks_of_type
from kalkan.run.state import SETTLED_TASK_STATUSES, RunContext, parse_task_id, transaction
from kalkan.run.tasks import find_by_dedupe_key, new_task
from kalkan.run.validation import (
    NON_CODE_CLASSES,
    REASON_VALIDATION,
    allocate_hunter_verifies,
    create_deterministic_verifies,
)
from kalkan.util.text import utf16_key

__all__ = [
    "ALL_GROUP",
    "CLASS_WEIGHT",
    "EXCLUDED_UNIT_CLASSES",
    "KIND_CLASSES",
    "LEVELS",
    "NON_CODE_CLASSES",
    "REASON_BUDGET",
    "REASON_CRITIC_BUDGET",
    "REASON_CRITIC_FAILED",
    "REASON_NO_HUNT",
    "REASON_FAST",
    "REASON_VALIDATION",
    "REASON_WAVES",
    "START_LEVEL",
    "agent_id_of",
    "build_units",
    "choose_units",
    "classes_for_surface",
    "companion_blocks",
    "create_critic",
    "create_deterministic_verifies",
    "create_hunt_wave",
    "defer_planned",
    "folder_of",
    "form_batches",
    "gap_unit",
    "hunt_idle",
    "hunt_waves",
    "level_unit",
    "mark_incomplete",
    "order_units",
    "plan_ledger",
    "plan_tasks",
    "subsystem_groups",
]

_WEB: Final = (
    "sqli",
    "nosqli",
    "os-command-injection",
    "code-injection",
    "ssti",
    "xss",
    "ssrf",
    "path-traversal",
    "file-upload",
    "xxe",
    "deserialization",
    "authn",
    "jwt",
    "oauth-oidc-saml",
    "missing-authz",
    "idor",
    "multi-tenant",
    "csrf",
    "open-redirect",
    "cors",
    "mass-assignment",
    "business-logic",
    "race-condition",
    "graphql",
    "prototype-pollution",
    "dos-redos",
    "request-smuggling-crlf-cache",
    "rate-limit-bruteforce",
    "sensitive-data-exposure",
    "llm-ai",
)
_JOBS: Final = (
    "deserialization",
    "os-command-injection",
    "code-injection",
    "sqli",
    "race-condition",
    "business-logic",
    "multi-tenant",
)
#: Surface kind -> classes that fit it (docs/PHASES.md section 5). ``other``: every run class.
KIND_CLASSES: Final[dict[str, tuple[str, ...] | None]] = {
    "http": _WEB,
    "rpc": _WEB,
    "webhook": ("webhook-replay", "deserialization", "ssrf", "authn", "business-logic"),
    "queue": _JOBS,
    "cron": _JOBS,
    "cli": ("os-command-injection", "path-traversal", "code-injection", "deserialization"),
    "file": (
        "path-traversal",
        "file-upload",
        "xxe",
        "deserialization",
        "iac-cloud-container",
        "supply-chain-cicd",
        "hardcoded-secrets",
        "security-misconfig",
    ),
    "agent-tool": ("llm-ai", "ssrf", "os-command-injection", "path-traversal"),
    "other": None,
}
#: Classes that never become ledger units.
EXCLUDED_UNIT_CLASSES: Final = frozenset({*DEPENDENCY_CLASSES, "code-quality"})
#: Class severity weight for the unit priority (3 high impact, 1 low impact; default 2).
CLASS_WEIGHT: Final = {
    **dict.fromkeys(
        (
            "os-command-injection",
            "code-injection",
            "sqli",
            "nosqli",
            "deserialization",
            "ssti",
            "xxe",
            "authn",
            "missing-authz",
            "idor",
            "jwt",
            "oauth-oidc-saml",
            "multi-tenant",
            "path-traversal",
            "ssrf",
            "file-upload",
            "memory-safety",
            "smart-contract",
        ),
        3,
    ),
    **dict.fromkeys(
        (
            "cors",
            "open-redirect",
            "security-misconfig",
            "dos-redos",
            "rate-limit-bruteforce",
            "mobile-desktop-ipc",
            "code-quality",
        ),
        1,
    ),
}

#: Unit levels from fine to coarse (module docstring).
LEVELS: Final = ("surface", "file", "subsystem", "folder", "all")
#: The finest level of each profile.
START_LEVEL: Final = {"fast": "subsystem", "standard": "surface", "deep": "surface"}
#: The group name of the coarsest level.
ALL_GROUP: Final = "all-in-scope-code"
REASON_BUDGET: Final = "budget_cannot_reserve_critics_and_validation"
REASON_FAST: Final = "fast_profile_final_critic"
REASON_WAVES: Final = "hunt_waves_exhausted"
REASON_CRITIC_BUDGET: Final = "critic_budget_exhausted"
REASON_CRITIC_FAILED: Final = "critic_failed"
REASON_NO_HUNT: Final = "hunt_not_started"
_HINT_SEVERITIES: Final = frozenset({"critical", "high", "medium", "low"})
_UNKNOWN_SUBSYSTEM: Final = "unknown subsystem"
#: Weakest first: a unit takes the weakest auth of its surfaces.
_AUTH_ORDER: Final = ("none", "unknown", "user", "privileged")


# ---------------------------------------------------------------------------------------------
# Units


def hunt_waves(state: dict[str, Any]) -> int:
    """Return the number of hunt waves of the run's profile (equal to its critic waves)."""
    return budget.critic_waves(state)


@functools.lru_cache(maxsize=1)
def _domain_classes() -> tuple[tuple[str, frozenset[str]], ...]:
    try:
        base = knowledge.knowledge_dir() / "domains"
        names = sorted(path.stem for path in base.glob("*.md"))
        return tuple(
            (name, frozenset(knowledge.load_domain(name).meta_list("classes"))) for name in names
        )
    except (FileNotFoundError, OSError):
        return ()


def companion_blocks(class_slug: str) -> list[str]:
    """Return the selected companion blocks of a class: the ``Core discipline`` and
    ``Validation rules`` sections of every domain pack that lists the class."""
    blocks: list[str] = []
    for name, classes in _domain_classes():
        if class_slug in classes:
            blocks += [
                f"knowledge/domains/{name}.md#Core discipline",
                f"knowledge/domains/{name}.md#Validation rules",
            ]
    return blocks


def _hint_index(candidates: list[dict[str, Any]]) -> dict[str, Counter[str]]:
    index: dict[str, Counter[str]] = {}
    for candidate in candidates:
        slug, file = candidate.get("class"), candidate.get("file")
        if (
            isinstance(slug, str)
            and get_class(slug)
            and slug not in EXCLUDED_UNIT_CLASSES
            and isinstance(file, str)
            and file
            and candidate.get("severity") in _HINT_SEVERITIES
        ):
            index.setdefault(file, Counter())[slug] += 1
    return index


def classes_for_surface(
    surface: dict[str, Any], run_classes: Iterable[str], hints: dict[str, Counter[str]]
) -> list[str]:
    """Return the unit classes of a surface (module docstring), in a stable order."""
    allowed = [slug for slug in run_classes if slug not in EXCLUDED_UNIT_CLASSES]
    fitting = KIND_CLASSES.get(str(surface.get("kind")), None)
    chosen = allowed if fitting is None else [slug for slug in fitting if slug in allowed]
    hinted = sorted(hints.get(str(surface.get("file")), Counter()))
    return unique([*chosen, *hinted])


def folder_of(path: str) -> str:
    """Return the folder group of a path: its first two folders, ``(root)`` for a top file."""
    parts = path.split("/")
    if len(parts) == 1:
        return "(root)"
    return "/".join(parts[:2]) if len(parts) > 2 else parts[0]


def _label(surface: dict[str, Any]) -> str:
    text = clean_text(surface.get("subsystem"), 300)
    return "" if text.casefold() == _UNKNOWN_SUBSYSTEM else text


def subsystem_groups(surfaces: Iterable[dict[str, Any]]) -> dict[str, str]:
    """Return ``{file: group}``: surfaces that share a file or a subsystem label are one group.

    The group name is the most frequent label of the group (ties: UTF-16 order), or the folder
    of its first file when no surface has a label.
    """
    parent: dict[str, str] = {}

    def find(node: str) -> str:
        parent.setdefault(node, node)
        while parent[node] != node:
            parent[node] = parent[parent[node]]
            node = parent[node]
        return node

    members = [s for s in surfaces if isinstance(s.get("file"), str) and s["file"]]
    for surface in members:
        file_root = find(f"f:{surface['file']}")
        label = _label(surface)
        if label:
            label_root = find(f"s:{label}")
            if label_root != file_root:
                parent[label_root] = file_root
    labels: dict[str, Counter[str]] = {}
    files: dict[str, list[str]] = {}
    for surface in members:
        root = find(f"f:{surface['file']}")
        label = _label(surface)
        if label:
            labels.setdefault(root, Counter())[label] += 1
        files.setdefault(root, []).append(surface["file"])
    groups: dict[str, str] = {}
    for root, paths in files.items():
        counts = labels.get(root)
        if counts:
            name = min(counts, key=lambda label: (-counts[label], utf16_key(label)))
        else:
            name = folder_of(sorted(paths, key=utf16_key)[0])
        for path in paths:
            groups[path] = name
    return groups


def _weakest_auth(values: Iterable[object]) -> str:
    present = [str(value) for value in values]
    for auth in _AUTH_ORDER:
        if auth in present:
            return auth
    return present[0] if present else "unknown"


def _level_key(level: str, surface: dict[str, Any], groups: dict[str, str]) -> tuple[str, ...]:
    file = surface["file"]
    if level == "surface":
        return (file, str(surface.get("name")), str(surface.get("trust_boundary")))
    if level == "file":
        return (file,)
    if level == "subsystem":
        return (groups.get(file) or folder_of(file),)
    if level == "folder":
        return (folder_of(file),)
    return (ALL_GROUP,)


def _refs(
    level: str, profile: str, surface: dict[str, Any], groups: dict[str, str]
) -> tuple[str, str, str, str]:
    """Return the ``(surface, boundary, subsystem, batch group)`` references of a unit."""
    file = surface["file"]
    group = groups.get(file) or folder_of(file)
    if level == "surface":
        boundary = str(surface.get("trust_boundary") or "unknown trust boundary")
        return f"{file}#{surface.get('name')}", boundary, group, group
    if level == "file":
        return f"{file}#all-entry-surfaces", f"{file}#all-trust-boundaries", group, group
    key = _level_key(level, surface, groups)[0]
    if profile == "fast":
        return f"{key}#all-entry-surfaces", FAST_BOUNDARY, FAST_SUBSYSTEM, key
    return f"{key}#all-entry-surfaces", f"{key}#all-trust-boundaries", key, key


def level_unit(
    level: str,
    profile: str,
    owners: list[dict[str, Any]],
    class_slug: str,
    groups: dict[str, str],
    *,
    hints: dict[str, Counter[str]] | None = None,
    extra_paths: Iterable[str] = (),
    wave: int = 1,
    origin: str = "plan",
) -> dict[str, Any] | None:
    """Return the unit of ``class_slug`` for the surfaces ``owners`` (one level key)."""
    surface_ref, boundary, subsystem, group = _refs(level, profile, owners[0], groups)
    files = unique(owner["file"] for owner in owners)
    kinds = unique(str(owner.get("kind", "other")) for owner in owners)
    counts = hints or {}
    return make_unit(
        surface=surface_ref,
        boundary=boundary,
        subsystem=subsystem,
        class_slug=class_slug,
        starting_paths=[*files, *extra_paths],
        companion_blocks=companion_blocks(class_slug),
        wave=wave,
        bookkeeping={
            "surface_ids": unique(owner["id"] for owner in owners if owner.get("id")),
            "kind": kinds[0] if len(kinds) == 1 else "mixed",
            "auth": _weakest_auth(owner.get("auth", "unknown") for owner in owners),
            "hints": sum(counts.get(file, Counter())[class_slug] for file in files),
            "group": group,
            "level": level,
            "origin": origin,
        },
    )


def _merge_into(target: dict[str, Any], unit: dict[str, Any]) -> None:
    target["starting_paths"] = unique([*target["starting_paths"], *unit["starting_paths"]])[:50]
    book, other = target["kalkan"], unit["kalkan"]
    book["surface_ids"] = unique([*book["surface_ids"], *other["surface_ids"]])
    book["hints"] = max(book["hints"], other["hints"])
    book["auth"] = _weakest_auth([book["auth"], other["auth"]])


def _units_at(
    level: str,
    profile: str,
    surfaces: list[dict[str, Any]],
    run_classes: list[str],
    hints: dict[str, Counter[str]],
    groups: dict[str, str],
) -> list[dict[str, Any]]:
    units: dict[str, dict[str, Any]] = {}
    buckets: dict[tuple[str, ...], list[dict[str, Any]]] = {}
    for surface in surfaces:
        buckets.setdefault(_level_key(level, surface, groups), []).append(surface)
    for members in buckets.values():
        owners: dict[str, list[dict[str, Any]]] = {}
        for surface in members:
            for slug in classes_for_surface(surface, run_classes, hints):
                owners.setdefault(slug, []).append(surface)
        for slug, found in owners.items():
            unit = level_unit(level, profile, found, slug, groups, hints=hints)
            if unit is None:
                continue
            if unit["coverage_id"] in units:
                _merge_into(units[unit["coverage_id"]], unit)
            else:
                units[unit["coverage_id"]] = unit
    return list(units.values())


def _usable_surfaces(ctx: RunContext) -> list[dict[str, Any]]:
    return [
        surface
        for surface in load_surfaces(ctx)
        if isinstance(surface.get("file"), str) and safe_paths([surface["file"]])
    ]


def choose_units(ctx: RunContext) -> tuple[str, list[dict[str, Any]]]:
    """Return ``(level, units)``: the finest level from the profile's start whose hunt batches
    fit :func:`kalkan.run.budget.hunt_wave_cap`, else the coarsest level."""
    surfaces = _usable_surfaces(ctx)
    run_classes = load_classes(ctx)
    hints = _hint_index(load_candidates(ctx))
    groups = subsystem_groups(surfaces)
    profile = ctx.options["profile"]
    cap = budget.hunt_wave_cap(ctx.state)
    size = budget.batch_size(ctx.state)
    levels = LEVELS[LEVELS.index(START_LEVEL.get(profile, "surface")) :]
    units: list[dict[str, Any]] = []
    for level in levels:
        units = _units_at(level, profile, surfaces, run_classes, hints, groups)
        batches, _ = form_batches(order_units(units), size)
        if len(batches) <= cap:
            return level, units
    return levels[-1], units


def build_units(ctx: RunContext, level: str | None = None) -> list[dict[str, Any]]:
    """Return the ledger units of the run (all ``planned``, wave 1), without duplicates, at
    ``level`` (default: the level that :func:`choose_units` picks)."""
    if level is None:
        return choose_units(ctx)[1]
    surfaces = _usable_surfaces(ctx)
    hints = _hint_index(load_candidates(ctx))
    groups = subsystem_groups(surfaces)
    profile = ctx.options["profile"]
    return _units_at(level, profile, surfaces, load_classes(ctx), hints, groups)


def _priority(unit: dict[str, Any]) -> tuple[Any, ...]:
    book = unit.get("kalkan") if isinstance(unit.get("kalkan"), dict) else {}
    return (
        0 if book.get("auth") == "none" else 1,
        0 if book.get("hints") else 1,
        -CLASS_WEIGHT.get(str(unit.get("attack_class")), 2),
        utf16_key(str(unit.get("coverage_id", ""))),
    )


def order_units(units: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return the units in priority order (module docstring)."""
    return sorted(units, key=_priority)


def _group(unit: dict[str, Any]) -> str:
    book = unit.get("kalkan") if isinstance(unit.get("kalkan"), dict) else {}
    return str(book.get("group") or unit.get("subsystem") or "")


def form_batches(
    ordered: list[dict[str, Any]], size: int = 3, max_batches: int | None = None
) -> tuple[list[list[dict[str, Any]]], list[dict[str, Any]]]:
    """Split units (in priority order) into batches of at most ``size`` units of one group.

    Returns ``(batches, left_over)``. With ``max_batches`` a unit that needs a new batch beyond
    the limit is left over; a later unit can still join an open batch of its group.
    """
    batches: list[list[dict[str, Any]]] = []
    open_batch: dict[str, list[dict[str, Any]]] = {}
    left: list[dict[str, Any]] = []
    for unit in ordered:
        group = _group(unit)
        batch = open_batch.get(group)
        if batch is None or len(batch) >= max(1, size):
            if max_batches is not None and len(batches) >= max_batches:
                left.append(unit)
                continue
            batch = []
            batches.append(batch)
            open_batch[group] = batch
        batch.append(unit)
    return batches, left


# ---------------------------------------------------------------------------------------------
# plan steps


def plan_ledger(ctx: RunContext) -> dict[str, Any]:
    """Build ``coverage-ledger.json`` (step ``plan:ledger``); return counts."""
    ctx.reload()
    level, chosen = choose_units(ctx)
    units = order_units(chosen)
    cap = budget.hunt_wave_cap(ctx.state)
    _, left = form_batches(units, budget.batch_size(ctx.state), max_batches=cap)
    left_ids = {unit["coverage_id"] for unit in left}
    for unit in units:
        if unit["coverage_id"] in left_ids:
            defer(unit, REASON_BUDGET)
    with transaction(ctx):
        save_ledger(ctx, units)  # always written, also when it holds no unit
    return {
        "units": len(units),
        "planned": len(units) - len(left),
        "deferred": len(left),
        "hunt_budget": cap,
        "level": level,
    }


def plan_tasks(ctx: RunContext) -> dict[str, Any]:
    """Create the wave-1 hunt tasks (step ``plan:tasks``). The verify tasks come after each
    hunt wave (:mod:`kalkan.run.validation`)."""
    return {"hunt": create_hunt_wave(ctx, 1)}


def _wave_dedupe(wave: int, coverage_ids: list[str]) -> str:
    return dedupe_key(f"hunt:w{wave}", "|".join(coverage_ids))


def create_hunt_wave(ctx: RunContext, wave: int) -> dict[str, int]:
    """Create the hunt tasks of ``wave`` for every ``planned`` unit, within the budget.

    Existing tasks of the same batch (dedupe key) are reused without budget. New tasks stay
    within :func:`kalkan.run.budget.hunt_wave_cap` (computed once for the wave); the units of
    batches that do not fit become ``deferred`` (:data:`REASON_BUDGET`). The assigned units
    become ``in_progress`` with the task's lower-case ID as owner.
    """
    ctx.reload()
    planned = order_units(unit for unit in load_ledger(ctx) if unit.get("status") == "planned")
    batches, _ = form_batches(planned, budget.batch_size(ctx.state))
    allowed = budget.hunt_wave_cap(ctx.state)
    all_ids = [unit["coverage_id"] for batch in batches for unit in batch]
    assignments: list[tuple[str, list[str]]] = []
    deferred: list[str] = []
    for batch in batches:
        ids = sorted((unit["coverage_id"] for unit in batch), key=utf16_key)
        key = _wave_dedupe(wave, ids)
        task_id = find_by_dedupe_key(ctx.state, key)
        if task_id is None:
            if allowed < 1 or budget.available(ctx.state, "hunt") < 1:
                deferred += ids
                continue
            others = [item for item in all_ids if item not in ids]
            urgent = any((unit.get("kalkan") or {}).get("auth") == "none" for unit in batch)
            task_id = new_task(
                ctx,
                "hunt",
                "hunt",
                hunt_input(ctx, batch, others, wave),
                priority=70 if urgent else 60,
                dedupe_key=key,
                meta={"wave": wave},
            )
            allowed -= 1
        assignments.append((task_id, ids))
    with ledger_transaction(ctx) as (_, units):
        by_id = {unit["coverage_id"]: unit for unit in units}
        for task_id, ids in assignments:
            for coverage_id in ids:
                unit = by_id.get(coverage_id)
                if unit is not None and unit["status"] == "planned":
                    assign(unit, task_id.lower(), wave)
        for coverage_id in deferred:
            unit = by_id.get(coverage_id)
            if unit is not None and unit["status"] == "planned":
                defer(unit, REASON_BUDGET)
    return {
        "tasks": len(assignments),
        "units": sum(len(ids) for _, ids in assignments),
        "deferred": len(deferred),
    }


# ---------------------------------------------------------------------------------------------
# Gaps (hunt uncovered, critic missing units)


def _ledger_level(ctx: RunContext) -> str:
    for unit in load_ledger(ctx):
        book = unit.get("kalkan") if isinstance(unit.get("kalkan"), dict) else {}
        if book.get("origin") == "plan" and book.get("level") in LEVELS:
            return str(book["level"])
    return START_LEVEL.get(ctx.options["profile"], "surface")


def gap_unit(
    ctx: RunContext,
    item: dict[str, Any],
    surfaces_by_id: dict[str, dict[str, Any]],
    *,
    wave: int,
    origin: str,
) -> dict[str, Any] | None:
    """Return a ``planned`` unit for an ``uncovered`` or ``missing_units`` entry, or None.

    The unit uses the level of the wave-1 plan, so a gap inside a coarse unit maps to the same
    ``coverage_id`` (the critic then reassigns that unit instead).
    """
    slug = item.get("class")
    if not isinstance(slug, str) or not get_class(slug) or slug in EXCLUDED_UNIT_CLASSES:
        return None
    paths = safe_paths(item.get("starting_paths"))
    surface = surfaces_by_id.get(str(item.get("surface_id")))
    if surface is not None and not safe_paths([surface.get("file")]):
        surface = None
    if not paths and surface is None:
        return None
    if surface is None:
        surface = {
            "id": None,
            "kind": "other",
            "name": clean_text(item.get("surface_id"), 300) or "unnamed surface",
            "file": paths[0],
            "auth": "unknown",
            "trust_boundary": "unknown trust boundary",
            "subsystem": "",
        }
    groups = subsystem_groups(_usable_surfaces(ctx))
    groups.setdefault(surface["file"], folder_of(surface["file"]))
    return level_unit(
        _ledger_level(ctx),
        ctx.options["profile"],
        [surface],
        slug,
        groups,
        extra_paths=[path for path in paths if path != surface["file"]],
        wave=wave,
        origin=origin,
    )


# ---------------------------------------------------------------------------------------------
# Hunt phase progression


def defer_planned(ctx: RunContext, reason: str) -> int:
    """Defer every ``planned`` unit and every ``in_progress`` unit whose task is settled."""
    count = 0
    with ledger_transaction(ctx) as (tx, units):
        owners = _owner_statuses(tx.state)
        for unit in units:
            if unit["status"] == "planned" or (
                unit["status"] == "in_progress" and _owner_settled(owners, unit)
            ):
                defer(unit, reason)
                count += 1
    return count


def _owner_statuses(state: dict[str, Any]) -> dict[str, str]:
    return {task_id.lower(): task["status"] for task_id, task in state["tasks"].items()}


def _owner_settled(owners: dict[str, str], unit: dict[str, Any]) -> bool:
    agent = unit.get("agent_id")
    if not isinstance(agent, str) or agent not in owners:
        return True
    return owners[agent] in SETTLED_TASK_STATUSES


def _reset_orphans(ctx: RunContext) -> int:
    """Return ``in_progress`` units whose hunt task is settled to ``planned`` (a dead hunt)."""
    count = 0
    with ledger_transaction(ctx) as (tx, units):
        owners = _owner_statuses(tx.state)
        for unit in units:
            if unit["status"] == "in_progress" and _owner_settled(owners, unit):
                reset_to_planned(unit)
                count += 1
    return count


def create_critic(ctx: RunContext, wave: int) -> str | None:
    """Create the critic task after hunt wave ``wave`` (None when the budget has no room)."""
    ctx.reload()
    key = f"critic:w{wave}"
    existing = find_by_dedupe_key(ctx.state, key)
    if existing is not None:
        return existing
    if budget.available(ctx.state, "critic") < 1:
        return None
    return new_task(
        ctx,
        "critic",
        "hunt",
        critic_input(ctx, load_ledger(ctx), wave),
        priority=85,
        dedupe_key=key,
        meta={"wave": wave},
    )


def _wave_of(task: dict[str, Any]) -> int:
    wave = (task.get("meta") or {}).get("wave")
    return wave if isinstance(wave, int) and wave >= 1 else 1


def _advance_waves(ctx: RunContext, hunts: list[tuple[str, dict[str, Any]]]) -> bool:
    state = ctx.reload()
    wave = max(_wave_of(task) for _, task in hunts)
    critics = [task for _, task in tasks_of_type(state, "critic") if _wave_of(task) == wave]
    if critics:
        failed = all(task["status"] != "done" for task in critics)
        defer_planned(ctx, REASON_CRITIC_FAILED if failed else REASON_WAVES)
        return False
    if state.get("incomplete_pending"):
        defer_planned(ctx, REASON_VALIDATION)
        return False
    if wave <= hunt_waves(state) and create_critic(ctx, wave) is not None:
        return True
    if wave <= hunt_waves(state):
        # Cloudflare: a consumed critic reserve makes the run incomplete, with no
        # complete-coverage claim.
        mark_incomplete(ctx, REASON_CRITIC_BUDGET)
        defer_planned(ctx, REASON_CRITIC_BUDGET)
    else:
        defer_planned(ctx, REASON_WAVES)
    return False


def hunt_idle(ctx: RunContext) -> bool:
    """Advance the hunt phase when no hunt or critic task is open; return True for new work.

    1. Units of settled hunt tasks that are still ``in_progress`` go back to ``planned``.
    2. The verify tasks of all hunter candidates so far are allocated
       (:func:`kalkan.run.validation.allocate_hunter_verifies`); a candidate without budget
       records the pending incomplete reason.
    3. Without hunt tasks, the phase ends (planned units: :data:`REASON_NO_HUNT`).
    4. When the critic of the current wave exists, it already scheduled the next wave or
       deferred the work: the phase ends (a dead critic: :data:`REASON_CRITIC_FAILED`).
    5. With a pending incomplete reason, hunting stops (:data:`REASON_VALIDATION`).
    6. Otherwise the critic of the current wave is created, budget permitting
       (:data:`REASON_CRITIC_BUDGET`).

    When the phase ends, the verify tasks of deterministic tool results are created
    (:func:`kalkan.run.validation.create_deterministic_verifies`).
    """
    state = ctx.reload()
    hunts = tasks_of_type(state, "hunt")
    _reset_orphans(ctx)
    if hunts:
        allocate_hunter_verifies(ctx)
        if _advance_waves(ctx, hunts):
            return True
    else:
        defer_planned(ctx, REASON_NO_HUNT)
    create_deterministic_verifies(ctx)
    return False


def mark_incomplete(ctx: RunContext, reason: str) -> None:
    """Record ``reason`` as the pending incomplete reason (the first reason wins).

    The run continues: validation, merge and the report still run, and the report step turns
    the pending reason into ``incomplete_reason`` (docs/PHASES.md section 7).
    """
    with transaction(ctx) as tx:
        if not tx.state.get("incomplete_pending"):
            tx.state["incomplete_pending"] = reason
            tx.event("incomplete_pending", reason=reason)


def agent_id_of(task_id: str) -> str:
    """Return the ledger agent ID of a task: its lower-case ID."""
    assert parse_task_id(task_id) is not None
    return task_id.lower()
