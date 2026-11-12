# SPDX-License-Identifier: MIT
"""Root-cause consolidation of the final records (docs/PHASES.md sections 3 and 4,
docs/ENGINE-SPEC.md sections 15 and 18).

Verifiers run in parallel and see only the claims near the same code, so one root cause can
survive as several final records: filed under different classes, or anchored in different files.
The validate step ``consolidate`` (:mod:`kalkan.run.consolidate`) links the final records with
deterministic rules, a ``consolidate`` agent judges each linked group with quotes, and merge folds
the accepted groups. Evidence overlap alone never folds two records: related code with a
different flaw or a different fix stays separate. This module holds the engine rules; it never
reads run state.

Eligible records (:func:`eligible`): ``confirmed`` or ``needs_validation`` with a ``KF-`` id and
no ``reject`` review decision (rejected records never take part).

Link rules (:func:`link_reasons`). Two records are linked when any of these holds:

1. ``shared_location``: they cite a common evidence location: the same file and lines at most
   :data:`LOCATION_WINDOW` apart, across ``evidence[]`` and every ``audit_answers.*.evidence[]``.
2. ``nearby_anchor``: their first ``evidence`` items are in the same file, at most
   :data:`ANCHOR_WINDOW` lines apart.
3. ``same_class_file``: the same ``class`` and at least one common cited file (the files of the
   locations of rule 1).

Candidate groups (:func:`candidate_groups`): the connected components of the link graph
(union-find) with at least two records. A component of more than :data:`CHUNK_SIZE` records is
split so that the strongest links stay inside one chunk (:func:`chunk_component`):

1. The links are taken strongest first (:func:`link_strength`: the number of shared locations,
   then a nearby anchor, then the same class in a shared file; ties in :func:`location_key`
   order). A link joins the chunks of its two records when the joined chunk holds at most
   :data:`CHUNK_SIZE` records.
2. A record left alone (every neighbor sits in a full chunk) moves into a new chunk with its
   strongest neighbor, which leaves its old chunk. No chunk holds a single record.
3. Chunks come in the order of their first record.

A plain split in walk order would cut strong links: it can separate true duplicate pairs (each
linked by shared locations), while weak same-class links hold the chunks together.

Primary (:func:`pick_primary`): the highest verdict rank (``confirmed`` > ``needs_validation``),
then the highest overall severity, then the most ``evidence`` items, then the smallest id. The
primary keeps its own fields, so folding never lowers a severity and loses no information.

Folding (:func:`fold_groups`): every other member of an accepted group gets ``duplicate_of``
(the primary id) and ``duplicate_reason``; the primary gets ``related`` (``[{id, title, class,
reason, poc_status}]``; ``poc_status`` only when the folded record has a PoC, so a PoC that
passed on a folded record stays visible on the primary). Records are never deleted. A group
that names fewer than two eligible records, or a record that an earlier group already folded,
is skipped with a warning.

Task input (:func:`record_view`): per record the id, fingerprint, verdict, class, CWE, title,
description, root cause, a short remediation strategy, the overall severity, the evidence
locations, the verified audit-answer quotes, a trace summary (kind and ``file:line``) and the
review decision. Long prose is cut (:data:`TEXT_LIMIT`, :data:`REMEDIATION_LIMIT` characters).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final, TypeVar

from kalkan.util.text import utf16_key

RecordT = TypeVar("RecordT", bound=Mapping[str, Any])

__all__ = [
    "ANCHOR_WINDOW",
    "CHUNK_SIZE",
    "ELIGIBLE_VERDICTS",
    "LINK_RULES",
    "LOCATION_WINDOW",
    "REMEDIATION_LIMIT",
    "TEXT_LIMIT",
    "CandidateGroup",
    "FoldStats",
    "candidate_groups",
    "chunk_component",
    "cited_locations",
    "eligible",
    "fold_groups",
    "link_reasons",
    "link_strength",
    "location_key",
    "pick_primary",
    "primary_key",
    "record_view",
    "severity_rank",
]

#: Rule 1: two cited lines of the same file at most this far apart are one location.
LOCATION_WINDOW: Final = 3
#: Rule 2: the first evidence items of two records at most this far apart in one file.
ANCHOR_WINDOW: Final = 15
#: The most records in one ``consolidate`` task.
CHUNK_SIZE: Final = 12
LINK_RULES: Final = ("shared_location", "nearby_anchor", "same_class_file")
ELIGIBLE_VERDICTS: Final = ("confirmed", "needs_validation")
#: The most characters of the description and the root cause in a task input record.
TEXT_LIMIT: Final = 1200
#: The most characters of the remediation strategy in a task input record.
REMEDIATION_LIMIT: Final = 400
#: PoC statuses that a ``related`` entry repeats (``poc_status``) from its folded record.
POC_STATUSES: Final = ("passed", "failed", "blocked", "not_run")
_VERDICT_RANK: Final = {"confirmed": 2, "needs_validation": 1, "rejected": 0}
_SEVERITY_RANK: Final = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def eligible(finding: Mapping[str, Any]) -> bool:
    """Return True for a record that consolidation may fold (module docstring)."""
    review = finding.get("review")
    rejected_by_review = isinstance(review, Mapping) and review.get("decision") == "reject"
    finding_id = finding.get("id")
    return (
        finding.get("verdict") in ELIGIBLE_VERDICTS
        and isinstance(finding_id, str)
        and bool(finding_id)
        and not rejected_by_review
    )


def _location(entry: object) -> tuple[str, int] | None:
    if not isinstance(entry, Mapping):
        return None
    file, line = entry.get("file"), entry.get("line")
    if not isinstance(file, str) or not file:
        return None
    if not isinstance(line, int) or isinstance(line, bool) or line < 1:
        return None
    return file, line


def cited_locations(finding: Mapping[str, Any]) -> list[tuple[str, int]]:
    """Return the ``(file, line)`` pairs of ``evidence[]`` and every
    ``audit_answers.*.evidence[]``, in order and without duplicates."""
    entries: list[object] = list(finding.get("evidence") or [])
    answers = finding.get("audit_answers")
    if isinstance(answers, Mapping):
        for answer in answers.values():
            if isinstance(answer, Mapping) and isinstance(answer.get("evidence"), list):
                entries.extend(answer["evidence"])
    found: list[tuple[str, int]] = []
    for entry in entries:
        location = _location(entry)
        if location is not None and location not in found:
            found.append(location)
    return found


def _anchor(finding: Mapping[str, Any]) -> tuple[str, int] | None:
    evidence = finding.get("evidence")
    return _location(evidence[0]) if isinstance(evidence, list) and evidence else None


def location_key(finding: Mapping[str, Any]) -> tuple[Any, ...]:
    """The stable order of records: first evidence file and line, then the fingerprint."""
    anchor = _anchor(finding) or ("", 0)
    return (
        utf16_key(anchor[0]),
        anchor[1],
        utf16_key(str(finding.get("fingerprint") or "")),
        str(finding.get("id") or ""),
    )


def link_reasons(a: Mapping[str, Any], b: Mapping[str, Any]) -> list[str]:
    """Return why two records are linked (one text per rule that holds), or an empty list.

    Each text starts with the rule name of :data:`LINK_RULES`, for example
    ``shared_location: app/routes.py:14 and app/routes.py:15``.
    """
    reasons: list[str] = []
    left, right = cited_locations(a), cited_locations(b)
    shared = next(
        (
            (first, second)
            for first in left
            for second in right
            if first[0] == second[0] and abs(first[1] - second[1]) <= LOCATION_WINDOW
        ),
        None,
    )
    if shared is not None:
        (file, one), (_, two) = shared
        reasons.append(f"shared_location: {file}:{one} and {file}:{two}")
    anchor_a, anchor_b = _anchor(a), _anchor(b)
    if (
        anchor_a is not None
        and anchor_b is not None
        and anchor_a[0] == anchor_b[0]
        and abs(anchor_a[1] - anchor_b[1]) <= ANCHOR_WINDOW
    ):
        reasons.append(
            f"nearby_anchor: first evidence {anchor_a[0]}:{anchor_a[1]} and line {anchor_b[1]}"
        )
    slug = a.get("class")
    if isinstance(slug, str) and slug and slug == b.get("class"):
        common = sorted({file for file, _ in left} & {file for file, _ in right}, key=utf16_key)
        if common:
            reasons.append(f"same_class_file: {slug} in {common[0]}")
    return reasons


def link_strength(a: Mapping[str, Any], b: Mapping[str, Any]) -> tuple[int, int, int]:
    """Return the strength of the link between two records, compared as a tuple.

    ``(shared, anchor, same_class)``: the number of cited locations of ``a`` that match a
    location of ``b`` (rule 1), then 1 when rule 2 holds, then 1 when rule 3 holds. A pair
    without a link gives ``(0, 0, 0)``.
    """
    left, right = cited_locations(a), cited_locations(b)
    shared = sum(
        1
        for first in left
        if any(
            first[0] == second[0] and abs(first[1] - second[1]) <= LOCATION_WINDOW
            for second in right
        )
    )
    anchor_a, anchor_b = _anchor(a), _anchor(b)
    anchor = int(
        anchor_a is not None
        and anchor_b is not None
        and anchor_a[0] == anchor_b[0]
        and abs(anchor_a[1] - anchor_b[1]) <= ANCHOR_WINDOW
    )
    slug = a.get("class")
    same_class = int(
        isinstance(slug, str)
        and bool(slug)
        and slug == b.get("class")
        and bool({file for file, _ in left} & {file for file, _ in right})
    )
    return shared, anchor, same_class


def chunk_component(
    members: Sequence[int],
    strength: Mapping[tuple[int, int], tuple[int, int, int]],
    order: Mapping[int, int],
    size: int = CHUNK_SIZE,
) -> list[list[int]]:
    """Split one component into chunks of at most ``size`` (module docstring).

    ``members`` are record indexes, ``strength`` maps each linked pair ``(a, b)`` with
    ``a < b`` to its :func:`link_strength`, and ``order`` gives each index its stable position.
    """
    ordered = sorted(members, key=order.__getitem__)
    if len(ordered) <= size:
        return [ordered]
    inside = set(members)
    edges = sorted(
        ((pair, value) for pair, value in strength.items() if set(pair) <= inside),
        key=lambda item: (
            tuple(-part for part in item[1]),
            order[item[0][0]],
            order[item[0][1]],
        ),
    )
    parent = {index: index for index in members}
    count = dict.fromkeys(members, 1)

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    for (a, b), _ in edges:
        root_a, root_b = find(a), find(b)
        if root_a != root_b and count[root_a] + count[root_b] <= size:
            keep, drop = sorted((root_a, root_b), key=order.__getitem__)
            parent[drop] = keep
            count[keep] += count[drop]
    clusters: dict[int, list[int]] = {}
    for index in ordered:
        clusters.setdefault(find(index), []).append(index)
    chunks = [cluster for cluster in clusters.values() if len(cluster) > 1]
    for alone in (cluster[0] for cluster in clusters.values() if len(cluster) == 1):
        # Every neighbor sits in a full chunk: pair the record with its strongest neighbor.
        neighbor = next(
            other for (a, b), _ in edges if alone in (a, b) for other in (b if a == alone else a,)
        )
        home = next(chunk for chunk in chunks if neighbor in chunk)
        home.remove(neighbor)
        chunks.append(sorted([alone, neighbor], key=order.__getitem__))
    return sorted(chunks, key=lambda chunk: order[chunk[0]])


@dataclass
class CandidateGroup:
    """One chunk of linked records: the records, the links inside it and its place in the
    component."""

    records: list[dict[str, Any]]
    links: list[dict[str, Any]]
    component_size: int
    chunk: int
    chunks: int

    @property
    def fingerprints(self) -> list[str]:
        """The record fingerprints in UTF-16 order (the dedupe key of the task)."""
        return sorted((str(item.get("fingerprint")) for item in self.records), key=utf16_key)


def candidate_groups(findings: Iterable[Mapping[str, Any]]) -> list[CandidateGroup]:
    """Return the candidate groups of the eligible records (module docstring).

    Groups come in component order (by the first record in :func:`location_key` order), then
    chunk order. Each group lists its links: ``{"ids": [a, b], "reasons": [...]}`` for every
    linked pair inside it.
    """
    records = sorted((dict(item) for item in findings if eligible(item)), key=location_key)
    count = len(records)
    parent = list(range(count))

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    reasons: dict[tuple[int, int], list[str]] = {}
    strength: dict[tuple[int, int], tuple[int, int, int]] = {}
    for left in range(count):
        for right in range(left + 1, count):
            found = link_reasons(records[left], records[right])
            if not found:
                continue
            reasons[(left, right)] = found
            strength[(left, right)] = link_strength(records[left], records[right])
            a, b = find(left), find(right)
            if a != b:
                parent[max(a, b)] = min(a, b)
    components: dict[int, list[int]] = {}
    for index in range(count):
        components.setdefault(find(index), []).append(index)
    order = {index: index for index in range(count)}
    groups: list[CandidateGroup] = []
    for root in sorted(components):
        members = components[root]
        if len(members) < 2:
            continue
        chunks = chunk_component(members, strength, order)
        for number, chunk in enumerate(chunks, start=1):
            inside = set(chunk)
            links = [
                {"ids": [records[a]["id"], records[b]["id"]], "reasons": list(found)}
                for (a, b), found in sorted(reasons.items())
                if a in inside and b in inside
            ]
            groups.append(
                CandidateGroup(
                    records=[records[index] for index in chunk],
                    links=links,
                    component_size=len(members),
                    chunk=number,
                    chunks=len(chunks),
                )
            )
    return groups


def severity_rank(finding: Mapping[str, Any]) -> int:
    """Return the overall severity rank (``informational`` 0 … ``critical`` 4), else -1.

    Reads ``severity.overall_severity`` of a canonical record, or ``overall_severity`` of the
    record view in a ``consolidate`` task input.
    """
    severity = finding.get("severity")
    value = (
        severity.get("overall_severity")
        if isinstance(severity, Mapping)
        else finding.get("overall_severity")
    )
    return _SEVERITY_RANK.get(value, -1) if isinstance(value, str) else -1


def primary_key(finding: Mapping[str, Any]) -> tuple[Any, ...]:
    """The sort key of the primary rule (the smallest key wins; module docstring)."""
    evidence = finding.get("evidence")
    return (
        -_VERDICT_RANK.get(str(finding.get("verdict")), -1),
        -severity_rank(finding),
        -(len(evidence) if isinstance(evidence, list) else 0),
        str(finding.get("id") or ""),
    )


def pick_primary(findings: Iterable[RecordT]) -> RecordT:
    """Return the primary of a group (module docstring). Raises ``ValueError`` when empty."""
    items = list(findings)
    if not items:
        raise ValueError("a group needs at least one record")
    return min(items, key=primary_key)


def _cut(value: object, limit: int) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = " ".join(value.split())
    return text if len(text) <= limit else text[: limit - 2].rstrip() + " …"


def record_view(finding: Mapping[str, Any]) -> dict[str, Any]:
    """Return the record as a ``consolidate`` task input shows it (module docstring)."""
    severity = finding.get("severity")
    remediation = finding.get("remediation")
    review = finding.get("review")
    evidence = [
        {"file": entry["file"], "line": entry["line"], "description": entry.get("description")}
        for entry in finding.get("evidence") or []
        if _location(entry) is not None
    ]
    quotes: list[dict[str, Any]] = []
    answers = finding.get("audit_answers")
    for answer in answers.values() if isinstance(answers, Mapping) else ():
        entries = answer.get("evidence") if isinstance(answer, Mapping) else None
        for entry in entries if isinstance(entries, list) else ():
            if _location(entry) is None or not isinstance(entry.get("quote"), str):
                continue
            quote = {"file": entry["file"], "line": entry["line"], "quote": entry["quote"]}
            if quote not in quotes:
                quotes.append(quote)
    trace = [
        f"{step.get('kind')} {step['file']}:{step['line']}"
        for step in finding.get("trace") or []
        if _location(step) is not None
    ]
    return {
        "id": finding.get("id"),
        "fingerprint": finding.get("fingerprint"),
        "verdict": finding.get("verdict"),
        "class": finding.get("class"),
        "cwe": [item for item in finding.get("cwe") or [] if isinstance(item, str)],
        "title": finding.get("title"),
        "description": _cut(finding.get("description"), TEXT_LIMIT),
        "root_cause": _cut(
            finding.get("root_cause") or finding.get("claimed_root_cause"), TEXT_LIMIT
        ),
        "remediation": _cut(
            remediation.get("strategy") if isinstance(remediation, Mapping) else None,
            REMEDIATION_LIMIT,
        ),
        "overall_severity": (
            severity.get("overall_severity") if isinstance(severity, Mapping) else None
        ),
        "evidence": evidence,
        "quotes": quotes,
        "trace": trace,
        "review": (
            {"decision": review.get("decision"), "reason": review.get("reason")}
            if isinstance(review, Mapping)
            else None
        ),
    }


@dataclass
class FoldStats:
    """What :func:`fold_groups` did."""

    applied: int = 0
    duplicates: int = 0
    skipped: int = 0
    warnings: list[str] = field(default_factory=list)


def _strings(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return list(dict.fromkeys(item for item in value if isinstance(item, str)))


def fold_groups(
    findings: Sequence[dict[str, Any]], groups: Iterable[tuple[str, Mapping[str, Any]]]
) -> FoldStats:
    """Fold the accepted groups into ``findings`` in place (module docstring).

    ``groups`` holds ``(where, group)`` pairs in the order to apply, where ``group`` has ``ids``
    and ``reason`` and ``where`` names its source for warnings. The primary is chosen again on
    the given records (:func:`pick_primary`), so a verdict that changed after the step (a PoC
    result) still gives the strongest record.
    """
    stats = FoldStats()
    by_id = {item["id"]: item for item in findings if isinstance(item.get("id"), str)}
    folded: set[str] = set()
    for where, group in groups:
        ids = _strings(group.get("ids"))
        reason = group.get("reason")
        members = [by_id[item] for item in ids if item in by_id and eligible(by_id[item])]
        if len(members) < 2 or not isinstance(reason, str):
            stats.skipped += 1
            stats.warnings.append(
                f"{where}: a consolidation group names fewer than two eligible records; skipped"
            )
            continue
        taken = [item["id"] for item in members if item["id"] in folded]
        if taken:
            stats.skipped += 1
            stats.warnings.append(
                f"{where}: {', '.join(taken)} already belong to another consolidation group; "
                "group skipped"
            )
            continue
        if len(members) < len(ids):
            stats.warnings.append(
                f"{where}: a consolidation group names records that are missing or not "
                "eligible; the others are folded"
            )
        primary = pick_primary(members)
        duplicates = sorted((item for item in members if item is not primary), key=primary_key)
        related = []
        for item in duplicates:
            item["duplicate_of"] = primary["id"]
            item["duplicate_reason"] = reason
            entry: dict[str, Any] = {"id": item["id"], "title": item.get("title")}
            if isinstance(item.get("class"), str):
                entry["class"] = item["class"]
            entry["reason"] = reason
            poc = item.get("poc")
            if isinstance(poc, Mapping) and poc.get("status") in POC_STATUSES:
                entry["poc_status"] = poc["status"]
            related.append(entry)
        primary["related"] = related
        folded.update(item["id"] for item in members)
        stats.applied += 1
        stats.duplicates += len(duplicates)
    return stats
