# SPDX-License-Identifier: MIT
"""Merge the task outputs of a run into ``findings.json`` (docs/ENGINE-SPEC.md, section 15).

Inputs, read only from tasks whose status is ``done`` in ``state.json``:

- ``tasks/<id>/finding.json``: one canonical finding (verify handler). A list of findings is
  also accepted.
- ``tasks/<id>/poc.json``: ``{finding_id, level, status, observed_result, artifacts[]}``, optional
  ``blocker`` and the run facts ``started_at``, ``duration_ms``, ``exit_code``,
  ``output_truncated`` (all copied into the finding's ``poc``)
  (poc handler). An optional ``blocker`` string names the blocker for a ``blocked`` or
  ``not_run`` result.
- ``tasks/<id>/translations.json``: ``{translations: [{id, title, description,
  remediation_strategy}]}`` (translate handler).
- ``tasks/<id>/review.json``: the outcome of a final review (review handler,
  :mod:`kalkan.findings.review`).
- ``tasks/<id>/consolidate.json``: the groups of records with one root cause (consolidate
  handler, :mod:`kalkan.findings.consolidate`).
- ``tasks/<id>/polish.json``: the accepted Turkish letter corrections (polish handler,
  :mod:`kalkan.findings.polish`).
- ``candidates.json`` (deterministic candidates) and ``sca/vulns.json`` (SCA records).

Rules:

1. Every finding passes :func:`kalkan.findings.validate.validate_findings` on its own; an invalid
   one is skipped with a warning.
2. Findings with the same ``id`` or the same ``fingerprint`` form one group (transitively). The
   record with the strongest verdict (``confirmed`` > ``needs_validation`` > ``rejected``) is the
   base; a tie goes to the richest evidence (evidence, trace and quoted answer entries), then to
   the earlier task. The group gives the union of ``engines``, ``candidates``, ``cwe`` and
   ``owasp``; records with the base verdict add their extra ``evidence`` entries.
3. Final reviews: each outcome applies to the merged record that holds one of its
   ``verify_tasks`` (else the same ``finding_id``, else the same ``fingerprint``) with
   :func:`kalkan.findings.review.apply_review`. A record with several outcomes takes the most
   conservative one (the weakest verdict after the review, then the later task). An outcome
   whose record changed its verdict, or that would give an invalid record, is skipped with a
   warning. Reviews apply before the PoC results.
4. PoC results (the strongest status per finding, ``passed`` > ``failed`` > ``blocked`` >
   ``not_run``; a tie goes to the later task):

   - ``passed`` sets ``poc`` and adds the engine ``poc-builder``. A ``confirmed`` finding gets
     ``confidence.score = high`` and the PoC observation as ``execution.observed_result``. A
     ``needs_validation`` finding becomes ``confirmed`` only when the ``result.json`` of its
     verify task holds every confirmed-branch field (``intended_behavior``, ``conditions``,
     ``execution``, ``remediation``, ``severity``, ``confidence``) and the promoted record is
     valid. Otherwise it keeps its verdict and gets the blocker ``confirmed_fields_missing``.
   - ``failed`` keeps the verdict and records the PoC.
   - ``blocked`` and ``not_run`` record the PoC (the observation holds the reason). A
     ``needs_validation`` finding also gets a blocker: the ``blocker`` of ``poc.json``, else
     ``sandbox_infeasible`` (blocked) or ``sandbox_unavailable`` (not run).

5. Translations set ``i18n.en`` (a later task wins).
6. A candidate links to a finding when the classes match (or one is null) and the candidate line
   range overlaps the finding's line range in the same file (the lowest to the highest
   ``trace`` and ``evidence`` line of that file). A link adds the candidate ID to
   ``candidates`` and the candidate engine to ``engines``. Unlinked candidates stay in
   ``candidates.json``; the report lists them as tool results. SCA records never become
   findings.
7. Findings without an ``id`` get one (:func:`kalkan.findings.fingerprint.assign_finding_ids`
   with the source lines of the target copy).
8. Consolidation: the accepted groups of every ``consolidate.json`` (task order) fold into the
   records with :func:`kalkan.findings.consolidate.fold_groups`: the primary (chosen again on
   the final records) gets ``related``, every other member stays with ``duplicate_of`` and
   ``duplicate_reason``. A group that overlaps an earlier group or names fewer than two
   eligible records is skipped with a warning. The counts by verdict and by severity leave the
   duplicates out (``duplicates_folded`` counts them).
9. Turkish letters (with step 8 only): the ``applied`` corrections of every ``polish.json``
   (task order) replace prose fields with
   :func:`kalkan.findings.polish.apply_corrections`, after the folding (so ``duplicate_reason``
   and ``related[].reason`` exist). A correction applies only to a prose field of a
   ``confirmed`` or ``needs_validation`` record that still holds the old text, and only when
   the letter check passes again; otherwise it is skipped with a warning (the record changed
   after the polish task). Ids, fingerprints, verdicts and quotes never change.
   ``polish_applied`` counts the applied corrections.
10. The document is sorted by fingerprint (UTF-16 order, as the validator expects), validated
    as a whole and written atomically.

:func:`merged_records` returns the records of steps 1 to 7 (and 8 and 9 with ``fold=True``)
without writing anything; the validate step ``consolidate`` builds its candidate groups from
the records without folding, the validate step ``polish`` selects from the folded ones.

The module never takes the run lock: the caller does (the ``merge`` command, or the run engine
that already holds it).
"""

from __future__ import annotations

import copy
import os
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

from kalkan.errors import UnsafeInputError, ValidationError
from kalkan.findings.consolidate import fold_groups
from kalkan.findings.fingerprint import GetLines, assign_finding_ids
from kalkan.findings.polish import apply_corrections
from kalkan.findings.review import DECISIONS, apply_review
from kalkan.findings.validate import validate_candidate, validate_findings
from kalkan.run.state import load_state, parse_task_id
from kalkan.schema.validator import enforce_json_text_limits, parse_json_text
from kalkan.util.paths import is_safe_relative_path
from kalkan.util.safe_io import atomic_write_json, read_text_bounded
from kalkan.util.text import has_visible_prose, utf16_key

__all__ = [
    "BLOCKER_CONFIRMED_FIELDS_MISSING",
    "BLOCKER_SANDBOX_INFEASIBLE",
    "BLOCKER_SANDBOX_UNAVAILABLE",
    "CANDIDATES_NAME",
    "CONFIRMED_FIELDS",
    "FINDINGS_NAME",
    "POC_RANK",
    "VERDICT_RANK",
    "VULNS_PATH",
    "is_duplicate",
    "link_candidates",
    "merge_findings",
    "merge_with_sources",
    "merge_run",
    "merged_records",
    "read_json",
    "sca_records",
    "severity_of",
    "target_get_lines",
]

FINDINGS_NAME: Final = "findings.json"
CANDIDATES_NAME: Final = "candidates.json"
VULNS_PATH: Final = "sca/vulns.json"
TASKS_DIRNAME: Final = "tasks"
TASK_FINDING: Final = "finding.json"
TASK_POC: Final = "poc.json"
TASK_TRANSLATIONS: Final = "translations.json"
TASK_REVIEW: Final = "review.json"
TASK_CONSOLIDATE: Final = "consolidate.json"
TASK_POLISH: Final = "polish.json"
TASK_RESULT: Final = "result.json"

VERDICT_RANK: Final = {"confirmed": 2, "needs_validation": 1, "rejected": 0}
POC_RANK: Final = {"passed": 3, "failed": 2, "blocked": 1, "not_run": 0}
POC_LEVELS: Final = ("unit", "app")
CONFIRMED_FIELDS: Final = (
    "intended_behavior",
    "conditions",
    "execution",
    "remediation",
    "severity",
    "confidence",
)
BLOCKER_CONFIRMED_FIELDS_MISSING: Final = "confirmed_fields_missing"
BLOCKER_SANDBOX_INFEASIBLE: Final = "sandbox_infeasible"
BLOCKER_SANDBOX_UNAVAILABLE: Final = "sandbox_unavailable"
#: The PoC scope statement of runs before 1.7.0 (ADR-0004, replaced by ADR-0006): those runs
#: wrote it as the ``observed_result`` of each skipped PoC. ``i18n.poc_observed`` still matches
#: this exact text, so keep the value. A run of 1.7.0 or later writes ``sandbox_unavailable``.
POC_OUT_OF_SCOPE: Final = (
    "PoC sandbox is not part of this version (ADR-0004); findings rest on engine-verified "
    "static evidence and the final review"
)
POC_ENGINE: Final = "poc-builder"

#: JSON files that the validator limits apply to (task outputs).
TASK_JSON_MAX_BYTES: Final = 5 * 1024 * 1024
#: candidates.json and sca/vulns.json can hold many records; no 1000-item array limit.
BULK_JSON_MAX_BYTES: Final = 64 * 1024 * 1024
#: The largest target file that get_lines reads (the target copy skips larger files).
TARGET_FILE_MAX_BYTES: Final = 5 * 1024 * 1024

_SEVERITY_NAMES: Final = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "info",
    "info": "info",
}
_SEVERITIES: Final = ("critical", "high", "medium", "low", "info")
_FIELD_ORDER: Final = (
    "verdict",
    "fingerprint",
    "title",
    "description",
    "root_cause",
    "claimed_root_cause",
    "intended_behavior",
    "trace",
    "evidence",
    "conditions",
    "execution",
    "remediation",
    "severity",
    "confidence",
    "blockers",
    "validation_plan",
    "reason",
    "id",
    "class",
    "cwe",
    "owasp",
    "engines",
    "candidates",
    "audit_answers",
    "review",
    "duplicate_of",
    "duplicate_reason",
    "related",
    "poc",
    "sca",
    "i18n",
    "cvss",
)
# Engine prose that merge writes into a finding, in the run language.
_POC_OBSERVED_DEFAULT: Final = {
    "tr": {
        "passed": "PoC zafiyeti gösterdi.",
        "failed": "PoC zafiyeti göstermedi.",
        "blocked": "PoC çalıştırılamadı.",
        "not_run": "PoC çalışmadı.",
    },
    "en": {
        "passed": "The PoC demonstrated the vulnerability.",
        "failed": "The PoC did not demonstrate the vulnerability.",
        "blocked": "The PoC could not run.",
        "not_run": "The PoC did not run.",
    },
}
_POC_CONFIDENCE_REASON: Final = {
    "tr": "Sandbox içindeki PoC zafiyeti gösterdi.",
    "en": "The sandbox PoC demonstrated the vulnerability.",
}


# ---------------------------------------------------------------------------------------------
# Input helpers (also used by kalkan.report)


def read_json(
    path: str | os.PathLike[str],
    *,
    max_bytes: int = TASK_JSON_MAX_BYTES,
    enforce_limits: bool = True,
) -> Any:
    """Return the parsed JSON of ``path``.

    Raises ``FileNotFoundError`` when the file does not exist,
    :class:`~kalkan.errors.UnsafeInputError` when it cannot be read safely (symlink, size,
    encoding) and :class:`~kalkan.errors.ValidationError` when it is not valid JSON or, with
    ``enforce_limits``, nests deeper than 64 levels or holds an array of more than 1000 items.
    """
    target = Path(path)
    try:
        os.lstat(target)
    except FileNotFoundError:
        raise
    except (OSError, ValueError) as exc:
        if isinstance(exc, NotADirectoryError):
            raise FileNotFoundError(str(exc)) from None
        raise UnsafeInputError("input could not be opened or read safely") from exc
    text = read_text_bounded(target, max_bytes)
    if enforce_limits:
        enforce_json_text_limits(text)
    return parse_json_text(text)


def target_get_lines(target_dir: str | os.PathLike[str]) -> GetLines:
    """Return a ``get_lines(path)`` callable for the target copy of a run.

    Delegates to :func:`kalkan.run.source.make_get_lines`, the one reader that the verify
    handler also uses, so that ``KF-`` IDs and SARIF fingerprints always agree.
    """
    from kalkan.run.source import make_get_lines

    return make_get_lines(target_dir)


def severity_of(finding: Mapping[str, Any]) -> str | None:
    """Return the overall severity of a finding as a kalkan severity (``informational`` becomes
    ``info``), or None when the finding has none."""
    severity = finding.get("severity")
    value = severity.get("overall_severity") if isinstance(severity, Mapping) else None
    return _SEVERITY_NAMES.get(value) if isinstance(value, str) else None


def is_duplicate(finding: Mapping[str, Any]) -> bool:
    """Return True for a record that consolidation folded into another one (``duplicate_of``).

    The counts of merge and of the report leave such a record out; ``findings.json`` keeps it.
    """
    value = finding.get("duplicate_of")
    return isinstance(value, str) and bool(value)


def sca_records(document: object) -> list[dict[str, Any]] | None:
    """Return the record list of an ``sca/vulns.json`` document, or None for an unknown shape.

    Accepted shapes: a list of records, or an object with a ``records``, ``vulns`` or
    ``vulnerabilities`` list. Entries that are not objects are dropped.
    """
    items: object = None
    if isinstance(document, list):
        items = document
    elif isinstance(document, dict):
        for key in ("records", "vulns", "vulnerabilities"):
            if isinstance(document.get(key), list):
                items = document[key]
                break
    if not isinstance(items, list):
        return None
    return [item for item in items if isinstance(item, dict)]


# ---------------------------------------------------------------------------------------------
# Merge model


@dataclass
class _Source:
    """One finding read from a task output."""

    finding: dict[str, Any]
    task_id: str
    order: int


@dataclass
class _Merged:
    """One merged finding and the tasks whose findings it holds (base task first)."""

    finding: dict[str, Any]
    sources: list[str] = field(default_factory=list)


@dataclass
class _Stats:
    merged_duplicates: int = 0
    poc_applied: int = 0
    reviews: dict[str, int] = field(
        default_factory=lambda: {"applied": 0, "verified": 0, "downgrade": 0, "reject": 0}
    )
    promoted: int = 0
    promotion_refused: int = 0
    translations_applied: int = 0
    consolidation: dict[str, int] = field(
        default_factory=lambda: {"groups": 0, "duplicates": 0, "skipped": 0}
    )
    polish_applied: int = 0
    warnings: list[str] = field(default_factory=list)


def _strings(value: object) -> list[str]:
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


def _union(*lists: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(item for values in lists for item in values))


def _richness(finding: Mapping[str, Any]) -> int:
    score = len(finding.get("evidence") or []) + len(finding.get("trace") or [])
    answers = finding.get("audit_answers")
    if isinstance(answers, Mapping):
        for answer in answers.values():
            if isinstance(answer, Mapping) and isinstance(answer.get("evidence"), list):
                score += len(answer["evidence"])
    return score


def _ordered(finding: Mapping[str, Any]) -> dict[str, Any]:
    """Return ``finding`` with the canonical key order (unknown keys last, in their order)."""
    known = {key: finding[key] for key in _FIELD_ORDER if key in finding}
    rest = {key: value for key, value in finding.items() if key not in known}
    return {**known, **rest}


def _group(sources: list[_Source]) -> list[list[_Source]]:
    parent = list(range(len(sources)))

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    first: dict[str, int] = {}
    for index, source in enumerate(sources):
        keys = []
        if isinstance(source.finding.get("id"), str) and source.finding["id"]:
            keys.append("id\x00" + source.finding["id"])
        keys.append("fp\x00" + source.finding["fingerprint"])
        for key in keys:
            if key in first:
                a, b = find(index), find(first[key])
                if a != b:
                    parent[max(a, b)] = min(a, b)
            else:
                first[key] = index
    groups: dict[int, list[_Source]] = {}
    for index, source in enumerate(sources):
        groups.setdefault(find(index), []).append(source)
    return [groups[root] for root in sorted(groups)]


def _merge_group(group: list[_Source]) -> _Merged:
    best = max(
        group,
        key=lambda s: (VERDICT_RANK[s.finding["verdict"]], _richness(s.finding), -s.order),
    )
    base = copy.deepcopy(best.finding)
    others = [source for source in group if source is not best]
    ordered = [best, *others]
    for source in others:
        if source.finding["verdict"] != base["verdict"]:
            continue
        for entry in source.finding.get("evidence") or []:
            if entry not in base["evidence"]:
                base["evidence"].append(copy.deepcopy(entry))
    for key in ("engines", "candidates", "cwe", "owasp"):
        merged = _union(*(_strings(source.finding.get(key)) for source in ordered))
        if merged:
            base[key] = merged
    if not base.get("class"):
        for source in others:
            if isinstance(source.finding.get("class"), str):
                base["class"] = source.finding["class"]
                break
    pocs = [s.finding["poc"] for s in ordered if isinstance(s.finding.get("poc"), dict)]
    if pocs:
        base["poc"] = copy.deepcopy(max(pocs, key=lambda poc: POC_RANK.get(poc["status"], -1)))
    if "i18n" not in base:
        for source in others:
            if isinstance(source.finding.get("i18n"), dict):
                base["i18n"] = copy.deepcopy(source.finding["i18n"])
                break
    return _Merged(_ordered(base), [source.task_id for source in ordered])


def merge_findings(
    sources: Iterable[tuple[str, Mapping[str, Any]]],
) -> tuple[list[dict[str, Any]], int]:
    """Merge ``(task_id, finding)`` pairs by ``id`` and ``fingerprint``.

    Returns the merged findings (in the order of their first source) and the number of records
    that merged into another one. The findings must be valid; see :func:`merge_run`.
    """
    items = [
        _Source(copy.deepcopy(dict(finding)), task_id, order)
        for order, (task_id, finding) in enumerate(sources)
    ]
    groups = _group(items)
    return [_merge_group(group).finding for group in groups], len(items) - len(groups)


def merge_with_sources(
    sources: Iterable[tuple[str, Mapping[str, Any]]],
) -> list[tuple[dict[str, Any], list[str]]]:
    """Merge ``(task_id, finding)`` pairs like :func:`merge_findings` and return each merged
    finding with the task IDs of its records (base task first)."""
    items = [
        _Source(copy.deepcopy(dict(finding)), task_id, order)
        for order, (task_id, finding) in enumerate(sources)
    ]
    merged = [_merge_group(group) for group in _group(items)]
    return [(item.finding, item.sources) for item in merged]


# ---------------------------------------------------------------------------------------------
# Candidate linking


def _line_ranges(finding: Mapping[str, Any]) -> dict[str, tuple[int, int]]:
    ranges: dict[str, tuple[int, int]] = {}
    for key in ("trace", "evidence"):
        for entry in finding.get(key) or []:
            if not isinstance(entry, Mapping):
                continue
            file, line = entry.get("file"), entry.get("line")
            if not isinstance(file, str) or not isinstance(line, int) or isinstance(line, bool):
                continue
            low, high = ranges.get(file, (line, line))
            ranges[file] = (min(low, line), max(high, line))
    return ranges


def _add_unique(finding: dict[str, Any], key: str, value: str) -> bool:
    values = finding.setdefault(key, [])
    if value in values:
        return False
    values.append(value)
    return True


def link_candidates(
    findings: list[dict[str, Any]], candidates: Iterable[Mapping[str, Any]]
) -> set[str]:
    """Link candidates to findings (ENGINE-SPEC 15) and return the linked candidate IDs.

    The returned set also holds the candidate IDs that the findings already listed.
    """
    linked = {cid for finding in findings for cid in _strings(finding.get("candidates"))}
    ranges = [_line_ranges(finding) for finding in findings]
    for candidate in candidates:
        cid, file, start = candidate.get("id"), candidate.get("file"), candidate.get("start_line")
        if not isinstance(cid, str) or not isinstance(file, str) or not file:
            continue
        if not isinstance(start, int) or isinstance(start, bool):
            continue
        end = candidate.get("end_line")
        end = end if isinstance(end, int) and not isinstance(end, bool) and end >= start else start
        candidate_class = candidate.get("class")
        for finding, finding_ranges in zip(findings, ranges, strict=True):
            finding_class = finding.get("class")
            if candidate_class and finding_class and candidate_class != finding_class:
                continue
            span = finding_ranges.get(file)
            if span is None or start > span[1] or end < span[0]:
                continue
            _add_unique(finding, "candidates", cid)
            engine = candidate.get("engine")
            if isinstance(engine, str) and engine:
                _add_unique(finding, "engines", engine)
            linked.add(cid)
    return linked


# ---------------------------------------------------------------------------------------------
# PoC results and translations


def _poc_record(
    poc: object, lang: str, where: str, warnings: list[str]
) -> tuple[str, dict[str, Any], str | None] | None:
    if not isinstance(poc, dict):
        warnings.append(f"{where}: poc.json is not an object; skipped")
        return None
    finding_id, level, status = poc.get("finding_id"), poc.get("level"), poc.get("status")
    if not isinstance(finding_id, str) or not finding_id:
        warnings.append(f"{where}: poc.json has no finding_id; skipped")
        return None
    if status not in POC_RANK or level not in POC_LEVELS:
        warnings.append(f"{where}: poc.json has an invalid level or status; skipped")
        return None
    observed = poc.get("observed_result")
    if not has_visible_prose(observed):
        observed = _POC_OBSERVED_DEFAULT.get(lang, _POC_OBSERVED_DEFAULT["tr"])[status]
    artifacts: list[str] = []
    for artifact in poc.get("artifacts") or []:
        if is_safe_relative_path(artifact):
            if artifact not in artifacts:
                artifacts.append(artifact)
        else:
            warnings.append(f"{where}: poc.json artifact is not a safe relative path; dropped")
    blocker = poc.get("blocker")
    blocker = blocker.strip() if isinstance(blocker, str) and has_visible_prose(blocker) else None
    record = {"level": level, "status": status, "observed_result": observed, "artifacts": artifacts}
    if blocker:
        record["blocker"] = blocker
    record.update(_poc_run_fields(poc))
    return finding_id, record, blocker


def _poc_run_fields(poc: Mapping[str, Any]) -> dict[str, Any]:
    """Return the valid run facts of a ``poc.json`` (start, duration, exit code, truncation)."""
    fields: dict[str, Any] = {}
    started = poc.get("started_at")
    if isinstance(started, str) and started.strip():
        fields["started_at"] = started.strip()
    duration = poc.get("duration_ms")
    if isinstance(duration, int) and not isinstance(duration, bool) and duration >= 0:
        fields["duration_ms"] = duration
    code = poc.get("exit_code")
    if isinstance(code, int) and not isinstance(code, bool):
        fields["exit_code"] = code
    if isinstance(poc.get("output_truncated"), bool):
        fields["output_truncated"] = poc["output_truncated"]
    return fields


def _verify_finding(run_dir: Path, task_id: str) -> dict[str, Any] | None:
    try:
        result = read_json(run_dir / TASKS_DIRNAME / task_id / TASK_RESULT)
    except (FileNotFoundError, UnsafeInputError, ValidationError):
        return None
    finding = result.get("finding") if isinstance(result, dict) else None
    return finding if isinstance(finding, dict) else None


def _promote(
    merged: _Merged, poc: dict[str, Any], run_dir: Path, lang: str
) -> dict[str, Any] | None:
    current = merged.finding
    for task_id in merged.sources:
        verified = _verify_finding(run_dir, task_id)
        if verified is None or any(key not in verified for key in CONFIRMED_FIELDS):
            continue
        root_cause = verified.get("root_cause")
        if not has_visible_prose(root_cause):
            root_cause = current["claimed_root_cause"]
        execution = copy.deepcopy(verified["execution"])
        if isinstance(execution, dict):
            execution["observed_result"] = poc["observed_result"]
        promoted: dict[str, Any] = {
            key: copy.deepcopy(value)
            for key, value in current.items()
            if key not in ("verdict", "claimed_root_cause", "blockers", "validation_plan")
        }
        promoted.update(
            verdict="confirmed",
            root_cause=root_cause,
            intended_behavior=copy.deepcopy(verified["intended_behavior"]),
            conditions=copy.deepcopy(verified["conditions"]),
            execution=execution,
            remediation=copy.deepcopy(verified["remediation"]),
            severity=copy.deepcopy(verified["severity"]),
            confidence={"score": "high", "reason": _POC_CONFIDENCE_REASON[lang]},
        )
        promoted = _ordered(promoted)
        if not validate_findings([promoted]):
            return promoted
    return None


def _apply_pocs(
    merged: list[_Merged],
    pocs: list[tuple[str, object]],
    run_dir: Path,
    lang: str,
    stats: _Stats,
) -> None:
    by_id = {item.finding["id"]: item for item in merged if isinstance(item.finding.get("id"), str)}
    chosen: dict[str, tuple[tuple[int, int], dict[str, Any], str | None]] = {}
    for order, (task_id, poc) in enumerate(pocs):
        parsed = _poc_record(poc, lang, f"tasks/{task_id}", stats.warnings)
        if parsed is None:
            continue
        finding_id, record, blocker = parsed
        if finding_id not in by_id:
            stats.warnings.append(f"tasks/{task_id}: poc.json names an unknown finding; skipped")
            continue
        rank = (POC_RANK[record["status"]], order)
        if finding_id not in chosen or rank > chosen[finding_id][0]:
            chosen[finding_id] = (rank, record, blocker)
    for finding_id, (_, record, blocker) in chosen.items():
        item = by_id[finding_id]
        finding = item.finding
        existing = finding.get("poc")
        if isinstance(existing, dict) and POC_RANK.get(existing.get("status"), -1) > POC_RANK.get(
            record["status"], -1
        ):
            continue
        finding["poc"] = record
        stats.poc_applied += 1
        status, verdict = record["status"], finding["verdict"]
        if status == "passed":
            _add_unique(finding, "engines", POC_ENGINE)
            if verdict == "confirmed":
                finding["confidence"] = {"score": "high", "reason": _POC_CONFIDENCE_REASON[lang]}
                if isinstance(finding.get("execution"), dict):
                    finding["execution"]["observed_result"] = record["observed_result"]
            elif verdict == "needs_validation":
                promoted = _promote(item, record, run_dir, lang)
                if promoted is not None:
                    item.finding = promoted
                    stats.promoted += 1
                else:
                    _add_unique(finding, "blockers", BLOCKER_CONFIRMED_FIELDS_MISSING)
                    stats.promotion_refused += 1
            else:
                stats.warnings.append(
                    f"{finding_id}: a passed PoC belongs to a rejected finding; verdict kept"
                )
        elif status in ("blocked", "not_run") and verdict == "needs_validation":
            default = (
                BLOCKER_SANDBOX_INFEASIBLE if status == "blocked" else BLOCKER_SANDBOX_UNAVAILABLE
            )
            _add_unique(finding, "blockers", blocker or default)
        item.finding = _ordered(item.finding)


# A weaker verdict after the review is the more conservative outcome.
_REVIEW_STRENGTH: Final = {"rejected": 0, "needs_validation": 1, "confirmed": 2}


def _review_target(merged: list[_Merged], review: Mapping[str, Any]) -> int | None:
    """Return the index of the merged record that a review outcome names, or None."""
    tasks = set(_strings(review.get("verify_tasks")))
    for index, item in enumerate(merged):
        if tasks & set(item.sources):
            return index
    for key, name in (("finding_id", "id"), ("fingerprint", "fingerprint")):
        value = review.get(key)
        if not isinstance(value, str) or not value:
            continue
        for index, item in enumerate(merged):
            if item.finding.get(name) == value:
                return index
    return None


def _apply_reviews(merged: list[_Merged], reviews: list[tuple[str, object]], stats: _Stats) -> None:
    chosen: dict[int, tuple[tuple[int, int], str, dict[str, Any]]] = {}
    for order, (task_id, review) in enumerate(reviews):
        if not isinstance(review, dict) or review.get("decision") not in DECISIONS:
            stats.warnings.append(f"tasks/{task_id}: review.json has no valid decision; skipped")
            continue
        index = _review_target(merged, review)
        if index is None:
            stats.warnings.append(f"tasks/{task_id}: review.json names an unknown finding; skipped")
            continue
        rank = (-_REVIEW_STRENGTH.get(str(review.get("verdict_after")), 2), order)
        if index not in chosen or rank > chosen[index][0]:
            chosen[index] = (rank, task_id, review)
    for index, (_, task_id, review) in sorted(chosen.items()):
        item = merged[index]
        try:
            reviewed = apply_review(item.finding, review)
        except (KeyError, TypeError, ValueError) as exc:
            stats.warnings.append(f"tasks/{task_id}: review not applied ({exc})")
            continue
        errors = validate_findings([reviewed])
        if errors:
            stats.warnings.append(f"tasks/{task_id}: review not applied: {'; '.join(errors[:3])}")
            continue
        item.finding = _ordered(reviewed)
        stats.reviews["applied"] += 1
        stats.reviews[review["decision"]] += 1


def _apply_translations(
    merged: list[_Merged], translations: list[tuple[str, object]], stats: _Stats
) -> None:
    by_id = {item.finding["id"]: item for item in merged if isinstance(item.finding.get("id"), str)}
    applied: set[str] = set()
    for task_id, document in translations:
        entries = document.get("translations") if isinstance(document, dict) else None
        if not isinstance(entries, list):
            stats.warnings.append(f"tasks/{task_id}: translations.json has no list; skipped")
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            finding_id = entry.get("id")
            title, description = entry.get("title"), entry.get("description")
            if not has_visible_prose(title) or not has_visible_prose(description):
                stats.warnings.append(
                    f"tasks/{task_id}: a translation has no visible title or description; skipped"
                )
                continue
            if finding_id not in by_id:
                stats.warnings.append(
                    f"tasks/{task_id}: a translation names an unknown finding; skipped"
                )
                continue
            english = {"title": title, "description": description}
            strategy = entry.get("remediation_strategy")
            if has_visible_prose(strategy):
                english["remediation_strategy"] = strategy
            item = by_id[finding_id]
            item.finding["i18n"] = {"en": english}
            item.finding = _ordered(item.finding)
            applied.add(finding_id)
    stats.translations_applied = len(applied)


# ---------------------------------------------------------------------------------------------
# Run-level merge


def _done_tasks(state: Mapping[str, Any]) -> list[str]:
    tasks = state.get("tasks")
    if not isinstance(tasks, Mapping):
        return []
    done = []
    for task_id, task in tasks.items():
        parsed = parse_task_id(task_id)
        if parsed is not None and isinstance(task, Mapping) and task.get("status") == "done":
            done.append((parsed[0], task_id))
    return [task_id for _, task_id in sorted(done)]


def _dead_poc_tasks(state: Mapping[str, Any]) -> list[str]:
    """Return the dead ``poc_build`` tasks: ``poc:run`` wrote a ``blocked`` poc.json for each."""
    tasks = state.get("tasks")
    if not isinstance(tasks, Mapping):
        return []
    dead = []
    for task_id, task in tasks.items():
        parsed = parse_task_id(task_id)
        if (
            parsed is not None
            and isinstance(task, Mapping)
            and task.get("status") == "dead"
            and task.get("type") == "poc_build"
        ):
            dead.append((parsed[0], task_id))
    return [task_id for _, task_id in sorted(dead)]


def _read_task_json(
    run_dir: Path, task_id: str, name: str, warnings: list[str]
) -> tuple[bool, Any]:
    path = run_dir / TASKS_DIRNAME / task_id / name
    try:
        return True, read_json(path)
    except FileNotFoundError:
        return False, None
    except (UnsafeInputError, ValidationError) as exc:
        warnings.append(f"tasks/{task_id}/{name}: cannot be read ({exc}); skipped")
        return False, None


def _load_candidates(run_dir: Path, warnings: list[str]) -> list[dict[str, Any]] | None:
    try:
        document = read_json(
            run_dir / CANDIDATES_NAME, max_bytes=BULK_JSON_MAX_BYTES, enforce_limits=False
        )
    except FileNotFoundError:
        return None
    except (UnsafeInputError, ValidationError) as exc:
        warnings.append(f"{CANDIDATES_NAME}: cannot be read ({exc}); no candidate is linked")
        return None
    items = document.get("candidates") if isinstance(document, dict) else document
    if not isinstance(items, list):
        warnings.append(f"{CANDIDATES_NAME}: no candidate list; no candidate is linked")
        return None
    valid = [item for item in items if isinstance(item, dict) and not validate_candidate(item)]
    if len(valid) != len(items):
        warnings.append(f"{CANDIDATES_NAME}: {len(items) - len(valid)} invalid candidates skipped")
    return valid


def _count_sca(run_dir: Path, warnings: list[str]) -> int | None:
    try:
        document = read_json(
            run_dir / VULNS_PATH, max_bytes=BULK_JSON_MAX_BYTES, enforce_limits=False
        )
    except FileNotFoundError:
        return None
    except (UnsafeInputError, ValidationError) as exc:
        warnings.append(f"{VULNS_PATH}: cannot be read ({exc})")
        return None
    records = sca_records(document)
    if records is None:
        warnings.append(f"{VULNS_PATH}: unknown document shape")
        return None
    return len(records)


def _count_by(findings: Iterable[Mapping[str, Any]]) -> tuple[dict[str, int], dict[str, int]]:
    """Count the records by verdict and the confirmed records by severity; a duplicate that
    consolidation folded (:func:`is_duplicate`) is not counted."""
    verdicts = dict.fromkeys(VERDICT_RANK, 0)
    severities = dict.fromkeys(_SEVERITIES, 0)
    for finding in findings:
        if is_duplicate(finding):
            continue
        verdicts[finding["verdict"]] += 1
        if finding["verdict"] == "confirmed":
            severity = severity_of(finding)
            if severity is not None:
                severities[severity] += 1
    return verdicts, severities


@dataclass
class _Inputs:
    """The task outputs that merge reads from the done tasks."""

    sources: list[_Source] = field(default_factory=list)
    pocs: list[tuple[str, object]] = field(default_factory=list)
    translations: list[tuple[str, object]] = field(default_factory=list)
    reviews: list[tuple[str, object]] = field(default_factory=list)
    consolidations: list[tuple[str, object]] = field(default_factory=list)
    polishes: list[tuple[str, object]] = field(default_factory=list)
    counts: dict[str, int] = field(
        default_factory=lambda: {
            "done_tasks": 0,
            "finding_files": 0,
            "poc_files": 0,
            "translation_files": 0,
            "review_files": 0,
            "consolidate_files": 0,
            "polish_files": 0,
        }
    )


def _read_inputs(directory: Path, state: Mapping[str, Any], stats: _Stats) -> _Inputs:
    inputs = _Inputs()
    counts = inputs.counts
    for task_id in _done_tasks(state):
        counts["done_tasks"] += 1
        found, document = _read_task_json(directory, task_id, TASK_FINDING, stats.warnings)
        if found:
            counts["finding_files"] += 1
            items = document if isinstance(document, list) else [document]
            for index, item in enumerate(items):
                where = f"tasks/{task_id}/{TASK_FINDING}" + (
                    f"[{index}]" if isinstance(document, list) else ""
                )
                errors = validate_findings([item])
                if errors:
                    shown = "; ".join(errors[:3])
                    stats.warnings.append(f"{where}: invalid finding skipped: {shown}")
                    continue
                inputs.sources.append(_Source(copy.deepcopy(item), task_id, len(inputs.sources)))
        for name, key, target in (
            (TASK_POC, "poc_files", inputs.pocs),
            (TASK_TRANSLATIONS, "translation_files", inputs.translations),
            (TASK_REVIEW, "review_files", inputs.reviews),
            (TASK_CONSOLIDATE, "consolidate_files", inputs.consolidations),
            (TASK_POLISH, "polish_files", inputs.polishes),
        ):
            found, document = _read_task_json(directory, task_id, name, stats.warnings)
            if found:
                counts[key] += 1
                target.append((task_id, document))
    for task_id in _dead_poc_tasks(state):
        found, document = _read_task_json(directory, task_id, TASK_POC, stats.warnings)
        if found:
            counts["poc_files"] += 1
            inputs.pocs.append((task_id, document))
    return inputs


def _consolidation_groups(
    consolidations: list[tuple[str, object]], warnings: list[str]
) -> list[tuple[str, Mapping[str, Any]]]:
    """Return the accepted groups of the ``consolidate.json`` files, in task order."""
    groups: list[tuple[str, Mapping[str, Any]]] = []
    for task_id, document in consolidations:
        items = document.get("groups") if isinstance(document, dict) else None
        if not isinstance(items, list):
            warnings.append(f"tasks/{task_id}: {TASK_CONSOLIDATE} has no group list; skipped")
            continue
        for index, group in enumerate(items):
            if isinstance(group, dict) and group.get("accepted") is True:
                groups.append((f"tasks/{task_id}/{TASK_CONSOLIDATE} group {index}", group))
    return groups


def _polish_corrections(
    polishes: list[tuple[str, object]], warnings: list[str]
) -> list[tuple[str, Mapping[str, Any]]]:
    """Return the accepted corrections of the ``polish.json`` files, in task order."""
    corrections: list[tuple[str, Mapping[str, Any]]] = []
    for task_id, document in polishes:
        items = document.get("applied") if isinstance(document, dict) else None
        if not isinstance(items, list):
            warnings.append(f"tasks/{task_id}: {TASK_POLISH} has no correction list; skipped")
            continue
        for index, entry in enumerate(items):
            if isinstance(entry, dict):
                corrections.append((f"tasks/{task_id}/{TASK_POLISH} applied[{index}]", entry))
    return corrections


def _merge(
    directory: Path, state: Mapping[str, Any], stats: _Stats, *, fold: bool
) -> tuple[list[dict[str, Any]], _Inputs, list[dict[str, Any]] | None, set[str]]:
    """Apply the merge rules 1 to 9 of the module docstring (8 and 9 only with ``fold``)."""
    lang = state["options"]["lang"]
    inputs = _read_inputs(directory, state, stats)
    groups = _group(inputs.sources)
    merged = [_merge_group(group) for group in groups]
    stats.merged_duplicates = len(inputs.sources) - len(groups)
    _apply_reviews(merged, inputs.reviews, stats)
    _apply_pocs(merged, inputs.pocs, directory, lang, stats)
    _apply_translations(merged, inputs.translations, stats)

    findings = [item.finding for item in merged]
    candidates = _load_candidates(directory, stats.warnings)
    linked = link_candidates(findings, candidates or [])
    assign_finding_ids(findings, get_lines=target_get_lines(directory / state["target"]["copy"]))
    if fold:
        folded = fold_groups(findings, _consolidation_groups(inputs.consolidations, stats.warnings))
        stats.consolidation = {
            "groups": folded.applied,
            "duplicates": folded.duplicates,
            "skipped": folded.skipped,
        }
        stats.warnings.extend(folded.warnings)
        polished = apply_corrections(
            findings,
            _polish_corrections(inputs.polishes, stats.warnings),
            check=lambda record: validate_findings([record]),
        )
        stats.polish_applied = polished.applied
        stats.warnings.extend(polished.warnings)
    findings = [_ordered(finding) for finding in findings]
    findings.sort(key=lambda finding: utf16_key(finding["fingerprint"]))
    return findings, inputs, candidates, linked


def merged_records(run_dir: str | os.PathLike[str], *, fold: bool = False) -> list[dict[str, Any]]:
    """Return the records that :func:`merge_run` would write now, without writing anything.

    Without ``fold`` the consolidation groups and the Turkish letter corrections are not
    applied (module docstring, rules 8 and 9). The records are sorted by fingerprint; they are
    not validated as a document.

    Raises :class:`~kalkan.errors.StateError` when ``state.json`` is missing or invalid.
    """
    directory = Path(run_dir)
    findings, _, _, _ = _merge(directory, load_state(directory), _Stats(), fold=fold)
    return findings


def merge_run(run_dir: str | os.PathLike[str], *, write: bool = True) -> dict[str, Any]:
    """Merge the task outputs of the run in ``run_dir`` and write ``findings.json``.

    Returns a summary: counts by verdict and by severity (confirmed findings; folded duplicates
    are left out and counted in ``duplicates_folded``), merged duplicates, linked and unlinked
    candidates, applied PoC results, promotions, reviews, consolidation groups, Turkish letter
    corrections, translations, the SCA record count and the warnings. With ``write=False``
    nothing is written.

    Raises :class:`~kalkan.errors.StateError` when ``state.json`` is missing or invalid and
    :class:`~kalkan.errors.ValidationError` when the merged document fails validation (then no
    file is written).
    """
    directory = Path(run_dir)
    state = load_state(directory)
    stats = _Stats()
    findings, inputs, candidates, linked = _merge(directory, state, stats, fold=True)
    candidate_ids = {item["id"] for item in candidates or []}
    errors = validate_findings(findings)
    if errors:
        raise ValidationError("the merged findings failed validation; nothing written", errors)
    if write:
        atomic_write_json(directory / FINDINGS_NAME, findings)

    by_verdict, by_severity = _count_by(findings)
    sca_count = _count_sca(directory, stats.warnings)
    return {
        "run_id": state["run_id"],
        "findings_file": FINDINGS_NAME,
        "written": write,
        "findings": len(findings),
        "by_verdict": by_verdict,
        "by_severity": by_severity,
        "duplicates_folded": sum(1 for finding in findings if is_duplicate(finding)),
        "merged_duplicates": stats.merged_duplicates,
        "candidates": {
            "available": candidates is not None,
            "total": len(candidate_ids),
            "linked": len(linked & candidate_ids),
            "unlinked": len(candidate_ids - linked),
        },
        "poc": {
            "applied": stats.poc_applied,
            "promoted": stats.promoted,
            "promotion_refused": stats.promotion_refused,
        },
        "reviews": dict(stats.reviews),
        "consolidation": dict(stats.consolidation),
        "polish_applied": stats.polish_applied,
        "translations_applied": stats.translations_applied,
        "sca_records": sca_count,
        "inputs": inputs.counts,
        "warnings": stats.warnings,
    }
