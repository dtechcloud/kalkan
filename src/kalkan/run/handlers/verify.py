# SPDX-License-Identifier: MIT
"""Handler of ``verify`` results: build the canonical finding (docs/PHASES.md section 4,
docs/ENGINE-SPEC.md section 18 "Building a finding").

1. The result's ``subject`` must equal the task's subject.
2. Cosmetic slips of an honest result are repaired before the strict checks, and every repair
   is listed in ``verdict.json`` (``normalized``): the trace gets ``entrypoint`` first, ``sink``
   last and ``propagation`` between, in the agent's order of steps
   (:func:`kalkan.run.cleaning.normalize_trace`); cited paths lose ``./`` prefixes and
   backslashes; exact duplicate evidence, conditions and payloads are removed; a code change
   with an unsafe file name is dropped; a ``needs_validation`` finding without a visible
   validation plan gets an engine plan that names its blockers. Quotes, lines and the verdict
   rules never change.
3. :func:`kalkan.findings.quote_verify.evaluate` with the target's ``get_lines`` computes the
   verdict and keeps only the verified quotes. When the verdict is ``confirmed``, the result
   must carry every confirmed-branch field (``intended_behavior``, ``conditions``,
   ``execution``, ``remediation``, ``severity``, ``confidence``); otherwise the result is
   rejected (``ValidationError``).
4. The finding keeps only the fields of its branch. ``root_cause`` becomes
   ``claimed_root_cause`` for ``needs_validation`` and ``rejected``. ``needs_validation`` gets the
   agent's blockers plus the engine reason codes (``unverified_evidence``,
   ``ungrounded_refutation``; ``unknown:<question>`` when nothing else names a blocker).
   ``confirmed`` gets a static ``execution.observed_result`` prefix, ``confidence`` at most
   ``medium`` and ``overall_severity`` at most the impact.
5. ``fingerprint`` = ``<class>:<sink file>:<sink scope>`` reduced to the allowed characters; a
   honored ``duplicate_of`` (not for ``rejected``) takes the fingerprint of the named claim, so
   ``kalkan.findings.merge`` keeps one record with the strongest verdict.
6. ``id`` from :func:`kalkan.findings.fingerprint.assign_finding_ids` with the real
   ``get_lines``; ``engines`` (``hunter`` or the deterministic engine, plus ``verifier``),
   ``candidates`` (deterministic subjects), ``audit_answers`` (verified), ``class``, ``cwe`` (the
   result's, else the class default) and ``owasp`` (taxonomy).
7. :func:`kalkan.findings.validate.validate_findings` must pass; then the handler writes
   ``tasks/<id>/finding.json`` and ``tasks/<id>/verdict.json`` (verdict, reason codes,
   duplicate decision, normalization notes).
"""

from __future__ import annotations

import copy
import re
from typing import Any, Final

from kalkan.errors import ValidationError
from kalkan.findings import quote_verify
from kalkan.findings.fingerprint import assign_finding_ids
from kalkan.findings.taxonomy import get_class, normalize_cwe, owasp_for_class
from kalkan.findings.validate import validate_findings
from kalkan.run.cleaning import (
    clean_text,
    fingerprint_for,
    normalize_path,
    normalize_trace,
    unique,
)
from kalkan.run.runfiles import read_task_json, target_get_lines, task_input, write_json
from kalkan.run.state import RunContext, parse_task_id
from kalkan.util.paths import is_safe_relative_path

CONFIRMED_FIELDS: Final = (
    "intended_behavior",
    "conditions",
    "execution",
    "remediation",
    "severity",
    "confidence",
)
_SEVERITY_RANK: Final = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_ENGINE: Final = re.compile(r"\A[a-z0-9][a-z0-9._-]*\Z")
_CANDIDATE_ID: Final = re.compile(r"\ACAND-[0-9A-F]{16}\Z")
_STATIC_PREFIX: Final = {
    "tr": "Yalnızca statik analiz (PoC çalışmadı):",
    "en": "Static analysis only (no PoC ran):",
}
_STATIC_MARKERS: Final = ("static analysis", "statik analiz")
_ENGINE_PLAN: Final = {
    "tr": "Motor bu bulguyu doğrulanmış kabul etmedi. Şu engelleri kaynakta veya yerel bir "
    "testte çöz: {blockers}.",
    "en": "The engine did not accept this finding as confirmed. Resolve these blockers in "
    "source or in a local test: {blockers}.",
}


def _paths(items: list[Any], where: str, notes: list[str]) -> list[Any]:
    """Return ``items`` with normalized ``file`` paths (:func:`normalize_path`)."""
    out = []
    for item in items:
        if isinstance(item, dict) and "file" in item:
            path = normalize_path(item["file"])
            if path != item["file"]:
                notes.append(f"{where} path {item['file']!r} -> {path!r}")
                item = {**item, "file": path}
        out.append(item)
    return out


def _unique_noted(items: list[Any], where: str, notes: list[str]) -> list[Any]:
    kept = _dedupe_items(items)
    if len(kept) != len(items):
        notes.append(f"{len(items) - len(kept)} duplicate {where} item(s) removed")
    return kept


def _normalize_answers(answers: dict[str, Any], notes: list[str]) -> dict[str, Any]:
    """Return the audit answers with normalized evidence paths (the quotes stay as given)."""
    out = {}
    for question, answer in answers.items():
        if isinstance(answer, dict) and isinstance(answer.get("evidence"), list):
            answer = {
                **answer,
                "evidence": _paths(answer["evidence"], f"audit_answers.{question}", notes),
            }
        out[question] = answer
    return out


def _execution(execution: dict[str, Any], notes: list[str]) -> dict[str, Any]:
    result = copy.deepcopy(execution)
    if isinstance(result.get("payloads"), list):
        result["payloads"] = _unique_noted(result["payloads"], "execution.payloads", notes)
    return result


def _remediation(remediation: dict[str, Any], notes: list[str]) -> dict[str, Any]:
    result = copy.deepcopy(remediation)
    changes = result.get("code_changes")
    if isinstance(changes, list):
        kept = []
        for change in changes:
            name = normalize_path(change.get("file_name")) if isinstance(change, dict) else None
            if isinstance(name, str) and is_safe_relative_path(name):
                kept.append({**change, "file_name": name})
            else:
                notes.append("remediation code change without a safe file name dropped")
        result["code_changes"] = kept
    return result


def _dedupe_items(items: list[Any]) -> list[Any]:
    out: list[Any] = []
    for item in items:
        if item not in out:
            out.append(copy.deepcopy(item))
    return out


def _cwe(finding: dict[str, Any], class_slug: str) -> list[str]:
    values = unique(value for value in map(normalize_cwe, finding.get("cwe") or []) if value)
    if values:
        return values
    vuln_class = get_class(class_slug)
    return list(vuln_class.cwe) if vuln_class is not None else []


def _validation_plan(
    source: dict[str, Any], blockers: list[str], lang: str, notes: list[str]
) -> dict[str, str]:
    plan = source.get("validation_plan") or {}
    kept = {
        key: plan[key]
        for key in ("local", "deployment")
        if isinstance(plan.get(key), str) and clean_text(plan[key])
    }
    if kept:
        return kept
    notes.append("validation_plan: engine plan from the blockers (the result gave none)")
    template = _ENGINE_PLAN.get(lang, _ENGINE_PLAN["en"])
    return {"local": template.format(blockers=", ".join(blockers))}


def _blockers(finding: dict[str, Any], evaluation: dict[str, Any]) -> list[str]:
    blockers = [text for text in map(clean_text, finding.get("blockers") or []) if text]
    blockers += [code for _, code in sorted(evaluation["reasons"].items())]
    if not blockers:
        blockers = [
            f"unknown:{question}"
            for question in quote_verify.QUESTIONS
            if evaluation["audit_answers"][question]["status"] != "established"
        ]
    return unique(blockers) or ["needs_validation"]


def _static_execution(execution: dict[str, Any], lang: str) -> dict[str, Any]:
    result = copy.deepcopy(execution)
    observed = clean_text(result.get("observed_result")) or ""
    prefix = _STATIC_PREFIX.get(lang, _STATIC_PREFIX["en"])
    if not any(marker in observed.lower() for marker in _STATIC_MARKERS):
        observed = f"{prefix} {observed}".strip()
    result["observed_result"] = observed
    return result


def _severity(severity: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(severity)
    impact = result["impact"]["score"]
    if _SEVERITY_RANK[result["overall_severity"]] > _SEVERITY_RANK[impact]:
        result["overall_severity"] = impact
    return result


def _confidence(confidence: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(confidence)
    if result.get("score") == "high":
        result["score"] = "medium"
    return result


def _audit_answers(evaluation: dict[str, Any]) -> dict[str, Any]:
    answers = {}
    for question in quote_verify.QUESTIONS:
        answer = evaluation["audit_answers"][question]
        answers[question] = {
            "status": answer["status"],
            "reason": answer["reason"] or "-",
            "evidence": _dedupe_items(
                [
                    {"file": item["file"], "line": item["line"], "quote": item["quote"]}
                    for item in answer["evidence"]
                    if item["quote"]
                ]
            ),
        }
    return answers


def _duplicate_fingerprint(ctx: RunContext, ref: object, own_task: str) -> str | None:
    """Return the fingerprint of the claim that ``duplicate_of`` names, or None."""
    if not isinstance(ref, str) or not ref.strip():
        return None
    ref = ref.strip()
    for task_id, task in ctx.state["tasks"].items():
        meta = task.get("meta") or {}
        if task["type"] != "verify" or task_id == own_task or meta.get("subject") != ref:
            continue
        finding = read_task_json(ctx, task_id, "finding.json")
        if isinstance(finding, dict) and isinstance(finding.get("fingerprint"), str):
            return finding["fingerprint"]
        if isinstance(meta.get("fingerprint"), str):
            return meta["fingerprint"]
    hunt_task, _, index = ref.partition("#")
    if parse_task_id(hunt_task) is not None and index.isdigit():
        data = read_task_json(ctx, hunt_task, "candidates.json")
        for item in (data or {}).get("candidates", []) if isinstance(data, dict) else []:
            if item.get("index") == int(index) and isinstance(item.get("fingerprint"), str):
                return item["fingerprint"]
    return None


def build_finding(
    ctx: RunContext, task: dict[str, Any], result: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return ``(finding, verdict_record)`` for a verify result (module docstring, steps 1-6)."""
    task_id = task["id"]
    data = task_input(ctx, task_id)
    subject = data.get("subject")
    if isinstance(subject, dict) and result["subject"] != subject:
        raise ValidationError(
            f"the result of {task_id} verifies another subject",
            [f"$result.subject: must be {subject}"],
        )
    source = result["finding"]
    notes: list[str] = []
    answers = _normalize_answers(result["audit_answers"], notes)
    get_lines = target_get_lines(ctx)
    evaluation = quote_verify.evaluate(answers, get_lines)
    verdict = evaluation["verdict"]
    if verdict == "confirmed":
        missing = [name for name in CONFIRMED_FIELDS if name not in source]
        if missing:
            raise ValidationError(
                f"the result of {task_id} gives three established answers with verified "
                "quotes, but not the confirmed-branch fields",
                [f"$result.finding: missing {name}" for name in missing],
            )
    class_slug = source["class"]
    trace, trace_notes = normalize_trace(source["trace"])
    notes += trace_notes
    computed = fingerprint_for(class_slug, trace)
    duplicate = (
        None
        if verdict == "rejected"
        else _duplicate_fingerprint(ctx, result.get("duplicate_of"), task_id)
    )
    finding: dict[str, Any] = {
        "verdict": verdict,
        "fingerprint": duplicate or computed,
        "title": source["title"],
        "description": source["description"],
    }
    if verdict == "confirmed":
        finding["root_cause"] = source["root_cause"]
        finding["intended_behavior"] = source["intended_behavior"]
    else:
        finding["claimed_root_cause"] = source["root_cause"]
    finding["trace"] = trace
    evidence = _paths(source["evidence"], "evidence", notes)
    finding["evidence"] = _unique_noted(evidence, "evidence", notes)
    if verdict == "confirmed":
        finding["conditions"] = _unique_noted(source["conditions"], "conditions", notes)
        finding["execution"] = _static_execution(_execution(source["execution"], notes), ctx.lang)
        finding["remediation"] = _remediation(source["remediation"], notes)
        finding["severity"] = _severity(source["severity"])
        finding["confidence"] = _confidence(source["confidence"])
    elif verdict == "needs_validation":
        finding["blockers"] = _blockers(source, evaluation)
        finding["validation_plan"] = _validation_plan(source, finding["blockers"], ctx.lang, notes)
    else:
        finding["reason"] = source["reason"]
    finding["class"] = class_slug
    finding["cwe"] = _cwe(source, class_slug)
    finding["owasp"] = owasp_for_class(class_slug)
    if isinstance(subject, dict) and subject.get("kind") == "deterministic":
        claim = data.get("claim") or {}
        engine = claim.get("engine") if isinstance(claim, dict) else None
        valid = isinstance(engine, str) and _ENGINE.fullmatch(engine) is not None
        finding["engines"] = unique([engine if valid else "tool", "verifier"])
        if isinstance(subject.get("ref"), str) and _CANDIDATE_ID.fullmatch(subject["ref"]):
            finding["candidates"] = [subject["ref"]]
    else:
        finding["engines"] = ["hunter", "verifier"]
    finding["audit_answers"] = _audit_answers(evaluation)
    assign_finding_ids([finding], get_lines=get_lines)
    record = {
        "task_id": task_id,
        "verdict": verdict,
        "reasons": evaluation["reasons"],
        "fingerprint": finding["fingerprint"],
        "computed_fingerprint": computed,
        "duplicate_of": result.get("duplicate_of"),
        "duplicate_honored": duplicate is not None,
        "finding_id": finding["id"],
        "normalized": notes,
    }
    return finding, record


def handle(ctx: RunContext, task: dict[str, Any], result: dict[str, Any]) -> None:
    """Build, validate and write the canonical finding of a verify result."""
    finding, record = build_finding(ctx, task, result)
    errors = validate_findings([finding])
    if errors:
        raise ValidationError(
            f"the result of {task['id']} does not give a valid canonical finding", errors
        )
    directory = ctx.task_dir(task["id"])
    write_json(directory / "finding.json", finding)
    write_json(directory / "verdict.json", record)
