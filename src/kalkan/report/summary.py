# SPDX-License-Identifier: MIT
"""Machine-readable report outputs: ``summary.json`` and ``findings.sarif``
(docs/ENGINE-SPEC.md, sections 8.2 and 16).

:func:`build_sarif` calls :func:`kalkan.sarif.emit.emit` for the findings and appends the SCA
records as extra results: one rule per vulnerability ID, the level from the severity,
``properties.kind = "sca"`` and the reachability in the properties. A known malicious package
version always has level ``error``, the properties ``class: malicious-dependency`` and
``malicious: true``, a rule tagged ``malicious`` and CWE-506, and the remediation in its
message. ``summary.json`` counts these records (``counts.sca_malicious``) and lists them
(``malicious_dependencies``). Unverified tool candidates
are left out unless ``include_candidates`` is set; then each one becomes a result with
``properties.kind = "candidate"``.

:func:`build_summary` returns the ``summary.json`` document: counts, engines, coverage, budget,
missing inputs and the report file paths. The finding counts leave out the records that
consolidation folded into a primary record; ``counts.duplicates_folded`` counts them. In SARIF
such a record stays a result with an ``external`` suppression (:mod:`kalkan.sarif.emit`).
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Any, Final
from urllib.parse import quote

from kalkan.findings.merge import VERDICT_RANK
from kalkan.findings.severity import from_label, to_sarif_level, to_security_severity
from kalkan.findings.taxonomy import normalize_cwe
from kalkan.report.model import SEVERITY_ORDER, ReportModel, ScaRecord, clean, get_lines_for
from kalkan.sarif.emit import SOURCE_ROOT_ID, emit
from kalkan.sca.merge import MALICIOUS_REMEDIATION
from kalkan.sca.normalize import MALICIOUS_CLASS
from kalkan.util.paths import is_safe_relative_path

__all__ = [
    "CANDIDATE_FINGERPRINT_KEY",
    "SCA_FINGERPRINT_KEY",
    "SUMMARY_SCHEMA_VERSION",
    "build_sarif",
    "build_summary",
]

SUMMARY_SCHEMA_VERSION: Final = 1
SCA_FINGERPRINT_KEY: Final = "kalkanSca/v1"
CANDIDATE_FINGERPRINT_KEY: Final = "kalkanCandidate/v1"
SCA_CWE: Final = "CWE-1395"
MALICIOUS_CWE: Final = "CWE-506"


def _sha256(*parts: str) -> str:
    text = "\x00".join(parts)
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()


def _location(file: str, start: int | None = None, end: int | None = None) -> dict[str, Any]:
    physical: dict[str, Any] = {
        "artifactLocation": {"uri": quote(file, safe="/"), "uriBaseId": SOURCE_ROOT_ID}
    }
    if start is not None and start >= 1:
        region: dict[str, Any] = {"startLine": start}
        if end is not None and end >= start:
            region["endLine"] = end
        physical["region"] = region
    return {"physicalLocation": physical}


def _sca_result(record: ScaRecord, rule_id: str, rule_index: int) -> dict[str, Any]:
    fixed = ", ".join(record.fixed_versions)
    text = f"{record.package} {record.version}"
    if record.ecosystem:
        text += f" ({record.ecosystem})"
    if record.malicious:
        text += f" is a known malicious package version: {record.vuln_id}. "
        text += MALICIOUS_REMEDIATION
    else:
        text += f" is affected by {record.vuln_id}."
        text += f" Fixed versions: {fixed}." if fixed else " No fixed version is known."
    if record.summary:
        text += f"\n\n{record.summary}"
    result: dict[str, Any] = {
        "ruleId": rule_id,
        "ruleIndex": rule_index,
        "level": "error" if record.malicious else to_sarif_level(record.severity),
        "message": {"text": text},
    }
    locations = [item for item in record.locations if is_safe_relative_path(item)]
    if locations:
        result["locations"] = [_location(locations[0])]
    result["partialFingerprints"] = {
        SCA_FINGERPRINT_KEY: _sha256(
            record.ecosystem, record.package, record.version, record.vuln_id
        )
    }
    properties: dict[str, Any] = {
        "kind": "sca",
        "ecosystem": record.ecosystem,
        "package": record.package,
        "version": record.version,
        "vulnIds": list(record.ids),
        "fixedVersions": list(record.fixed_versions),
        "reachability": record.reachability,
    }
    if record.severity:
        properties["severity"] = record.severity
        properties["security-severity"] = to_security_severity(record.severity)
    if record.cvss_score is not None:
        properties["cvssScore"] = record.cvss_score
    if record.cvss_vector:
        properties["cvssVector"] = record.cvss_vector
    if record.engines:
        properties["engines"] = list(record.engines)
    if record.pin_source:
        properties["pinSource"] = record.pin_source
    if record.vendored_files:
        properties["vendoredFiles"] = list(record.vendored_files)
    if record.malicious:
        properties["class"] = MALICIOUS_CLASS
        properties["malicious"] = True
    result["properties"] = properties
    return result


def _candidate_rule_and_result(
    candidate: Mapping[str, Any], rule_id: str, rule_index: int
) -> tuple[dict[str, Any], dict[str, Any]]:
    cwes = [cwe for cwe in map(normalize_cwe, candidate.get("cwe") or []) if cwe]
    severity = (
        from_label(candidate["severity"]) if isinstance(candidate.get("severity"), str) else None
    )
    title = clean(candidate.get("title")) or clean(candidate.get("rule_id"))
    rule = {
        "id": rule_id,
        "shortDescription": {"text": title or rule_id},
        "properties": {
            "tags": ["security", "candidate", *(f"external/cwe/cwe-{cwe[4:]}" for cwe in cwes)]
        },
    }
    message = "\n\n".join(part for part in (title, clean(candidate.get("message"))) if part)
    result: dict[str, Any] = {
        "ruleId": rule_id,
        "ruleIndex": rule_index,
        "level": to_sarif_level(severity),
        "message": {"text": message or rule_id},
    }
    file = candidate.get("file")
    if isinstance(file, str) and is_safe_relative_path(file):
        start, end = candidate.get("start_line"), candidate.get("end_line")
        result["locations"] = [
            _location(
                file,
                start if isinstance(start, int) and not isinstance(start, bool) else None,
                end if isinstance(end, int) and not isinstance(end, bool) else None,
            )
        ]
    result["partialFingerprints"] = {CANDIDATE_FINGERPRINT_KEY: clean(candidate.get("id"))}
    properties: dict[str, Any] = {
        "kind": "candidate",
        "verdict": "unverified",
        "candidateId": clean(candidate.get("id")),
        "engine": clean(candidate.get("engine")),
        "toolRuleId": clean(candidate.get("rule_id")),
    }
    if severity:
        properties["severity"] = severity
        properties["security-severity"] = to_security_severity(severity)
    if isinstance(candidate.get("class"), str):
        properties["class"] = candidate["class"]
    if cwes:
        properties["cwe"] = cwes
    if isinstance(candidate.get("confidence"), str):
        properties["confidence"] = candidate["confidence"]
    result["properties"] = properties
    return rule, result


def build_sarif(model: ReportModel, *, include_candidates: bool = False) -> dict[str, Any]:
    """Return the SARIF 2.1.0 document of the report.

    The findings come from :func:`kalkan.sarif.emit.emit` (with the source lines of the target
    copy, so that the partial fingerprints match the finding IDs). SCA records follow as extra
    results. Unverified tool candidates are added only with ``include_candidates``.
    """
    document = emit(
        model.findings,
        tool_version=model.kalkan_version,
        run_id=model.run_id,
        get_lines=get_lines_for(model),
    )
    run = document["runs"][0]
    rules: list[dict[str, Any]] = run["tool"]["driver"]["rules"]
    results: list[dict[str, Any]] = run["results"]
    index = {rule["id"]: position for position, rule in enumerate(rules)}

    sca_rules: dict[str, str] = {}
    for record in model.sca:
        wanted = record.vuln_id or "unknown-vulnerability"
        if wanted not in sca_rules:
            rule_id = _free_rule_id(wanted, "sca", index)
            sca_rules[wanted] = rule_id
            index[rule_id] = len(rules)
            if record.malicious:
                fallback = f"Malicious dependency: {wanted}"
                tags = ["security", "sca", "malicious", f"external/cwe/cwe-{MALICIOUS_CWE[4:]}"]
            else:
                fallback = f"Vulnerable dependency: {wanted}"
                tags = ["security", "sca", f"external/cwe/cwe-{SCA_CWE[4:]}"]
            rules.append(
                {
                    "id": rule_id,
                    "shortDescription": {"text": record.summary or fallback},
                    "properties": {"tags": tags},
                }
            )
        rule_id = sca_rules[wanted]
        results.append(_sca_result(record, rule_id, index[rule_id]))

    if include_candidates:
        candidate_rules: dict[str, str] = {}
        for candidate in model.tool_results:
            wanted = f"{clean(candidate.get('engine'))}/{clean(candidate.get('rule_id'))}"
            known = wanted in candidate_rules
            rule_id = (
                candidate_rules[wanted] if known else _free_rule_id(wanted, "candidate", index)
            )
            rule, result = _candidate_rule_and_result(
                candidate, rule_id, index[rule_id] if known else len(rules)
            )
            if not known:
                candidate_rules[wanted] = rule_id
                index[rule_id] = len(rules)
                rules.append(rule)
            results.append(result)
    return document


def _free_rule_id(wanted: str, prefix: str, taken: Mapping[str, Any]) -> str:
    """Return the first free ID: ``wanted``, ``<prefix>/<wanted>``, then with a counter."""
    if wanted not in taken:
        return wanted
    candidate = f"{prefix}/{wanted}"
    counter = 2
    while candidate in taken:
        candidate = f"{prefix}/{wanted}/{counter}"
        counter += 1
    return candidate


def build_summary(
    model: ReportModel, *, lang: str, paths: Mapping[str, str] | None = None
) -> dict[str, Any]:
    """Return the ``summary.json`` document for ``model``.

    ``paths`` maps an output name (``report_md``, ``findings_sarif`` and others) to its path
    relative to the run folder.
    """
    by_engine: dict[str, dict[str, int]] = {}
    for engine, items in model.tool_results_by_engine().items():
        counts = dict.fromkeys(SEVERITY_ORDER, 0)
        for item in items:
            severity = item.get("severity")
            counts[severity if severity in counts else "info"] += 1
        by_engine[clean(engine)] = {name: count for name, count in counts.items() if count}
    reachability = {"reachable": 0, "not_reachable": 0, "unknown": 0}
    for record in model.sca:
        reachability[record.reachability] = reachability.get(record.reachability, 0) + 1
    verdicts = model.verdict_counts()
    return {
        "schema_version": SUMMARY_SCHEMA_VERSION,
        "run_id": model.run_id,
        "generated_at": model.generated_at,
        "kalkan_version": model.kalkan_version,
        "lang": lang,
        "run_lang": model.run_lang,
        "target": {
            "source": model.target_source or None,
            "kind": model.target_kind or None,
            "git_ref": model.git_ref,
        },
        "profile": model.profile,
        "run": {
            "type": model.run_type(),
            "elapsed_seconds": model.elapsed_seconds(),
            "usage": model.usage,
            "usage_source": (
                "claude stream-json result events (kalkan-audit rounds)"
                if model.usage
                else "not recorded: an interactive session or a tools-only run"
            ),
        },
        "phase": model.phase,
        "complete": model.complete,
        "partial": bool(model.partial_reasons),
        "partial_reasons": [
            {
                "code": key.removeprefix("partial_"),
                **{k: clean(v) if isinstance(v, str) else v for k, v in values.items()},
            }
            for key, values in model.partial_reasons
        ],
        "counts": {
            "findings": sum(verdicts.values()),
            "by_verdict": {name: verdicts[name] for name in VERDICT_RANK},
            "by_severity": model.severity_counts(),
            "template_only": len(model.template_confirmed),
            "duplicates_folded": len(model.duplicates),
            "candidates": model.candidates_total,
            "tool_results": len(model.tool_results),
            "tool_results_by_engine": by_engine,
            "sca": len(model.sca),
            "sca_by_reachability": reachability,
            "sca_malicious": len(model.sca_malicious()),
            "hardening": len(model.hardening),
            "unvalidated_candidates": len(model.unvalidated),
        },
        "malicious_dependencies": [
            {
                "ecosystem": record.ecosystem,
                "package": record.package,
                "version": record.version,
                "vuln_ids": list(record.ids),
                "locations": list(record.locations),
            }
            for record in model.sca_malicious()
        ],
        "unvalidated_candidates": [
            {
                "fingerprint": row.fingerprint,
                "title": row.title,
                "class": row.slug,
                "file": row.file or None,
                "line": row.line,
                "refs": list(row.refs),
                "units": list(row.units),
            }
            for row in model.unvalidated
        ],
        "engines": [
            {
                "engine": engine.engine,
                "group": engine.group,
                "status": engine.status,
                "message": engine.message,
                "tool_version": engine.tool_version,
                "duration_seconds": engine.duration_seconds,
            }
            for engine in model.engines
        ],
        "coverage": (
            {
                "units": model.ledger_total,
                "open": model.ledger_open,
                "by_status": model.ledger,
                "closed_by_siblings": model.ledger_sibling_closed,
            }
            if model.ledger is not None
            else None
        ),
        "review": {
            "separate_pass": model.profile != "fast" if model.profile else None,
            **model.review_counts(),
        },
        "coverage_gaps": {
            "unchecked_manifests": [
                {
                    "file": item.file,
                    "ecosystem": item.ecosystem,
                    "reason": item.reason,
                    "exact_pins": item.exact_pins,
                    "ranges": item.ranges,
                }
                for item in model.unchecked_manifests
            ],
            "database_gaps": [
                {"engine": item.engine, "ecosystem": item.ecosystem, "reason": item.reason}
                for item in model.database_gaps
            ],
            "engines": {
                clean(gap.engine): {
                    "partial_files": gap.partial_count,
                    "skipped_files": gap.skipped_count,
                    "partial_packages": gap.package_count,
                }
                for gap in model.scan_gaps
            },
            "long_paths": model.long_paths["count"] if model.long_paths else 0,
            "sca_from_manifest_pins": model.sca_from_pins(),
            "sca_from_vendored_files": len(model.sca_vendored()),
        },
        "sbom": (
            {"components": len(model.sbom.components), "by_source": model.sbom.by_source()}
            if model.sbom is not None
            else None
        ),
        "budget": model.budget,
        "sca_source": model.sca_source,
        "missing_inputs": list(model.missing),
        "warnings": list(model.warnings),
        "paths": dict(paths or {}),
    }
