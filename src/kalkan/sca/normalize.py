# SPDX-License-Identifier: MIT
"""Matcher outputs to vulnerability records (ENGINE-SPEC 17).

Three formats become the same record shape (:func:`new_record`):

- **OSV-Scanner JSON** (``osv-scanner scan source -r --format json``): ``results[]`` with a
  ``source.path`` (the manifest or lockfile) and ``packages[]``. Each package lists the full
  OSV entries in ``vulnerabilities[]`` and the alias groups in ``groups[]`` (``ids``,
  ``aliases``, ``max_severity``). One record per group.
- **Grype JSON** (``grype sbom:<sbom> -o json``): ``matches[]`` with ``vulnerability``,
  ``relatedVulnerabilities``, ``matchDetails`` and ``artifact``. One record per match.
- **govulncheck JSON** (``govulncheck -json``): a stream of JSON objects (indented, not one
  per line). Each object has one of ``config``, ``progress``, ``SBOM``, ``osv`` or
  ``finding``. One record per (OSV entry, module) with at least one finding.
  :func:`parse_govulncheck` also returns the finding level per record (module, package or
  symbol) and the call traces, for :mod:`kalkan.sca.reach`.

Severity (:func:`severity_for`): the CVSS score with the ENGINE-SPEC 7 numeric rule when a
score above 0 exists, else the database label (``unknown`` counts as no label), else
``medium``. CVSS 3.x base scores are computed from the vector (:func:`cvss3_base_score`) so that
the stored score and vector belong together. OSV-Scanner also gives ``max_severity`` per group,
which covers CVSS 4.0 vectors.

Malicious packages (ADR-0005, K.2; :func:`mark_malicious`): a record with an OSV ``MAL-`` ID
(OpenSSF malicious-packages) is a known malicious package version. Grype has no ``MAL-`` ID:
its database carries the GitHub malware advisories (GHSA IDs) with a link to the ``MAL-`` record
of ``github.com/ossf/malicious-packages``; :func:`malicious_ids` takes the ``MAL-`` ID from such
a link. A record whose advisory title is the GitHub malware title ("Malicious code in <package>
(<ecosystem>)") is also malicious. Such a record gets ``class: malicious-dependency``, severity
``critical`` and keeps it: reachability never lowers it (:mod:`kalkan.sca.merge`).

A bad entry never stops the parse: it is skipped with a warning.
"""

from __future__ import annotations

import json
import math
import os
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from decimal import ROUND_CEILING, Decimal
from typing import Any

from kalkan.errors import ValidationError
from kalkan.findings import severity as sev
from kalkan.findings.taxonomy import normalize_cwe
from kalkan.sca.sbom import (
    GRYPE_TYPES,
    display_version,
    normalize_package,
    package_key,
    purl_identity,
    relative_location,
)

__all__ = [
    "ENGINE_ORDER",
    "MALICIOUS_CLASS",
    "MALICIOUS_REACHABILITY_REASON",
    "MALICIOUS_TOOL_SEVERITY",
    "make_ref",
    "merge_symbols",
    "GovulncheckResult",
    "NormalizeResult",
    "cvss3_base_score",
    "is_malicious",
    "is_malicious_id",
    "malicious_ids",
    "malware_title",
    "mark_malicious",
    "new_record",
    "parse_govulncheck",
    "parse_govulncheck_text",
    "parse_grype",
    "parse_osv_scanner",
    "primary_id",
    "severity_for",
]

#: Engine preference: the candidate engine is the first engine of a record in this order.
#: ``retirejs`` names the vulnerability ranges of the RetireJS repository (kalkan.sca.vendored).
ENGINE_ORDER: tuple[str, ...] = ("osv-scanner", "grype", "govulncheck", "retirejs")

#: The largest summary that a record keeps.
MAX_SUMMARY_CHARS = 2000

#: The taxonomy class of a known malicious package version (ENGINE-SPEC 3 and 17).
MALICIOUS_CLASS = "malicious-dependency"
#: ``tool_severity`` of a malicious record: the malware classification decides, not a score.
MALICIOUS_TOOL_SEVERITY = "malicious package"
#: ``reachability_reason`` of a malicious record: no reachability task, no downgrade.
MALICIOUS_REACHABILITY_REASON = (
    "not assessed: a malicious package runs code when it is installed, so reachability does "
    "not lower the severity"
)

_MAL = re.compile(r"MAL-[0-9]{4}-[0-9]+", re.IGNORECASE)
_GHSA = re.compile(r"GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}", re.IGNORECASE)
_CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}", re.IGNORECASE)
_LABELS_WITHOUT_MEANING = frozenset({"", "unknown", "none", "n/a"})
# A link to an OpenSSF malicious-packages record, for example
# https://github.com/ossf/malicious-packages/blob/<commit>/osv/malicious/pypi/<name>/MAL-2025-41758.json
_MALICIOUS_PACKAGES_LINK = re.compile(
    r"https://github\.com/ossf/malicious-packages/[^\s?#]*?/(MAL-[0-9]{4}-[0-9]+)\.json",
    re.IGNORECASE,
)
# The summary of every GitHub malware advisory: "Malicious code in <package> (<ecosystem>)".
_MALWARE_TITLE = re.compile(r"Malicious code in \S+ \([^()]+\)")


@dataclass
class NormalizeResult:
    """The records and the warnings of one matcher output."""

    records: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass
class GovulncheckResult(NormalizeResult):
    """govulncheck records plus the reachability facts per record.

    ``levels`` maps ``(module, osv_id)`` to the deepest finding level: ``module``, ``package``
    or ``symbol``. ``traces`` maps the same key to the symbol-level traces; each trace is a list
    of frames ``{module, version, package, function, receiver, file, line}`` from the
    vulnerable symbol to the entry point. ``config`` holds the ``config`` message.

    ``analyzed`` maps the target-relative ``go.mod`` of each scanned module to the module
    paths of its ``SBOM`` message: the modules that provide a package of the build of
    ``./...``. govulncheck 1.8.0 emits no finding at all (not even at module level) for a
    required module outside that list, so this list is the evidence that such a module is
    not imported.
    """

    levels: dict[tuple[str, str], str] = field(default_factory=dict)
    traces: dict[tuple[str, str], list[list[dict[str, Any]]]] = field(default_factory=dict)
    config: dict[str, Any] = field(default_factory=dict)
    analyzed: dict[str, list[str]] = field(default_factory=dict)


# --- the record --------------------------------------------------------------------------------


def new_record(
    *,
    ecosystem: str,
    package: str,
    version: str,
    ids: Iterable[str],
    summary: str = "",
    cvss_score: float | None = None,
    cvss_vector: str | None = None,
    label: str = "",
    cwe: Iterable[str] = (),
    fixed_versions: Iterable[str] = (),
    locations: Iterable[str] = (),
    engine: str,
    affected_symbols: Iterable[Mapping[str, Any]] = (),
    vulnerable_ranges: Iterable[str] = (),
    fallback_id: str = "",
    malicious: bool = False,
) -> dict[str, Any]:
    """Return a vulnerability record (the ``sca/vulns.json`` record shape).

    ``ids`` holds the vulnerability ID and its aliases. :func:`primary_id` picks ``vuln_id``;
    the other IDs become ``aliases``. The severity comes from :func:`severity_for`. A record
    with a ``MAL-`` ID, or with ``malicious`` (a GitHub malware advisory), gets the malicious
    rule of :func:`mark_malicious`.
    """
    unique_ids = _unique_text(ids)
    vuln_id = primary_id(unique_ids, fallback_id or (unique_ids[0] if unique_ids else ""))
    severity, tool_severity = severity_for(cvss_score, label)
    record: dict[str, Any] = {
        "ref": "",
        "ecosystem": ecosystem,
        "package": normalize_package(ecosystem, package),
        "version": display_version(ecosystem, version),
        "vuln_id": vuln_id,
        "aliases": sorted(i for i in unique_ids if i != vuln_id),
        "summary": _clip(summary),
        "severity": severity,
        "severity_original": None,
        "tool_severity": tool_severity,
        "cvss_score": cvss_score if cvss_score is not None and cvss_score > 0 else None,
        "cvss_vector": cvss_vector or None,
        "cwe": _unique_text(normalize_cwe(c) for c in cwe),
        "fixed_versions": _unique_text(display_version(ecosystem, v) for v in fixed_versions),
        "locations": _unique_text(locations),
        "engines": [engine],
        "affected_symbols": merge_symbols([], affected_symbols),
        "vulnerable_ranges": _unique_text(vulnerable_ranges),
        "reachability": "unknown",
        "reachability_reason": "",
        "reachability_source": None,
        "reach_evidence": [],
        "reach_searched": [],
        "reach_task_id": None,
    }
    if malicious:
        record["class"] = MALICIOUS_CLASS
    mark_malicious(record)
    record["ref"] = make_ref(record)
    return record


def make_ref(record: Mapping[str, Any]) -> str:
    """Return ``<ecosystem>/<package>@<version>/<vuln_id>``."""
    return f"{record['ecosystem']}/{record['package']}@{record['version']}/{record['vuln_id']}"


def primary_id(ids: Iterable[str], fallback: str = "") -> str:
    """Return the primary ID: the first ``MAL-`` ID, else the first GHSA ID, else the first CVE
    ID, else ``fallback``.

    A ``MAL-`` ID names a known malicious package version (OpenSSF malicious-packages); it wins
    so that the record keeps one ``ref`` whether OSV-Scanner, Grype or both report it. "First"
    is the smallest in sorted order, so that every engine picks the same ID from the same ID
    set. Without ``fallback`` the first ID in the given order is used.
    """
    values = _unique_text(ids)
    for pattern in (_MAL, _GHSA, _CVE):
        matching = sorted(v for v in values if pattern.fullmatch(v))
        if matching:
            return matching[0]
    if fallback:
        return fallback
    return values[0] if values else ""


def is_malicious_id(value: object) -> bool:
    """Return True for an OSV ``MAL-`` ID (OpenSSF malicious-packages)."""
    return isinstance(value, str) and _MAL.fullmatch(value.strip()) is not None


def malicious_ids(links: Iterable[object]) -> list[str]:
    """Return the ``MAL-`` IDs of the OpenSSF malicious-packages links among ``links``.

    The Grype database carries the GitHub malware advisories with such a link (for example
    ``https://github.com/ossf/malicious-packages/blob/<commit>/osv/malicious/pypi/<name>/
    MAL-2025-41758.json``), but not the ``MAL-`` ID itself.
    """
    found: list[str] = []
    for link in links:
        if not isinstance(link, str):
            continue
        for match in _MALICIOUS_PACKAGES_LINK.finditer(link):
            value = match.group(1).upper()
            if value not in found:
                found.append(value)
    return found


def malware_title(value: object) -> bool:
    """Return True when ``value`` is the title of a GitHub malware advisory ("Malicious code in
    <package> (<ecosystem>)")."""
    return isinstance(value, str) and _MALWARE_TITLE.fullmatch(value.strip()) is not None


def is_malicious(record: Mapping[str, Any]) -> bool:
    """Return True for a known malicious package version: ``class`` is
    ``malicious-dependency`` or one of the record IDs is a ``MAL-`` ID."""
    if record.get("class") == MALICIOUS_CLASS:
        return True
    ids = [record.get("vuln_id"), *(record.get("aliases") or [])]
    return any(is_malicious_id(value) for value in ids)


def mark_malicious(record: dict[str, Any]) -> bool:
    """Apply the malicious rule to ``record`` when :func:`is_malicious` holds; return it.

    The record gets ``class: malicious-dependency``, severity ``critical`` (``tool_severity``
    :data:`MALICIOUS_TOOL_SEVERITY`) and no lowered severity: a ``not_reachable`` decision
    becomes ``unknown``. An open reachability gets the reason
    :data:`MALICIOUS_REACHABILITY_REASON`. The malicious code runs at install time, so the
    reachability of the package does not matter.
    """
    if not is_malicious(record):
        return False
    record["class"] = MALICIOUS_CLASS
    record["severity"] = "critical"
    record["severity_original"] = None
    record["tool_severity"] = MALICIOUS_TOOL_SEVERITY
    if record.get("reachability") == "not_reachable":
        record["reachability"] = "unknown"
    if record.get("reachability") == "unknown" and not record.get("reachability_reason"):
        record["reachability_reason"] = MALICIOUS_REACHABILITY_REASON
    return True


def severity_for(cvss_score: float | None, label: str = "") -> tuple[str, str]:
    """Return ``(severity, tool_severity)``.

    A CVSS score above 0 decides (ENGINE-SPEC 7). Else a database label that
    :func:`kalkan.findings.severity.from_label` knows decides; ``unknown`` and an empty label
    count as no label. Else ``medium`` with an empty ``tool_severity``.
    """
    if cvss_score is not None and cvss_score > 0:
        mapped = sev.from_score(cvss_score)
        if mapped is not None:
            return mapped, _score_text(cvss_score)
    text = label.strip() if isinstance(label, str) else ""
    if text.lower() not in _LABELS_WITHOUT_MEANING:
        mapped = sev.from_label(text)
        if mapped is not None:
            return mapped, text
    return "medium", ""


def _score_text(score: float) -> str:
    return f"{score:.1f}" if score == round(score, 1) else str(score)


# --- CVSS 3.x ----------------------------------------------------------------------------------

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def cvss3_base_score(vector: object) -> float | None:
    """Return the CVSS 3.0 or 3.1 base score of a vector, or None for another text.

    The formula and the rounding follow the CVSS 3.1 specification (section 7.1 and
    Appendix A).
    """
    if not isinstance(vector, str) or not vector.startswith(("CVSS:3.0/", "CVSS:3.1/")):
        return None
    metrics: dict[str, str] = {}
    for part in vector.split("/")[1:]:
        key, _, value = part.partition(":")
        metrics[key] = value
    try:
        scope_changed = {"U": False, "C": True}[metrics["S"]]
        av = _AV[metrics["AV"]]
        ac = _AC[metrics["AC"]]
        pr = (_PR_CHANGED if scope_changed else _PR_UNCHANGED)[metrics["PR"]]
        ui = _UI[metrics["UI"]]
        c, i, a = (_CIA[metrics[key]] for key in ("C", "I", "A"))
    except KeyError:
        return None
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    total = impact + exploitability
    if scope_changed:
        total *= 1.08
    return _roundup(min(total, 10.0))


def _roundup(value: float) -> float:
    # CVSS 3.1 Appendix A: avoid floating point artifacts before rounding up to one decimal.
    integer = round(value * 100000)
    if integer % 10000 == 0:
        return integer / 100000.0
    return float((Decimal(integer) / Decimal(10000)).to_integral_value(ROUND_CEILING)) / 10.0


def _best_vector(
    severities: Iterable[Mapping[str, Any]], known_max: float | None
) -> tuple[float | None, str | None]:
    """Pick ``(score, vector)`` from OSV ``severity`` entries.

    The highest CVSS 3.x score wins with its vector. When ``known_max`` (OSV-Scanner
    ``max_severity``) is higher, it came from another version: the score is ``known_max`` and
    the vector is the first CVSS 4.0 vector, else the first CVSS 2 vector, else the best 3.x
    vector.
    """
    best: tuple[float, str] | None = None
    other: dict[str, str] = {}
    for item in severities:
        kind = str(item.get("type") or "")
        vector = item.get("score")
        if not isinstance(vector, str) or not vector.strip():
            continue
        if kind == "CVSS_V3":
            score = cvss3_base_score(vector.strip())
            if score is not None and (best is None or score > best[0]):
                best = (score, vector.strip())
        elif kind in ("CVSS_V4", "CVSS_V2"):
            other.setdefault(kind, vector.strip())
    if best is not None and (known_max is None or known_max <= best[0] + 0.05):
        return best
    if known_max is not None:
        vector = other.get("CVSS_V4") or other.get("CVSS_V2") or (best[1] if best else None)
        return known_max, vector
    return None, other.get("CVSS_V4") or other.get("CVSS_V2")


# --- OSV-Scanner -------------------------------------------------------------------------------


def parse_osv_scanner(
    doc: Any, target_root: str | os.PathLike[str] | None, source_file: str = "osv.json"
) -> NormalizeResult:
    """Turn OSV-Scanner JSON into records: one record per package and alias group.

    Raise :class:`~kalkan.errors.ValidationError` when ``doc`` has no ``results`` array.
    """
    if not isinstance(doc, Mapping) or not isinstance(doc.get("results"), list):
        message = f"{source_file}: not OSV-Scanner JSON (no 'results' array)"
        raise ValidationError(message, [message])
    outcome = NormalizeResult()
    for result_index, result in enumerate(doc["results"]):
        where = f"{source_file}: results[{result_index}]"
        if not isinstance(result, Mapping):
            outcome.warnings.append(f"{where}: not an object; skipped")
            continue
        source_path = _mapping(result.get("source")).get("path")
        location = relative_location(source_path, target_root)
        if source_path and location is None:
            outcome.warnings.append(f"{where}: the source path is not inside the target")
        for package_index, item in enumerate(_list(result.get("packages"))):
            at = f"{where}.packages[{package_index}]"
            try:
                outcome.records.extend(_osv_package_records(item, location, at, outcome.warnings))
            except Exception as exc:  # one bad package never stops the parse
                outcome.warnings.append(f"{at}: {type(exc).__name__}: {exc}; skipped")
    return outcome


def _osv_package_records(
    item: object, location: str | None, where: str, warnings: list[str]
) -> list[dict[str, Any]]:
    if not isinstance(item, Mapping):
        warnings.append(f"{where}: not an object; skipped")
        return []
    package = _mapping(item.get("package"))
    ecosystem = _text(package.get("ecosystem"))
    name = _text(package.get("name"))
    version = _text(package.get("version"))
    if not (ecosystem and name and version):
        warnings.append(f"{where}: the package has no ecosystem, name or version; skipped")
        return []
    entries = {
        _text(entry.get("id")): entry
        for entry in _list(item.get("vulnerabilities"))
        if isinstance(entry, Mapping) and _text(entry.get("id"))
    }
    groups = [g for g in _list(item.get("groups")) if isinstance(g, Mapping)]
    if not groups:
        # Older outputs have no groups: one group per entry.
        groups = [{"ids": [entry_id], "aliases": [], "max_severity": ""} for entry_id in entries]
    records = []
    for group in groups:
        group_ids = [i for i in _strings(group.get("ids")) if i.strip()]
        group_entries = [entries[i] for i in group_ids if i in entries]
        ids = [*group_ids, *_strings(group.get("aliases"))]
        for entry in group_entries:
            ids.extend(_strings(entry.get("aliases")))
        if not ids:
            continue
        severities = [s for e in group_entries for s in _list(e.get("severity")) if _is_map(s)]
        score, vector = _best_vector(severities, _number(group.get("max_severity")))
        affected = [a for e in group_entries for a in _matching_affected(e, ecosystem, name)]
        records.append(
            new_record(
                ecosystem=ecosystem,
                package=name,
                version=version,
                ids=ids,
                summary=_richest(_osv_summary(e) for e in group_entries),
                cvss_score=score,
                cvss_vector=vector,
                label=_osv_label(group_entries),
                cwe=[c for e in group_entries for c in _osv_cwes(e)],
                fixed_versions=[v for a in affected for v in _osv_fixed(a)],
                locations=[location] if location else [],
                engine="osv-scanner",
                affected_symbols=[s for a in affected for s in _osv_symbols(a, name)],
                vulnerable_ranges=[r for a in affected for r in _osv_ranges(a)],
                fallback_id=group_ids[0] if group_ids else "",
                malicious=any(malware_title(_osv_summary(e)) for e in group_entries),
            )
        )
    return records


def _osv_summary(entry: Mapping[str, Any]) -> str:
    summary = _text(entry.get("summary"))
    if summary:
        return summary
    details = _text(entry.get("details"))
    return details.split("\n\n", 1)[0].strip()


def _osv_label(entries: Sequence[Mapping[str, Any]]) -> str:
    labels = []
    for entry in entries:
        label = _text(_mapping(entry.get("database_specific")).get("severity"))
        if label:
            labels.append(label)
    known = [label for label in labels if sev.from_label(label) is not None]
    if not known:
        return labels[0] if labels else ""
    return max(known, key=lambda label: sev.rank(sev.from_label(label) or "info"))


def _osv_cwes(entry: Mapping[str, Any]) -> list[str]:
    values = _mapping(entry.get("database_specific")).get("cwe_ids")
    return [c for c in _strings(values) if normalize_cwe(c)]


def _ecosystem_base(value: str) -> str:
    return value.split(":", 1)[0].strip()


def _matching_affected(entry: Mapping[str, Any], ecosystem: str, name: str) -> list[Mapping]:
    """Return the ``affected[]`` items of an OSV entry for this package."""
    key = package_key(ecosystem, name)
    found = []
    for affected in _list(entry.get("affected")):
        if not isinstance(affected, Mapping):
            continue
        package = _mapping(affected.get("package"))
        affected_ecosystem = _text(package.get("ecosystem"))
        if _ecosystem_base(affected_ecosystem) != _ecosystem_base(ecosystem):
            continue
        if package_key(ecosystem, _text(package.get("name"))) == key:
            found.append(affected)
    return found


def _osv_fixed(affected: Mapping[str, Any]) -> list[str]:
    fixed = []
    for version_range in _list(affected.get("ranges")):
        if not isinstance(version_range, Mapping) or version_range.get("type") == "GIT":
            continue
        for event in _list(version_range.get("events")):
            value = _text(_mapping(event).get("fixed"))
            if value:
                fixed.append(value)
    return fixed


def _osv_ranges(affected: Mapping[str, Any]) -> list[str]:
    texts = []
    for version_range in _list(affected.get("ranges")):
        if not isinstance(version_range, Mapping) or version_range.get("type") == "GIT":
            continue
        lower = ""
        open_range = False
        for event in _list(version_range.get("events")):
            event = _mapping(event)
            introduced = _text(event.get("introduced"))
            if introduced:
                lower = "" if introduced == "0" else f">={introduced}"
                open_range = True
                continue
            for key, operator in (("fixed", "<"), ("last_affected", "<=")):
                value = _text(event.get(key))
                if value:
                    texts.append(", ".join(p for p in (lower, f"{operator}{value}") if p))
                    lower, open_range = "", False
                    break
        if open_range:
            texts.append(lower or ">=0")
    specific = _mapping(affected.get("database_specific"))
    known = _text(specific.get("last_known_affected_version_range"))
    if known:
        texts.append(known)
    return texts


def _osv_symbols(affected: Mapping[str, Any], name: str) -> list[dict[str, Any]]:
    specific = _mapping(affected.get("ecosystem_specific"))
    symbols = []
    for item in _list(specific.get("imports")):  # Go
        path = _text(_mapping(item).get("path"))
        if path:
            symbols.append({"package": path, "symbols": _strings(_mapping(item).get("symbols"))})
    functions = _strings(_mapping(specific.get("affects")).get("functions"))  # RustSec
    functions += _strings(specific.get("affected_functions"))
    if functions:
        symbols.append({"package": name, "symbols": functions})
    return symbols


# --- Grype -------------------------------------------------------------------------------------


def parse_grype(
    doc: Any, target_root: str | os.PathLike[str] | None, source_file: str = "grype.json"
) -> NormalizeResult:
    """Turn Grype JSON into records: one record per match.

    Raise :class:`~kalkan.errors.ValidationError` when ``doc`` has no ``matches`` array.
    """
    if not isinstance(doc, Mapping) or not isinstance(doc.get("matches"), list):
        message = f"{source_file}: not Grype JSON (no 'matches' array)"
        raise ValidationError(message, [message])
    outcome = NormalizeResult()
    for index, match in enumerate(doc["matches"]):
        where = f"{source_file}: matches[{index}]"
        try:
            record = _grype_record(match, target_root, where, outcome.warnings)
        except Exception as exc:  # one bad match never stops the parse
            outcome.warnings.append(f"{where}: {type(exc).__name__}: {exc}; skipped")
            continue
        if record is not None:
            outcome.records.append(record)
    return outcome


def _grype_record(
    match: object,
    target_root: str | os.PathLike[str] | None,
    where: str,
    warnings: list[str],
) -> dict[str, Any] | None:
    if not isinstance(match, Mapping):
        warnings.append(f"{where}: not an object; skipped")
        return None
    vulnerability = _mapping(match.get("vulnerability"))
    artifact = _mapping(match.get("artifact"))
    related = [r for r in _list(match.get("relatedVulnerabilities")) if isinstance(r, Mapping)]
    vuln_id = _text(vulnerability.get("id"))
    identity = purl_identity(artifact.get("purl")) if artifact.get("purl") else None
    ecosystem = identity[0] if identity else ""
    name = identity[1] if identity else ""
    if not ecosystem:
        ecosystem = GRYPE_TYPES.get(_text(artifact.get("type")), _text(artifact.get("language")))
    name = name or _text(artifact.get("name"))
    version = _text(artifact.get("version")) or (identity[2] if identity else "")
    if not (vuln_id and ecosystem and name and version):
        warnings.append(f"{where}: the match has no ID, ecosystem, package or version; skipped")
        return None
    locations = []
    for item in _list(artifact.get("locations")):
        path = _mapping(item).get("path")
        location = relative_location(path, target_root)
        if location:
            locations.append(location)
        elif path:
            warnings.append(f"{where}: the location is not inside the target; ignored")
    score, vector = _grype_cvss([vulnerability, *related])
    ranges = []
    for detail in _list(match.get("matchDetails")):
        constraint = _text(_mapping(_mapping(detail).get("found")).get("versionConstraint"))
        if constraint:
            ranges.append(re.sub(r"\s*\([^)]*\)\s*$", "", constraint))
    fix = _mapping(vulnerability.get("fix"))
    cwes = [
        _text(_mapping(item).get("cwe"))
        for source in (vulnerability, *related)
        for item in _list(source.get("cwes"))
    ]
    labels = [_text(vulnerability.get("severity"))] + [_text(r.get("severity")) for r in related]
    # GitHub malware advisories name their OpenSSF malicious-packages record only in a link.
    links = [
        link
        for source in (vulnerability, *related)
        for link in (_text(source.get("dataSource")), *_strings(source.get("urls")))
    ]
    mal_ids = malicious_ids(links)
    return new_record(
        ecosystem=ecosystem,
        package=name,
        version=version,
        ids=[vuln_id, *(_text(r.get("id")) for r in related), *mal_ids],
        summary=_text(vulnerability.get("description"))
        or _richest(_text(r.get("description")) for r in related),
        cvss_score=score,
        cvss_vector=vector,
        label=next((label for label in labels if label), ""),
        cwe=[c for c in cwes if normalize_cwe(c)],
        fixed_versions=_strings(fix.get("versions")),
        locations=locations,
        engine="grype",
        vulnerable_ranges=ranges,
        fallback_id=vuln_id,
        malicious=bool(mal_ids) or malware_title(vulnerability.get("description")),
    )


def _grype_cvss(sources: Sequence[Mapping[str, Any]]) -> tuple[float | None, str | None]:
    """Return the highest CVSS 3.x or 4.0 base score with its vector (CVSS 2 as a fallback)."""
    best: tuple[float, str | None] | None = None
    legacy: tuple[float, str | None] | None = None
    for source in sources:
        for item in _list(source.get("cvss")):
            item = _mapping(item)
            score = _number(_mapping(item.get("metrics")).get("baseScore"))
            vector = _text(item.get("vector")) or None
            version = _text(item.get("version"))
            if score is None:
                score = cvss3_base_score(vector)
            if score is None or score <= 0:
                continue
            if version.startswith("2"):
                if legacy is None or score > legacy[0]:
                    legacy = (score, vector)
            elif best is None or score > best[0]:
                best = (score, vector)
    chosen = best or legacy
    return chosen if chosen else (None, None)


# --- govulncheck -------------------------------------------------------------------------------


def parse_govulncheck_text(
    text: str, module_dir: str = "", source_file: str = "govulncheck.json"
) -> GovulncheckResult:
    """Parse the govulncheck JSON stream text (see :func:`parse_govulncheck`)."""
    messages: list[Any] = []
    warnings: list[str] = []
    decoder = json.JSONDecoder()
    index = 0
    length = len(text)
    while index < length:
        while index < length and text[index] in " \t\r\n﻿":
            index += 1
        if index >= length:
            break
        try:
            value, index = decoder.raw_decode(text, index)
        except ValueError as exc:
            warnings.append(f"{source_file}: the JSON stream is broken at offset {index}: {exc}")
            break
        messages.append(value)
    outcome = parse_govulncheck(messages, module_dir, source_file)
    outcome.warnings[:0] = warnings
    return outcome


def parse_govulncheck(
    messages: Iterable[Any], module_dir: str = "", source_file: str = "govulncheck.json"
) -> GovulncheckResult:
    """Turn govulncheck messages into records and reachability facts.

    ``module_dir`` is the target-relative folder of the scanned module (``""`` for the target
    root). Records get the location ``<module_dir>/go.mod``; trace positions in the main
    module become target-relative paths under ``module_dir``.

    The kalkan govulncheck adapter runs one govulncheck per Go module and writes a marker
    object ``{"kalkan_invocation": {"index", "label", "dir"}}`` before the messages of each
    module. The ``dir`` of a marker (null for the target root) replaces ``module_dir`` for
    the messages that follow it. Findings of several modules join: the deepest level wins and
    the records keep every ``go.mod`` location.
    """
    outcome = GovulncheckResult()
    segments: list[tuple[str, list[Any]]] = []
    current_dir, current = module_dir.strip("/"), []
    for message in messages:
        marker = message.get("kalkan_invocation") if isinstance(message, Mapping) else None
        if isinstance(marker, Mapping):
            if current:
                segments.append((current_dir, current))
            folder = marker.get("dir")
            current_dir = (relative_location(folder, None) or "") if folder else ""
            current = []
            continue
        current.append(message)
    if current:
        segments.append((current_dir, current))
    keyed: dict[tuple[str, str], dict[str, Any]] = {}
    for folder, segment in segments:
        _govulncheck_segment(segment, folder, source_file, outcome, keyed)
    outcome.records.extend(record for record in keyed.values() if record["version"])
    return outcome


def _govulncheck_segment(
    messages: list[Any],
    module_dir: str,
    source_file: str,
    outcome: GovulncheckResult,
    keyed: dict[tuple[str, str], dict[str, Any]],
) -> None:
    entries: dict[str, Mapping[str, Any]] = {}
    findings: list[Mapping[str, Any]] = []
    root_modules: set[str] = set()
    sbom_modules: set[str] | None = None
    for index, message in enumerate(messages):
        if not isinstance(message, Mapping):
            outcome.warnings.append(f"{source_file}: message {index} is not an object; skipped")
            continue
        if isinstance(message.get("config"), Mapping):
            outcome.config = dict(message["config"])
        elif isinstance(message.get("SBOM"), Mapping):
            root_modules.update(_strings(message["SBOM"].get("roots")))
            sbom_modules = sbom_modules or set()
            for module in _list(message["SBOM"].get("modules")):
                path = _text(_mapping(module).get("path"))
                if path:
                    sbom_modules.add(path)
        elif isinstance(message.get("osv"), Mapping):
            entry = message["osv"]
            if _text(entry.get("id")):
                entries[_text(entry.get("id"))] = entry
        elif isinstance(message.get("finding"), Mapping):
            findings.append(message["finding"])
    go_mod = f"{module_dir}/go.mod" if module_dir else "go.mod"
    if sbom_modules is not None:
        known = set(outcome.analyzed.get(go_mod, []))
        outcome.analyzed[go_mod] = sorted(known | sbom_modules)

    for index, finding in enumerate(findings):
        osv_id = _text(finding.get("osv"))
        trace = [f for f in _list(finding.get("trace")) if isinstance(f, Mapping)]
        if not osv_id or not trace:
            outcome.warnings.append(f"{source_file}: finding {index} has no OSV ID or trace")
            continue
        first = trace[0]
        module = _text(first.get("module"))
        if not module:
            continue
        key = (module, osv_id)
        if _text(first.get("function")):
            level = "symbol"
        elif _text(first.get("package")):
            level = "package"
        else:
            level = "module"
        if _LEVEL_RANK[level] > _LEVEL_RANK.get(outcome.levels.get(key, ""), -1):
            outcome.levels[key] = level
        if level == "symbol":
            outcome.traces.setdefault(key, []).append(
                [_frame(frame, module_dir, root_modules) for frame in trace]
            )
        if key in keyed:
            if go_mod not in keyed[key]["locations"]:
                keyed[key]["locations"].append(go_mod)
            continue
        entry = entries.get(osv_id, {})
        affected = _matching_affected(entry, "Go", module) if entry else []
        fixed = _text(finding.get("fixed_version"))
        keyed[key] = new_record(
            ecosystem="Go",
            package=module,
            version=_text(first.get("version")),
            ids=[osv_id, *_strings(entry.get("aliases"))],
            summary=_osv_summary(entry) if entry else "",
            cvss_score=None,
            label="",
            cwe=_osv_cwes(entry) if entry else [],
            fixed_versions=[fixed] if fixed else [v for a in affected for v in _osv_fixed(a)],
            locations=[go_mod],
            engine="govulncheck",
            affected_symbols=[s for a in affected for s in _osv_symbols(a, module)],
            vulnerable_ranges=[r for a in affected for r in _osv_ranges(a)],
            fallback_id=osv_id,
        )


_LEVEL_RANK = {"module": 0, "package": 1, "symbol": 2}


def _frame(frame: Mapping[str, Any], module_dir: str, roots: set[str]) -> dict[str, Any]:
    position = _mapping(frame.get("position"))
    filename = _text(position.get("filename")).replace("\\", "/")
    line = position.get("line")
    module = _text(frame.get("module"))
    file = ""
    if filename and (not roots or module in roots):
        prefix = module_dir.strip("/")
        file = f"{prefix}/{filename}" if prefix else filename
        file = relative_location(file, None) or ""
    return {
        "module": module,
        "version": _text(frame.get("version")),
        "package": _text(frame.get("package")),
        "function": _text(frame.get("function")),
        "receiver": _text(frame.get("receiver")),
        "file": file,
        "line": line if isinstance(line, int) and not isinstance(line, bool) and line > 0 else None,
    }


# --- symbols merge (shared with kalkan.sca.merge) ----------------------------------------------


def merge_symbols(
    current: list[dict[str, Any]], extra: Iterable[Mapping[str, Any]]
) -> list[dict[str, Any]]:
    """Join ``{package, symbols[]}`` lists: one item per package, symbols without duplicates."""
    result = [{"package": i["package"], "symbols": list(i["symbols"])} for i in current]
    index = {item["package"]: item for item in result}
    for item in extra:
        package = _text(_mapping(item).get("package"))
        if not package:
            continue
        symbols = _strings(_mapping(item).get("symbols"))
        known = index.get(package)
        if known is None:
            known = {"package": package, "symbols": []}
            index[package] = known
            result.append(known)
        for symbol in symbols:
            if symbol.strip() and symbol.strip() not in known["symbols"]:
                known["symbols"].append(symbol.strip())
    return result


# --- small helpers -----------------------------------------------------------------------------


def _richest(values: Iterable[str]) -> str:
    best = ""
    for value in values:
        text = value.strip() if isinstance(value, str) else ""
        if len(text) > len(best):
            best = text
    return best


def _clip(text: str) -> str:
    text = text.strip() if isinstance(text, str) else ""
    if len(text) <= MAX_SUMMARY_CHARS:
        return text
    return text[: MAX_SUMMARY_CHARS - 3].rstrip() + "..."


def _unique_text(values: Iterable[object]) -> list[str]:
    seen: list[str] = []
    for value in values:
        if isinstance(value, str) and value.strip() and value.strip() not in seen:
            seen.append(value.strip())
    return seen


def _number(value: object) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        number = float(value)
    elif isinstance(value, str) and value.strip():
        try:
            number = float(value.strip())
        except ValueError:
            return None
    else:
        return None
    return number if math.isfinite(number) and number >= 0 else None


def _text(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


def _strings(value: object) -> list[str]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []


def _is_map(value: object) -> bool:
    return isinstance(value, Mapping)


def _mapping(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _list(value: object) -> list[Any]:
    return value if isinstance(value, list) else []
