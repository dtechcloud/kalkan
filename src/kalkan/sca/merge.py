# SPDX-License-Identifier: MIT
"""Record merge rules, ``sca/vulns.json`` and the SCA candidates (ENGINE-SPEC 17).

Merge rule (:func:`merge_records`): two records merge when their ``(ecosystem, package,
version)`` keys match (:func:`kalkan.sca.sbom.package_key` and
:func:`kalkan.sca.sbom.version_key`) and their ID sets (``vuln_id`` plus ``aliases``)
intersect. The merge is transitive inside one key. The merged record keeps the union of the
IDs, fixed versions, locations, engines, CWEs, affected symbols and vulnerable ranges, the
highest severity (with its CVSS score and vector) and the longest summary. The primary ID and
the ``ref`` are computed again from the joined ID set.

``sca/vulns.json`` is ``{"schema_version": 1, "records": [...], "warnings": [...]}`` plus,
after ``sca match``, ``unchecked_manifests`` (``kalkan/schemas/vulns.schema.json``).
:func:`write_vulns` validates and writes it atomically.

A known malicious package version (:func:`kalkan.sca.normalize.mark_malicious`: a ``MAL-`` ID,
or a GitHub malware advisory) carries ``class: malicious-dependency`` and severity
``critical``. A merged record is malicious when one input is, or when the joined ID set holds a
``MAL-`` ID. Reachability never lowers it: :func:`set_reachability` turns ``not_reachable`` into
``unknown`` for such a record, :func:`carry_over` skips it, and its candidate has the class
``malicious-dependency`` (CWE-506) with the remediation "remove the package and the version;
treat the machines that installed it as exposed".

A record found only through the exact pins of a manifest without a lockfile
(:mod:`kalkan.sca.manifests`) carries ``pin_source: "manifest"``; a record found only in a
vendored JavaScript file (:mod:`kalkan.sca.vendored`) carries ``pin_source: "vendored"``. A
merged record keeps ``pin_source`` only when every merged input carries the same value. The
optional ``vendored`` entries (file, line, library, version, extractor) and ``references``
(advisory links) of the inputs are joined.

:func:`build_candidates` makes one candidate per record (ENGINE-SPEC 4). The candidate file is
the manifest or lockfile location; :func:`find_package_line` finds the line of the package
entry with a bounded text search. For a vendored file the line of the detection is used
(``vendored``), never a text search of the (often minified) file. :func:`write_candidates`
hands the candidates to ``kalkan.scanners.candidates.merge_candidates`` under the source name
``sca``.
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

from kalkan.errors import KalkanError, ToolError, UnsafeInputError, ValidationError
from kalkan.findings import severity as sev
from kalkan.findings.fingerprint import candidate_id
from kalkan.sca.normalize import (
    ENGINE_ORDER,
    MALICIOUS_CLASS,
    MALICIOUS_REACHABILITY_REASON,
    is_malicious,
    make_ref,
    mark_malicious,
    merge_symbols,
    primary_id,
)
from kalkan.sca.sbom import package_key, version_key
from kalkan.util.paths import is_safe_relative_path
from kalkan.util.safe_io import DEFAULT_MAX_BYTES, atomic_write_json, read_text_bounded

__all__ = [
    "CANDIDATE_SOURCE",
    "MALICIOUS_REMEDIATION",
    "MAX_SCAN_LINES",
    "SCHEMA_VERSION",
    "VULNS_FILE",
    "build_candidates",
    "carry_over",
    "empty_doc",
    "find_package_line",
    "locate",
    "lower_severity",
    "merge_records",
    "read_vulns",
    "set_reachability",
    "sort_records",
    "source_lines",
    "validate_vulns",
    "vulns_path",
    "write_candidates",
    "write_vulns",
]

SCHEMA_VERSION = 1
#: ``sca/vulns.json`` relative to the run folder (also ``raw.sarif_file`` of the candidates).
VULNS_FILE = "sca/vulns.json"
#: ``merge_candidates`` source name of the SCA candidates.
CANDIDATE_SOURCE = "sca"
#: The line lookup reads at most this many lines of a manifest.
MAX_SCAN_LINES = 200_000
#: The longest line part that the line lookup compares.
MAX_LINE_CHARS = 4000
#: The largest vulns.json that :func:`read_vulns` reads.
MAX_VULNS_BYTES = 64 * 1024 * 1024
#: A merged record keeps at most this many advisory links (``references``).
MAX_REFERENCES = 20
#: The snippet of a vendored file is a window of this many characters around the version.
VENDORED_SNIPPET_CHARS = 240
#: The first CWE of an SCA candidate: a vulnerable dependency, or a malicious one.
VULNERABLE_CWE = "CWE-1395"
MALICIOUS_CWE = "CWE-506"
#: The remediation of a malicious record (candidate message; the report has its own text).
MALICIOUS_REMEDIATION = (
    "Remove the package and this version, and regenerate the lockfile. Treat every machine "
    "that installed it (developer machines, CI runners, build images) as exposed, rotate the "
    "secrets that the install could read, and check the lockfile history for the commit that "
    "added it."
)
#: Engine order for ``engines`` and for the candidate engine.
_ENGINE_RANK = {engine: index for index, engine in enumerate(ENGINE_ORDER)}
_REACH_FIELDS = (
    "reachability",
    "reachability_reason",
    "reachability_source",
    "reach_evidence",
    "reach_searched",
    "reach_task_id",
)


# --- merge -------------------------------------------------------------------------------------


def merge_records(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Merge records (see the module docstring) and return them in :func:`sort_records` order.

    The inputs are not changed. Inside one merged record the first input record, in engine
    order (osv-scanner, grype, govulncheck) and then input order, gives the display package
    name, version and the fallback primary ID.
    """
    ordered = sorted(
        enumerate(records),
        key=lambda pair: (_engine_rank(pair[1].get("engines")), pair[0]),
    )
    by_key: dict[tuple[str, str, str], list[Mapping[str, Any]]] = {}
    for _, record in ordered:
        by_key.setdefault(_record_key(record), []).append(record)
    merged: list[dict[str, Any]] = []
    for group in by_key.values():
        for component in _components(group):
            merged.append(_merge_component(component))
    return sort_records(merged)


def sort_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Sort records by severity (critical first), then by ``ref``."""
    return sorted(records, key=lambda r: (-sev.rank(r["severity"]), r["ref"]))


def _record_key(record: Mapping[str, Any]) -> tuple[str, str, str]:
    ecosystem = str(record.get("ecosystem") or "")
    return (
        ecosystem,
        package_key(ecosystem, str(record.get("package") or "")),
        version_key(ecosystem, str(record.get("version") or "")),
    )


def _ids(record: Mapping[str, Any]) -> set[str]:
    values = {str(record.get("vuln_id") or "")}
    values.update(str(alias) for alias in record.get("aliases") or [])
    values.discard("")
    return values


def _components(group: list[Mapping[str, Any]]) -> list[list[Mapping[str, Any]]]:
    """Split records of one key into groups whose ID sets intersect (union-find)."""
    parent = list(range(len(group)))

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    owner: dict[str, int] = {}
    for index, record in enumerate(group):
        for identifier in sorted(_ids(record)):
            if identifier in owner:
                left, right = find(owner[identifier]), find(index)
                if left != right:
                    parent[max(left, right)] = min(left, right)
            else:
                owner[identifier] = index
    components: dict[int, list[Mapping[str, Any]]] = {}
    for index, record in enumerate(group):
        components.setdefault(find(index), []).append(record)
    return [components[root] for root in sorted(components)]


def _merge_component(records: list[Mapping[str, Any]]) -> dict[str, Any]:
    first = records[0]
    merged = {key: _copy(value) for key, value in first.items()}
    all_ids: list[str] = []
    for record in records:
        for identifier in [record.get("vuln_id"), *(record.get("aliases") or [])]:
            if isinstance(identifier, str) and identifier and identifier not in all_ids:
                all_ids.append(identifier)
    for record in records[1:]:
        _absorb(merged, record)
    merged["vuln_id"] = primary_id(all_ids, str(first.get("vuln_id") or ""))
    merged["aliases"] = sorted(i for i in all_ids if i != merged["vuln_id"])
    merged["engines"] = sorted(
        dict.fromkeys(e for r in records for e in r.get("engines") or []),
        key=lambda engine: (_ENGINE_RANK.get(engine, len(_ENGINE_RANK)), engine),
    )
    merged["ref"] = make_ref(merged)
    sources = {record.get("pin_source") for record in records}
    if len(sources) != 1 or None in sources:
        merged.pop("pin_source", None)
    if any(record.get("class") == MALICIOUS_CLASS for record in records):
        merged["class"] = MALICIOUS_CLASS
    mark_malicious(merged)
    return merged


def _absorb(merged: dict[str, Any], other: Mapping[str, Any]) -> None:
    other_rank = sev.rank(other["severity"])
    current_rank = sev.rank(merged["severity"])
    other_score = other.get("cvss_score")
    current_score = merged.get("cvss_score")
    higher_score = isinstance(other_score, int | float) and (
        not isinstance(current_score, int | float) or other_score > current_score
    )
    if other_rank > current_rank or (other_rank == current_rank and higher_score):
        for key in ("severity", "tool_severity", "cvss_score", "cvss_vector"):
            merged[key] = other.get(key)
    if len(str(other.get("summary") or "")) > len(str(merged.get("summary") or "")):
        merged["summary"] = other.get("summary") or ""
    for key in ("cwe", "fixed_versions", "locations", "vulnerable_ranges"):
        merged[key] = _union(merged.get(key) or [], other.get(key) or [])
    merged["affected_symbols"] = merge_symbols(
        merged.get("affected_symbols") or [], other.get("affected_symbols") or []
    )
    if other.get("references"):
        merged["references"] = _union(merged.get("references") or [], other["references"])[
            :MAX_REFERENCES
        ]
    if other.get("vendored"):
        entries = [_copy(entry) for entry in merged.get("vendored") or []]
        for entry in other["vendored"]:
            if entry not in entries:
                entries.append(_copy(entry))
        merged["vendored"] = entries


def _union(left: Iterable[str], right: Iterable[str]) -> list[str]:
    return list(dict.fromkeys([*left, *right]))


def _engine_rank(engines: object) -> int:
    if isinstance(engines, list) and engines:
        return min(_ENGINE_RANK.get(str(e), len(_ENGINE_RANK)) for e in engines)
    return len(_ENGINE_RANK)


def _copy(value: Any) -> Any:
    if isinstance(value, list):
        return [_copy(item) for item in value]
    if isinstance(value, dict):
        return {key: _copy(item) for key, item in value.items()}
    return value


# --- reachability state ------------------------------------------------------------------------


def lower_severity(severity: str) -> str:
    """Return the severity one level lower; ``info`` stays ``info``."""
    order = sev.SEVERITIES
    index = order.index(sev.max_severity(severity) or "info")
    return order[min(index + 1, len(order) - 1)]


def set_reachability(
    record: dict[str, Any],
    reachability: str,
    *,
    reason: str,
    evidence: Sequence[Mapping[str, Any]] = (),
    source: str | None,
    searched: Sequence[str] = (),
    task_id: str | None = None,
) -> None:
    """Set the reachability fields of ``record`` and keep the severity rule.

    ``not_reachable`` lowers the severity by one level and keeps the earlier severity in
    ``severity_original``. Any other value restores ``severity_original``. Thus the rule holds
    after repeated calls: ``severity_original`` is set exactly when the record is
    ``not_reachable``.

    A malicious record (:func:`kalkan.sca.normalize.is_malicious`) is never lowered: a
    ``not_reachable`` answer is stored as ``unknown`` with the reason prefixed by
    :data:`kalkan.sca.normalize.MALICIOUS_REACHABILITY_REASON`.
    """
    if reachability not in ("reachable", "not_reachable", "unknown"):
        raise ValueError(f"unknown reachability: {reachability!r}")
    if is_malicious(record) and reachability == "not_reachable":
        reachability = "unknown"
        reason = f"{MALICIOUS_REACHABILITY_REASON}: {reason.strip()}".rstrip(": ")
    base = record.get("severity_original") or record["severity"]
    if reachability == "not_reachable":
        record["severity_original"] = base
        record["severity"] = lower_severity(base)
    else:
        record["severity"] = base
        record["severity_original"] = None
    record["reachability"] = reachability
    record["reachability_reason"] = reason.strip()
    record["reachability_source"] = source
    record["reach_evidence"] = [
        {"file": str(e["file"]), "line": int(e["line"]), "quote": str(e["quote"])} for e in evidence
    ]
    record["reach_searched"] = [s.strip() for s in searched if isinstance(s, str) and s.strip()]
    record["reach_task_id"] = task_id


def carry_over(records: list[dict[str, Any]], previous: Iterable[Mapping[str, Any]]) -> int:
    """Copy the reachability decisions of ``previous`` records into matching new records.

    A previous record matches by ``ref``, else by key and an intersecting ID set. The
    severity rule of :func:`set_reachability` is applied to the new severity. A malicious
    record keeps its own state (reachability does not apply to it). Returns the number of
    records that got a decision.
    """
    by_ref: dict[str, Mapping[str, Any]] = {}
    by_key: dict[tuple[str, str, str], list[Mapping[str, Any]]] = {}
    for old in previous:
        if not isinstance(old, Mapping) or (
            old.get("reachability") == "unknown" and not old.get("reach_task_id")
        ):
            continue
        by_ref[str(old.get("ref"))] = old
        by_key.setdefault(_record_key(old), []).append(old)
    count = 0
    for record in records:
        if is_malicious(record):
            continue
        old = by_ref.get(record["ref"])
        if old is None:
            ids = _ids(record)
            old = next((o for o in by_key.get(_record_key(record), []) if _ids(o) & ids), None)
        if old is None:
            continue
        set_reachability(
            record,
            str(old.get("reachability") or "unknown"),
            reason=str(old.get("reachability_reason") or ""),
            evidence=[e for e in old.get("reach_evidence") or [] if isinstance(e, Mapping)],
            source=old.get("reachability_source"),
            searched=[s for s in old.get("reach_searched") or [] if isinstance(s, str)],
            task_id=old.get("reach_task_id"),
        )
        count += 1
    return count


# --- vulns.json --------------------------------------------------------------------------------


def vulns_path(run_dir: str | os.PathLike[str]) -> Path:
    """Return ``<run>/sca/vulns.json``."""
    return Path(run_dir) / "sca" / "vulns.json"


def empty_doc() -> dict[str, Any]:
    """Return an empty vulns.json document."""
    return {"schema_version": SCHEMA_VERSION, "records": [], "warnings": []}


def validate_vulns(doc: object) -> list[str]:
    """Return the errors of a vulns.json document (an empty list means valid).

    The document is checked against ``kalkan/schemas/vulns.schema.json``. Records are checked
    one by one, so the 1000-item array limit of the validator does not cap the record count.
    The function also checks that every ``ref`` matches its fields and is unique, that
    ``severity_original`` is set exactly for ``not_reachable`` records, and that a
    ``malicious-dependency`` record is ``critical`` and never ``not_reachable``.
    """
    from kalkan.schema.loader import shared_schema
    from kalkan.schema.validator import collect_data_limit_errors, collect_unchecked

    schema = shared_schema("vulns")
    if not isinstance(doc, dict):
        return ["$: expected an object"]
    records = doc.get("records")
    shell = dict(doc)
    if isinstance(records, list):
        shell["records"] = []
    errors = list(collect_data_limit_errors(shell, "$")) or list(
        collect_unchecked(shell, schema, "$")
    )
    if not isinstance(records, list):
        return errors
    record_schema = schema["properties"]["records"]["items"]
    seen: set[str] = set()
    for index, record in enumerate(records):
        where = f"$.records[{index}]"
        record_errors = list(collect_data_limit_errors(record, where)) or list(
            collect_unchecked(record, record_schema, where)
        )
        errors.extend(record_errors)
        if record_errors or not isinstance(record, dict):
            continue
        if record["ref"] != make_ref(record):
            errors.append(f"{where}.ref: does not match <ecosystem>/<package>@<version>/<vuln_id>")
        if record["ref"] in seen:
            errors.append(f"{where}.ref: duplicate ref {record['ref']!r}")
        seen.add(record["ref"])
        lowered = record["severity_original"] is not None
        if lowered != (record["reachability"] == "not_reachable"):
            errors.append(f"{where}.severity_original: must be set exactly for not_reachable")
        if record.get("class") == MALICIOUS_CLASS and (
            record["severity"] != "critical" or record["reachability"] == "not_reachable"
        ):
            errors.append(f"{where}: a malicious-dependency record stays critical")
        if len(errors) >= 100:
            break
    return errors[:100]


def write_vulns(
    run_dir: str | os.PathLike[str],
    records: list[dict[str, Any]],
    warnings: Sequence[str],
    unchecked_manifests: Sequence[Mapping[str, Any]] | None = None,
    database_gaps: Sequence[Mapping[str, Any]] | None = None,
) -> Path:
    """Validate and write ``<run>/sca/vulns.json`` atomically. Return the path.

    ``unchecked_manifests`` (the manifests without a lockfile, :mod:`kalkan.sca.manifests`) and
    ``database_gaps`` (matchers without a local database, :mod:`kalkan.sca.vulndb`) are written
    when they are not None (``database_gaps`` only when it is not empty); callers that rewrite
    an existing document pass their values on.
    Raise :class:`~kalkan.errors.ValidationError` when the document does not validate (an
    engine bug, never input data).
    """
    doc: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "records": records,
        "warnings": list(dict.fromkeys(str(w) for w in warnings)),
    }
    if database_gaps:
        doc["database_gaps"] = [dict(item) for item in database_gaps]
    if unchecked_manifests is not None:
        doc["unchecked_manifests"] = [dict(item) for item in unchecked_manifests]
    errors = validate_vulns(doc)
    if errors:
        raise ValidationError("sca/vulns.json failed validation", errors)
    path = vulns_path(run_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_json(path, doc)
    return path


def read_vulns(run_dir: str | os.PathLike[str]) -> dict[str, Any]:
    """Read and validate ``<run>/sca/vulns.json``. A missing file gives :func:`empty_doc`.

    Raise :class:`~kalkan.errors.ValidationError` for a file that is not valid.
    """
    import json

    path = vulns_path(run_dir)
    if not path.exists():
        return empty_doc()
    try:
        text = read_text_bounded(path, MAX_VULNS_BYTES)
        doc = json.loads(text)
    except (UnsafeInputError, ValueError) as exc:
        message = f"sca/vulns.json cannot be read: {exc}"
        raise ValidationError(message, [message]) from exc
    errors = validate_vulns(doc)
    if errors:
        raise ValidationError("sca/vulns.json failed validation", errors)
    return doc


# --- candidates --------------------------------------------------------------------------------

#: File-specific patterns of a package entry; ``{n}`` is the escaped package name pattern.
_DEFINITIONS: dict[str, str] = {
    "package-lock.json": r'"(?:[^"]*/)?node_modules/{n}"\s*:|^\s*"{n}"\s*:\s*\{{',
    "npm-shrinkwrap.json": r'"(?:[^"]*/)?node_modules/{n}"\s*:|^\s*"{n}"\s*:\s*\{{',
    "package.json": r'^\s*"{n}"\s*:',
    "yarn.lock": r'^"?{n}@',
    "pnpm-lock.yaml": r"^\s*['\"]?/?{n}[@/(]",
    "bun.lock": r'^\s*"{n}"\s*:',
    "go.mod": r"^\s*(?:require\s+)?{n}\s+v",
    "go.sum": r"^{n}\s+v",
    "poetry.lock": r'^name\s*=\s*"{n}"',
    "uv.lock": r'^name\s*=\s*"{n}"',
    "pdm.lock": r'^name\s*=\s*"{n}"',
    "cargo.lock": r'^name\s*=\s*"{n}"',
    "cargo.toml": r"^\s*{n}\s*=",
    "pipfile.lock": r'^\s*"{n}"\s*:\s*\{{',
    "pipfile": r"^\s*['\"]?{n}['\"]?\s*=",
    "pyproject.toml": r"['\"]{n}\s*[<>=!~\[;'\"]",
    "pom.xml": r"<artifactId>\s*{n}\s*</artifactId>",
    "build.gradle": r"['\"][^'\"]*:{n}:",
    "build.gradle.kts": r"['\"][^'\"]*:{n}:",
    "gradle.lockfile": r"^[^:]+:{n}:",
    "gemfile.lock": r"^\s{{4}}{n}\s\(",
    "composer.lock": r'"name"\s*:\s*"{n}"',
    "composer.json": r'^\s*"{n}"\s*:',
    "gemfile": r"^\s*gem\s*\(?\s*['\"]{n}['\"]",
    "gems.rb": r"^\s*gem\s*\(?\s*['\"]{n}['\"]",
    "packages.lock.json": r'^\s*"{n}"\s*:\s*\{{',
    "packages.config": r'id="{n}"',
}
_REQUIREMENTS = r"^\s*{n}\s*(?:[<>=!~\[;@]|$)"


def find_package_line(
    lines: Sequence[str], file_name: str, ecosystem: str, package: str, version: str
) -> int | None:
    """Return the 1-based line of the package entry in a manifest, or None.

    A bounded text search over at most :data:`MAX_SCAN_LINES` lines. A line must name the
    package as a whole token. The best line scores highest: a file-specific entry pattern
    (``"node_modules/<name>":`` in ``package-lock.json``, ``<name>==`` in requirements files,
    ``<module> v<version>`` in ``go.mod``, ...), the version on the line or in the next three
    lines. Comment lines of requirements files are skipped. The first best line wins.
    """
    name = _name_regex(ecosystem, package)
    if name is None:
        return None
    base = file_name.replace("\\", "/").rsplit("/", 1)[-1].lower()
    flags = re.IGNORECASE if ecosystem == "PyPI" else 0
    token = re.compile(rf"(?<![A-Za-z0-9_.-]){name}(?![A-Za-z0-9_-]|\.[A-Za-z0-9])", flags)
    template = _DEFINITIONS.get(base)
    is_requirements = base.endswith(".txt") or base.endswith(".in")
    if template is None and is_requirements:
        template = _REQUIREMENTS
    definition = re.compile(template.format(n=name), flags) if template else None
    version_re = _version_regex(ecosystem, version)
    best_score, best_line = 0, None
    limit = min(len(lines), MAX_SCAN_LINES)
    for index in range(limit):
        line = lines[index][:MAX_LINE_CHARS]
        if not token.search(line):
            continue
        stripped = line.strip()
        if is_requirements and stripped.startswith("#"):
            continue
        if base == "go.mod" and stripped.startswith("//"):
            continue
        score = 1
        if definition is not None and definition.search(line):
            score += 4
        if version_re is not None:
            if version_re.search(line):
                score += 3
            elif any(
                version_re.search(lines[i][:MAX_LINE_CHARS])
                for i in range(index + 1, min(index + 4, limit))
            ):
                score += 2
        if score > best_score:
            best_score, best_line = score, index + 1
    return best_line


def _name_regex(ecosystem: str, package: str) -> str | None:
    name = package.strip()
    if not name:
        return None
    if ecosystem == "Maven" and ":" in name:
        name = name.rsplit(":", 1)[-1]
    if ecosystem == "PyPI":
        parts = [p for p in re.split(r"[-_.]+", name) if p]
        return r"[-_.]+".join(re.escape(p) for p in parts) if parts else None
    return re.escape(name)


def _version_regex(ecosystem: str, version: str) -> re.Pattern[str] | None:
    text = version.strip()
    if not text:
        return None
    if ecosystem == "Go" and text.startswith("v"):
        text = text[1:]
    pattern = rf"(?<![0-9A-Za-z.])v?{re.escape(text)}(?![0-9A-Za-z]|\.[0-9])"
    if ecosystem == "PyPI" and re.fullmatch(r"[0-9]+(?:\.[0-9]+)*", text):
        # PEP 440: 5.3 equals 5.3.0.
        parts = text.split(".")
        while len(parts) > 1 and int(parts[-1]) == 0:
            parts.pop()
        release = re.escape(".".join(parts))
        pattern = rf"(?<![0-9A-Za-z.]){release}(?:\.0)*(?![0-9A-Za-z]|\.[0-9])"
    return re.compile(pattern)


class _LineSource:
    """Reads target files once, bounded and inside the target root."""

    def __init__(self, target_dir: str | os.PathLike[str] | None) -> None:
        self.root = Path(target_dir).resolve() if target_dir is not None else None
        self.cache: dict[str, list[str] | None] = {}

    def lines(self, relative: str) -> list[str] | None:
        if relative not in self.cache:
            self.cache[relative] = self._read(relative)
        return self.cache[relative]

    def _read(self, relative: str) -> list[str] | None:
        if self.root is None or not is_safe_relative_path(relative):
            return None
        path = self.root / relative
        try:
            if not path.resolve().is_relative_to(self.root):
                return None
            text = read_text_bounded(path, DEFAULT_MAX_BYTES)
        except (KalkanError, OSError, ValueError):
            return None
        return text.split("\n")


def source_lines(target_dir: str | os.PathLike[str] | None) -> Callable[[str], list[str] | None]:
    """Return a cached ``get_lines(path)`` for target-relative paths (bounded reads)."""
    return _LineSource(target_dir).lines


def locate(
    record: Mapping[str, Any], get_lines: Callable[[str], list[str] | None]
) -> list[tuple[str, int | None, str]]:
    """Return ``(file, line, line text)`` for each location of a record (line None when the
    entry is not found).

    A vendored file (an entry of ``vendored``) gives the line of its detection (None for a
    file name or hash detection) and a short window of that line around the version.
    """
    hints: dict[str, int | None] = {}
    for entry in record.get("vendored") or []:
        if isinstance(entry, Mapping) and isinstance(entry.get("file"), str):
            line = entry.get("line")
            valid = isinstance(line, int) and not isinstance(line, bool) and line > 0
            hints.setdefault(entry["file"], line if valid else None)
    found = []
    for location in record.get("locations") or []:
        if location in hints:
            line = hints[location]
            lines = get_lines(location) if line is not None else None
            text = ""
            if lines is not None and line is not None and line <= len(lines):
                text = _window(lines[line - 1].rstrip("\r"), str(record.get("version") or ""))
            found.append((location, line, text))
            continue
        lines = get_lines(location)
        line = None
        if lines is not None:
            line = find_package_line(
                lines, location, record["ecosystem"], record["package"], record["version"]
            )
        text = lines[line - 1].rstrip("\r") if lines is not None and line else ""
        found.append((location, line, text))
    return found


def _window(text: str, version: str) -> str:
    """Return at most :data:`VENDORED_SNIPPET_CHARS` characters of a (minified) line, around
    the first place of ``version``."""
    if len(text) <= VENDORED_SNIPPET_CHARS:
        return text
    position = text.find(version) if version else -1
    start = max(0, position - VENDORED_SNIPPET_CHARS // 3) if position >= 0 else 0
    return text[start : start + VENDORED_SNIPPET_CHARS]


def build_candidates(
    records: Sequence[Mapping[str, Any]],
    target_dir: str | os.PathLike[str] | None,
    *,
    vulns_file: str = VULNS_FILE,
) -> list[dict[str, Any]]:
    """Return one candidate per record (ENGINE-SPEC 4), in record order.

    ``raw`` points at ``vulns_file`` with ``result_index`` = the record index. Candidate IDs
    use :func:`kalkan.findings.fingerprint.candidate_id`; a duplicate ID (two records on the
    same manifest line with the same rule ID) keeps only the first candidate.
    """
    get_lines = source_lines(target_dir)
    candidates: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, record in enumerate(records):
        candidate = _candidate(record, index, get_lines, vulns_file)
        if candidate["id"] in seen:
            continue
        seen.add(candidate["id"])
        candidates.append(candidate)
    return candidates


def _candidate(
    record: Mapping[str, Any],
    index: int,
    get_lines: Callable[[str], list[str] | None],
    vulns_file: str,
) -> dict[str, Any]:
    places = locate(record, get_lines)
    file, line, snippet = "", None, ""
    for place in places:
        if place[1] is not None:
            file, line, snippet = place
            break
    else:
        if places:
            file = places[0][0]
    engines = list(record.get("engines") or [])
    engine = engines[0] if engines else "osv-scanner"
    vuln_id = record["vuln_id"]
    aliases = list(record.get("aliases") or [])
    package, version, ecosystem = record["package"], record["version"], record["ecosystem"]
    fixed = list(record.get("fixed_versions") or [])
    summary = str(record.get("summary") or "")
    also = f" (also known as {', '.join(aliases)})" if aliases else ""
    malicious = is_malicious(record)
    if malicious:
        message = (
            f"{package} {version} ({ecosystem}) is a known malicious package version: "
            f"{vuln_id}{also}. {MALICIOUS_REMEDIATION}"
        )
    else:
        fix_text = f" Fixed in: {', '.join(fixed)}." if fixed else " No fixed version is known."
        message = f"{package} {version} ({ecosystem}) is affected by {vuln_id}{also}.{fix_text}"
    vendored_files = [
        str(entry["file"])
        for entry in record.get("vendored") or []
        if isinstance(entry, Mapping) and isinstance(entry.get("file"), str)
    ]
    if vendored_files:
        message += f" Vendored copy without a package manager: {', '.join(vendored_files[:5])}."
    if summary:
        message += f" {summary}"
    tags = ["sca", f"engines:{','.join(engines)}", f"reachability:{record['reachability']}"]
    if record.get("pin_source") in ("manifest", "vendored"):
        tags.append(f"pin-source:{record['pin_source']}")
    elif record.get("vendored"):
        tags.append("vendored")
    if malicious:
        tags.append("malicious")
    default_cwe = MALICIOUS_CWE if malicious else VULNERABLE_CWE
    cwe = list(dict.fromkeys([default_cwe, *(record.get("cwe") or [])]))
    snippet = snippet.strip()
    title = _title(summary, vuln_id, package, version)
    if malicious and not summary.strip():
        title = f"Malicious package: {package} {version}"
    return {
        "id": candidate_id(engine, vuln_id, file, line, snippet),
        "engine": engine,
        "rule_id": vuln_id,
        "class": MALICIOUS_CLASS if malicious else "vulnerable-dependency",
        "cwe": cwe,
        "title": title,
        "message": message,
        "file": file,
        "start_line": line,
        "end_line": line,
        "snippet": snippet,
        "severity": record["severity"],
        "tool_severity": str(record.get("tool_severity") or ""),
        "confidence": None,
        "tags": tags,
        "fingerprints": {"kalkanSca/v1": record["ref"]},
        "sca": {
            "ecosystem": ecosystem,
            "package": package,
            "version": version,
            "vuln_ids": [vuln_id, *aliases],
            "fixed_versions": fixed,
            "cvss_score": record.get("cvss_score"),
            "cvss_vector": record.get("cvss_vector"),
        },
        "raw": {"sarif_file": vulns_file, "run_index": 0, "result_index": index},
    }


def _title(summary: str, vuln_id: str, package: str, version: str) -> str:
    text = " ".join(summary.split())
    if not text:
        return f"{vuln_id} in {package} {version}"
    if len(text) > 160:
        text = text[:157].rsplit(" ", 1)[0] + "..."
    return text


def write_candidates(
    run_dir: str | os.PathLike[str],
    records: Sequence[Mapping[str, Any]],
    warnings: Sequence[str] = (),
    *,
    target_dir: str | os.PathLike[str] | None = None,
) -> int:
    """Rebuild the SCA candidates from ``records`` and write them with ``merge_candidates``.

    ``target_dir`` defaults to ``<run>/target``. Returns the number of SCA candidates that
    ``merge_candidates`` reports. Raise :class:`~kalkan.errors.ToolError` when
    ``kalkan.scanners.candidates`` is not available.
    """
    try:
        from kalkan.scanners.candidates import merge_candidates
    except ImportError as exc:  # the scanner package is developed in parallel
        raise ToolError(f"kalkan.scanners.candidates is not available: {exc}") from exc
    root = Path(target_dir) if target_dir is not None else Path(run_dir) / "target"
    candidates = build_candidates(records, root)
    return int(merge_candidates(Path(run_dir), CANDIDATE_SOURCE, candidates, list(warnings)))
