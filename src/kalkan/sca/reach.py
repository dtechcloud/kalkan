# SPDX-License-Identifier: MIT
"""Reachability of vulnerable dependencies (ENGINE-SPEC 17 and 18).

Two sources decide whether the target's code reaches the vulnerable part of a dependency:

- **govulncheck** (Go only; kalkan installs the Go toolchain): :func:`apply_govulncheck`. A
  symbol-level finding (a call trace) marks the record ``reachable``. A record whose findings
  stay at the module or package level (the module is required or the package imported, but no
  vulnerable symbol is called) becomes ``not_reachable``. A record without a finding whose
  module is missing from the ``SBOM`` module list of every scanned ``go.mod`` it names (the
  module is required, but no package of it is in the build of ``./...``) also becomes
  ``not_reachable``. Other records keep their state.
- **sca_reach agent tasks** for the other ecosystems: :func:`select_for_agents` picks the
  records, :func:`build_reach_input` writes the task input, :func:`apply_reach_result` applies
  a verified result.

Rules of :func:`apply_reach_result`:

- ``reachable`` needs at least one engine-verified quote, else ``unknown``
  (``unverified_evidence``).
- ``not_reachable`` needs a non-empty ``searched`` list, else ``unknown``
  (``ungrounded_not_reachable``). When the result cites quotes and none is verified, it also
  becomes ``unknown`` (``unverified_evidence``), as in the verdict policy of ENGINE-SPEC 6.3.
- ``not_reachable`` lowers the severity by one level; ``severity_original`` keeps the old value.
  A record is never deleted.

A malicious record (``class: malicious-dependency``, :func:`kalkan.sca.normalize.is_malicious`)
gets no ``sca_reach`` task and no govulncheck decision: the malicious code runs at install
time, so reachability does not matter (ADR-0005, K.2).

Each decision updates ``sca/vulns.json`` and rewrites the SCA candidates, so that the candidate
severity follows the record.
"""

from __future__ import annotations

import contextlib
import os
from collections.abc import Iterable, Iterator, Mapping, Sequence
from pathlib import Path
from typing import Any

from kalkan.errors import ValidationError
from kalkan.findings import severity as sev
from kalkan.sca.merge import (
    locate,
    read_vulns,
    set_reachability,
    source_lines,
    write_candidates,
    write_vulns,
)
from kalkan.sca.normalize import GovulncheckResult, is_malicious
from kalkan.sca.sbom import package_key, version_key

__all__ = [
    "AGENT_SEVERITIES",
    "UNGROUNDED_NOT_REACHABLE",
    "UNVERIFIED_EVIDENCE",
    "apply_govulncheck",
    "apply_reach_result",
    "build_reach_input",
    "decide_reachability",
    "import_patterns",
    "mark_reach_tasks",
    "select_for_agents",
]

#: Severities that get an agent reachability task.
AGENT_SEVERITIES = frozenset({"critical", "high"})
#: Reason code: a ``reachable`` (or quoted ``not_reachable``) claim without a verified quote.
UNVERIFIED_EVIDENCE = "unverified_evidence"
#: Reason code: a ``not_reachable`` claim without a search list.
UNGROUNDED_NOT_REACHABLE = "ungrounded_not_reachable"
#: At most this many govulncheck call traces become evidence of one record.
MAX_TRACE_EVIDENCE = 5
#: The longest quote that the engine stores from a source line.
MAX_QUOTE_CHARS = 300

# Distribution names whose import name differs (PyPI).
_PYTHON_IMPORT_NAMES: dict[str, tuple[str, ...]] = {
    "pyyaml": ("yaml",),
    "beautifulsoup4": ("bs4",),
    "pillow": ("PIL",),
    "scikit-learn": ("sklearn",),
    "python-dateutil": ("dateutil",),
    "pyjwt": ("jwt",),
    "opencv-python": ("cv2",),
    "opencv-python-headless": ("cv2",),
    "protobuf": ("google.protobuf",),
    "pycryptodome": ("Crypto",),
    "pycryptodomex": ("Cryptodome",),
    "pyopenssl": ("OpenSSL",),
    "python-jose": ("jose",),
    "python-multipart": ("multipart", "python_multipart"),
    "msgpack-python": ("msgpack",),
    "setuptools": ("setuptools", "pkg_resources"),
    "pymongo": ("pymongo", "bson", "gridfs"),
    "dnspython": ("dns",),
    "pyserial": ("serial",),
    "python-ldap": ("ldap",),
    "mysqlclient": ("MySQLdb",),
    "psycopg2-binary": ("psycopg2",),
    "attrs": ("attr", "attrs"),
    "ruamel-yaml": ("ruamel.yaml",),
    "google-cloud-storage": ("google.cloud.storage",),
}


# --- govulncheck -------------------------------------------------------------------------------


def apply_govulncheck(
    records: list[dict[str, Any]],
    result: GovulncheckResult,
    target_dir: str | os.PathLike[str] | None = None,
) -> dict[str, int]:
    """Apply govulncheck findings to the Go records and return counts per new state.

    A record matches a finding when the module equals the record package, one of the record IDs
    equals the OSV ID and, when govulncheck names a version, the versions match. Records that an
    agent decided (``reachability_source == "sca_reach"``) and malicious records keep their
    state.
    """
    versions: dict[tuple[str, str], str] = {}
    for record in result.records:
        for identifier in [record["vuln_id"], *record["aliases"]]:
            versions[(record["package"], identifier)] = record["version"]
    for module, osv_id in result.levels:
        versions.setdefault((module, osv_id), "")
    get_lines = source_lines(target_dir)
    counts = {"reachable": 0, "not_reachable": 0, "unchanged": 0}
    for record in records:
        if record.get("ecosystem") != "Go" or record.get("reachability_source") == "sca_reach":
            continue
        if is_malicious(record):
            counts["unchanged"] += 1
            continue
        key = _govulncheck_key(record, result, versions)
        if key is None:
            outside = _outside_build(record, result)
            if outside:
                folders = ", ".join(sorted({_folder(loc) for loc in outside}))
                set_reachability(
                    record,
                    "not_reachable",
                    reason=(
                        f"govulncheck: the module is required, but no package of "
                        f"{record['package']} is in the build of {folders} (govulncheck "
                        "analyzed ./... with the default build tags and no tests)."
                    ),
                    source="govulncheck",
                    searched=[
                        f"govulncheck SBOM of {loc}: " + ", ".join(result.analyzed[loc])
                        for loc in outside
                    ],
                )
                counts["not_reachable"] += 1
                continue
            counts["unchanged"] += 1
            continue
        level = result.levels[key]
        if level == "symbol":
            traces = result.traces.get(key, [])
            evidence = _trace_evidence(traces, get_lines)
            set_reachability(
                record,
                "reachable",
                reason=_trace_reason(traces, key),
                evidence=evidence,
                source="govulncheck",
                searched=["govulncheck call graph (scan level symbol)"],
            )
            counts["reachable"] += 1
        else:
            what = (
                "the vulnerable package is imported, but no vulnerable symbol is called"
                if level == "package"
                else "the module is required, but no vulnerable package is imported"
            )
            set_reachability(
                record,
                "not_reachable",
                reason=f"govulncheck: {what} ({level}-level finding for {key[1]}).",
                source="govulncheck",
                searched=["govulncheck call graph (scan level symbol)"],
            )
            counts["not_reachable"] += 1
    return counts


def _outside_build(record: Mapping[str, Any], result: GovulncheckResult) -> list[str]:
    """Return the scanned ``go.mod`` locations of a record whose builds lack its module.

    Empty unless every ``go.mod`` location of the record was scanned and none of the module
    lists names the record package.
    """
    module = str(record.get("package") or "")
    mods = [str(loc) for loc in record.get("locations") or [] if str(loc).endswith("go.mod")]
    if not module or not mods or any(loc not in result.analyzed for loc in mods):
        return []
    if any(module in result.analyzed[loc] for loc in mods):
        return []
    return mods


def _folder(go_mod: str) -> str:
    folder = go_mod.rsplit("/", 1)[0] if "/" in go_mod else ""
    return f"{folder}/" if folder else "the target root"


def _govulncheck_key(
    record: Mapping[str, Any],
    result: GovulncheckResult,
    versions: Mapping[tuple[str, str], str],
) -> tuple[str, str] | None:
    module = str(record.get("package") or "")
    for identifier in [record.get("vuln_id"), *(record.get("aliases") or [])]:
        key = (module, str(identifier))
        if key not in result.levels:
            continue
        found = versions.get(key, "")
        if found and version_key("Go", found) != version_key("Go", str(record.get("version"))):
            continue
        return key
    return None


def _trace_evidence(
    traces: Sequence[Sequence[Mapping[str, Any]]], get_lines: Any
) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    for trace in traces:
        call = next((frame for frame in trace[1:] if frame.get("file") and frame.get("line")), None)
        if call is None:
            continue
        lines = get_lines(call["file"])
        line = int(call["line"])
        text = ""
        if lines is not None and 1 <= line <= len(lines):
            text = lines[line - 1].strip()[:MAX_QUOTE_CHARS]
        symbol = _symbol(trace[0])
        item = {"file": call["file"], "line": line, "quote": text or symbol}
        if item not in evidence:
            evidence.append(item)
        if len(evidence) >= MAX_TRACE_EVIDENCE:
            break
    return evidence


def _trace_reason(traces: Sequence[Sequence[Mapping[str, Any]]], key: tuple[str, str]) -> str:
    if not traces:
        return f"govulncheck: a vulnerable symbol of {key[0]} is called ({key[1]})."
    trace = traces[0]
    entry = trace[-1]
    caller = _symbol(entry) or entry.get("package") or "the main module"
    return f"govulncheck: {caller} calls {_symbol(trace[0])} ({key[1]})."


def _symbol(frame: Mapping[str, Any]) -> str:
    function = str(frame.get("function") or "")
    receiver = str(frame.get("receiver") or "").lstrip("*")
    package = str(frame.get("package") or frame.get("module") or "")
    name = f"{receiver}.{function}" if receiver else function
    return f"{package}.{name}" if package and name else name or package


# --- agent tasks -------------------------------------------------------------------------------


def select_for_agents(
    records: Iterable[Mapping[str, Any]], *, remaining_budget: int, max_tasks: int
) -> list[Mapping[str, Any]]:
    """Return the records that get a ``sca_reach`` task, at most ``min(remaining_budget,
    max_tasks)`` of them.

    Eligible: severity ``critical`` or ``high``, reachability ``unknown``, no decision source,
    no task yet (``reach_task_id`` is null) and not malicious (a malicious package harms at
    install time; reachability does not apply). Order: the most severe record of each package
    first (one import search answers much of the question for all records of a package), then
    the second record of each package, and so on; inside a round severity (critical first),
    then ``ref``.
    """
    limit = min(max(int(remaining_budget), 0), max(int(max_tasks), 0))
    if limit == 0:
        return []
    eligible = [
        record
        for record in records
        if record.get("severity") in AGENT_SEVERITIES
        and record.get("reachability") == "unknown"
        and not record.get("reachability_source")
        and not record.get("reach_task_id")
        and not is_malicious(record)
    ]
    eligible.sort(key=lambda r: (-sev.rank(str(r["severity"])), str(r["ref"])))
    seen: dict[tuple[str, str], int] = {}
    rounds: list[int] = []
    for record in eligible:
        package = (str(record.get("ecosystem")), str(record.get("package")))
        rounds.append(seen.get(package, 0))
        seen[package] = rounds[-1] + 1
    ranked = sorted(range(len(eligible)), key=lambda index: (rounds[index], index))
    return [eligible[index] for index in ranked[:limit]]


def build_reach_input(
    record: Mapping[str, Any], target_dir: str | os.PathLike[str] | None
) -> dict[str, Any]:
    """Return the ``input.json`` of a ``sca_reach`` task for ``record``.

    The input holds the record fields, the affected symbols and vulnerable ranges that the
    databases name, the manifest locations with the line of the package entry (``line`` is null
    when the entry is not found) and the import patterns of the ecosystem. A vendored
    JavaScript library (``vendored``, :mod:`kalkan.sca.vendored`) adds its files and the file
    names that a page or a bundler uses to load it.
    """
    places = locate(record, source_lines(target_dir))
    vendored = [
        {key: entry.get(key) for key in ("file", "line", "library", "version")}
        for entry in record.get("vendored") or []
        if isinstance(entry, Mapping) and isinstance(entry.get("file"), str)
    ]
    patterns = import_patterns(
        record["ecosystem"], record["package"], record.get("affected_symbols") or []
    )
    for entry in vendored:
        name = str(entry["file"]).rsplit("/", 1)[-1]
        patterns += [name, name.replace(".min.", ".")]
    extra = {"vendored": vendored} if vendored else {}
    return {
        "vuln_ref": record["ref"],
        "ecosystem": record["ecosystem"],
        "package": record["package"],
        "version": record["version"],
        "vuln_id": record["vuln_id"],
        "aliases": list(record.get("aliases") or []),
        "summary": record.get("summary") or "",
        "severity": record["severity"],
        "cvss_score": record.get("cvss_score"),
        "cvss_vector": record.get("cvss_vector"),
        "cwe": list(record.get("cwe") or []),
        "fixed_versions": list(record.get("fixed_versions") or []),
        "vulnerable_ranges": list(record.get("vulnerable_ranges") or []),
        "affected_symbols": [
            {"package": item["package"], "symbols": list(item["symbols"])}
            for item in record.get("affected_symbols") or []
        ],
        "engines": list(record.get("engines") or []),
        "locations": [{"file": file, "line": line} for file, line, _ in places],
        "import_patterns": list(dict.fromkeys(patterns)),
        **extra,
    }


def import_patterns(
    ecosystem: str, package: str, affected_symbols: Iterable[Mapping[str, Any]] = ()
) -> list[str]:
    """Return text patterns that find imports of ``package`` in the target's code."""
    patterns: list[str] = []
    if ecosystem == "PyPI":
        for module in python_import_names(package):
            patterns += [
                f"import {module}",
                f"from {module} import",
                f"from {module}.",
                f'import_module("{module}',
                f"__import__('{module}",
            ]
    elif ecosystem == "npm":
        patterns += [
            f'require("{package}")',
            f"require('{package}')",
            f'require("{package}/',
            f"require('{package}/",
            f'from "{package}"',
            f"from '{package}'",
            f'from "{package}/',
            f"from '{package}/",
            f'import("{package}")',
            f"import('{package}')",
        ]
    elif ecosystem == "Go":
        paths = [package] + [
            str(item.get("package"))
            for item in affected_symbols
            if item.get("package") and str(item.get("package")) != package
        ]
        for path in dict.fromkeys(paths):
            patterns += [f'"{path}"', f'"{path}/']
    elif ecosystem == "Maven":
        group, _, artifact = package.rpartition(":")
        if group:
            patterns += [f"import {group}.", f"{group}:{artifact}"]
        patterns.append(f"<artifactId>{artifact or package}</artifactId>")
    elif ecosystem == "crates.io":
        crate = package.replace("-", "_")
        patterns += [f"use {crate}::", f"{crate}::", f"extern crate {crate}"]
    elif ecosystem == "RubyGems":
        patterns += [f"require '{package}'", f'require "{package}"', f"gem '{package}'"]
    elif ecosystem == "NuGet":
        patterns += [f"using {package}", f'Include="{package}"']
    elif ecosystem == "Packagist":
        patterns.append(f'"{package}"')
        vendor = package.split("/", 1)[0]
        if vendor:
            patterns.append(f"use {vendor.capitalize()}\\")
    else:
        patterns.append(package)
    return list(dict.fromkeys(patterns))


def python_import_names(package: str) -> list[str]:
    """Return likely import names of a PyPI distribution (``pyyaml`` → ``yaml``)."""
    key = package_key("PyPI", package)
    names = list(_PYTHON_IMPORT_NAMES.get(key, ()))
    names.append(key.replace("-", "_"))
    if key.startswith("python-"):
        names.append(key[len("python-") :].replace("-", "_"))
    return list(dict.fromkeys(names))


def mark_reach_tasks(run_dir: str | os.PathLike[str], assignments: Mapping[str, str]) -> int:
    """Record the ``sca_reach`` task ID of each record (``{ref: task_id}``) in vulns.json.

    :func:`select_for_agents` skips records with a task ID, so that a repeated step does not
    create a second task. Returns the number of records marked.
    """
    if not assignments:
        return 0
    with _locked(Path(run_dir), True):
        doc = read_vulns(run_dir)
        count = 0
        for record in doc["records"]:
            task_id = assignments.get(record["ref"])
            if task_id:
                record["reach_task_id"] = task_id
                count += 1
        write_vulns(
            run_dir,
            doc["records"],
            doc["warnings"],
            doc.get("unchecked_manifests"),
            doc.get("database_gaps"),
        )
    return count


# --- results -----------------------------------------------------------------------------------


def decide_reachability(
    result: Mapping[str, Any], verified: Sequence[Any]
) -> tuple[str, str, list[dict[str, Any]], list[str]]:
    """Return ``(reachability, reason, evidence, searched)`` for a ``sca_reach`` result.

    ``verified`` holds the evidence items that passed quote verification
    (:class:`kalkan.findings.quote_verify.Evidence` objects or ``{file, line, quote}`` dicts).
    See the module docstring for the rules. A downgraded reason starts with the reason code.
    """
    claimed = str(result.get("reachability") or "")
    if claimed not in ("reachable", "not_reachable", "unknown"):
        raise ValidationError(
            "sca_reach result failed validation",
            [f"reachability: expected reachable, not_reachable or unknown, got {claimed!r}"],
        )
    reason = str(result.get("reason") or "").strip()
    evidence = _evidence_items(verified)
    cited = [e for e in result.get("evidence") or [] if isinstance(e, Mapping)]
    searched = [s.strip() for s in result.get("searched") or [] if isinstance(s, str) and s.strip()]
    if claimed == "reachable" and not evidence:
        return "unknown", _downgraded(UNVERIFIED_EVIDENCE, reason), [], searched
    if claimed == "not_reachable":
        if not searched:
            return "unknown", _downgraded(UNGROUNDED_NOT_REACHABLE, reason), evidence, searched
        if cited and not evidence:
            return "unknown", _downgraded(UNVERIFIED_EVIDENCE, reason), [], searched
    return claimed, reason, evidence, searched


def apply_reach_result(
    run_dir: str | os.PathLike[str],
    result: Mapping[str, Any],
    verified: Sequence[Any],
    *,
    use_lock: bool = True,
) -> None:
    """Apply a ``sca_reach`` task result to ``sca/vulns.json`` and the SCA candidates.

    ``verified`` is the list of evidence items that the engine verified with
    :mod:`kalkan.findings.quote_verify`. Raise :class:`~kalkan.errors.ValidationError` when
    ``vuln_ref`` matches no record. With ``use_lock`` the vulns.json update holds ``run.lock``;
    the candidate rewrite runs after the release (``merge_candidates`` takes the lock itself),
    so the caller must not hold the lock.
    """
    if not isinstance(result, Mapping):
        raise ValidationError("sca_reach result failed validation", ["expected an object"])
    reachability, reason, evidence, searched = decide_reachability(result, verified)
    ref = str(result.get("vuln_ref") or "")
    task_id = result.get("task_id") if isinstance(result.get("task_id"), str) else None
    run_path = Path(run_dir)
    with _locked(run_path, use_lock):
        doc = read_vulns(run_path)
        record = next((r for r in doc["records"] if r["ref"] == ref), None)
        if record is None:
            message = f"vuln_ref {ref!r} matches no record in sca/vulns.json"
            raise ValidationError(message, [message])
        set_reachability(
            record,
            reachability,
            reason=reason,
            evidence=evidence,
            source="sca_reach",
            searched=searched,
            task_id=task_id if task_id and task_id.endswith("-sca_reach") else None,
        )
        write_vulns(
            run_path,
            doc["records"],
            doc["warnings"],
            doc.get("unchecked_manifests"),
            doc.get("database_gaps"),
        )
    # merge_candidates replaces the warnings of the source: keep the match warnings.
    write_candidates(run_path, doc["records"], doc["warnings"])


def _evidence_items(verified: Sequence[Any]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for item in verified or []:
        if isinstance(item, Mapping):
            file, line, quote = item.get("file"), item.get("line"), item.get("quote")
        else:
            file = getattr(item, "file", None)
            line = getattr(item, "line", None)
            quote = getattr(item, "quote", None)
        if (
            isinstance(file, str)
            and file
            and isinstance(line, int)
            and not isinstance(line, bool)
            and line >= 1
            and isinstance(quote, str)
            and quote.strip()
        ):
            entry = {"file": file, "line": line, "quote": quote.strip()}
            if entry not in items:
                items.append(entry)
    return items


def _downgraded(code: str, reason: str) -> str:
    return f"{code}: {reason}" if reason else code


@contextlib.contextmanager
def _locked(run_dir: Path, use_lock: bool) -> Iterator[None]:
    if not use_lock:
        yield
        return
    from kalkan.run.lock import run_lock

    with run_lock(run_dir):
        yield
