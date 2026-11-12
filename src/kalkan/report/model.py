# SPDX-License-Identifier: MIT
"""The report data model, built from a run folder (docs/ENGINE-SPEC.md, sections 10 and 16).

:func:`build_model` reads every input of the report. Each input may be missing, because a run
can stop early: the model then records the file in :attr:`ReportModel.missing` and the
renderers say so. An input that exists but cannot be read safely, or fails its check, goes to
:attr:`ReportModel.warnings`.

Inputs (paths relative to the run folder):

- ``state.json``: run metadata, phases, budget, tasks (checked with
  :func:`kalkan.run.state.load_state`; a state that fails the check is still read, with a
  warning); a tools-only run (``options.mode``) gets the first partial pass reason
  ``partial_tools_only``: no agent validated anything, every result is an unverified tool
  result;
- ``target-manifest.json``: the detected technologies and the Windows long paths;
- ``findings.json``: the merged findings (validated; invalid records are dropped), with the
  decision of the final review (``review``) of each reviewed record; a record with
  ``duplicate_of`` (consolidation) goes to :attr:`ReportModel.duplicates`, and the verdict lists
  and every count leave it out;
- ``consolidate/groups.json`` and ``tasks/<id>/consolidate.json`` of done consolidate tasks:
  candidate groups without budget and dropped groups (warnings only);
- ``candidates.json``: deterministic candidates; the ones that no finding links are the
  unverified tool results;
- ``sca/vulns.json``: SCA records with reachability (else the SCA candidates) and the
  manifests without a lockfile (``unchecked_manifests``, a partial pass reason); known
  malicious package versions (``class: malicious-dependency`` or a ``MAL-`` ID) are
  :attr:`ScaRecord.malicious`, critical, and sort first;
- ``scans/*.status.json`` and ``sca/*.status.json``: engines that ran or were skipped, and the
  files that an engine analyzed only partially or skipped (``partial_files``,
  ``skipped_files``);
- ``coverage-ledger.json``: coverage unit counts by status, and the ``covered`` units that the
  critic closed from sibling coverage (``kalkan.closure`` with its check in ``local_checks``);
- ``tasks/<id>/result.json`` of done hunt tasks: hardening notes;
- ``tasks/<id>/candidates.json`` of done hunt tasks: the hunter candidates that stayed
  unvalidated (the validation budget ran out), with their ledger units;
- ``<repo>/.tools/installed.json``: tool versions.

Every text that comes from the target or from an agent is untrusted. :func:`clean` removes
control characters, lone surrogates and bidirectional controls; the renderers escape the rest.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from kalkan import __version__
from kalkan.errors import KalkanError, StateError, UnsafeInputError, ValidationError
from kalkan.findings.deployment import SCOPE_TEMPLATE, deployment_kind, deployment_scope
from kalkan.findings.fingerprint import GetLines, finding_location
from kalkan.findings.merge import (
    BULK_JSON_MAX_BYTES,
    CANDIDATES_NAME,
    FINDINGS_NAME,
    VULNS_PATH,
    is_duplicate,
    read_json,
    sca_records,
    severity_of,
    target_get_lines,
)
from kalkan.findings.severity import from_label, rank
from kalkan.findings.taxonomy import get_class
from kalkan.findings.validate import validate_findings
from kalkan.resources import home
from kalkan.run.budget import PROFILE_ALIASES
from kalkan.run.state import PHASES, load_state, parse_task_id
from kalkan.run.usage import load as load_usage
from kalkan.run.usage import summarize as usage_summary
from kalkan.sca.normalize import MALICIOUS_CLASS, is_malicious, is_malicious_id
from kalkan.unattended.auth import API_MODES

if TYPE_CHECKING:
    from kalkan.report.sbom import SbomInventory

__all__ = [
    "DEFAULT",
    "MAX_TOOL_ROWS_PER_ENGINE",
    "SEVERITY_ORDER",
    "EngineRun",
    "HardeningNote",
    "ReportModel",
    "ScaRecord",
    "DatabaseGap",
    "ScanGap",
    "UncheckedManifest",
    "UnvalidatedCandidate",
    "build_model",
    "class_title",
    "clean",
    "fmt_ts",
    "get_lines_for",
    "localized",
    "location_of",
    "manifest_reason_key",
]

#: Sentinel for "use the default" in keyword arguments that also accept None.
DEFAULT: Final = object()
SEVERITY_ORDER: Final = ("critical", "high", "medium", "low", "info")
#: The report lists at most this many tool results per engine; the rest stay in candidates.json.
MAX_TOOL_ROWS_PER_ENGINE: Final = 200
LEDGER_NAME: Final = "coverage-ledger.json"
STATE_NAME: Final = "state.json"
MANIFEST_NAME: Final = "target-manifest.json"
OPEN_LEDGER_STATUSES: Final = frozenset({"planned", "in_progress", "deferred", "blocked"})
FINISHED_PHASES: Final = frozenset({"report", "done"})
QUICK_PROFILE_TASKS: Final = 40

# C0 and C1 controls except tab and line feed; lone surrogates.
_CONTROL: Final = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f\ud800-\udfff]")
# Bidirectional formatting characters ("Trojan Source") and other invisible format controls.
_BIDI: Final = re.compile("[؜‎‏‪-‮⁦-⁩]")
_REACHABILITY: Final = ("reachable", "not_reachable", "unknown")
_REACH_ORDER: Final = {"reachable": 0, "unknown": 1, "not_reachable": 2}


def clean(value: object) -> str:
    """Return ``value`` as safe text: ``\\r\\n`` and ``\\r`` become ``\\n``, other control
    characters and lone surrogates become U+FFFD, bidirectional controls become a visible
    ``[U+XXXX]`` marker. A value that is not a string gives an empty string, except numbers."""
    if isinstance(value, bool) or value is None:
        return ""
    if isinstance(value, int | float):
        return str(value)
    if not isinstance(value, str):
        return ""
    text = value.replace("\r\n", "\n").replace("\r", "\n")
    text = _CONTROL.sub("�", text)
    return _BIDI.sub(lambda match: f"[U+{ord(match.group()):04X}]", text)


def fmt_ts(value: object) -> str:
    """Return an ISO UTC timestamp as ``YYYY-MM-DD HH:MM UTC``; other text stays as it is."""
    text = clean(value)
    match = re.fullmatch(r"(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2})(?::\d{2}(?:\.\d+)?)?Z", text)
    return f"{match.group(1)} {match.group(2)} UTC" if match else text


def class_title(slug: object, lang: str) -> str:
    """Return the taxonomy title of a class slug in ``lang``, or the slug itself."""
    if not isinstance(slug, str) or not slug:
        return ""
    item = get_class(slug)
    if item is None:
        return clean(slug)
    return item.title_en if lang == "en" else item.title_tr


def manifest_reason_key(reason: str) -> str | None:
    """Return the UI string key of a known ``unchecked_manifests`` reason, else None."""
    from kalkan.sca.manifests import REASON_PINS_ONLY, REASON_RANGES, REASON_UNREADABLE

    keys = {
        REASON_RANGES: "reason_ranges",
        REASON_PINS_ONLY: "reason_pins_only",
        REASON_UNREADABLE: "reason_unreadable",
    }
    return keys.get(reason)


def location_of(finding: Mapping[str, Any]) -> str:
    """Return ``file:line`` of the finding location (the sink, else the first evidence)."""
    file, line = finding_location(finding)
    if not file:
        return ""
    return f"{file}:{line}" if line is not None else file


def localized(
    finding: Mapping[str, Any], key: str, report_lang: str, run_lang: str
) -> tuple[str, bool]:
    """Return ``(text, not_translated)`` for ``title``, ``description`` or
    ``remediation_strategy``.

    In a report whose language differs from the run language, the ``i18n.en`` text wins; without
    it the original text comes back with ``not_translated`` set.
    """
    if key == "remediation_strategy":
        remediation = finding.get("remediation")
        original = remediation.get("strategy") if isinstance(remediation, Mapping) else None
    else:
        original = finding.get(key)
    original_text = clean(original)
    if report_lang == run_lang:
        return original_text, False
    if report_lang == "en":
        i18n = finding.get("i18n")
        english = i18n.get("en") if isinstance(i18n, Mapping) else None
        if isinstance(english, Mapping) and isinstance(english.get(key), str):
            return clean(english[key]), False
    return original_text, bool(original_text)


@dataclass(frozen=True)
class EngineRun:
    """One scanner or SCA tool run, from ``<group>/<engine>.status.json``."""

    engine: str
    group: str
    status: str
    message: str
    tool_version: str | None
    duration_seconds: float | None


@dataclass(frozen=True)
class ScaRecord:
    """One vulnerable dependency."""

    ecosystem: str
    package: str
    version: str
    vuln_id: str
    aliases: tuple[str, ...]
    summary: str
    severity: str | None
    cvss_score: float | None
    cvss_vector: str | None
    fixed_versions: tuple[str, ...]
    reachability: str
    engines: tuple[str, ...]
    locations: tuple[str, ...]
    #: ``manifest`` when the record comes from an exact pin of a manifest without a lockfile;
    #: ``vendored`` when it comes from JavaScript files copied into the target.
    pin_source: str | None = None
    #: The vendored JavaScript files of the record (``vendored`` entries of vulns.json).
    vendored_files: tuple[str, ...] = ()
    #: A known malicious package version (``class: malicious-dependency`` or a ``MAL-`` ID).
    malicious: bool = False

    @property
    def ids(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys((self.vuln_id, *self.aliases)))


@dataclass(frozen=True)
class UncheckedManifest:
    """A dependency manifest without a lockfile (``sca/vulns.json`` ``unchecked_manifests``)."""

    file: str
    ecosystem: str
    reason: str
    exact_pins: int | None
    ranges: int | None


@dataclass(frozen=True)
class DatabaseGap:
    """A matcher without a local vulnerability database (``sca/vulns.json``
    ``database_gaps``): it checked no package, or none of one ecosystem."""

    engine: str
    ecosystem: str | None
    reason: str


@dataclass(frozen=True)
class PackageGap:
    """One Go package that gosec or govulncheck loaded with errors (``partial_packages``)."""

    package: str
    missing_imports: tuple[str, ...]
    files: tuple[str, ...]


@dataclass(frozen=True)
class ScanGap:
    """Files or Go packages that one engine analyzed only partially or skipped (its status
    file)."""

    engine: str
    partial_count: int
    partial_paths: tuple[str, ...]
    skipped_count: int
    skipped_reasons: tuple[tuple[str, int], ...]
    skipped_paths: tuple[str, ...]
    package_count: int = 0
    packages: tuple[PackageGap, ...] = ()
    packages_local: bool = True


@dataclass(frozen=True)
class HardeningNote:
    """One hardening note of a hunt task."""

    title: str
    file: str
    line: int | None
    note: str


@dataclass(frozen=True)
class UnvalidatedCandidate:
    """A hunter candidate without a verify task (Cloudflare incomplete-run rule): it is not a
    finding, and the report lists its fingerprint and ledger units."""

    fingerprint: str
    title: str
    slug: str
    file: str
    line: int | None
    likelihood: str | None
    impact: str | None
    refs: tuple[str, ...]
    units: tuple[str, ...]


@dataclass
class ReportModel:
    """Everything the renderers need. Lists are already sorted for display."""

    run_id: str
    run_lang: str
    generated_at: str
    kalkan_version: str
    state_available: bool = False
    target_source: str = ""
    target_kind: str = ""
    git_ref: str | None = None
    profile: str | None = None
    created_at: str = ""
    updated_at: str = ""
    phase: str | None = None
    incomplete_reason: str | None = None
    tech: list[str] = field(default_factory=list)
    phases: list[dict[str, Any]] = field(default_factory=list)
    budget: dict[str, int] | None = None
    dead_tasks: int = 0
    engines: list[EngineRun] = field(default_factory=list)
    ledger: dict[str, int] | None = None
    #: ``covered`` units that were ``blocked`` until the critic closed them from sibling coverage.
    ledger_sibling_closed: int = 0
    findings_available: bool = False
    findings: list[dict[str, Any]] = field(default_factory=list)
    confirmed: list[dict[str, Any]] = field(default_factory=list)
    needs_validation: list[dict[str, Any]] = field(default_factory=list)
    rejected: list[dict[str, Any]] = field(default_factory=list)
    #: Records that consolidation folded into a primary record (``duplicate_of``). The verdict
    #: lists above and every count leave them out; the appendix lists them.
    duplicates: list[dict[str, Any]] = field(default_factory=list)
    candidates_available: bool = False
    candidates_total: int = 0
    tool_results: list[dict[str, Any]] = field(default_factory=list)
    sca_source: str | None = None
    sca: list[ScaRecord] = field(default_factory=list)
    unchecked_manifests: list[UncheckedManifest] = field(default_factory=list)
    database_gaps: list[DatabaseGap] = field(default_factory=list)
    scan_gaps: list[ScanGap] = field(default_factory=list)
    #: ``{count, limit, condition, paths, root_length, long_paths_enabled}`` of the manifest.
    long_paths: dict[str, Any] | None = None
    hunt_done: int = 0
    hardening: list[HardeningNote] = field(default_factory=list)
    unvalidated: list[UnvalidatedCandidate] = field(default_factory=list)
    tool_versions: list[tuple[str, str, str]] | None = None
    missing: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    partial_reasons: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    target_dir: Path | None = None
    #: True for a tools-only run (``options.mode``): the agent phases were skipped.
    tools_only: bool = False
    #: The joined SBOM components (``kalkan.report.sbom``), None without any SBOM input.
    sbom: SbomInventory | None = None
    #: The report file names that exist after the current ``write_report`` call, in the order
    #: of ``kalkan.report.commands.OUTPUT_FILES`` (empty when a renderer is called directly).
    outputs: tuple[str, ...] = ()
    #: The deployment running in production (``options.live_paths``), empty when unknown.
    live_paths: list[str] = field(default_factory=list)
    #: Code that production does not load (``options.not_live_paths``), empty when unknown.
    not_live_paths: list[str] = field(default_factory=list)
    #: The deployment sets of the target (manifest ``deployments.sets``): kind, path, files.
    deployments: list[dict[str, Any]] = field(default_factory=list)
    #: The deployment files of the target (manifest ``deployments.files``).
    deployment_files: frozenset[str] = frozenset()
    #: Run options that describe the run type (``docker``, ``mode``, ``allow_build_network``).
    run_options: dict[str, Any] = field(default_factory=dict)
    #: Totals of ``usage.jsonl`` (:func:`kalkan.run.usage.summarize`), None when not recorded.
    usage: dict[str, Any] | None = None

    def run_type(self) -> str:
        """Return the run type: profile or tools-only, with the sandbox and the live paths."""
        parts = ["tools-only" if self.tools_only else (self.profile or "unknown")]
        docker = self.run_options.get("docker")
        if docker and not self.tools_only:
            parts.append(f"docker {docker}")
        if self.run_options.get("allow_build_network"):
            parts.append("build network")
        if self.live_paths:
            parts.append("live " + ", ".join(self.live_paths))
        if self.not_live_paths:
            parts.append("not live " + ", ".join(self.not_live_paths))
        api = [mode for mode in (self.usage or {}).get("auth") or [] if mode in API_MODES]
        if api:
            parts.append("api " + ", ".join(api))
        return " · ".join(parts)

    def elapsed_seconds(self) -> int | None:
        """Return the calendar time from the run start to its last state change, or None."""
        start, end = _parse_ts(self.created_at), _parse_ts(self.updated_at)
        if start is None or end is None or end < start:
            return None
        return int((end - start).total_seconds())

    def scope_of(self, finding: Mapping[str, Any]) -> str | None:
        """Return ``live``, ``template`` or None (``kalkan.findings.deployment``)."""
        return deployment_scope(
            finding, self.live_paths, self._is_deployment_file, self.not_live_paths
        )

    def _is_deployment_file(self, path: str) -> bool:
        return path in self.deployment_files or deployment_kind(path) is not None

    @property
    def template_confirmed(self) -> list[dict[str, Any]]:
        """Confirmed findings that exist only in deployment files or code outside production."""
        return [item for item in self.confirmed if self.scope_of(item) == SCOPE_TEMPLATE]

    @property
    def complete(self) -> bool:
        return self.state_available and self.phase in FINISHED_PHASES and not self.incomplete_reason

    @property
    def ledger_total(self) -> int:
        return sum(self.ledger.values()) if self.ledger else 0

    @property
    def ledger_open(self) -> int:
        if not self.ledger:
            return 0
        return sum(count for status, count in self.ledger.items() if status in OPEN_LEDGER_STATUSES)

    def verdict_counts(self) -> dict[str, int]:
        return {
            "confirmed": len(self.confirmed),
            "needs_validation": len(self.needs_validation),
            "rejected": len(self.rejected),
        }

    def severity_counts(self) -> dict[str, int]:
        counts = dict.fromkeys(SEVERITY_ORDER, 0)
        for finding in self.confirmed:
            severity = severity_of(finding)
            if severity is not None:
                counts[severity] += 1
        return counts

    def highest_severity(self) -> str | None:
        """Return the highest severity of the confirmed findings that are not template only."""
        present = {
            severity_of(item) for item in self.confirmed if self.scope_of(item) != SCOPE_TEMPLATE
        }
        return next((severity for severity in SEVERITY_ORDER if severity in present), None)

    def review_counts(self) -> dict[str, int]:
        """Return the final review counts: reviewed records by decision, and the confirmed and
        needs_validation records without a review. Folded duplicates are not counted."""
        counts = {"verified": 0, "downgrade": 0, "reject": 0}
        for finding in (*self.confirmed, *self.needs_validation, *self.rejected):
            review = finding.get("review")
            decision = review.get("decision") if isinstance(review, Mapping) else None
            if decision in counts:
                counts[decision] += 1
        open_records = [*self.confirmed, *self.needs_validation]
        missing = sum(1 for item in open_records if not isinstance(item.get("review"), Mapping))
        return {"reviewed": sum(counts.values()), **counts, "not_reviewed": missing}

    def finding_by_id(self, finding_id: object) -> dict[str, Any] | None:
        """Return the record with ``finding_id`` (a listed finding or a folded duplicate)."""
        if not isinstance(finding_id, str):
            return None
        return next((item for item in self.findings if item.get("id") == finding_id), None)

    def tool_results_by_engine(self) -> dict[str, list[dict[str, Any]]]:
        groups: dict[str, list[dict[str, Any]]] = {}
        for candidate in self.tool_results:
            groups.setdefault(candidate["engine"], []).append(candidate)
        return groups

    def sca_reachable(self) -> int:
        return sum(1 for record in self.sca if record.reachability == "reachable")

    def sca_from_pins(self) -> int:
        return sum(1 for record in self.sca if record.pin_source == "manifest")

    def sca_vendored(self) -> list[ScaRecord]:
        """Return the records with a vendored JavaScript file."""
        return [record for record in self.sca if record.vendored_files]

    def sca_malicious(self) -> list[ScaRecord]:
        """Return the known malicious package versions (the report shows them first)."""
        return [record for record in self.sca if record.malicious]

    def sca_vulnerable(self) -> list[ScaRecord]:
        """Return the ordinary SCA records (known vulnerabilities, not malicious packages)."""
        return [record for record in self.sca if not record.malicious]

    def sbom_files(self) -> tuple[str, ...]:
        """Return the SBOM file names of :attr:`outputs`."""
        return tuple(name for name in self.outputs if name.startswith("sbom."))

    @property
    def has_coverage_gaps(self) -> bool:
        return bool(
            self.unchecked_manifests or self.database_gaps or self.scan_gaps or self.long_paths
        )


# ---------------------------------------------------------------------------------------------
# Readers


def _read(
    model: ReportModel, run_dir: Path, name: str, *, bulk: bool = False, missing: bool = True
) -> Any:
    try:
        if bulk:
            return read_json(run_dir / name, max_bytes=BULK_JSON_MAX_BYTES, enforce_limits=False)
        return read_json(run_dir / name)
    except FileNotFoundError:
        if missing:
            model.missing.append(name)
        return None
    except (UnsafeInputError, ValidationError) as exc:
        model.warnings.append(f"{name}: cannot be read ({clean(str(exc))})")
        return None


def _text(value: object) -> str:
    return clean(value).strip()


def _int(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _load_state(model: ReportModel, run_dir: Path) -> dict[str, Any] | None:
    path = run_dir / STATE_NAME
    if not path.exists():
        model.missing.append(STATE_NAME)
        return None
    try:
        return load_state(run_dir)
    except StateError as exc:
        model.warnings.append(f"{STATE_NAME}: {clean(str(exc))}")
    state = _read(model, run_dir, STATE_NAME, missing=False)
    return state if isinstance(state, dict) else None


def _apply_state(model: ReportModel, state: Mapping[str, Any], run_dir: Path) -> None:
    model.state_available = True
    run_id = _text(state.get("run_id"))
    if run_id:
        model.run_id = run_id
    target = state.get("target") if isinstance(state.get("target"), Mapping) else {}
    model.target_source = _text(target.get("source"))
    model.target_kind = _text(target.get("kind"))
    model.git_ref = _text(target.get("git_ref")) or None
    copy_name = target.get("copy") if isinstance(target.get("copy"), str) else "target"
    model.target_dir = run_dir / (copy_name if copy_name == "target" else "target")
    options = state.get("options") if isinstance(state.get("options"), Mapping) else {}
    model.live_paths = list(_strings(options.get("live_paths")))
    model.not_live_paths = list(_strings(options.get("not_live_paths")))
    model.run_options = {
        key: options[key] for key in ("docker", "mode", "allow_build_network") if key in options
    }
    profile = _text(options.get("profile"))
    model.profile = PROFILE_ALIASES.get(profile, profile) or None
    model.tools_only = options.get("mode") == "tools-only"
    lang = options.get("lang")
    if lang in ("tr", "en"):
        model.run_lang = lang
    model.created_at = _text(state.get("created_at"))
    model.updated_at = _text(state.get("updated_at"))
    model.phase = _text(state.get("phase")) or None
    model.incomplete_reason = _text(state.get("incomplete_reason")) or None
    phases = state.get("phases") if isinstance(state.get("phases"), Mapping) else {}
    order = {name: index for index, name in enumerate(PHASES)}
    for name in sorted(phases, key=lambda item: (order.get(item, len(order)), str(item))):
        record = phases[name]
        if not isinstance(record, Mapping) or name == "done":
            continue
        model.phases.append(
            {
                "name": clean(name),
                "status": _text(record.get("status")),
                "started_at": _text(record.get("started_at")),
                "finished_at": _text(record.get("finished_at")),
            }
        )
    budget = state.get("budget") if isinstance(state.get("budget"), Mapping) else {}
    maximum, used = _int(budget.get("max_agent_tasks")), _int(budget.get("used_agent_tasks"))
    if maximum is not None and used is not None:
        model.budget = {"max": maximum, "used": used}
    tasks = state.get("tasks") if isinstance(state.get("tasks"), Mapping) else {}
    model.dead_tasks = sum(
        1 for task in tasks.values() if isinstance(task, Mapping) and task.get("status") == "dead"
    )


def _done_tasks_of_type(state: Mapping[str, Any] | None, task_type: str) -> list[str]:
    tasks = state.get("tasks") if isinstance(state, Mapping) else None
    if not isinstance(tasks, Mapping):
        return []
    done = []
    for task_id, task in tasks.items():
        parsed = parse_task_id(task_id)
        if (
            parsed is not None
            and parsed[1] == task_type
            and isinstance(task, Mapping)
            and task.get("status") == "done"
        ):
            done.append((parsed[0], task_id))
    return [task_id for _, task_id in sorted(done)]


def _load_manifest(model: ReportModel, run_dir: Path) -> None:
    manifest = _read(model, run_dir, MANIFEST_NAME)
    deployments = manifest.get("deployments") if isinstance(manifest, Mapping) else None
    if isinstance(deployments, Mapping):
        sets = deployments.get("sets")
        model.deployments = [
            {
                "kind": _text(item.get("kind")),
                "path": _text(item.get("path")),
                "files": item.get("files"),
            }
            for item in (sets if isinstance(sets, list) else [])
            if isinstance(item, Mapping) and _text(item.get("kind")) and _text(item.get("path"))
        ]
        model.deployment_files = frozenset(_strings(deployments.get("files")))
    if isinstance(manifest, Mapping) and isinstance(manifest.get("tech"), list):
        model.tech = sorted({_text(item) for item in manifest["tech"] if _text(item)})
    long_paths = manifest.get("long_paths") if isinstance(manifest, Mapping) else None
    count = _int(long_paths.get("count")) if isinstance(long_paths, Mapping) else None
    if isinstance(long_paths, Mapping) and count:
        limit = _int(long_paths.get("limit")) or 260
        enabled = long_paths.get("long_paths_enabled")
        model.long_paths = {
            "count": count,
            "limit": limit,
            "condition": _text(long_paths.get("condition")),
            "paths": list(_strings(long_paths.get("paths"))),
            "root_length": _int(long_paths.get("root_length")),
            "long_paths_enabled": enabled if isinstance(enabled, bool) else None,
        }
        model.warnings.append(
            f"Files with an absolute path of {limit} or more characters: {count}. Opengrep may "
            "skip them without a warning: its core program is not long-path aware, also with "
            "LongPathsEnabled=1. Set KALKAN_RUNS_DIR to a short folder (for example C:/kr) and "
            "start a new run."
        )


def _confirmed_key(finding: Mapping[str, Any]) -> tuple[Any, ...]:
    severity = severity_of(finding) or "info"
    return (-rank(severity), _text(finding.get("title")).casefold(), _text(finding.get("id")))


def _plain_key(finding: Mapping[str, Any]) -> tuple[Any, ...]:
    return (_text(finding.get("title")).casefold(), _text(finding.get("id")))


def _load_findings(model: ReportModel, run_dir: Path) -> None:
    document = _read(model, run_dir, FINDINGS_NAME)
    if document is None:
        return
    model.findings_available = True
    if not isinstance(document, list):
        model.warnings.append(f"{FINDINGS_NAME}: not an array; no finding is shown")
        return
    errors = validate_findings(document)
    findings = document
    if errors:
        findings = [item for item in document if not validate_findings([item])]
        model.warnings.append(
            f"{FINDINGS_NAME}: failed validation ({clean(errors[0])}); "
            f"{len(document) - len(findings)} invalid records are not shown"
        )
    model.findings = findings
    ids = {item["id"] for item in findings if isinstance(item.get("id"), str)}
    listed: list[dict[str, Any]] = []
    for item in findings:
        if not is_duplicate(item):
            listed.append(item)
        elif item["duplicate_of"] in ids and item["duplicate_of"] != item.get("id"):
            model.duplicates.append(item)
        else:
            listed.append(item)
            model.warnings.append(
                f"{FINDINGS_NAME}: {clean(item.get('id'))} is a duplicate of an unknown record; "
                "it is shown as a finding"
            )
    model.duplicates.sort(key=lambda item: (_text(item.get("duplicate_of")), _plain_key(item)))
    model.confirmed = sorted(
        (item for item in listed if item["verdict"] == "confirmed"), key=_confirmed_key
    )
    model.needs_validation = sorted(
        (item for item in listed if item["verdict"] == "needs_validation"), key=_plain_key
    )
    model.rejected = sorted(
        (item for item in listed if item["verdict"] == "rejected"), key=_plain_key
    )


def _candidate_severity(candidate: Mapping[str, Any]) -> str:
    value = candidate.get("severity")
    return (from_label(value) if isinstance(value, str) else None) or "info"


def _load_candidates(model: ReportModel, run_dir: Path) -> list[dict[str, Any]]:
    document = _read(model, run_dir, CANDIDATES_NAME, bulk=True)
    if document is None:
        return []
    items = document.get("candidates") if isinstance(document, Mapping) else document
    if not isinstance(items, list):
        model.warnings.append(f"{CANDIDATES_NAME}: no candidate list")
        return []
    model.candidates_available = True
    valid = [
        item
        for item in items
        if isinstance(item, dict)
        and isinstance(item.get("id"), str)
        and isinstance(item.get("engine"), str)
    ]
    if len(valid) != len(items):
        model.warnings.append(f"{CANDIDATES_NAME}: {len(items) - len(valid)} malformed entries")
    model.candidates_total = len(valid)
    linked = {
        cid
        for finding in model.findings
        for cid in finding.get("candidates", [])
        if isinstance(cid, str)
    }
    results = [item for item in valid if item.get("sca") is None and item["id"] not in linked]
    results.sort(
        key=lambda item: (
            _text(item.get("engine")),
            -rank(_candidate_severity(item)),
            _text(item.get("file")),
            _int(item.get("start_line")) or 0,
            _text(item.get("rule_id")),
            item["id"],
        )
    )
    model.tool_results = results
    return valid


def _parse_ts(value: str) -> datetime | None:
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError):
        return None


def _strings(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(dict.fromkeys(_text(item) for item in value if _text(item)))


def _number(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value)


def _sca_from_vulns(records: list[dict[str, Any]]) -> list[ScaRecord]:
    result = []
    for record in records:
        severity = record.get("severity")
        reach = record.get("reachability")
        locations = []
        for location in record.get("locations") or []:
            if isinstance(location, str):
                locations.append(_text(location))
            elif isinstance(location, Mapping) and isinstance(location.get("file"), str):
                locations.append(_text(location["file"]))
        vendored = [
            _text(entry.get("file"))
            for entry in record.get("vendored") or []
            if isinstance(entry, Mapping) and _text(entry.get("file"))
        ]
        pin_source = record.get("pin_source")
        malicious = is_malicious(record)
        if malicious:
            severity = "critical"  # ENGINE-SPEC 17: a malicious package is never lowered
        result.append(
            ScaRecord(
                ecosystem=_text(record.get("ecosystem")),
                package=_text(record.get("package")),
                version=_text(record.get("version")),
                vuln_id=_text(record.get("vuln_id")),
                aliases=_strings(record.get("aliases")),
                summary=_text(record.get("summary")),
                severity=from_label(severity) if isinstance(severity, str) else None,
                cvss_score=_number(record.get("cvss_score")),
                cvss_vector=_text(record.get("cvss_vector")) or None,
                fixed_versions=_strings(record.get("fixed_versions")),
                reachability=reach if reach in _REACHABILITY else "unknown",
                engines=_strings(record.get("engines")),
                locations=tuple(dict.fromkeys(item for item in locations if item)),
                pin_source=pin_source if pin_source in ("manifest", "vendored") else None,
                vendored_files=tuple(dict.fromkeys(vendored)),
                malicious=malicious,
            )
        )
    return result


def _database_gaps(document: object) -> list[DatabaseGap]:
    items = document.get("database_gaps") if isinstance(document, Mapping) else None
    result = []
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, Mapping) or not _text(item.get("engine")):
            continue
        ecosystem = _text(item.get("ecosystem")) or None
        result.append(DatabaseGap(_text(item.get("engine")), ecosystem, _text(item.get("reason"))))
    return result


def _unchecked_manifests(document: object) -> list[UncheckedManifest]:
    items = document.get("unchecked_manifests") if isinstance(document, Mapping) else None
    result = []
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, Mapping) or not _text(item.get("file")):
            continue
        result.append(
            UncheckedManifest(
                file=_text(item.get("file")),
                ecosystem=_text(item.get("ecosystem")),
                reason=_text(item.get("reason")),
                exact_pins=_int(item.get("exact_pins")),
                ranges=_int(item.get("ranges")),
            )
        )
    return sorted(result, key=lambda m: (m.file.casefold(), m.file))


def _sca_from_candidates(candidates: list[dict[str, Any]]) -> list[ScaRecord]:
    merged: dict[tuple[str, str, str, str], ScaRecord] = {}
    for candidate in candidates:
        sca = candidate.get("sca")
        if not isinstance(sca, Mapping):
            continue
        ids = _strings(sca.get("vuln_ids")) or (_text(candidate.get("rule_id")),)
        key = (_text(sca.get("ecosystem")), _text(sca.get("package")), _text(sca.get("version")))
        malicious = candidate.get("class") == MALICIOUS_CLASS or any(
            is_malicious_id(value) for value in ids
        )
        record = ScaRecord(
            ecosystem=key[0],
            package=key[1],
            version=key[2],
            vuln_id=ids[0],
            aliases=ids[1:],
            summary=_text(candidate.get("title")),
            severity="critical" if malicious else _candidate_severity(candidate),
            cvss_score=_number(sca.get("cvss_score")),
            cvss_vector=_text(sca.get("cvss_vector")) or None,
            fixed_versions=_strings(sca.get("fixed_versions")),
            reachability="unknown",
            engines=(_text(candidate.get("engine")),),
            locations=(_text(candidate.get("file")),) if _text(candidate.get("file")) else (),
            malicious=malicious,
        )
        full_key = (*key, ids[0])
        if full_key in merged:
            old = merged[full_key]
            record = ScaRecord(
                **{
                    **old.__dict__,
                    "engines": tuple(dict.fromkeys((*old.engines, *record.engines))),
                    "locations": tuple(dict.fromkeys((*old.locations, *record.locations))),
                }
            )
        merged[full_key] = record
    return list(merged.values())


def _sca_key(record: ScaRecord) -> tuple[Any, ...]:
    return (
        not record.malicious,
        -rank(record.severity or "info"),
        _REACH_ORDER.get(record.reachability, 1),
        record.package.casefold(),
        record.version,
        record.vuln_id,
    )


def _load_sca(model: ReportModel, run_dir: Path, candidates: list[dict[str, Any]]) -> None:
    document = _read(model, run_dir, VULNS_PATH, bulk=True)
    records: list[ScaRecord] = []
    if document is not None:
        raw = sca_records(document)
        if raw is None:
            model.warnings.append(f"{VULNS_PATH}: unknown document shape")
        else:
            model.sca_source = "vulns"
            records = _sca_from_vulns(raw)
            model.unchecked_manifests = _unchecked_manifests(document)
            model.database_gaps = _database_gaps(document)
    if model.sca_source is None:
        fallback = _sca_from_candidates(candidates)
        if fallback:
            model.sca_source = "candidates"
            records = fallback
    model.sca = sorted(records, key=_sca_key)


def _load_engines(model: ReportModel, run_dir: Path) -> None:
    found = False
    for group in ("scans", "sca"):
        folder = run_dir / group
        if not folder.is_dir():
            continue
        for path in sorted(folder.glob("*.status.json")):
            found = True
            name = f"{group}/{path.name}"
            record = _read(model, run_dir, name, missing=False)
            if not isinstance(record, Mapping):
                if record is not None:
                    model.warnings.append(f"{name}: not an object")
                continue
            engine = _text(record.get("engine")) or path.name.removesuffix(".status.json")
            version = record.get("tool_version")
            gap = _scan_gap(engine, record)
            if gap is not None:
                model.scan_gaps.append(gap)
            model.engines.append(
                EngineRun(
                    engine=engine,
                    group=group,
                    status=_text(record.get("status")) or "unknown",
                    message=_text(record.get("message")),
                    tool_version=_text(version) or None,
                    duration_seconds=_number(record.get("duration_seconds")),
                )
            )
    if not found:
        model.missing.append("scans/*.status.json")


def _scan_gap(engine: str, record: Mapping[str, Any]) -> ScanGap | None:
    partial = record.get("partial_files")
    skipped = record.get("skipped_files")
    packages = record.get("partial_packages")
    partial = partial if isinstance(partial, Mapping) else {}
    skipped = skipped if isinstance(skipped, Mapping) else {}
    packages = packages if isinstance(packages, Mapping) else {}
    reasons = skipped.get("reasons") if isinstance(skipped.get("reasons"), Mapping) else {}
    listed = packages.get("packages") if isinstance(packages.get("packages"), list) else []
    gap = ScanGap(
        engine=engine,
        partial_count=_int(partial.get("count")) or 0,
        partial_paths=_strings(partial.get("paths")),
        skipped_count=_int(skipped.get("count")) or 0,
        skipped_reasons=tuple(
            (_text(reason), count)
            for reason, count in reasons.items()
            if _text(reason) and isinstance(count, int) and count > 0
        ),
        skipped_paths=_strings(skipped.get("paths")),
        package_count=_int(packages.get("count")) or 0,
        packages=tuple(
            PackageGap(
                package=_text(item.get("package")) or ".",
                missing_imports=_strings(item.get("missing_imports")),
                files=_strings(item.get("files")),
            )
            for item in listed[:50]
            if isinstance(item, Mapping)
        ),
        packages_local=packages.get("mode") != "online",
    )
    return gap if gap.partial_count or gap.skipped_count or gap.package_count else None


def _load_ledger(model: ReportModel, run_dir: Path) -> None:
    document = _read(model, run_dir, LEDGER_NAME, bulk=True)
    if document is None:
        return
    units = document.get("units") if isinstance(document, Mapping) else document
    if not isinstance(units, list):
        model.warnings.append(f"{LEDGER_NAME}: not an array of units")
        return
    counts: dict[str, int] = {}
    for unit in units:
        if isinstance(unit, Mapping):
            status = _text(unit.get("status")) or "unknown"
            counts[status] = counts.get(status, 0) + 1
            if status == "covered" and _sibling_closure(unit):
                model.ledger_sibling_closed += 1
    model.ledger = dict(sorted(counts.items()))


def _sibling_closure(unit: Mapping[str, Any]) -> bool:
    """Return True when the live evidence of ``unit`` holds the check of its critic closure."""
    bookkeeping = unit.get("kalkan")
    closure = bookkeeping.get("closure") if isinstance(bookkeeping, Mapping) else None
    task = closure.get("task") if isinstance(closure, Mapping) else None
    checks = unit.get("local_checks")
    if not isinstance(task, str) or not isinstance(checks, list):
        return False
    agent = task.lower()
    return any(isinstance(check, Mapping) and check.get("agent_id") == agent for check in checks)


def _load_hardening(model: ReportModel, run_dir: Path, state: Mapping[str, Any] | None) -> None:
    notes: dict[tuple[str, str, int | None, str], HardeningNote] = {}
    hunts = _done_tasks_of_type(state, "hunt")
    model.hunt_done = len(hunts)
    for task_id in hunts:
        name = f"tasks/{task_id}/result.json"
        result = _read(model, run_dir, name, missing=False)
        items = result.get("hardening") if isinstance(result, Mapping) else None
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, Mapping):
                continue
            note = HardeningNote(
                title=_text(item.get("title")),
                file=_text(item.get("file")),
                line=_int(item.get("line")),
                note=_text(item.get("note")),
            )
            if note.title or note.note:
                notes[(note.title, note.file, note.line, note.note)] = note
    model.hardening = sorted(
        notes.values(), key=lambda n: (n.file, n.line or 0, n.title.casefold(), n.note)
    )


_UNVALIDATED_NOTE: Final = "validation_budget_exhausted: "


def _unit_labels(model: ReportModel, run_dir: Path) -> dict[str, list[str]]:
    """Return ``{fingerprint: ["<surface> · <class>"]}`` from the ledger notes."""
    document = _read(model, run_dir, LEDGER_NAME, bulk=True, missing=False)
    units = document.get("units") if isinstance(document, Mapping) else document
    labels: dict[str, list[str]] = {}
    for unit in units if isinstance(units, list) else []:
        if not isinstance(unit, Mapping) or not isinstance(unit.get("unresolved"), list):
            continue
        label = f"{_text(unit.get('surface'))} · {_text(unit.get('attack_class'))}"
        for note in unit["unresolved"]:
            if isinstance(note, str) and note.startswith(_UNVALIDATED_NOTE):
                fingerprint = note.removeprefix(_UNVALIDATED_NOTE).strip()
                labels.setdefault(fingerprint, [])
                if label not in labels[fingerprint]:
                    labels[fingerprint].append(label)
    return labels


def _load_unvalidated(model: ReportModel, run_dir: Path, state: Mapping[str, Any] | None) -> None:
    found: dict[str, dict[str, Any]] = {}
    for task_id in _done_tasks_of_type(state, "hunt"):
        document = _read(model, run_dir, f"tasks/{task_id}/candidates.json", missing=False)
        items = document.get("candidates") if isinstance(document, Mapping) else None
        for item in items if isinstance(items, list) else []:
            if not isinstance(item, Mapping) or item.get("status") != "unvalidated":
                continue
            fingerprint = _text(item.get("fingerprint"))
            if not fingerprint:
                continue
            entry = found.setdefault(fingerprint, {"item": item, "refs": []})
            entry["refs"].append(_text(item.get("ref")))
    if not found:
        return
    labels = _unit_labels(model, run_dir)
    rows = []
    for fingerprint, entry in found.items():
        item = entry["item"]
        suggested = item.get("suggested_severity")
        suggested = suggested if isinstance(suggested, Mapping) else {}
        rows.append(
            UnvalidatedCandidate(
                fingerprint=fingerprint,
                title=_text(item.get("title")),
                slug=_text(item.get("class")),
                file=_text(item.get("file")),
                line=_int(item.get("line")),
                likelihood=_text(suggested.get("likelihood")) or None,
                impact=_text(suggested.get("impact")) or None,
                refs=tuple(ref for ref in entry["refs"] if ref),
                units=tuple(labels.get(fingerprint, [])),
            )
        )
    model.unvalidated = sorted(rows, key=lambda row: row.fingerprint)


CONSOLIDATE_GROUPS: Final = "consolidate/groups.json"


def _load_consolidation(model: ReportModel, run_dir: Path, state: Mapping[str, Any] | None) -> None:
    """Add a warning for each consolidation gap: candidate groups without budget
    (``consolidate/groups.json``) and groups that a task result lost to a quote that does not
    match the source (``tasks/<id>/consolidate.json``). The records of such a group stay
    separate; the gap never makes the pass partial."""
    document = _read(model, run_dir, CONSOLIDATE_GROUPS, missing=False)
    unfunded = _int(document.get("unfunded")) if isinstance(document, Mapping) else None
    if unfunded:
        model.warnings.append(
            f"Possible duplicates were not checked for {unfunded} candidate groups: the agent "
            "task budget ran out. Their records stay separate findings."
        )
    for task_id in _done_tasks_of_type(state, "consolidate"):
        outcome = _read(model, run_dir, f"tasks/{task_id}/consolidate.json", missing=False)
        dropped = _int(outcome.get("dropped")) if isinstance(outcome, Mapping) else None
        if dropped:
            model.warnings.append(
                f"tasks/{task_id}: {dropped} consolidation groups were dropped because a quote "
                "does not match the source. Their records stay separate findings."
            )


def _load_tool_versions(model: ReportModel, installed: object) -> None:
    path: Path | None
    if installed is DEFAULT:
        try:
            path = home() / ".tools" / "installed.json"
        except KalkanError:
            path = None
    else:
        path = Path(installed) if installed is not None else None  # type: ignore[arg-type]
    if path is None:
        return
    try:
        document = read_json(path)
    except FileNotFoundError:
        model.missing.append(".tools/installed.json")
        return
    except (UnsafeInputError, ValidationError) as exc:
        model.warnings.append(f".tools/installed.json: cannot be read ({clean(str(exc))})")
        return
    tools = document.get("tools") if isinstance(document, Mapping) else None
    if not isinstance(tools, Mapping):
        model.warnings.append(".tools/installed.json: no tool map")
        return
    rows = []
    for name in sorted(tools):
        entry = tools[name]
        if isinstance(entry, Mapping):
            rows.append((clean(name), _text(entry.get("version")), _text(entry.get("kind"))))
    model.tool_versions = rows


def _partial_reasons(model: ReportModel) -> list[tuple[str, dict[str, Any]]]:
    reasons = _state_reasons(model)
    if model.unchecked_manifests:
        reasons.append(("partial_unchecked_manifests", {"n": len(model.unchecked_manifests)}))
    if model.database_gaps:
        reasons.append(("partial_database_gaps", {"n": len(model.database_gaps)}))
    return reasons


def _state_reasons(model: ReportModel) -> list[tuple[str, dict[str, Any]]]:
    reasons: list[tuple[str, dict[str, Any]]] = []
    if not model.state_available:
        reasons.append(("partial_no_state", {}))
        return reasons
    if model.tools_only:
        reasons.append(("partial_tools_only", {}))
    elif model.profile == "fast":
        maximum = model.budget["max"] if model.budget else QUICK_PROFILE_TASKS
        reasons.append(("partial_fast", {"max": maximum}))
    if model.budget and model.budget["max"] > 0 and model.budget["used"] >= model.budget["max"]:
        reasons.append(("partial_budget", dict(model.budget)))
    if model.phase not in FINISHED_PHASES:
        reasons.append(("partial_not_done", {"phase": model.phase or "?"}))
    if model.incomplete_reason:
        reasons.append(("partial_reason", {"reason": model.incomplete_reason}))
    if model.unvalidated:
        reasons.append(("partial_unvalidated", {"n": len(model.unvalidated)}))
    if model.ledger_open:
        reasons.append(("partial_ledger_open", {"n": model.ledger_open}))
    if model.dead_tasks:
        reasons.append(("partial_dead_tasks", {"n": model.dead_tasks}))
    return reasons


def build_model(
    run_dir: str | Path,
    *,
    generated_at: str | None = None,
    kalkan_version: str = __version__,
    installed_tools: object = DEFAULT,
) -> ReportModel:
    """Read the run folder ``run_dir`` and return the report model.

    ``generated_at`` defaults to the current UTC time. ``installed_tools`` is the path of
    ``installed.json`` (default: ``<repo>/.tools/installed.json``; None skips tool versions).
    The function never raises for a missing or broken input.
    """
    directory = Path(run_dir)
    if generated_at is None:
        generated_at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    model = ReportModel(
        run_id=clean(directory.name),
        run_lang="tr",
        generated_at=generated_at,
        kalkan_version=kalkan_version,
    )
    state = _load_state(model, directory)
    if state is not None:
        _apply_state(model, state, directory)
    else:
        model.target_dir = directory / "target"
    _load_manifest(model, directory)
    model.usage = usage_summary(load_usage(directory))
    _load_findings(model, directory)
    candidates = _load_candidates(model, directory)
    _load_sca(model, directory, candidates)
    _load_engines(model, directory)
    _load_ledger(model, directory)
    _load_hardening(model, directory, state)
    _load_unvalidated(model, directory, state)
    _load_consolidation(model, directory, state)
    _load_tool_versions(model, installed_tools)
    _load_sbom(model, directory)
    model.partial_reasons = _partial_reasons(model)
    return model


def _load_sbom(model: ReportModel, run_dir: Path) -> None:
    """Join the SBOM inputs of the run (``kalkan.report.sbom``)."""
    from kalkan.report.sbom import collect

    inventory = collect(run_dir, model.target_dir)
    if inventory is not None:
        model.warnings.extend(clean(warning) for warning in inventory.warnings)
        model.sbom = inventory


def get_lines_for(model: ReportModel) -> GetLines:
    """Return the ``get_lines`` callable of the run's target copy (for the SARIF hashes)."""
    return target_get_lines(model.target_dir or Path("target"))
