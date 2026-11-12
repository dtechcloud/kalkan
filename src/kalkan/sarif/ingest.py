# SPDX-License-Identifier: MIT
"""SARIF 2.1.0 ingest: scanner results to candidate records (ENGINE-SPEC 4 and 8.1).

:func:`ingest_document` turns each SARIF result into one candidate record. A bad result never
stops the ingest: the result is skipped and a warning is recorded. A document that is not
SARIF 2.1.0 raises :class:`~kalkan.errors.ValidationError`.

Choices that ENGINE-SPEC 8.1 leaves open:

- CWE order: result properties (``tags``, then ``cwe``), then rule properties, then rule
  ``relationships``. A relationship counts when its target ID starts with ``CWE-`` or its
  tool component is ``CWE`` (gosec writes the bare number).
- Results of kind ``pass`` and ``notApplicable`` report no problem. They are skipped.
- ``fingerprints`` holds the SARIF ``fingerprints`` and ``partialFingerprints`` (the latter
  wins on a key conflict). Empty values are dropped. Opengrep writes only ``fingerprints``.
- ``tags`` holds the result tags, then the rule tags, without duplicates.
- ``confidence`` comes from a ``confidence`` or ``issue_confidence`` property, then from an
  ``<X> CONFIDENCE`` tag (Opengrep), then from the SARIF ``precision`` property.
- ``sca`` is filled for OSV-Scanner, Grype and govulncheck, and for Trivy results whose rule
  has the ``vulnerability`` tag. ``ecosystem`` uses the OSV ecosystem names. An unknown
  ``ecosystem``, ``package`` or ``version`` is ``""`` (the candidate schema wants strings).
- ``class``: the class of the first CWE. When it gives no class, :func:`default_class` decides
  from the engine and the rule. The engines whose SARIF kalkan writes (:data:`RULE_CLASS_ENGINES`:
  zizmor, actionlint, poutine, scorecard, vacuum) come first: their adapters write the class of
  each rule as the property ``kalkan-class`` (of the result or of the rule), and a known slug
  there wins over the CWE. The vendored Opengrep rule packs (:data:`PACK_CLASS_ENGINES`:
  opengrep-packs) do the same with the class of ``rules/opengrep-packs/index.json``, which comes
  from the CWE metadata first and from the curation of the packs where no CWE maps.
"""

from __future__ import annotations

import json
import math
import os
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path, PurePath
from typing import Any
from urllib.parse import unquote

from kalkan.errors import ValidationError
from kalkan.findings.severity import for_sarif_result
from kalkan.findings.taxonomy import SLUGS, class_for_cwe, normalize_cwe
from kalkan.sarif.uri import is_target_relative, normalize_uri
from kalkan.util.safe_io import read_bounded

SARIF_VERSION = "2.1.0"
#: The largest SARIF file that :func:`ingest_file` reads.
MAX_SARIF_BYTES = 50 * 1024 * 1024

#: The engine names of ENGINE-SPEC 4. ``gitleaks-history`` is the git-history mode of the
#: Gitleaks adapter (ENGINE-SPEC 13).
ENGINES: tuple[str, ...] = (
    "trivy",
    "checkov",
    "hadolint",
    "gitleaks",
    "gitleaks-history",
    "opengrep",
    "bandit",
    "gosec",
    "osv-scanner",
    "grype",
    "govulncheck",
    "syft",
    "matcher",
    "zizmor",
    "actionlint",
    "poutine",
    "scorecard",
    "kingfisher",
    "kingfisher-history",
    "shellcheck",
    "flawfinder",
    "gixy",
    "helm-checkov",
    "vacuum",
    "opengrep-packs",
)

#: CI/CD engines (ADR-0005) whose results default to ``supply-chain-cicd``.
CICD_ENGINES = frozenset({"zizmor", "actionlint", "poutine", "scorecard"})
#: Engines (ADR-0005) whose SARIF kalkan writes or rewrites itself: the property
#: ``kalkan-class`` of a result or of its rule names the class (kalkan.scanners.adapters._cicd).
RULE_CLASS_ENGINES = CICD_ENGINES | {"vacuum"}
#: The vendored Opengrep rule packs (ADR-0005 K.8): their adapter writes ``kalkan-class`` on
#: every rule from ``rules/opengrep-packs/index.json``. No default class (unlike CI/CD).
PACK_CLASS_ENGINES = frozenset({"opengrep-packs"})
_RULE_CLASS_PROPERTY = "kalkan-class"

#: Engines whose results are all vulnerable packages.
SCA_ENGINES = frozenset({"osv-scanner", "grype", "govulncheck"})

# SARIF result kinds that report no problem.
_NOT_A_PROBLEM = frozenset({"pass", "notApplicable"})

# A tag that names a CWE: "external/cwe/cwe-89", "CWE-89", "cwe-89", "CWE-89: description".
_CWE_TAG = re.compile(r"\s*(?:external/cwe/)?cwe[\s_:-]*[0-9]", re.IGNORECASE)
# Opengrep and Semgrep write the rule confidence as a tag: "HIGH CONFIDENCE".
_CONFIDENCE_TAG = re.compile(r"\s*(high|medium|low)\s+confidence\s*", re.IGNORECASE)
_CONFIDENCE_WORDS = {
    "high": "high",
    "medium": "medium",
    "low": "low",
    "very-high": "high",
    "very_high": "high",
    "very high": "high",
}
_CONFIDENCE_KEYS = ("confidence", "issue_confidence")

# A vulnerability ID in a tag (govulncheck writes the aliases of an OSV entry as tags).
_VULN_ID = re.compile(
    r"(?:CVE|GHSA|GO|PYSEC|RUSTSEC|OSV|GSD|MAL|BIT|CGA|DLA|DSA|USN|RHSA|ALAS|ALSA|RLSA|ELSA"
    r"|SNYK|UVI|PSF)-[0-9A-Za-z][0-9A-Za-z.:_-]*"
)
# OSV-Scanner: "Package 'lodash@4.17.20' is vulnerable to 'CVE-2021-23337' (also known as
# 'GHSA-35jh-r3h4-6jhm')."
_OSV_MESSAGE = re.compile(
    r"Package '(?P<package>.+)@(?P<version>[^@']*)' is vulnerable to '(?P<id>[^']+)'"
    r"(?: \(also known as (?P<aliases>.*)\))?"
)
_QUOTED = re.compile(r"'([^']+)'")

# Package types of Grype and the OSV ecosystem names.
_GRYPE_TYPES = {
    "npm": "npm",
    "python": "PyPI",
    "go-module": "Go",
    "java-archive": "Maven",
    "jenkins-plugin": "Maven",
    "gem": "RubyGems",
    "rust-crate": "crates.io",
    "dotnet": "NuGet",
    "php-composer": "Packagist",
    "dart-pub": "Pub",
    "hex": "Hex",
    "deb": "Debian",
    "apk": "Alpine",
}
# Package URL types and the OSV ecosystem names. An unknown type stays as written.
_PURL_TYPES = {
    "npm": "npm",
    "pypi": "PyPI",
    "golang": "Go",
    "maven": "Maven",
    "gem": "RubyGems",
    "cargo": "crates.io",
    "nuget": "NuGet",
    "composer": "Packagist",
    "pub": "Pub",
    "hex": "Hex",
    "cran": "CRAN",
    "conan": "ConanCenter",
    "swift": "SwiftURL",
    "cocoapods": "CocoaPods",
    "deb": "Debian",
    "apk": "Alpine",
    "github": "GitHub Actions",
}
# Package URL types whose namespace is a distribution, not a part of the package name.
_DISTRO_PURL_TYPES = frozenset({"deb", "rpm", "apk", "alpm"})
# Manifest and lock file names and the OSV ecosystem names.
_MANIFESTS = {
    "package-lock.json": "npm",
    "npm-shrinkwrap.json": "npm",
    "yarn.lock": "npm",
    "pnpm-lock.yaml": "npm",
    "bun.lock": "npm",
    "package.json": "npm",
    "pipfile.lock": "PyPI",
    "poetry.lock": "PyPI",
    "pdm.lock": "PyPI",
    "uv.lock": "PyPI",
    "pylock.toml": "PyPI",
    "pyproject.toml": "PyPI",
    "setup.py": "PyPI",
    "go.mod": "Go",
    "go.sum": "Go",
    "cargo.lock": "crates.io",
    "cargo.toml": "crates.io",
    "gemfile.lock": "RubyGems",
    "gems.locked": "RubyGems",
    "composer.lock": "Packagist",
    "composer.json": "Packagist",
    "pom.xml": "Maven",
    "gradle.lockfile": "Maven",
    "build.gradle": "Maven",
    "build.gradle.kts": "Maven",
    "packages.lock.json": "NuGet",
    "packages.config": "NuGet",
    "pubspec.lock": "Pub",
    "mix.lock": "Hex",
    "renv.lock": "CRAN",
    "conan.lock": "ConanCenter",
}
# Explicit CVSS properties: (score key, vector key), in order of preference.
_CVSS_KEYS = (
    ("cvssv3_baseScore", "cvssv3_vector"),
    ("cvssv40_baseScore", "cvssv40_vector"),
    ("cvss_score", "cvss_vector"),
    ("cvssScore", "cvssVector"),
    ("cvssv2_baseScore", "cvssv2_vector"),
    ("cvssv2_score", "cvssv2_vector"),
)
_PACKAGE_KEYS = ("packageName", "package_name", "package", "pkgName")
_VERSION_KEYS = ("packageVersion", "package_version", "installedVersion", "installed_version")
_FIXED_KEYS = ("fixedVersions", "fixed_versions", "fixedVersion", "fixed_version", "fixVersion")

# Default classes of the engines whose results all belong to one class.
_ENGINE_CLASSES = {
    "gitleaks": "hardcoded-secrets",
    "gitleaks-history": "hardcoded-secrets",
    "kingfisher": "hardcoded-secrets",
    "kingfisher-history": "hardcoded-secrets",
    "hadolint": "iac-cloud-container",
    "osv-scanner": "vulnerable-dependency",
    "grype": "vulnerable-dependency",
    "govulncheck": "vulnerable-dependency",
    **dict.fromkeys(CICD_ENGINES, "supply-chain-cicd"),
    "vacuum": "security-misconfig",
}
_CHECKOV_SECRET = re.compile(r"CKV2?_SECRET_")
# Checkov CI/CD pipeline and source-control checks. ENGINE-SPEC 8.1 names GitHub Actions
# (CKV_GHA_, CKV2_GHA_). The checks for the other CI systems and for GitHub, GitLab and
# Bitbucket settings are supply chain checks too.
_CHECKOV_SUPPLY_CHAIN = re.compile(
    r"CKV2?_(?:GHA|GITHUB|GITLABCI|GITLAB|BITBUCKETPIPELINES|BITBUCKET|AZUREPIPELINES"
    r"|CIRCLECIPIPELINES)_"
)
# Trivy check IDs: DS002, KSV001, AWS-0086, AVD-AWS-0107.
_TRIVY_CHECK_ID = re.compile(r"(?:AVD-)?[A-Z][A-Z0-9]*-?[0-9]{3,4}")
# Trivy built-in secret rule IDs: aws-access-key-id, github-pat, private-key.
_TRIVY_SECRET_ID = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)+")


@dataclass
class IngestResult:
    """The candidates and the warnings of one SARIF document."""

    candidates: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class _BadResult(Exception):
    """A SARIF result that cannot become a candidate."""


def ingest_file(
    path: str | os.PathLike[str], engine: str, target_root: str | os.PathLike[str] | None
) -> IngestResult:
    """Read a SARIF file and return its candidates and warnings.

    :func:`kalkan.util.safe_io.read_bounded` reads the file: at most :data:`MAX_SARIF_BYTES`,
    and never through a symlink or a reparse point. The JSON can be UTF-8 (with or without a
    byte order mark), UTF-16 or UTF-32. Windows PowerShell writes UTF-16.

    Raise :class:`~kalkan.errors.UnsafeInputError` when the file is missing, is not a regular
    file, is too large or cannot be read safely. Raise :class:`~kalkan.errors.ValidationError`
    for a file that is not SARIF 2.1.0 JSON. ``raw.sarif_file`` of each candidate is ``path``
    with ``/`` separators.
    """
    source = Path(path)
    data = read_bounded(source, MAX_SARIF_BYTES)
    try:
        # json.loads detects UTF-8 (with or without a BOM), UTF-16 and UTF-32 in bytes.
        doc = json.loads(data)
    except ValueError as exc:
        message = f"{source.as_posix()}: not a JSON document: {exc}"
        raise ValidationError(message, [message]) from exc
    return ingest_document(doc, engine, target_root, source.as_posix())


def ingest_document(
    doc: Any,
    engine: str,
    target_root: str | os.PathLike[str] | None,
    sarif_file: str | os.PathLike[str],
) -> IngestResult:
    """Turn a parsed SARIF 2.1.0 document into candidate records (ENGINE-SPEC 4).

    ``engine`` is one of :data:`ENGINES`. ``target_root`` is the root that file paths become
    relative to. ``sarif_file`` names the document in ``raw.sarif_file`` and in warnings.
    Raise :class:`~kalkan.errors.ValidationError` for an unknown engine or a document that
    is not SARIF 2.1.0. Runs without results are ignored.
    """
    # Lazy import: ENGINE-SPEC 6.2 IDs come from the fingerprint module.
    from kalkan.findings.fingerprint import candidate_id

    if engine not in ENGINES:
        message = f"unknown engine {engine!r}; expected one of: {', '.join(ENGINES)}"
        raise ValidationError(message, [message])
    source = _source_name(sarif_file)
    runs = _runs(doc, source)
    outcome = IngestResult()
    for run_index, run in enumerate(runs):
        where_run = f"{source}: run {run_index}"
        if not isinstance(run, Mapping):
            outcome.warnings.append(f"{where_run}: the run is not an object; skipped")
            continue
        results = run.get("results")
        if results is None:
            continue
        if not isinstance(results, list):
            outcome.warnings.append(f"{where_run}: 'results' is not an array; skipped")
            continue
        context = _RunContext.build(run)
        for result_index, item in enumerate(results):
            where = f"{where_run}, result {result_index}"
            notes: list[str] = []
            try:
                candidate = _candidate(item, context, engine, target_root, notes, candidate_id)
            except _BadResult as exc:
                outcome.warnings.append(f"{where}: {exc}; skipped")
                continue
            except Exception as exc:  # ENGINE-SPEC 8.1: never raise on a single bad result.
                outcome.warnings.append(f"{where}: {type(exc).__name__}: {exc}; skipped")
                continue
            outcome.warnings.extend(f"{where}: {note}" for note in notes)
            if candidate is None:
                continue
            candidate["raw"] = {
                "sarif_file": source,
                "run_index": run_index,
                "result_index": result_index,
            }
            outcome.candidates.append(candidate)
    return outcome


def default_class(engine: str, rule_id: str, rule: Mapping[str, Any] | None = None) -> str | None:
    """Return the class of a result whose CWE IDs give no class (ENGINE-SPEC 8.1).

    - gitleaks, gitleaks-history, kingfisher, kingfisher-history: ``hardcoded-secrets``.
    - trivy: the rule tags and the rule name give the result type. Without them, the rule ID
      shape decides. Secret results give ``hardcoded-secrets``, vulnerability results
      ``vulnerable-dependency``, misconfiguration results ``iac-cloud-container``. License
      results give None.
    - checkov and helm-checkov: ``CKV_SECRET_*`` gives ``hardcoded-secrets``. CI/CD and
      source-control checks (``CKV_GHA_*``, ``CKV2_GHA_*``, GitLab CI, Bitbucket, Azure
      Pipelines, CircleCI, GitHub and GitLab settings) give ``supply-chain-cicd``. A
      vulnerability ID gives ``vulnerable-dependency``. All other checks give
      ``iac-cloud-container``.
    - hadolint: ``iac-cloud-container``.
    - osv-scanner, grype, govulncheck: ``vulnerable-dependency``.
    - zizmor, actionlint, poutine, scorecard: ``supply-chain-cicd`` (a result without a
      ``kalkan-class`` property and without a mapped CWE).
    - vacuum: ``security-misconfig`` (a result without a ``kalkan-class`` property and without a
      mapped CWE).
    - bandit, gosec, opengrep, matcher, syft, shellcheck, flawfinder and gixy: None. A rule of
      these engines without a mapped CWE has no safe default (the ShellCheck and gixy adapters
      give every result a CWE that maps).
    """
    if engine in _ENGINE_CLASSES:
        return _ENGINE_CLASSES[engine]
    if engine == "trivy":
        return _trivy_class(rule_id, rule or {})
    if engine in ("checkov", "helm-checkov"):
        return _checkov_class(rule_id)
    return None


def _trivy_class(rule_id: str, rule: Mapping[str, Any]) -> str | None:
    # Trivy writes the result type as the first rule tag and in the rule name: "vulnerability"
    # (name "LanguageSpecificPackageVulnerability" or "OsPackageVulnerability"),
    # "misconfiguration" (name "Misconfiguration"), "secret" (name "Secret") and "license".
    tags = {tag.strip().lower() for tag in _strings(_mapping(rule.get("properties")).get("tags"))}
    name = _string(rule.get("name")).strip().lower()
    if "license" in tags or name == "license":
        return None
    if "secret" in tags or name == "secret":
        return "hardcoded-secrets"
    if "vulnerability" in tags or name.endswith("vulnerability"):
        return "vulnerable-dependency"
    if "misconfiguration" in tags or name == "misconfiguration":
        return "iac-cloud-container"
    if _is_vuln_id(rule_id):
        return "vulnerable-dependency"
    if _TRIVY_CHECK_ID.fullmatch(rule_id):
        return "iac-cloud-container"
    if _TRIVY_SECRET_ID.fullmatch(rule_id):
        return "hardcoded-secrets"
    return None


def _checkov_class(rule_id: str) -> str:
    if _CHECKOV_SECRET.match(rule_id):
        return "hardcoded-secrets"
    if _CHECKOV_SUPPLY_CHAIN.match(rule_id):
        return "supply-chain-cicd"
    # Checkov SCA results (they need a Prisma Cloud API key) use the vulnerability ID.
    if _is_vuln_id(rule_id):
        return "vulnerable-dependency"
    return "iac-cloud-container"


@dataclass(frozen=True)
class _RunContext:
    driver_rules: list[Any]
    driver_by_id: Mapping[str, Mapping[str, Any]]
    extension_by_id: Mapping[str, Mapping[str, Any]]
    base_uris: Mapping[str, Any] | None
    artifacts: list[Any]

    @classmethod
    def build(cls, run: Mapping[str, Any]) -> _RunContext:
        tool = _mapping(run.get("tool"))
        driver_rules = _list(_mapping(tool.get("driver")).get("rules"))
        extension_rules = [
            rule
            for extension in _list(tool.get("extensions"))
            for rule in _list(_mapping(extension).get("rules"))
        ]
        base_uris = run.get("originalUriBaseIds")
        return cls(
            driver_rules=driver_rules,
            driver_by_id=_rules_by_id(driver_rules),
            extension_by_id=_rules_by_id(extension_rules),
            base_uris=base_uris if isinstance(base_uris, Mapping) else None,
            artifacts=_list(run.get("artifacts")),
        )

    def artifact_location(self, index: object) -> Mapping[str, Any]:
        """Return ``run.artifacts[index].location`` (SARIF ``artifactLocation.index``)."""
        if _is_int(index) and 0 <= index < len(self.artifacts):
            return _mapping(_mapping(self.artifacts[index]).get("location"))
        return {}


def _candidate(
    item: object,
    context: _RunContext,
    engine: str,
    target_root: str | os.PathLike[str] | None,
    notes: list[str],
    make_id: Callable[[str, str, str, int | None, str], str],
) -> dict[str, Any] | None:
    if not isinstance(item, Mapping):
        raise _BadResult("the result is not an object")
    if item.get("kind") in _NOT_A_PROBLEM:
        return None
    rule_id, rule = _find_rule(item, context)
    result_props = _mapping(item.get("properties"))
    rule_props = _mapping(rule.get("properties"))

    cwe = _cwes(result_props, rule_props, rule)
    vuln_class = (
        _rule_class(engine, result_props, rule_props)
        or (class_for_cwe(cwe[0]) if cwe else None)
        or default_class(engine, rule_id, rule)
    )
    title = _message_text(rule.get("shortDescription")).strip() or _string(rule.get("name")).strip()
    message = _message_text(item.get("message")) or _message_text(rule.get("fullDescription"))
    file, start_line, end_line, snippet = _location(item, context, target_root, notes)
    if engine == "grype":
        file = _grype_path(file)
    if file and not is_target_relative(file):
        notes.append(f"the file {file!r} is not inside the target root")
    severity, tool_severity = for_sarif_result(item, rule)
    tags = _unique([*_strings(result_props.get("tags")), *_strings(rule_props.get("tags"))])

    return {
        "id": make_id(engine, rule_id, file, start_line, snippet),
        "engine": engine,
        "rule_id": rule_id,
        "class": vuln_class,
        "cwe": cwe,
        "title": title or rule_id,
        "message": message,
        "file": file,
        "start_line": start_line,
        "end_line": end_line,
        "snippet": snippet,
        "severity": severity,
        "tool_severity": tool_severity,
        "confidence": _confidence(result_props, rule_props),
        "tags": tags,
        "fingerprints": _fingerprints(item),
        "sca": _sca(engine, rule_id, rule, rule_props, result_props, message, file),
    }


def _rule_class(
    engine: str, result_props: Mapping[str, Any], rule_props: Mapping[str, Any]
) -> str | None:
    """Return the ``kalkan-class`` of a result or its rule for :data:`RULE_CLASS_ENGINES` and
    :data:`PACK_CLASS_ENGINES`.

    Only a known taxonomy slug counts; any other engine gives None.
    """
    if engine not in RULE_CLASS_ENGINES and engine not in PACK_CLASS_ENGINES:
        return None
    for props in (result_props, rule_props):
        value = props.get(_RULE_CLASS_PROPERTY)
        if isinstance(value, str) and value in SLUGS:
            return value
    return None


def _find_rule(item: Mapping[str, Any], context: _RunContext) -> tuple[str, Mapping[str, Any]]:
    """Return the rule ID and the rule (empty when the run has no rule for it)."""
    reference = _mapping(item.get("rule"))
    rule_id = _string(item.get("ruleId")) or _string(reference.get("id"))
    index = item.get("ruleIndex")
    if index is None and "toolComponent" not in reference:
        index = reference.get("index")

    rule: Mapping[str, Any] | None = None
    if _is_int(index) and 0 <= index < len(context.driver_rules):
        indexed = _mapping(context.driver_rules[index])
        indexed_id = _string(indexed.get("id"))
        # A ruleIndex that disagrees with the ruleId is wrong (old Checkov versions). The
        # ruleId wins.
        if indexed and (not rule_id or indexed_id == rule_id):
            rule = indexed
            rule_id = rule_id or indexed_id
    if rule is None and rule_id:
        rule = context.driver_by_id.get(rule_id) or context.extension_by_id.get(rule_id)
    if not rule_id:
        raise _BadResult("the result has no rule ID")
    return rule_id, rule or {}


def _cwes(
    result_props: Mapping[str, Any], rule_props: Mapping[str, Any], rule: Mapping[str, Any]
) -> list[str]:
    found: list[str] = []
    for props in (result_props, rule_props):
        for tag in _strings(props.get("tags")):
            if _CWE_TAG.match(tag):
                _append(found, normalize_cwe(tag))
        for value in _cwe_values(props.get("cwe")):
            _append(found, normalize_cwe(value))
    for relationship in _list(rule.get("relationships")):
        target = _mapping(_mapping(relationship).get("target"))
        target_id = target.get("id")
        if not isinstance(target_id, str):
            continue
        component = _string(_mapping(target.get("toolComponent")).get("name"))
        if target_id.strip().upper().startswith("CWE-") or component.strip().upper() == "CWE":
            _append(found, normalize_cwe(target_id))
    return found


def _cwe_values(value: object) -> list[object]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str | int)]
    if isinstance(value, str | int):
        return [value]
    return []


def _location(
    item: Mapping[str, Any],
    context: _RunContext,
    target_root: str | os.PathLike[str] | None,
    notes: list[str],
) -> tuple[str, int | None, int | None, str]:
    physical: Mapping[str, Any] | None = None
    for location in _list(item.get("locations")):
        value = _mapping(location).get("physicalLocation")
        if isinstance(value, Mapping):
            physical = value
            break
    if physical is None:
        return "", None, None, ""

    artifact = _mapping(physical.get("artifactLocation"))
    uri = artifact.get("uri")
    base_id = artifact.get("uriBaseId")
    if not _string(uri).strip():
        listed = context.artifact_location(artifact.get("index"))
        uri = listed.get("uri")
        base_id = base_id or listed.get("uriBaseId")
    file = normalize_uri(
        _string(uri),
        target_root,
        context.base_uris,
        uri_base_id=_string(base_id) or None,
    )

    region = _mapping(physical.get("region"))
    start_line = _line(region, "startLine", notes)
    end_line = _line(region, "endLine", notes) if start_line is not None else None
    if start_line is not None:
        if end_line is not None and end_line < start_line:
            notes.append(f"region.endLine {end_line} is before startLine {start_line}; ignored")
            end_line = None
        if end_line is None:
            end_line = start_line
    snippet = _mapping(region.get("snippet")).get("text")
    return file, start_line, end_line, snippet if isinstance(snippet, str) else ""


def _line(region: Mapping[str, Any], key: str, notes: list[str]) -> int | None:
    value = region.get(key)
    if value is None:
        return None
    if _is_int(value) and value >= 1:
        return value
    notes.append(f"region.{key} {value!r} is not a line number; ignored")
    return None


def _grype_path(file: str) -> str:
    # Grype writes a package location relative to its scan root with a leading "/" (a Syft
    # location path), for example "/package-lock.json".
    if file.startswith("/") and not file.startswith("//"):
        return file.lstrip("/")
    return file


def _confidence(result_props: Mapping[str, Any], rule_props: Mapping[str, Any]) -> str | None:
    for props in (result_props, rule_props):
        for key in _CONFIDENCE_KEYS:
            value = props.get(key)
            if isinstance(value, str) and value.strip().lower() in _CONFIDENCE_WORDS:
                return _CONFIDENCE_WORDS[value.strip().lower()]
    for props in (result_props, rule_props):
        for tag in _strings(props.get("tags")):
            match = _CONFIDENCE_TAG.fullmatch(tag)
            if match:
                return match.group(1).lower()
    for props in (result_props, rule_props):
        value = props.get("precision")
        if isinstance(value, str) and value.strip().lower() in _CONFIDENCE_WORDS:
            return _CONFIDENCE_WORDS[value.strip().lower()]
    return None


def _fingerprints(item: Mapping[str, Any]) -> dict[str, str]:
    values: dict[str, str] = {}
    for source in (item.get("fingerprints"), item.get("partialFingerprints")):
        for key, value in _mapping(source).items():
            if isinstance(key, str) and isinstance(value, str) and value:
                values[key] = value
    return values


# --- software composition analysis -----------------------------------------------------------


def _sca(
    engine: str,
    rule_id: str,
    rule: Mapping[str, Any],
    rule_props: Mapping[str, Any],
    result_props: Mapping[str, Any],
    message: str,
    file: str,
) -> dict[str, Any] | None:
    rule_tags = {tag.strip().lower() for tag in _strings(rule_props.get("tags"))}
    if engine not in SCA_ENGINES and not (engine == "trivy" and "vulnerability" in rule_tags):
        return None
    sca: dict[str, Any] = {
        "ecosystem": "",
        "package": "",
        "version": "",
        "vuln_ids": [],
        "fixed_versions": [],
        "cvss_score": None,
        "cvss_vector": None,
    }
    for props in (result_props, rule_props):
        _read_sca_properties(sca, props)
    if engine == "grype":
        _read_grype(sca, rule_id, rule)
    elif engine == "osv-scanner":
        _read_osv_scanner(sca, rule_id, rule, rule_props, message)
    elif engine == "govulncheck":
        _add_ids(sca, [rule_id, *(t for t in _strings(rule_props.get("tags")) if _is_vuln_id(t))])
        _set(sca, "ecosystem", "Go")
    else:
        _read_trivy(sca, rule_id, message)
    _set(sca, "ecosystem", _manifest_ecosystem(file))
    return sca


def _read_sca_properties(sca: dict[str, Any], props: Mapping[str, Any]) -> None:
    purls = props.get("purls")
    for purl in [*_strings(purls), _string(props.get("purl"))]:
        parsed = _parse_purl(purl)
        if parsed is not None:
            ecosystem, package, version = parsed
            _set(sca, "ecosystem", ecosystem)
            _set(sca, "package", package)
            _set(sca, "version", version)
            break
    for key in _PACKAGE_KEYS:
        _set(sca, "package", props.get(key))
    for key in _VERSION_KEYS:
        _set(sca, "version", props.get(key))
    for key in _FIXED_KEYS:
        _add_fixed(sca, props.get(key))
    _set(sca, "ecosystem", props.get("ecosystem"))
    _add_ids(sca, _strings(props.get("aliases")))
    for score_key, vector_key in _CVSS_KEYS:
        score = _number(props.get(score_key))
        vector = _string(props.get(vector_key)).strip()
        if score is None and not vector:
            continue
        if sca["cvss_score"] is None and sca["cvss_vector"] is None:
            sca["cvss_score"] = score
            sca["cvss_vector"] = vector or None
        break


def _read_grype(sca: dict[str, Any], rule_id: str, rule: Mapping[str, Any]) -> None:
    # Grype help text: "Vulnerability <id>\nSeverity: ...\nPackage: ...\nVersion: ...\n
    # Fix Version: ...\nType: ...\nLocation: ...\nData Namespace: ...\nLink: ...".
    help_text = _message_text(rule.get("help"))
    fields = _help_fields(help_text)
    _set(sca, "package", fields.get("package"))
    _set(sca, "version", fields.get("version"))
    _add_fixed(sca, fields.get("fix version"))
    _set(sca, "ecosystem", _GRYPE_TYPES.get(fields.get("type", "").strip().lower()))
    match = re.search(r"^Vulnerability (\S+)", help_text, re.MULTILINE)
    vuln_id = match.group(1) if match else ""
    package = sca["package"]
    # The Grype rule ID is "<vulnerability ID>-<package name>".
    if not vuln_id and package and rule_id.endswith("-" + package):
        vuln_id = rule_id[: -len(package) - 1]
    _add_ids(sca, [vuln_id])


def _read_osv_scanner(
    sca: dict[str, Any],
    rule_id: str,
    rule: Mapping[str, Any],
    rule_props: Mapping[str, Any],
    message: str,
) -> None:
    ids = [rule_id]
    match = _OSV_MESSAGE.search(message)
    if match:
        _set(sca, "package", match.group("package"))
        _set(sca, "version", match.group("version"))
        ids.append(match.group("id"))
        ids.extend(_QUOTED.findall(match.group("aliases") or ""))
    # OSV-Scanner lists all IDs of the alias group as deprecatedIds of the rule.
    ids.extend(_strings(rule.get("deprecatedIds")))
    _add_ids(sca, ids)
    # The OSV-Scanner security-severity is the CVSS base score of the worst alias.
    if sca["cvss_score"] is None:
        sca["cvss_score"] = _number(rule_props.get("security-severity"))


def _read_trivy(sca: dict[str, Any], rule_id: str, message: str) -> None:
    # Trivy message: "Package: ...\nInstalled Version: ...\nVulnerability <id>\n
    # Severity: ...\nFixed Version: ...\nLink: ...".
    fields = _help_fields(message)
    _set(sca, "package", fields.get("package"))
    _set(sca, "version", fields.get("installed version"))
    _add_fixed(sca, fields.get("fixed version"))
    _add_ids(sca, [rule_id])


def _help_fields(text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in text.splitlines():
        key, separator, value = line.partition(":")
        if separator and key.strip():
            fields.setdefault(key.strip().lower(), value.strip())
    return fields


def _parse_purl(text: str) -> tuple[str | None, str | None, str | None] | None:
    """Return ``(ecosystem, package, version)`` of a package URL, or None."""
    if not text.startswith("pkg:"):
        return None
    body = text[4:].split("#", 1)[0].split("?", 1)[0].lstrip("/")
    purl_type, _, rest = body.partition("/")
    if not purl_type or not rest:
        return None
    name_part, version = rest, ""
    at = rest.rfind("@")
    if at > 0 and "/" not in rest[at + 1 :]:
        name_part, version = rest[:at], rest[at + 1 :]
    segments = [unquote(segment) for segment in name_part.split("/") if segment]
    if not segments:
        return None
    purl_type = purl_type.lower()
    if purl_type == "maven" and len(segments) >= 2:
        package = ":".join(segments[-2:])
    elif purl_type in _DISTRO_PURL_TYPES:
        package = segments[-1]
    else:
        package = "/".join(segments)
    return _PURL_TYPES.get(purl_type, purl_type), package, unquote(version) or None


def _manifest_ecosystem(file: str) -> str | None:
    name = file.rsplit("/", 1)[-1].lower()
    if name in _MANIFESTS:
        return _MANIFESTS[name]
    if name.startswith("requirements") and name.endswith(".txt"):
        return "PyPI"
    if name.endswith((".csproj", ".deps.json")):
        return "NuGet"
    return None


def _set(sca: dict[str, Any], key: str, value: object) -> None:
    if not sca[key] and isinstance(value, str) and value.strip():
        sca[key] = value.strip()


def _add_ids(sca: dict[str, Any], values: Iterable[str]) -> None:
    for value in values:
        if isinstance(value, str) and value.strip() and value.strip() not in sca["vuln_ids"]:
            sca["vuln_ids"].append(value.strip())


def _add_fixed(sca: dict[str, Any], value: object) -> None:
    items = value.split(",") if isinstance(value, str) else _strings(value)
    for item in items:
        version = item.strip()
        if version and version not in sca["fixed_versions"]:
            sca["fixed_versions"].append(version)


def _is_vuln_id(value: str) -> bool:
    return _VULN_ID.fullmatch(value.strip()) is not None


def _number(value: object) -> float | None:
    """Return a finite, non-negative score, or None. JSON has no NaN or infinity."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        number = float(value)
    elif isinstance(value, str):
        try:
            number = float(value.strip())
        except ValueError:
            return None
    else:
        return None
    return number if math.isfinite(number) and number >= 0 else None


# --- small helpers -----------------------------------------------------------------------------


def _runs(doc: Any, source: str) -> list[Any]:
    if not isinstance(doc, Mapping):
        message = f"{source}: the SARIF document is not a JSON object"
        raise ValidationError(message, [message])
    version = doc.get("version")
    if version != SARIF_VERSION:
        message = f"{source}: SARIF version {version!r} is not supported; expected '2.1.0'"
        raise ValidationError(message, [message])
    runs = doc.get("runs")
    if not isinstance(runs, list):
        message = f"{source}: 'runs' is not an array"
        raise ValidationError(message, [message])
    return runs


def _source_name(sarif_file: str | os.PathLike[str]) -> str:
    if isinstance(sarif_file, PurePath):
        return sarif_file.as_posix()
    return os.fspath(sarif_file).replace("\\", "/")


def _rules_by_id(rules: list[Any]) -> Mapping[str, Mapping[str, Any]]:
    by_id: dict[str, Mapping[str, Any]] = {}
    for rule in rules:
        if isinstance(rule, Mapping):
            rule_id = _string(rule.get("id"))
            if rule_id:
                by_id.setdefault(rule_id, rule)
    return by_id


def _message_text(value: object) -> str:
    """Return ``value["text"]`` of a SARIF message object, or ``""``."""
    text = _mapping(value).get("text")
    return text if isinstance(text, str) and text.strip() else ""


def _append(values: list[str], value: str | None) -> None:
    if value is not None and value not in values:
        values.append(value)


def _unique(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(values))


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _string(value: object) -> str:
    return value if isinstance(value, str) else ""


def _strings(value: object) -> list[str]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []


def _mapping(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _list(value: object) -> list[Any]:
    return value if isinstance(value, list) else []
