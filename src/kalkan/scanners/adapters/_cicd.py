# SPDX-License-Identifier: MIT
"""Helpers of the CI/CD and supply chain adapters: zizmor, actionlint, poutine, Scorecard.

1. **Files.** :func:`ci_files` finds the CI configuration files that the tools read, with
   the path patterns of the tools (target-relative POSIX paths): GitHub Actions workflows
   (``.github/workflows/*.yml``), action metadata (``action.yml`` in any folder), Dependabot
   and pre-commit files (zizmor), GitLab CI, Azure Pipelines and Tekton files (poutine).
2. **Paths.** :func:`target_path` turns a path that a tool reports into a target-relative POSIX
   path: absolute paths, Windows separators, paths relative to the working directory of the
   tool, and paths relative to a git repository that holds the run folder (zizmor writes
   ``runs/<run-id>/target/.github/...`` when the runs folder is inside a git work tree).
3. **Classes.** Each adapter has a rule table: rule ID to kalkan class and CWE IDs (the module
   docstring of each adapter lists it). The adapters write the class as the SARIF property
   ``kalkan-class`` of the rule (or of one result) and the CWE IDs as ``external/cwe/cwe-<n>``
   rule tags. :mod:`kalkan.sarif.ingest` takes the class from ``kalkan-class`` for these engines,
   so a CWE that the taxonomy maps to another class (CWE-522 artipacked) keeps its CI/CD class.
4. **SARIF.** :func:`sarif_document`, :func:`sarif_rule` and :func:`sarif_result` build the
   SARIF 2.1.0 output of the adapters that convert a JSON report (actionlint, poutine,
   Scorecard).
"""

from __future__ import annotations

import os
import posixpath
import re
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Final

from kalkan.findings.taxonomy import SLUGS

__all__ = [
    "ACTION_METADATA",
    "AZURE_PIPELINES",
    "CLASS_PROPERTY",
    "DEFAULT_CLASS",
    "DEPENDABOT",
    "GITHUB_WORKFLOW",
    "GITLAB_CI",
    "PRE_COMMIT",
    "TEKTON",
    "CiFiles",
    "RuleClass",
    "ci_files",
    "on_windows",
    "rule_properties",
    "sarif_document",
    "sarif_result",
    "sarif_rule",
    "target_path",
]

#: The SARIF property that names the kalkan class of a rule or result (kalkan.sarif.ingest).
CLASS_PROPERTY: Final = "kalkan-class"
#: The class of a rule that a rule table does not list.
DEFAULT_CLASS: Final = "supply-chain-cicd"

#: Folders that :func:`ci_files` does not enter (no CI configuration lives there).
SKIP_DIRS: Final = frozenset({".git", "node_modules", ".venv", "venv"})
#: GitHub Actions workflows: only the files directly in ``.github/workflows`` count.
GITHUB_WORKFLOW: Final = re.compile(r"^\.github/workflows/[^/]+\.ya?ml$")
#: Action metadata (composite, JavaScript and Docker actions) in any folder.
ACTION_METADATA: Final = re.compile(r"(?:^|/)action\.ya?ml$")
#: Dependabot configuration (zizmor audits it).
DEPENDABOT: Final = re.compile(r"^\.github/dependabot\.ya?ml$")
#: pre-commit configuration and hook definitions (zizmor audits them).
PRE_COMMIT: Final = re.compile(r"^\.pre-commit-(?:config|hooks)\.ya?ml$")
#: GitLab CI, Azure Pipelines and Tekton: the patterns of poutine 1.1.6 (scanner/parsers.go).
GITLAB_CI: Final = re.compile(r"\.?gitlab-ci(?:-.+)?\.ya?ml$")
AZURE_PIPELINES: Final = re.compile(r"\.?azure-pipelines(?:-.+)?\.ya?ml$")
TEKTON: Final = re.compile(r"^\.tekton/[^/]+\.ya?ml$")


@dataclass(frozen=True)
class CiFiles:
    """The CI configuration files of a target (target-relative POSIX paths, sorted)."""

    workflows: tuple[str, ...] = ()
    actions: tuple[str, ...] = ()
    dependabot: tuple[str, ...] = ()
    pre_commit: tuple[str, ...] = ()
    gitlab: tuple[str, ...] = ()
    azure: tuple[str, ...] = ()
    tekton: tuple[str, ...] = ()


def on_windows() -> bool:
    """Return True on Windows, where poutine 1.1.6 and Scorecard 5.5.0 miss files (tests patch
    this function)."""
    return os.name == "nt"


def ci_files(target: Path) -> CiFiles:
    """Return the CI configuration files of ``target`` (one walk of the target copy).

    The walk takes regular files only, enters no link or Windows junction and skips
    :data:`SKIP_DIRS`. Unlike the walk of the matchers it enters ``build`` and ``dist``: a local
    action often lives in ``.github/actions/build/action.yml``.
    """
    found: dict[str, list[str]] = {name: [] for name in CiFiles.__dataclass_fields__}
    patterns = (
        ("workflows", GITHUB_WORKFLOW),
        ("actions", ACTION_METADATA),
        ("dependabot", DEPENDABOT),
        ("pre_commit", PRE_COMMIT),
        ("gitlab", GITLAB_CI),
        ("azure", AZURE_PIPELINES),
        ("tekton", TEKTON),
    )
    for rel in _walk(target):
        for name, pattern in patterns:
            if pattern.search(rel):
                found[name].append(rel)
    return CiFiles(**{name: tuple(sorted(paths)) for name, paths in found.items()})


def _walk(root: Path) -> list[str]:
    """Return the target-relative POSIX paths of the regular files below ``root``."""
    found: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        base = Path(dirpath)
        dirnames[:] = sorted(
            name for name in dirnames if name not in SKIP_DIRS and not _is_link(base / name)
        )
        for name in filenames:
            path = base / name
            try:
                if stat.S_ISREG(os.lstat(path).st_mode):
                    found.append(path.relative_to(root).as_posix())
            except OSError:
                continue
    return sorted(found)


def _is_link(path: Path) -> bool:
    if path.is_symlink():
        return True
    isjunction = getattr(os.path, "isjunction", None)
    return bool(isjunction and isjunction(path))


def target_path(raw: object, target: Path, *, cwd: Path | None = None) -> str:
    """Return a tool path as a target-relative POSIX path (module docstring, point 2).

    The rules, in order: an absolute path inside the target; a path relative to ``cwd`` that
    lies inside the target; a path that names a file of the target as it is; a path whose
    leading folders are the last folders of the target path (relative to a git repository that
    holds the run folder). Anything else comes back as written, with ``/`` separators; the
    SARIF ingest then warns that the file is outside the target.
    """
    text = str(raw or "").strip()
    if not text:
        return ""
    if text.lower().startswith("file://"):
        text = text[7:]
    posix = text.replace("\\", "/")
    root = target.resolve()
    candidate = Path(text)
    if candidate.is_absolute() or re.match(r"^[A-Za-z]:/", posix):
        try:
            return Path(os.path.abspath(text)).resolve().relative_to(root).as_posix()
        except (OSError, ValueError):
            return posix
    if cwd is not None:
        try:
            joined = (cwd / posix).resolve()  # a Windows path from a tool on POSIX too
            if joined.is_file():
                return joined.relative_to(root).as_posix()
        except (OSError, ValueError):
            pass
    clean = posixpath.normpath(posix)
    if clean.startswith("./"):
        clean = clean[2:]
    if _is_file(root, clean):
        return clean
    parts = root.parts
    for count in range(1, len(parts)):
        prefix = "/".join(parts[-count:]) + "/"
        if clean.startswith(prefix) and _is_file(root, clean[len(prefix) :]):
            return clean[len(prefix) :]
    return clean


def _is_file(root: Path, rel: str) -> bool:
    if not rel or rel.startswith(("../", "/")) or rel == "..":
        return False
    try:
        path = (root / PurePosixPath(rel)).resolve()
        return path.is_file() and path.is_relative_to(root)
    except (OSError, ValueError):
        return False


@dataclass(frozen=True)
class RuleClass:
    """The kalkan class and CWE IDs of one tool rule."""

    vuln_class: str
    cwe: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.vuln_class not in SLUGS:
            raise ValueError(f"unknown class {self.vuln_class!r}")


def rule_properties(rule: RuleClass, extra_tags: tuple[str, ...] = ()) -> dict[str, Any]:
    """Return the SARIF property bag of a rule: tags with the CWE IDs and ``kalkan-class``."""
    tags = ["security", *extra_tags, *(f"external/cwe/{c.lower()}" for c in rule.cwe)]
    if rule.vuln_class == "code-quality":
        tags = [tag for tag in tags if tag != "security"]
    return {"tags": list(dict.fromkeys(tags)), CLASS_PROPERTY: rule.vuln_class}


def sarif_rule(
    rule_id: str,
    rule: RuleClass,
    *,
    title: str = "",
    description: str = "",
    help_uri: str = "",
    extra_tags: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Return one SARIF ``reportingDescriptor``."""
    item: dict[str, Any] = {"id": rule_id, "name": rule_id}
    if title:
        item["shortDescription"] = {"text": title}
    if description:
        item["fullDescription"] = {"text": description}
    if help_uri:
        item["helpUri"] = help_uri
    item["properties"] = rule_properties(rule, extra_tags)
    return item


def sarif_result(
    rule_id: str,
    message: str,
    *,
    level: str = "warning",
    file: str = "",
    start_line: int | None = None,
    end_line: int | None = None,
    start_column: int | None = None,
    end_column: int | None = None,
    snippet: str = "",
    properties: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return one SARIF result. Without ``file`` the result has no location (repository)."""
    result: dict[str, Any] = {"ruleId": rule_id, "level": level, "message": {"text": message}}
    if file:
        location: dict[str, Any] = {"artifactLocation": {"uri": file}}
        if start_line is not None and start_line >= 1:
            region: dict[str, Any] = {"startLine": start_line}
            region["endLine"] = (
                end_line if end_line is not None and end_line >= start_line else (start_line)
            )
            if start_column is not None and start_column >= 1:
                region["startColumn"] = start_column
                if end_column is not None and end_column > start_column:
                    region["endColumn"] = end_column
            if snippet:
                region["snippet"] = {"text": snippet}
            location["region"] = region
        result["locations"] = [{"physicalLocation": location}]
    if properties:
        result["properties"] = properties
    return result


def sarif_document(
    tool: str,
    version: str,
    information_uri: str,
    rules: list[dict[str, Any]],
    results: list[dict[str, Any]],
    *,
    properties: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return a SARIF 2.1.0 document with one run."""
    driver: dict[str, Any] = {"name": tool, "informationUri": information_uri, "rules": rules}
    if version:
        driver["version"] = version
    run: dict[str, Any] = {"tool": {"driver": driver}, "results": results}
    if properties:
        run["properties"] = properties
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [run],
    }
