# SPDX-License-Identifier: MIT
"""Deployment scope of a finding: live deployment or template only (N.2).

A repository often holds several ways to deploy the same application: a ``docker-compose.yml``
for local development, Helm charts, Kubernetes manifests, Terraform. Only some of them run in
production, and kalkan cannot tell which from the source. The user names the live deployment
with ``run init --live <path>`` (or ``run set --live`` after the audit), and the report then
separates a production risk from a risk that exists only in an unused template.

Application code can be outside production too: a plugin that only one deployment loads, for
example a Docker Compose provisioner when production runs on Kubernetes. The user names such
code with ``run init --not-live <path>`` (or ``run set --not-live``).

The rule is conservative:

1. A finding with any file below a live path is ``live``. A live path wins over a not-live path.
2. A finding is ``template`` when every sink step of its trace is below a not-live path: the
   vulnerable operation runs only in code that production does not load.
3. A finding is ``template`` when every file of its trace and its evidence is not live: below a
   not-live path, or a deployment file while live paths are known.
4. Any other finding has no scope. A finding that touches application code is never
   ``template`` from rule 3.

The severity of the record does not change: the report marks the finding and leaves it out of
the overall risk.
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Final

from kalkan.util.paths import is_safe_relative_path

__all__ = [
    "MAX_LISTED_FILES",
    "SCOPE_LIVE",
    "SCOPE_TEMPLATE",
    "DeploymentScan",
    "DeploymentSet",
    "check_live_paths",
    "deployment_kind",
    "deployment_scope",
    "finding_files",
    "scan_deployments",
    "sink_files",
]

SCOPE_LIVE: Final = "live"
SCOPE_TEMPLATE: Final = "template"
#: Deployment files kept in the target manifest (the report classifies with this list).
MAX_LISTED_FILES: Final = 5000

_COMPOSE: Final = re.compile(r"^(?:docker-)?compose(?:[.-][\w.-]+)?\.ya?ml$", re.IGNORECASE)
_YAML: Final = re.compile(r"\.ya?ml$", re.IGNORECASE)
_K8S_HEAD: Final = re.compile(r"^apiVersion:\s*\S", re.MULTILINE)
_K8S_KIND: Final = re.compile(r"^kind:\s*\S", re.MULTILINE)
_SKIP_DIRS: Final = frozenset({".git", "node_modules", "vendor", ".venv", "venv", "__pycache__"})
_MAX_SCAN_FILES: Final = 50000
_MAX_PROBE_BYTES: Final = 64 * 1024


@dataclass(frozen=True)
class DeploymentSet:
    """One deployment description of the target: its kind, its folder or file, its files."""

    kind: str
    path: str
    files: int


@dataclass(frozen=True)
class DeploymentScan:
    """The deployment sets of a target and the files behind them."""

    sets: tuple[DeploymentSet, ...]
    files: tuple[str, ...]
    truncated: bool


def _parts(path: str) -> tuple[str, ...]:
    return PurePosixPath(path.replace("\\", "/")).parts


def deployment_kind(path: str, head: str | None = None) -> str | None:
    """Return the deployment kind of a target-relative file from its name, or None.

    ``compose`` (``docker-compose*.yml``, ``compose*.yaml``), ``kustomize``
    (``kustomization.yaml``), ``terraform`` (``*.tf``, ``*.tfvars``), ``bicep``, ``helm`` (a
    YAML or template file below a folder named ``charts`` or ``helm``, or ``Chart.yaml``) and
    ``kubernetes`` (a YAML file whose start ``head`` has a top-level ``apiVersion`` and
    ``kind``). A Dockerfile is not a deployment alternative: its image usually runs in every
    deployment.
    """
    parts = _parts(path)
    if not parts:
        return None
    name = parts[-1]
    lower = name.lower()
    if _COMPOSE.match(name):
        return "compose"
    if lower in ("kustomization.yaml", "kustomization.yml"):
        return "kustomize"
    if lower.endswith((".tf", ".tfvars")):
        return "terraform"
    if lower.endswith(".bicep"):
        return "bicep"
    if _YAML.search(lower) or lower.endswith(".tpl"):
        folders = {part.lower() for part in parts[:-1]}
        if lower == "chart.yaml" or folders & {"charts", "helm"}:
            return "helm"
        if head is not None and _K8S_HEAD.search(head) and _K8S_KIND.search(head):
            return "kubernetes"
    return None


def _head(target_dir: Path, path: str) -> str | None:
    try:
        with open(target_dir / path, "rb") as handle:
            return handle.read(_MAX_PROBE_BYTES).decode("utf-8", errors="replace")
    except OSError:
        return None


def _chart_root(target_dir: Path, path: str) -> str | None:
    """Return the folder of the nearest ``Chart.yaml`` above ``path``, or None."""
    parts = _parts(path)
    for depth in range(len(parts) - 1, 0, -1):
        folder = "/".join(parts[:depth])
        if (target_dir / folder / "Chart.yaml").is_file():
            return folder
    return None


def _classify(target_dir: Path, path: str) -> tuple[str, str] | None:
    """Return ``(kind, set root)`` of a deployment file of the target copy, or None."""
    name = _parts(path)[-1]
    is_text = bool(_YAML.search(name)) or name.lower().endswith(".tpl")
    chart = _chart_root(target_dir, path) if is_text else None
    if chart is not None:
        return "helm", chart
    kind = deployment_kind(path)
    if kind is None and _YAML.search(name):
        kind = deployment_kind(path, _head(target_dir, path))
    if kind is None:
        return None
    if kind == "compose":
        return kind, path
    return kind, "/".join(_parts(path)[:-1]) or "."


def scan_deployments(target_dir: Path) -> DeploymentScan:
    """Walk the target copy and return its deployment sets and files.

    The walk skips VCS, dependency and virtual environment folders, never follows a link and
    stops after a fixed number of files (``truncated``).
    """
    counts: dict[tuple[str, str], int] = {}
    files: list[str] = []
    seen, truncated = 0, False
    for root, dirs, names in os.walk(target_dir, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS)
        for name in sorted(names):
            seen += 1
            if seen > _MAX_SCAN_FILES:
                truncated = True
                break
            path = Path(root, name).relative_to(target_dir).as_posix()
            found = _classify(target_dir, path)
            if found is None:
                continue
            counts[found] = counts.get(found, 0) + 1
            if len(files) < MAX_LISTED_FILES:
                files.append(path)
            else:
                truncated = True
        if truncated and seen > _MAX_SCAN_FILES:
            break
    sets = tuple(DeploymentSet(kind, path, n) for (kind, path), n in sorted(counts.items()))
    return DeploymentScan(sets, tuple(files), truncated)


def finding_files(finding: Mapping[str, Any]) -> list[str]:
    """Return the distinct files of a finding's trace and evidence, in order."""
    files: list[str] = []
    for key in ("trace", "evidence"):
        items = finding.get(key)
        for item in items if isinstance(items, list) else []:
            file = item.get("file") if isinstance(item, Mapping) else None
            if isinstance(file, str) and file and file not in files:
                files.append(file)
    return files


def _below(path: str, root: str) -> bool:
    path_parts, root_parts = _parts(path), _parts(root)
    if root_parts in ((), (".",)):
        return True
    return path_parts[: len(root_parts)] == root_parts


def sink_files(finding: Mapping[str, Any]) -> list[str]:
    """Return the distinct files of the sink steps of a finding's trace, in order."""
    files: list[str] = []
    trace = finding.get("trace")
    for step in trace if isinstance(trace, list) else []:
        if not isinstance(step, Mapping) or step.get("kind") != "sink":
            continue
        file = step.get("file")
        if isinstance(file, str) and file and file not in files:
            files.append(file)
    return files


def deployment_scope(
    finding: Mapping[str, Any],
    live_paths: Sequence[str],
    is_deployment: Callable[[str], bool],
    not_live_paths: Sequence[str] = (),
) -> str | None:
    """Return ``live``, ``template`` or None for a finding (module docstring).

    ``is_deployment`` decides whether a target-relative file is a deployment file. None means:
    no live or not-live path is known, the finding has no file, or it touches live code.
    """
    if not live_paths and not not_live_paths:
        return None
    files = finding_files(finding)
    if not files:
        return None
    if any(_below(file, root) for file in files for root in live_paths):
        return SCOPE_LIVE

    def declared(file: str) -> bool:
        return any(_below(file, root) for root in not_live_paths)

    sinks = sink_files(finding)
    if sinks and all(declared(file) for file in sinks):
        return SCOPE_TEMPLATE
    if all(declared(file) or (bool(live_paths) and is_deployment(file)) for file in files):
        return SCOPE_TEMPLATE
    return None


def check_live_paths(
    paths: Iterable[str], target_dir: Path | None = None, *, option: str = "--live"
) -> list[str]:
    """Return the paths in posix form; raise ValueError for an unsafe or missing path.

    ``option`` names the command-line option in the error text (``--live``, ``--not-live``).
    """
    checked: list[str] = []
    for raw in paths:
        path = str(raw).strip().replace("\\", "/").rstrip("/")
        if not path or not is_safe_relative_path(path):
            raise ValueError(f"{option} needs a path inside the target, got {raw!r}")
        if target_dir is not None and not (target_dir / path).exists():
            raise ValueError(f"{option} {path}: no such file or folder in the target")
        if path not in checked:
            checked.append(path)
    return checked
