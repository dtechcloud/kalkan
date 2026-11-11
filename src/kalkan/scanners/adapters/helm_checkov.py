# SPDX-License-Identifier: MIT
"""helm-checkov: Checkov on the Helm charts of the target, rendered offline (ENGINE-SPEC 13,
ADR-0005 K.3).

Checkov's own ``helm`` framework is off in the ``checkov`` adapter: it starts ``helm template
--dependency-update``, which downloads chart dependencies and writes them into the ``charts/``
folder of the chart. This adapter renders every chart itself with the pinned ``helm`` binary,
without any download, and runs Checkov's ``kubernetes`` framework on the rendered manifests.

Why a separate adapter and not an extension of ``checkov``: it needs a second tool (``helm``)
and is skipped on its own when that tool or a chart is missing; a chart that does not render,
or a timeout, does not mark the main Checkov results as failed; it has its own status keys
(rendered charts, chart gaps, location mapping) and its own time limit; and its locations are
mapped back from rendered files to templates, so the engine name tells the reader that the line
is a best-effort mapping.

Contract:

1. **Applies** when the target has a ``Chart.yaml`` (:func:`charts`: regular files, without the
   vendored folders of :mod:`kalkan.scanners.adapters._sources` and without the subcharts in
   the ``charts/`` folder of another chart, which render as part of their parent; at most
   :data:`MAX_CHARTS`) and both ``helm`` and ``checkov`` are installed (:data:`checkov_resolver`
   finds Checkov; the run resolves ``helm``).
2. **Render** (one setup run per chart, checked against ``helm template --help`` of the pinned
   4.3.0 on 2026-10-25), working directory ``scans/.work/helm-checkov``::

       helm template kalkan <absolute chart folder> --output-dir <work>/helm/<NNN>
           --skip-schema-validation

   - Offline: never ``dependency update`` or ``build``, never ``--dependency-update``,
     ``--repo``, ``--verify`` or a chart reference; the chart is an absolute folder path (a
     relative one that is not found is read as a repository reference). A chart whose
     dependencies are not in its ``charts/`` folder fails with ``missing in charts/
     directory``; the status file records it as a scan gap, no chart is downloaded.
   - ``--skip-schema-validation``: Helm 4.3.0 loads the ``$ref`` documents of a
     ``values.schema.json``, also from remote URLs (the proxy trap saw ``CONNECT`` to the
     schema host). The values are not checked against the schema; rendering does not need it.
   - Values: the ``values.yaml`` of the chart only (no ``-f`` file, no ``--set``): a target can
     hold many values files for many environments, and the defaults are what ``helm install``
     of the folder deploys. ``--enable-dns`` stays off (no ``getHostByName`` lookups);
     ``--dry-run`` is ``client`` (no cluster). The release name is ``kalkan``, the namespace
     ``default``.
   - Environment: ``HELM_CACHE_HOME``, ``HELM_CONFIG_HOME`` and ``HELM_DATA_HOME`` name folders
     in the work folder (no repository list, registry login or plugin of the user is read),
     ``HOME`` and ``USERPROFILE`` an empty folder, ``KUBECONFIG`` a file that does not exist; the
     minimal tool environment holds no other ``HELM_*`` or cloud variable.
   - Exit code 1 (an error such as missing dependencies or a template error) is a scan gap of
     that chart, not a failed run; :meth:`HelmCheckovAdapter.status_details` takes the reason
     from the ``Error:`` line of the chart's section of the stderr log.
3. **Scan** (one run), working directory ``<work>/helm`` (Checkov writes URIs relative to it)::

       <tool venv python> -I -X utf8 -c <checkov.LAUNCHER> -d . -o sarif
           --output-file-path <work>/results --framework kubernetes --skip-download --quiet
           --compact

   ``-d .`` (the working directory is the scan root): the Kubernetes framework of Checkov drops
   every file whose full path contains ``/.``. An absolute root under a hidden folder (the
   plugin data folder ``~/.claude/...``, the work folder ``scans/.work``) would hide every
   Kubernetes result on Linux and macOS. A relative root keeps the URIs unchanged.

   The launcher, the empty home folder and ``CKV_SKIP_PACKAGE_UPDATE_CHECK=true`` are those of
   the ``checkov`` adapter (no config discovery, no platform key, no version check). Exit codes
   0 and 1.
4. **Locations** (:func:`map_result`, best effort): Checkov reports a rendered file
   (``<NNN>/<chart name>/templates/x.yaml``) and the line range of the whole resource. The
   ``# Source: <chart name>/templates/x.yaml`` comment of the rendered document names the
   template; the adapter replaces the chart name with the chart folder of the target. The
   k-th rendered document of a template maps to the k-th template document (``---``), and the
   range shrinks to its first and last content lines (no blank, comment or ``{{ ... }}``-only
   line). For the checks of :data:`RULE_KEYS` (a boolean key such as ``privileged``), the region
   is the single template line that sets the key, when the document has exactly one
   (``mapping``: ``template-key``; else ``template-document``). A template of a packaged
   dependency (``charts/<name>.tgz``) is not in the target: the result points to the
   ``Chart.yaml`` of the chart (``mapping``: ``chart``). Each result keeps the rendered source
   and lines (``rendered_source``, ``rendered_lines``), and the snippet is the template line.
5. **Suppressions** (ADR-0003): as for ``checkov`` (config discovery off in every mode;
   ``checkov.io/skip`` annotations of the templates give suppressed results, kept and tagged by
   default). The ``.helmignore`` of a chart stays effective: it decides which files belong to
   the chart, as for a real install, so an ignored template is never deployed either.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from pathlib import Path, PurePosixPath
from typing import Any, Final

from kalkan.errors import KalkanError, ToolError
from kalkan.scanners.adapters import _sources
from kalkan.scanners.adapters.checkov import LAUNCHER, RESULT_NAME, launcher_python
from kalkan.scanners.base import PYTHON_TOOL_ENV, Invocation, ScanContext, ToolAdapter, work_dir
from kalkan.util.safe_io import atomic_write_json, read_bounded

__all__ = [
    "MAX_CHARTS",
    "RELEASE_NAME",
    "RULE_KEYS",
    "HelmCheckovAdapter",
    "chart_gap",
    "charts",
    "checkov_resolver",
    "map_result",
    "rewrite_sarif",
    "split_documents",
]

CHART_FILE: Final = "Chart.yaml"
RELEASE_NAME: Final = "kalkan"
#: The most charts that one run renders; the others are recorded as skipped.
MAX_CHARTS: Final = 200
RENDER_DIRNAME: Final = "helm"
HOME_DIRNAME: Final = "home"
HELM_HOME_DIRNAME: Final = "helm-home"
RESULTS_DIRNAME: Final = "results"
MAX_RENDERED_BYTES: Final = 5 * 1024 * 1024
MAX_SARIF_BYTES: Final = 50 * 1024 * 1024
#: Checkov checks of one boolean key: the region becomes the template line that sets it.
RULE_KEYS: Final[dict[str, str]] = {
    "CKV_K8S_16": "privileged",
    "CKV_K8S_17": "hostPID",
    "CKV_K8S_18": "hostIPC",
    "CKV_K8S_19": "hostNetwork",
    "CKV_K8S_20": "allowPrivilegeEscalation",
}
GAP_DEPENDENCIES: Final = (
    "chart dependencies missing from charts/ (local mode downloads no chart; vendor them with "
    "helm dependency build before the audit)"
)
GAP_ERROR: Final = "helm template failed with the default values of the chart"
GAP_EMPTY: Final = "the chart rendered no manifest with its default values"
GAP_LIMIT: Final = f"more than {MAX_CHARTS} charts in the target"

_SEPARATOR = re.compile(r"^---(?:\s|$)")
_SOURCE = re.compile(r"^#\s*Source:\s*(\S.*?)\s*$")
_ACTION_ONLY = re.compile(r"^\s*\{\{.*\}\}\s*$")
_HEADER = re.compile(r"^== kalkan: run (\d+)/(\d+)(?: \((.*)\))? ==$")
_MISSING_DEPS = re.compile(r"missing in charts/ directory:\s*(.+)$")
_PART = re.compile(r"^[0-9]{3}$")


def _resolve_checkov(*, allow_path: bool = False) -> Any:
    from kalkan.tools.resolve import resolve  # lazy: small import graph

    return resolve("checkov", allow_path=allow_path)


#: Finds Checkov: ``checkov_resolver(allow_path=...) -> ResolvedTool | None`` (tests replace it).
checkov_resolver: Callable[..., Any] = _resolve_checkov


def charts(target: Path) -> list[str]:
    """Return the target-relative folders of the Helm charts (``""`` for the root), sorted.

    A chart in the ``charts/`` folder of another chart is a dependency of that chart: Helm
    renders it with its parent, so it is not listed on its own.
    """
    files = _sources.source_files(target, lambda rel: PurePosixPath(rel).name == CHART_FILE)
    folders = {PurePosixPath(rel).parent.as_posix() for rel in files}
    folders = {"" if folder == "." else folder for folder in folders}
    found = []
    for folder in sorted(folders):
        path = PurePosixPath(folder)
        parent = path.parent.as_posix() if path.parent.name == "charts" else None
        if parent is not None:
            owner = PurePosixPath(parent).parent.as_posix()
            if ("" if owner == "." else owner) in folders:
                continue
        found.append(folder)
    return found


def _chart_file(folder: str) -> str:
    return f"{folder}/{CHART_FILE}" if folder else CHART_FILE


def split_documents(lines: list[str]) -> list[tuple[int, int]]:
    """Return the 1-based line ranges ``(first, last)`` of the YAML documents of ``lines``.

    A line ``---`` (optionally followed by a space and more text) separates documents; it is
    part of no range. Empty documents are kept, so the index of a document is stable.
    """
    ranges: list[tuple[int, int]] = []
    start = 1
    for number, line in enumerate(lines, start=1):
        if _SEPARATOR.match(line):
            if number > start:
                ranges.append((start, number - 1))
            start = number + 1
    if start <= len(lines):
        ranges.append((start, len(lines)))
    return ranges


def _is_content(line: str) -> bool:
    text = line.strip()
    return bool(text) and not text.startswith("#") and not _ACTION_ONLY.match(line)


def _content_range(lines: list[str], first: int, last: int) -> tuple[int, int] | None:
    numbers = [n for n in range(first, last + 1) if _is_content(lines[n - 1])]
    return (numbers[0], numbers[-1]) if numbers else None


def _rendered_document(lines: list[str], line: int) -> tuple[str, int] | None:
    """Return the ``# Source:`` of the rendered document that holds ``line`` and the index of
    that document among the documents of the same source."""
    ranges = split_documents(lines)
    sources: list[str] = []
    for first, last in ranges:
        source = ""
        for number in range(first, last + 1):
            match = _SOURCE.match(lines[number - 1].strip())
            if match:
                source = match.group(1).replace("\\", "/")
                break
            if lines[number - 1].strip():
                break
        sources.append(source)
    for index, (first, last) in enumerate(ranges):
        if first <= line <= last or (index == len(ranges) - 1 and line > last):
            source = sources[index]
            if not source:
                return None
            return source, sum(1 for other in sources[:index] if other == source)
    return None


def _template_path(chart: str, source: str) -> str | None:
    """Return the target-relative template of a ``# Source:`` path, or None when it is not a
    safe path inside the chart."""
    parts = PurePosixPath(source).parts
    if len(parts) < 2 or any(part in ("", ".", "..") for part in parts):
        return None
    rest = PurePosixPath(*parts[1:]).as_posix()
    return f"{chart}/{rest}" if chart else rest


def map_result(
    *,
    chart: str,
    rendered: list[str],
    start: int,
    end: int,
    rule_id: str,
    read_target: Callable[[str], list[str] | None],
    fallback_source: str = "",
) -> dict[str, Any]:
    """Map one Checkov result of a rendered file to the target (module docstring, point 4).

    ``rendered`` holds the lines of the rendered file, ``start``/``end`` the rendered region.
    ``read_target(rel)`` returns the lines of a target file or None. The answer has ``file``,
    ``start``, ``end``, ``snippet``, ``mapping`` and ``rendered_source``.
    """
    found = _rendered_document(rendered, start)
    source, index = found if found is not None else (fallback_source, 0)
    template = _template_path(chart, source) if source else None
    lines = read_target(template) if template else None
    if template is None or lines is None:
        chart_file = _chart_file(chart)
        chart_lines = read_target(chart_file) or [""]
        return {
            "file": chart_file,
            "start": 1,
            "end": 1,
            "snippet": chart_lines[0].rstrip("\r"),
            "mapping": "chart",
            "rendered_source": source,
        }
    documents = [
        found_range
        for first, last in split_documents(lines)
        if (found_range := _content_range(lines, first, last)) is not None
    ]
    if documents:
        first, last = documents[min(index, len(documents) - 1)]
    else:
        first, last = 1, max(1, len(lines))
    mapping = "template-document"
    key = RULE_KEYS.get(rule_id)
    if key:
        pattern = re.compile(rf"^\s*(?:-\s+)?[\"']?{re.escape(key)}[\"']?\s*:")
        hits = [n for n in range(first, last + 1) if pattern.match(lines[n - 1])]
        if len(hits) == 1:
            first = last = hits[0]
            mapping = "template-key"
    snippet = lines[first - 1].rstrip("\r") if 0 < first <= len(lines) else ""
    return {
        "file": template,
        "start": first,
        "end": last,
        "snippet": snippet,
        "mapping": mapping,
        "rendered_source": source,
    }


def rewrite_sarif(
    doc: Any,
    *,
    render_root: Path,
    chart_folders: list[str],
    read_target: Callable[[str], list[str] | None],
) -> tuple[dict[str, Any], dict[str, int]]:
    """Rewrite the Checkov SARIF of the rendered charts to target locations (point 4).

    Returns the document and the count of results per ``mapping`` (``dropped``: a result
    without a rendered file of a known chart). Raises :class:`~kalkan.errors.ToolError` when
    ``doc`` is not a SARIF 2.1.0 document.
    """
    if not isinstance(doc, dict) or doc.get("version") != "2.1.0":
        raise ToolError("Checkov did not write a SARIF 2.1.0 document")
    counts: dict[str, int] = {}
    cache: dict[str, list[str] | None] = {}

    def rendered_lines(rel: str) -> list[str] | None:
        if rel not in cache:
            path = render_root / rel
            try:
                data = read_bounded(path, MAX_RENDERED_BYTES)
                cache[rel] = data.decode("utf-8", errors="replace").split("\n")
            except (KalkanError, OSError):
                cache[rel] = None
        return cache[rel]

    for run in doc.get("runs") or []:
        if not isinstance(run, dict):
            continue
        run.pop("artifacts", None)
        run.pop("originalUriBaseIds", None)
        kept = []
        for result in run.get("results") or []:
            mapped = _rewrite_result(result, chart_folders, rendered_lines, read_target)
            counts[mapped] = counts.get(mapped, 0) + 1
            if mapped != "dropped":
                kept.append(result)
        run["results"] = kept
    return doc, counts


def _rewrite_result(
    result: Any,
    chart_folders: list[str],
    rendered_lines: Callable[[str], list[str] | None],
    read_target: Callable[[str], list[str] | None],
) -> str:
    if not isinstance(result, dict):
        return "dropped"
    locations = result.get("locations")
    physical = (
        locations[0].get("physicalLocation")
        if isinstance(locations, list) and locations and isinstance(locations[0], dict)
        else None
    )
    if not isinstance(physical, dict):
        return "dropped"
    artifact = physical.get("artifactLocation") or {}
    uri = str(artifact.get("uri") or "").replace("\\", "/").removeprefix("./")
    parts = PurePosixPath(uri).parts
    if len(parts) < 2 or not _PART.match(parts[0]) or int(parts[0]) >= len(chart_folders):
        return "dropped"
    chart = chart_folders[int(parts[0])]
    rendered = rendered_lines(uri)
    if rendered is None:
        return "dropped"
    region = physical.get("region") if isinstance(physical.get("region"), dict) else {}
    start = region.get("startLine") if isinstance(region.get("startLine"), int) else 1
    end = region.get("endLine") if isinstance(region.get("endLine"), int) else start
    mapped = map_result(
        chart=chart,
        rendered=rendered,
        start=max(1, start),
        end=max(start, end),
        rule_id=str(result.get("ruleId") or ""),
        read_target=read_target,
        fallback_source=PurePosixPath(*parts[1:]).as_posix(),
    )
    new_region: dict[str, Any] = {"startLine": mapped["start"], "endLine": mapped["end"]}
    if mapped["snippet"].strip():
        new_region["snippet"] = {"text": mapped["snippet"]}
    result["locations"] = [
        {"physicalLocation": {"artifactLocation": {"uri": mapped["file"]}, "region": new_region}}
    ]
    properties = result.setdefault("properties", {})
    if isinstance(properties, dict):
        properties["helm_chart"] = chart or "."
        properties["rendered_source"] = mapped["rendered_source"]
        properties["rendered_lines"] = [start, end]
        properties["mapping"] = mapped["mapping"]
    message = result.get("message")
    if isinstance(message, dict) and isinstance(message.get("text"), str):
        where = mapped["rendered_source"] or "the chart"
        message["text"] += f" (rendered by helm template from {where} with the default values)"
    return str(mapped["mapping"])


def chart_gap(section: str) -> tuple[str, str]:
    """Return the gap reason and detail of a chart that rendered nothing, from its section of
    the stderr log."""
    errors = [line.strip() for line in section.splitlines() if line.strip().startswith("Error:")]
    detail = errors[-1] if errors else ""
    match = _MISSING_DEPS.search(detail)
    if match:
        return GAP_DEPENDENCIES, f"missing in charts/: {match.group(1).strip()}"
    if detail:
        return GAP_ERROR, detail[:500]
    return GAP_EMPTY, ""


def _log_sections(path: Path) -> dict[str, str]:
    """Return the text of each labeled run section of a log file (label to text)."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}
    sections: dict[str, str] = {}
    label = None
    chunk: list[str] = []
    for line in text.splitlines():
        match = _HEADER.match(line.strip())
        if match:
            if label is not None:
                sections[label] = "\n".join(chunk)
            label, chunk = match.group(3) or match.group(1), []
            continue
        chunk.append(line)
    if label is not None:
        sections[label] = "\n".join(chunk)
    return sections


class HelmCheckovAdapter(ToolAdapter):
    """``helm template`` per chart, then Checkov on the rendered manifests (module docstring)."""

    name = "helm-checkov"
    tool = "helm"
    output = "sarif-file"
    output_dir = "scans"
    output_name = "helm-checkov.sarif"
    #: helm: 1 is an error of one chart (a scan gap). Checkov: 1 means failed checks.
    ok_exit_codes = (0, 1)
    timeout_seconds = 1200

    def __init__(self) -> None:
        self._charts: list[str] = []
        self._extra_charts: list[str] = []
        self._checkov: Any = None
        self._launcher_used: bool | None = None
        self._rendered: dict[int, int] = {}
        self._mapping: dict[str, int] = {}

    # --- discovery -------------------------------------------------------------------------

    def applies(self, ctx: ScanContext) -> tuple[bool, str]:
        if not charts(ctx.target_dir):
            return False, "no Helm chart (Chart.yaml) in the target"
        self._checkov = checkov_resolver(allow_path=ctx.allow_path_tools)
        if self._checkov is None:
            return False, (
                "tool not found: checkov is not installed (run: kalkan tools install checkov)"
            )
        return True, ""

    # --- folders ---------------------------------------------------------------------------

    @staticmethod
    def render_root(ctx: ScanContext) -> Path:
        """Return ``<work>/helm``, the parent of the rendered chart folders ``<NNN>``."""
        return work_dir(ctx.run_dir, HelmCheckovAdapter) / RENDER_DIRNAME

    def home_dir(self, ctx: ScanContext) -> Path:
        """Return the empty home folder of helm and Checkov."""
        return work_dir(ctx.run_dir, self) / HOME_DIRNAME

    def helm_home(self, ctx: ScanContext, kind: str) -> Path:
        """Return the ``cache``, ``config`` or ``data`` folder of helm in the work folder."""
        return work_dir(ctx.run_dir, self) / HELM_HOME_DIRNAME / kind

    def results_dir(self, ctx: ScanContext) -> Path:
        """Return the ``--output-file-path`` folder of Checkov."""
        return work_dir(ctx.run_dir, self) / RESULTS_DIRNAME

    def prepare(self, ctx: ScanContext, stage: Path) -> None:
        """Create the home, helm and render folders in the work folder."""
        for folder in (
            self.home_dir(ctx),
            self.helm_home(ctx, "cache"),
            self.helm_home(ctx, "config"),
            self.helm_home(ctx, "data"),
            self.render_root(ctx),
        ):
            folder.mkdir(parents=True, exist_ok=True)

    def env(self, ctx: ScanContext) -> dict[str, str]:
        home = str(self.home_dir(ctx))
        return {
            **PYTHON_TOOL_ENV,
            "CKV_SKIP_PACKAGE_UPDATE_CHECK": "true",
            "HOME": home,
            "USERPROFILE": home,
            "HELM_CACHE_HOME": str(self.helm_home(ctx, "cache")),
            "HELM_CONFIG_HOME": str(self.helm_home(ctx, "config")),
            "HELM_DATA_HOME": str(self.helm_home(ctx, "data")),
            "KUBECONFIG": str(self.home_dir(ctx) / "kubeconfig-none"),
        }

    def cwd(self, ctx: ScanContext) -> Path:
        return work_dir(ctx.run_dir, self)

    # --- command lines ---------------------------------------------------------------------

    @staticmethod
    def helm_arguments(chart_dir: Path, out_dir: Path) -> list[str]:
        """Return the ``helm template`` arguments of one chart (module docstring, point 2)."""
        return [
            "template",
            RELEASE_NAME,
            str(chart_dir),
            "--output-dir",
            str(out_dir),
            "--skip-schema-validation",
        ]

    def checkov_arguments(self, ctx: ScanContext) -> list[str]:
        """Return the Checkov arguments (module docstring, point 3)."""
        return [
            "-d",
            ".",
            "-o",
            "sarif",
            "--output-file-path",
            str(self.results_dir(ctx)),
            "--framework",
            "kubernetes",
            "--skip-download",
            "--quiet",
            "--compact",
        ]

    def checkov_command(self, ctx: ScanContext) -> list[str]:
        """Return the Checkov command line through the launcher of the ``checkov`` adapter."""
        checkov = self._checkov or checkov_resolver(allow_path=ctx.allow_path_tools)
        if checkov is None:
            raise ToolError("checkov is not installed (run: kalkan tools install checkov)")
        self._checkov = checkov
        python = launcher_python(Path(checkov.path))
        self._launcher_used = python is not None
        if python is None:
            return [*(str(arg) for arg in checkov.argv), *self.checkov_arguments(ctx)]
        return [str(python), "-I", "-X", "utf8", "-c", LAUNCHER, *self.checkov_arguments(ctx)]

    def command(self, ctx: ScanContext, tool_path: Path, out: Path) -> list[str]:
        folders = charts(ctx.target_dir)
        if not folders:
            return [str(tool_path), "version"]
        return [str(tool_path), *self.helm_arguments(ctx.target_dir / folders[0], out.parent)]

    def invocations(self, ctx: ScanContext, tool_path: Path, out: Path) -> list[Invocation]:
        found = charts(ctx.target_dir)
        self._charts, self._extra_charts = found[:MAX_CHARTS], found[MAX_CHARTS:]
        self._rendered = {}
        self._mapping = {}
        root = self.render_root(ctx)
        items: list[Invocation] = []
        for index, folder in enumerate(self._charts):
            chart_dir = (ctx.target_dir / folder) if folder else ctx.target_dir
            out_dir = root / f"{index:03d}"
            argv = (str(tool_path), *self.helm_arguments(chart_dir, out_dir))
            items.append(
                Invocation(
                    argv,
                    self.cwd(ctx),
                    out_dir / ".rendered",
                    label=f"chart {folder or '.'}",
                    setup=True,
                )
            )
        items.append(
            Invocation(
                tuple(self.checkov_command(ctx)),
                root,
                self.results_dir(ctx) / RESULT_NAME,
                label="checkov",
            )
        )
        return items

    # --- results ---------------------------------------------------------------------------

    def after_run(self, ctx: ScanContext, item: Invocation) -> None:
        """Count the rendered files of a chart, or map the Checkov SARIF to the templates."""
        root = self.render_root(ctx)
        if item.setup:
            index = int(item.output.parent.name)
            folder = item.output.parent
            count = sum(1 for path in folder.rglob("*") if path.is_file()) if folder.is_dir() else 0
            self._rendered[index] = count
            return
        if not item.output.is_file():
            if not any(self._rendered.values()):
                atomic_write_json(item.output, _empty_sarif())
                return
            raise ToolError("Checkov wrote no SARIF for the rendered charts")
        try:
            doc = json.loads(read_bounded(item.output, MAX_SARIF_BYTES))
        except (KalkanError, ValueError) as exc:
            raise ToolError(f"the Checkov SARIF is not valid JSON: {exc}") from None
        doc, self._mapping = rewrite_sarif(
            doc,
            render_root=root,
            chart_folders=self._charts,
            read_target=lambda rel: _target_lines(ctx.target_dir, rel),
        )
        atomic_write_json(item.output, doc)

    def status_details(
        self, ctx: ScanContext, stdout_log: Path, stderr_log: Path, outputs: list[Path]
    ) -> dict[str, Any]:
        """Record the rendered charts, the chart gaps and the location mapping."""
        sections = _log_sections(stderr_log)
        gaps: list[dict[str, str]] = []
        rendered: list[str] = []
        for index, folder in enumerate(self._charts):
            if self._rendered.get(index):
                rendered.append(folder or ".")
                continue
            if index not in self._rendered:
                continue  # the run did not get to this chart (timeout)
            reason, detail = chart_gap(sections.get(f"chart {folder or '.'}", ""))
            gaps.append({"chart": _chart_file(folder), "reason": reason, "detail": detail})
        for folder in self._extra_charts:
            gaps.append({"chart": _chart_file(folder), "reason": GAP_LIMIT, "detail": ""})
        details: dict[str, Any] = {
            "charts": {
                "count": len(self._charts) + len(self._extra_charts),
                "rendered": rendered[:50],
                "rendered_count": len(rendered),
                "truncated": len(rendered) > 50,
            },
            "values": "the values.yaml of each chart only (no -f file, no --set)",
            "schema_validation": (
                "off (--skip-schema-validation: helm 4.3.0 fetches remote $ref documents of a "
                "values.schema.json)"
            ),
            "mapping": dict(sorted(self._mapping.items())),
        }
        if self._checkov is not None:
            details["checkov_version"] = str(getattr(self._checkov, "version", "") or "")
        if gaps:
            reasons: dict[str, int] = {}
            for gap in gaps:
                reasons[gap["reason"]] = reasons.get(gap["reason"], 0) + 1
            details["skipped_files"] = {
                "count": len(gaps),
                "reasons": reasons,
                "paths": [gap["chart"] for gap in gaps[:50]],
                "truncated": len(gaps) > 50,
            }
            details["chart_gaps"] = gaps[:50]
        return details

    def suppression_sources(self, ctx: ScanContext) -> tuple[list[str], list[str]]:
        config = (
            ".checkov.yaml/.checkov.yml config discovery (turned off in every mode: such a file "
            "can make Checkov run Python code)"
        )
        helmignore = (
            ".helmignore of each chart (it decides which files belong to the chart, as for a "
            "real install)"
        )
        if self._launcher_used is False:
            config = (
                ".checkov.yaml/.checkov.yml of the working folder: config discovery could not be "
                "turned off (Checkov does not run from the kalkan tool venv)"
            )
            return [], [config, helmignore]
        skips = "checkov.io/skip annotations of the templates"
        if ctx.honor_suppressions:
            return [config], [f"{skips} (Checkov skips the checks)", helmignore]
        return [config, f"{skips} (Checkov keeps them as suppressed SARIF results)"], [helmignore]


def _target_lines(target: Path, rel: str) -> list[str] | None:
    """Return the lines of a regular target file (no link), or None."""
    path = target / rel
    try:
        if path.is_symlink() or not path.is_file():
            return None
    except OSError:
        return None
    return _sources.read_lines(path)


def _empty_sarif() -> dict[str, Any]:
    driver = {"name": "Checkov", "informationUri": "https://checkov.io", "rules": []}
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": driver}, "results": []}],
    }
