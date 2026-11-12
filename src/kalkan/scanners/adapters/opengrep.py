# SPDX-License-Identifier: MIT
"""Opengrep scan with the kalkan rule pack ``<repo>/rules/opengrep`` (ENGINE-SPEC 13).

Command line, checked against ``opengrep scan --help`` of the pinned version 1.30.1::

    opengrep scan -f <repo>/rules/opengrep --sarif --output <run>/scans/opengrep.sarif
        --disable-version-check --no-rewrite-rule-ids --no-git-ignore
        --x-ignore-semgrepignore-files [--disable-nosem] <target>

Metrics: version 1.30.1 has no ``--metrics`` option and sends no metrics. Its only outbound
call is the version check, which ``--disable-version-check`` turns off.

Differences from section 13:

- ``--sarif --output <out>`` instead of ``--sarif-output=<out>``: the latter also prints the
  full text report to stdout.
- ``--no-rewrite-rule-ids``: without it Opengrep prefixes every rule ID with the rule folder
  path relative to the working directory (for example
  ``C.Users.<user>.Desktop....rules.opengrep.kalkan.python.sqli...``), so candidate IDs would
  change from machine to machine.
- ``--no-git-ignore``: a run folder lies inside the kalkan repository, where ``runs/`` is in
  ``.gitignore``. Without the flag Opengrep asks git and scans no file at all (tested).
- ``--x-ignore-semgrepignore-files``: without it the built-in ignore list skips folders such as
  ``tests/`` (tested), and a ``.semgrepignore`` of the target could hide files. The option is
  marked internal; it is checked for the pinned version only.

Suppressions (ADR-0003): ``--disable-nosem`` by default. Opengrep 1.30.1 keeps the results of
lines with a ``nosem``, ``nosemgrep`` or ``noopengrep`` comment in the SARIF as results with a
``suppressions`` entry, with or without the option (tested); :func:`run_adapter` keeps them
tagged by default and drops them with ``honor_suppressions``. ``.semgrepignore`` files are
ignored in both modes (``--x-ignore-semgrepignore-files``).

SARIF URIs are absolute Windows paths with backslashes on Windows; the ingest normalizes them
to target-relative POSIX paths (tested).

Files (:mod:`kalkan.tools.toolhome`, measured on Windows 11 on 2026-10-29): opengrep 1.30.1
unpacks its runtime (277 MB) below ``AppData/Local`` of ``USERPROFILE``, logs the target paths
and the code of the matches to ``.opengrep/semgrep.log`` there, and leaves its rule files and
its core input and output in the temporary folder. ``USERPROFILE`` and ``HOME`` therefore name
the kalkan folder ``<home>/.tools/cache/opengrep`` (the runtime is unpacked once per version),
``SEMGREP_LOG_FILE`` and ``XDG_CONFIG_HOME`` the work folder, and ``TEMP`` and ``TMP`` its
``tmp`` folder (:func:`kalkan.scanners.base.run_adapter`). The work folder holds the log after
a failed run; it goes with the run.

Coverage gaps (:meth:`OpengrepAdapter.status_details`, recorded in ``scans/opengrep.status.json``):

- ``partial_files``: Opengrep prints ``Partially scanned: <n> files only partially analyzed due
  to parsing or internal Opengrep errors`` in its stderr summary and writes one SARIF
  ``invocations[].toolExecutionNotifications`` entry per file (``Syntax error at line
  <path>:<line>:``). The count is the larger of the two; the paths (at most 50) come from the
  notifications.
- ``skipped_files``: the ``Scan skipped: <n> files <reason>, ...`` line of the summary. For a
  ``larger than <x> MB`` reason the paths are the target files above that size (Opengrep names
  them only with ``--verbose``). On Windows the files whose absolute path has 260 or more
  characters are added (:mod:`kalkan.util.winpath`): Opengrep counts them as scanned, but its
  core program skips them without any message.
- ``files_scanned``: the ``Ran <r> rules on <n> files`` count of the summary.
"""

from __future__ import annotations

import json
import os
import re
from collections import Counter
from collections.abc import Sequence
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from kalkan.errors import KalkanError
from kalkan.scanners.base import ScanContext, ToolAdapter, work_dir
from kalkan.tools import toolhome
from kalkan.util.paths import is_safe_relative_path
from kalkan.util.safe_io import read_bounded
from kalkan.util.winpath import WINDOWS_PATH_LIMIT, find_long_paths

#: ``partial_files`` and ``skipped_files`` list at most this many paths.
MAX_LISTED_PATHS = 50
#: The skip reason of the files that the Windows path limit hides (not reported by Opengrep).
LONG_PATH_REASON = (
    f"files with an absolute path of {WINDOWS_PATH_LIMIT} or more characters "
    "(not reported by Opengrep)"
)
_SUMMARY_TAIL_BYTES = 64 * 1024
_SARIF_MAX_BYTES = 50 * 1024 * 1024
_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_PARTIAL = re.compile(r"Partially scanned:\s*(\d+)\s+files?\b")
_SKIPPED = re.compile(r"Scan skipped:\s*(.+)")
_SKIP_ITEM = re.compile(r"(\d+)\s+files?\s+(.+)")
_RAN = re.compile(r"Ran\s+(\d+)\s+rules?\s+on\s+(\d+)\s+files?")
_LARGER = re.compile(r"larger than\s+([0-9]+(?:\.[0-9]+)?)\s*MB", re.IGNORECASE)
_NOTE_PATH = re.compile(r"\bat line (.+?):\d+:")
_DRIVE = re.compile(r"/?[A-Za-z]:/")


def default_rules_dir() -> Path:
    """Return the ``rules/opengrep`` folder (:func:`kalkan.resources.rules_dir`)."""
    from kalkan.resources import rules_dir

    return rules_dir("opengrep")


def default_home() -> Path:
    """Return ``<home>/.tools/cache/opengrep`` of the kalkan home (:mod:`kalkan.tools.toolhome`)."""
    from kalkan.resources import home

    return toolhome.opengrep_home(home())


class OpengrepAdapter(ToolAdapter):
    """``opengrep scan`` with the kalkan rule pack."""

    name = "opengrep"
    tool = "opengrep"
    output = "sarif-file"
    output_dir = "scans"
    output_name = "opengrep.sarif"
    ok_exit_codes = (0,)
    timeout_seconds = 1800

    def __init__(self, rules_dir: Path | None = None, *, home: Path | None = None) -> None:
        self._rules_dir = rules_dir
        self._home = home

    def rules_dir(self) -> Path:
        """Return the rule pack folder."""
        return self._rules_dir if self._rules_dir is not None else default_rules_dir()

    def home(self) -> Path:
        """Return the profile folder of the opengrep process (module docstring, "Files")."""
        return self._home if self._home is not None else default_home()

    def prepare(self, ctx: ScanContext, stage: Path) -> None:
        """Create the profile folder (opengrep unpacks its runtime below ``AppData/Local``)."""
        toolhome.prepare_home(self.home())

    def env(self, ctx: ScanContext) -> dict[str, str]:
        return toolhome.opengrep_env(self.home(), work_dir(ctx.run_dir, self))

    def applies(self, ctx: ScanContext) -> tuple[bool, str]:
        folder = self.rules_dir()
        if not folder.is_dir():
            return False, f"rule pack not found: {folder.as_posix()}"
        if not any(folder.glob("*.yaml")) and not any(folder.glob("*.yml")):
            return False, f"the rule pack {folder.as_posix()} has no YAML rule files"
        return True, ""

    def arguments(self, ctx: ScanContext, out: Path) -> list[str]:
        return [
            "scan",
            "-f",
            str(self.rules_dir()),
            "--sarif",
            "--output",
            str(out),
            "--disable-version-check",
            "--no-rewrite-rule-ids",
            "--no-git-ignore",
            "--x-ignore-semgrepignore-files",
            *([] if ctx.honor_suppressions else ["--disable-nosem"]),
            str(ctx.target_dir),
        ]

    def suppression_sources(self, ctx: ScanContext) -> tuple[list[str], list[str]]:
        ignore_files = (
            ".semgrepignore files of the target (--x-ignore-semgrepignore-files, in every mode: "
            "the option also turns off the built-in list that skips tests/ folders)"
        )
        comments = "nosem, nosemgrep and noopengrep comments"
        if ctx.honor_suppressions:
            return [ignore_files], [comments]
        return [f"{comments} (--disable-nosem)", ignore_files], []

    def status_details(
        self, ctx: ScanContext, stdout_log: Path, stderr_log: Path, outputs: Sequence[Path]
    ) -> dict[str, Any]:
        """Return ``files_scanned``, ``partial_files`` and ``skipped_files`` (module docstring)."""
        summary = parse_summary(_tail(stderr_log))
        kinds: Counter[str] = Counter()
        partial: list[str] = []
        for output in outputs:
            more_kinds, more_paths = notification_paths(_sarif(output), ctx.target_dir)
            kinds.update(more_kinds)
            partial += [path for path in more_paths if path not in partial]
        reasons: dict[str, int] = dict(summary["skipped"])
        skipped: list[str] = []
        for reason in reasons:
            match = _LARGER.search(reason)
            if match:
                skipped += large_files(ctx.target_dir, float(match.group(1)) * 1_000_000)
        long_paths = find_long_paths(ctx.target_dir)
        if long_paths:
            reasons[LONG_PATH_REASON] = len(long_paths)
            skipped += long_paths
        skipped = sorted(dict.fromkeys(skipped))
        details: dict[str, Any] = {
            "partial_files": {
                "count": max(summary["partial"], len(partial)),
                "paths": sorted(partial)[:MAX_LISTED_PATHS],
                "truncated": len(partial) > MAX_LISTED_PATHS,
                "kinds": dict(sorted(kinds.items())),
            },
            "skipped_files": {
                "count": sum(reasons.values()),
                "reasons": reasons,
                "paths": skipped[:MAX_LISTED_PATHS],
                "truncated": len(skipped) > MAX_LISTED_PATHS,
            },
        }
        if summary["files_scanned"] is not None:
            details["files_scanned"] = summary["files_scanned"]
        return details


def _tail(path: Path) -> str:
    try:
        with open(path, "rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - _SUMMARY_TAIL_BYTES))
            return handle.read().decode("utf-8", errors="replace")
    except OSError:
        return ""


def _sarif(path: Path) -> Any:
    try:
        return json.loads(read_bounded(path, _SARIF_MAX_BYTES))
    except (KalkanError, ValueError):  # a bad output is reported by the ingest
        return None


def parse_summary(text: str) -> dict[str, Any]:
    """Parse the scan summary that Opengrep 1.30.1 prints on stderr.

    Returns ``{"files_scanned": int | None, "partial": int, "skipped": {reason: count}}``.
    """
    result: dict[str, Any] = {"files_scanned": None, "partial": 0, "skipped": {}}
    for raw in _ANSI.sub("", text).splitlines():
        line = raw.strip()
        match = _PARTIAL.search(line)
        if match:
            result["partial"] = int(match.group(1))
            continue
        match = _SKIPPED.search(line)
        if match:
            for part in match.group(1).split(","):
                item = _SKIP_ITEM.fullmatch(part.strip().rstrip("."))
                if item:
                    reason = f"files {item.group(2).strip()}"
                    count = result["skipped"].get(reason, 0) + int(item.group(1))
                    result["skipped"][reason] = count
            continue
        match = _RAN.search(line)
        if match:
            result["files_scanned"] = int(match.group(2))
    return result


def notification_paths(doc: Any, target_dir: Path) -> tuple[dict[str, int], list[str]]:
    """Return the notification kinds (descriptor ID counts) and the target-relative paths of
    the SARIF ``invocations[].toolExecutionNotifications``.

    A path comes from ``locations[].physicalLocation.artifactLocation.uri``, else from the
    message text ``... at line <path>:<line>:``. Paths outside the target are left out.
    """
    kinds: Counter[str] = Counter()
    paths: list[str] = []
    runs = doc.get("runs") if isinstance(doc, dict) else None
    for run in runs if isinstance(runs, list) else []:
        invocations = run.get("invocations") if isinstance(run, dict) else None
        for invocation in invocations if isinstance(invocations, list) else []:
            notes = (
                invocation.get("toolExecutionNotifications")
                if isinstance(invocation, dict)
                else None
            )
            for note in notes if isinstance(notes, list) else []:
                if not isinstance(note, dict):
                    continue
                descriptor = note.get("descriptor")
                kind = descriptor.get("id") if isinstance(descriptor, dict) else None
                kinds[kind if isinstance(kind, str) and kind else "unknown"] += 1
                path = _note_path(note, target_dir)
                if path and path not in paths:
                    paths.append(path)
    return dict(kinds), paths


def _note_path(note: dict[str, Any], target_dir: Path) -> str | None:
    candidates: list[str] = []
    locations = note.get("locations")
    for location in locations if isinstance(locations, list) else []:
        physical = location.get("physicalLocation") if isinstance(location, dict) else None
        artifact = physical.get("artifactLocation") if isinstance(physical, dict) else None
        uri = artifact.get("uri") if isinstance(artifact, dict) else None
        if isinstance(uri, str):
            candidates.append(uri)
    message = note.get("message")
    text = message.get("text") if isinstance(message, dict) else None
    if isinstance(text, str):
        match = _NOTE_PATH.search(text)
        if match:
            candidates.append(match.group(1))
    for candidate in candidates:
        relative = target_relative(candidate, target_dir)
        if relative:
            return relative
    return None


def target_relative(path: str, target_dir: Path) -> str | None:
    """Return a tool path (absolute, ``file://`` or relative) as a target-relative POSIX path,
    or None for a path outside the target."""
    text = path.strip().replace("\\", "/")
    if text.lower().startswith("file://"):
        text = unquote(text[7:])
    if text.startswith("//?/"):
        text = text[4:]
    if _DRIVE.match(text):
        text = text.lstrip("/")
    root = Path(target_dir).resolve().as_posix().rstrip("/")
    if os.name == "nt":
        inside = text.casefold().startswith(root.casefold() + "/")
    else:
        inside = text.startswith(root + "/")
    if inside:
        text = text[len(root) + 1 :]
    elif _DRIVE.match(text) or text.startswith("/"):
        return None
    return text if is_safe_relative_path(text) else None


def large_files(target_dir: Path, limit_bytes: float) -> list[str]:
    """Return the sorted target-relative paths of the files larger than ``limit_bytes``."""
    root = Path(target_dir).resolve()
    found: list[str] = []
    for current, _dirs, files in os.walk(root):
        for name in files:
            full = Path(current) / name
            try:
                if full.stat().st_size > limit_bytes:
                    found.append(full.relative_to(root).as_posix())
            except OSError:
                continue
    return sorted(found)
