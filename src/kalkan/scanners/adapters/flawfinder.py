# SPDX-License-Identifier: MIT
"""flawfinder scan of the C and C++ sources (ENGINE-SPEC 13). Runs only when the tech list has
``c`` or ``cpp``.

Command line, checked against ``flawfinder --help`` of the pinned version 2.0.20, in batches of
:data:`~kalkan.scanners.adapters._sources.BATCH_SIZE` absolute file paths (SARIF on stdout)::

    flawfinder --sarif --neverignore -- <file> [...]

1. Files: ``.c``, ``.h``, ``.cc``, ``.cpp``, ``.cxx``, ``.c++``, ``.hh``, ``.hpp``, ``.hxx``,
   ``.h++``, ``.ec``, ``.ecp``, ``.pgc`` and ``.pcc`` (case-insensitive), vendored folders left
   out (:mod:`kalkan.scanners.adapters._sources`). The list is explicit, so flawfinder also
   reads the folders whose name starts with a dot (it skips them when it walks a folder) and
   follows no link.
2. ``--sarif``: SARIF 2.1.0 on stdout; it also turns off the progress and the header lines.
   The tool starts through the tool venv with ``PYTHONUTF8=1``.
3. Minimum level :data:`MIN_LEVEL` (3), applied by the adapter: flawfinder 2.0.20 ignores
   ``--minlevel`` for ``--sarif`` (checked: the SARIF writer gets the whole hit list, and a
   ``char buf[32]`` of level 2 was reported), so :func:`rewrite_sarif` drops the results whose
   ``rank`` (level / 5) is below 0.6. flawfinder rates each hit from 0 to 5. Level 2 and lower
   are mostly code quality hints: every ``char buf[N]`` declaration, ``memcpy``, ``fopen``,
   ``atoi``, ``strncpy``, ``strlen``. Level 3 to 5 keep the calls that flawfinder considers
   risky by default: unbounded copies (``strcpy`` 4, ``sprintf`` and ``strcat`` 4, ``gets``
   5), format strings that are not constant (``printf(user)`` 4), command execution
   (``system``, ``popen``, ``exec*`` 4), race-prone file checks (``access`` 4, ``chmod`` 5),
   temporary files (``tmpnam`` 3, ``mktemp`` 4) and weak randomness (``random``, ``srand``
   3). flawfinder lowers the level of a call whose format is a constant string, so
   ``snprintf(buf, sizeof buf, "%s", s)`` (level 1) is not reported.
4. ``--neverignore``: flawfinder ignores a hit on a line with a ``flawfinder: ignore``,
   ``RATS: ignore`` or ``ITS4: ignore`` comment (or the next line); this option turns that off
   (ADR-0003). With ``honor_suppressions`` it is left out. flawfinder has no config file.
5. ``--`` ends the options. On Windows flawfinder expands every argument with ``glob``, so the
   adapter escapes ``[``, ``*`` and ``?`` in the paths (:func:`glob.escape`).
6. Encoding: flawfinder reads the files as strict UTF-8; a file that is not valid UTF-8 is
   skipped with a warning on stdout (inside the SARIF document) and exit code 15. The adapter
   therefore copies such a file into the work folder as UTF-8 (each byte read as Latin-1, so
   lines and columns stay the same) and scans the copy; the result keeps the target path
   (``transcoded_files`` in the status file).

Output: the SARIF of flawfinder has absolute, percent-encoded URIs with the base ``SRCROOT``;
:meth:`FlawfinderAdapter.after_run` rewrites them to target-relative paths and adds the
flawfinder level (``properties.flawfinder_level``, from ``rank`` x 5). The rules carry their
CWE IDs as relationships (tool component ``CWE``), and ``kalkan.sarif.ingest`` maps the first
one: CWE-120, CWE-119 and CWE-134 give ``memory-safety``, CWE-78 ``os-command-injection``,
CWE-362 ``race-condition``, CWE-327 ``crypto``; other CWE IDs (CWE-377, CWE-807) keep no
class. The level is flawfinder's: 4 and 5 give ``error``, 3 ``warning``. Exit code 0.
"""

from __future__ import annotations

import glob
import json
import os
from pathlib import Path, PurePosixPath
from typing import Any, Final

from kalkan.errors import KalkanError, ToolError
from kalkan.scanners.adapters import _sources
from kalkan.scanners.base import (
    PYTHON_TOOL_ENV,
    Invocation,
    ScanContext,
    ToolAdapter,
    part_path,
    work_dir,
)
from kalkan.util.safe_io import atomic_write_json, read_bounded

__all__ = [
    "EXTENSIONS",
    "MIN_LEVEL",
    "FlawfinderAdapter",
    "c_sources",
    "file_argument",
    "flawfinder_level",
    "is_c_source",
    "needs_transcoding",
    "rewrite_sarif",
]

#: The C and C++ extensions that flawfinder 2.0.20 reads (compared case-insensitively).
EXTENSIONS: Final = (
    ".c",
    ".h",
    ".cc",
    ".cpp",
    ".cxx",
    ".c++",
    ".hh",
    ".hpp",
    ".hxx",
    ".h++",
    ".ec",
    ".ecp",
    ".pgc",
    ".pcc",
)
MIN_LEVEL: Final = 3
#: The work folder entry that holds UTF-8 copies of files that are not valid UTF-8.
TRANSCODED_DIRNAME: Final = "transcoded"
MAX_OUTPUT_BYTES: Final = 50 * 1024 * 1024


def is_c_source(rel: str) -> bool:
    """Return True for a C or C++ file name."""
    return PurePosixPath(rel).name.lower().endswith(EXTENSIONS)


def c_sources(target: Path) -> list[str]:
    """Return the target-relative paths of the C and C++ files, sorted."""
    return _sources.source_files(target, is_c_source)


def needs_transcoding(path: Path) -> bool:
    """Return True when a file is not valid UTF-8 (flawfinder would skip it)."""
    try:
        read_bounded(path, _sources.MAX_SOURCE_BYTES).decode("utf-8")
    except UnicodeDecodeError:
        return True
    except (KalkanError, OSError):
        return False
    return False


def file_argument(path: Path, *, windows: bool = os.name == "nt") -> str:
    """Return a file argument: on Windows with ``[``, ``*`` and ``?`` escaped, because
    flawfinder expands every argument with :func:`glob.glob` there."""
    text = str(path)
    return glob.escape(text) if windows else text


def flawfinder_level(result: dict[str, Any]) -> int | None:
    """Return the flawfinder level (0-5) of a SARIF result from its ``rank`` (level / 5)."""
    rank = result.get("rank")
    if isinstance(rank, bool) or not isinstance(rank, (int, float)):
        return None
    return round(float(rank) * 5)


def rewrite_sarif(
    doc: dict[str, Any], *, target: Path, transcoded: Path, min_level: int = MIN_LEVEL
) -> tuple[dict[str, Any], int]:
    """Make every result URI target-relative (a copy under ``transcoded`` maps back to its
    target path), add ``properties.flawfinder_level`` and drop the results below
    ``min_level``. Results outside both folders are dropped too. Return the document and the
    number of results below the minimum level."""
    runs = doc.get("runs") if isinstance(doc, dict) else None
    if not isinstance(runs, list):
        raise ToolError("the flawfinder output is not a SARIF document with runs")
    below = 0
    for run in runs:
        if not isinstance(run, dict):
            continue
        kept: list[Any] = []
        for result in run.get("results") or []:
            if not isinstance(result, dict):
                continue
            locations = result.get("locations")
            physical = (
                locations[0].get("physicalLocation")
                if isinstance(locations, list) and locations and isinstance(locations[0], dict)
                else None
            )
            artifact = physical.get("artifactLocation") if isinstance(physical, dict) else None
            if not isinstance(artifact, dict):
                continue
            uri = str(artifact.get("uri") or "")
            rel = _sources.target_relative(uri, transcoded) or _sources.target_relative(uri, target)
            if rel is None:
                continue
            level = flawfinder_level(result)
            if level is not None and level < min_level:
                below += 1
                continue
            artifact["uri"] = rel
            artifact.pop("uriBaseId", None)
            if level is not None:
                properties = result.setdefault("properties", {})
                if isinstance(properties, dict):
                    properties["flawfinder_level"] = level
            kept.append(result)
        run["results"] = kept
        run.pop("originalUriBaseIds", None)
    return doc, below


class FlawfinderAdapter(ToolAdapter):
    """``flawfinder --sarif`` over the C and C++ files."""

    name = "flawfinder"
    tool = "flawfinder"
    output = "sarif-stdout"
    output_dir = "scans"
    output_name = "flawfinder.sarif"
    ok_exit_codes = (0,)
    timeout_seconds = 900

    def __init__(self) -> None:
        self._below = 0

    def applies(self, ctx: ScanContext) -> tuple[bool, str]:
        if not {"c", "cpp"} & ctx.tech:
            return False, "the target has no C or C++ code (tech tags 'c' and 'cpp' missing)"
        if not c_sources(ctx.target_dir):
            return False, "no C or C++ file found in the target (outside vendored folders)"
        return True, ""

    def env(self, ctx: ScanContext) -> dict[str, str]:
        return dict(PYTHON_TOOL_ENV)

    def transcoded_dir(self, ctx: ScanContext) -> Path:
        """Return the work folder of the UTF-8 copies."""
        return work_dir(ctx.run_dir, self) / TRANSCODED_DIRNAME

    def _paths(self, ctx: ScanContext) -> list[Path]:
        copies = self.transcoded_dir(ctx)
        paths: list[Path] = []
        for rel in c_sources(ctx.target_dir):
            source = ctx.target_dir / rel
            paths.append(copies / rel if needs_transcoding(source) else source)
        return paths

    def prepare(self, ctx: ScanContext, stage: Path) -> None:
        """Write a UTF-8 copy of every C or C++ file that is not valid UTF-8."""
        copies = self.transcoded_dir(ctx)
        for rel in c_sources(ctx.target_dir):
            source = ctx.target_dir / rel
            if not needs_transcoding(source):
                continue
            text = read_bounded(source, _sources.MAX_SOURCE_BYTES).decode("latin-1")
            copy = copies / rel
            copy.parent.mkdir(parents=True, exist_ok=True)
            copy.write_text(text, encoding="utf-8", newline="")

    def _arguments(self, ctx: ScanContext, paths: list[Path]) -> list[str]:
        args = ["--sarif"]
        if not ctx.honor_suppressions:
            args.append("--neverignore")
        return [*args, "--", *(file_argument(path) for path in paths)]

    def arguments(self, ctx: ScanContext, out: Path) -> list[str]:
        return self._arguments(ctx, self._paths(ctx))

    def invocations(self, ctx: ScanContext, tool_path: Path, out: Path) -> list[Invocation]:
        self._below = 0
        paths = self._paths(ctx)
        groups = [
            paths[i : i + _sources.BATCH_SIZE] for i in range(0, len(paths), _sources.BATCH_SIZE)
        ]
        items: list[Invocation] = []
        for index, batch in enumerate(groups):
            argv = (str(tool_path), *self._arguments(ctx, batch))
            target = out if len(groups) == 1 else part_path(out, index)
            first = index * _sources.BATCH_SIZE + 1
            label = f"files {first}-{first + len(batch) - 1}"
            items.append(Invocation(argv, self.cwd(ctx), target, label=label))
        return items

    def after_run(self, ctx: ScanContext, item: Invocation) -> None:
        """Rewrite the SARIF URIs of one run to target-relative paths."""
        try:
            doc = json.loads(read_bounded(item.output, MAX_OUTPUT_BYTES))
        except (KalkanError, ValueError) as exc:
            raise ToolError(f"the flawfinder output is not a SARIF document: {exc}") from None
        rewritten, below = rewrite_sarif(
            doc, target=ctx.target_dir, transcoded=self.transcoded_dir(ctx)
        )
        self._below += below
        atomic_write_json(item.output, rewritten)

    def status_details(
        self, ctx: ScanContext, stdout_log: Path, stderr_log: Path, outputs: list[Path]
    ) -> dict[str, Any]:
        """Record the minimum level and the files that were scanned as UTF-8 copies."""
        copies = self.transcoded_dir(ctx)
        transcoded = (
            sorted(
                path.relative_to(copies).as_posix() for path in copies.rglob("*") if path.is_file()
            )
            if copies.is_dir()
            else []
        )
        details: dict[str, Any] = {"min_level": MIN_LEVEL, "below_min_level": self._below}
        if transcoded:
            details["transcoded_files"] = {"count": len(transcoded), "paths": transcoded[:50]}
        return details

    def suppression_sources(self, ctx: ScanContext) -> tuple[list[str], list[str]]:
        comments = "flawfinder: ignore, RATS: ignore and ITS4: ignore comments"
        if ctx.honor_suppressions:
            return [], [comments]
        return [f"{comments} (--neverignore)"], []
