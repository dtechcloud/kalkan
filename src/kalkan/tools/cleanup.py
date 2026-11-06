# SPDX-License-Identifier: MIT
"""What kalkan keeps on the machine and how to remove it: ``kalkan clean`` (docs/ENGINE-SPEC.md,
section 12).

:func:`usage` measures five parts with :func:`kalkan.util.fs.tree_size` (links are counted,
never followed):

- ``engine``: the venv that runs this engine (``sys.prefix``), or the package folder outside a
  venv. It is never deleted: it runs the command.
- ``tools``: ``<home>/.tools`` without the databases and the caches: one folder per manifest
  tool (the Go toolchain included), ``pyenv`` and ``installed.json``.
- ``databases``: ``<home>/.tools/vulndb`` (``kalkan sca update-db``).
- ``caches``: ``<home>/.tools/cache`` (the unpacked opengrep runtime,
  :mod:`kalkan.tools.toolhome`), ``.tools/go-build`` and ``.tools/.tmp``.
- ``runs``: the run folders of the runs root (``KALKAN_RUNS_DIR``, the plugin marker or
  ``<home>/runs``) and its ``LATEST`` file.

:func:`plan` lists what a deletion removes; :func:`delete` removes it with
:func:`kalkan.util.fs.remove_tree`. The rules:

- Only fixed names below the kalkan home (:func:`kalkan.resources.home`) and the runs root are
  candidates: the names above, and in the runs root only names of the run ID form and
  ``LATEST``. Another entry is never deleted; :attr:`Usage.other` lists the ones in ``.tools``.
- Every candidate lies in the home or the runs root after its parent folders are resolved. A
  link or a Windows junction is removed as a link; the folder that it names stays.
- A deletion in the home is refused when the home is a drive root or the user profile folder,
  or when nothing marks it as a kalkan home: ``.tools/installed.json``, the plugin marker that
  names it, or a kalkan source checkout.
- The source files of a checkout are never candidates. ``--keep-reports`` keeps the
  ``report/`` folder of every run and deletes the rest of it. The deletion list names the phase
  of every run (``done``, ``phase hunt, not finished``, ``cleaned``): a run that is not done may
  belong to an audit that still runs.
"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

from kalkan import resources
from kalkan.errors import KalkanError
from kalkan.util.fs import TreeStats, is_link, remove_tree, tree_size

__all__ = [
    "CACHE_NAMES",
    "DATABASE_NAMES",
    "PART_LABELS",
    "PARTS",
    "Item",
    "Part",
    "Usage",
    "delete",
    "home_problem",
    "next_steps",
    "plan",
    "usage",
]

#: The parts in the order of the usage view.
PARTS: Final = ("engine", "tools", "databases", "caches", "runs")
PART_LABELS: Final = {
    "engine": "Engine",
    "tools": "Tools",
    "databases": "Databases",
    "caches": "Caches",
    "runs": "Runs",
}
#: The parts that a deletion flag names (the engine is never deleted).
DELETABLE: Final = ("runs", "caches", "databases", "tools")
DATABASE_NAMES: Final = ("vulndb",)
CACHE_NAMES: Final = ("cache", "go-build", ".tmp")
#: Names below ``.tools`` that belong to the tools besides the manifest tool names.
TOOL_EXTRA_NAMES: Final = ("pyenv", "installed.json")
LATEST_NAME: Final = "LATEST"
REPORT_DIRNAME: Final = "report"


@dataclass
class Item:
    """One path of a part: what it is, its counts, and the part it belongs to."""

    part: str
    path: Path
    stats: TreeStats = field(default_factory=TreeStats)
    errors: list[str] = field(default_factory=list)
    #: For a run folder: its phase (``done``, ``hunt, not finished``, ``cleaned``).
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-ready dict."""
        return {
            "part": self.part,
            "path": self.path.as_posix(),
            "note": self.note or None,
            "files": self.stats.files,
            "bytes": self.stats.bytes,
            "links": self.stats.links,
            "errors": list(self.errors),
        }


@dataclass
class Part:
    """One part of the usage view: its items and their sum."""

    name: str
    folders: list[Path]
    items: list[Item] = field(default_factory=list)

    @property
    def label(self) -> str:
        return PART_LABELS[self.name]

    @property
    def stats(self) -> TreeStats:
        total = TreeStats()
        for item in self.items:
            total.add(item.stats)
        return total

    def to_dict(self) -> dict[str, Any]:
        stats = self.stats
        return {
            "part": self.name,
            "label": self.label,
            "folders": [folder.as_posix() for folder in self.folders],
            "files": stats.files,
            "bytes": stats.bytes,
            "items": [item.to_dict() for item in self.items],
        }


@dataclass
class Usage:
    """What kalkan keeps: the home, its source, the runs root, the parts and other entries of
    ``.tools`` that no rule names (never deleted)."""

    home: Path
    home_source: str
    runs_root: Path
    engine: Path
    parts: dict[str, Part]
    other: list[Item] = field(default_factory=list)
    runs: int = 0

    @property
    def total(self) -> TreeStats:
        total = TreeStats()
        for part in self.parts.values():
            total.add(part.stats)
        return total

    def to_dict(self) -> dict[str, Any]:
        total = self.total
        return {
            "home": self.home.as_posix(),
            "home_source": self.home_source,
            "runs_root": self.runs_root.as_posix(),
            "engine": self.engine.as_posix(),
            "runs": self.runs,
            "parts": [self.parts[name].to_dict() for name in PARTS],
            "total": {"files": total.files, "bytes": total.bytes},
            "other": [item.to_dict() for item in self.other],
        }


# --- the usage view ------------------------------------------------------------------------------


def engine_root() -> Path:
    """Return the venv that runs this engine (``sys.prefix``), or the package folder."""
    if sys.prefix != sys.base_prefix:
        return Path(sys.prefix)
    return Path(__file__).resolve().parents[1]


def tool_names() -> list[str]:
    """Return the names below ``.tools`` that hold tools: the manifest tools and the extras."""
    from kalkan.tools.manifest import load_manifest  # lazy: keeps the import graph small

    try:
        names = [tool.name for tool in load_manifest()]
    except KalkanError:
        names = []
    return [*names, *TOOL_EXTRA_NAMES]


def usage(
    *,
    home: Path | None = None,
    home_source: str | None = None,
    runs_root: Path | None = None,
    engine: Path | None = None,
    names: Iterable[str] | None = None,
    with_engine: bool = True,
) -> Usage:
    """Measure the parts (module docstring). The arguments replace the locations (tests);
    ``with_engine`` False leaves the engine unmeasured (``kalkan doctor``)."""
    if home is None:
        found = resources.home_info()
        home, home_source = found.path, found.source
    if runs_root is None:
        from kalkan.run.ids import runs_root as default_runs_root  # lazy

        runs_root = default_runs_root()
    engine = engine or engine_root()
    tools = Path(home) / ".tools"
    tool_set = list(dict.fromkeys(names if names is not None else tool_names()))
    caches = [tools / name for name in CACHE_NAMES]
    engine_items = [Item("engine", engine, tree_size(engine))] if with_engine else []
    parts = {
        "engine": Part("engine", [engine], engine_items),
        "tools": Part("tools", [tools], _items("tools", tools, tool_set)),
        "databases": Part("databases", [tools / "vulndb"], _items("databases", tools, ("vulndb",))),
        "caches": Part("caches", caches, _items("caches", tools, CACHE_NAMES)),
        "runs": Part("runs", [Path(runs_root)], _run_items(Path(runs_root))),
    }
    known = {*tool_set, *DATABASE_NAMES, *CACHE_NAMES}
    other = [
        Item("other", tools / name, tree_size(tools / name))
        for name in _children(tools)
        if name not in known
    ]
    runs = sum(1 for item in parts["runs"].items if item.path.name != LATEST_NAME)
    return Usage(Path(home), home_source or "", Path(runs_root), engine, parts, other, runs)


def _children(folder: Path) -> list[str]:
    try:
        with os.scandir(folder) as entries:
            return sorted(entry.name for entry in entries)
    except OSError:
        return []


def _items(part: str, folder: Path, names: Iterable[str]) -> list[Item]:
    present = set(_children(folder))
    return [
        Item(part, folder / name, tree_size(folder / name)) for name in names if name in present
    ]


def _run_items(root: Path) -> list[Item]:
    from kalkan.run.ids import is_run_id  # lazy

    items = []
    for name in _children(root):
        if is_run_id(name):
            path = root / name
            items.append(Item("runs", path, tree_size(path), note=_run_note(path)))
        elif name == LATEST_NAME:
            items.append(Item("runs", root / name, tree_size(root / name)))
    return items


def _run_note(run: Path) -> str:
    """Return the phase of a run for the deletion list: an audit may still run a run that is
    not done."""
    from kalkan.util.safe_io import read_text_bounded  # lazy

    if (run / "cleaned.json").is_file():
        return "cleaned"
    try:
        state = json.loads(read_text_bounded(run / "state.json", 32 * 1024 * 1024))
    except Exception:  # missing, unsafe or not JSON
        return "no readable state"
    phase = state.get("phase") if isinstance(state, dict) else None
    if phase == "done":
        return "done"
    return f"phase {phase}, not finished" if isinstance(phase, str) else "no readable state"


# --- deletion ------------------------------------------------------------------------------------


def home_problem(home: Path, home_source: str = "") -> str:
    """Return why the home must not be cleaned, or an empty string (module docstring)."""
    real = Path(os.path.realpath(home))
    if real == Path(real.anchor):
        return f"the kalkan home {home.as_posix()} is a drive root"
    try:
        profile = os.path.normcase(os.path.realpath(Path.home()))
    except (RuntimeError, OSError):  # no profile folder is known
        profile = ""
    if os.path.normcase(str(real)) == profile:
        return f"the kalkan home {home.as_posix()} is the user profile folder"
    if (home / ".tools" / "installed.json").is_file():
        return ""
    if home_source == "marker":
        return ""
    checkout = resources.checkout_root()
    if checkout is not None and os.path.normcase(os.path.realpath(checkout)) == os.path.normcase(
        str(real)
    ):
        return ""
    return (
        f"nothing marks {home.as_posix()} as a kalkan home (no .tools/installed.json, no plugin "
        "marker, no kalkan checkout)"
    )


def plan(found: Usage, parts: Iterable[str], *, keep_reports: bool = False) -> list[Item]:
    """Return the items that a deletion of ``parts`` removes (the measured items of the usage
    view). ``keep_reports`` keeps ``report/`` of every run: the other entries of each run
    folder become the items. Raises :class:`~kalkan.errors.KalkanError` when a rule refuses."""
    wanted = [name for name in DELETABLE if name in set(parts)]
    if any(name != "runs" for name in wanted):
        problem = home_problem(found.home, found.home_source)
        if problem:
            raise KalkanError(f"refusing to delete: {problem}")
    items: list[Item] = []
    for name in wanted:
        base = found.runs_root if name == "runs" else found.home
        for item in found.parts[name].items:
            if not _inside(base, item.path.parent):
                raise KalkanError(
                    f"refusing to delete {item.path.as_posix()}: its folder links out of "
                    f"{base.as_posix()}"
                )
            if name == "runs" and keep_reports and item.path.name != LATEST_NAME:
                if _is_link(item.path):
                    items.append(item)  # a link named like a run: removed as a link
                    continue
                items.extend(_run_parts(item.path))
            else:
                items.append(item)
    return items


def _is_link(path: Path) -> bool:
    try:
        return is_link(os.lstat(path))
    except OSError:
        return False


def _run_parts(run: Path) -> list[Item]:
    """The entries of a run folder except ``report/`` (``--keep-reports``)."""
    return [
        Item("runs", run / name, tree_size(run / name))
        for name in _children(run)
        if name != REPORT_DIRNAME
    ]


def _inside(root: Path, folder: Path) -> bool:
    base = os.path.normcase(os.path.realpath(root))
    real = os.path.normcase(os.path.realpath(folder))
    return real == base or real.startswith(base.rstrip(os.sep) + os.sep)


def delete(items: Iterable[Item]) -> list[Item]:
    """Remove each item with :func:`kalkan.util.fs.remove_tree`; return the items with the
    counts of what was removed and the errors."""
    done: list[Item] = []
    for item in items:
        stats = remove_tree(item.path)
        done.append(Item(item.part, item.path, stats, list(stats.errors)))
    return done


def next_steps(found: Usage) -> list[str]:
    """Return what removes the rest after ``--all``: the engine and the folders around it.

    The plugin: ``claude plugin uninstall kalkan@kalkan`` removes the plugin data folder (the
    home with the engine venv) unless ``--keep-data``; the copy in the plugin cache stays until
    Claude Code removes it, and the runs folder is outside both (checked with a probe plugin
    on 2026-10-29). A checkout: delete its folder. Else: remove the engine and the home.
    """
    if found.home_source == "marker":
        return [
            "claude plugin uninstall kalkan@kalkan  (removes the plugin and its data folder "
            f"{found.home.as_posix()} with the engine venv; --keep-data keeps the folder)",
            "claude plugin marketplace remove kalkan",
            f"The runs folder {found.runs_root.as_posix()} is outside the plugin folders: delete "
            "it by hand when it is empty.",
        ]
    if found.home_source == "checkout":
        return [
            f"Delete the checkout folder {found.home.as_posix()}: the engine venv "
            f"{found.engine.as_posix()} and the source files are all that is left of kalkan."
        ]
    return [
        f"Remove the engine: pip uninstall kalkan, or delete the venv {found.engine.as_posix()}.",
        f"Then delete {found.home.as_posix()} when it is empty.",
    ]
