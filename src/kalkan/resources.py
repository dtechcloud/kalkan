# SPDX-License-Identifier: MIT
"""Locate the read-only kalkan data, the kalkan home and the runs root (docs/ENGINE-SPEC.md,
section 24).

kalkan runs from a source checkout (``pip install -e .``) or from an installed wheel, for
example inside the Claude Code plugin. This module is the one place that knows both layouts.

**Read-only data** (:func:`data_dir`): the ``knowledge/`` packs and the ``rules/`` packs.

1. ``kalkan/_data/<name>`` next to the installed package. The wheel build copies the repository
   folders there (``[tool.hatch.build.targets.wheel.force-include]`` in ``pyproject.toml``).
2. ``<checkout>/<name>`` in a source checkout or an editable install.

The prompt templates and the JSON schemas are ordinary package data (``kalkan/prompts``,
``kalkan/schemas``) and need no locator.

**Home** (:func:`home`): the folder for mutable data, ``.tools/`` and (by default) ``runs/``.

1. ``KALKAN_HOME`` when it is set and not empty. It must name an existing folder.
2. The ``home`` of the marker ``<sys.prefix>/kalkan-home.json``. The plugin setup command writes
   this file into the venv that it creates in ``${CLAUDE_PLUGIN_DATA}``.
3. The source checkout root (as before the plugin layout).
4. ``~/.kalkan``, created on first use.

**Runs root** (:func:`runs_root`): ``KALKAN_RUNS_DIR`` when it is set and not empty; else the
``runs`` of the marker (the plugin uses ``~/kalkan-runs``: Claude Code never lets a subagent
write below a ``.claude`` folder, and ``${CLAUDE_PLUGIN_DATA}`` is one); else ``<home>/runs``.

**Plugin install** (:func:`plugin_install`): no source checkout holds the package, and the
marker exists in the venv. ``kalkan unattended`` then starts the plugin skill from the runs root
and leaves the permissions to the plugin hook (docs/ENGINE-SPEC.md, section 22).
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from kalkan.errors import KalkanError
from kalkan.util.paths import KALKAN_HOME_ENV, find_repo_root

__all__ = [
    "DATA_NAMES",
    "DEFAULT_HOME_DIRNAME",
    "HOME_MARKER",
    "PACKAGED_DATA_DIRNAME",
    "PLUGIN_RUNS_DIRNAME",
    "RUNS_DIR_ENV",
    "Home",
    "checkout_root",
    "data_dir",
    "data_source",
    "doctor_check",
    "engine_command",
    "home",
    "home_info",
    "knowledge_dir",
    "marker_runs_root",
    "packaged_data_root",
    "plugin_install",
    "rules_dir",
    "runs_root",
    "write_home_marker",
]

#: Folders of read-only data that the wheel carries under ``kalkan/_data``.
DATA_NAMES: Final = ("knowledge", "rules")
#: Package folder that holds the read-only data in a wheel.
PACKAGED_DATA_DIRNAME: Final = "_data"
#: File in the venv root (``sys.prefix``) that names the home and the runs root.
HOME_MARKER: Final = "kalkan-home.json"
#: Default home below the user's home folder when nothing else names one.
DEFAULT_HOME_DIRNAME: Final = ".kalkan"
#: Runs root of the Claude Code plugin below the user's home folder (written into the marker).
PLUGIN_RUNS_DIRNAME: Final = "kalkan-runs"
#: Environment variable that overrides the runs root.
RUNS_DIR_ENV: Final = "KALKAN_RUNS_DIR"

_PACKAGE_DIR: Final = Path(__file__).resolve().parent
_MARKER_MAX_BYTES: Final = 64 * 1024

HOME_ENV: Final = "env"
HOME_FROM_MARKER: Final = "marker"
HOME_CHECKOUT: Final = "checkout"
HOME_DEFAULT: Final = "default"


@dataclass(frozen=True)
class Home:
    """The home folder, where its location came from (``env``, ``marker``, ``checkout``,
    ``default``) and the runs root of the marker (None: ``<home>/runs``)."""

    path: Path
    source: str
    runs: Path | None = None


def packaged_data_root() -> Path:
    """Return ``<package>/_data``. It exists only in an installed wheel."""
    return _PACKAGE_DIR / PACKAGED_DATA_DIRNAME


def checkout_root() -> Path | None:
    """Return the source checkout that holds this package, or None for an installed wheel."""
    return find_repo_root(_PACKAGE_DIR)


def _check_name(name: str) -> None:
    if name not in DATA_NAMES:
        raise ValueError(f"unknown kalkan data folder {name!r}; expected one of {DATA_NAMES}")


def data_source() -> str:
    """Return ``package`` when the wheel data exists, ``checkout`` for a source checkout, else
    ``missing``."""
    if all((packaged_data_root() / name).is_dir() for name in DATA_NAMES):
        return "package"
    root = checkout_root()
    if root is not None and all((root / name).is_dir() for name in DATA_NAMES):
        return "checkout"
    return "missing"


def data_dir(name: str) -> Path:
    """Return the folder of the read-only data ``name`` (``knowledge`` or ``rules``).

    Raises :class:`~kalkan.errors.KalkanError` when neither the package nor a checkout holds it.
    """
    _check_name(name)
    packaged = packaged_data_root() / name
    if packaged.is_dir():
        return packaged
    root = checkout_root()
    if root is not None and (root / name).is_dir():
        return root / name
    raise KalkanError(
        f"cannot find the kalkan {name} folder: the package has no {PACKAGED_DATA_DIRNAME}/{name} "
        "and this is not a source checkout. Reinstall kalkan from a wheel or a checkout."
    )


def knowledge_dir() -> Path:
    """Return the ``knowledge`` folder."""
    return data_dir("knowledge")


def rules_dir(kind: str) -> Path:
    """Return ``rules/<kind>``, for example ``rules/matchers`` or ``rules/opengrep``."""
    return data_dir("rules") / kind


def _marker_path(value: object, marker: Path, key: str) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise KalkanError(f"{marker.as_posix()}: {key!r} names no folder")
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise KalkanError(f"{marker.as_posix()}: {key!r} must be an absolute path")
    return path


def _read_marker(prefix: Path) -> tuple[Path, Path | None] | None:
    """Return ``(home, runs or None)`` from the marker in ``prefix``, or None without one."""
    marker = prefix / HOME_MARKER
    try:
        with marker.open("rb") as handle:
            raw = handle.read(_MARKER_MAX_BYTES + 1)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise KalkanError(f"{marker.as_posix()}: cannot be read ({exc})") from exc
    try:
        if len(raw) > _MARKER_MAX_BYTES:
            raise ValueError("the file is too large")
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise KalkanError(f"{marker.as_posix()}: not a JSON object ({exc})") from exc
    if not isinstance(document, dict):
        raise KalkanError(f"{marker.as_posix()}: not a JSON object")
    home_path = _marker_path(document.get("home"), marker, "home")
    runs = document.get("runs")
    return home_path, (None if runs is None else _marker_path(runs, marker, "runs"))


def home_info(*, prefix: str | os.PathLike[str] | None = None) -> Home:
    """Return the home folder and its source. ``prefix`` replaces ``sys.prefix`` (tests).

    Raises :class:`~kalkan.errors.KalkanError` when ``KALKAN_HOME`` or the marker names a folder
    that does not exist, or when the marker is malformed.
    """
    override = os.environ.get(KALKAN_HOME_ENV)
    if override:
        path = Path(override).expanduser().resolve()
        if not path.is_dir():
            raise KalkanError(f"{KALKAN_HOME_ENV} does not name a directory")
        return Home(path, HOME_ENV)
    marked = _read_marker(Path(prefix) if prefix is not None else Path(sys.prefix))
    if marked is not None:
        path, runs = marked
        if not path.is_dir():
            raise KalkanError(
                f"the kalkan home {path.as_posix()} (from {HOME_MARKER}) does not exist. "
                "Run the kalkan setup again."
            )
        return Home(path.resolve(), HOME_FROM_MARKER, None if runs is None else runs.resolve())
    root = checkout_root()
    if root is not None:
        return Home(root, HOME_CHECKOUT)
    default = Path.home() / DEFAULT_HOME_DIRNAME
    try:
        default.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise KalkanError(
            f"cannot create the default kalkan home {default.as_posix()} ({exc}); "
            f"set {KALKAN_HOME_ENV}"
        ) from exc
    return Home(default.resolve(), HOME_DEFAULT)


def home() -> Path:
    """Return the home folder for ``.tools/`` (see the module docstring)."""
    return home_info().path


def marker_runs_root(*, prefix: str | os.PathLike[str] | None = None) -> Path | None:
    """Return the runs root that the marker names, or None. ``KALKAN_HOME`` hides the marker."""
    if os.environ.get(KALKAN_HOME_ENV):
        return None
    marked = _read_marker(Path(prefix) if prefix is not None else Path(sys.prefix))
    return None if marked is None or marked[1] is None else marked[1].resolve()


def plugin_install(*, prefix: str | os.PathLike[str] | None = None) -> bool:
    """Return True when the engine runs from the venv of the Claude Code plugin.

    That is: no source checkout holds the package, and ``<prefix>/kalkan-home.json`` exists
    (``prefix`` replaces ``sys.prefix``; tests). Only the plugin setup command writes that
    marker. ``KALKAN_HOME`` hides the marker for :func:`home_info`, but not here: the plugin
    skill and the plugin hook still run the engine.
    """
    if checkout_root() is not None:
        return False
    folder = Path(prefix) if prefix is not None else Path(sys.prefix)
    return (folder / HOME_MARKER).is_file()


def runs_root(*, prefix: str | os.PathLike[str] | None = None) -> Path:
    """Return the runs root: ``KALKAN_RUNS_DIR``, else the marker's ``runs``, else
    ``<home>/runs``."""
    override = os.environ.get(RUNS_DIR_ENV)
    if override:
        return Path(override).expanduser().resolve()
    found = home_info(prefix=prefix)
    return found.runs if found.runs is not None else found.path / "runs"


def engine_command(*, prefix: str | os.PathLike[str] | None = None) -> str:
    """Return the command that starts this engine, for the fix hints that kalkan prints.

    ``kalkan`` in a checkout (the venv is active or on PATH). In the plugin venv
    (:func:`plugin_install`) no ``kalkan`` is on PATH, so the hint names the console script of
    the venv: ``<prefix>/Scripts/kalkan.exe`` on Windows, ``<prefix>/bin/kalkan`` elsewhere, in
    double quotes when the path has a space. ``prefix`` replaces ``sys.prefix`` (tests).
    """
    if not plugin_install(prefix=prefix):
        return "kalkan"
    folder = Path(prefix) if prefix is not None else Path(sys.prefix)
    script = folder / "Scripts" / "kalkan.exe" if os.name == "nt" else folder / "bin" / "kalkan"
    text = script.as_posix()
    return f'"{text}"' if " " in text else text


def write_home_marker(
    prefix: str | os.PathLike[str],
    folder: str | os.PathLike[str],
    runs: str | os.PathLike[str] | None = None,
) -> Path:
    """Write ``<prefix>/kalkan-home.json`` naming the home ``folder`` and an optional runs root.

    Return the marker path.
    """
    document: dict[str, str | None] = {"home": str(Path(folder).expanduser().resolve())}
    document["runs"] = None if runs is None else str(Path(runs).expanduser().resolve())
    marker = Path(prefix) / HOME_MARKER
    with marker.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(document, ensure_ascii=False, indent=2) + "\n")
    return marker


def doctor_check() -> dict:
    """Return the ``kalkan doctor`` check ``paths``: the home, the runs root and the data
    source."""
    data: dict = {"home": None, "home_source": None, "runs": None, "data_source": data_source()}
    try:
        found = home_info()
        runs = runs_root()
    except KalkanError as exc:
        return {"name": "paths", "status": "fail", "detail": str(exc), "data": data}
    data["home"] = found.path.as_posix()
    data["home_source"] = found.source
    data["runs"] = runs.as_posix()
    for name in DATA_NAMES:
        try:
            data[name] = data_dir(name).as_posix()
        except KalkanError:
            data[name] = None
    if data["data_source"] == "missing":
        detail = "the knowledge and rules folders are missing. Reinstall kalkan."
        return {"name": "paths", "status": "fail", "detail": detail, "data": data}
    detail = (
        f"home {data['home']} ({found.source}); runs {data['runs']}; "
        f"data from the {data['data_source']}"
    )
    return {"name": "paths", "status": "ok", "detail": detail, "data": data}
