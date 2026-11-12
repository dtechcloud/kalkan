# SPDX-License-Identifier: MIT
"""Dependency manifests without a lockfile and their exact pins (ENGINE-SPEC 17).

Syft, OSV-Scanner and Grype read lockfiles. A manifest without a lockfile next to it (for
example a ``package.json`` with ``package-lock=false`` in ``.npmrc``, or a NuGet project whose
versions come from Central Package Management) gives no package to the matchers, and the SCA
result is silently empty for it. :func:`scan_manifests` finds such
manifests and collects the dependencies that the manifest pins to one exact version:

==================  ===========  ======================================================
Manifest            Ecosystem    Lockfiles that make it checked
==================  ===========  ======================================================
``package.json``    npm          ``package-lock.json``, ``npm-shrinkwrap.json``,
                                 ``yarn.lock``, ``pnpm-lock.yaml``, ``bun.lock``,
                                 ``bun.lockb``
``composer.json``   Packagist    ``composer.lock``
``Gemfile``         RubyGems     ``Gemfile.lock``
``gems.rb``         RubyGems     ``gems.locked``
``Pipfile``         PyPI         ``Pipfile.lock``
``pyproject.toml``  PyPI         ``poetry.lock``, ``uv.lock``, ``pdm.lock``, ``pylock.toml``
``Cargo.toml``      crates.io    ``Cargo.lock``
``*.csproj``        NuGet        ``packages.lock.json`` (also ``*.fsproj`` and
                                 ``*.vbproj``; see "NuGet projects" below)
==================  ===========  ======================================================

- The lockfile must be in the same folder. A workspace member is also checked when a parent
  folder holds the lockfile and declares the workspace: ``workspaces`` in the parent
  ``package.json`` or a ``pnpm-workspace.yaml`` (npm), ``[workspace]`` in the parent
  ``Cargo.toml``, ``[tool.uv.workspace]`` in the parent ``pyproject.toml``.
- ``requirements*.txt``, ``go.mod``, ``pom.xml`` and the other lock-like files are read by the
  tools and are not listed.
- A manifest without dependencies is not listed. A ``pyproject.toml`` is listed only when it
  declares dependencies (``[project]`` dependencies, optional dependencies, dependency groups or
  Poetry dependencies).
- Manifests under ``node_modules``, ``vendor``, ``bower_components``, ``jspm_packages`` and
  ``.bundle`` belong to installed packages and are skipped.

Exact pins (:class:`Pin`): npm ``"1.2.3"`` or ``"=1.2.3"`` (also an ``npm:<name>@1.2.3``
alias), Composer ``"1.2.3"`` or ``"v1.2.3"``, Gemfile ``'1.2.3'`` or ``'= 1.2.3'`` as the only
requirement, Pipfile and PEP 508 ``==1.2.3``, Poetry ``"1.2.3"`` or ``"==1.2.3"``, Cargo
``"=1.2.3"``, NuGet ``1.2.3`` or ``[1.2.3]``. Every other requirement (``^``, ``~``, ``>``,
``<``, ``*``, ``x``, a tag, a URL, no version) counts as a range. Local references (``file:``,
``link:``, ``workspace:``, path and workspace dependencies) are not counted.

NuGet projects (a file name that ends with ``.csproj``, ``.fsproj`` or ``.vbproj``, compared
without case) are MSBuild XML, with the MSBuild namespace or without a namespace:

- The XML is untrusted. A file that contains ``<!DOCTYPE`` or ``<!ENTITY`` is refused before
  it is parsed (:data:`REASON_UNREADABLE`). Nothing is executed: no ``dotnet``, no network.
- Every ``PackageReference`` item counts: the attribute or the child element form, ``Include``
  (several names separated by ``;``), or ``Update`` when the item carries a version (it replaces
  the version of an earlier item of the same package). Conditions are not evaluated. A name that
  is not a NuGet package ID (for example ``$(Name)``) counts as a range.
- The version: ``VersionOverride``, else the ``Version`` of the item, else Central Package
  Management (CPM): the ``PackageVersion`` items of the nearest ``Directory.Packages.props`` in
  the project folder or a parent folder up to the target root. The first file found is used, as
  MSBuild does; an import of a parent props file is not followed. An empty value counts as not
  set. A project that sets ``ManagePackageVersionsCentrally`` to false does not use CPM. When
  the props file sets it to false, only a project that sets it to true uses CPM.
- A bare version ``1.2.3`` is a minimum in NuGet, but restore takes the lowest applicable
  version, so it is the resolved version and counts as a pin (when the feed does not have it,
  restore takes the next higher version and warns ``NU1603``). ``[1.2.3]`` is exact. Interval
  notation (``[1.0,2.0)``, ``(,2.0]``), floating versions (``1.*``, ``*``), an MSBuild property
  (``$(Version)``) and a missing or unresolved version count as ranges.
- ``GlobalPackageReference`` items of the props file apply to every CPM project under it. They
  count in the ``exact_pins`` and ``ranges`` of each listed project (unless the project
  references the package itself); their pins name the props file.
- When ``CentralPackageTransitivePinningEnabled`` is true in the props file, every exact
  ``PackageVersion`` that no CPM project under it references directly is a pin too: it floors a
  transitive dependency. It names the props file, :attr:`Pin.transitive` is true, and its
  component carries the CycloneDX property ``kalkan:manifest:transitive-pin`` = ``true``.
- A project with ``packages.lock.json`` in its folder is checked and is never listed, but its
  direct references still count as "referenced" for the transitive pins. The global and the
  transitive pins of a props file are emitted only when a CPM project under it is listed. The
  props file itself is not listed; when it cannot be read, a warning names it and the references
  that need its versions count as ranges.

:func:`pins_sbom` writes the pins as a minimal CycloneDX 1.5 document; the matchers read it like
any SBOM (``sca match``). Records found through it carry ``pin_source: "manifest"``. The same
document carries the vendored JavaScript libraries of :mod:`kalkan.sca.vendored` (records with
``pin_source: "vendored"``).
"""

from __future__ import annotations

import json
import os
import re
import tomllib
import xml.etree.ElementTree as ET
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any, Final
from urllib.parse import quote

from kalkan.errors import UnsafeInputError
from kalkan.sca.sbom import normalize_package, package_key, version_key
from kalkan.util.safe_io import read_text_bounded

if TYPE_CHECKING:
    from kalkan.sca.retirejs import Detection

__all__ = [
    "LOCKFILES",
    "MANIFESTS",
    "MANIFEST_SUFFIXES",
    "PIN_PROPERTY",
    "REASON_PINS_ONLY",
    "REASON_RANGES",
    "REASON_UNREADABLE",
    "TRANSITIVE_PIN_PROPERTY",
    "VENDORED_LIBRARY_PROPERTY",
    "VENDORED_PROPERTY",
    "ManifestScan",
    "Pin",
    "parse_manifest",
    "pin_purl",
    "pins_sbom",
    "scan_manifests",
]

#: Manifest file name (lower case) -> ecosystem.
MANIFESTS: Final[dict[str, str]] = {
    "package.json": "npm",
    "composer.json": "Packagist",
    "gemfile": "RubyGems",
    "gems.rb": "RubyGems",
    "pipfile": "PyPI",
    "pyproject.toml": "PyPI",
    "cargo.toml": "crates.io",
}
#: Manifest file name suffix (lower case) -> ecosystem, for the manifests without a fixed name.
MANIFEST_SUFFIXES: Final[dict[str, str]] = {
    ".csproj": "NuGet",
    ".fsproj": "NuGet",
    ".vbproj": "NuGet",
}
#: Manifest file name or suffix (lower case) -> lockfile names (lower case) in the same folder.
LOCKFILES: Final[dict[str, tuple[str, ...]]] = {
    "package.json": (
        "package-lock.json",
        "npm-shrinkwrap.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "bun.lock",
        "bun.lockb",
    ),
    "composer.json": ("composer.lock",),
    "gemfile": ("gemfile.lock",),
    "gems.rb": ("gems.locked",),
    "pipfile": ("pipfile.lock",),
    "pyproject.toml": ("poetry.lock", "uv.lock", "pdm.lock", "pylock.toml"),
    "cargo.toml": ("cargo.lock",),
    ".csproj": ("packages.lock.json",),
    ".fsproj": ("packages.lock.json",),
    ".vbproj": ("packages.lock.json",),
}
REASON_RANGES: Final = "version ranges without a lockfile"
REASON_PINS_ONLY: Final = (
    "no lockfile: the exact pins were checked, transitive dependencies were not"
)
REASON_UNREADABLE: Final = "the manifest cannot be read"
#: CycloneDX property that names the manifest of a pin.
PIN_PROPERTY: Final = "kalkan:manifest:path"
#: CycloneDX property (value ``true``) of a NuGet transitive pin (module docstring).
TRANSITIVE_PIN_PROPERTY: Final = "kalkan:manifest:transitive-pin"
#: CycloneDX properties of a vendored JavaScript library (:mod:`kalkan.sca.vendored`): the
#: target-relative file and the RetireJS library name.
VENDORED_PROPERTY: Final = "kalkan:vendored:path"
VENDORED_LIBRARY_PROPERTY: Final = "kalkan:vendored:library"
#: The largest manifest that is parsed.
MAX_MANIFEST_BYTES: Final = 2 * 1024 * 1024
#: At most this many manifests are examined.
MAX_MANIFESTS: Final = 5000

_SKIPPED_DIRS: Final = frozenset(
    {".git", "node_modules", "vendor", "bower_components", "jspm_packages", ".bundle"}
)
_PURL_TYPES: Final = {
    "npm": "npm",
    "Packagist": "composer",
    "RubyGems": "gem",
    "PyPI": "pypi",
    "crates.io": "cargo",
    "NuGet": "nuget",
}
_SEMVER: Final = r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?"
_NPM_EXACT: Final = re.compile(rf"=?\s*v?({_SEMVER})")
_NPM_NAME: Final = re.compile(r"(?:@[A-Za-z0-9._~-]+/)?[A-Za-z0-9._~-]+")
_NPM_LOCAL: Final = ("file:", "link:", "workspace:", "portal:", "patch:")
_COMPOSER_EXACT: Final = re.compile(
    r"(?:==?)?\s*v?(\d+(?:\.\d+){2,3}(?:-(?:alpha|beta|rc|patch|p|pl)\.?\d*)?)", re.IGNORECASE
)
_COMPOSER_NAME: Final = re.compile(r"[A-Za-z0-9._-]+/[A-Za-z0-9._-]+")
_COMPOSER_PLATFORM: Final = frozenset(
    {"php", "php-64bit", "hhvm", "composer", "composer-plugin-api", "composer-runtime-api"}
)
_GEM_LINE: Final = re.compile(r"""^\s*gem\s*\(?\s*(['"])([A-Za-z0-9._-]+)\1(.*)$""")
_GEM_ARG: Final = re.compile(r"""\s*,\s*(['"])([^'"]*)\1""")
_GEM_EXACT: Final = re.compile(r"(?:=\s*)?(\d+(?:\.[0-9A-Za-z]+)*)")
_GEM_LOCAL: Final = re.compile(r"\b(?:path|git|github|gitlab|bitbucket)\s*:|:(?:path|git)\s*=>")
_PEP440_EXACT: Final = re.compile(r"===?\s*([0-9][0-9A-Za-z.!+_-]*)")
_POETRY_EXACT: Final = re.compile(r"(?:==?)?\s*([0-9][0-9A-Za-z.!+_-]*)")
_PEP508: Final = re.compile(r"\s*([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(\[[^\]]*\])?(.*)")
_PYPI_NAME: Final = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?")
_CARGO_EXACT: Final = re.compile(rf"=\s*({_SEMVER})")
_CARGO_NAME: Final = re.compile(r"[A-Za-z0-9_-]+")
_NUGET_CENTRAL: Final = "directory.packages.props"
_MSBUILD_NAMESPACE: Final = "{http://schemas.microsoft.com/developer/msbuild/2003}"
_XML_DECLARATIONS: Final = ("<!doctype", "<!entity")
_NUGET_VERSION: Final = r"\d+(?:\.\d+){0,3}(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?"
_NUGET_EXACT: Final = re.compile(rf"\[\s*({_NUGET_VERSION})\s*\]|({_NUGET_VERSION})")
_NUGET_NAME: Final = re.compile(r"[A-Za-z0-9_](?:[A-Za-z0-9_.-]{0,98}[A-Za-z0-9_])?")


@dataclass(frozen=True)
class Pin:
    """One dependency that a manifest pins to one exact version."""

    ecosystem: str
    name: str
    version: str
    file: str  # target-relative POSIX path of the manifest
    transitive: bool = False  # a NuGet transitive pin of a Directory.Packages.props


@dataclass
class _Parsed:
    pins: list[tuple[str, str]] = field(default_factory=list)  # (name, version)
    ranges: int = 0
    referenced: set[str] = field(default_factory=set)  # NuGet: package keys of the references


@dataclass
class _Project:
    """The package references of one NuGet project file, before CPM gives the versions."""

    #: Package key -> (name, version of the item or None), in file order.
    references: dict[str, tuple[str, str | None]] = field(default_factory=dict)
    #: ``ManagePackageVersionsCentrally`` of the project file (None when it is not set).
    central: bool | None = None


@dataclass
class _Central:
    """One ``Directory.Packages.props`` file and what its CPM projects tell about it."""

    file: str  # target-relative POSIX path
    #: Package key -> (name, version) of the ``PackageVersion`` items.
    versions: dict[str, tuple[str, str | None]] = field(default_factory=dict)
    #: Package key -> (name, version) of the ``GlobalPackageReference`` items.
    global_references: dict[str, tuple[str, str | None]] = field(default_factory=dict)
    enabled: bool | None = None  # ManagePackageVersionsCentrally
    transitive: bool = False  # CentralPackageTransitivePinningEnabled
    listed: bool = False  # a CPM project under it is listed
    referenced: set[str] = field(default_factory=set)  # package keys its projects reference


@dataclass
class ManifestScan:
    """The result of :func:`scan_manifests`."""

    #: ``{file, ecosystem, reason, exact_pins, ranges}`` per manifest without a lockfile.
    unchecked: list[dict[str, Any]] = field(default_factory=list)
    #: Exact pins of those manifests, one per (ecosystem, package, version, file).
    pins: list[Pin] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def pin_files(self) -> dict[tuple[str, str, str], list[str]]:
        """Map ``(ecosystem, package key, version key)`` to the manifest paths of the pin."""
        found: dict[tuple[str, str, str], list[str]] = {}
        for pin in self.pins:
            files = found.setdefault(_pin_key(pin.ecosystem, pin.name, pin.version), [])
            if pin.file not in files:
                files.append(pin.file)
        return found


def _pin_key(ecosystem: str, name: str, version: str) -> tuple[str, str, str]:
    return (ecosystem, package_key(ecosystem, name), version_key(ecosystem, version))


# --- discovery ---------------------------------------------------------------------------------


def _walk(root: Path) -> Iterable[tuple[str, list[str]]]:
    """Yield ``(relative folder, lower-case file names)`` for every folder under ``root``."""
    for current, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d.casefold() not in _SKIPPED_DIRS)
        relative = Path(current).relative_to(root).as_posix()
        yield ("" if relative == "." else relative), files


def _join(folder: str, name: str) -> str:
    return f"{folder}/{name}" if folder else name


def _kind(name: str) -> str | None:
    """Return the :data:`LOCKFILES` key of a lower-case file name (the name or its suffix)."""
    if name in MANIFESTS:
        return name
    return next((suffix for suffix in MANIFEST_SUFFIXES if name.endswith(suffix)), None)


def scan_manifests(target_dir: str | os.PathLike[str]) -> ManifestScan:
    """Find the manifests without a lockfile under ``target_dir`` and their exact pins.

    Never raises for target content: a manifest that cannot be read or parsed is listed with
    :data:`REASON_UNREADABLE` and a warning.
    """
    root = Path(target_dir)
    result = ManifestScan()
    folders: dict[str, dict[str, str]] = {}  # folder -> {lower name: real name}
    manifests: list[tuple[str, str]] = []  # (folder, real name)
    for folder, files in _walk(root):
        names = {name.casefold(): name for name in files}
        folders[folder] = names
        for lower, real in sorted(names.items()):
            if _kind(lower) is not None:
                manifests.append((folder, real))
    if len(manifests) > MAX_MANIFESTS:
        result.warnings.append(
            f"{len(manifests)} dependency manifests found; only the first {MAX_MANIFESTS} "
            "were checked for a lockfile"
        )
        manifests = manifests[:MAX_MANIFESTS]
    seen: set[tuple[str, str, str, str]] = set()
    nuget = _NuGetScan(root, folders, result, seen)
    for folder, real in manifests:
        lower = real.casefold()
        kind = _kind(lower) or lower
        locked = any(lock in folders[folder] for lock in LOCKFILES[kind])
        relative = _join(folder, real)
        if kind in MANIFEST_SUFFIXES:
            nuget.project(folder, relative, locked)
            continue
        if locked or _covered_by_workspace(root, folders, folder, lower):
            continue
        ecosystem = MANIFESTS[lower]
        try:
            text = read_text_bounded(root / relative, MAX_MANIFEST_BYTES)
            parsed = parse_manifest(lower, text)
        except (UnsafeInputError, ValueError, TypeError) as exc:
            _list_unreadable(result, relative, ecosystem, exc)
            continue
        if parsed.pins or parsed.ranges:
            _list(result, seen, relative, ecosystem, parsed)
    nuget.finish()
    return result


def _add_pin(result: ManifestScan, seen: set[tuple[str, str, str, str]], pin: Pin) -> None:
    """Add ``pin`` unless the same (ecosystem, package, version, file) is already there."""
    key = (*_pin_key(pin.ecosystem, pin.name, pin.version), pin.file)
    if key not in seen:
        seen.add(key)
        result.pins.append(pin)


def _list(
    result: ManifestScan,
    seen: set[tuple[str, str, str, str]],
    relative: str,
    ecosystem: str,
    parsed: _Parsed,
    extra: tuple[int, int] = (0, 0),
) -> None:
    """List a manifest without a lockfile and add its pins. ``extra`` adds (pins, ranges) that
    apply to the manifest but name another file (NuGet global references)."""
    unique_pins = list(dict.fromkeys(parsed.pins))
    for name, version in unique_pins:
        _add_pin(
            result, seen, Pin(ecosystem, normalize_package(ecosystem, name), version, relative)
        )
    ranges = parsed.ranges + extra[1]
    result.unchecked.append(
        {
            "file": relative,
            "ecosystem": ecosystem,
            "reason": REASON_RANGES if ranges else REASON_PINS_ONLY,
            "exact_pins": len(unique_pins) + extra[0],
            "ranges": ranges,
        }
    )


def _list_unreadable(
    result: ManifestScan, relative: str, ecosystem: str, exc: BaseException
) -> None:
    result.warnings.append(f"{relative}: {REASON_UNREADABLE}: {_short(exc)}")
    result.unchecked.append(
        {
            "file": relative,
            "ecosystem": ecosystem,
            "reason": REASON_UNREADABLE,
            "exact_pins": 0,
            "ranges": 0,
        }
    )


class _NuGetScan:
    """The NuGet part of :func:`scan_manifests`: the projects, their ``Directory.Packages.props``
    and its global and transitive pins (module docstring)."""

    def __init__(
        self,
        root: Path,
        folders: Mapping[str, Mapping[str, str]],
        result: ManifestScan,
        seen: set[tuple[str, str, str, str]],
    ) -> None:
        self.root = root
        self.folders = folders
        self.result = result
        self.seen = seen
        self.centrals: dict[str, _Central] = {}  # props folder -> props file

    def central(self, folder: str) -> _Central | None:
        """Return the nearest ``Directory.Packages.props`` of a project folder, or None."""
        for candidate in (folder, *_parents(folder)):
            real = self.folders.get(candidate, {}).get(_NUGET_CENTRAL)
            if real is None:
                continue
            if candidate not in self.centrals:
                relative = _join(candidate, real)
                try:
                    text = read_text_bounded(self.root / relative, MAX_MANIFEST_BYTES)
                    self.centrals[candidate] = _read_central(relative, text)
                except (UnsafeInputError, ValueError) as exc:
                    self.result.warnings.append(
                        f"{relative}: {REASON_UNREADABLE}: {_short(exc)}; the central package "
                        "versions are unknown"
                    )
                    self.centrals[candidate] = _Central(relative)
            return self.centrals[candidate]
        return None

    def project(self, folder: str, relative: str, locked: bool) -> None:
        """Handle one project file. A locked project is read only to learn its references."""
        central = self.central(folder)
        if locked and (central is None or not central.transitive):
            return
        try:
            project = _read_project(read_text_bounded(self.root / relative, MAX_MANIFEST_BYTES))
        except (UnsafeInputError, ValueError) as exc:
            if not locked:
                _list_unreadable(self.result, relative, "NuGet", exc)
                if central is not None and central.enabled is not False:
                    central.listed = True  # its references are unknown: check the props pins
            return
        if central is not None and not _uses_central(project, central):
            central = None
        parsed = _parse_nuget(project, central.versions if central is not None else {})
        if central is not None:
            central.referenced |= parsed.referenced
        if locked or not (parsed.pins or parsed.ranges):
            return
        extra = (0, 0)
        if central is not None:
            central.listed = True
            extra_pins = extra_ranges = 0
            for key, (name, version) in central.global_references.items():
                if key in parsed.referenced:
                    continue
                if _nuget_exact(name, version):
                    extra_pins += 1
                else:
                    extra_ranges += 1
            extra = (extra_pins, extra_ranges)
        _list(self.result, self.seen, relative, "NuGet", parsed, extra)

    def finish(self) -> None:
        """Add the global and the transitive pins of each props file with a listed project."""
        for folder in sorted(self.centrals):
            central = self.centrals[folder]
            if not central.listed:
                continue
            for name, version in central.global_references.values():
                exact = _nuget_exact(name, version)
                if exact:
                    self._pin(name, exact, central.file, transitive=False)
            if not central.transitive:
                continue
            for key, (name, version) in central.versions.items():
                if key in central.referenced or key in central.global_references:
                    continue
                exact = _nuget_exact(name, version)
                if exact:
                    self._pin(name, exact, central.file, transitive=True)

    def _pin(self, name: str, version: str, file: str, *, transitive: bool) -> None:
        pin = Pin("NuGet", normalize_package("NuGet", name), version, file, transitive)
        _add_pin(self.result, self.seen, pin)


def _uses_central(project: _Project, central: _Central) -> bool:
    """Return True when a project uses CPM: its own setting wins over the props file setting."""
    if project.central is not None:
        return project.central
    return central.enabled is not False


def _short(exc: BaseException) -> str:
    text = " ".join(str(exc).split())
    return text[:200] if text else type(exc).__name__


def _parents(folder: str) -> Iterable[str]:
    parts = PurePosixPath(folder).parts if folder else ()
    for index in range(len(parts) - 1, -1, -1):
        yield "/".join(parts[:index])


def _read_parent(root: Path, folder: str, name: str) -> str | None:
    try:
        return read_text_bounded(root / _join(folder, name), MAX_MANIFEST_BYTES)
    except (UnsafeInputError, ValueError):
        return None


def _covered_by_workspace(
    root: Path, folders: Mapping[str, Mapping[str, str]], folder: str, manifest: str
) -> bool:
    """Return True when a parent folder holds the lockfile of a workspace (module docstring)."""
    if manifest not in ("package.json", "cargo.toml", "pyproject.toml"):
        return False
    for parent in _parents(folder):
        names = folders.get(parent, {})
        if manifest == "package.json":
            if "pnpm-lock.yaml" in names and "pnpm-workspace.yaml" in names:
                return True
            if "package.json" in names and any(n in names for n in LOCKFILES["package.json"]):
                text = _read_parent(root, parent, names["package.json"])
                try:
                    doc = json.loads(text) if text else None
                except ValueError:
                    doc = None
                if isinstance(doc, dict) and doc.get("workspaces"):
                    return True
        elif manifest in names and any(n in names for n in LOCKFILES[manifest]):
            text = _read_parent(root, parent, names[manifest])
            try:
                doc = tomllib.loads(text) if text else None
            except tomllib.TOMLDecodeError:
                doc = None
            if not isinstance(doc, dict):
                continue
            if manifest == "cargo.toml" and isinstance(doc.get("workspace"), dict):
                return True
            uv = _table(_table(doc.get("tool")).get("uv"))
            if manifest == "pyproject.toml" and isinstance(uv.get("workspace"), dict):
                return True
    return False


# --- parsers -----------------------------------------------------------------------------------


def parse_manifest(name: str, text: str, *, central: Mapping[str, str] | None = None) -> _Parsed:
    """Parse one manifest (``name`` is the lower-case file name). Return its pins and the
    number of range requirements. Raise :class:`ValueError` for text that does not parse.

    ``central`` applies to a NuGet project only: package name -> version of the
    ``PackageVersion`` items of its ``Directory.Packages.props`` (CPM; a project that sets
    ``ManagePackageVersionsCentrally`` to false ignores it).
    """
    text = text.lstrip("﻿")
    if _kind(name) in MANIFEST_SUFFIXES:
        project = _read_project(text)
        versions = {
            package_key("NuGet", package): (package, version)
            for package, version in (central or {}).items()
            if project.central is not False
        }
        return _parse_nuget(project, versions)
    if name == "package.json":
        return _parse_npm(_json_object(text))
    if name == "composer.json":
        return _parse_composer(_json_object(text))
    if name in ("gemfile", "gems.rb"):
        return _parse_gemfile(text)
    if name == "pipfile":
        return _parse_pipfile(tomllib.loads(text))
    if name == "pyproject.toml":
        return _parse_pyproject(tomllib.loads(text))
    if name == "cargo.toml":
        return _parse_cargo(tomllib.loads(text))
    raise ValueError(f"unknown manifest {name}")


def _json_object(text: str) -> dict[str, Any]:
    doc = json.loads(text)
    if not isinstance(doc, dict):
        raise ValueError("the manifest is not a JSON object")
    return doc


def _table(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _parse_npm(doc: Mapping[str, Any]) -> _Parsed:
    parsed = _Parsed()
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, spec in _table(doc.get(section)).items():
            if not isinstance(name, str) or not _NPM_NAME.fullmatch(name) or len(name) > 214:
                continue
            if not isinstance(spec, str):
                parsed.ranges += 1
                continue
            text = spec.strip()
            if text.startswith(_NPM_LOCAL):
                continue
            if text.startswith("npm:"):
                alias, _, version = text[4:].rpartition("@")
                match = _NPM_EXACT.fullmatch(version.strip())
                if alias and _NPM_NAME.fullmatch(alias) and match:
                    parsed.pins.append((alias, match.group(1)))
                else:
                    parsed.ranges += 1
                continue
            match = _NPM_EXACT.fullmatch(text)
            if match:
                parsed.pins.append((name, match.group(1)))
            else:
                parsed.ranges += 1
    return parsed


def _parse_composer(doc: Mapping[str, Any]) -> _Parsed:
    parsed = _Parsed()
    for section in ("require", "require-dev"):
        for name, spec in _table(doc.get(section)).items():
            if not isinstance(name, str):
                continue
            lower = name.casefold()
            if (
                lower in _COMPOSER_PLATFORM
                or lower.startswith(("ext-", "lib-"))
                or not _COMPOSER_NAME.fullmatch(name)
            ):
                continue
            match = _COMPOSER_EXACT.fullmatch(spec.strip()) if isinstance(spec, str) else None
            if match:
                parsed.pins.append((name, match.group(1)))
            else:
                parsed.ranges += 1
    return parsed


def _parse_gemfile(text: str) -> _Parsed:
    parsed = _Parsed()
    for line in text.splitlines():
        match = _GEM_LINE.match(line)
        if match is None:
            continue
        name, rest = match.group(2), match.group(3)
        requirements: list[str] = []
        position = 0
        while True:
            argument = _GEM_ARG.match(rest, position)
            if argument is None:
                break
            requirements.append(argument.group(2).strip())
            position = argument.end()
        if not requirements and _GEM_LOCAL.search(rest):
            continue
        exact = _GEM_EXACT.fullmatch(requirements[0]) if len(requirements) == 1 else None
        if exact:
            parsed.pins.append((name, exact.group(1)))
        else:
            parsed.ranges += 1
    return parsed


def _pep440_exact(spec: str) -> str | None:
    match = _PEP440_EXACT.fullmatch(spec.strip())
    if match is None or "*" in spec:
        return None
    return match.group(1)


def _parse_pipfile(doc: Mapping[str, Any]) -> _Parsed:
    parsed = _Parsed()
    for section in ("packages", "dev-packages"):
        for name, spec in _table(doc.get(section)).items():
            if not isinstance(name, str) or not _PYPI_NAME.fullmatch(name):
                continue
            version = spec if isinstance(spec, str) else _table(spec).get("version")
            if not isinstance(version, str):
                if isinstance(spec, dict) and any(k in spec for k in ("path", "file", "git")):
                    continue
                parsed.ranges += 1
                continue
            exact = _pep440_exact(version)
            if exact:
                parsed.pins.append((name, exact))
            else:
                parsed.ranges += 1
    return parsed


def _pep508(requirement: object, parsed: _Parsed) -> None:
    if not isinstance(requirement, str):
        return
    text = requirement.split(";", 1)[0].strip()
    match = _PEP508.fullmatch(text)
    if match is None or not text:
        parsed.ranges += 1
        return
    name, rest = match.group(1), match.group(3).strip()
    if rest.startswith("@"):  # a direct URL reference
        parsed.ranges += 1
        return
    rest = rest.strip("() ")
    exact = _pep440_exact(rest) if rest and "," not in rest else None
    if exact:
        parsed.pins.append((name, exact))
    else:
        parsed.ranges += 1


def _poetry(name: str, spec: object, parsed: _Parsed) -> None:
    if name.casefold() == "python" or not _PYPI_NAME.fullmatch(name):
        return
    version = spec if isinstance(spec, str) else _table(spec).get("version")
    if not isinstance(version, str):
        if isinstance(spec, dict) and any(k in spec for k in ("path", "git", "url", "file")):
            return
        parsed.ranges += 1
        return
    match = _POETRY_EXACT.fullmatch(version.strip())
    if match and "*" not in version:
        parsed.pins.append((name, match.group(1)))
    else:
        parsed.ranges += 1


def _parse_pyproject(doc: Mapping[str, Any]) -> _Parsed:
    parsed = _Parsed()
    project = _table(doc.get("project"))
    for requirement in project.get("dependencies") or []:
        _pep508(requirement, parsed)
    for group in _table(project.get("optional-dependencies")).values():
        for requirement in group if isinstance(group, list) else []:
            _pep508(requirement, parsed)
    for group in _table(doc.get("dependency-groups")).values():
        for requirement in group if isinstance(group, list) else []:
            _pep508(requirement, parsed)  # {include-group = ...} tables are skipped
    poetry = _table(_table(doc.get("tool")).get("poetry"))
    tables = [_table(poetry.get("dependencies")), _table(poetry.get("dev-dependencies"))]
    tables += [_table(_table(g).get("dependencies")) for g in _table(poetry.get("group")).values()]
    for table in tables:
        for name, spec in table.items():
            if isinstance(name, str):
                _poetry(name, spec, parsed)
    return parsed


def _cargo_tables(doc: Mapping[str, Any]) -> list[dict[str, Any]]:
    sections = ("dependencies", "dev-dependencies", "build-dependencies")
    tables = [_table(doc.get(section)) for section in sections]
    for target in _table(doc.get("target")).values():
        tables += [_table(_table(target).get(section)) for section in sections]
    return tables


def _parse_cargo(doc: Mapping[str, Any]) -> _Parsed:
    parsed = _Parsed()
    for table in _cargo_tables(doc):
        for name, spec in table.items():
            if not isinstance(name, str) or not _CARGO_NAME.fullmatch(name):
                continue
            details = _table(spec)
            if details.get("workspace") is True:
                continue  # the workspace root declares the version
            package = details.get("package") if isinstance(details.get("package"), str) else name
            version = spec if isinstance(spec, str) else details.get("version")
            if not isinstance(version, str):
                if any(key in details for key in ("path", "git")):
                    continue
                parsed.ranges += 1
                continue
            match = _CARGO_EXACT.fullmatch(version.strip())
            if match:
                parsed.pins.append((package, match.group(1)))
            else:
                parsed.ranges += 1
    return parsed


def _msbuild_root(text: str) -> ET.Element:
    """Parse MSBuild XML. Refuse a DOCTYPE or an ENTITY declaration before parsing."""
    folded = text.casefold()
    if any(declaration in folded for declaration in _XML_DECLARATIONS):
        raise ValueError("the XML has a DOCTYPE or an ENTITY declaration; refused")
    try:
        root = ET.fromstring(text.lstrip("\ufeff"))
    except ET.ParseError as exc:
        raise ValueError(f"the XML does not parse: {exc}") from None
    if _local(root.tag) != "project":
        raise ValueError("the root element is not <Project>")
    return root


def _local(tag: object) -> str | None:
    """Return the lower-case local name of an MSBuild element (MSBuild namespace or none)."""
    if not isinstance(tag, str):
        return None
    if tag.startswith("{"):
        if not tag.startswith(_MSBUILD_NAMESPACE):
            return None
        tag = tag[len(_MSBUILD_NAMESPACE) :]
    return tag.casefold()


def _attribute(element: ET.Element, name: str) -> str | None:
    """Return an attribute (lower-case ``name``, compared without case), stripped."""
    for key, value in element.attrib.items():
        if key.casefold() == name:
            return value.strip()
    return None


def _metadata(element: ET.Element, name: str) -> str | None:
    """Return item metadata from the attribute or the child element form; empty is None."""
    value = _attribute(element, name)
    if value is None:
        for child in element:
            if _local(child.tag) == name:
                value = (child.text or "").strip()
    return value or None


def _items(
    root: ET.Element, item_type: str, *, override: bool = False
) -> dict[str, tuple[str, str | None]]:
    """Return package key -> (name, version) of the ``item_type`` items (lower case).

    ``Include`` names one or more packages (separated by ``;``). An ``Update`` item counts only
    with a version. A later item of the same package keeps the first name and replaces the
    version. With ``override``, ``VersionOverride`` wins over ``Version``.
    """
    found: dict[str, tuple[str, str | None]] = {}
    for element in root.iter():
        if _local(element.tag) != item_type:
            continue
        version = _metadata(element, "version")
        if override:
            version = _metadata(element, "versionoverride") or version
        names = _attribute(element, "include")
        if names is None and version is not None:
            names = _attribute(element, "update")
        for name in (names or "").split(";"):
            name = name.strip()
            if not name:
                continue
            key = package_key("NuGet", name)
            first_name, old_version = found.get(key, (name, None))
            found[key] = (first_name, version or old_version)
    return found


def _flag(root: ET.Element, name: str) -> bool | None:
    """Return the last ``true`` or ``false`` value of a property (lower-case ``name``)."""
    value = None
    for group in root.iter():
        if _local(group.tag) != "propertygroup":
            continue
        for child in group:
            if _local(child.tag) == name:
                text = (child.text or "").strip().casefold()
                if text in ("true", "false"):
                    value = text == "true"
    return value


def _read_project(text: str) -> _Project:
    """Read the package references of a NuGet project file (module docstring)."""
    root = _msbuild_root(text)
    return _Project(
        _items(root, "packagereference", override=True),
        _flag(root, "managepackageversionscentrally"),
    )


def _read_central(file: str, text: str) -> _Central:
    """Read a ``Directory.Packages.props`` file (``file`` is its target-relative path)."""
    root = _msbuild_root(text)
    return _Central(
        file,
        _items(root, "packageversion"),
        _items(root, "globalpackagereference"),
        _flag(root, "managepackageversionscentrally"),
        _flag(root, "centralpackagetransitivepinningenabled") is True,
    )


def _nuget_exact(name: str, version: str | None) -> str | None:
    """Return the pinned version of a NuGet reference, or None for a range (module docstring)."""
    if version is None or not _NUGET_NAME.fullmatch(name):
        return None
    match = _NUGET_EXACT.fullmatch(version.strip())
    return (match.group(1) or match.group(2)) if match else None


def _parse_nuget(project: _Project, versions: Mapping[str, tuple[str, str | None]]) -> _Parsed:
    """Return the pins and ranges of a project; ``versions`` are the CPM versions by key."""
    parsed = _Parsed()
    for key, (name, version) in project.references.items():
        parsed.referenced.add(key)
        if version is None and key in versions:
            version = versions[key][1]
        exact = _nuget_exact(name, version)
        if exact:
            parsed.pins.append((name, exact))
        else:
            parsed.ranges += 1
    return parsed


# --- the pins SBOM -----------------------------------------------------------------------------


def pin_purl(ecosystem: str, name: str, version: str) -> str:
    """Return the package URL of a pin."""
    purl_type = _PURL_TYPES[ecosystem]
    if ecosystem == "PyPI":
        name = normalize_package("PyPI", name)
    segments = [quote(segment, safe="") for segment in name.split("/") if segment]
    return f"pkg:{purl_type}/{'/'.join(segments)}@{quote(version, safe='.+-_~')}"


def pins_sbom(pins: Iterable[Pin], vendored: Iterable[Detection] = ()) -> dict[str, Any]:
    """Return a minimal CycloneDX 1.5 document with one library component per pinned package.

    Each component names its manifests in ``kalkan:manifest:path`` properties. A component
    whose pins are all NuGet transitive pins also carries ``kalkan:manifest:transitive-pin`` =
    ``true``. ``vendored`` adds the JavaScript libraries that :mod:`kalkan.sca.vendored` found
    in the target: one ``pkg:npm/<npm name>@<version>`` component per package with a
    ``kalkan:vendored:path`` property per file and the RetireJS library name in
    ``kalkan:vendored:library``.
    """
    components: dict[str, dict[str, Any]] = {}
    transitive: dict[str, bool] = {}

    def component_of(purl: str, name: str, version: str) -> dict[str, Any]:
        return components.setdefault(
            purl,
            {
                "type": "library",
                "bom-ref": purl,
                "name": name,
                "version": version,
                "purl": purl,
                "properties": [],
            },
        )

    for pin in pins:
        purl = pin_purl(pin.ecosystem, pin.name, pin.version)
        transitive[purl] = transitive.get(purl, True) and pin.transitive
        component = component_of(purl, pin.name, pin.version)
        entry = {"name": PIN_PROPERTY, "value": pin.file}
        if entry not in component["properties"]:
            component["properties"].append(entry)
    for detection in vendored:
        purl = pin_purl("npm", detection.npm_name, detection.version)
        transitive[purl] = False
        component = component_of(purl, detection.npm_name, detection.version)
        for entry in (
            {"name": VENDORED_PROPERTY, "value": detection.path},
            {"name": VENDORED_LIBRARY_PROPERTY, "value": detection.library},
        ):
            if entry not in component["properties"]:
                component["properties"].append(entry)
    for purl, component in components.items():
        if transitive[purl]:
            component["properties"].append({"name": TRANSITIVE_PIN_PROPERTY, "value": "true"})
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {"tools": {"components": [{"type": "application", "name": "kalkan"}]}},
        "components": list(components.values()),
    }
