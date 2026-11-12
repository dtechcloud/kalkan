# SPDX-License-Identifier: MIT
"""CycloneDX SBOM parsing and the package identity helpers of the SCA module (ENGINE-SPEC 17).

:func:`parse_cyclonedx` turns a CycloneDX JSON document (Syft or Trivy) into
:class:`Component` records: OSV ecosystem, package name, version, package URL and the
target-relative manifest or lockfile paths where the package was found.

Locations come from these sources, in order:

- Syft properties ``syft:location:<n>:path`` (paths relative to the scan root, with a leading
  ``/``).
- CycloneDX ``evidence.occurrences[].location`` (CycloneDX 1.5 and later).
- The Trivy property ``aquasecurity:trivy:FilePath``.
- The Trivy dependency graph: Trivy lists each manifest as an ``application`` component with
  the property ``aquasecurity:trivy:Class`` = ``lang-pkgs`` and links its packages through
  ``dependencies[].dependsOn`` (for Go through the main module). Each package reachable from
  such a component gets the manifest path.

The same module holds the identity rules that the matcher outputs share:

- :func:`parse_purl` and :func:`purl_identity` read a package URL.
- :func:`package_key` normalizes a package name for comparison (PyPI names per PEP 503).
- :func:`version_key` normalizes a version for comparison (Go drops the ``v`` prefix, PyPI
  drops trailing ``.0`` release parts, so ``5.3`` equals ``5.3.0``).
- :func:`relative_location` turns a tool path into a safe target-relative POSIX path.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import unquote

from kalkan.errors import UnsafeInputError, ValidationError
from kalkan.util.paths import is_safe_relative_path
from kalkan.util.safe_io import read_bounded

__all__ = [
    "GRYPE_TYPES",
    "MANIFEST_ECOSYSTEMS",
    "MAX_JSON_BYTES",
    "PURL_TYPES",
    "Component",
    "Purl",
    "SbomResult",
    "display_version",
    "load_json_file",
    "manifest_ecosystem",
    "normalize_package",
    "package_key",
    "parse_cyclonedx",
    "parse_purl",
    "purl_identity",
    "read_sbom",
    "relative_location",
    "version_key",
]

#: The largest tool output file (SBOM or matcher JSON) that the SCA module reads.
MAX_JSON_BYTES = 100 * 1024 * 1024

#: Package URL types and the OSV ecosystem names. An unknown type stays as written.
PURL_TYPES: dict[str, str] = {
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

#: Grype and Syft package types and the OSV ecosystem names.
GRYPE_TYPES: dict[str, str] = {
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
    "github-action": "GitHub Actions",
    "github-action-workflow": "GitHub Actions",
}

#: Manifest and lockfile names (lower case) and the OSV ecosystem names.
MANIFEST_ECOSYSTEMS: dict[str, str] = {
    "package-lock.json": "npm",
    "npm-shrinkwrap.json": "npm",
    "yarn.lock": "npm",
    "pnpm-lock.yaml": "npm",
    "bun.lock": "npm",
    "package.json": "npm",
    "pipfile.lock": "PyPI",
    "pipfile": "PyPI",
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

# Package URL types whose namespace is a distribution, not a part of the package name.
_DISTRO_PURL_TYPES = frozenset({"deb", "rpm", "apk", "alpm"})
_PEP503_SEPARATORS = re.compile(r"[-_.]+")
_NUMERIC_RELEASE = re.compile(r"[0-9]+(?:\.[0-9]+)*")
_SYFT_LOCATION = re.compile(r"syft:location:[0-9]+:path")
_TRIVY_FILE_PATH = "aquasecurity:trivy:FilePath"
_TRIVY_CLASS = "aquasecurity:trivy:Class"
_DRIVE = re.compile(r"[A-Za-z]:/")


@dataclass(frozen=True)
class Purl:
    """The parts of a package URL (``pkg:type/namespace/name@version?qualifiers#subpath``)."""

    type: str
    namespace: str
    name: str
    version: str
    qualifiers: dict[str, str] = field(default_factory=dict)
    subpath: str = ""


@dataclass
class Component:
    """One package of an SBOM."""

    ecosystem: str
    name: str
    version: str
    purl: str = ""
    package_type: str = ""
    locations: list[str] = field(default_factory=list)
    bom_ref: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-ready dict."""
        return {
            "ecosystem": self.ecosystem,
            "name": self.name,
            "version": self.version,
            "purl": self.purl,
            "package_type": self.package_type,
            "locations": list(self.locations),
        }


@dataclass
class SbomResult:
    """The components and the warnings of one SBOM document."""

    components: list[Component] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    tool: str = ""
    spec_version: str = ""

    def by_ecosystem(self) -> dict[str, int]:
        """Return the number of components per ecosystem, sorted by ecosystem name."""
        counts: dict[str, int] = {}
        for component in self.components:
            key = component.ecosystem or "unknown"
            counts[key] = counts.get(key, 0) + 1
        return dict(sorted(counts.items()))


# --- package identity --------------------------------------------------------------------------


def parse_purl(text: object) -> Purl | None:
    """Parse a package URL. Return None for text that is not ``pkg:<type>/<name>``."""
    if not isinstance(text, str) or not text.startswith("pkg:"):
        return None
    body, _, subpath = text[4:].partition("#")
    body, _, query = body.partition("?")
    body = body.lstrip("/")
    purl_type, _, rest = body.partition("/")
    if not purl_type or not rest:
        return None
    version = ""
    at = rest.rfind("@")
    if at > 0 and "/" not in rest[at + 1 :]:
        rest, version = rest[:at], rest[at + 1 :]
    segments = [unquote(segment) for segment in rest.split("/") if segment]
    if not segments:
        return None
    qualifiers: dict[str, str] = {}
    for pair in query.split("&") if query else []:
        key, _, value = pair.partition("=")
        if key:
            qualifiers[unquote(key).lower()] = unquote(value)
    return Purl(
        type=purl_type.lower(),
        namespace="/".join(segments[:-1]),
        name=segments[-1],
        version=unquote(version),
        qualifiers=qualifiers,
        subpath=unquote(subpath),
    )


def purl_identity(text: object) -> tuple[str, str, str] | None:
    """Return ``(ecosystem, package, version)`` of a package URL, or None.

    The ecosystem uses the OSV names. Maven packages are ``group:artifact``; distribution
    packages drop the distribution namespace; other packages join the namespace and the name
    with ``/`` (``@scope/name`` for npm, the module path for Go).
    """
    purl = parse_purl(text)
    if purl is None:
        return None
    if purl.type == "maven" and purl.namespace:
        package = f"{purl.namespace.replace('/', '.')}:{purl.name}"
    elif purl.type in _DISTRO_PURL_TYPES or not purl.namespace:
        package = purl.name
    else:
        package = f"{purl.namespace}/{purl.name}"
    return PURL_TYPES.get(purl.type, purl.type), package, purl.version


def normalize_package(ecosystem: str, name: str) -> str:
    """Return the display form of a package name: PyPI names in PEP 503 form, others trimmed."""
    text = name.strip()
    if ecosystem == "PyPI":
        return _PEP503_SEPARATORS.sub("-", text).lower()
    return text


def package_key(ecosystem: str, name: str) -> str:
    """Return the comparison key of a package name.

    PyPI uses PEP 503 (``PyYAML`` and ``pyyaml`` match). npm, Go and Maven names compare
    exactly. Other ecosystems compare without case.
    """
    text = normalize_package(ecosystem, name)
    if ecosystem in ("npm", "Go", "Maven", "PyPI"):
        return text
    return text.lower()


def display_version(ecosystem: str, version: str) -> str:
    """Return the display form of a version: Go versions lose the ``v`` prefix."""
    text = version.strip()
    if ecosystem == "Go" and len(text) > 1 and text[0] == "v" and text[1].isdigit():
        return text[1:]
    return text


def version_key(ecosystem: str, version: str) -> str:
    """Return the comparison key of a version.

    Go drops the ``v`` prefix (OSV-Scanner writes ``0.3.5``, Syft and Grype ``v0.3.5``). PyPI
    drops trailing ``.0`` parts of a plain numeric release (``5.3.0`` equals ``5.3``, PEP 440).
    """
    text = display_version(ecosystem, version)
    if ecosystem == "PyPI":
        text = text.lower()
        if _NUMERIC_RELEASE.fullmatch(text):
            parts = text.split(".")
            while len(parts) > 1 and int(parts[-1]) == 0:
                parts.pop()
            text = ".".join(str(int(part)) for part in parts)
    return text


def manifest_ecosystem(path: str) -> str | None:
    """Return the OSV ecosystem of a manifest or lockfile path, or None."""
    name = path.replace("\\", "/").rsplit("/", 1)[-1].lower()
    if name in MANIFEST_ECOSYSTEMS:
        return MANIFEST_ECOSYSTEMS[name]
    if (name.startswith("requirements") or name.startswith("constraints")) and name.endswith(
        ".txt"
    ):
        return "PyPI"
    if name.endswith((".csproj", ".deps.json")):
        return "NuGet"
    return None


# --- locations ---------------------------------------------------------------------------------


def _exists_under(target_root: str | os.PathLike[str] | None, text: str) -> bool:
    """Return True when ``text`` (with its leading slashes removed) names a path in the target."""
    if target_root is None:
        return False
    parts = [part for part in text.split("/") if part]
    if not parts or any(part in (".", "..") for part in parts):
        return False
    try:
        return Path(target_root).joinpath(*parts).exists()
    except (OSError, ValueError):
        return False


def relative_location(path: object, target_root: str | os.PathLike[str] | None) -> str | None:
    """Return a tool path as a safe target-relative POSIX path, or None.

    - An absolute path inside ``target_root`` loses the root prefix (compared without case on
      Windows). An absolute path with a drive letter outside the root gives None.
    - A path with a leading ``/`` that is not inside the root is relative to the scan root
      (Syft and Grype write ``/package-lock.json``).
    - A leading ``./`` is removed. Backslashes become ``/``.

    The result must pass :func:`kalkan.util.paths.is_safe_relative_path`, else None.
    """
    if not isinstance(path, str) or not path.strip():
        return None
    text = path.strip().replace("\\", "/")
    if text.lower().startswith("file://"):
        text = unquote(text[7:])
        if text.startswith("/") and _DRIVE.match(text[1:]):
            text = text[1:]
    root = _root_text(target_root)
    if root:
        relative = _strip_root(text, root)
        if relative is not None:
            text = relative
        elif _DRIVE.match(text):
            return None
        elif text.startswith("/") and not _exists_under(target_root, text):
            # An absolute POSIX path outside the target, not a scan-root path such as
            # Syft's "/package-lock.json".
            return None
    elif _DRIVE.match(text):
        return None
    text = text.lstrip("/")
    while text.startswith("./"):
        text = text[2:]
    text = str(PurePosixPath(text)) if text else ""
    if text in ("", "."):
        return None
    return text if is_safe_relative_path(text) else None


def _root_text(target_root: str | os.PathLike[str] | None) -> str:
    if target_root is None:
        return ""
    try:
        resolved = Path(target_root).resolve()
    except (OSError, RuntimeError, ValueError):
        resolved = Path(target_root)
    return resolved.as_posix().rstrip("/")


def _strip_root(text: str, root: str) -> str | None:
    for candidate_root in {root, root.replace("\\", "/")}:
        if os.name == "nt":
            if text.casefold() == candidate_root.casefold():
                return ""
            prefix = candidate_root.casefold() + "/"
            if text.casefold().startswith(prefix):
                return text[len(prefix) :]
        else:
            if text == candidate_root:
                return ""
            if text.startswith(candidate_root + "/"):
                return text[len(candidate_root) + 1 :]
    return None


# --- reading -----------------------------------------------------------------------------------


def load_json_file(path: str | os.PathLike[str], max_bytes: int = MAX_JSON_BYTES) -> Any:
    """Read a JSON file of at most ``max_bytes`` (UTF-8 with or without a BOM, UTF-16).

    Raise :class:`~kalkan.errors.UnsafeInputError` for a file that cannot be read safely and
    :class:`~kalkan.errors.ValidationError` for text that is not JSON.
    """
    data = read_bounded(path, max_bytes)
    try:
        # json.loads detects UTF-8 (with or without a BOM), UTF-16 and UTF-32 in bytes.
        return json.loads(data)
    except ValueError as exc:
        name = Path(path).name
        message = f"{name}: not a JSON document: {exc}"
        raise ValidationError(message, [message]) from exc


def read_sbom(
    path: str | os.PathLike[str], target_root: str | os.PathLike[str] | None = None
) -> SbomResult:
    """Read and parse a CycloneDX JSON file (see :func:`parse_cyclonedx`)."""
    try:
        doc = load_json_file(path)
    except UnsafeInputError as exc:
        message = f"{Path(path).name}: {exc}"
        raise ValidationError(message, [message]) from exc
    return parse_cyclonedx(doc, target_root)


def parse_cyclonedx(doc: Any, target_root: str | os.PathLike[str] | None = None) -> SbomResult:
    """Return the library components of a CycloneDX JSON document.

    Raise :class:`~kalkan.errors.ValidationError` when the document is not CycloneDX JSON.
    A component without a name or a version, or of type ``file``, is skipped. Nested
    ``components`` are read too. The result keeps one component per (ecosystem, package,
    version); the locations of duplicates are joined.
    """
    if not isinstance(doc, Mapping) or doc.get("bomFormat") != "CycloneDX":
        message = "the SBOM is not a CycloneDX JSON document (bomFormat is not 'CycloneDX')"
        raise ValidationError(message, [message])
    result = SbomResult(
        tool=_tool_name(doc.get("metadata")),
        spec_version=str(doc.get("specVersion") or ""),
    )
    raw_components = list(_walk_components(doc.get("components")))
    manifest_locations = _trivy_manifest_locations(doc, raw_components, target_root)

    by_key: dict[tuple[str, str, str], Component] = {}
    for index, raw in enumerate(raw_components):
        if raw.get("type") == "file":
            continue
        component = _component(raw, target_root, result.warnings, index)
        if component is None:
            continue
        for location in manifest_locations.get(component.bom_ref, []):
            if location not in component.locations:
                component.locations.append(location)
        key = (
            component.ecosystem,
            package_key(component.ecosystem, component.name),
            version_key(component.ecosystem, component.version),
        )
        known = by_key.get(key)
        if known is None:
            by_key[key] = component
            result.components.append(component)
        else:
            for location in component.locations:
                if location not in known.locations:
                    known.locations.append(location)
    return result


def _tool_name(metadata: object) -> str:
    tools = _mapping(metadata).get("tools")
    # CycloneDX 1.5+: {"components": [...]}; older: a list of {vendor, name, version}.
    items = _mapping(tools).get("components") if isinstance(tools, Mapping) else tools
    for item in items if isinstance(items, list) else []:
        name = _mapping(item).get("name")
        if isinstance(name, str) and name.strip():
            return name.strip()
    return ""


def _walk_components(value: object) -> Iterable[Mapping[str, Any]]:
    stack = [value]
    seen = 0
    while stack:
        items = stack.pop()
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, Mapping):
                continue
            seen += 1
            if seen > 1_000_000:  # a hostile SBOM; stop instead of exhausting memory
                return
            yield item
            nested = item.get("components")
            if isinstance(nested, list):
                stack.append(nested)


def _component(
    raw: Mapping[str, Any],
    target_root: str | os.PathLike[str] | None,
    warnings: list[str],
    index: int,
) -> Component | None:
    name = raw.get("name")
    version = raw.get("version")
    purl = raw.get("purl") if isinstance(raw.get("purl"), str) else ""
    properties = _properties(raw)
    package_type = _first(properties, "syft:package:type") or _first(
        properties, "aquasecurity:trivy:PkgType"
    )
    identity = purl_identity(purl) if purl else None
    ecosystem = ""
    package = name.strip() if isinstance(name, str) else ""
    if identity is not None:
        ecosystem, purl_package, purl_version = identity
        package = purl_package or package
        if not (isinstance(version, str) and version.strip()):
            version = purl_version
    if not ecosystem:
        ecosystem = GRYPE_TYPES.get(package_type, "")
    if not package or not isinstance(version, str) or not version.strip():
        return None
    if raw.get("type") not in (None, "library", "framework", "application", "container"):
        return None
    if raw.get("type") == "application" and identity is None:
        # Trivy lists manifests as application components without a package URL.
        return None
    locations: list[str] = []
    for key, value in properties:
        if _SYFT_LOCATION.fullmatch(key) or key == _TRIVY_FILE_PATH:
            _add_location(locations, value, target_root, warnings, index)
    for occurrence in _list(_mapping(raw.get("evidence")).get("occurrences")):
        _add_location(locations, _mapping(occurrence).get("location"), target_root, warnings, index)
    if not ecosystem:
        for location in locations:
            ecosystem = manifest_ecosystem(location) or ""
            if ecosystem:
                break
    ecosystem = ecosystem or "unknown"
    return Component(
        ecosystem=ecosystem,
        name=normalize_package(ecosystem, package),
        version=display_version(ecosystem, version),
        purl=purl,
        package_type=package_type,
        locations=locations,
        bom_ref=str(raw.get("bom-ref") or ""),
    )


def _trivy_manifest_locations(
    doc: Mapping[str, Any],
    components: list[Mapping[str, Any]],
    target_root: str | os.PathLike[str] | None,
) -> dict[str, list[str]]:
    """Map bom-refs to the manifest paths of the Trivy dependency graph."""
    roots: dict[str, str] = {}
    for raw in components:
        if raw.get("type") != "application":
            continue
        properties = _properties(raw)
        if _first(properties, _TRIVY_CLASS) != "lang-pkgs":
            continue
        location = relative_location(raw.get("name"), target_root)
        ref = raw.get("bom-ref")
        if location and isinstance(ref, str):
            roots[ref] = location
    if not roots:
        return {}
    edges: dict[str, list[str]] = {}
    for dependency in _list(doc.get("dependencies")):
        ref = _mapping(dependency).get("ref")
        if isinstance(ref, str):
            children = _list(_mapping(dependency).get("dependsOn"))
            edges.setdefault(ref, []).extend(c for c in children if isinstance(c, str))
    found: dict[str, list[str]] = {}
    for root_ref, location in roots.items():
        seen = {root_ref}
        stack = list(edges.get(root_ref, []))
        while stack:
            ref = stack.pop()
            if ref in seen:
                continue
            seen.add(ref)
            places = found.setdefault(ref, [])
            if location not in places:
                places.append(location)
            stack.extend(edges.get(ref, []))
    return found


def _add_location(
    locations: list[str],
    value: object,
    target_root: str | os.PathLike[str] | None,
    warnings: list[str],
    index: int,
) -> None:
    if not isinstance(value, str) or not value.strip():
        return
    location = relative_location(value, target_root)
    if location is None:
        warnings.append(f"component {index}: the location is not inside the target; ignored")
        return
    if location not in locations:
        locations.append(location)


def _properties(raw: Mapping[str, Any]) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for item in _list(raw.get("properties")):
        name = _mapping(item).get("name")
        value = _mapping(item).get("value")
        if isinstance(name, str) and isinstance(value, str):
            pairs.append((name, value))
    return pairs


def _first(pairs: list[tuple[str, str]], key: str) -> str:
    for name, value in pairs:
        if name == key and value.strip():
            return value.strip()
    return ""


def _mapping(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _list(value: object) -> list[Any]:
    return value if isinstance(value, list) else []
