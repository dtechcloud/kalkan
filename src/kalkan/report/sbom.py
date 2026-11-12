# SPDX-License-Identifier: MIT
"""The SBOM deliverables of the report: ``report/sbom.cdx.json`` and ``report/sbom.spdx.json``
(docs/ENGINE-SPEC.md 16 and 17).

1. **Inputs** (:func:`collect`, relative to the run folder): ``sca/sbom.cdx.json`` (Syft, or the
   Trivy fallback), ``sca/manifest-pins.cdx.json`` (the exact pins of manifests without a
   lockfile, NuGet Central Package Management included, and the vendored JavaScript libraries)
   and ``sca/vendored.json`` (the vendored library check). Each input may be missing; one that
   cannot be read gives a warning.
2. **Join.** One component per package: the key is ``(ecosystem, package, version)`` of the
   package URL with the comparison rules of :mod:`kalkan.sca.sbom` (PyPI names per PEP 503,
   NuGet names without case, Go versions without ``v``), else ``(type, name, version)``. The
   first source in the order Syft (or Trivy), manifest pins, vendored files gives the name,
   version and package URL; sources, locations, licenses, hashes and the RetireJS library
   names are joined. The components are sorted by package URL (else name) and version.
3. **Privacy.** Only an allow list of fields is copied: type, name, group, version, package URL
   (qualifiers limited to :data:`PURL_QUALIFIERS`; a value with a user or password is dropped),
   licenses (the SPDX ID, name or expression as the SBOM tool wrote it; a ``LicenseRef-`` ID
   becomes a name, because CycloneDX allows only SPDX list IDs in ``id``), CPE and hashes
   (known algorithms, hex values). Locations are target-relative paths; a path outside the
   target is dropped. No tool property, external reference or absolute path is copied. The
   target is named by its folder name (a local folder) or by its URL without user, password,
   query and fragment (a git URL). Both documents passed the official CycloneDX 1.6 and SPDX
   2.3 JSON schemas, and ``syft convert`` 1.54.0 read both (checked on 2026-10-25).
4. **CycloneDX** (:func:`cyclonedx`): CycloneDX 1.6 JSON. ``metadata`` holds the report time,
   the tools (kalkan, the tool that wrote the SBOM input with the version of its own record,
   and the RetireJS repository as a ``data`` component with its date and SHA-256 when a
   vendored component exists), the target as the ``component`` and the properties
   ``kalkan:run-id``, ``kalkan:target``, ``kalkan:target-kind`` and ``kalkan:git-ref``. The
   SPDX document names the same tools as creators. A component lists its locations in
   ``evidence.occurrences`` and its sources in ``kalkan:source`` properties (``syft``,
   ``trivy``, ``manifest-pin``, ``vendored``); a vendored one also names its RetireJS library
   (``kalkan:vendored:library``). The serial number is a UUID 5 of the run ID and the report
   time, so the same report gives the same file.
5. **SPDX** (:func:`spdx`): SPDX 2.3 JSON, written in Python from the same components. Not
   ``syft convert``: it would convert only Syft's own SBOM (the manifest pins and the vendored
   libraries are not in it), the report step must also work where the tools are missing, and
   Syft writes a random document namespace, so its output is not reproducible. The target is
   the root package (``SPDXRef-Target``): the document ``DESCRIBES`` it and it ``CONTAINS``
   every package. A package has a stable SPDX ID from its key, ``downloadLocation`` and
   ``copyrightText`` ``NOASSERTION``, ``filesAnalyzed`` false, ``licenseDeclared`` from SPDX
   IDs or a license expression (else ``NOASSERTION``), the package URL and the CPE as external
   references, and its sources and locations in ``sourceInfo``.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final
from urllib.parse import unquote, urlsplit, urlunsplit

from kalkan.errors import UnsafeInputError
from kalkan.sca.sbom import package_key, purl_identity, relative_location, version_key
from kalkan.util.safe_io import read_bounded

if TYPE_CHECKING:
    from kalkan.report.model import ReportModel

__all__ = [
    "CYCLONEDX_FILE",
    "FORMAT_NAMES",
    "PURL_QUALIFIERS",
    "SOURCE_ORDER",
    "SPDX_FILE",
    "SbomComponent",
    "SbomInventory",
    "collect",
    "cyclonedx",
    "spdx",
    "target_label",
    "text_values",
]

CYCLONEDX_FILE: Final = "sbom.cdx.json"
SPDX_FILE: Final = "sbom.spdx.json"
#: The format of each SBOM file, for the report text.
FORMAT_NAMES: Final = {CYCLONEDX_FILE: "CycloneDX 1.6", SPDX_FILE: "SPDX 2.3"}
#: The SBOM inputs, relative to the run folder.
SBOM_INPUT: Final = "sca/sbom.cdx.json"
PINS_INPUT: Final = "sca/manifest-pins.cdx.json"
VENDORED_INPUT: Final = "sca/vendored.json"
#: Source labels in their order of precedence.
SOURCE_ORDER: Final = ("syft", "trivy", "sbom", "manifest-pin", "vendored")
#: Package URL qualifiers that are copied (others can carry repository URLs).
PURL_QUALIFIERS: Final = frozenset(
    {"type", "classifier", "arch", "distro", "os", "epoch", "extension", "platform", "upstream"}
)
MAX_INPUT_BYTES: Final = 100 * 1024 * 1024
MAX_COMPONENTS: Final = 200_000
MAX_LOCATIONS: Final = 50
_COMPONENT_TYPES: Final = frozenset(
    {
        "library",
        "framework",
        "application",
        "container",
        "platform",
        "operating-system",
        "device",
        "firmware",
    }
)
_SPDX_PURPOSE: Final = {
    "library": "LIBRARY",
    "framework": "FRAMEWORK",
    "application": "APPLICATION",
    "container": "CONTAINER",
    "platform": "OTHER",
    "operating-system": "OPERATING-SYSTEM",
    "device": "DEVICE",
    "firmware": "FIRMWARE",
}
_HASH_ALGORITHMS: Final = frozenset(
    {
        "MD5",
        "SHA-1",
        "SHA-256",
        "SHA-384",
        "SHA-512",
        "SHA3-256",
        "SHA3-384",
        "SHA3-512",
        "BLAKE2b-256",
        "BLAKE2b-384",
        "BLAKE2b-512",
        "BLAKE3",
    }
)
_SPDX_HASH: Final = {
    "MD5": "MD5",
    "SHA-1": "SHA1",
    "SHA-256": "SHA256",
    "SHA-384": "SHA384",
    "SHA-512": "SHA512",
    "SHA3-256": "SHA3-256",
    "SHA3-384": "SHA3-384",
    "SHA3-512": "SHA3-512",
    "BLAKE2b-256": "BLAKE2b-256",
    "BLAKE2b-384": "BLAKE2b-384",
    "BLAKE2b-512": "BLAKE2b-512",
    "BLAKE3": "BLAKE3",
}
_LICENSE_ID: Final = re.compile(r"(?:LicenseRef-)?[A-Za-z0-9][A-Za-z0-9.+-]{0,99}")
_EXPRESSION_TOKEN: Final = re.compile(r"\(|\)|[A-Za-z0-9][A-Za-z0-9.+:-]*")
_HEX: Final = re.compile(r"[0-9A-Fa-f]{8,128}")
_SYFT_LOCATION: Final = re.compile(r"syft:location:[0-9]+:path")
_TRIVY_FILE_PATH: Final = "aquasecurity:trivy:FilePath"
_CONTROL: Final = re.compile(r"[\x00-\x1f\x7f]")
_NAMESPACE: Final = uuid.NAMESPACE_URL


@dataclass
class SbomComponent:
    """One package of the joined SBOM."""

    key: tuple[str, ...]
    type: str
    name: str
    version: str
    purl: str = ""
    group: str = ""
    cpe: str = ""
    sources: list[str] = field(default_factory=list)
    locations: list[str] = field(default_factory=list)
    licenses: list[dict[str, Any]] = field(default_factory=list)
    hashes: list[dict[str, str]] = field(default_factory=list)
    libraries: list[str] = field(default_factory=list)

    def absorb(self, other: SbomComponent) -> None:
        """Join the sources, locations, licenses, hashes and libraries of ``other``."""
        for name in ("sources", "locations", "licenses", "hashes", "libraries"):
            mine = getattr(self, name)
            for item in getattr(other, name):
                if item not in mine:
                    mine.append(item)
        self.locations[:] = self.locations[:MAX_LOCATIONS]
        if not self.cpe:
            self.cpe = other.cpe
        if not self.group:
            self.group = other.group


@dataclass
class SbomInventory:
    """The joined components and what was read."""

    components: list[SbomComponent] = field(default_factory=list)
    inputs: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    #: ``(name, version)`` of the tool that wrote ``sca/sbom.cdx.json`` (Syft or Trivy).
    producer: tuple[str, str] | None = None
    #: ``sha256`` and ``updated_at`` of the RetireJS repository (``sca/vendored.json``).
    retire: dict[str, str] | None = None

    def by_source(self) -> dict[str, int]:
        """Return the number of components per source, in :data:`SOURCE_ORDER`."""
        counts = dict.fromkeys(SOURCE_ORDER, 0)
        for component in self.components:
            for source in component.sources:
                counts[source] = counts.get(source, 0) + 1
        return {name: count for name, count in counts.items() if count}


# --- reading -------------------------------------------------------------------------------------


def _text(value: object, limit: int) -> str:
    if not isinstance(value, str):
        return ""
    text = _CONTROL.sub(" ", value).strip()
    return text if 0 < len(text) <= limit else ""


def _load(path: Path, inventory: SbomInventory, name: str) -> Any:
    try:
        data = read_bounded(path, MAX_INPUT_BYTES)
    except UnsafeInputError as exc:
        if path.exists():
            inventory.warnings.append(f"{name}: cannot be read ({exc})")
        return None
    try:
        doc = json.loads(data)
    except ValueError as exc:
        inventory.warnings.append(f"{name}: not JSON ({exc})")
        return None
    inventory.inputs.append(name)
    return doc


def _walk(items: object) -> Iterable[Mapping[str, Any]]:
    stack = [items]
    seen = 0
    while stack:
        value = stack.pop()
        if not isinstance(value, list):
            continue
        for item in value:
            if not isinstance(item, Mapping):
                continue
            seen += 1
            if seen > MAX_COMPONENTS:
                return
            yield item
            stack.append(item.get("components"))


def _properties(raw: Mapping[str, Any]) -> list[tuple[str, str]]:
    found = []
    for item in raw.get("properties") or []:
        if isinstance(item, Mapping):
            name, value = item.get("name"), item.get("value")
            if isinstance(name, str) and isinstance(value, str):
                found.append((name, value))
    return found


def _clean_purl(text: object) -> str:
    """Return a package URL with only the allowed qualifiers, or ``""``."""
    purl = _text(text, 1000)
    if not purl.startswith("pkg:"):
        return ""
    body, hash_mark, subpath = purl.partition("#")
    base, question, query = body.partition("?")
    kept = []
    for pair in query.split("&") if question else []:
        key, _, value = pair.partition("=")
        decoded = unquote(value)
        if key.lower() in PURL_QUALIFIERS and "@" not in decoded and "://" not in decoded:
            kept.append(pair)
    result = base + ("?" + "&".join(kept) if kept else "")
    if hash_mark and subpath and ".." not in subpath.split("/"):
        result += "#" + subpath
    return result


def _licenses(raw: Mapping[str, Any]) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    for item in raw.get("licenses") or []:
        if not isinstance(item, Mapping):
            continue
        expression = _text(item.get("expression"), 300)
        license_doc = item.get("license")
        if expression and _valid_expression(expression):
            entry: dict[str, Any] = {"expression": expression}
        elif isinstance(license_doc, Mapping):
            identifier = _text(license_doc.get("id"), 100)
            name = _text(license_doc.get("name"), 200)
            # CycloneDX allows only SPDX list IDs in "id"; a LicenseRef becomes a name.
            if identifier.startswith("LicenseRef-"):
                identifier, name = "", name or identifier
            if identifier and _LICENSE_ID.fullmatch(identifier):
                entry = {"license": {"id": identifier}}
            elif name:
                entry = {"license": {"name": name}}
            else:
                continue
        else:
            continue
        if entry not in found:
            found.append(entry)
    return found


def _hashes(raw: Mapping[str, Any]) -> list[dict[str, str]]:
    found = []
    for item in raw.get("hashes") or []:
        if not isinstance(item, Mapping):
            continue
        algorithm, content = item.get("alg"), item.get("content")
        if algorithm in _HASH_ALGORITHMS and isinstance(content, str) and _HEX.fullmatch(content):
            entry = {"alg": str(algorithm), "content": content.lower()}
            if entry not in found:
                found.append(entry)
    return found


def _key(purl: str, kind: str, name: str, version: str) -> tuple[str, ...]:
    identity = purl_identity(purl) if purl else None
    if identity is not None and identity[1]:
        ecosystem, package, purl_version = identity
        return (
            "purl",
            ecosystem,
            package_key(ecosystem, package),
            version_key(ecosystem, purl_version or version),
        )
    return ("name", kind, name.casefold(), version)


def _component(
    raw: Mapping[str, Any], source: str, target_dir: Path | None
) -> SbomComponent | None:
    kind = raw.get("type") if isinstance(raw.get("type"), str) else "library"
    if kind not in _COMPONENT_TYPES:
        return None
    name = _text(raw.get("name"), 300)
    version = _text(raw.get("version"), 200)
    if not name or not version:
        return None
    purl = _clean_purl(raw.get("purl"))
    locations: list[str] = []
    for key, value in _properties(raw):
        if _SYFT_LOCATION.fullmatch(key) or key == _TRIVY_FILE_PATH:
            locations.append(value)
    evidence = raw.get("evidence")
    occurrences = evidence.get("occurrences") if isinstance(evidence, Mapping) else None
    for item in occurrences if isinstance(occurrences, list) else []:
        if isinstance(item, Mapping) and isinstance(item.get("location"), str):
            locations.append(item["location"])
    kept = [path for value in locations if (path := relative_location(value, target_dir))]
    cpe = _text(raw.get("cpe"), 500)
    return SbomComponent(
        key=_key(purl, kind, name, version),
        type=kind,
        name=name,
        version=version,
        purl=purl,
        group=_text(raw.get("group"), 300),
        cpe=cpe if cpe.startswith("cpe:2.3:") else "",
        sources=[source],
        locations=list(dict.fromkeys(kept))[:MAX_LOCATIONS],
        licenses=_licenses(raw),
        hashes=_hashes(raw),
    )


def _producer(doc: Mapping[str, Any]) -> tuple[str, str]:
    """Return ``(source label, tool version)`` of the tool that wrote an SBOM input."""
    metadata = doc.get("metadata")
    tools = metadata.get("tools") if isinstance(metadata, Mapping) else None
    items = tools.get("components") if isinstance(tools, Mapping) else tools
    for item in items if isinstance(items, list) else []:
        name = item.get("name") if isinstance(item, Mapping) else None
        if isinstance(name, str) and name.strip().lower() in ("syft", "trivy"):
            return name.strip().lower(), _text(item.get("version"), 100)
    return "sbom", ""


def _kalkan_path(value: object) -> str | None:
    """Return a target-relative path that kalkan wrote (pins, vendored files), or None for an
    absolute or unsafe path."""
    if not isinstance(value, str) or value.startswith(("/", "\\")) or re.match(r"[A-Za-z]:", value):
        return None
    return relative_location(value, None)


def _pins_components(doc: Mapping[str, Any]) -> list[SbomComponent]:
    from kalkan.sca.manifests import PIN_PROPERTY, VENDORED_LIBRARY_PROPERTY, VENDORED_PROPERTY

    found = []
    for raw in _walk(doc.get("components")):
        component = _component({**raw, "properties": []}, "manifest-pin", None)
        if component is None:
            continue
        component.sources = []
        for key, value in _properties(raw):
            is_path = key in (PIN_PROPERTY, VENDORED_PROPERTY)
            path = _kalkan_path(value) if is_path else None
            if key == PIN_PROPERTY and path:
                component.sources.append("manifest-pin")
                component.locations.append(path)
            elif key == VENDORED_PROPERTY and path:
                component.sources.append("vendored")
                component.locations.append(path)
            elif key == VENDORED_LIBRARY_PROPERTY and _text(value, 200):
                component.libraries.append(_text(value, 200))
        component.sources = list(dict.fromkeys(component.sources)) or ["manifest-pin"]
        component.locations = list(dict.fromkeys(component.locations))[:MAX_LOCATIONS]
        component.libraries = list(dict.fromkeys(component.libraries))
        found.append(component)
    return found


def _vendored_components(doc: Mapping[str, Any]) -> list[SbomComponent]:
    found = []
    for item in doc.get("libraries") or []:
        if not isinstance(item, Mapping):
            continue
        name = _text(item.get("npm_name"), 300)
        version = _text(item.get("version"), 200)
        path = _kalkan_path(item.get("path"))
        purl = _clean_purl(item.get("purl"))
        if not name or not version or not path:
            continue
        library = _text(item.get("library"), 200)
        found.append(
            SbomComponent(
                key=_key(purl, "library", name, version),
                type="library",
                name=name,
                version=version,
                purl=purl,
                sources=["vendored"],
                locations=[path],
                libraries=[library] if library else [],
            )
        )
    return found


def collect(run_dir: str | Path, target_dir: str | Path | None) -> SbomInventory | None:
    """Return the joined SBOM components of a run, or None when no SBOM input exists."""
    directory = Path(run_dir)
    target = Path(target_dir) if target_dir is not None else None
    inventory = SbomInventory()
    gathered: list[SbomComponent] = []
    doc = _load(directory / SBOM_INPUT, inventory, SBOM_INPUT)
    if isinstance(doc, Mapping) and doc.get("bomFormat") == "CycloneDX":
        source, version = _producer(doc)
        if source != "sbom" and version:
            inventory.producer = (source, version)
        for raw in _walk(doc.get("components")):
            component = _component(raw, source, target)
            if component is not None:
                gathered.append(component)
    elif doc is not None:
        inventory.warnings.append(f"{SBOM_INPUT}: not a CycloneDX document")
    pins = _load(directory / PINS_INPUT, inventory, PINS_INPUT)
    if isinstance(pins, Mapping):
        gathered.extend(_pins_components(pins))
    found = _load(directory / VENDORED_INPUT, inventory, VENDORED_INPUT)
    if isinstance(found, Mapping):
        gathered.extend(_vendored_components(found))
        repository = found.get("repository")
        if isinstance(repository, Mapping):
            sha = _text(repository.get("sha256"), 64)
            updated = _text(repository.get("updated_at"), 40)
            if sha and _HEX.fullmatch(sha):
                inventory.retire = {"sha256": sha.lower(), "updated_at": updated}
    if not inventory.inputs:
        return None
    joined: dict[tuple[str, ...], SbomComponent] = {}
    for component in gathered:
        known = joined.get(component.key)
        if known is None:
            joined[component.key] = component
        else:
            known.absorb(component)
    order = {name: index for index, name in enumerate(SOURCE_ORDER)}
    for component in joined.values():
        component.sources.sort(key=lambda name: order.get(name, len(order)))
    inventory.components = sorted(
        joined.values(),
        key=lambda c: ((c.purl or c.name).casefold(), c.version, c.key),
    )
    return inventory


def text_values(model: ReportModel, lang: str) -> dict[str, Any] | None:
    """Return the values of the report string ``sca_sbom`` (files, count, sources), or None
    when this report has no SBOM file."""
    from kalkan.report.i18n import sbom_source_label

    files = model.sbom_files()
    if not files or model.sbom is None:
        return None
    return {
        "files": ", ".join(f"`report/{name}` ({FORMAT_NAMES.get(name, name)})" for name in files),
        "n": len(model.sbom.components),
        "sources": ", ".join(
            f"{sbom_source_label(lang, source)} {count}"
            for source, count in model.sbom.by_source().items()
        ),
    }


# --- the target ----------------------------------------------------------------------------------


def target_label(source: str, kind: str) -> tuple[str, str]:
    """Return ``(name, label)`` of the target without a secret or a local absolute path.

    A git URL keeps its scheme, host and path (no user, password, query or fragment); the
    name is its last path part without ``.git``. A local folder gives its folder name for both.
    """
    text = source.strip()
    if kind == "git" or "://" in text:
        try:
            parts = urlsplit(text)
        except ValueError:
            parts = None
        if parts is not None and parts.scheme and parts.hostname:
            host = parts.hostname + (f":{parts.port}" if parts.port else "")
            label = urlunsplit((parts.scheme, host, parts.path, "", ""))
            name = parts.path.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git")
            return name or host, label
        if "@" in text and ":" in text:  # scp form: user@host:org/repo.git
            path = text.split(":", 1)[1]
            name = path.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git")
            return name or "target", name or "target"
    name = re.split(r"[\\/]", text.rstrip("\\/"))[-1] if text else ""
    name = _text(name, 200) or "target"
    return name, name


# --- documents -----------------------------------------------------------------------------------


def _tools(model: ReportModel, inventory: SbomInventory) -> list[tuple[str, str]]:
    """Return kalkan and the tool that wrote the SBOM input (its own version record)."""
    tools = [("kalkan", model.kalkan_version)]
    if inventory.producer is not None:
        tools.append(inventory.producer)
    return tools


def _retire_data(inventory: SbomInventory) -> dict[str, Any] | None:
    """Return the CycloneDX ``data`` component of the RetireJS repository, or None when no
    vendored component exists."""
    if inventory.retire is None or not any("vendored" in c.sources for c in inventory.components):
        return None
    entry: dict[str, Any] = {"type": "data", "name": "RetireJS jsrepository-v5"}
    if inventory.retire.get("updated_at"):
        entry["version"] = inventory.retire["updated_at"][:10]
    entry["hashes"] = [{"alg": "SHA-256", "content": inventory.retire["sha256"]}]
    return entry


def _uuid(model: ReportModel, kind: str) -> str:
    return str(uuid.uuid5(_NAMESPACE, f"kalkan:{model.run_id}:{model.generated_at}:{kind}"))


def _ref(component: SbomComponent) -> str:
    digest = hashlib.sha256("\x00".join(component.key).encode("utf-8")).hexdigest()
    return digest[:20]


def cyclonedx(model: ReportModel, inventory: SbomInventory) -> dict[str, Any]:
    """Return the CycloneDX 1.6 document of the joined components (module docstring, 4)."""
    name, label = target_label(model.target_source, model.target_kind)
    properties = [
        {"name": "kalkan:run-id", "value": model.run_id},
        {"name": "kalkan:target", "value": label},
    ]
    if model.target_kind:
        properties.append({"name": "kalkan:target-kind", "value": model.target_kind})
    if model.git_ref:
        properties.append({"name": "kalkan:git-ref", "value": model.git_ref})
    target: dict[str, Any] = {"type": "application", "bom-ref": "kalkan:target", "name": name}
    if model.git_ref:
        target["version"] = model.git_ref
    components = []
    refs: set[str] = set()
    for item in inventory.components:
        ref = item.purl or f"kalkan:component:{_ref(item)}"
        if ref in refs:
            ref = f"{ref}#kalkan-{_ref(item)}"
        refs.add(ref)
        component: dict[str, Any] = {"type": item.type, "bom-ref": ref, "name": item.name}
        if item.group:
            component["group"] = item.group
        component["version"] = item.version
        if item.purl:
            component["purl"] = item.purl
        if item.cpe:
            component["cpe"] = item.cpe
        if item.licenses:
            component["licenses"] = [dict(entry) for entry in item.licenses]
        if item.hashes:
            component["hashes"] = [dict(entry) for entry in item.hashes]
        if item.locations:
            component["evidence"] = {"occurrences": [{"location": p} for p in item.locations]}
        component["properties"] = [{"name": "kalkan:source", "value": s} for s in item.sources]
        component["properties"] += [
            {"name": "kalkan:vendored:library", "value": library} for library in item.libraries
        ]
        components.append(component)
    tools: list[dict[str, Any]] = [
        {"type": "application", "name": tool, "version": version}
        for tool, version in _tools(model, inventory)
    ]
    retire = _retire_data(inventory)
    if retire is not None:
        tools.append(retire)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{_uuid(model, 'cyclonedx')}",
        "version": 1,
        "metadata": {
            "timestamp": model.generated_at,
            "tools": {"components": tools},
            "component": target,
            "properties": properties,
        },
        "components": components,
    }


def _valid_expression(text: str) -> bool:
    tokens = _EXPRESSION_TOKEN.findall(text)
    if "".join(tokens) != text.replace(" ", ""):
        return False
    depth = 0
    for token in tokens:
        depth += token == "("
        depth -= token == ")"
        if depth < 0:
            return False
    return depth == 0 and any(_LICENSE_ID.fullmatch(t) for t in tokens if t not in ("(", ")"))


def _declared(component: SbomComponent) -> str:
    for entry in component.licenses:
        if "expression" in entry:
            return str(entry["expression"])
    identifiers = [
        entry["license"]["id"]
        for entry in component.licenses
        if isinstance(entry.get("license"), Mapping) and "id" in entry["license"]
    ]
    return " AND ".join(dict.fromkeys(identifiers)) if identifiers else "NOASSERTION"


def spdx(model: ReportModel, inventory: SbomInventory) -> dict[str, Any]:
    """Return the SPDX 2.3 document of the joined components (module docstring, 5)."""
    name, label = target_label(model.target_source, model.target_kind)
    root: dict[str, Any] = {
        "SPDXID": "SPDXRef-Target",
        "name": name,
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "primaryPackagePurpose": "APPLICATION",
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "copyrightText": "NOASSERTION",
        "comment": f"kalkan run {model.run_id}; target {label}",
    }
    if model.git_ref:
        root["versionInfo"] = model.git_ref
    packages = [root]
    relationships = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": "SPDXRef-Target",
        }
    ]
    seen: set[str] = set()
    for item in inventory.components:
        identifier = f"SPDXRef-Package-{_ref(item)}"
        while identifier in seen:
            identifier += "-1"
        seen.add(identifier)
        package: dict[str, Any] = {
            "SPDXID": identifier,
            "name": item.name,
            "versionInfo": item.version,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "primaryPackagePurpose": _SPDX_PURPOSE.get(item.type, "LIBRARY"),
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": _declared(item),
            "copyrightText": "NOASSERTION",
        }
        references = []
        if item.purl:
            references.append(
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": item.purl,
                }
            )
        if item.cpe:
            references.append(
                {
                    "referenceCategory": "SECURITY",
                    "referenceType": "cpe23Type",
                    "referenceLocator": item.cpe,
                }
            )
        if references:
            package["externalRefs"] = references
        checksums = [
            {"algorithm": _SPDX_HASH[entry["alg"]], "checksumValue": entry["content"]}
            for entry in item.hashes
            if entry["alg"] in _SPDX_HASH
        ]
        if checksums:
            package["checksums"] = checksums
        info = f"kalkan sources: {', '.join(item.sources)}"
        if item.locations:
            info += f"; locations: {', '.join(item.locations)}"
        if item.libraries:
            info += f"; RetireJS library: {', '.join(item.libraries)}"
        package["sourceInfo"] = info[:4000]
        packages.append(package)
        relationships.append(
            {
                "spdxElementId": "SPDXRef-Target",
                "relationshipType": "CONTAINS",
                "relatedSpdxElement": identifier,
            }
        )
    creators = [
        "Tool: " + f"{tool}-{version}".replace(" ", "-")
        for tool, version in _tools(model, inventory)
    ]
    comment = (
        "Joined by kalkan from the SBOM of Syft (or Trivy), the exact pins of manifests "
        "without a lockfile and the vendored JavaScript libraries."
    )
    retire = _retire_data(inventory)
    if retire is not None:
        version = f" {retire['version']}" if retire.get("version") else ""
        comment += (
            f" Vendored libraries: RetireJS jsrepository-v5{version} "
            f"(SHA-256 {retire['hashes'][0]['content']})."
        )
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"kalkan-sbom-{name}",
        "documentNamespace": f"https://kalkan.invalid/spdx/{model.run_id}-{_uuid(model, 'spdx')}",
        "creationInfo": {
            "created": model.generated_at,
            "creators": creators,
            "comment": comment,
        },
        "packages": packages,
        "relationships": relationships,
    }
