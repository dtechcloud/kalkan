# SPDX-License-Identifier: MIT
"""Load and validate the pinned tool manifest (docs/ENGINE-SPEC.md, section 12).

The manifest is package data (``kalkan/tools/manifest.json``). It pins every external tool:
version, license, kind (``binary``, ``toolchain``, ``pip`` or ``go-install``), blocked versions
and, for binary tools and toolchains, one asset per platform with the download URL, the SHA-256
of the asset, the archive type and the path of the executable inside the archive.

A ``toolchain`` (the Go toolchain) is a whole folder tree, not one file: its asset also names
the top folder of the archive (``root``), the number of regular files (``files``) and the
SHA-256 of the tree (``tree_sha256``, see :func:`tree_digest`).

A ``go-install`` tool can name ``build_flags``: extra ``go install`` flags, limited to
``-trimpath`` and ``-ldflags=`` with ``-s``, ``-w`` and ``-X name=value`` (poutine stamps its
release version with ``-X``).

Every entry records two dates (ISO ``YYYY-MM-DD``, UTC): ``released_at``, the day of the
upstream release (or PyPI upload) of the pinned version, and ``pinned_at``, the day the pin was
made or last checked again against the upstream checksums. ADR-0005 rule 1: the pin day is at
least :data:`MIN_RELEASE_AGE_DAYS` days after the release day (:func:`release_age_errors`).

The version probe (``kalkan.tools.resolve.probe_version``) runs ``version_args`` with the
minimal tool environment plus ``version_env``: the variables that turn off the update check or
the telemetry of the version command. ``version_args`` can name :data:`WORKDIR_URL`, the
``file://`` URL of the empty working folder of the probe.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from types import MappingProxyType
from typing import Any

from kalkan.errors import ToolError, ValidationError
from kalkan.tools.platform import PLATFORMS

DEFAULT_MANIFEST_PATH = Path(__file__).with_name("manifest.json")

SCHEMA_VERSION = 1
KINDS = ("binary", "toolchain", "pip", "go-install")
#: Kinds whose assets are downloaded from a URL with a pinned SHA-256.
ASSET_KINDS = ("binary", "toolchain")
ARCHIVES = ("zip", "tar.gz", "none")
SHA256_SOURCES = ("upstream-checksums", "computed-at-pin-time")
ASSET_URL_PREFIXES = ("https://", "file://")
#: ADR-0005 rule 1: a pin is made at least this many days after the upstream release.
MIN_RELEASE_AGE_DAYS = 14
#: Placeholder in ``version_args``: the ``file://`` URL of the empty working folder of the
#: version probe (govulncheck reads it as an empty local database instead of vuln.go.dev).
WORKDIR_URL = "{workdir_url}"
VERSION_PLACEHOLDERS = (WORKDIR_URL,)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_DATE_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
_ENV_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
_VERSION_RE = re.compile(r"^[0-9]+(?:\.[0-9]+){1,3}$")
_EXECUTABLE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_REQUIREMENT_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[A-Za-z0-9._,-]+\])?==([^\s;]+)$")
_GO_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+(?:\.[0-9]+)?$")
#: The ``go install`` flags that a go-install tool may name in ``build_flags``: ``-trimpath``,
#: and ``-ldflags=`` with only ``-s``, ``-w`` and ``-X name=value`` (no external linker or tool).
_LDFLAG = r"(?:-[sw]|-X [\w./-]+=[\w.+-]*)"
_BUILD_FLAG_RE = re.compile(rf"^(?:-trimpath|-ldflags={_LDFLAG}(?: {_LDFLAG})*)$")


def is_sha256(value: object) -> bool:
    """Return True when the value is a lower-case 64-character hex SHA-256 digest."""
    return isinstance(value, str) and _SHA256_RE.fullmatch(value) is not None


def tree_digest(files: Iterable[tuple[str, str]]) -> str:
    """Return the SHA-256 of a folder tree from ``(relative POSIX path, file SHA-256)`` pairs.

    The digest covers one line ``<file sha256>  <path>`` per file (the ``sha256sum`` format,
    each line ends with a line feed), sorted by path. Folders are not part of it. The same
    function computes the pinned value from the archive members and the installed value from
    the files on disk.
    """
    lines = "".join(f"{digest}  {path}\n" for path, digest in sorted(files))
    return hashlib.sha256(lines.encode("utf-8")).hexdigest()


def strip_v(version: str) -> str:
    """Remove a leading ``v`` from a version string (``v0.75.0`` gives ``0.75.0``)."""
    return version[1:] if version[:1] in ("v", "V") else version


@dataclass(frozen=True)
class Asset:
    """One downloadable build of a binary tool for one platform."""

    platform: str
    url: str
    sha256: str
    archive: str
    binary: str
    binary_sha256: str | None = None
    size: int | None = None
    root: str | None = None
    files: int | None = None
    tree_sha256: str | None = None


@dataclass(frozen=True)
class Tool:
    """One pinned tool from the manifest."""

    name: str
    version: str
    kind: str
    license: str
    executable: str
    version_args: tuple[str, ...] = ("--version",)
    blocked_versions: tuple[str, ...] = ()
    requires_go: bool = False
    platforms: Mapping[str, Asset] = field(default_factory=dict)
    notes: str = ""
    package: str | None = None
    requirement: str | None = None
    module: str | None = None
    min_go_version: str | None = None
    sha256_source: str | None = None
    data: Mapping[str, Any] = field(default_factory=dict)
    build_flags: tuple[str, ...] = ()
    version_env: Mapping[str, str] = field(default_factory=dict)
    released_at: str | None = None
    pinned_at: str | None = None

    def asset(self, platform_key: str) -> Asset | None:
        """Return the asset for the platform, or None when the release ships no build for it."""
        return self.platforms.get(platform_key)

    def is_blocked(self, version: str) -> bool:
        """Return True when the version (with or without a leading ``v``) is blocked."""
        return strip_v(version) in self.blocked_versions


@dataclass(frozen=True)
class Manifest:
    """The parsed tool manifest. ``tools`` keeps the order of the JSON file."""

    tools: Mapping[str, Tool]
    schema_version: int = SCHEMA_VERSION
    source: str = ""

    def names(self) -> list[str]:
        """Return the tool names in manifest order."""
        return list(self.tools)

    def get(self, name: str) -> Tool:
        """Return the tool or raise ToolError for an unknown name."""
        try:
            return self.tools[name]
        except KeyError:
            known = ", ".join(self.tools)
            raise ToolError(f"unknown tool {name!r} (known tools: {known})") from None

    def __contains__(self, name: object) -> bool:
        return name in self.tools

    def __iter__(self) -> Iterator[Tool]:
        return iter(self.tools.values())


def load_manifest(path: str | os.PathLike[str] | None = None) -> Manifest:
    """Read, validate and parse a manifest file (default: the packaged ``manifest.json``)."""
    target = Path(path) if path is not None else DEFAULT_MANIFEST_PATH
    try:
        text = target.read_text(encoding="utf-8")
    except OSError as exc:
        raise ToolError(f"cannot read the tool manifest {target}: {exc}") from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValidationError(f"the tool manifest {target} is not valid JSON", [str(exc)]) from exc
    return parse_manifest(data, source=str(target))


def parse_manifest(data: object, *, source: str = "<memory>") -> Manifest:
    """Validate a decoded manifest document and return the parsed Manifest."""
    errors = validate_manifest(data)
    if errors:
        raise ValidationError(f"the tool manifest {source} is invalid", errors)
    assert isinstance(data, dict)
    tools: dict[str, Tool] = {}
    for name, entry in data["tools"].items():
        tools[name] = _parse_tool(name, entry)
    return Manifest(
        tools=MappingProxyType(tools), schema_version=data["schema_version"], source=source
    )


def _parse_tool(name: str, entry: dict[str, Any]) -> Tool:
    platforms: dict[str, Asset] = {}
    for key, asset in (entry.get("platforms") or {}).items():
        platforms[key] = Asset(
            platform=key,
            url=asset["url"],
            sha256=asset["sha256"],
            archive=asset["archive"],
            binary=asset["binary"],
            binary_sha256=asset.get("binary_sha256"),
            size=asset.get("size"),
            root=asset.get("root"),
            files=asset.get("files"),
            tree_sha256=asset.get("tree_sha256"),
        )
    return Tool(
        name=name,
        version=entry["version"],
        kind=entry["kind"],
        license=entry["license"],
        executable=entry["executable"],
        version_args=tuple(entry.get("version_args", ["--version"])),
        blocked_versions=tuple(strip_v(v) for v in entry.get("blocked_versions", [])),
        requires_go=bool(entry.get("requires_go", False)),
        platforms=MappingProxyType(platforms),
        notes=entry.get("notes", ""),
        package=entry.get("package"),
        requirement=entry.get("requirement"),
        module=entry.get("module"),
        min_go_version=entry.get("min_go_version"),
        sha256_source=entry.get("sha256_source"),
        data=MappingProxyType(dict(entry)),
        build_flags=tuple(entry.get("build_flags", [])),
        version_env=MappingProxyType(dict(entry.get("version_env", {}))),
        released_at=entry.get("released_at"),
        pinned_at=entry.get("pinned_at"),
    )


def validate_manifest(data: object) -> list[str]:
    """Return a list of structure errors. An empty list means the manifest is valid."""
    errors: list[str] = []
    if not isinstance(data, dict):
        return ["manifest: must be a JSON object"]
    if data.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"schema_version: must be {SCHEMA_VERSION}")
    tools = data.get("tools")
    if not isinstance(tools, dict) or not tools:
        errors.append("tools: must be a non-empty object")
        return errors
    for name, entry in tools.items():
        prefix = f"tools.{name}"
        if not isinstance(name, str) or not _NAME_RE.fullmatch(name):
            errors.append(f"{prefix}: tool names use lower-case letters, digits and '-'")
        if not isinstance(entry, dict):
            errors.append(f"{prefix}: must be an object")
            continue
        errors.extend(_validate_tool(prefix, entry))
    return errors


def _validate_tool(prefix: str, entry: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    version = entry.get("version")
    if not isinstance(version, str) or not _VERSION_RE.fullmatch(version):
        errors.append(f"{prefix}.version: must be a version like 1.2.3 (no leading 'v')")
        version = None
    if not _is_text(entry.get("license")):
        errors.append(f"{prefix}.license: must be a non-empty string")
    kind = entry.get("kind")
    if kind not in KINDS:
        errors.append(f"{prefix}.kind: must be one of {', '.join(KINDS)}")
    executable = entry.get("executable")
    if not isinstance(executable, str) or not _EXECUTABLE_RE.fullmatch(executable):
        errors.append(f"{prefix}.executable: must be a plain file name without a path")
    version_args = entry.get("version_args", ["--version"])
    if not isinstance(version_args, list) or not all(_is_text(a) for a in version_args):
        errors.append(f"{prefix}.version_args: must be a list of strings")
    else:
        for arg in version_args:
            for placeholder in re.findall(r"\{[^{}]*\}", arg):
                if placeholder not in VERSION_PLACEHOLDERS:
                    errors.append(f"{prefix}.version_args: unknown placeholder {placeholder}")
    version_env = entry.get("version_env", {})
    if not isinstance(version_env, dict) or not all(
        isinstance(k, str) and _ENV_NAME_RE.fullmatch(k) and isinstance(v, str)
        for k, v in version_env.items()
    ):
        errors.append(f"{prefix}.version_env: must map upper-case variable names to string values")
    errors.extend(_validate_dates(prefix, entry))
    if not isinstance(entry.get("requires_go", False), bool):
        errors.append(f"{prefix}.requires_go: must be true or false")
    min_go = entry.get("min_go_version")
    if min_go is not None:
        if not isinstance(min_go, str) or not _GO_VERSION_RE.fullmatch(min_go):
            errors.append(f"{prefix}.min_go_version: must be a version like 1.26")
        elif entry.get("requires_go") is not True:
            errors.append(f"{prefix}.min_go_version: only for tools with requires_go true")
    if not isinstance(entry.get("notes", ""), str):
        errors.append(f"{prefix}.notes: must be a string")
    blocked = entry.get("blocked_versions")
    if not isinstance(blocked, list) or not all(_is_text(v) for v in blocked):
        errors.append(f"{prefix}.blocked_versions: must be a list of version strings")
    elif version is not None and version in {strip_v(v) for v in blocked}:
        errors.append(f"{prefix}.version: {version} is a blocked version")

    if kind == "binary":
        errors.extend(_validate_binary_tool(prefix, entry))
    elif kind == "toolchain":
        errors.extend(_validate_binary_tool(prefix, entry))
        errors.extend(_validate_toolchain(prefix, entry))
    elif kind == "pip":
        errors.extend(_validate_pip_tool(prefix, entry, version))
    elif kind == "go-install":
        errors.extend(_validate_go_tool(prefix, entry, version))
    if "build_flags" in entry:
        flags = entry["build_flags"]
        if kind != "go-install":
            errors.append(f"{prefix}.build_flags: only for go-install tools")
        elif not isinstance(flags, list) or not all(
            isinstance(flag, str) and _BUILD_FLAG_RE.fullmatch(flag) for flag in flags
        ):
            errors.append(
                f"{prefix}.build_flags: must be a list of -trimpath and -ldflags= with only "
                "-s, -w and -X name=value"
            )
    return errors


def parse_date(value: object) -> date | None:
    """Return the date of an ISO ``YYYY-MM-DD`` string, or None for anything else."""
    if not isinstance(value, str) or not _DATE_RE.fullmatch(value):
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        return None


def _validate_dates(prefix: str, entry: dict[str, Any]) -> list[str]:
    """``released_at`` and ``pinned_at``: ISO dates, the release not after the pin."""
    errors: list[str] = []
    found: dict[str, date] = {}
    for key in ("released_at", "pinned_at"):
        if key not in entry:
            continue
        parsed = parse_date(entry[key])
        if parsed is None:
            errors.append(f"{prefix}.{key}: must be an ISO date like 2026-10-25")
        else:
            found[key] = parsed
    if len(found) == 2 and found["released_at"] > found["pinned_at"]:
        errors.append(f"{prefix}.pinned_at: must not be before released_at")
    return errors


def release_age_errors(data: object, *, min_days: int = MIN_RELEASE_AGE_DAYS) -> list[str]:
    """Return one message per tool entry that breaks ADR-0005 rule 1.

    Every entry needs ``released_at`` and ``pinned_at`` (ISO dates), and the pin day is at least
    ``min_days`` days after the release day. A unit test runs it on the packaged manifest. An
    empty list means that every entry obeys the rule.
    """
    tools = data.get("tools") if isinstance(data, dict) else None
    if not isinstance(tools, dict):
        return ["tools: must be an object"]
    errors: list[str] = []
    for name, entry in tools.items():
        entry = entry if isinstance(entry, dict) else {}
        released = parse_date(entry.get("released_at"))
        pinned = parse_date(entry.get("pinned_at"))
        if released is None or pinned is None:
            errors.append(f"tools.{name}: needs released_at and pinned_at (ISO dates)")
            continue
        age = (pinned - released).days
        if age < min_days:
            errors.append(
                f"tools.{name}: pinned on {pinned.isoformat()}, {age} days after the release on "
                f"{released.isoformat()}; ADR-0005 needs at least {min_days} days"
            )
    return errors


def _validate_binary_tool(prefix: str, entry: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    source = entry.get("sha256_source")
    if source not in SHA256_SOURCES:
        errors.append(f"{prefix}.sha256_source: must be one of {', '.join(SHA256_SOURCES)}")
    if source == "upstream-checksums" and not _is_url(entry.get("checksums_url")):
        errors.append(f"{prefix}.checksums_url: required for sha256_source upstream-checksums")
    if "checksums_sha256" in entry and not is_sha256(entry["checksums_sha256"]):
        errors.append(f"{prefix}.checksums_sha256: must be a 64-character lower-case hex digest")
    platforms = entry.get("platforms")
    if not isinstance(platforms, dict) or not platforms:
        errors.append(f"{prefix}.platforms: must be a non-empty object")
        return errors
    notes = entry.get("notes", "") if isinstance(entry.get("notes", ""), str) else ""
    for key in PLATFORMS:
        if key not in platforms and key not in notes:
            errors.append(f"{prefix}.platforms: {key} is missing and notes do not explain why")
    for key, asset in platforms.items():
        where = f"{prefix}.platforms.{key}"
        if key not in PLATFORMS:
            errors.append(f"{where}: unknown platform (known: {', '.join(PLATFORMS)})")
        if not isinstance(asset, dict):
            errors.append(f"{where}: must be an object")
            continue
        errors.extend(_validate_asset(where, asset))
    return errors


def _validate_asset(where: str, asset: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    url = asset.get("url")
    if not isinstance(url, str) or not url.startswith(ASSET_URL_PREFIXES):
        errors.append(f"{where}.url: must be an https:// (or file://) URL")
    if not is_sha256(asset.get("sha256")):
        errors.append(f"{where}.sha256: must be a 64-character lower-case hex digest")
    archive = asset.get("archive")
    if archive not in ARCHIVES:
        errors.append(f"{where}.archive: must be one of {', '.join(ARCHIVES)}")
    binary = asset.get("binary")
    if not isinstance(binary, str) or not is_safe_member_name(binary):
        errors.append(f"{where}.binary: must be a safe relative path inside the archive")
    elif archive == "none" and "/" in binary:
        errors.append(f"{where}.binary: must be a plain file name when archive is none")
    if "binary_sha256" in asset:
        if not is_sha256(asset["binary_sha256"]):
            errors.append(f"{where}.binary_sha256: must be a 64-character lower-case hex digest")
        elif archive == "none" and asset["binary_sha256"] != asset.get("sha256"):
            errors.append(f"{where}.binary_sha256: must equal sha256 when archive is none")
    size = asset.get("size")
    if size is not None and (not isinstance(size, int) or isinstance(size, bool) or size <= 0):
        errors.append(f"{where}.size: must be a positive integer")
    return errors


def _validate_toolchain(prefix: str, entry: dict[str, Any]) -> list[str]:
    """Extra checks for a ``toolchain`` asset: a whole archive tree below one top folder."""
    errors: list[str] = []
    if entry.get("requires_go", False):
        errors.append(f"{prefix}.requires_go: a toolchain does not require Go")
    platforms = entry.get("platforms")
    if not isinstance(platforms, dict):
        return errors
    for key, asset in platforms.items():
        where = f"{prefix}.platforms.{key}"
        if not isinstance(asset, dict):
            continue
        if asset.get("archive") not in ("zip", "tar.gz"):
            errors.append(f"{where}.archive: a toolchain must be a zip or tar.gz archive")
        root = asset.get("root")
        if not isinstance(root, str) or not is_safe_member_name(root) or "/" in root:
            errors.append(f"{where}.root: must be the top folder name of the archive")
        else:
            binary = asset.get("binary")
            if isinstance(binary, str) and not binary.startswith(root + "/"):
                errors.append(f"{where}.binary: must be inside the root folder {root}")
        files = asset.get("files")
        if not isinstance(files, int) or isinstance(files, bool) or files <= 0:
            errors.append(f"{where}.files: must be the positive number of files in the archive")
        if not is_sha256(asset.get("tree_sha256")):
            errors.append(f"{where}.tree_sha256: must be a 64-character lower-case hex digest")
        if not is_sha256(asset.get("binary_sha256")):
            errors.append(f"{where}.binary_sha256: must be a 64-character lower-case hex digest")
    return errors


def _validate_pip_tool(prefix: str, entry: dict[str, Any], version: str | None) -> list[str]:
    errors: list[str] = []
    package = entry.get("package")
    if not _is_text(package):
        errors.append(f"{prefix}.package: must be a non-empty string")
    requirement = entry.get("requirement")
    match = _REQUIREMENT_RE.fullmatch(requirement) if isinstance(requirement, str) else None
    if match is None:
        errors.append(f"{prefix}.requirement: must pin an exact version: name[extras]==version")
        return errors
    if _is_text(package) and _normalize_dist(match.group(1)) != _normalize_dist(package):
        errors.append(f"{prefix}.requirement: names {match.group(1)}, expected {package}")
    if version is not None and match.group(3) != version:
        errors.append(f"{prefix}.requirement: pins {match.group(3)}, expected {version}")
    return errors


def _validate_go_tool(prefix: str, entry: dict[str, Any], version: str | None) -> list[str]:
    errors: list[str] = []
    module = entry.get("module")
    if not _is_text(module) or "@" not in module:
        errors.append(f"{prefix}.module: must be a module path with @version")
    elif version is not None and not module.endswith(f"@v{version}"):
        errors.append(f"{prefix}.module: must end with @v{version}")
    if entry.get("requires_go") is not True:
        errors.append(f"{prefix}.requires_go: must be true for go-install tools")
    return errors


def is_safe_member_name(name: str) -> bool:
    """Return True for a relative POSIX path without '..', drive letters or backslashes."""
    if not name or "\\" in name or "\x00" in name or name.startswith("/"):
        return False
    if re.match(r"^[A-Za-z]:", name):
        return False
    parts = name.split("/")
    return all(part not in ("", ".", "..") for part in parts)


def _normalize_dist(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _is_text(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _is_url(value: object) -> bool:
    return isinstance(value, str) and value.startswith(ASSET_URL_PREFIXES)
