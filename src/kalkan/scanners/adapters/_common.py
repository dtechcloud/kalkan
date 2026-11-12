# SPDX-License-Identifier: MIT
"""Helpers shared by several adapters: file discovery, Go modules and the Go environment."""

from __future__ import annotations

import os
import re
from collections.abc import Callable, Iterable
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any

from kalkan.scanners.base import ScanContext
from kalkan.tools import toolhome

if TYPE_CHECKING:
    from kalkan.tools.golang import GoToolchain

#: The Go build cache of a Go tool run inside its work folder (``GOCACHE``).
GO_CACHE_DIRNAME = "go-cache"
#: ``GOPATH`` of a Go tool run with ``--online`` inside its work folder (module downloads).
GO_PATH_DIRNAME = "go-path"

#: Go variables that pass through to gosec and govulncheck (module proxy, module cache, flags).
#: ``GOCACHE`` is not one of them: the build cache is a folder of the run (:func:`go_env`).
GO_PASSTHROUGH = (
    "GOPATH",
    "GOROOT",
    "GOMODCACHE",
    "GOPROXY",
    "GOPRIVATE",
    "GONOPROXY",
    "GONOSUMDB",
    "GOSUMDB",
    "GOFLAGS",
    "GOINSECURE",
)
#: The CycloneDX file in ``sca/`` with the exact pins of manifests without a lockfile
#: (:mod:`kalkan.sca.manifests`); ``osv-scanner-pins`` and ``grype-pins`` read it.
PINS_SBOM_NAME = "manifest-pins.cdx.json"
#: Path segments whose go.mod files are not modules of the target.
_GO_SKIP_SEGMENTS = frozenset({"vendor", "testdata"})
#: ``partial_packages`` lists at most this many packages, files per package and errors.
MAX_PARTIAL_PACKAGES = 50
MAX_PARTIAL_FILES = 10
MAX_PARTIAL_ERRORS = 5
#: Go load errors that name a package whose module Go could not load.
_MISSING_IMPORT = (
    re.compile(r"could not import (\S+)"),
    re.compile(r"no required module provides package (\S+?)[;:]"),
    re.compile(r"missing go\.sum entry for module providing package (\S+)"),
    re.compile(r"cannot find module providing package (\S+?)[;:]"),
    re.compile(r"module lookup disabled by GOPROXY=off"),
)


def target_files(root: Path) -> list[str]:
    """Return the target-relative POSIX paths of all regular files (no links, sorted).

    The walk skips ``.git``, ``node_modules``, ``.venv``, ``venv``, ``dist`` and ``build``
    (:func:`kalkan.matchers.engine.list_files`).
    """
    from kalkan.matchers.engine import list_files  # lazy: phase 2 module

    return list_files(root)


def find_executable(name: str) -> Path | None:
    """Return the path of ``name`` on PATH (never the current directory), or None."""
    from kalkan.tools.platform import find_on_path

    return find_on_path(name)


#: Replaced in tests.
executable_finder: Callable[[str], Path | None] = find_executable


def find_go(allow_path: bool = False) -> GoToolchain | None:
    """Return the Go toolchain of the Go tools (:func:`kalkan.tools.golang.resolve_go`).

    The kalkan copy in ``.tools/go`` comes first; a system Go counts only when its version is
    at least the required one (any version with ``allow_path``). None when neither exists.
    """
    from kalkan.errors import KalkanError
    from kalkan.tools.golang import resolve_go  # lazy: keeps the import graph small

    try:
        return resolve_go(allow_path=allow_path)
    except KalkanError:
        return None


#: ``go_resolver(allow_path) -> GoToolchain | None``. Replaced in tests.
go_resolver: Callable[[bool], GoToolchain | None] = find_go


def go_installed(allow_path: bool = False) -> bool:
    """Return True when an acceptable Go toolchain exists (:func:`find_go`)."""
    return go_resolver(allow_path) is not None


def git_installed() -> bool:
    """Return True when ``git`` is on PATH."""
    return executable_finder("git") is not None


def go_modules(target: Path) -> list[str]:
    """Return the target-relative folders that hold a ``go.mod`` (``""`` for the root).

    ``vendor`` and ``testdata`` folders are skipped.
    """
    modules: list[str] = []
    for rel in target_files(target):
        path = PurePosixPath(rel)
        if path.name != "go.mod":
            continue
        if _GO_SKIP_SEGMENTS.intersection(path.parts[:-1]):
            continue
        parent = path.parent.as_posix()
        modules.append("" if parent == "." else parent)
    return sorted(set(modules))


def go_env(ctx: ScanContext, work: Path | None = None) -> dict[str, str]:
    """Return the environment of the Go tools.

    The ``bin`` folder of the Go of :func:`find_go` comes first on PATH: gosec and govulncheck
    start ``go list`` to load the packages. For the kalkan copy ``GOROOT`` names its tree (a
    ``GOROOT`` of the user would point at another Go). ``GOTOOLCHAIN=local`` stops Go from
    downloading and running the toolchain that a target ``go.mod`` names. Local mode (the
    default, docs/SECURITY.md) also sets ``GOPROXY=off`` and ``GOSUMDB=off``: Go downloads no
    module (the module paths and versions of the target would go to the proxy and the checksum
    database), also not for a ``GONOPROXY`` or ``GOPRIVATE`` path. Packages whose modules are
    not in the local module cache or a ``vendor`` folder then load with errors; gosec still
    checks their syntax.

    ``work`` is the work folder of the adapter (:func:`go_prepare` fills it). Go then keeps its
    build cache there (``GOCACHE``; ``go list`` filled ``%LOCALAPPDATA%\\go-build`` with 93 MB
    for vulnapp before) and reads its configuration from there (telemetry off,
    :mod:`kalkan.tools.toolhome`). With ``--online`` the module downloads go there too
    (``GOPATH``, ``GOMODCACHE``). In local mode the module cache of the user stays: Go only
    reads it.
    """
    from kalkan.tools.golang import run_env  # lazy: keeps the import graph small

    env = {key: os.environ[key] for key in GO_PASSTHROUGH if os.environ.get(key)}
    go = go_resolver(ctx.allow_path_tools)
    if go is not None:
        env.update(run_env(go))
    env["GOTOOLCHAIN"] = "local"
    if ctx.offline:
        env["GOPROXY"] = "off"
        env["GOSUMDB"] = "off"
    if work is not None:
        env["GOCACHE"] = str(work / GO_CACHE_DIRNAME)
        config = toolhome.go_config_env(work / toolhome.GO_CONFIG_DIRNAME)
        env.update(config)
        if "HOME" in config:  # macOS: keep the module cache of the user readable
            env.setdefault("GOPATH", toolhome.user_gopath())
        if not ctx.offline:
            gopath = work / GO_PATH_DIRNAME
            env["GOPATH"] = str(gopath)
            env["GOMODCACHE"] = str(gopath / "pkg" / "mod")
    return env


def go_prepare(work: Path) -> None:
    """Create the build cache and the Go configuration folder (telemetry off) of
    :func:`go_env` in the work folder ``work``."""
    (work / GO_CACHE_DIRNAME).mkdir(parents=True, exist_ok=True)
    toolhome.go_telemetry_off(work / toolhome.GO_CONFIG_DIRNAME)


def go_vendored(module_dir: Path) -> bool:
    """Return True when a Go module folder has ``vendor/modules.txt`` (a vendored module)."""
    try:
        return (module_dir / "vendor" / "modules.txt").is_file()
    except OSError:
        return False


def go_module_env(module_dir: Path) -> tuple[tuple[str, str], ...]:
    """Return the variables of one Go module run (:attr:`Invocation.env`).

    A module with ``vendor/modules.txt`` gets ``GOFLAGS=-mod=vendor``: Go loads the packages of
    its dependencies from the ``vendor`` folder of the target, so local mode needs no module
    cache and no download for it. A ``-mod`` flag in the ``GOFLAGS`` of the user is replaced;
    the other flags stay. Other modules get nothing (the adapter environment applies).
    """
    if not go_vendored(module_dir):
        return ()
    flags = [
        flag
        for flag in os.environ.get("GOFLAGS", "").split()
        if not flag.startswith(("-mod=", "--mod="))
    ]
    return (("GOFLAGS", " ".join([*flags, "-mod=vendor"])),)


def go_applies(ctx: ScanContext, engine: str) -> tuple[bool, str]:
    """The common gate of gosec and govulncheck: the tech tag ``go``, a Go toolchain, a module."""
    if "go" not in ctx.tech:
        return False, "the target has no Go code (tech tag 'go' missing)"
    if not go_installed(ctx.allow_path_tools):
        return False, (
            f"Go is not installed: {engine} needs the Go toolchain (run: kalkan tools install go)"
        )
    if not go_modules(ctx.target_dir):
        return False, "no go.mod found in the target"
    return True, ""


def go_load_reason(missing: Iterable[str], *, offline: bool) -> str:
    """Return the reason text of a package that loaded with errors."""
    names = ", ".join(sorted(set(missing)))
    if not names:
        return "the package has load errors (syntax or type errors)"
    if offline:
        return (
            f"the module of {names} is not in the local module cache or a vendor folder "
            "(local mode downloads no Go module: GOPROXY=off)"
        )
    return f"the module of {names} could not be loaded"


def go_missing_import(message: str) -> str | None:
    """Return the import path that a Go load error names as not loadable, or None.

    An error without a path that still says that the module could not be looked up (for
    example ``module lookup disabled by GOPROXY=off``) gives ``""``.
    """
    for pattern in _MISSING_IMPORT:
        match = pattern.search(message)
        if match is not None:
            return match.group(1).strip("\"'") if match.groups() else ""
    return None


def go_relative(path: str, target: Path, module_dir: Path) -> str:
    """Return a Go tool file path relative to the target (POSIX), or the path itself.

    An absolute path must be inside the target; a relative path is relative to the module
    folder (the working directory of the tool).
    """
    text = path.strip()
    candidate = Path(text)
    if not candidate.is_absolute():
        candidate = module_dir / candidate
    try:
        return candidate.resolve().relative_to(target.resolve()).as_posix()
    except (OSError, ValueError):
        return text.replace("\\", "/")


def go_partial_packages(
    errors: Iterable[tuple[str, str]], *, offline: bool, hint: str
) -> dict[str, Any]:
    """Group Go load errors by package folder into the ``partial_packages`` status record.

    ``errors`` holds ``(target-relative file, message)`` pairs; the package is the folder of the
    file (``.`` for the target root). Return ``{}`` without errors, else ``{count, packages
    [{package, files, missing_imports, errors, reason}] (at most 50), truncated, mode, hint}``.
    """
    packages: dict[str, dict[str, Any]] = {}
    for file, message in errors:
        file = file.strip() or "."
        folder = PurePosixPath(file).parent.as_posix() if file.endswith(".go") else file
        entry = packages.setdefault(
            folder,
            {"package": folder, "files": [], "missing_imports": [], "errors": []},
        )
        if file.endswith(".go") and file not in entry["files"]:
            entry["files"].append(file)
        missing = go_missing_import(message)
        if missing and missing not in entry["missing_imports"]:
            entry["missing_imports"].append(missing)
        if missing is not None:
            entry["missing_module"] = True
        text = message.strip()
        if text and text not in entry["errors"]:
            entry["errors"].append(text)
    if not packages:
        return {}
    listed = []
    for name in sorted(packages):
        entry = packages[name]
        missing_module = entry.pop("missing_module", False)
        imports = sorted(entry["missing_imports"])
        named = (imports or ["an imported package"]) if missing_module else []
        reason = go_load_reason(named, offline=offline)
        listed.append(
            {
                "package": entry["package"],
                "files": sorted(entry["files"])[:MAX_PARTIAL_FILES],
                "missing_imports": imports,
                "errors": entry["errors"][:MAX_PARTIAL_ERRORS],
                "reason": reason,
            }
        )
    return {
        "count": len(listed),
        "packages": listed[:MAX_PARTIAL_PACKAGES],
        "truncated": len(listed) > MAX_PARTIAL_PACKAGES,
        "mode": "local" if offline else "online",
        "hint": hint,
    }
