# SPDX-License-Identifier: MIT
"""The Go toolchain for gosec and govulncheck (docs/ENGINE-SPEC.md, sections 12 and 13).

The manifest pins Go as a tool of kind ``toolchain`` (name ``go``). :func:`resolve_go` returns
the Go that the Go tools use:

1. the kalkan copy under ``.tools/go/<version>/go`` (``GOROOT``);
2. else a system Go on PATH whose version is at least :func:`kalkan.tools.resolve.
   required_go_version` (the highest ``min_go_version`` of the tools that need Go);
3. else None. ``kalkan tools install go`` fixes it.

:func:`run_env` gives the environment changes that run a Go tool with that Go: its ``bin``
folder first on PATH (gosec and govulncheck start ``go list`` to load packages), ``GOROOT`` for
the kalkan copy and ``GOTOOLCHAIN=local``. :func:`build_env` gives the full environment of a
``go install`` build: the same Go, plus ``GOPATH``, ``GOMODCACHE``, ``GOCACHE``, ``GOTMPDIR``
and ``GOBIN`` under ``.tools``, the Go configuration folder ``.tools/go-build/config`` (its
``go/telemetry/mode`` says ``off``, so the build writes no telemetry counters into the profile;
:mod:`kalkan.tools.toolhome`), ``GOENV=off`` (no user ``go env -w`` settings), ``GOWORK=off``,
``CGO_ENABLED=0`` and no other ``GO*`` or ``CGO_*`` variable of the caller (a ``GOFLAGS``,
``GONOSUMDB`` or ``GOOS`` of the user cannot change or weaken the build). ``GOPROXY`` and
``GONOPROXY`` stay: the checksum database still verifies every module.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from kalkan.errors import KalkanError
from kalkan.tools import toolhome
from kalkan.tools.manifest import Manifest, Tool, load_manifest
from kalkan.tools.platform import Finder, Runner, platform_key
from kalkan.tools.resolve import (
    SOURCE_KALKAN,
    default_repo_root,
    go_build_dir,
    required_go_version,
    resolve,
    toolchain_root,
)

GO_TOOL = "go"
#: Variables of the caller that a ``go install`` build keeps (module transport only).
BUILD_PASSTHROUGH = ("GOPROXY", "GONOPROXY")


@dataclass(frozen=True)
class GoToolchain:
    """A Go toolchain that kalkan can run.

    ``root`` is the ``GOROOT`` of the kalkan copy. It is None for a system Go, which finds its
    own root (a ``GOROOT`` of the environment then stays).
    """

    path: Path
    version: str
    source: str
    root: Path | None = None

    @property
    def bin_dir(self) -> Path:
        """Return the folder of the ``go`` executable."""
        return self.path.parent

    def to_dict(self) -> dict[str, str | None]:
        """Return a JSON-ready dict (paths use forward slashes)."""
        return {
            "path": self.path.as_posix(),
            "version": self.version,
            "source": self.source,
            "root": self.root.as_posix() if self.root is not None else None,
        }


def toolchain_tool(manifest: Manifest) -> Tool | None:
    """Return the Go toolchain entry of the manifest, or None."""
    if GO_TOOL in manifest and manifest.get(GO_TOOL).kind == "toolchain":
        return manifest.get(GO_TOOL)
    return None


def resolve_go(
    repo_root: str | os.PathLike[str] | None = None,
    *,
    manifest: Manifest | None = None,
    key: str | None = None,
    runner: Runner | None = None,
    path_env: str | None = None,
    finder: Finder | None = None,
    allow_path: bool = False,
) -> GoToolchain | None:
    """Return the Go toolchain for the Go tools, or None when no acceptable Go exists.

    Order: the kalkan copy, then a system Go of at least the required version (any version
    with ``allow_path``).
    """
    manifest = manifest or load_manifest()
    tool = toolchain_tool(manifest)
    if tool is None:
        return None
    root = Path(repo_root) if repo_root is not None else default_repo_root()
    try:
        key = key or platform_key()
    except KalkanError:
        key = None
    if key is None:
        return None
    found = resolve(
        tool.name,
        repo_root=root,
        allow_path=allow_path,
        manifest=manifest,
        key=key,
        runner=runner,
        path_env=path_env,
        finder=finder,
    )
    if found is None:
        return None
    goroot = toolchain_root(root, tool, key) if found.source == SOURCE_KALKAN else None
    return GoToolchain(found.path, str(found.version), found.source, goroot)


def required_version(manifest: Manifest | None = None) -> str | None:
    """Return the lowest system Go version that kalkan accepts (for messages)."""
    return required_go_version(manifest or load_manifest())


def run_env(go: GoToolchain, *, environ: Mapping[str, str] | None = None) -> dict[str, str]:
    """Return the variables that run a Go tool with ``go``: PATH, GOROOT, GOTOOLCHAIN.

    PATH is the ``bin`` folder of ``go``, then the PATH of ``environ`` (default: the process
    environment). ``GOROOT`` is set only for the kalkan copy.
    """
    source = os.environ if environ is None else environ
    current = source.get("PATH") or source.get("Path") or ""
    path = str(go.bin_dir) + (os.pathsep + current if current else "")
    env = {"PATH": path, "GOTOOLCHAIN": "local"}
    if go.root is not None:
        env["GOROOT"] = str(go.root)
    return env


def build_env(
    repo_root: str | os.PathLike[str],
    go: GoToolchain,
    gobin: str | os.PathLike[str],
    *,
    environ: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Return the full environment of ``go install`` for a go-install tool (module docstring)."""
    source = dict(os.environ if environ is None else environ)
    env = {
        name: value
        for name, value in source.items()
        if not name.upper().startswith(("GO", "CGO_")) or name.upper() in BUILD_PASSTHROUGH
    }
    build = go_build_dir(repo_root)
    gopath = build / "gopath"
    fixed = {
        **run_env(go, environ=source),
        **toolhome.go_config_env(config_dir(repo_root)),
        "GOPATH": str(gopath),
        "GOMODCACHE": str(gopath / "pkg" / "mod"),
        "GOCACHE": str(build / "cache"),
        "GOTMPDIR": str(build / "tmp"),
        "GOBIN": os.fspath(gobin),
        "GOENV": "off",
        "GOWORK": "off",
        "CGO_ENABLED": "0",
    }
    if os.name == "nt":  # one spelling of PATH and APPDATA on Windows
        for name in [n for n in env if n.upper() in fixed and n not in fixed]:
            del env[name]
    env.update(fixed)
    return env


def config_dir(repo_root: str | os.PathLike[str]) -> Path:
    """Return ``.tools/go-build/config``, the Go configuration folder of the builds."""
    return go_build_dir(repo_root) / "config"


def build_dirs(repo_root: str | os.PathLike[str]) -> list[Path]:
    """Return the folders that :func:`build_env` names (GOPATH, GOCACHE, GOTMPDIR, the Go
    configuration folder); create them first and call :func:`prepare_build`."""
    build = go_build_dir(repo_root)
    return [build / "gopath", build / "cache", build / "tmp", config_dir(repo_root)]


def prepare_build(repo_root: str | os.PathLike[str]) -> None:
    """Create the folders of :func:`build_dirs` and turn Go telemetry off for the builds."""
    for folder in build_dirs(repo_root):
        folder.mkdir(parents=True, exist_ok=True)
    toolhome.go_telemetry_off(config_dir(repo_root))
