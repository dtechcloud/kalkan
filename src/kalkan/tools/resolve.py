# SPDX-License-Identifier: MIT
"""Find the executable of a pinned tool (docs/ENGINE-SPEC.md, section 12).

``resolve(name)`` prefers the copy that ``kalkan tools install`` placed under ``<repo>/.tools``.
It accepts a binary on PATH only when the version output of that binary matches the manifest
version, or when the caller sets ``allow_path=True``. A blocked version is never accepted.
A toolchain on PATH (a system Go) is accepted when its version is at least the required
version (:func:`required_go_version`), not only the pinned one.

Version probes (:func:`probe_version`, :func:`probe_tool_version`, :func:`go_toolchain_version`;
``kalkan doctor`` and ``resolve`` use them) never run with the environment of the user. They get
the minimal tool environment of the adapters (:func:`probe_env`, docs/SECURITY.md promise 3):
no token or other secret reaches the tool, and the proxy variables stay. A probe of a manifest
tool adds the ``version_env`` of the tool (update checks and telemetry off) and runs its
``version_args`` in a new empty working folder, so that no configuration file of the current
folder is read. That folder is also the temporary folder of the probe (``TEMP``, ``TMP``,
``TMPDIR``) and, for a Go program, the Go configuration folder (no telemetry counters in the
profile). opengrep gets its kalkan profile folder and logs into the working folder
(:mod:`kalkan.tools.toolhome`). The folder is removed after the probe.

This module also owns the on-disk layout of ``.tools``:

```
.tools/installed.json                    what kalkan installed (tool, version, path, SHA-256)
.tools/<tool>/<version>/bin/<executable>  binary and go-install tools
.tools/go/<version>/go/                  the Go toolchain tree (GOROOT; kind toolchain)
.tools/go-build/gopath/                  GOPATH and GOMODCACHE of the go-install builds
.tools/go-build/cache/                   GOCACHE of the go-install builds
.tools/go-build/config/, tmp/            Go configuration (telemetry off) and GOTMPDIR of them
.tools/pyenv/                            venv for the pip tools (checkov, bandit)
.tools/cache/opengrep/                   profile folder of opengrep: its unpacked runtime
.tools/vulndb/                           local vulnerability databases (kalkan.sca.vulndb)
.tools/.tmp/                             downloads of tools install before their check
```

``tools install`` deletes ``.tools/go-build`` after the go-install builds of a call
(:func:`kalkan.tools.install.remove_go_build`). ``.tools/cache`` holds data that tools keep
between runs and that holds nothing of a target (:mod:`kalkan.tools.toolhome`).
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from kalkan import resources
from kalkan.errors import KalkanError
from kalkan.tools import toolhome
from kalkan.tools.manifest import WORKDIR_URL, Manifest, Tool, load_manifest, strip_v
from kalkan.tools.platform import (
    Finder,
    Runner,
    exe_suffix,
    find_on_path,
    platform_key,
    run_command,
)

TOOLS_DIRNAME = ".tools"
INSTALLED_FILENAME = "installed.json"
PYENV_DIRNAME = "pyenv"
GO_BUILD_DIRNAME = "go-build"
INSTALLED_SCHEMA_VERSION = 1
VERSION_TIMEOUT_SECONDS = 30.0
#: The Go version in the output of ``go env GOVERSION`` or ``go version`` (``go1.26.9``).
GO_VERSION_RE = re.compile(r"(?<![0-9A-Za-z])go([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?![0-9.])")

SOURCE_KALKAN = "kalkan"
SOURCE_PATH = "path"
#: The tool that gets its kalkan profile folder (:mod:`kalkan.tools.toolhome`).
OPENGREP = "opengrep"


@dataclass(frozen=True)
class ResolvedTool:
    """A runnable tool: path, version and where it came from (``kalkan`` or ``path``).

    Start the tool with ``argv`` plus the tool arguments, not with ``path`` alone: a pip tool
    whose entry point is a plain Python script (checkov on Windows) runs through the Python of
    the tool venv.
    """

    name: str
    path: Path
    version: str
    source: str
    command: tuple[str, ...] = ()

    @property
    def argv(self) -> list[str]:
        """Return the argument list prefix that starts the tool."""
        return list(self.command) if self.command else [str(self.path)]

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-ready dict (paths use forward slashes)."""
        return {
            "name": self.name,
            "path": self.path.as_posix(),
            "version": self.version,
            "source": self.source,
            "argv": [Path(arg).as_posix() for arg in self.argv],
        }


def default_repo_root() -> Path:
    """Return the kalkan home that holds ``.tools`` (:func:`kalkan.resources.home`)."""
    return resources.home()


def tools_root(repo_root: str | os.PathLike[str]) -> Path:
    """Return ``<repo>/.tools``."""
    return Path(repo_root) / TOOLS_DIRNAME


def installed_json_path(repo_root: str | os.PathLike[str]) -> Path:
    """Return ``<repo>/.tools/installed.json``."""
    return tools_root(repo_root) / INSTALLED_FILENAME


def tool_dir(repo_root: str | os.PathLike[str], tool: Tool) -> Path:
    """Return ``<repo>/.tools/<tool>/<version>``."""
    return tools_root(repo_root) / tool.name / tool.version


def tool_bin_dir(repo_root: str | os.PathLike[str], tool: Tool) -> Path:
    """Return ``<repo>/.tools/<tool>/<version>/bin``."""
    return tool_dir(repo_root, tool) / "bin"


def binary_path(repo_root: str | os.PathLike[str], tool: Tool, key: str) -> Path:
    """Return the install path of the executable of a tool for a platform key.

    A toolchain keeps the archive tree: ``<repo>/.tools/go/<version>/go/bin/go.exe``.
    """
    asset = tool.asset(key) if tool.kind == "toolchain" else None
    if asset is not None:
        return tool_dir(repo_root, tool) / asset.binary
    return tool_bin_dir(repo_root, tool) / (tool.executable + exe_suffix(key))


def toolchain_root(repo_root: str | os.PathLike[str], tool: Tool, key: str) -> Path | None:
    """Return the root folder of a toolchain tree (GOROOT) for a platform key, or None."""
    asset = tool.asset(key)
    if tool.kind != "toolchain" or asset is None or not asset.root:
        return None
    return tool_dir(repo_root, tool) / asset.root


def go_build_dir(repo_root: str | os.PathLike[str]) -> Path:
    """Return ``<repo>/.tools/go-build``: GOPATH and GOCACHE of the go-install builds."""
    return tools_root(repo_root) / GO_BUILD_DIRNAME


def pyenv_dir(repo_root: str | os.PathLike[str]) -> Path:
    """Return ``<repo>/.tools/pyenv``, the venv of the pip tools."""
    return tools_root(repo_root) / PYENV_DIRNAME


def pyenv_python(repo_root: str | os.PathLike[str]) -> Path:
    """Return the Python interpreter of the tool venv for this host."""
    if os.name == "nt":
        return pyenv_dir(repo_root) / "Scripts" / "python.exe"
    return pyenv_dir(repo_root) / "bin" / "python"


def pyenv_script(repo_root: str | os.PathLike[str], executable: str) -> Path | None:
    """Return the entry point of a pip tool in the tool venv, or None when it is missing.

    On Windows this is ``Scripts/<name>.exe`` or, for packages that ship a plain script (checkov),
    the extension-less Python script ``Scripts/<name>``. A ``.cmd`` or ``.bat`` launcher is never
    used: ``checkov.cmd`` starts whatever ``python`` is on PATH, not the tool venv.
    """
    if os.name == "nt":
        scripts = pyenv_dir(repo_root) / "Scripts"
        candidates = [scripts / f"{executable}.exe", scripts / executable]
    else:
        candidates = [pyenv_dir(repo_root) / "bin" / executable]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def pyenv_command(repo_root: str | os.PathLike[str], script: str | os.PathLike[str]) -> list[str]:
    """Return the argv prefix that runs a tool venv entry point on this host.

    A script runs with the Python of the tool venv, also on Linux and macOS: its ``#!`` line
    holds the absolute path of the venv at install time, so a moved checkout gave "bad
    interpreter" for checkov, bandit, flawfinder and gixy (macOS, 2026-11-13). The Python of a
    moved venv still finds its packages (``pyvenv.cfg`` sits next to it). A Windows ``.exe``
    launcher runs on its own.
    """
    path = Path(script)
    if os.name == "nt" and path.suffix.lower() == ".exe":
        return [str(path)]
    return [str(pyenv_python(repo_root)), str(path)]


def read_installed(repo_root: str | os.PathLike[str]) -> dict[str, Any]:
    """Read ``.tools/installed.json``. A missing or unreadable file gives an empty record."""
    empty: dict[str, Any] = {"schema_version": INSTALLED_SCHEMA_VERSION, "tools": {}}
    path = installed_json_path(repo_root)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return empty
    if not isinstance(data, dict) or not isinstance(data.get("tools"), dict):
        return empty
    return data


def installed_entry(repo_root: str | os.PathLike[str], name: str) -> dict[str, Any] | None:
    """Return the installed.json record of one tool, or None."""
    entry = read_installed(repo_root)["tools"].get(name)
    return entry if isinstance(entry, dict) else None


def entry_path(repo_root: str | os.PathLike[str], entry: dict[str, Any]) -> Path | None:
    """Return the absolute path of an installed.json record when it stays inside ``.tools``."""
    raw = entry.get("path")
    if not isinstance(raw, str) or not raw:
        return None
    root = Path(repo_root).resolve()
    path = (root / raw).resolve()
    try:
        path.relative_to(tools_root(root))
    except ValueError:
        return None
    return path


def version_in_output(output: str, version: str) -> bool:
    """Return True when ``version`` (optionally with a leading ``v``) appears as a whole token."""
    pattern = (
        r"(?<![0-9A-Za-z.])v?" + re.escape(strip_v(version)) + r"(?![0-9A-Za-z]|[.-][0-9A-Za-z])"
    )
    return re.search(pattern, output) is not None


def first_version(output: str) -> str | None:
    """Return the first ``x.y.z`` version in a version output, or None."""
    match = re.search(r"(?<![0-9.])v?([0-9]+\.[0-9]+\.[0-9]+)", output)
    return match.group(1) if match else None


def probe_env(
    tool: Tool | None = None, *, environ: Mapping[str, str] | None = None
) -> dict[str, str]:
    """Return the environment of a version probe.

    The minimal tool environment of the adapters (:func:`kalkan.scanners.base.minimal_env`:
    ``PATH``, the system and temporary folders, ``HOME``, the locale, the proxy and certificate
    variables; no token, no ``GOFLAGS``, no ``PYTHONPATH``), plus for a manifest tool: the
    Python settings of the adapters for a pip tool, ``GOTOOLCHAIN=local`` for a Go program (it
    never downloads another toolchain), and the ``version_env`` of the tool (for example
    ``CKV_SKIP_PACKAGE_UPDATE_CHECK=true``). Every value is final: the folders of one probe
    come from :func:`probe_folders`, which :func:`probe_version` adds for its working folder.
    """
    from kalkan.scanners.base import PYTHON_TOOL_ENV, minimal_env  # lazy: small import graph

    extra: dict[str, str] = {}
    if tool is not None:
        if tool.kind == "pip":
            extra.update(PYTHON_TOOL_ENV)
        if _go_program(tool):
            extra["GOTOOLCHAIN"] = "local"
        extra.update(tool.version_env)
    return minimal_env(extra, environ=environ)


def probe_folders(tool: Tool | None, workdir: str | os.PathLike[str]) -> dict[str, str]:
    """Return the variables that keep one probe in its working folder ``workdir`` and prepare
    the folders they name (:mod:`kalkan.tools.toolhome`).

    ``workdir`` is the temporary folder of the process (``TEMP``, ``TMP``, ``TMPDIR``). For a Go
    program it is also the Go configuration folder, and ``go/telemetry/mode`` there says
    ``off``: Go otherwise starts a telemetry process that keeps a counter file open after the
    probe, and the folder stays behind (measured on 2026-10-29). opengrep gets its kalkan
    profile folder (created here; skipped when the kalkan home cannot be used, which the
    doctor check ``paths`` reports) and logs into ``workdir``.
    """
    folder = Path(workdir)
    env = toolhome.temp_env(folder)
    if tool is None:
        return env
    if _go_program(tool):
        toolhome.go_telemetry_off(folder)
        env.update(toolhome.go_config_env(folder))
    if tool.name == OPENGREP:
        try:
            home = toolhome.prepare_home(toolhome.opengrep_home(default_repo_root()))
        except (KalkanError, OSError):
            return env
        env.update(toolhome.opengrep_env(home, folder))
    return env


def probe_version(
    command: str | os.PathLike[str] | Sequence[str],
    args: Sequence[str],
    *,
    runner: Runner | None = None,
    timeout: float = VERSION_TIMEOUT_SECONDS,
    env: Mapping[str, str] | None = None,
    tool: Tool | None = None,
) -> str | None:
    """Run ``<command> <args>`` and return stdout plus stderr, or None when it cannot run.

    ``command`` is a path or an argv prefix (for example ``ResolvedTool.argv``). The process
    gets ``env`` (default: :func:`probe_env` without a tool) and a new empty working folder,
    never the environment and the folder of the caller. The placeholder ``{workdir_url}``
    (:data:`kalkan.tools.manifest.WORKDIR_URL`) in ``args`` becomes the ``file://`` URL of that
    folder. :func:`probe_folders` of ``tool`` adds the variables of that folder, so nothing
    that the process leaves there outlives the probe.
    """
    run = runner or run_command
    if isinstance(command, (str, os.PathLike)):
        prefix = [os.fspath(command)]
    else:
        prefix = [os.fspath(part) for part in command]
    environment = dict(env) if env is not None else probe_env()
    try:
        with tempfile.TemporaryDirectory(prefix="kalkan-probe-", ignore_cleanup_errors=True) as tmp:
            workdir = Path(tmp)
            argv = [*prefix, *(arg.replace(WORKDIR_URL, workdir.as_uri()) for arg in args)]
            final = {**environment, **probe_folders(tool, workdir)}
            proc = run(argv, timeout=timeout, env=final, cwd=workdir)
    except (OSError, subprocess.SubprocessError, ValueError):
        return None
    return f"{proc.stdout or ''}\n{proc.stderr or ''}"


def probe_tool_version(
    command: str | os.PathLike[str] | Sequence[str],
    tool: Tool,
    *,
    runner: Runner | None = None,
    timeout: float = VERSION_TIMEOUT_SECONDS,
) -> str | None:
    """Run the version command of a manifest tool (``version_args``) with :func:`probe_env`
    and :func:`probe_folders`."""
    return probe_version(
        command, tool.version_args, runner=runner, timeout=timeout, env=probe_env(tool), tool=tool
    )


def _go_program(tool: Tool) -> bool:
    """True for a Go program: the toolchain, a go-install tool or a tool that needs Go."""
    return tool.requires_go or tool.kind in ("toolchain", "go-install")


def go_version_in_output(output: str) -> str | None:
    """Return the Go version of a ``go env GOVERSION`` or ``go version`` output (``1.26.9``)."""
    match = GO_VERSION_RE.search(output or "")
    return match.group(1) if match else None


def go_toolchain_version(
    go: str | os.PathLike[str],
    *,
    runner: Runner | None = None,
    goroot: str | os.PathLike[str] | None = None,
    timeout: float = VERSION_TIMEOUT_SECONDS,
) -> str | None:
    """Return the version of a Go toolchain (``1.26.9``), or None when it cannot be read.

    Runs ``go env GOVERSION`` with the probe environment (:func:`probe_env`) and
    ``GOTOOLCHAIN=local`` in a new empty working folder, so neither a ``go.mod`` or ``go.work``
    nor a ``GOFLAGS`` or ``GOTOOLCHAIN`` of the user can make Go download another toolchain.
    The folder is also the temporary and the Go configuration folder (telemetry off) of the
    process (:mod:`kalkan.tools.toolhome`, :func:`probe_version`). ``goroot`` sets ``GOROOT``
    (the kalkan copy); otherwise a ``GOROOT`` of the environment stays.
    """
    run = runner or run_command
    env = probe_env()
    env["GOTOOLCHAIN"] = "local"
    if goroot is not None:
        env["GOROOT"] = os.fspath(goroot)
    elif os.environ.get("GOROOT"):
        env["GOROOT"] = os.environ["GOROOT"]
    try:
        with tempfile.TemporaryDirectory(prefix="kalkan-probe-", ignore_cleanup_errors=True) as tmp:
            toolhome.go_telemetry_off(tmp)
            env.update({**toolhome.temp_env(tmp), **toolhome.go_config_env(tmp)})
            proc = run([os.fspath(go), "env", "GOVERSION"], timeout=timeout, env=env, cwd=tmp)
    except Exception:  # OSError, timeout, ValueError: the version is unknown
        return None
    if proc.returncode != 0:
        return None
    return go_version_in_output(proc.stdout or "")


def version_tuple(version: str) -> tuple[int, ...]:
    """Return the numbers of a version string (``1.26.9`` gives ``(1, 26, 9)``)."""
    return tuple(int(part) for part in re.findall(r"[0-9]+", version))


def required_go_version(manifest: Manifest) -> str | None:
    """Return the lowest Go version that every tool with ``requires_go`` accepts.

    This is the highest ``min_go_version`` of those tools. Without one, it is the
    ``major.minor`` of the pinned toolchain; without a toolchain, None.
    """
    needs = [tool.min_go_version for tool in manifest if tool.requires_go and tool.min_go_version]
    if needs:
        return max(needs, key=version_tuple)
    for tool in manifest:
        if tool.kind == "toolchain":
            return ".".join(tool.version.split(".")[:2])
    return None


def blocked_version_in(tool: Tool, output: str) -> str | None:
    """Return the blocked version that the output reports, or None."""
    for blocked in tool.blocked_versions:
        if version_in_output(output, blocked):
            return blocked
    return None


def resolve(
    name: str,
    *,
    repo_root: str | os.PathLike[str] | None = None,
    allow_path: bool = False,
    manifest: Manifest | None = None,
    key: str | None = None,
    runner: Runner | None = None,
    path_env: str | None = None,
    finder: Finder | None = None,
) -> ResolvedTool | None:
    """Return the tool to run, or None when no acceptable copy exists.

    Order: the kalkan copy under ``.tools``; then PATH, but only when the version output matches
    the manifest version (or ``allow_path`` is set). A toolchain on PATH needs a version of at
    least :func:`required_go_version`. Raises ToolError for an unknown tool name. ``finder``
    replaces the PATH search (tests).
    """
    find = finder or (lambda executable: find_on_path(executable, path_env=path_env))
    manifest = manifest or load_manifest()
    tool = manifest.get(name)
    root = Path(repo_root) if repo_root is not None else default_repo_root()
    local = _resolve_local(root, tool, key or platform_key(), runner=runner)
    if local is not None:
        return local
    if tool.kind == "toolchain":
        required = required_go_version(manifest)
        return _resolve_toolchain_on_path(
            tool, required, allow_path=allow_path, runner=runner, find=find
        )
    return _resolve_on_path(tool, allow_path=allow_path, runner=runner, find=find)


def _resolve_local(
    root: Path, tool: Tool, key: str, *, runner: Runner | None
) -> ResolvedTool | None:
    entry = installed_entry(root, tool.name)
    if tool.kind == "pip":
        script = pyenv_script(root, tool.executable)
        if script is None:
            return None
        command = tuple(pyenv_command(root, script))
        if entry and entry.get("version") == tool.version:
            return ResolvedTool(tool.name, script, tool.version, SOURCE_KALKAN, command)
        output = probe_tool_version(command, tool, runner=runner)
        if output is not None and version_in_output(output, tool.version):
            return ResolvedTool(tool.name, script, tool.version, SOURCE_KALKAN, command)
        return None
    recorded = entry_path(root, entry) if entry else None
    if entry and entry.get("version") == tool.version and recorded and recorded.is_file():
        return ResolvedTool(tool.name, recorded, tool.version, SOURCE_KALKAN)
    candidate = binary_path(root, tool, key)
    if candidate.is_file():
        return ResolvedTool(tool.name, candidate, tool.version, SOURCE_KALKAN)
    return None


def _resolve_toolchain_on_path(
    tool: Tool,
    required: str | None,
    *,
    allow_path: bool,
    runner: Runner | None,
    find: Finder,
) -> ResolvedTool | None:
    """Accept a system toolchain whose version is at least ``required`` and not blocked."""
    found = find(tool.executable)
    if found is None:
        return None
    version = go_toolchain_version(found, runner=runner)
    if version is None or tool.is_blocked(version):
        return None
    if allow_path or required is None or version_tuple(version) >= version_tuple(required):
        return ResolvedTool(tool.name, found, version, SOURCE_PATH)
    return None


def _resolve_on_path(
    tool: Tool, *, allow_path: bool, runner: Runner | None, find: Finder
) -> ResolvedTool | None:
    found = find(tool.executable)
    if found is None:
        return None
    output = probe_tool_version(found, tool, runner=runner)
    if output is None:
        return None
    if blocked_version_in(tool, output) is not None:
        return None
    if version_in_output(output, tool.version):
        return ResolvedTool(tool.name, found, tool.version, SOURCE_PATH)
    if allow_path:
        return ResolvedTool(tool.name, found, first_version(output) or "unknown", SOURCE_PATH)
    return None
