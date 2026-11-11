# SPDX-License-Identifier: MIT
"""``run init``: create a run from a local folder or a git URL (docs/ENGINE-SPEC.md, section 10).

:func:`init_run` creates ``runs/<run-id>/`` and writes, in this order: ``target/`` (the filtered,
neutralized copy), ``target-manifest.json``, ``state.json``, ``events.jsonl`` and
``runs/LATEST``. With ``update_latest=False`` (CLI ``--no-latest``) it leaves ``runs/LATEST``
unchanged: the caller then names the run with ``--run <run-id>`` in every later command. When a
step fails, the new run folder is removed and ``LATEST`` keeps the previous run.

Targets:

- A local folder. The original folder is only read, never written, and no process runs in it.
  When the folder is the root of a git work tree (it has a ``.git`` folder or file),
  :func:`copy_history` makes a private mirror of its history in ``<run>/source`` (a bare
  ``git clone --mirror --no-local`` with the safety options below). ``source_dir`` names that
  copy, and ``git rev-parse --verify HEAD`` in the copy gives ``git_ref``. A copy that fails
  (for example a repository that another user owns) is not fatal: ``source_dir`` is null, the
  manifest ``history`` entry records the reason, and the history scan is skipped. For a folder
  inside a work tree (not its root), :func:`read_head` reads ``git_ref`` from the files of the
  git folder (no git process). Every scanner reads only ``<run>/target`` and ``<run>/source``.
- A git URL: ``https://...``, ``ssh://...`` or ``user@host:path``, with or without ``.git``.
  ``git clone --no-recurse-submodules -c core.symlinks=false -- <url> <run>/source`` runs with a
  timeout, prompts off (``GIT_TERMINAL_PROMPT=0``), only the https and ssh protocols
  (``GIT_ALLOW_PROTOCOL``) and no LFS download. Then ``source/`` is copied to ``target/``.
  ``file://``, ``ext::`` and every other transport are refused. Credentials in an https URL are
  used for the clone but never stored. A missing git gives :class:`~kalkan.errors.ToolError`.
- A git URL with ``ref`` (``run init --ref <tag|branch|commit>``): the clone runs with
  ``--no-checkout`` (full history of every branch and tag, for the history scans), then
  :func:`checkout_ref` resolves the ref in this order: tag ``refs/tags/<ref>``, branch
  ``refs/remotes/origin/<ref>``, commit (hex, at least 7 digits). When none resolves,
  ``git fetch --no-recurse-submodules --no-tags --end-of-options origin <ref>`` fetches it (for
  example a commit that no branch contains) and ``FETCH_HEAD`` is used. The commit is checked
  out as a detached HEAD with ``core.symlinks=false``. The manifest records the commit in
  ``git_ref`` and the given ref in ``requested_ref``. A ref is refused for a local folder.

History copy of a local work tree (:func:`copy_history`)::

    git -c core.fsmonitor=false -c core.symlinks=false clone --mirror --no-local --template=
        --quiet "--upload-pack='<git>' -c core.fsmonitor=false -c transfer.hideRefs=!refs/
        -c uploadpack.hideRefs=!refs/ upload-pack" -- <folder> <run>/source

- ``--mirror``: every ref (branches, tags, remote-tracking branches, ``refs/stash``, notes)
  and a detached HEAD, as ``gitleaks git --all`` saw them in the original.
- ``--no-local``: the objects come through the pack protocol, so the copy is self-contained
  (no hard links, no alternates, no symlinks in ``objects/`` are followed).
- ``--template=``: no hook or other template file from the user's git configuration.
- ``--upload-pack``: the upload-pack of the original exposes every ref; without it,
  ``uploadpack.hideRefs`` in the repository config hides refs from the copy (tested).
- Environment: ``GIT_ALLOW_PROTOCOL=file`` (only the local transport, only for this clone),
  ``GIT_NO_LAZY_FETCH=1`` (a partial clone never fetches missing objects from its remote),
  ``GIT_TERMINAL_PROMPT=0``. The working directory is the run folder.
- Afterwards the ``remote.origin`` section is removed from the copy's config, so the copy has no
  link back to the original.

Copy rules (:func:`copy_tree`): the copy skips the folders ``.git``, ``node_modules``,
``.venv``, ``venv``, ``__pycache__``, ``.tox``, ``.mypy_cache``, ``.pytest_cache``, ``dist``,
``build``, ``.next``, ``.nuxt`` and ``.tools`` (names compared case-insensitively), the .NET
build output (a ``bin`` or ``obj`` folder next to a ``.csproj``, ``.fsproj`` or ``.vbproj``
file; class ``dotnet-build``), the kalkan runs folder (by location), symlinks and Windows
reparse points (junctions; never followed), special files, files larger than 5 MiB, names
that are not safe relative path segments (:func:`kalkan.util.paths.is_safe_relative_path`)
and files that cannot be read safely. Each class is counted in the manifest with up to 200
example paths. Files are read with :func:`kalkan.util.safe_io.read_bounded` and written with
exclusive create inside ``target/`` only. Parent folders are trusted, as in
:mod:`kalkan.util.safe_io`.

Neutralization: agent instruction files and folders get the suffix ``.kalkan-neutralized`` in
the copy (names compared case-insensitively on every platform, at any depth): files
``CLAUDE.md``, ``CLAUDE.local.md``, ``AGENTS.md``, ``AGENTS.override.md``, ``GEMINI.md``,
``.cursorrules``, ``.windsurfrules``, ``.github/copilot-instructions.md``; folders ``.claude``,
``.codex``, ``.agents``, ``.cursor``, ``.gemini``, ``.windsurf``. The copy is written under the
new name directly, so the original name never exists in ``target/``. When the new name is taken,
``-2``, ``-3`` and so on follow the suffix. For a git URL, the same names are renamed in place
in the ``source/`` work tree (history scans read the git objects, not the work tree). The
manifest records every renamed path.
"""

from __future__ import annotations

import contextlib
import os
import re
import shutil
import stat
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Final
from urllib.parse import urlsplit, urlunsplit

from kalkan import resources
from kalkan.errors import KalkanError, StateError, ToolError, UnsafeInputError, ValidationError
from kalkan.findings.deployment import check_live_paths, scan_deployments
from kalkan.run import budget, events, ids, tech
from kalkan.run.lock import run_lock
from kalkan.run.state import (
    DOCKER_MODES,
    LANGUAGES,
    MAX_PARALLEL_LIMIT,
    MODE_AGENTS,
    MODE_TOOLS_ONLY,
    RUN_MODES,
    SCHEMA_VERSION,
    SOURCE_DIRNAME,
    TARGET_DIRNAME,
    RunContext,
    new_phases,
    save_state,
)
from kalkan.schema.loader import shared_schema
from kalkan.schema.validator import validate
from kalkan.util import paths
from kalkan.util.safe_io import atomic_write_json, read_bounded
from kalkan.util.text import escape_unsafe_diagnostic_characters
from kalkan.util.winpath import (
    LONG_PATH_CONDITION,
    WINDOWS_PATH_LIMIT,
    find_long_paths,
    long_paths_enabled,
)

__all__ = [
    "EXCLUDED_CLASSES",
    "GIT_CLONE_TIMEOUT_SECONDS",
    "INSTRUCTION_DIRS",
    "INSTRUCTION_FILES",
    "MANIFEST_NAME",
    "MAX_FILE_BYTES",
    "NEUTRALIZED_SUFFIX",
    "SKIPPED_DIRS",
    "CopyResult",
    "Target",
    "checkout_ref",
    "classify_target",
    "clone_repository",
    "copy_history",
    "copy_tree",
    "find_long_paths",
    "git_head",
    "init_run",
    "is_instruction_name",
    "neutralize_in_place",
    "read_head",
    "validate_ref",
]

MANIFEST_NAME: Final = "target-manifest.json"
NEUTRALIZED_SUFFIX: Final = ".kalkan-neutralized"
MAX_FILE_BYTES: Final = 5 * 1024 * 1024
GIT_CLONE_TIMEOUT_SECONDS: Final = 540
GIT_QUERY_TIMEOUT_SECONDS: Final = 30
#: Folder names that the copy skips; each one is its own excluded class.
SKIPPED_DIRS: Final = (
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    "dist",
    "build",
    ".next",
    ".nuxt",
    ".tools",
)
#: Build output folders of a .NET project: skipped only next to a project file (class
#: ``dotnet-build``), because a ``bin`` folder elsewhere often holds scripts.
DOTNET_BUILD_DIRS: Final = frozenset({"bin", "obj"})
DOTNET_PROJECT_SUFFIXES: Final = (".csproj", ".fsproj", ".vbproj")
#: Every excluded class of the manifest, in manifest order.
EXCLUDED_CLASSES: Final = (
    *SKIPPED_DIRS,
    "dotnet-build",
    "kalkan-runs",
    "symlink",
    "large-file",
    "special-file",
    "unsafe-name",
    "unreadable",
    "copy-error",
)
INSTRUCTION_FILES: Final = (
    "CLAUDE.md",
    "CLAUDE.local.md",
    "AGENTS.md",
    "AGENTS.override.md",
    "GEMINI.md",
    ".cursorrules",
    ".windsurfrules",
)
INSTRUCTION_DIRS: Final = (".claude", ".codex", ".agents", ".cursor", ".gemini", ".windsurf")

_SKIPPED: Final = {name.casefold(): name for name in SKIPPED_DIRS}
_INSTRUCTION_NAMES: Final = frozenset(
    name.casefold() for name in (*INSTRUCTION_FILES, *INSTRUCTION_DIRS)
)
_COPILOT_FILE: Final = "copilot-instructions.md"
_GITHUB_DIR: Final = ".github"
_EXAMPLE_PATHS: Final = 200
_NEUTRALIZED_LIST_MAX: Final = 1000
_RUN_DIR_ATTEMPTS: Final = 10

_URL_SCHEME: Final = re.compile(r"\A[A-Za-z][A-Za-z0-9+.-]*://")
_TRANSPORT: Final = re.compile(r"\A[A-Za-z][A-Za-z0-9+.-]*::")
_SCP_URL: Final = re.compile(
    r"\A[A-Za-z0-9._-]+@([A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?):(?!-)(?!/*\Z)(.+)\Z"
)
_HOST: Final = re.compile(r"\A[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\Z")
_PRINTABLE_ASCII: Final = re.compile(r"\A[\x21-\x7e]+\Z")
_GIT_SHA: Final = re.compile(r"\A(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_HEX_REF: Final = re.compile(r"\A[0-9a-fA-F]{7,64}\Z")
#: A tag, branch or commit name: no leading ``-`` or ``/``, no ``..``, ``//``, ``@{``, no part
#: that starts with ``.``, no ``.lock`` or ``/`` or ``.`` at the end (``git check-ref-format``).
_REF: Final = re.compile(
    r"\A(?![-/])(?!.*\.\.)(?!.*//)(?!.*(?:^|/)\.)[A-Za-z0-9._/+-]{1,200}(?<![./])(?<!\.lock)\Z"
)


# ---------------------------------------------------------------------------------------------
# Targets


@dataclass(frozen=True)
class Target:
    """A classified ``run init`` target."""

    kind: str  # "path" or "git"
    location: str  # the absolute folder, or the URL exactly as given (for git clone)
    display: str  # stored text: absolute POSIX folder path, or the URL without credentials
    name: str  # folder or repository name, the source of the run ID slug


def _repository_name(path: str) -> str:
    segments = [segment for segment in re.split(r"[/:]", path) if segment]
    name = segments[-1] if segments else ""
    return name[:-4] if name.lower().endswith(".git") else name


def _refuse_url() -> UnsafeInputError:
    return UnsafeInputError(
        "unsupported target URL: use https://, ssh:// or git@host:path "
        "(file://, ext:: and other transports are refused)"
    )


def classify_target(target: str) -> Target:
    """Classify a ``run init`` target as a git URL or a local folder.

    Raises :class:`~kalkan.errors.UnsafeInputError` for a refused or malformed URL and
    :class:`~kalkan.errors.KalkanError` when a local target is not an existing folder.
    """
    if not isinstance(target, str) or not target:
        raise KalkanError("the target must be a folder path or a git URL")
    if _URL_SCHEME.match(target):
        parts = urlsplit(target)
        if parts.scheme.lower() not in ("https", "ssh"):
            raise _refuse_url()
        if not _PRINTABLE_ASCII.fullmatch(target):
            raise UnsafeInputError("the target URL must be printable ASCII without spaces")
        host = parts.hostname or ""
        try:
            port = parts.port
        except ValueError:
            raise UnsafeInputError("invalid port in the target URL") from None
        if not _HOST.fullmatch(host):
            raise UnsafeInputError("invalid host in the target URL")
        if not parts.path.strip("/"):
            raise UnsafeInputError("the target URL has no repository path")
        netloc = host if port is None else f"{host}:{port}"
        if parts.scheme.lower() == "ssh" and parts.username:
            netloc = f"{parts.username}@{netloc}"  # an ssh user name is not a secret
        display = urlunsplit((parts.scheme.lower(), netloc, parts.path, "", ""))
        return Target("git", target, display, _repository_name(parts.path))
    if _TRANSPORT.match(target):
        raise _refuse_url()
    match = _SCP_URL.fullmatch(target)
    if match is not None:
        if not _PRINTABLE_ASCII.fullmatch(target):
            raise UnsafeInputError("the target URL must be printable ASCII without spaces")
        return Target("git", target, target, _repository_name(match.group(2)))
    folder = Path(target).expanduser()
    try:
        resolved = folder.resolve(strict=True)
    except (OSError, RuntimeError):
        shown = escape_unsafe_diagnostic_characters(target)
        raise KalkanError(f"target not found: {shown}") from None
    if not resolved.is_dir():
        shown = escape_unsafe_diagnostic_characters(target)
        raise KalkanError(f"the target is not a folder: {shown}")
    return Target("path", str(resolved), resolved.as_posix(), resolved.name)


# ---------------------------------------------------------------------------------------------
# git


#: Variables that point git at another repository, work tree or object store. They never pass
#: to the git processes of ``run init``.
_GIT_LOCATION_ENV: Final = (
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_COMMON_DIR",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_NAMESPACE",
)


def _git_env() -> dict[str, str]:
    env = {key: value for key, value in os.environ.items() if key.upper() not in _GIT_LOCATION_ENV}
    env.update(
        {
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ALLOW_PROTOCOL": "https:ssh",
            "GIT_LFS_SKIP_SMUDGE": "1",
            "GIT_NO_LAZY_FETCH": "1",
        }
    )
    return env


def _sh_quote(text: str) -> str:
    """Quote ``text`` for the POSIX shell that git uses to start ``--upload-pack``."""
    return "'" + text.replace("'", "'\\''") + "'"


def copy_history(
    work_tree: Path,
    destination: Path,
    *,
    timeout_seconds: int = GIT_CLONE_TIMEOUT_SECONDS,
) -> None:
    """Copy the git history of the local work tree ``work_tree`` into the new bare mirror
    ``destination`` (module docstring). The original is only read.

    Raises :class:`~kalkan.errors.ToolError` when git is missing, fails or times out.
    """
    git = shutil.which("git")
    if git is None:
        raise ToolError("git is not installed or not on PATH")
    upload_pack = (
        f"{_sh_quote(Path(git).as_posix())} -c core.fsmonitor=false "
        "-c transfer.hideRefs=!refs/ -c uploadpack.hideRefs=!refs/ upload-pack"
    )
    command = [
        git,
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.symlinks=false",
        "clone",
        "--mirror",
        "--no-local",
        "--template=",
        "--quiet",
        f"--upload-pack={upload_pack}",
        "--",
        str(work_tree),
        str(destination),
    ]
    env = _git_env()
    env["GIT_ALLOW_PROTOCOL"] = "file"
    try:
        completed = subprocess.run(
            command,
            shell=False,
            cwd=str(destination.parent),
            timeout=timeout_seconds,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
        )
    except subprocess.TimeoutExpired:
        raise ToolError(f"the history copy timed out after {timeout_seconds} seconds") from None
    except OSError as exc:
        raise ToolError("git clone could not start") from exc
    if completed.returncode != 0:
        tail = (completed.stderr or "").strip()[-500:]
        raise ToolError(
            f"the history copy failed (git clone exit {completed.returncode}): "
            f"{escape_unsafe_diagnostic_characters(tail)}"
        )
    detached = _git(git, destination, ["config", "--remove-section", "remote.origin"], 60)
    if detached.returncode != 0:
        raise ToolError("the history copy keeps a link to the original (git config failed)")


def clone_repository(
    url: str,
    destination: Path,
    *,
    display: str | None = None,
    timeout_seconds: int = GIT_CLONE_TIMEOUT_SECONDS,
    no_checkout: bool = False,
) -> None:
    """Clone ``url`` into ``destination`` (full history, no submodules, no symlinks).

    ``no_checkout`` leaves the work tree empty (:func:`checkout_ref` fills it). Raises
    :class:`~kalkan.errors.ToolError` when git is missing, fails or times out. Error messages
    show ``display`` instead of the URL, so credentials never reach the output.
    """
    git = shutil.which("git")
    if git is None:
        raise ToolError("git is not installed or not on PATH; install git to audit a git URL")
    command = [
        git,
        "clone",
        "--no-recurse-submodules",
        *(["--no-checkout"] if no_checkout else []),
        "-c",
        "core.symlinks=false",
        "-c",
        "core.fsmonitor=false",
        "--",
        url,
        str(destination),
    ]
    try:
        completed = subprocess.run(
            command,
            shell=False,
            timeout=timeout_seconds,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=_git_env(),
        )
    except subprocess.TimeoutExpired:
        raise ToolError(f"git clone timed out after {timeout_seconds} seconds") from None
    except OSError as exc:
        raise ToolError("git clone could not start") from exc
    if completed.returncode != 0:
        tail = (completed.stderr or "").strip().replace(url, display or "<url>")[-500:]
        raise ToolError(
            f"git clone failed (exit {completed.returncode}): "
            f"{escape_unsafe_diagnostic_characters(tail)}"
        )


def validate_ref(ref: object) -> str:
    """Return ``ref`` when it is a safe tag, branch or commit name.

    Raises :class:`~kalkan.errors.ValidationError` otherwise (for example a leading ``-``, which
    git would read as an option).
    """
    if not isinstance(ref, str) or not _REF.fullmatch(ref):
        shown = escape_unsafe_diagnostic_characters(str(ref))[:80]
        raise ValidationError(
            f"invalid --ref {shown!r}: use a tag, branch or commit name "
            "(letters, digits, '.', '_', '/', '+', '-'; no leading '-')"
        )
    return ref


def _git(
    git: str, repo: Path, args: list[str], timeout: int, *, scrub: tuple[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    command = [git, "-c", "core.fsmonitor=false", "-c", "core.symlinks=false", "-C", str(repo)]
    try:
        completed = subprocess.run(
            [*command, *args],
            shell=False,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=_git_env(),
        )
    except subprocess.TimeoutExpired:
        raise ToolError(f"git {args[0]} timed out after {timeout} seconds") from None
    except OSError as exc:
        raise ToolError(f"git {args[0]} could not start") from exc
    if scrub is not None:
        completed.stderr = (completed.stderr or "").replace(*scrub)
    return completed


def _resolve(git: str, repo: Path, name: str) -> str | None:
    completed = _git(
        git, repo, ["rev-parse", "--verify", "--quiet", name], GIT_QUERY_TIMEOUT_SECONDS
    )
    value = (completed.stdout or "").strip()
    return value if completed.returncode == 0 and _GIT_SHA.fullmatch(value) else None


def checkout_ref(
    repo: Path,
    ref: str,
    *,
    url: str | None = None,
    display: str | None = None,
    timeout_seconds: int = GIT_CLONE_TIMEOUT_SECONDS,
) -> str:
    """Check out the tag, branch or commit ``ref`` in the clone ``repo`` as a detached HEAD and
    return the commit (module docstring).

    ``url`` and ``display``: the clone URL and its form without credentials; git messages show
    ``display``. Raises :class:`~kalkan.errors.ValidationError` for an invalid ref,
    :class:`~kalkan.errors.KalkanError` when the ref does not exist and
    :class:`~kalkan.errors.ToolError` when git fails.
    """
    validate_ref(ref)
    git = shutil.which("git")
    if git is None:
        raise ToolError("git is not installed or not on PATH; install git to audit a git URL")
    names = [f"refs/tags/{ref}^{{commit}}", f"refs/remotes/origin/{ref}^{{commit}}"]
    if _HEX_REF.fullmatch(ref):
        names.append(f"{ref}^{{commit}}")
    commit = next((c for c in (_resolve(git, repo, name) for name in names) if c), None)
    scrub = (url, display or "<url>") if url else None
    shown = escape_unsafe_diagnostic_characters(ref)
    if commit is None:
        fetched = _git(
            git,
            repo,
            ["fetch", "--no-recurse-submodules", "--no-tags", "--end-of-options", "origin", ref],
            timeout_seconds,
            scrub=scrub,
        )
        if fetched.returncode == 0:
            commit = _resolve(git, repo, "FETCH_HEAD^{commit}")
    if commit is None:
        raise KalkanError(
            f"the ref {shown!r} was not found in the repository (tag, branch or commit)"
        )
    done = _git(
        git, repo, ["checkout", "--detach", "--quiet", commit, "--"], timeout_seconds, scrub=scrub
    )
    if done.returncode != 0:
        tail = (done.stderr or "").strip()[-500:]
        raise ToolError(
            f"git checkout of {shown!r} failed (exit {done.returncode}): "
            f"{escape_unsafe_diagnostic_characters(tail)}"
        )
    return commit


def git_head(directory: Path) -> str | None:
    """Return the HEAD commit of the git work tree that contains ``directory``, else None."""
    git = shutil.which("git")
    if git is None:
        return None
    command = [
        git,
        "-c",
        "core.fsmonitor=false",
        "-C",
        str(directory),
        "rev-parse",
        "--verify",
        "--quiet",
        "HEAD",
    ]
    try:
        completed = subprocess.run(
            command,
            shell=False,
            timeout=GIT_QUERY_TIMEOUT_SECONDS,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=_git_env(),
        )
    except (subprocess.SubprocessError, OSError):
        return None
    value = (completed.stdout or "").strip()
    if completed.returncode != 0 or not _GIT_SHA.fullmatch(value):
        return None
    return value


_HEAD_MAX_BYTES: Final = 4096
_PACKED_REFS_MAX_BYTES: Final = 64 * 1024 * 1024
_REF_NAME: Final = re.compile(r"\Arefs/(?!.*\.\.)[A-Za-z0-9._/+@-]{1,250}\Z")


def _read_small(path: Path, limit: int = _HEAD_MAX_BYTES) -> str | None:
    try:
        return read_bounded(path, limit).decode("utf-8", errors="replace")
    except UnsafeInputError:
        return None


def _git_folder(work_tree: Path) -> Path | None:
    """Return the git folder of the work tree root ``work_tree`` (a ``.git`` folder, or the folder
    that the ``gitdir:`` line of a ``.git`` file names). Links are never followed."""
    entry = work_tree / ".git"
    try:
        info = os.lstat(entry)
    except OSError:
        return None
    if _is_link(info):
        return None
    if stat.S_ISDIR(info.st_mode):
        return entry
    if not stat.S_ISREG(info.st_mode):
        return None
    text = _read_small(entry) or ""
    for line in text.splitlines():
        if line.startswith("gitdir:"):
            named = Path(line.split(":", 1)[1].strip())
            folder = named if named.is_absolute() else work_tree / named
            return folder if _is_real_directory(folder) else None
    return None


def _ref_commit(git_folder: Path, ref: str) -> str | None:
    common = git_folder
    pointer = _read_small(git_folder / "commondir")
    if pointer and pointer.strip():
        named = Path(pointer.strip())
        common = named if named.is_absolute() else git_folder / named
    for base in dict.fromkeys((git_folder, common)):
        value = (_read_small(base / ref) or "").strip()
        if _GIT_SHA.fullmatch(value):
            return value
    packed = _read_small(common / "packed-refs", _PACKED_REFS_MAX_BYTES) or ""
    for line in packed.splitlines():
        sha, _, name = line.partition(" ")
        if name.strip() == ref and _GIT_SHA.fullmatch(sha):
            return sha
    return None


def read_head(directory: Path) -> str | None:
    """Return the HEAD commit of the git work tree that contains ``directory``, else None.

    Reads files only (``HEAD``, a loose ref, ``packed-refs``); no git process runs and nothing
    is written. The search goes up the parent folders and stops below a folder of
    ``GIT_CEILING_DIRECTORIES``. A reftable repository or an unborn branch gives None.
    """
    ceilings = {
        os.path.normcase(os.path.abspath(item))
        for item in os.environ.get("GIT_CEILING_DIRECTORIES", "").split(os.pathsep)
        if item and os.path.isabs(item)
    }
    start = Path(os.path.abspath(directory))
    for folder in (start, *start.parents):
        if folder != start and os.path.normcase(str(folder)) in ceilings:
            return None
        if not os.path.lexists(folder / ".git"):
            continue
        git_folder = _git_folder(folder)
        if git_folder is None:
            return None
        head = (_read_small(git_folder / "HEAD") or "").strip()
        if _GIT_SHA.fullmatch(head):
            return head
        if head.startswith("ref:"):
            ref = head[4:].strip()
            return _ref_commit(git_folder, ref) if _REF_NAME.fullmatch(ref) else None
        return None
    return None


# ---------------------------------------------------------------------------------------------
# Copy and neutralization


def is_instruction_name(name: str, parent: str = "") -> bool:
    """Return True when ``name`` (in a folder named ``parent``) is an agent instruction file or
    folder that neutralization renames. Names compare case-insensitively."""
    folded = name.casefold()
    if folded in _INSTRUCTION_NAMES:
        return True
    return folded == _COPILOT_FILE and parent.casefold() == _GITHUB_DIR


def _neutral_name(name: str, taken: set[str]) -> str:
    candidate = name + NEUTRALIZED_SUFFIX
    number = 2
    while candidate.casefold() in taken:
        candidate = f"{name}{NEUTRALIZED_SUFFIX}-{number}"
        number += 1
    return candidate


def _is_link(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
    )


def _is_real_directory(path: Path) -> bool:
    try:
        info = os.lstat(path)
    except OSError:
        return False
    return stat.S_ISDIR(info.st_mode) and not _is_link(info)


def _join(base: str, name: str) -> str:
    return f"{base}/{name}" if base else name


@dataclass
class CopyResult:
    """Counters and records of :func:`copy_tree` and :func:`neutralize_in_place`."""

    copied: int = 0
    bytes: int = 0
    directories: int = 0
    counts: dict[str, int] = field(default_factory=lambda: dict.fromkeys(EXCLUDED_CLASSES, 0))
    examples: dict[str, list[str]] = field(
        default_factory=lambda: {name: [] for name in EXCLUDED_CLASSES}
    )
    neutralized: list[dict[str, str]] = field(default_factory=list)

    def skip(self, kind: str, path: str) -> None:
        """Count one skipped path of class ``kind``."""
        self.counts[kind] += 1
        if len(self.examples[kind]) < _EXAMPLE_PATHS:
            self.examples[kind].append(escape_unsafe_diagnostic_characters(path))

    @property
    def skipped(self) -> int:
        return sum(self.counts.values())

    def excluded(self) -> list[dict[str, Any]]:
        """Return the manifest ``excluded`` list."""
        return [
            {
                "class": kind,
                "count": self.counts[kind],
                "paths": list(self.examples[kind]),
                "truncated": self.counts[kind] > len(self.examples[kind]),
            }
            for kind in EXCLUDED_CLASSES
        ]


def copy_tree(
    source: Path, destination: Path, *, skip_paths: frozenset[str] = frozenset()
) -> CopyResult:
    """Copy ``source`` into the new folder ``destination`` with the copy and neutralization
    rules of the module docstring.

    ``skip_paths`` holds case-folded POSIX paths, relative to ``source``, of folders to skip
    as the kalkan runs folder. Raises :class:`~kalkan.errors.KalkanError` when ``source``
    cannot be listed and :class:`~kalkan.errors.StateError` when ``destination`` exists.
    """
    result = CopyResult()
    try:
        destination.mkdir()
    except FileExistsError:
        raise StateError("the target copy folder exists already") from None
    try:
        with os.scandir(source):
            pass
    except OSError as exc:
        raise KalkanError("the target folder cannot be read") from exc

    # (source folder, destination folder, source-relative path, destination-relative path,
    #  source folder name)
    stack: list[tuple[Path, Path, str, str, str]] = [(source, destination, "", "", "")]
    while stack:
        src_dir, dst_dir, rel_src, rel_dst, parent_name = stack.pop()
        if rel_src and not _is_real_directory(src_dir):
            result.skip("symlink", rel_src)
            continue
        try:
            with os.scandir(src_dir) as iterator:
                entries = sorted(iterator, key=lambda entry: entry.name)
        except OSError:
            result.skip("unreadable", rel_src or ".")
            continue
        taken = {entry.name.casefold() for entry in entries}
        dotnet_project = any(name.endswith(DOTNET_PROJECT_SUFFIXES) for name in taken)
        for entry in entries:
            name = entry.name
            rel = _join(rel_src, name)
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError:
                result.skip("unreadable", rel)
                continue
            if _is_link(info):
                result.skip("symlink", rel)
                continue
            is_dir = stat.S_ISDIR(info.st_mode)
            folded = name.casefold()
            if is_dir and folded in _SKIPPED:
                result.skip(_SKIPPED[folded], rel)
                continue
            if is_dir and dotnet_project and folded in DOTNET_BUILD_DIRS:
                result.skip("dotnet-build", rel)
                continue
            if is_dir and rel.casefold() in skip_paths:
                result.skip("kalkan-runs", rel)
                continue
            if not paths.is_safe_relative_path(name):
                result.skip("unsafe-name", rel)
                continue
            if not is_dir and not stat.S_ISREG(info.st_mode):
                result.skip("special-file", rel)
                continue
            if not is_dir and info.st_size > MAX_FILE_BYTES:
                result.skip("large-file", rel)
                continue
            new_name = name
            if is_instruction_name(name, parent_name):
                new_name = _neutral_name(name, taken)
                taken.add(new_name.casefold())
                result.neutralized.append(
                    {
                        "area": "target",
                        "path": rel,
                        "renamed_to": _join(rel_dst, new_name),
                        "kind": "directory" if is_dir else "file",
                    }
                )
            target_path = dst_dir / new_name
            if is_dir:
                try:
                    target_path.mkdir()
                except OSError:
                    result.skip("copy-error", rel)
                    continue
                result.directories += 1
                stack.append((Path(entry.path), target_path, rel, _join(rel_dst, new_name), name))
                continue
            try:
                data = read_bounded(entry.path, MAX_FILE_BYTES)
            except UnsafeInputError:
                result.skip("unreadable", rel)
                continue
            try:
                with open(target_path, "xb") as handle:
                    handle.write(data)
            except OSError:
                result.skip("copy-error", rel)
                continue
            result.copied += 1
            result.bytes += len(data)
    return result


def neutralize_in_place(root: Path, *, area: str = "source") -> list[dict[str, str]]:
    """Rename the instruction files and folders under ``root`` in place; return the records.

    Skips the folders of :data:`SKIPPED_DIRS` (``.git`` among them) and never follows links.
    A name that cannot be renamed stays and is not recorded.
    """
    records: list[dict[str, str]] = []
    stack: list[tuple[Path, str, str]] = [(root, "", "")]
    while stack:
        directory, rel_dir, parent_name = stack.pop()
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda entry: entry.name)
        except OSError:
            continue
        taken = {entry.name.casefold() for entry in entries}
        for entry in entries:
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError:
                continue
            if _is_link(info):
                continue
            is_dir = stat.S_ISDIR(info.st_mode)
            name = entry.name
            if is_dir and name.casefold() in _SKIPPED:
                continue
            current = Path(entry.path)
            if is_instruction_name(name, parent_name):
                new_name = _neutral_name(name, taken)
                try:
                    os.rename(current, directory / new_name)
                except OSError:
                    continue
                taken.add(new_name.casefold())
                records.append(
                    {
                        "area": area,
                        "path": _join(rel_dir, name),
                        "renamed_to": _join(rel_dir, new_name),
                        "kind": "directory" if is_dir else "file",
                    }
                )
                current = directory / new_name
                name_now = new_name
            else:
                name_now = name
            if is_dir:
                stack.append((current, _join(rel_dir, name_now), name))
    return records


# ---------------------------------------------------------------------------------------------
# init


def _inner_paths(copy_root: Path, folders: list[Path]) -> frozenset[str]:
    """Return the case-folded POSIX paths of ``folders`` that lie inside ``copy_root``.

    Raises :class:`~kalkan.errors.UnsafeInputError` when ``copy_root`` is one of the folders.
    """
    base = os.path.realpath(copy_root)
    found: set[str] = set()
    for folder in folders:
        try:
            relative = os.path.relpath(os.path.realpath(folder), base)
        except ValueError:  # another drive on Windows
            continue
        if relative == os.curdir:
            raise UnsafeInputError("the target must not be the kalkan runs folder")
        parts = Path(relative).parts
        if not parts or parts[0] == os.pardir or os.path.isabs(relative):
            continue
        found.add(Path(relative).as_posix().casefold())
    return frozenset(found)


def _runs_folders(root: Path) -> list[Path]:
    folders = [root]
    with contextlib.suppress(KalkanError):
        folders.append(resources.home() / "runs")
    return folders


def _create_run_dir(root: Path, name: str, moment: datetime) -> tuple[str, Path]:
    for _ in range(_RUN_DIR_ATTEMPTS):
        run_id = ids.new_run_id(name, moment)
        directory = root / run_id
        try:
            directory.mkdir()
        except FileExistsError:
            continue
        return run_id, directory
    raise StateError("could not create a new run folder")


def _remove_tree(path: Path) -> None:
    def retry(function: Any, target: str, _error: object) -> None:
        with contextlib.suppress(OSError):
            os.chmod(target, stat.S_IWRITE)
            function(target)

    with contextlib.suppress(OSError):
        if sys.version_info >= (3, 12):
            shutil.rmtree(path, onexc=retry)
        else:  # pragma: no cover - Python 3.11
            shutil.rmtree(path, onerror=retry)


def _local_history(
    folder: Path, run_dir: Path, timeout_seconds: int
) -> tuple[Path | None, dict[str, str]]:
    """Make the private history copy of a local target; return ``(source_dir, history)``.

    Only the root of a work tree gets a copy. A failed copy is recorded, not raised.
    """
    if not os.path.lexists(folder / ".git"):
        return None, {
            "status": "none",
            "detail": "the target folder is not the root of a git work tree (no .git entry)",
        }
    if _git_folder(folder) is None:
        return None, {
            "status": "failed",
            "detail": "the .git entry of the target is a link or "
            "names no git folder; no history copy",
        }
    destination = run_dir / SOURCE_DIRNAME
    try:
        copy_history(folder, destination, timeout_seconds=timeout_seconds)
    except ToolError as exc:
        _remove_tree(destination)
        return None, {"status": "failed", "detail": str(exc)}
    return destination, {
        "status": "copied",
        "detail": "private mirror of the local history in source/ (git clone --mirror --no-local)",
    }


def _check_options(
    profile: str,
    lang: str,
    max_parallel: int,
    docker: str,
    allow_build_network: bool,
    mode: str = MODE_AGENTS,
) -> str:
    try:
        canonical = budget.canonical_profile(profile)
    except ValueError as exc:
        raise ValidationError(str(exc)) from None
    if mode not in RUN_MODES:
        raise ValidationError(f"mode must be one of: {', '.join(RUN_MODES)}")
    if lang not in LANGUAGES:
        raise ValidationError(f"lang must be one of: {', '.join(LANGUAGES)}")
    if (
        isinstance(max_parallel, bool)
        or not isinstance(max_parallel, int)
        or not 1 <= max_parallel <= MAX_PARALLEL_LIMIT
    ):
        raise ValidationError(f"max_parallel must be an integer from 1 to {MAX_PARALLEL_LIMIT}")
    if docker not in DOCKER_MODES:
        raise ValidationError(f"docker must be one of: {', '.join(DOCKER_MODES)}")
    if not isinstance(allow_build_network, bool):
        raise ValidationError("allow_build_network must be a boolean")
    return canonical


def _sandbox_expected(docker: str, tools_only: bool) -> bool:
    """Return True when the PoC sandbox will likely run: ``--docker on``, or ``auto`` with an
    answering Docker engine. The PoC budget reserve exists only then."""
    if tools_only or docker == "off":
        return False
    if docker == "on":
        return True
    try:
        from kalkan.sandbox.runner import docker_available  # noqa: PLC0415

        return docker_available()
    except Exception:  # noqa: BLE001 - an unknown engine state gives no reserve
        return False


def _deployments_record(target_dir: Path) -> dict[str, Any] | None:
    """Return the manifest ``deployments`` entry (:mod:`kalkan.findings.deployment`), or None."""
    scan = scan_deployments(target_dir)
    if not scan.sets:
        return None
    return {
        "sets": [{"kind": s.kind, "path": s.path, "files": s.files} for s in scan.sets],
        "files": list(scan.files),
        "truncated": scan.truncated,
    }


def _long_paths_record(target_dir: Path) -> dict[str, Any] | None:
    """Return the manifest ``long_paths`` entry (:mod:`kalkan.util.winpath`), or None."""
    found = find_long_paths(target_dir)
    if not found:
        return None
    return {
        "limit": WINDOWS_PATH_LIMIT,
        "count": len(found),
        "paths": found[:_NEUTRALIZED_LIST_MAX],
        "condition": LONG_PATH_CONDITION,
        "root_length": len(str(target_dir.resolve())),
        "long_paths_enabled": long_paths_enabled(),
    }


def init_run(
    target: str,
    *,
    profile: str = "standard",
    lang: str = "en",
    max_parallel: int = 6,
    docker: str = "auto",
    allow_build_network: bool = False,
    runs_dir: Path | None = None,
    now: datetime | None = None,
    clone_timeout_seconds: int = GIT_CLONE_TIMEOUT_SECONDS,
    ref: str | None = None,
    update_latest: bool = True,
    mode: str = MODE_AGENTS,
    live_paths: Sequence[str] | None = None,
    not_live_paths: Sequence[str] | None = None,
) -> RunContext:
    """Create a run for ``target`` (a local folder or a git URL) and return its context.

    ``profile`` accepts ``fast``, ``standard`` and ``deep`` and their older names;
    the state stores the English name. ``runs_dir`` overrides :func:`kalkan.run.ids.runs_root`.
    ``ref`` (git URL targets only) checks out a tag, branch or commit (:func:`checkout_ref`).
    ``update_latest`` False leaves ``runs/LATEST`` unchanged. ``mode`` ``tools-only`` records
    ``options.mode`` and an agent task budget of 0: the phase engine then skips the agent
    phases (docs/PHASES.md section 3); the default ``agents`` writes no ``mode`` field.
    ``live_paths`` names the deployment that runs in production (target-relative folders or
    files, ``options.live_paths``); the report marks findings only in other deployment files as
    template only (:mod:`kalkan.findings.deployment`). ``not_live_paths`` names code that
    production does not load (``options.not_live_paths``); a finding whose sinks are all there is
    template only as well.
    After init, ``prep`` is done (steps ``copy``, ``neutralize``, ``tech``) and the run phase is
    ``deterministic``. Raises :class:`~kalkan.errors.ValidationError` for invalid options (also
    a ``ref`` with a local folder) and the errors of :func:`classify_target`,
    :func:`clone_repository` and :func:`checkout_ref`.
    """
    canonical = _check_options(profile, lang, max_parallel, docker, allow_build_network, mode)
    try:
        check_live_paths(live_paths or ())
        check_live_paths(not_live_paths or (), option="--not-live")
    except ValueError as exc:
        raise ValidationError(str(exc)) from None
    tools_only = mode == MODE_TOOLS_ONLY
    moment = ids.as_utc(now)
    timestamp = ids.format_ts(moment)
    spec = classify_target(target)
    if ref is not None:
        validate_ref(ref)
        if spec.kind != "git":
            raise ValidationError(
                "--ref works only with a git URL target; for a local folder, check out the ref "
                "there and run init on the folder"
            )
    root = runs_dir if runs_dir is not None else ids.runs_root()
    if spec.kind == "path" and _inner_paths(Path(spec.location), [root]):
        # _inner_paths also refuses the runs folder itself as a target.
        raise UnsafeInputError(
            "the runs folder lies inside the target folder, and kalkan never writes into an "
            "audited folder; set KALKAN_RUNS_DIR to a folder outside the target"
        )
    root.mkdir(parents=True, exist_ok=True)
    run_id, run_dir = _create_run_dir(root, spec.name, moment)
    try:
        source_dir: Path | None
        if spec.kind == "git":
            source_dir = run_dir / SOURCE_DIRNAME
            history = {"status": "cloned", "detail": "git clone of the URL into source/"}
            if ref is None:
                clone_repository(
                    spec.location,
                    source_dir,
                    display=spec.display,
                    timeout_seconds=clone_timeout_seconds,
                )
            else:
                clone_repository(
                    spec.location,
                    source_dir,
                    display=spec.display,
                    timeout_seconds=clone_timeout_seconds,
                    no_checkout=True,
                )
                checkout_ref(
                    source_dir,
                    ref,
                    url=spec.location,
                    display=spec.display,
                    timeout_seconds=clone_timeout_seconds,
                )
        else:
            folder = Path(spec.location)
            source_dir, history = _local_history(folder, run_dir, clone_timeout_seconds)
        # The folder that the target copy comes from: the URL clone, or the original folder
        # (only read).
        copy_from = run_dir / SOURCE_DIRNAME if spec.kind == "git" else Path(spec.location)
        git_ref = git_head(source_dir) if source_dir is not None else read_head(copy_from)
        skip_paths = _inner_paths(copy_from, _runs_folders(root))
        copied = copy_tree(copy_from, run_dir / TARGET_DIRNAME, skip_paths=skip_paths)
        neutralized = list(copied.neutralized)
        if spec.kind == "git":
            neutralized += neutralize_in_place(copy_from, area="source")
        tags = tech.detect(run_dir / TARGET_DIRNAME)

        manifest = {
            "schema_version": SCHEMA_VERSION,
            "run_id": run_id,
            "created_at": timestamp,
            "source": spec.display,
            "kind": spec.kind,
            "source_dir": source_dir.absolute().as_posix() if source_dir is not None else None,
            "history": history,
            "git_ref": git_ref,
            **({"requested_ref": ref} if ref is not None else {}),
            "copy": TARGET_DIRNAME,
            "files": {
                "copied": copied.copied,
                "bytes": copied.bytes,
                "directories": copied.directories,
                "skipped": copied.skipped,
            },
            "excluded": copied.excluded(),
            "neutralized": neutralized[:_NEUTRALIZED_LIST_MAX],
            "neutralized_count": len(neutralized),
            "tech": tags,
        }
        long_paths = _long_paths_record(run_dir / TARGET_DIRNAME)
        if long_paths:
            manifest["long_paths"] = long_paths
        deployments = _deployments_record(run_dir / TARGET_DIRNAME)
        if deployments:
            manifest["deployments"] = deployments
        try:
            live = check_live_paths(live_paths or (), run_dir / TARGET_DIRNAME)
            not_live = check_live_paths(
                not_live_paths or (), run_dir / TARGET_DIRNAME, option="--not-live"
            )
        except ValueError as exc:
            raise ValidationError(str(exc)) from None
        errors = validate(manifest, shared_schema("target-manifest"), "$manifest")
        if errors:  # pragma: no cover - a bug in this module
            raise StateError(f"internal error: invalid target manifest: {errors[0]}")
        atomic_write_json(run_dir / MANIFEST_NAME, manifest)

        phases = new_phases()
        phases["prep"] = {
            "status": "done",
            "started_at": timestamp,
            "finished_at": timestamp,
            "steps": {
                "copy": {
                    "status": "done",
                    "detail": f"{copied.copied} files copied, {copied.skipped} paths skipped",
                },
                "neutralize": {"status": "done", "detail": f"{len(neutralized)} paths renamed"},
                "tech": {"status": "done", "detail": ", ".join(tags) or "none"},
            },
        }
        state: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "run_id": run_id,
            "created_at": timestamp,
            "updated_at": timestamp,
            "target": {
                "source": spec.display,
                "kind": spec.kind,
                "git_ref": git_ref,
                "copy": TARGET_DIRNAME,
            },
            "options": {
                "profile": canonical,
                "lang": lang,
                "max_parallel": max_parallel,
                "allow_build_network": allow_build_network,
                "docker": docker,
                **({"mode": mode} if tools_only else {}),
                **({"live_paths": live} if live else {}),
                **({"not_live_paths": not_live} if not_live else {}),
            },
            "budget": budget.initial_budget(canonical, poc=_sandbox_expected(docker, tools_only)),
            "phase": "deterministic",
            "phases": phases,
            "tasks": {},
            "next_task_seq": 1,
            "incomplete_reason": None,
        }
        if tools_only:
            # No agent task can run: create_task refuses every budget-counted task.
            state["budget"].update(max_agent_tasks=0, reserve_critic=0)
        with run_lock(run_dir):
            save_state(run_dir, state, now=moment)
            events.append_event(
                run_dir,
                "run_initialized",
                run_id=run_id,
                target_kind=spec.kind,
                profile=canonical,
                files_copied=copied.copied,
                paths_skipped=copied.skipped,
                neutralized=len(neutralized),
                tech=tags,
                **({"mode": mode} if tools_only else {}),
            )
        if update_latest:
            ids.write_latest(run_id, root)
    except BaseException:
        _remove_tree(run_dir)
        raise
    return RunContext(run_dir, state)
