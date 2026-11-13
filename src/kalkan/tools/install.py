# SPDX-License-Identifier: MIT
"""Install and verify the pinned tools (docs/ENGINE-SPEC.md, section 12).

- ``binary`` tools: download with urllib (HTTPS, timeouts, HTTPS-only redirects, the TLS context
  of :mod:`kalkan.tools.tls`), hash while streaming, refuse a SHA-256 mismatch, check every
  archive member (no absolute paths, no '..', no links, no device files), extract only the
  declared binary and place it in
  ``.tools/<tool>/<version>/bin/``.
- ``toolchain`` tools (Go): download and hash like a binary tool, check every member of the
  archive (the same rules, plus: every member below the declared top folder, no name that
  Windows cannot store, no duplicate, at most :data:`MAX_TREE_FILES` files and
  :data:`MAX_TREE_BYTES` bytes), extract the whole tree into a new folder, check the SHA-256
  of the executable and of the tree (:func:`kalkan.tools.manifest.tree_digest`) and move the
  folder to ``.tools/<tool>/<version>/``.
- ``pip`` tools: one venv ``.tools/pyenv`` with exact versions. pip runs with
  ``--no-cache-dir``: no download stays in the pip cache of the user.
- ``go-install`` tools: ``go install [build_flags] <module>@<version>`` with the Go of
  :func:`kalkan.tools.golang.resolve_go` and :func:`kalkan.tools.golang.build_env` (``GOBIN``,
  ``GOPATH``, ``GOMODCACHE``, ``GOCACHE``, ``GOTMPDIR`` and the Go configuration folder with
  telemetry off under ``.tools``). When no acceptable Go exists,
  the pinned toolchain is installed first. Without it, the install fails. The install record
  keeps the ``build_flags``; a copy built with other flags is built again. After the go-install
  tools of one call, :func:`remove_go_build` deletes the build folder ``.tools/go-build``: no
  scan reads it, and it held 868 MB in 24,920 files after the govulncheck and poutine builds
  (Windows 11, 2026-10-29). A later build downloads the modules again.

Every install updates ``.tools/installed.json`` atomically. Blocked versions are refused.
"""

from __future__ import annotations

import base64
import contextlib
import csv
import hashlib
import http.client
import json
import os
import re
import shutil
import stat
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
import zlib
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import IO, Any

from kalkan import __version__
from kalkan.errors import ToolError
from kalkan.tools import tls
from kalkan.tools.manifest import Asset, Manifest, Tool, load_manifest, tree_digest
from kalkan.tools.platform import Finder, Runner, find_on_path, platform_key, run_command
from kalkan.tools.resolve import (
    INSTALLED_SCHEMA_VERSION,
    binary_path,
    entry_path,
    go_build_dir,
    go_toolchain_version,
    installed_entry,
    installed_json_path,
    probe_env,
    pyenv_dir,
    pyenv_python,
    pyenv_script,
    read_installed,
    tool_bin_dir,
    tool_dir,
    toolchain_root,
    tools_root,
)
from kalkan.util.fs import TreeStats, remove_tree
from kalkan.util.safe_io import atomic_write_json

STATUS_INSTALLED = "installed"
STATUS_PRESENT = "present"
STATUS_SKIPPED = "skipped"
STATUS_FAILED = "failed"

VERIFY_OK = "ok"
VERIFY_MISMATCH = "mismatch"
VERIFY_MISSING = "missing"
VERIFY_SKIPPED = "skipped"

USER_AGENT = f"kalkan/{__version__} (tools install)"
DOWNLOAD_TIMEOUT_SECONDS = 60.0
DOWNLOAD_DEADLINE_SECONDS = 1800.0
DOWNLOAD_ATTEMPTS = 3
MAX_DOWNLOAD_BYTES = 512 * 1024 * 1024
MAX_BINARY_BYTES = 1024 * 1024 * 1024
CHUNK_BYTES = 1024 * 1024
VENV_TIMEOUT_SECONDS = 600.0
PIP_TIMEOUT_SECONDS = 3600.0
GO_TIMEOUT_SECONDS = 1800.0
QUERY_TIMEOUT_SECONDS = 120.0
#: Limits of a toolchain archive (Go 1.26.9: 15045 files, 236 MB).
MAX_TREE_FILES = 100_000
MAX_TREE_BYTES = 4 * 1024 * 1024 * 1024
#: Characters and names that Windows cannot store in a file name (or that open a data stream).
_WINDOWS_BAD_CHARS = frozenset('<>:"|?*')
_WINDOWS_RESERVED = frozenset(
    {"con", "prn", "aux", "nul"}
    | {f"com{n}" for n in range(1, 10)}
    | {f"lpt{n}" for n in range(1, 10)}
)

Opener = Callable[..., Any]
Log = Callable[[str], None]

_sleep = time.sleep

_LIST_DISTRIBUTIONS = (
    "import importlib.metadata as m, json; "
    "print(json.dumps({d.metadata['Name']: d.version for d in m.distributions() "
    "if d.metadata['Name']}, sort_keys=True))"
)


@dataclass(frozen=True)
class InstallResult:
    """The outcome of installing one tool.

    ``status`` is ``installed``, ``present`` (already installed and intact), ``skipped`` (not
    possible on this machine, for example no build for the platform or no Go) or ``failed``.
    ``path`` is relative to the repository root with forward slashes.
    """

    name: str
    version: str
    kind: str
    status: str
    message: str = ""
    path: str | None = None
    sha256: str | None = None

    @property
    def ok(self) -> bool:
        """Return True unless the install failed."""
        return self.status != STATUS_FAILED

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-ready dict."""
        return asdict(self)


@dataclass(frozen=True)
class VerifyResult:
    """The outcome of re-hashing one installed tool.

    ``status`` is ``ok``, ``mismatch`` (hash or version differs), ``missing`` (not installed) or
    ``skipped`` (cannot be installed on this machine).
    """

    name: str
    version: str
    kind: str
    status: str
    message: str = ""
    path: str | None = None
    expected_sha256: str | None = None
    actual_sha256: str | None = None

    @property
    def ok(self) -> bool:
        """Return True for ``ok`` and ``skipped``."""
        return self.status in (VERIFY_OK, VERIFY_SKIPPED)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-ready dict."""
        return asdict(self)


# ---------------------------------------------------------------------------------------------
# Public API


def select_tools(manifest: Manifest, names: Iterable[str] | str | None) -> list[Tool]:
    """Return the selected tools in manifest order. ``None`` or ``"all"`` selects every tool."""
    if names is None or names == "all":
        return list(manifest)
    wanted = [names] if isinstance(names, str) else list(names)
    unknown = [name for name in wanted if name not in manifest]
    if unknown:
        known = ", ".join(manifest.names())
        raise ToolError(f"unknown tool(s): {', '.join(unknown)} (known tools: {known})")
    chosen = set(wanted)
    return [tool for tool in manifest if tool.name in chosen]


def install(
    names: Iterable[str] | str | None = "all",
    *,
    repo_root: str | os.PathLike[str],
    force: bool = False,
    manifest: Manifest | None = None,
    key: str | None = None,
    runner: Runner | None = None,
    finder: Finder | None = None,
    opener: Opener | None = None,
    log: Log | None = None,
) -> list[InstallResult]:
    """Install the selected tools (``"all"`` or a list of names) under ``<repo_root>/.tools``.

    Toolchains install first, so that the go-install tools build with them. A go-install tool
    without an acceptable Go installs the pinned toolchain itself; its result is then part of
    the list too. The list follows the manifest order. A failure of one tool does not stop the
    others: check ``result.status`` for ``failed``. Raises ToolError for an unknown tool name.
    A call with a go-install tool ends its go-install part with :func:`remove_go_build`, also
    when every tool was present: an older install left the folder behind.
    """
    manifest = manifest or load_manifest()
    selected = select_tools(manifest, names)
    root = Path(repo_root).resolve()
    key = key or platform_key()
    run = runner or run_command
    find = finder or find_on_path
    say = log or _quiet

    results: dict[str, InstallResult] = {}
    for tool in selected:
        if tool.kind == "toolchain":
            results[tool.name] = _install_toolchain(tool, root, key, force, opener, say)
    for tool in selected:
        if tool.kind == "binary":
            results[tool.name] = _install_binary(tool, root, key, force, opener, say)
        elif tool.kind == "go-install":
            context = _GoContext(manifest, root, key, run, find, opener, say, results)
            results[tool.name] = _install_go(tool, context, force)
    if any(tool.kind == "go-install" for tool in selected):
        remove_go_build(root, say)
    pip_tools = [tool for tool in selected if tool.kind == "pip"]
    if pip_tools:
        for result in _install_pip(pip_tools, root, force, run, say):
            results[result.name] = result
    return [results[tool.name] for tool in manifest if tool.name in results]


def verify(
    names: Iterable[str] | str | None = "all",
    *,
    repo_root: str | os.PathLike[str],
    manifest: Manifest | None = None,
    key: str | None = None,
    runner: Runner | None = None,
    finder: Finder | None = None,
    deep: bool = True,
) -> list[VerifyResult]:
    """Re-hash the installed tools against the manifest (binary tools) or the install record.

    A toolchain tree has many files (Go: 15045). ``deep=True`` re-hashes all of them; on Windows
    with a real-time virus scanner this read took minutes. ``deep=False`` (``kalkan doctor``)
    hashes the executable, counts the files and checks the install record instead.
    """
    manifest = manifest or load_manifest()
    selected = select_tools(manifest, names)
    root = Path(repo_root).resolve()
    key = key or platform_key()
    run = runner or run_command
    find = finder or find_on_path
    results: list[VerifyResult] = []
    for tool in selected:
        if tool.kind == "binary":
            results.append(_verify_binary(tool, root, key))
        elif tool.kind == "toolchain":
            results.append(_verify_toolchain(tool, root, key, deep=deep))
        elif tool.kind == "pip":
            results.append(_verify_pip(tool, root, run))
        else:
            results.append(_verify_go(tool, root, key, find))
    return results


def sha256_file(path: str | os.PathLike[str]) -> str:
    """Return the hex SHA-256 of a file."""
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


# ---------------------------------------------------------------------------------------------
# Binary tools


def _install_binary(
    tool: Tool, root: Path, key: str, force: bool, opener: Opener | None, say: Log
) -> InstallResult:
    def result(status: str, message: str, path: Path | None = None, digest: str | None = None):
        rel = _rel(root, path) if path is not None else None
        return InstallResult(tool.name, tool.version, tool.kind, status, message, rel, digest)

    if tool.is_blocked(tool.version):
        return result(STATUS_FAILED, f"version {tool.version} is blocked; refusing to install it")
    asset = tool.asset(key)
    if asset is None:
        reason = f"the {tool.name} {tool.version} release has no build for {key}"
        return result(STATUS_SKIPPED, f"{reason}. {tool.notes}".strip())
    target = binary_path(root, tool, key)
    if not force and target.is_file():
        expected = asset.binary_sha256 or (installed_entry(root, tool.name) or {}).get("sha256")
        actual = sha256_file(target)
        if expected and actual == expected:
            _record_binary(root, tool, key, asset, target, actual)
            return result(STATUS_PRESENT, "already installed, SHA-256 ok", target, actual)
    try:
        digest = _fetch_and_place(tool, asset, root, target, opener, say)
    except (ToolError, OSError) as exc:
        return result(STATUS_FAILED, str(exc))
    _record_binary(root, tool, key, asset, target, digest)
    return result(STATUS_INSTALLED, f"installed from {asset.url}", target, digest)


def _fetch_and_place(
    tool: Tool, asset: Asset, root: Path, target: Path, opener: Opener | None, say: Log
) -> str:
    staging = tools_root(root) / ".tmp"
    staging.mkdir(parents=True, exist_ok=True)
    target.parent.mkdir(parents=True, exist_ok=True)
    size = f" ({asset.size / 1_000_000:.1f} MB)" if asset.size else ""
    say(f"Downloading {tool.name} {tool.version}{size}: {asset.url}")
    download: Path | None = None
    staged: Path | None = None
    try:
        download = download_verified(
            asset.url, asset.sha256, dest_dir=staging, max_bytes=asset.size, opener=opener
        )
        if asset.archive == "none":
            staged, digest = download, asset.sha256
        else:
            staged, digest = extract_member(download, asset.archive, asset.binary, target.parent)
        if asset.binary_sha256 and digest != asset.binary_sha256:
            raise ToolError(
                f"SHA-256 mismatch for {asset.binary} from {asset.url}: expected "
                f"{asset.binary_sha256}, got {digest}"
            )
        if os.name != "nt":
            os.chmod(staged, 0o755)
        _replace(staged, target)
        staged = None
    finally:
        for leftover in (download, staged):
            if leftover is not None:
                with contextlib.suppress(OSError):
                    leftover.unlink(missing_ok=True)
        with contextlib.suppress(OSError):
            staging.rmdir()
    return digest


def _replace(source: str | os.PathLike[str], target: str | os.PathLike[str]) -> None:
    """os.replace with a few retries on Windows, where a virus scanner can hold a new file."""
    attempts = 5 if os.name == "nt" else 1
    for attempt in range(1, attempts + 1):
        try:
            os.replace(source, target)
            return
        except PermissionError:
            if attempt == attempts:
                raise
            _sleep(0.2 * attempt)


def _record_binary(root: Path, tool: Tool, key: str, asset: Asset, target: Path, digest: str):
    record = {
        "version": tool.version,
        "kind": tool.kind,
        "platform": key,
        "path": _rel(root, target),
        "sha256": digest,
        "asset_url": asset.url,
        "asset_sha256": asset.sha256,
        "installed_at": _now(),
    }
    previous = installed_entry(root, tool.name)
    if previous and _same_install(previous, record):
        record["installed_at"] = previous.get("installed_at", record["installed_at"])
        if previous == record:
            return
    _update_installed(root, {tool.name: record})


def _same_install(previous: dict[str, Any], record: dict[str, Any]) -> bool:
    keys = ("version", "path", "sha256", "asset_sha256")
    return all(previous.get(k) == record.get(k) for k in keys)


def _verify_binary(tool: Tool, root: Path, key: str) -> VerifyResult:
    asset = tool.asset(key)
    if asset is None:
        return VerifyResult(
            tool.name, tool.version, tool.kind, VERIFY_SKIPPED, f"no build for {key}"
        )
    target = binary_path(root, tool, key)
    rel = _rel(root, target)
    entry = installed_entry(root, tool.name) or {}
    expected = asset.binary_sha256 or entry.get("sha256")
    if not target.is_file():
        return VerifyResult(
            tool.name, tool.version, tool.kind, VERIFY_MISSING, "not installed", rel, expected
        )
    actual = sha256_file(target)
    if expected is None:
        message = "no reference SHA-256 in the manifest or in installed.json"
        status = VERIFY_MISMATCH
    elif actual == expected:
        message, status = "SHA-256 ok", VERIFY_OK
    else:
        message, status = "SHA-256 differs from the pinned value", VERIFY_MISMATCH
    return VerifyResult(tool.name, tool.version, tool.kind, status, message, rel, expected, actual)


# ---------------------------------------------------------------------------------------------
# Download and extraction


class _HttpsOnlyRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follow redirects, but only to HTTPS URLs."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.lower().startswith("https://"):
            raise urllib.error.HTTPError(
                newurl, code, f"refusing a redirect to a non-HTTPS URL: {newurl}", headers, fp
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _default_opener() -> Opener:
    https = urllib.request.HTTPSHandler(context=tls.ssl_context())
    return urllib.request.build_opener(https, _HttpsOnlyRedirectHandler).open


def download_verified(
    url: str,
    sha256: str,
    *,
    dest_dir: str | os.PathLike[str],
    max_bytes: int | None = None,
    opener: Opener | None = None,
) -> Path:
    """Download ``url`` into a new file in ``dest_dir`` and check its SHA-256.

    The file is hashed while it streams. A mismatch deletes the file and raises ToolError.
    Only ``https://`` and ``file://`` URLs are accepted. ``max_bytes`` (default 512 MiB) stops
    an oversized download.
    """
    lowered = url.lower()
    if not lowered.startswith(("https://", "file://")):
        raise ToolError(f"refusing to download from a non-HTTPS URL: {url}")
    open_url = opener or _default_opener()
    limit = max_bytes or MAX_DOWNLOAD_BYTES
    attempts = DOWNLOAD_ATTEMPTS if lowered.startswith("https://") else 1
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            path, actual = _stream_to_file(url, Path(dest_dir), limit, open_url)
        except urllib.error.HTTPError as exc:
            last_error = exc
            if 400 <= exc.code < 500:
                break
        except (urllib.error.URLError, http.client.HTTPException, TimeoutError, OSError) as exc:
            last_error = exc
        else:
            if actual != sha256:
                with contextlib.suppress(OSError):
                    path.unlink(missing_ok=True)
                raise ToolError(
                    f"SHA-256 mismatch for {url}: expected {sha256}, got {actual}. "
                    "The download was deleted."
                )
            return path
        if attempt < attempts:
            _sleep(2.0 * attempt)
    raise ToolError(f"download failed: {url}: {tls.explain(last_error)}")


def _stream_to_file(url: str, dest_dir: Path, limit: int, open_url: Opener) -> tuple[Path, str]:
    request = urllib.request.Request(
        url, headers={"User-Agent": USER_AGENT, "Accept": "application/octet-stream"}
    )
    dest_dir.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix="download-", suffix=".part", dir=dest_dir)
    path = Path(name)
    digest = hashlib.sha256()
    total = 0
    deadline = time.monotonic() + DOWNLOAD_DEADLINE_SECONDS
    try:
        with (
            os.fdopen(fd, "wb") as out,
            open_url(request, timeout=DOWNLOAD_TIMEOUT_SECONDS) as resp,
        ):
            while True:
                chunk = resp.read(CHUNK_BYTES)
                if not chunk:
                    break
                total += len(chunk)
                if total > limit:
                    raise ToolError(f"download of {url} is larger than {limit} bytes; refused")
                if time.monotonic() > deadline:
                    raise ToolError(
                        f"download of {url} took longer than {DOWNLOAD_DEADLINE_SECONDS:.0f} s"
                    )
                digest.update(chunk)
                out.write(chunk)
    except BaseException:
        with contextlib.suppress(OSError):
            path.unlink(missing_ok=True)
        raise
    return path, digest.hexdigest()


def archive_member_problem(name: str) -> str | None:
    """Return why an archive member name is unsafe (absolute path, drive, '..'), or None."""
    text = name.replace("\\", "/")
    if "\x00" in text:
        return f"member name with a NUL byte: {name!r}"
    if text.startswith("/") or re.match(r"^[A-Za-z]:", text):
        return f"absolute member path: {name!r}"
    if ".." in text.split("/"):
        return f"member path with '..': {name!r}"
    return None


def _normalize_member(name: str) -> str:
    parts = name.replace("\\", "/").split("/")
    return "/".join(part for part in parts if part not in ("", "."))


def _zip_member_problem(info: zipfile.ZipInfo) -> str | None:
    problem = archive_member_problem(info.filename)
    if problem:
        return problem
    mode = (info.external_attr >> 16) & 0xFFFF
    kind = stat.S_IFMT(mode)
    if stat.S_ISLNK(mode):
        return f"symbolic link member: {info.filename!r}"
    if kind and kind not in (stat.S_IFREG, stat.S_IFDIR):
        return f"device or special file member: {info.filename!r}"
    if info.flag_bits & 0x1:
        return f"encrypted member: {info.filename!r}"
    return None


def _tar_member_problem(info: tarfile.TarInfo) -> str | None:
    problem = archive_member_problem(info.name)
    if problem:
        return problem
    if info.issym() or info.islnk():
        return f"link member: {info.name!r} -> {info.linkname!r}"
    if info.ischr() or info.isblk() or info.isfifo() or info.isdev():
        return f"device or special file member: {info.name!r}"
    if not (info.isfile() or info.isdir()):
        return f"unsupported member type: {info.name!r}"
    return None


def extract_member(
    archive: str | os.PathLike[str], kind: str, member: str, dest_dir: str | os.PathLike[str]
) -> tuple[Path, str]:
    """Check every member of a zip or tar.gz archive, then extract one member to a new file.

    Returns the path of the new file in ``dest_dir`` and its SHA-256. Raises ToolError when
    any member is unsafe (absolute path, '..', link, device file), when the member is missing
    or duplicated, or when the archive is corrupt.
    """
    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)
    if kind == "zip":
        return _extract_from_zip(Path(archive), member, dest)
    if kind == "tar.gz":
        return _extract_from_tar(Path(archive), member, dest)
    raise ToolError(f"unsupported archive type: {kind}")


def _extract_from_zip(archive: Path, member: str, dest: Path) -> tuple[Path, str]:
    try:
        zf = zipfile.ZipFile(archive)
    except (zipfile.BadZipFile, OSError) as exc:
        raise ToolError(f"cannot open the zip archive: {exc}") from exc
    with zf:
        infos = zf.infolist()
        for info in infos:
            problem = _zip_member_problem(info)
            if problem:
                raise ToolError(f"unsafe archive, nothing extracted: {problem}")
        matches = [info for info in infos if _normalize_member(info.filename) == member]
        info = _single_member(matches, member)
        if info.is_dir():
            raise ToolError(f"archive member {member!r} is a directory")
        if info.file_size > MAX_BINARY_BYTES:
            raise ToolError(f"archive member {member!r} is larger than {MAX_BINARY_BYTES} bytes")
        try:
            with zf.open(info) as src:
                return _copy_to_new_file(src, dest)
        except (zipfile.BadZipFile, zlib.error, OSError) as exc:
            raise ToolError(f"cannot extract {member!r}: {exc}") from exc


def _extract_from_tar(archive: Path, member: str, dest: Path) -> tuple[Path, str]:
    try:
        tf = tarfile.open(archive, mode="r:gz")
    except (tarfile.TarError, OSError, EOFError, zlib.error) as exc:
        raise ToolError(f"cannot open the tar.gz archive: {exc}") from exc
    with tf:
        try:
            infos = tf.getmembers()
        except (tarfile.TarError, OSError, EOFError, zlib.error) as exc:
            raise ToolError(f"corrupt tar.gz archive: {exc}") from exc
        for info in infos:
            problem = _tar_member_problem(info)
            if problem:
                raise ToolError(f"unsafe archive, nothing extracted: {problem}")
        matches = [info for info in infos if _normalize_member(info.name) == member]
        info = _single_member(matches, member)
        if not info.isfile():
            raise ToolError(f"archive member {member!r} is not a regular file")
        if info.size > MAX_BINARY_BYTES:
            raise ToolError(f"archive member {member!r} is larger than {MAX_BINARY_BYTES} bytes")
        try:
            src = tf.extractfile(info)
            if src is None:
                raise ToolError(f"cannot read archive member {member!r}")
            with src:
                return _copy_to_new_file(src, dest)
        except (tarfile.TarError, OSError, EOFError, zlib.error) as exc:
            raise ToolError(f"cannot extract {member!r}: {exc}") from exc


def _single_member(matches: list, member: str):
    if not matches:
        raise ToolError(f"the archive has no member {member!r}")
    if len(matches) > 1:
        raise ToolError(f"the archive has {len(matches)} members named {member!r}")
    return matches[0]


def _copy_to_new_file(src: IO[bytes], dest: Path) -> tuple[Path, str]:
    fd, name = tempfile.mkstemp(prefix=".extract-", suffix=".tmp", dir=dest)
    path = Path(name)
    digest = hashlib.sha256()
    total = 0
    try:
        with os.fdopen(fd, "wb") as out:
            for chunk in iter(lambda: src.read(CHUNK_BYTES), b""):
                total += len(chunk)
                if total > MAX_BINARY_BYTES:
                    raise ToolError(f"extracted file is larger than {MAX_BINARY_BYTES} bytes")
                digest.update(chunk)
                out.write(chunk)
    except BaseException:
        with contextlib.suppress(OSError):
            path.unlink(missing_ok=True)
        raise
    return path, digest.hexdigest()


# ---------------------------------------------------------------------------------------------
# Toolchains (whole archive trees: Go)


def _install_toolchain(
    tool: Tool, root: Path, key: str, force: bool, opener: Opener | None, say: Log
) -> InstallResult:
    def result(status: str, message: str, path: Path | None = None, digest: str | None = None):
        rel = _rel(root, path) if path is not None else None
        return InstallResult(tool.name, tool.version, tool.kind, status, message, rel, digest)

    if tool.is_blocked(tool.version):
        return result(STATUS_FAILED, f"version {tool.version} is blocked; refusing to install it")
    asset = tool.asset(key)
    if asset is None:
        reason = f"the {tool.name} {tool.version} release has no build for {key}"
        return result(STATUS_SKIPPED, f"{reason}. {tool.notes}".strip())
    final = tool_dir(root, tool)
    exe = binary_path(root, tool, key)
    if not force and exe.is_file():
        problem = _toolchain_problem(root, tool, key, asset, deep=False)
        if problem is None:
            _record_toolchain(root, tool, key, asset)
            message = "already installed: executable SHA-256, file count and record ok"
            return result(STATUS_PRESENT, message, exe, asset.binary_sha256)
        say(f"{tool.name} {tool.version}: {problem}; installing it again")
    try:
        _fetch_tree(tool, asset, root, final, opener, say)
    except (ToolError, OSError) as exc:
        return result(STATUS_FAILED, str(exc))
    _record_toolchain(root, tool, key, asset)
    message = f"installed from {asset.url} ({asset.files} files)"
    return result(STATUS_INSTALLED, message, exe, asset.binary_sha256)


def _fetch_tree(
    tool: Tool, asset: Asset, root: Path, final: Path, opener: Opener | None, say: Log
) -> None:
    staging_root = tools_root(root) / ".tmp"
    staging_root.mkdir(parents=True, exist_ok=True)
    size = f" ({asset.size / 1_000_000:.1f} MB)" if asset.size else ""
    say(f"Downloading {tool.name} {tool.version}{size}: {asset.url}")
    download: Path | None = None
    staging = Path(tempfile.mkdtemp(prefix=f"{tool.name}-", dir=staging_root))
    old: Path | None = None
    try:
        download = download_verified(
            asset.url, asset.sha256, dest_dir=staging_root, max_bytes=asset.size, opener=opener
        )
        say(f"Extracting {tool.name} {tool.version} ({asset.files or '?'} files)")
        files, digest = extract_tree(download, asset.archive, asset.root or "", staging)
        if asset.files is not None and files != asset.files:
            raise ToolError(f"the archive has {files} files, the manifest pins {asset.files}")
        if asset.tree_sha256 and digest != asset.tree_sha256:
            raise ToolError(
                f"tree SHA-256 mismatch for {asset.url}: expected {asset.tree_sha256}, got {digest}"
            )
        exe_digest = sha256_file(_fs(staging / asset.binary))
        if asset.binary_sha256 and exe_digest != asset.binary_sha256:
            raise ToolError(
                f"SHA-256 mismatch for {asset.binary} from {asset.url}: expected "
                f"{asset.binary_sha256}, got {exe_digest}"
            )
        final.parent.mkdir(parents=True, exist_ok=True)
        if os.path.lexists(_fs(final)):
            old = Path(tempfile.mkdtemp(prefix=f"{tool.name}-old-", dir=staging_root))
            old.rmdir()
            _replace(_fs(final), _fs(old))
        try:
            _replace(_fs(staging), _fs(final))
        except OSError:
            if old is not None:  # put the previous tree back
                with contextlib.suppress(OSError):
                    _replace(_fs(old), _fs(final))
                    old = None
            raise
        staging = None  # type: ignore[assignment]
    finally:
        if download is not None:
            with contextlib.suppress(OSError):
                download.unlink(missing_ok=True)
        for leftover in (staging, old):
            if leftover is not None:
                _remove_tree(leftover)
        with contextlib.suppress(OSError):
            staging_root.rmdir()


def _record_toolchain(root: Path, tool: Tool, key: str, asset: Asset) -> None:
    exe = binary_path(root, tool, key)
    goroot = toolchain_root(root, tool, key)
    record = {
        "version": tool.version,
        "kind": tool.kind,
        "platform": key,
        "path": _rel(root, exe),
        "root": _rel(root, goroot) if goroot is not None else None,
        "sha256": asset.binary_sha256,
        "files": asset.files,
        "tree_sha256": asset.tree_sha256,
        "asset_url": asset.url,
        "asset_sha256": asset.sha256,
        "installed_at": _now(),
    }
    previous = installed_entry(root, tool.name)
    keys = ("version", "path", "sha256", "tree_sha256", "asset_sha256")
    if previous and all(previous.get(k) == record.get(k) for k in keys):
        return
    _update_installed(root, {tool.name: record})


def _toolchain_problem(root: Path, tool: Tool, key: str, asset: Asset, *, deep: bool) -> str | None:
    """Check an installed toolchain tree. Return None when it matches the manifest.

    ``deep`` re-hashes every file (:func:`hash_tree`). Otherwise the check hashes the
    executable, counts the files (no file is read) and needs an install record whose tree
    SHA-256 is the pinned one: kalkan writes that record only after it checked the tree of the
    extracted archive. Without such a record the check is deep.
    """
    exe = binary_path(root, tool, key)
    if not exe.is_file():
        return "not installed"
    entry = installed_entry(root, tool.name) or {}
    recorded = entry.get("version") == tool.version and entry.get("tree_sha256") == (
        asset.tree_sha256
    )
    try:
        if not deep and recorded:
            if asset.binary_sha256 and sha256_file(_fs(exe)) != asset.binary_sha256:
                return f"SHA-256 of {asset.binary} differs from the pinned value"
            files, digest = hash_tree(tool_dir(root, tool), hash_files=False)
        else:
            files, digest = hash_tree(tool_dir(root, tool))
    except (ToolError, OSError) as exc:
        return str(exc)
    if asset.files is not None and files != asset.files:
        return f"{files} files installed, the manifest pins {asset.files}"
    if digest and asset.tree_sha256 and digest != asset.tree_sha256:
        return "tree SHA-256 differs from the pinned value"
    return None


def _verify_toolchain(tool: Tool, root: Path, key: str, *, deep: bool = True) -> VerifyResult:
    def result(status: str, message: str, actual: str | None = None) -> VerifyResult:
        return VerifyResult(
            tool.name, tool.version, tool.kind, status, message, rel, expected, actual
        )

    asset = tool.asset(key)
    if asset is None:
        return VerifyResult(
            tool.name, tool.version, tool.kind, VERIFY_SKIPPED, f"no build for {key}"
        )
    rel = _rel(root, binary_path(root, tool, key))
    expected = asset.tree_sha256
    if not binary_path(root, tool, key).is_file():
        return result(VERIFY_MISSING, "not installed")
    problem = _toolchain_problem(root, tool, key, asset, deep=deep)
    if problem is not None:
        return result(VERIFY_MISMATCH, problem)
    if deep:
        return result(VERIFY_OK, f"tree SHA-256 ok ({asset.files} files)", expected)
    message = f"executable SHA-256 ok, {asset.files} files, tree SHA-256 recorded at install"
    return result(VERIFY_OK, message)


def hash_tree(folder: str | os.PathLike[str], *, hash_files: bool = True) -> tuple[int, str]:
    """Return the number of files and the tree digest of an installed folder.

    Paths are relative to ``folder`` with forward slashes. A symbolic link, a Windows reparse
    point or a special file anywhere in the tree raises ToolError: kalkan never creates one.
    With ``hash_files=False`` no file is read and the digest is ``""`` (a fast count).
    """
    base = Path(folder)
    entries: list[tuple[str, str]] = []
    pending: list[tuple[str, str]] = [(_fs(base), "")]
    while pending:
        current, prefix = pending.pop()
        with os.scandir(current) as found:
            for entry in found:
                rel = f"{prefix}{entry.name}"
                info = entry.stat(follow_symlinks=False)
                if _is_link(info):
                    raise ToolError(f"link in the installed tree: {rel}")
                if stat.S_ISDIR(info.st_mode):
                    pending.append((entry.path, rel + "/"))
                elif stat.S_ISREG(info.st_mode):
                    entries.append((rel, sha256_file(entry.path) if hash_files else ""))
                else:
                    raise ToolError(f"special file in the installed tree: {rel}")
    return len(entries), (tree_digest(entries) if hash_files else "")


def _is_link(info: os.stat_result) -> bool:
    if stat.S_ISLNK(info.st_mode):
        return True
    attributes = getattr(info, "st_file_attributes", 0)
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def tree_member_problem(name: str) -> str | None:
    """Return why a toolchain member name is unsafe on any supported system, or None.

    Adds to :func:`archive_member_problem`: control characters, the characters ``<>:"|?*``
    (``:`` opens an NTFS data stream), reserved Windows device names, and names that end in a
    dot or a space.
    """
    problem = archive_member_problem(name)
    if problem:
        return problem
    for part in _normalize_member(name).split("/"):
        if any(ord(char) < 32 for char in part) or _WINDOWS_BAD_CHARS.intersection(part):
            return f"member name with a character that Windows cannot store: {name!r}"
        if part.split(".", 1)[0].lower() in _WINDOWS_RESERVED:
            return f"member name with a reserved Windows device name: {name!r}"
        if part.endswith((".", " ")):
            return f"member name that ends in a dot or a space: {name!r}"
    return None


def extract_tree(
    archive: str | os.PathLike[str], kind: str, root_name: str, dest_dir: str | os.PathLike[str]
) -> tuple[int, str]:
    """Check every member of a toolchain archive, then extract the whole tree into ``dest_dir``.

    Every member must be ``root_name`` or below it, a regular file or a folder (no link, no
    device), with a safe name (:func:`tree_member_problem`), unique without regard to case, and
    not below a member that is a file. ``dest_dir`` must be an empty folder. Returns the number
    of files and the tree digest of the extracted files. Raises ToolError and extracts nothing
    when any member is unsafe or a limit is passed.
    """
    dest = Path(dest_dir)
    if not dest.is_dir() or any(dest.iterdir()):
        raise ToolError(f"the extraction folder must be an empty folder: {dest}")
    if kind == "zip":
        return _extract_zip_tree(Path(archive), root_name, dest)
    if kind == "tar.gz":
        return _extract_tar_tree(Path(archive), root_name, dest)
    raise ToolError(f"unsupported archive type: {kind}")


def _plan_tree(items: list[tuple[str, bool, int]], root_name: str) -> None:
    """Check the member list ``(name, is_dir, size)``; raise ToolError for the first problem."""
    if len(items) > MAX_TREE_FILES:
        raise ToolError(f"unsafe archive, nothing extracted: more than {MAX_TREE_FILES} members")
    seen: dict[str, bool] = {}
    total = 0
    for name, is_dir, size in items:
        problem = tree_member_problem(name)
        if problem:
            raise ToolError(f"unsafe archive, nothing extracted: {problem}")
        normal = _normalize_member(name)
        if not root_name or (normal != root_name and not normal.startswith(root_name + "/")):
            raise ToolError(
                f"unsafe archive, nothing extracted: member outside the folder {root_name!r}: "
                f"{name!r}"
            )
        folded = normal.casefold()
        if folded in seen and not (is_dir and seen[folded]):
            raise ToolError(f"unsafe archive, nothing extracted: duplicate member {name!r}")
        seen[folded] = is_dir
        if not is_dir:
            total += size
            if size > MAX_BINARY_BYTES or total > MAX_TREE_BYTES:
                raise ToolError(f"unsafe archive, nothing extracted: too large at {name!r}")
    for folded in seen:
        parts = folded.split("/")
        for depth in range(1, len(parts)):
            if seen.get("/".join(parts[:depth])) is False:
                raise ToolError(
                    f"unsafe archive, nothing extracted: member below a file: {folded!r}"
                )


def _extract_zip_tree(archive: Path, root_name: str, dest: Path) -> tuple[int, str]:
    try:
        zf = zipfile.ZipFile(archive)
    except (zipfile.BadZipFile, OSError) as exc:
        raise ToolError(f"cannot open the zip archive: {exc}") from exc
    with zf:
        infos = zf.infolist()
        for info in infos:
            problem = _zip_member_problem(info)
            if problem:
                raise ToolError(f"unsafe archive, nothing extracted: {problem}")
        _plan_tree([(i.filename, i.is_dir(), i.file_size) for i in infos], root_name)
        entries: list[tuple[str, str]] = []
        try:
            for info in infos:
                name = _normalize_member(info.filename)
                if info.is_dir():
                    os.makedirs(_fs(dest / name), exist_ok=True)
                    continue
                mode = (info.external_attr >> 16) & 0o777
                with zf.open(info) as src:
                    entries.append((name, _write_member(src, dest / name, mode)))
        except (zipfile.BadZipFile, zlib.error, OSError) as exc:
            raise ToolError(f"cannot extract the zip archive: {exc}") from exc
    return len(entries), tree_digest(entries)


def _extract_tar_tree(archive: Path, root_name: str, dest: Path) -> tuple[int, str]:
    try:
        tf = tarfile.open(archive, mode="r:gz")
    except (tarfile.TarError, OSError, EOFError, zlib.error) as exc:
        raise ToolError(f"cannot open the tar.gz archive: {exc}") from exc
    with tf:
        try:
            infos = tf.getmembers()
        except (tarfile.TarError, OSError, EOFError, zlib.error) as exc:
            raise ToolError(f"corrupt tar.gz archive: {exc}") from exc
        for info in infos:
            problem = _tar_member_problem(info)
            if problem:
                raise ToolError(f"unsafe archive, nothing extracted: {problem}")
        _plan_tree([(i.name, i.isdir(), i.size) for i in infos], root_name)
        entries: list[tuple[str, str]] = []
        try:
            for info in infos:
                name = _normalize_member(info.name)
                if info.isdir():
                    os.makedirs(_fs(dest / name), exist_ok=True)
                    continue
                src = tf.extractfile(info)
                if src is None:
                    raise ToolError(f"cannot read archive member {info.name!r}")
                with src:
                    entries.append((name, _write_member(src, dest / name, info.mode & 0o777)))
        except (tarfile.TarError, OSError, EOFError, zlib.error) as exc:
            raise ToolError(f"cannot extract the tar.gz archive: {exc}") from exc
    return len(entries), tree_digest(entries)


def _write_member(src: IO[bytes], target: Path, mode: int) -> str:
    """Write one member to a new file (never over an existing one) and return its SHA-256."""
    os.makedirs(_fs(target.parent), exist_ok=True)
    digest = hashlib.sha256()
    total = 0
    with open(_fs(target), "xb") as out:
        for chunk in iter(lambda: src.read(CHUNK_BYTES), b""):
            total += len(chunk)
            if total > MAX_BINARY_BYTES:
                raise ToolError(f"extracted file is larger than {MAX_BINARY_BYTES} bytes")
            digest.update(chunk)
            out.write(chunk)
    if os.name != "nt":
        os.chmod(target, 0o755 if mode & 0o111 else 0o644)
    return digest.hexdigest()


def _fs(path: str | os.PathLike[str]) -> str:
    """Return an absolute path string. On Windows it has the extended-length prefix, so a path
    of 260 or more characters also works (the Go tree is deep)."""
    text = os.path.abspath(os.fspath(path))
    if os.name != "nt" or text.startswith("\\\\?\\"):
        return text
    if text.startswith("\\\\"):
        return "\\\\?\\UNC\\" + text[2:]
    return "\\\\?\\" + text


def _remove_tree(path: Path) -> None:
    """Remove a folder tree; clear read-only flags on Windows; ignore a missing folder."""

    def retry(function, name, _error):
        with contextlib.suppress(OSError):
            os.chmod(name, stat.S_IWRITE | stat.S_IREAD)
            function(name)

    target = _fs(path)
    if not os.path.lexists(target):
        return
    if sys.version_info >= (3, 12):
        shutil.rmtree(target, onexc=retry)
    else:
        shutil.rmtree(target, onerror=retry)


# ---------------------------------------------------------------------------------------------
# pip tools


def _install_pip(
    tools: list[Tool], root: Path, force: bool, run: Runner, say: Log
) -> list[InstallResult]:
    python = pyenv_python(root)
    results: dict[str, InstallResult] = {}
    pending: list[Tool] = []
    try:
        current = _pyenv_versions(python, run) if python.is_file() else {}
    except ToolError:
        current = {}  # a broken tool venv: pip install below repairs or reports it
    for tool in tools:
        if tool.is_blocked(tool.version):
            results[tool.name] = _pip_result(
                tool, root, STATUS_FAILED, f"version {tool.version} is blocked; refusing it"
            )
            continue
        script = pyenv_script(root, tool.executable)
        if not force and script and _dist_version(current, tool.package) == tool.version:
            _record_pip(root, tool, script, current)
            results[tool.name] = _pip_result(
                tool, root, STATUS_PRESENT, "already installed in .tools/pyenv", script
            )
            continue
        pending.append(tool)

    if pending:
        specs = [tool.requirement or "" for tool in pending]
        try:
            if not python.is_file():
                say("Creating the tool venv .tools/pyenv")
                _checked(
                    run(
                        [sys.executable, "-m", "venv", str(pyenv_dir(root))],
                        timeout=VENV_TIMEOUT_SECONDS,
                    ),
                    "python -m venv",
                )
            argv = [
                str(python),
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                "--no-input",
                "--no-cache-dir",  # no download stays in the pip cache of the user
            ]
            if force:
                argv.append("--force-reinstall")
            say(f"Installing {' '.join(specs)} with pip (this can take a few minutes)")
            _checked(run([*argv, *specs], timeout=PIP_TIMEOUT_SECONDS), "pip install")
            versions = _pyenv_versions(python, run)
        except ToolError as exc:
            for tool in pending:
                results[tool.name] = _pip_result(tool, root, STATUS_FAILED, str(exc))
        else:
            for tool in pending:
                results[tool.name] = _finish_pip(tool, root, versions)
            _update_installed(root, {}, pyenv=_pyenv_record(root, python, versions))
    return [results[tool.name] for tool in tools]


def _finish_pip(tool: Tool, root: Path, versions: dict[str, str]) -> InstallResult:
    got = _dist_version(versions, tool.package)
    if got != tool.version:
        message = f"pip installed {tool.package} {got or 'nothing'}, expected {tool.version}"
        return _pip_result(tool, root, STATUS_FAILED, message)
    script = pyenv_script(root, tool.executable)
    if script is None:
        return _pip_result(tool, root, STATUS_FAILED, f"console script {tool.executable} not found")
    _record_pip(root, tool, script, versions)
    return _pip_result(tool, root, STATUS_INSTALLED, f"pip installed {tool.requirement}", script)


def _pip_result(
    tool: Tool, root: Path, status: str, message: str, script: Path | None = None
) -> InstallResult:
    rel = _rel(root, script) if script is not None else None
    return InstallResult(tool.name, tool.version, tool.kind, status, message, rel)


def _record_pip(root: Path, tool: Tool, script: Path, versions: dict[str, str]) -> None:
    record = {
        "version": tool.version,
        "kind": tool.kind,
        "requirement": tool.requirement,
        "path": _rel(root, script),
        "installed_at": _now(),
    }
    previous = installed_entry(root, tool.name)
    if previous and all(previous.get(k) == record[k] for k in ("version", "requirement", "path")):
        return
    pyenv = _pyenv_record(root, pyenv_python(root), versions) if versions else None
    _update_installed(root, {tool.name: record}, pyenv=pyenv)


def _pyenv_record(root: Path, python: Path, versions: dict[str, str]) -> dict[str, Any]:
    return {
        "path": _rel(root, pyenv_dir(root)),
        "python": _rel(root, python),
        "packages": dict(sorted(versions.items(), key=lambda kv: kv[0].lower())),
        "updated_at": _now(),
    }


def _pyenv_versions(python: Path, run: Runner) -> dict[str, str]:
    try:
        proc = run(
            [str(python), "-I", "-c", _LIST_DISTRIBUTIONS],
            timeout=QUERY_TIMEOUT_SECONDS,
            env=probe_env(),  # the version probe environment, never the full user one
        )
    except (OSError, ValueError) as exc:
        raise ToolError(f"cannot run the tool venv Python {python}: {exc}") from exc
    except Exception as exc:  # subprocess.TimeoutExpired and similar
        raise ToolError(f"cannot query the tool venv Python {python}: {exc}") from exc
    if proc.returncode != 0:
        raise ToolError(f"cannot list the packages of the tool venv: {_tail(proc.stderr)}")
    try:
        data = json.loads(proc.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError) as exc:
        raise ToolError(f"unexpected package list from the tool venv: {exc}") from exc
    return {str(k): str(v) for k, v in data.items()}


def _dist_version(versions: dict[str, str], package: str | None) -> str | None:
    if not package:
        return None
    wanted = _normalize_dist(package)
    for name, version in versions.items():
        if _normalize_dist(name) == wanted:
            return version
    return None


def _normalize_dist(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _verify_pip(tool: Tool, root: Path, run: Runner) -> VerifyResult:
    def result(status: str, message: str, path: Path | None = None) -> VerifyResult:
        rel = _rel(root, path) if path is not None else None
        return VerifyResult(tool.name, tool.version, tool.kind, status, message, rel)

    python = pyenv_python(root)
    script = pyenv_script(root, tool.executable)
    if not python.is_file() or script is None:
        return result(VERIFY_MISSING, "not installed in .tools/pyenv")
    try:
        versions = _pyenv_versions(python, run)
    except ToolError as exc:
        return result(VERIFY_MISMATCH, str(exc), script)
    got = _dist_version(versions, tool.package)
    if got is None:
        return result(VERIFY_MISSING, f"{tool.package} is not installed in .tools/pyenv", script)
    if got != tool.version:
        return result(VERIFY_MISMATCH, f"{tool.package} {got} installed, expected {tool.version}")
    problems = verify_dist_record(pyenv_dir(root), tool.package or tool.name, got)
    if problems:
        shown = "; ".join(problems[:3])
        return result(
            VERIFY_MISMATCH, f"{len(problems)} file(s) differ from RECORD: {shown}", script
        )
    return result(VERIFY_OK, f"{tool.package} {got}, RECORD hashes ok", script)


def verify_dist_record(venv: str | os.PathLike[str], package: str, version: str) -> list[str]:
    """Re-hash the files of an installed distribution against its RECORD file.

    Returns a list of problems. An empty list means every hashed file matches.
    """
    venv_path = Path(venv).resolve()
    record = _find_record(venv_path, package, version)
    if record is None:
        return [f"no RECORD file for {package} {version}"]
    base = record.parent.parent
    problems: list[str] = []
    try:
        rows = list(csv.reader(record.read_text(encoding="utf-8").splitlines()))
    except (OSError, UnicodeDecodeError, csv.Error) as exc:
        return [f"cannot read {record.name}: {exc}"]
    for row in rows:
        if len(row) < 2 or not row[1]:
            continue
        rel, hash_spec = row[0], row[1]
        algorithm, _, expected = hash_spec.partition("=")
        if algorithm != "sha256":
            continue
        path = (base / rel).resolve()
        try:
            path.relative_to(venv_path)
        except ValueError:
            problems.append(f"{rel}: outside the venv")
            continue
        if not path.is_file():
            problems.append(f"{rel}: missing")
            continue
        raw = hashlib.sha256(path.read_bytes()).digest()
        actual = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
        if actual != expected:
            problems.append(f"{rel}: SHA-256 differs")
    return problems


def _find_record(venv: Path, package: str, version: str) -> Path | None:
    wanted = _normalize_dist(package)
    candidates = list(venv.glob("Lib/site-packages/*.dist-info")) + list(
        venv.glob("lib/python*/site-packages/*.dist-info")
    )
    for folder in candidates:
        name, _, found_version = folder.name[: -len(".dist-info")].rpartition("-")
        if _normalize_dist(name) == wanted and found_version == version:
            record = folder / "RECORD"
            if record.is_file():
                return record
    return None


# ---------------------------------------------------------------------------------------------
# go-install tools


@dataclass
class _GoContext:
    """What a go-install build needs besides the tool: the manifest, the host and the results."""

    manifest: Manifest
    root: Path
    key: str
    run: Runner
    find: Finder
    opener: Opener | None
    say: Log
    results: dict[str, InstallResult]


def _install_go(tool: Tool, ctx: _GoContext, force: bool) -> InstallResult:
    from kalkan.tools import golang  # lazy: golang imports this package's resolve module

    root = ctx.root

    def result(status: str, message: str, path: Path | None = None, digest: str | None = None):
        rel = _rel(root, path) if path is not None else None
        return InstallResult(tool.name, tool.version, tool.kind, status, message, rel, digest)

    if tool.is_blocked(tool.version):
        return result(STATUS_FAILED, f"version {tool.version} is blocked; refusing to install it")
    target = binary_path(root, tool, ctx.key)
    entry = installed_entry(root, tool.name) or {}
    if (
        not force
        and target.is_file()
        and entry.get("version") == tool.version
        and entry.get("build_flags", []) == list(tool.build_flags)
        and entry.get("sha256") == sha256_file(target)
    ):
        return result(STATUS_PRESENT, "already installed, SHA-256 ok", target, entry["sha256"])

    need = golang.required_version(ctx.manifest) or tool.min_go_version
    need_text = f"Go {need} or later" if need else "Go"
    go = golang.resolve_go(
        root, manifest=ctx.manifest, key=ctx.key, runner=ctx.run, finder=ctx.find
    )
    toolchain = golang.toolchain_tool(ctx.manifest)
    if go is None and toolchain is not None:
        prior = ctx.results.get(toolchain.name)
        if prior is None:
            ctx.say(f"{tool.name} needs {need_text}: installing the pinned Go toolchain first")
            prior = _install_toolchain(toolchain, root, ctx.key, False, ctx.opener, ctx.say)
            ctx.results[toolchain.name] = prior
        go = golang.resolve_go(
            root, manifest=ctx.manifest, key=ctx.key, runner=ctx.run, finder=ctx.find
        )
        if go is None:
            status = STATUS_SKIPPED if prior.status == STATUS_SKIPPED else STATUS_FAILED
            return result(
                status, f"{tool.name} needs {need_text}: {toolchain.name}: {prior.message}"
            )
    if go is None:
        return result(
            STATUS_FAILED, f"{tool.name} needs {need_text}; the manifest pins no Go toolchain"
        )

    bin_dir = tool_bin_dir(root, tool)
    bin_dir.mkdir(parents=True, exist_ok=True)
    golang.prepare_build(root)
    env = golang.build_env(root, go, bin_dir)
    ctx.say(f"Building {tool.module} with go install (Go {go.version}, {go.source})")
    try:
        _checked(
            ctx.run(
                [str(go.path), "install", *tool.build_flags, str(tool.module)],
                timeout=GO_TIMEOUT_SECONDS,
                env=env,
                cwd=str(go_build_dir(root)),
            ),
            "go install",
        )
    except ToolError as exc:
        return result(STATUS_FAILED, str(exc))
    except (OSError, ValueError) as exc:
        return result(STATUS_FAILED, f"cannot run {go.path}: {exc}")
    if not target.is_file():
        return result(STATUS_FAILED, f"go install did not create {_rel(root, target)}")
    digest = sha256_file(target)
    record = {
        "version": tool.version,
        "kind": tool.kind,
        "platform": ctx.key,
        "path": _rel(root, target),
        "sha256": digest,
        "module": tool.module,
        "go_version": go.version,
        "go_source": go.source,
        "installed_at": _now(),
    }
    if tool.build_flags:
        record["build_flags"] = list(tool.build_flags)
    _update_installed(root, {tool.name: record})
    return result(STATUS_INSTALLED, f"built with Go {go.version} ({go.source})", target, digest)


def remove_go_build(root: str | os.PathLike[str], log: Log | None = None) -> TreeStats | None:
    """Delete ``<root>/.tools/go-build``: the ``GOPATH`` with the module cache and the
    ``GOCACHE`` of the go-install builds (:func:`kalkan.tools.golang.build_env`).

    The installed executables live in ``.tools/<tool>/<version>/bin`` and need nothing of it.
    Go marks the module files read-only; :func:`kalkan.util.fs.remove_tree` makes them
    writable first and follows no link. A failure only warns. Returns the counts, or None when
    the folder does not exist. ``docker/Dockerfile`` removes the same folder in its Go layer.
    """
    say = log or _quiet
    folder = go_build_dir(Path(root))
    if not os.path.lexists(folder):
        return None
    stats = remove_tree(folder)
    size = f"{stats.bytes / 1_000_000:.1f} MB in {stats.files} files"
    if stats.errors:
        say(
            f"warning: could not remove all of the Go build folder {folder.as_posix()} "
            f"({stats.errors[0]}); delete it by hand, no tool needs it"
        )
    else:
        say(
            f"Removed the Go build folder .tools/go-build ({size}); a later build downloads "
            "the Go modules again"
        )
    return stats


def go_version(go: str | os.PathLike[str], run: Runner) -> str | None:
    """Return the version of a Go toolchain (``1.26.1``), or None when it cannot be read."""
    return go_toolchain_version(go, runner=run, timeout=QUERY_TIMEOUT_SECONDS)


def _verify_go(tool: Tool, root: Path, key: str, find: Finder) -> VerifyResult:
    entry = installed_entry(root, tool.name)
    target = (entry_path(root, entry) if entry else None) or binary_path(root, tool, key)
    rel = _rel(root, target)
    if not target.is_file():
        return VerifyResult(
            tool.name, tool.version, tool.kind, VERIFY_MISSING, "not installed", rel
        )
    expected = entry.get("sha256") if entry else None
    actual = sha256_file(target)
    if expected is None:
        status, message = VERIFY_MISMATCH, "no install record with a SHA-256"
    elif entry and entry.get("version") != tool.version:
        status, message = VERIFY_MISMATCH, f"installed version {entry.get('version')} is not pinned"
    elif entry and entry.get("build_flags", []) != list(tool.build_flags):
        status, message = VERIFY_MISMATCH, "built with other build_flags than the manifest names"
    elif actual == expected:
        status, message = VERIFY_OK, "SHA-256 ok (install record)"
    else:
        status, message = VERIFY_MISMATCH, "SHA-256 differs from the install record"
    return VerifyResult(tool.name, tool.version, tool.kind, status, message, rel, expected, actual)


# ---------------------------------------------------------------------------------------------
# installed.json and small helpers


def _update_installed(
    root: Path, records: dict[str, dict[str, Any]], *, pyenv: dict[str, Any] | None = None
) -> None:
    data = read_installed(root)
    data["schema_version"] = INSTALLED_SCHEMA_VERSION
    data.setdefault("tools", {}).update(records)
    if pyenv is not None:
        data["pyenv"] = pyenv
    data["tools"] = dict(sorted(data["tools"].items()))
    data["updated_at"] = _now()
    target = installed_json_path(root)
    target.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_json(target, data)


def _checked(proc: Any, what: str) -> Any:
    if proc.returncode != 0:
        detail = _tail(proc.stderr) or _tail(proc.stdout)
        raise ToolError(f"{what} failed with exit code {proc.returncode}: {detail}")
    return proc


def _tail(text: str | None, lines: int = 15) -> str:
    if not text:
        return ""
    return "\n".join(text.strip().splitlines()[-lines:])


def _version_tuple(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"[0-9]+", version))


def _rel(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _quiet(_message: str) -> None:
    return None
