# SPDX-License-Identifier: MIT
"""The local Go vulnerability database of govulncheck (docs/ENGINE-SPEC.md 17, docs/SECURITY.md).

govulncheck 1.8.0 reads a database from a folder with ``-db file:///<absolute folder>`` when the
folder follows the API of https://go.dev/security/vuln/database:

    index/db.json          {"modified": "<RFC 3339 UTC time>"}
    index/modules.json     [{"path": <module>, "vulns": [{"id", "modified", "fixed"?}]}]
    index/vulns.json       [{"id", "modified", "aliases"}]
    ID/<id>.json           one OSV entry

(golang.org/x/vuln@v1.8.0 ``internal/client``: a ``file`` source needs ``index/modules.json``;
it reads ``index/db.json``, ``index/modules.json`` and the ``ID`` files, never the network.)

``kalkan sca update-db`` fills ``<home>/.tools/vulndb/go/`` from one of two sources:

1. ``official``: the bulk download of the Go project, ``https://vuln.go.dev/vulndb.zip``
   (go.dev/security/vuln/database, "Bulk download"). It is a plain GET request without any data
   of a project. Checked on 2026-10-16: HTTP 200, ``Content-Type: application/zip``, 3.4 MB,
   4,616 members (the three index files and 4,613 ``ID/GO-*.json`` files), ``index/db.json``
   modified ``2026-10-08T22:31:09Z``. The name ``vuln.zip`` does not exist (HTTP 404 with an
   HTML page).
2. ``osv``: built from the ``GO-*.json`` entries of the OSV offline database for Go
   (``osv/osv-scalibr/Go/all.zip``, which ``sca update-db`` downloads too), when the download
   fails or ``--go-source osv`` asks for it. On 2026-10-16 that archive held the 4,613 GO
   entries of the official archive plus 19 withdrawn ones (govulncheck skips withdrawn entries).
   kalkan writes the index files. ``modules.json`` leaves out the optional ``fixed`` field, so
   govulncheck reads every entry of a module and checks the version ranges itself: a computed
   ``fixed`` value can never hide an entry.

Every archive is checked before it replaces the database: an HTTPS end point, a zip content
type, the zip signature, at most :data:`MAX_ARCHIVE_BYTES`, :data:`MAX_MEMBERS` members of at
most :data:`MAX_MEMBER_BYTES` each. Only names of the API layout are written (other members are
counted and ignored, so no path from the archive reaches the disk). Every index and entry must
be valid JSON, every ``ID/<id>.json`` must hold the entry ``<id>``, and every ID of
``index/modules.json`` must have its file. The new folder replaces the old one only after these
checks; a failed update keeps the old database. ``kalkan-source.json`` in the folder records
the source, its ``modified`` time (``index/db.json``), the number of entries and the time of the
update (``doctor`` shows it).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import zipfile
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

__all__ = [
    "OFFICIAL_URL",
    "SOURCES",
    "GoDbError",
    "build_from_osv",
    "db_uri",
    "download",
    "info",
    "install_official",
    "ready",
    "update",
]

#: The bulk download of the Go vulnerability database (go.dev/security/vuln/database).
OFFICIAL_URL: Final = "https://vuln.go.dev/vulndb.zip"
#: ``update(source=...)`` values: the official archive first, then the OSV build (``auto``).
SOURCES: Final = ("auto", "official", "osv")
#: The folder name below the vulnerability database root.
FOLDER: Final = "go"
#: The metadata file that kalkan writes into the folder.
SOURCE_FILE: Final = "kalkan-source.json"
MAX_ARCHIVE_BYTES: Final = 256 * 1024 * 1024
MAX_MEMBER_BYTES: Final = 32 * 1024 * 1024
MAX_TOTAL_BYTES: Final = 1024 * 1024 * 1024
MAX_MEMBERS: Final = 200_000
#: Content types of a zip answer.
ZIP_TYPES: Final = frozenset(
    {"application/zip", "application/x-zip-compressed", "application/octet-stream"}
)
DB_ENDPOINT: Final = "index/db.json"
MODULES_ENDPOINT: Final = "index/modules.json"
VULNS_ENDPOINT: Final = "index/vulns.json"
_INDEX_NAMES: Final = frozenset({DB_ENDPOINT, MODULES_ENDPOINT, VULNS_ENDPOINT})
_ID_MEMBER: Final = re.compile(r"ID/(GO-[0-9]{4}-[0-9]{4,7})\.json")
_OSV_MEMBER: Final = re.compile(r"(GO-[0-9]{4}-[0-9]{4,7})\.json")
_ZIP_MAGIC: Final = b"PK\x03\x04"

Fetch = Callable[[str, Path, int], dict[str, Any]]


class GoDbError(Exception):
    """A source of the Go vulnerability database cannot be used."""


def folder(root: Path) -> Path:
    """Return ``<root>/go`` (``root`` is the vulnerability database root)."""
    return Path(root) / FOLDER


def ready(root: Path) -> bool:
    """Return True when the folder holds a non-empty ``index/db.json`` and ``modules.json``."""
    base = folder(root)
    try:
        return all((base / name).stat().st_size > 0 for name in (DB_ENDPOINT, MODULES_ENDPOINT))
    except OSError:
        return False


def info(root: Path) -> dict[str, Any] | None:
    """Return ``kalkan-source.json`` of the database (source, modified, entries), or None."""
    if not ready(root):
        return None
    try:
        from kalkan.util.safe_io import read_text_bounded

        data = json.loads(read_text_bounded(folder(root) / SOURCE_FILE, 1024 * 1024))
    except Exception:  # missing or broken metadata: the database still works
        return {"source": "unknown"}
    return data if isinstance(data, dict) else {"source": "unknown"}


def db_uri(root: Path) -> str:
    """Return the ``file:///`` URL of the folder for ``govulncheck -db``."""
    return folder(root).resolve().as_uri()


# --- sources -----------------------------------------------------------------------------------


def download(url: str, dest: Path, timeout_seconds: int) -> dict[str, Any]:
    """Download ``url`` to the new file ``dest`` and return what the server answered.

    Redirects are followed (urllib), but the final URL must use HTTPS. The answer must have a
    zip content type and the zip signature, and at most :data:`MAX_ARCHIVE_BYTES`. Raise
    :class:`GoDbError` otherwise. The request carries no data of a project.
    """
    import http.client
    import urllib.error
    import urllib.request

    from kalkan import __version__
    from kalkan.tools import tls

    request = urllib.request.Request(
        url, headers={"User-Agent": f"kalkan/{__version__}", "Accept": "application/zip"}
    )
    digest = hashlib.sha256()
    size = 0
    try:
        with (
            urllib.request.urlopen(  # noqa: S310 - fixed HTTPS URL
                request, timeout=timeout_seconds or None, context=tls.ssl_context()
            ) as response,
            open(dest, "xb") as out,
        ):
            final = str(response.geturl())
            if not final.startswith("https://"):
                raise GoDbError(f"the download ended at a URL without HTTPS: {final}")
            kind = response.headers.get_content_type()
            if kind not in ZIP_TYPES:
                raise GoDbError(f"{final} answered with {kind}, not a zip archive")
            modified = response.headers.get("Last-Modified")
            while chunk := response.read(1 << 16):
                size += len(chunk)
                if size > MAX_ARCHIVE_BYTES:
                    raise GoDbError(f"{final} sent more than {MAX_ARCHIVE_BYTES} bytes")
                digest.update(chunk)
                out.write(chunk)
    except urllib.error.HTTPError as exc:
        raise GoDbError(f"{url} answered HTTP {exc.code} {exc.reason}") from None
    except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as exc:
        reason = tls.explain(getattr(exc, "reason", None) or exc)
        raise GoDbError(f"{url}: {reason}") from None
    with open(dest, "rb") as handle:
        if handle.read(4) != _ZIP_MAGIC:
            raise GoDbError(f"{final} sent no zip archive (no zip signature)")
    return {
        "url": final,
        "content_type": kind,
        "bytes": size,
        "sha256": digest.hexdigest(),
        "last_modified": modified,
    }


def install_official(root: Path, archive: Path, meta: dict[str, Any]) -> dict[str, Any]:
    """Check the official archive ``archive`` and make it the database. Return the metadata."""
    with _open_zip(archive) as bundle:
        members = _members(bundle)
        files: dict[str, bytes] = {}
        ignored = 0
        for item in members:
            name = item.filename
            if name in _INDEX_NAMES or _ID_MEMBER.fullmatch(name):
                files[name] = _read_member(bundle, item)
            elif not name.endswith("/"):
                ignored += 1
    entries = _check_layout(files)
    modified = _db_modified(files[DB_ENDPOINT])
    source = {
        "source": "official",
        "url": meta.get("url") or OFFICIAL_URL,
        "sha256": meta.get("sha256"),
        "bytes": meta.get("bytes"),
        "last_modified": meta.get("last_modified"),
        "modified": modified,
        "entries": entries,
        "ignored_members": ignored,
        "updated_at": _now(),
    }
    _replace(root, files, source)
    return source


def build_from_osv(root: Path, osv_zip: Path) -> dict[str, Any]:
    """Build the database from the ``GO-*.json`` entries of the OSV Go archive ``osv_zip``."""
    if not osv_zip.is_file():
        raise GoDbError(
            f"no OSV Go database at {osv_zip.as_posix()} (run: kalkan sca update-db "
            '--ecosystems "Go")'
        )
    digest = _sha256(osv_zip)
    entries: dict[str, dict[str, Any]] = {}
    raw: dict[str, bytes] = {}
    with _open_zip(osv_zip) as bundle:
        for item in _members(bundle):
            match = _OSV_MEMBER.fullmatch(item.filename)
            if match is None:
                continue
            data = _read_member(bundle, item)
            entry = _entry(data, match.group(1))
            entries[match.group(1)] = entry
            raw[match.group(1)] = data
    if not entries:
        raise GoDbError(f"{osv_zip.name} holds no GO entry")
    files = _index_files(entries)
    for vuln_id, data in raw.items():
        files[f"ID/{vuln_id}.json"] = data
    count = _check_layout(files)
    source = {
        "source": "osv",
        "built_from": f"osv/osv-scalibr/Go/{osv_zip.name}",
        "sha256": digest,
        "modified": _db_modified(files[DB_ENDPOINT]),
        "entries": count,
        "updated_at": _now(),
    }
    _replace(root, files, source)
    return source


def update(
    root: Path,
    osv_zip: Path,
    *,
    source: str = "auto",
    timeout_seconds: int = 600,
    fetch: Fetch | None = None,
) -> dict[str, Any]:
    """Fetch or build the Go database into ``<root>/go``. Return the ``update-db`` part.

    ``auto`` tries the official archive, then the OSV build. The result has ``status``
    (``ok`` or ``failed``), ``source``, ``modified``, ``entries`` and ``message`` (why the
    official archive was not used, or why both failed). A failure keeps the old database.
    """
    if source not in SOURCES:
        raise ValueError(f"unknown Go database source: {source} (known: {', '.join(SOURCES)})")
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    _cleanup(root)
    problems: list[str] = []
    if source in ("auto", "official"):
        work = root / f".go-download-{secrets.token_hex(4)}"
        work.mkdir()
        try:
            archive = work / "vulndb.zip"
            meta = (fetch or download)(OFFICIAL_URL, archive, timeout_seconds)
            done = install_official(root, archive, meta)
            return _result(done, "")
        except (GoDbError, OSError) as exc:
            problems.append(f"official archive {OFFICIAL_URL}: {exc}")
        finally:
            shutil.rmtree(work, ignore_errors=True)
    if source in ("auto", "osv"):
        try:
            done = build_from_osv(root, osv_zip)
            message = f"built from the OSV Go database ({problems[0]})" if problems else ""
            return _result(done, message)
        except (GoDbError, OSError) as exc:
            problems.append(f"OSV build: {exc}")
    kept = " (the previous database stays)" if ready(root) else ""
    return {
        "status": "failed",
        "source": None,
        "message": "; ".join(problems) + kept,
        "ready": ready(root),
    }


def _result(source: dict[str, Any], message: str) -> dict[str, Any]:
    return {
        "status": "ok",
        "source": source["source"],
        "modified": source["modified"],
        "entries": source["entries"],
        "url": source.get("url"),
        "built_from": source.get("built_from"),
        "message": message,
        "ready": True,
    }


# --- checks ------------------------------------------------------------------------------------


class _Zip:
    """A zip file that closes its handle (``zipfile.ZipFile`` with a context manager)."""

    def __init__(self, path: Path) -> None:
        try:
            self.bundle = zipfile.ZipFile(path)
        except (zipfile.BadZipFile, OSError, ValueError) as exc:
            raise GoDbError(f"{path.name} is not a valid zip archive: {exc}") from None

    def __enter__(self) -> zipfile.ZipFile:
        return self.bundle

    def __exit__(self, *_exc: object) -> None:
        self.bundle.close()


def _open_zip(path: Path) -> _Zip:
    return _Zip(path)


def _members(bundle: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    members = bundle.infolist()
    if len(members) > MAX_MEMBERS:
        raise GoDbError(f"the archive has more than {MAX_MEMBERS} members")
    total = 0
    names: set[str] = set()
    for item in members:
        if item.file_size > MAX_MEMBER_BYTES:
            raise GoDbError(f"the member {item.filename!r} is larger than {MAX_MEMBER_BYTES} bytes")
        total += item.file_size
        if item.filename in names:
            raise GoDbError(f"the archive holds {item.filename!r} twice")
        names.add(item.filename)
    if total > MAX_TOTAL_BYTES:
        raise GoDbError(f"the archive expands to more than {MAX_TOTAL_BYTES} bytes")
    return members


def _read_member(bundle: zipfile.ZipFile, item: zipfile.ZipInfo) -> bytes:
    try:
        with bundle.open(item) as handle:
            data = handle.read(MAX_MEMBER_BYTES + 1)
    except (zipfile.BadZipFile, OSError, ValueError, EOFError) as exc:
        raise GoDbError(f"cannot read {item.filename!r}: {exc}") from None
    if len(data) > MAX_MEMBER_BYTES:
        raise GoDbError(f"the member {item.filename!r} is larger than {MAX_MEMBER_BYTES} bytes")
    return data


def _json(data: bytes, name: str) -> Any:
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise GoDbError(f"{name} is not valid JSON: {exc}") from None


def _entry(data: bytes, vuln_id: str) -> dict[str, Any]:
    entry = _json(data, f"{vuln_id}.json")
    if not isinstance(entry, dict) or entry.get("id") != vuln_id:
        raise GoDbError(f"{vuln_id}.json does not hold the entry {vuln_id}")
    if not isinstance(entry.get("modified"), str) or _time(entry["modified"]) is None:
        raise GoDbError(f"{vuln_id}.json has no valid 'modified' time")
    if not isinstance(entry.get("affected", []), list):
        raise GoDbError(f"{vuln_id}.json has an invalid 'affected' list")
    return entry


def _check_layout(files: dict[str, bytes]) -> int:
    """Check the API layout; return the number of ``ID`` entries."""
    for name in (DB_ENDPOINT, MODULES_ENDPOINT):
        if name not in files:
            raise GoDbError(f"the archive has no {name}")
    _db_modified(files[DB_ENDPOINT])
    ids = {match.group(1) for name in files if (match := _ID_MEMBER.fullmatch(name)) is not None}
    if not ids:
        raise GoDbError("the archive has no ID/GO-*.json entry")
    for vuln_id in ids:
        _entry(files[f"ID/{vuln_id}.json"], vuln_id)
    modules = _json(files[MODULES_ENDPOINT], MODULES_ENDPOINT)
    if not isinstance(modules, list):
        raise GoDbError(f"{MODULES_ENDPOINT} is not a list")
    for module in modules:
        vulns = module.get("vulns") if isinstance(module, dict) else None
        if not isinstance(module, dict) or not isinstance(module.get("path"), str):
            raise GoDbError(f"{MODULES_ENDPOINT} has an entry without a module path")
        if not isinstance(vulns, list):
            raise GoDbError(f"{MODULES_ENDPOINT}: {module['path']} has no vulns list")
        for vuln in vulns:
            vuln_id = vuln.get("id") if isinstance(vuln, dict) else None
            if vuln_id not in ids:
                raise GoDbError(f"{MODULES_ENDPOINT} names {vuln_id!r}, which has no ID file")
    if VULNS_ENDPOINT in files and not isinstance(
        _json(files[VULNS_ENDPOINT], VULNS_ENDPOINT), list
    ):
        raise GoDbError(f"{VULNS_ENDPOINT} is not a list")
    return len(ids)


def _db_modified(data: bytes) -> str:
    meta = _json(data, DB_ENDPOINT)
    modified = meta.get("modified") if isinstance(meta, dict) else None
    if not isinstance(modified, str) or _time(modified) is None:
        raise GoDbError(f"{DB_ENDPOINT} has no valid 'modified' time")
    return modified


def _time(text: str) -> datetime | None:
    try:
        moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return moment if moment.tzinfo is not None else None


def _index_files(entries: dict[str, dict[str, Any]]) -> dict[str, bytes]:
    """Return the three index files of the API for ``entries`` (id to OSV entry)."""
    latest = max(entries.values(), key=lambda entry: _time(entry["modified"]) or datetime.min)
    modules: dict[str, list[dict[str, str]]] = {}
    vulns: list[dict[str, Any]] = []
    for vuln_id in sorted(entries):
        entry = entries[vuln_id]
        aliases = [alias for alias in entry.get("aliases") or [] if isinstance(alias, str)]
        vulns.append({"id": vuln_id, "modified": entry["modified"], "aliases": aliases})
        paths: list[str] = []
        for affected in entry.get("affected") or []:
            package = affected.get("package") if isinstance(affected, dict) else None
            path = package.get("name") if isinstance(package, dict) else None
            if isinstance(path, str) and path and path not in paths:
                paths.append(path)
        for path in paths:
            modules.setdefault(path, []).append({"id": vuln_id, "modified": entry["modified"]})
    module_list = [{"path": path, "vulns": modules[path]} for path in sorted(modules)]
    return {
        DB_ENDPOINT: _dump({"modified": latest["modified"]}),
        MODULES_ENDPOINT: _dump(module_list),
        VULNS_ENDPOINT: _dump(vulns),
    }


def _dump(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


# --- files -------------------------------------------------------------------------------------


def _replace(root: Path, files: dict[str, bytes], source: dict[str, Any]) -> None:
    """Write ``files`` into a new folder and put it in place of ``<root>/go``."""
    token = secrets.token_hex(4)
    new = root / f".go-new-{token}"
    old = root / f".go-old-{token}"
    final = folder(root)
    new.mkdir()
    try:
        for sub in ("index", "ID"):
            (new / sub).mkdir()
        for name, data in files.items():
            with open(new / name, "xb") as handle:  # names come from the fixed layout only
                handle.write(data)
        with open(new / SOURCE_FILE, "x", encoding="utf-8", newline="\n") as handle:
            json.dump(source, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
        if final.exists():
            os.replace(final, old)
        try:
            os.replace(new, final)
        except OSError:
            if old.exists() and not final.exists():
                os.replace(old, final)
            raise
    finally:
        shutil.rmtree(new, ignore_errors=True)
        shutil.rmtree(old, ignore_errors=True)


def _cleanup(root: Path) -> None:
    """Remove the work folders of an update that stopped (``.go-new-*``, ``.go-old-*``)."""
    for pattern in (".go-new-*", ".go-old-*", ".go-download-*"):
        for path in root.glob(pattern):
            shutil.rmtree(path, ignore_errors=True)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
