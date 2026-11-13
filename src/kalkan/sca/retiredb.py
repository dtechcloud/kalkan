# SPDX-License-Identifier: MIT
"""The local RetireJS repository (docs/ENGINE-SPEC.md 17, docs/SECURITY.md promise 3).

The vendored JavaScript check (:mod:`kalkan.sca.vendored`) reads the library repository of
RetireJS (github.com/RetireJS/retire.js, Apache-2.0, ``LICENSE.md``) from the kalkan home:

    <home>/.tools/vulndb/retire/jsrepository-v5.json    the repository file
    <home>/.tools/vulndb/retire/kalkan-source.json      source, SHA-256, size, update time

1. **Source.** :data:`URL` is ``repository/jsrepository-v5.json`` of the ``master`` branch:
   the file that the retire 6.1.0 command line downloads (``node/src/cli.ts``, release 6.1.0
   of 2026-10-06; the default branch names the same file on 2026-10-25). An automated job
   of the project updates it several times a week. ``jsrepository-v4.json`` lacks the
   ``excludes`` field, and ``jsrepository-v6.json`` only adds long ``details`` texts.
2. **Download** (:func:`download`, the only network use, started by ``kalkan sca update-db``):
   one plain GET request without any data of a project. Redirects are followed, but the final
   URL must use HTTPS; the content type must be ``text/plain``, ``application/json`` or
   ``application/octet-stream``; at most :data:`MAX_DOWNLOAD_BYTES`.
3. **Check** (:func:`install`): strict UTF-8 JSON that :func:`kalkan.sca.retirejs.parse_repository`
   accepts with at least :data:`MIN_LIBRARIES` usable libraries. Only then the new folder
   replaces ``retire/`` in one rename; a failed update keeps the old file.
4. **Record.** ``kalkan-source.json``: ``source`` (the URL), ``upstream``, ``license``,
   ``sha256``, ``bytes``, ``etag``, ``last_modified``, ``updated_at`` and the repository counts.
   ``sca update-db`` returns the part ``retire`` of ``status.json``; ``kalkan doctor`` (check
   ``vulndb``) reports it and its age.
5. **Use.** :func:`repository_file` returns the file only when it exists. A missing file is a
   database gap of ``sca match``, never an online query.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from kalkan.errors import ValidationError
from kalkan.sca.retirejs import load_repository

__all__ = [
    "FILE_NAME",
    "FOLDER",
    "LICENSE",
    "MAX_DOWNLOAD_BYTES",
    "SOURCE_FILE",
    "UPSTREAM",
    "URL",
    "RetireDbError",
    "download",
    "folder",
    "info",
    "install",
    "ready",
    "repository_file",
    "update",
]

#: The repository file that retire 6.1.0 downloads (module docstring, item 1).
URL: Final = (
    "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository-v5.json"
)
UPSTREAM: Final = "github.com/RetireJS/retire.js"
LICENSE: Final = "Apache-2.0"
FOLDER: Final = "retire"
FILE_NAME: Final = "jsrepository-v5.json"
SOURCE_FILE: Final = "kalkan-source.json"
MAX_DOWNLOAD_BYTES: Final = 32 * 1024 * 1024
#: A downloaded file with fewer usable libraries is refused (the 2026-10-25 file has 74).
MIN_LIBRARIES: Final = 20
CONTENT_TYPES: Final = frozenset({"text/plain", "application/json", "application/octet-stream"})

Fetch = Callable[[str, Path, int], dict[str, Any]]


class RetireDbError(Exception):
    """The RetireJS repository cannot be downloaded or used."""


def folder(root: Path) -> Path:
    """Return ``<root>/retire`` (``root`` is the vulnerability database root)."""
    return Path(root) / FOLDER


def repository_file(root: Path) -> Path | None:
    """Return the repository file when it exists and is not empty, else None."""
    path = folder(root) / FILE_NAME
    try:
        return path if path.is_file() and path.stat().st_size > 0 else None
    except OSError:
        return None


def ready(root: Path) -> bool:
    """Return True when the repository file exists."""
    return repository_file(root) is not None


def info(root: Path) -> dict[str, Any] | None:
    """Return ``kalkan-source.json`` of the repository, or None when the file is missing."""
    if not ready(root):
        return None
    try:
        from kalkan.util.safe_io import read_text_bounded

        data = json.loads(read_text_bounded(folder(root) / SOURCE_FILE, 1024 * 1024))
    except Exception:  # missing or broken metadata: the repository still works
        return {"source": "unknown"}
    return data if isinstance(data, dict) else {"source": "unknown"}


def download(url: str, dest: Path, timeout_seconds: int) -> dict[str, Any]:
    """Download ``url`` to the new file ``dest`` and return what the server answered.

    Raise :class:`RetireDbError` for a URL that does not end at HTTPS, another content type,
    an answer larger than :data:`MAX_DOWNLOAD_BYTES` or a network error.
    """
    import http.client
    import urllib.error
    import urllib.request

    from kalkan import __version__
    from kalkan.tools import tls

    request = urllib.request.Request(
        url, headers={"User-Agent": f"kalkan/{__version__}", "Accept": "application/json"}
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
                raise RetireDbError(f"the download ended at a URL without HTTPS: {final}")
            kind = response.headers.get_content_type()
            if kind not in CONTENT_TYPES:
                raise RetireDbError(f"{final} answered with {kind}, not a JSON file")
            etag = response.headers.get("ETag")
            modified = response.headers.get("Last-Modified")
            while chunk := response.read(1 << 16):
                size += len(chunk)
                if size > MAX_DOWNLOAD_BYTES:
                    raise RetireDbError(f"{final} sent more than {MAX_DOWNLOAD_BYTES} bytes")
                digest.update(chunk)
                out.write(chunk)
    except urllib.error.HTTPError as exc:
        raise RetireDbError(f"{url} answered HTTP {exc.code} {exc.reason}") from None
    except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as exc:
        reason = tls.explain(getattr(exc, "reason", None) or exc)
        raise RetireDbError(f"{url}: {reason}") from None
    return {
        "url": final,
        "content_type": kind,
        "bytes": size,
        "sha256": digest.hexdigest(),
        "etag": etag,
        "last_modified": modified,
    }


def install(root: Path, downloaded: Path, meta: dict[str, Any]) -> dict[str, Any]:
    """Check the downloaded file and make it the local repository. Return the source record.

    Raise :class:`RetireDbError` when the file is not a usable repository.
    """
    try:
        repository = load_repository(downloaded)
    except ValidationError as exc:
        raise RetireDbError(str(exc)) from None
    if len(repository.libraries) < MIN_LIBRARIES:
        raise RetireDbError(
            f"the file holds {len(repository.libraries)} usable libraries; at least "
            f"{MIN_LIBRARIES} are expected"
        )
    data = downloaded.read_bytes()
    source = {
        "source": meta.get("url") or URL,
        "upstream": UPSTREAM,
        "license": LICENSE,
        "file": FILE_NAME,
        "sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
        "etag": meta.get("etag"),
        "last_modified": meta.get("last_modified"),
        "updated_at": _now(),
        **repository.stats(),
    }
    _replace(root, data, source)
    return source


def update(
    root: Path,
    *,
    timeout_seconds: int = 600,
    fetch: Fetch | None = None,
    url: str = URL,
) -> dict[str, Any]:
    """Download and install the repository into ``<root>/retire``. Return the ``update-db``
    part: ``status`` (``ok`` or ``failed``), ``message``, ``sha256``, ``libraries``,
    ``vulnerabilities``, ``extractors``, ``source``. A failure keeps the old repository.
    ``fetch`` replaces :func:`download` (tests)."""
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    _cleanup(root)
    work = root / f".retire-download-{secrets.token_hex(4)}"
    work.mkdir()
    try:
        target = work / FILE_NAME
        meta = (fetch or download)(url, target, timeout_seconds)
        source = install(root, target, meta)
    except (RetireDbError, OSError) as exc:
        kept = " (the previous repository stays)" if ready(root) else ""
        return {"status": "failed", "message": f"{exc}{kept}", "ready": ready(root)}
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return {
        "status": "ok",
        "message": "",
        "source": source["source"],
        "sha256": source["sha256"],
        "bytes": source["bytes"],
        "libraries": source["libraries"],
        "vulnerabilities": source["vulnerabilities"],
        "extractors": source["extractors"],
        "skipped_extractors": source["skipped_extractors"],
        "ready": True,
    }


def _replace(root: Path, data: bytes, source: dict[str, Any]) -> None:
    """Write the repository into a new folder and put it in place of ``<root>/retire``."""
    token = secrets.token_hex(4)
    new = root / f".retire-new-{token}"
    old = root / f".retire-old-{token}"
    final = folder(root)
    new.mkdir()
    try:
        with open(new / FILE_NAME, "xb") as handle:
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
    """Remove the work folders of an update that stopped."""
    for pattern in (".retire-new-*", ".retire-old-*", ".retire-download-*"):
        for path in root.glob(pattern):
            shutil.rmtree(path, ignore_errors=True)


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
