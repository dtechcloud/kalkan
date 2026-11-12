# SPDX-License-Identifier: MIT
"""Normalize SARIF artifact URIs to target-relative POSIX paths (ENGINE-SPEC 8.1).

Scanners write locations in many forms: relative paths, ``./`` prefixes, Windows paths with
backslashes, ``file:///C:/...`` URIs, percent-encoded names, and relative URIs with a
``uriBaseId``. :func:`normalize_uri` turns all of them into one form: a POSIX path relative
to the target root.

Contract:

- A relative URI is relative to the target root. Run scanners with the target root as the
  working directory, or give them absolute paths.
- An absolute path under the target root loses the root prefix. Windows drive letters and
  Windows paths compare case-insensitively. POSIX paths compare case-sensitively.
- An absolute path outside the target root stays absolute, in POSIX form.
- A URI with a scheme other than ``file`` stays unchanged.

The module is pure string processing. It never reads the file system. Only a relative
``target_root`` is made absolute against the current working directory.
"""

from __future__ import annotations

import os
import posixpath
import re
import unicodedata
from collections.abc import Mapping
from typing import Any
from urllib.parse import unquote

# Two or more characters before the colon: a URI scheme. One letter is a Windows drive.
_SCHEME = re.compile(r"([A-Za-z][A-Za-z0-9+.-]+):")
_DRIVE = re.compile(r"([A-Za-z]):(?=/|$)")
_SLASH_DRIVE = re.compile(r"/([A-Za-z]):(?=/|$)")
_RAW_ABSOLUTE = re.compile(r"(?:[/\\]|[A-Za-z]:(?:[/\\]|$))")
# originalUriBaseIds entries can refer to other entries. Stop a cycle after this depth.
_MAX_BASE_DEPTH = 8


def normalize_uri(
    uri: str,
    target_root: str | os.PathLike[str] | None,
    base_uris: Mapping[str, Any] | None = None,
    *,
    uri_base_id: str | None = None,
) -> str:
    """Return ``uri`` as a POSIX path relative to ``target_root``.

    ``base_uris`` is the run's ``originalUriBaseIds`` object. ``uri_base_id`` is the
    ``artifactLocation.uriBaseId`` of ``uri``. A relative ``uri`` with a known base is
    resolved against it. When the resolved path is not under the target root, the scanner
    used another root, and the relative ``uri`` stays relative to the target root.

    Return ``""`` for a missing or empty ``uri``.
    """
    if not isinstance(uri, str):
        return ""
    text = uri.strip()
    if not text:
        return ""
    if _has_foreign_scheme(text):
        return text
    root = _absolute_root(target_root)

    if uri_base_id and base_uris and not _is_absolute_reference(text):
        base = _resolve_base(uri_base_id, base_uris, 0)
        if base is not None and not _has_foreign_scheme(base):
            joined = _to_path(_join(base, text))
            if not _is_absolute(joined):
                return joined
            relative = _strip_root(joined, root)
            if relative is not None:
                return relative

    path = _to_path(text)
    if _is_absolute(path):
        relative = _strip_root(path, root)
        return path if relative is None else relative
    return path


def is_target_relative(path: str) -> bool:
    """Return True when ``path`` is a non-empty relative path that stays in the target root."""
    if not path or _is_absolute(path) or _has_foreign_scheme(path):
        return False
    return path != ".." and not path.startswith("../")


def _absolute_root(target_root: str | os.PathLike[str] | None) -> str | None:
    if target_root is None:
        return None
    text = os.fspath(target_root) if isinstance(target_root, os.PathLike) else target_root
    if not isinstance(text, str):
        return None
    text = text.strip()
    if not text:
        return None
    path = _clean(text)
    if not _is_absolute(path):
        path = _clean(os.path.abspath(text))
    return path


def _to_path(text: str) -> str:
    """Turn a ``file:`` URI or a path into a clean POSIX path, absolute or relative."""
    match = _SCHEME.match(text)
    if match is not None and match.group(1).lower() == "file":
        text = _strip_file_scheme(text[match.end() :])
    return _clean(unquote(text))


def _strip_file_scheme(rest: str) -> str:
    if not rest.startswith("//"):
        # file:/C:/x, file:/home/x
        return rest
    rest = rest[2:]
    slash = rest.find("/")
    host, path = (rest, "") if slash < 0 else (rest[:slash], rest[slash:])
    if _DRIVE.fullmatch(host):
        # file://C:/x is a common malformed form: the drive is in the host position.
        return host + path
    if host.lower() in ("", "localhost"):
        return path
    # file://server/share/x is a UNC path.
    return "//" + host + path


def _clean(path: str) -> str:
    """Use ``/`` separators, remove ``/`` before a drive, normalize ``.`` and ``..``."""
    path = unicodedata.normalize("NFC", path.replace("\\", "/"))
    if _SLASH_DRIVE.match(path):
        path = path[1:]
    if _DRIVE.match(path):
        path = path[0].upper() + path[1:]
    if not path:
        return ""
    path = posixpath.normpath(path)
    return "" if path == "." else path


def _is_absolute(path: str) -> bool:
    return path.startswith("/") or _DRIVE.match(path) is not None


def _is_absolute_reference(text: str) -> bool:
    match = _SCHEME.match(text)
    if match is not None:
        return True
    return _RAW_ABSOLUTE.match(text) is not None


def _has_foreign_scheme(text: str) -> bool:
    match = _SCHEME.match(text)
    return match is not None and match.group(1).lower() != "file"


def _resolve_base(base_id: str, base_uris: Mapping[str, Any], depth: int) -> str | None:
    entry = base_uris.get(base_id)
    if isinstance(entry, str):
        uri, parent = entry, None
    elif isinstance(entry, Mapping):
        uri, parent = entry.get("uri"), entry.get("uriBaseId")
    else:
        return None
    if not isinstance(uri, str) or not uri.strip():
        return None
    uri = uri.strip()
    if isinstance(parent, str) and parent and not _is_absolute_reference(uri):
        if depth >= _MAX_BASE_DEPTH:
            return None
        parent_uri = _resolve_base(parent, base_uris, depth + 1)
        if parent_uri is not None:
            return _join(parent_uri, uri)
    return uri


def _join(base: str, relative: str) -> str:
    if not base.endswith(("/", "\\")):
        base += "/"
    return base + relative


def _strip_root(path: str, root: str | None) -> str | None:
    """Return ``path`` relative to ``root``, or None when it is not under ``root``."""
    if root is None:
        return None
    root_parts = _segments(root)
    path_parts = _segments(path)
    if len(path_parts) < len(root_parts):
        return None
    windows = _DRIVE.match(root) is not None or root.startswith("//")
    for root_part, path_part in zip(root_parts, path_parts, strict=False):
        if windows:
            if root_part.casefold() != path_part.casefold():
                return None
        elif root_part != path_part:
            return None
    return "/".join(path_parts[len(root_parts) :])


def _segments(path: str) -> list[str]:
    if path == "/":
        return [""]
    return path.split("/")
