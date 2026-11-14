# SPDX-License-Identifier: MIT
"""OpenAPI files and their references, for the vacuum adapter (ENGINE-SPEC 13).

1. :func:`openapi_files` finds the OpenAPI 3 and Swagger 2.0 documents of the target by content:
   ``*.yaml``, ``*.yml`` and ``*.json`` files (at most :data:`MAX_SPEC_BYTES`, without the
   vendored folders of :mod:`kalkan.scanners.adapters._sources`) with a top-level
   ``openapi: 3...`` or ``swagger: "2.0"`` (JSON: the ``"openapi"`` or ``"swagger"`` key).
2. :func:`check_references` decides whether vacuum may read a document. vacuum 0.33.0 follows
   local file references also with ``--remote=false``: a ``$ref`` to ``../../x.yaml`` or to an
   absolute path made it read and lint files outside the target (checked on 2026-10-25), and on
   Windows a ``//host/share`` path would open an SMB connection. The check follows every local
   reference of the document and of the files it references and refuses the document
   (:class:`RefCheck` ``problem``) when one of them:

   - is absolute (``/``, ``\\``, a drive letter), a UNC path, starts with ``~``, or has a URL
     scheme other than ``http``/``https`` (``file:``, ``urn:``, ...);
   - leaves the target after ``\\`` became ``/`` and ``%xx`` escapes were decoded, has a
     component that ends with a dot or a space (Windows drops them), names a Windows device
     (``NUL``, ``COM1``, ...), holds a ``:`` or a control character, or reaches a link;
   - cannot be read safely: a ``$ref`` or ``$id`` key whose value is a block scalar, an alias,
     an anchor, a tag, a flow collection, a quoted string that continues on the next line, a
     plain value that continues on the next line, an explicit key (``? $ref``), or a key written
     with an alias, anchor or tag;
   - is a ``$id`` with anything but an internal (``#``) or ``http``/``https`` value (a file
     ``$id`` changes the base of the relative references below it).

   Every key that YAML can decode to ``$ref`` or ``$id`` is found: the check reads the text as
   written and a copy with every backslash escape decoded (``"\\x24ref"``, ``"\\u002e\\u002e/"``,
   escaped line breaks). Both copies must pass. ``http``/``https`` references are allowed:
   ``--remote=false`` keeps vacuum from fetching them (zero connections under the proxy trap),
   and the result lists them (``remote``) because vacuum then reports the reference as
   unresolved and lints the document only partly.
"""

from __future__ import annotations

import posixpath
import re
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Final
from urllib.parse import unquote

from kalkan.errors import KalkanError
from kalkan.scanners.adapters import _sources
from kalkan.util.safe_io import read_bounded

__all__ = [
    "MAX_REFERENCED_FILES",
    "MAX_SPEC_BYTES",
    "RefCheck",
    "check_references",
    "classify_reference",
    "decode_text",
    "is_openapi",
    "openapi_files",
    "read_text",
    "reference_values",
]

SUFFIXES: Final = (".yaml", ".yml", ".json")
MAX_SPEC_BYTES: Final = 5 * 1024 * 1024
#: The most files that one document may reference (directly or through other files).
MAX_REFERENCED_FILES: Final = 500
MAX_TOTAL_BYTES: Final = 64 * 1024 * 1024

_YAML_OPENAPI = re.compile(r"""^["']?openapi["']?\s*:\s*["']?3\.""", re.MULTILINE)
_YAML_SWAGGER = re.compile(r"""^["']?swagger["']?\s*:\s*["']?2\.0\b""", re.MULTILINE)
_JSON_OPENAPI = re.compile(r'"openapi"\s*:\s*"3\.')
_JSON_SWAGGER = re.compile(r'"swagger"\s*:\s*"2\.0"')
#: The keys that make libopenapi (vacuum) look up another document or change the base URI.
REF_KEYS: Final = ("ref", "id", "dynamicRef", "recursiveRef")
_KEY = re.compile(
    # The lead (an explicit key, an alias, an anchor or a tag) starts only at a token boundary
    # and holds no flow indicator, and every repeat is possessive: before, 20,000 "?" took 33 s
    # (quadratic; self-audit of 2026-11-13). YAML anchor and tag names hold no [ ] { } ,.
    r"""(?P<lead>(?<![^\s"'{\[,])[?*&!][^\s"'${\[,]*+\s*+)?"""
    r"""(?P<q>["']?)\$(?P<key>ref|id|dynamicRef|recursiveRef)(?P=q)"""
    r"""(?P<colon>\s*+:)?"""
)
_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
#: The line breaks of the YAML parser of vacuum (go-yaml): CR LF, CR, LF, NEL, LS, PS.
_LINE_BREAK = re.compile("\r\n|[\r\n\x85  ]")
_ESCAPE = re.compile(r"\\(?:x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}|\r?\n[ \t]*|.)", re.S)
_SIMPLE_ESCAPES: Final = {
    "0": "\0",
    "a": "\a",
    "b": "\b",
    "t": "\t",
    "\t": "\t",
    "n": "\n",
    "v": "\v",
    "f": "\f",
    "r": "\r",
    "e": "\x1b",
    " ": " ",
    '"': '"',
    "/": "/",
    "\\": "\\",
    "N": "\x85",
    "_": "\xa0",
    "L": "\u2028",
    "P": "\u2029",
}
_DEVICES: Final = frozenset(
    {"con", "prn", "aux", "nul", "conin$", "conout$"}
    | {f"com{n}" for n in range(1, 10)}
    | {f"lpt{n}" for n in range(1, 10)}
    | {"com\u00b9", "com\u00b2", "com\u00b3", "lpt\u00b9", "lpt\u00b2", "lpt\u00b3"}
)


def decode_text(data: bytes) -> str | None:
    """Decode a document as the YAML parser of vacuum does: UTF-8 (with or without a byte order
    mark) or UTF-16 with a byte order mark. None when the bytes are not valid."""
    try:
        if data.startswith(b"\xef\xbb\xbf"):
            return data[3:].decode("utf-8")
        if data.startswith((b"\xff\xfe", b"\xfe\xff")):
            return data.decode("utf-16")
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def is_openapi(text: str) -> bool:
    """Return True for an OpenAPI 3 or Swagger 2.0 document (module docstring, point 1)."""
    if text.lstrip().startswith("{"):
        return bool(_JSON_OPENAPI.search(text) or _JSON_SWAGGER.search(text))
    return bool(_YAML_OPENAPI.search(text) or _YAML_SWAGGER.search(text))


def read_text(path: Path, limit: int = MAX_SPEC_BYTES) -> str | None:
    """Return the decoded text of a target file (:func:`decode_text`), or None."""
    try:
        return decode_text(read_bounded(path, limit))
    except (KalkanError, OSError):
        return None


def openapi_files(target: Path) -> list[str]:
    """Return the target-relative paths of the OpenAPI documents, sorted."""

    def accept(rel: str) -> bool:
        if not rel.lower().endswith(SUFFIXES):
            return False
        text = read_text(target / rel)
        return text is not None and is_openapi(text)

    return _sources.source_files(target, accept)


def _unescape(value: str) -> str:
    def repl(match: re.Match[str]) -> str:
        token = match.group(0)[1:]
        if token[:1] in ("x", "u", "U") and len(token) > 1:
            return chr(int(token[1:], 16))
        if token.startswith(("\n", "\r")):
            return ""
        return _SIMPLE_ESCAPES.get(token, token)

    return _ESCAPE.sub(repl, value)


@dataclass(frozen=True)
class _Value:
    key: str
    value: str | None  # None: the value cannot be read safely
    reason: str = ""


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" \t"))


def _next_content_line(lines: list[str], index: int) -> str | None:
    for line in lines[index + 1 :]:
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            return line
    return None


def _scalar(rest: str, *, unescape: bool) -> tuple[list[str] | None, str]:
    """Return the possible values of a scalar that starts ``rest`` (after ``key:``), or
    ``(None, reason)`` when it cannot be read from this line."""
    text = rest.lstrip(" \t")
    if not text or text.startswith("#"):
        return None, "the value starts on a later line"
    first = text[0]
    if first in "|>":
        return None, "a block scalar value"
    if first in "*&!":
        return None, "an alias, anchor or tag value"
    if first in "[{":
        return None, "a flow collection value"
    if first in "@`":
        return None, "a reserved indicator"
    if first == '"':
        match = re.match(r'"((?:[^"\\]|\\.)*)"', text)
        if match is None:
            return None, "a quoted value that continues on the next line"
        raw = match.group(1)
        return [_unescape(raw) if unescape else raw], ""
    if first == "'":
        match = re.match(r"'((?:[^']|'')*)'", text)
        if match is None:
            return None, "a quoted value that continues on the next line"
        return [match.group(1).replace("''", "'")], ""
    plain = re.split(r"\s+#", text, maxsplit=1)[0].strip()
    flow = re.split(r"[,}\]]", plain, maxsplit=1)[0].strip()
    return list(dict.fromkeys([plain, flow])), ""


def reference_values(text: str) -> list[_Value]:
    """Return every ``$ref``, ``$id``, ``$dynamicRef`` and ``$recursiveRef`` value of a text, in
    the written text and in the copy with decoded escapes (module docstring, point 2)."""
    found: list[_Value] = []
    for view, unescape in ((text, True), (_unescape(text), False)):
        lines = _LINE_BREAK.split(view)
        for index, line in enumerate(lines):
            for match in _KEY.finditer(line):
                key = "$" + match.group("key")
                end = match.end()
                if end < len(line) and match.group("colon") is None:
                    nxt = line[end]
                    if nxt.isalnum() or nxt in "_-":
                        continue  # a longer word such as $references
                lead = (match.group("lead") or "").strip()
                if lead.startswith("?"):
                    found.append(_Value(key, None, "an explicit key"))
                    continue
                if lead:
                    found.append(_Value(key, None, "a key with an alias, anchor or tag"))
                    continue
                if match.group("colon") is None:
                    continue  # the word in a text, not a key
                values, reason = _scalar(line[end:], unescape=unescape)
                if values is None:
                    found.append(_Value(key, None, reason))
                    continue
                stripped = line[end:].lstrip(" \t")
                plain = stripped[:1] not in ("'", '"')
                following = _next_content_line(lines, index)
                if plain and following is not None and _indent(following) > match.start():
                    if not following.lstrip().startswith(("-", "}", "]", ",")):
                        found.append(_Value(key, None, "a plain value that continues"))
                        continue
                found.extend(_Value(key, value) for value in values)
    return found


def classify_reference(value: str, base: str) -> tuple[str, str]:
    """Classify one reference value of the target file ``base`` (a target-relative POSIX path).

    Returns ``(kind, detail)``: ``internal`` (``#...``), ``remote`` (``http``/``https``),
    ``local`` (detail: the target-relative path) or ``unsafe`` (detail: the reason).
    """
    raw = value.strip()
    file_part = raw.split("#", 1)[0]
    if not file_part:
        return "internal", ""
    forms = list(dict.fromkeys([file_part, unquote(file_part)]))
    resolved = ""
    for form in forms:
        if any(ord(char) < 32 or ord(char) == 127 for char in form):
            return "unsafe", "a control character"
        scheme = _SCHEME.match(form)
        if scheme:
            name = scheme.group(0)[:-1].lower()
            if name in ("http", "https"):
                return "remote", raw
            if len(name) == 1:
                return "unsafe", "an absolute Windows path"
            return "unsafe", f"the URL scheme {name}:"
        if form.startswith(("/", "\\")):
            return "unsafe", "an absolute or UNC path"
        if form.startswith("~"):
            return "unsafe", "a home folder path"
        if ":" in form:
            return "unsafe", "a ':' in the path"
        path = form.replace("\\", "/")
        for part in path.split("/"):
            if part in ("", ".", ".."):
                continue
            if part.endswith((".", " ")):
                return "unsafe", "a path component that ends with a dot or a space"
            if part.split(".", 1)[0].strip().lower() in _DEVICES:
                return "unsafe", "a Windows device name"
        folder = posixpath.dirname(base)
        joined = posixpath.normpath(posixpath.join(folder, path))
        if joined == ".." or joined.startswith("../") or posixpath.isabs(joined):
            return "unsafe", "a path outside the target"
        resolved = resolved or joined
    return "local", resolved


@dataclass
class RefCheck:
    """The result of :func:`check_references` for one document."""

    files: list[str] = field(default_factory=list)  # the document and the files it references
    remote: list[str] = field(default_factory=list)  # http/https references (not fetched)
    problem: str = ""  # why vacuum must not read the document ("" when it may)
    where: str = ""  # the file of the problem

    @property
    def ok(self) -> bool:
        return not self.problem


def _link_inside(target: Path, rel: str) -> bool:
    """Return True when ``rel`` or one of its folders inside the target is a link."""
    current = target
    for part in PurePosixPath(rel).parts:
        current = current / part
        try:
            if current.is_symlink():
                return True
        except OSError:
            return True
    return False


def check_references(target: Path, spec: str) -> RefCheck:
    """Follow the references of the document ``spec`` (module docstring, point 2)."""
    check = RefCheck()
    queue: deque[str] = deque([spec])
    seen = {spec}
    total = 0
    while queue:
        rel = queue.popleft()
        check.files.append(rel)
        path = target / rel
        try:
            size = path.stat().st_size if path.is_file() else -1
        except OSError:
            size = -1
        if size < 0:
            continue  # not a file: vacuum reports the reference as unresolved
        total += size
        if total > MAX_TOTAL_BYTES:
            check.problem, check.where = "the referenced files are too large", rel
            return check
        text = read_text(path)
        if text is None:
            check.problem, check.where = "a file that is not UTF-8 or UTF-16 text", rel
            return check
        for item in reference_values(text):
            if item.value is None:
                check.problem, check.where = f"{item.key}: {item.reason}", rel
                return check
            kind, detail = classify_reference(item.value, rel)
            if item.key == "$id" and kind not in ("internal", "remote"):
                check.problem, check.where = "$id: a value that is not '#...' or http(s)", rel
                return check
            if kind == "unsafe":
                check.problem, check.where = f"{item.key}: {detail}", rel
                return check
            if kind == "remote":
                if detail not in check.remote:
                    check.remote.append(detail)
                continue
            if kind == "local" and detail not in seen:
                if _link_inside(target, detail):
                    check.problem, check.where = f"{item.key}: a link in the path", rel
                    return check
                seen.add(detail)
                if len(seen) > MAX_REFERENCED_FILES:
                    check.problem, check.where = "too many referenced files", rel
                    return check
                queue.append(detail)
    return check
