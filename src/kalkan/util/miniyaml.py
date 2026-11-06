# SPDX-License-Identifier: MIT
"""A small YAML reader for Semgrep and Opengrep rule files (ENGINE-SPEC 13).

kalkan has no runtime dependency, so it cannot use PyYAML. The rule packs (``rules/opengrep``
and the vendored packs below ``rules/opengrep-packs``) use a small part of YAML, and this
module reads exactly that part:

- block mappings and block sequences (also ``key:`` followed by ``- item`` at the same
  indentation), comments, a leading ``---`` document marker;
- plain scalars (also over several lines), single-quoted and double-quoted scalars (escapes and
  line folding), literal (``|``) and folded (``>``) block scalars with chomping (``-``, ``+``)
  and indentation indicators;
- flow sequences (``[a, "b", [c]]``, also over several lines).

Anchors, aliases, tags, flow mappings, complex keys and several documents raise
:class:`MiniYamlError`. Plain scalars resolve to ``None`` (``~``, ``null``, empty), ``True`` and
``False`` (``true``, ``false`` in three spellings), ``int`` and ``float``; everything else is a
string. Keys stay strings.

The reader was compared with PyYAML 6.0.3 (``yaml.safe_load``) on the 2,756 rule files of the
four upstream rule repositories and of ``rules/opengrep`` (2026-10-25): the results were equal,
apart from the YAML 1.1 words ``yes``, ``no``, ``on`` and ``off``, which PyYAML reads as
booleans and this reader keeps as strings (one upstream test file).
"""

from __future__ import annotations

import re
from typing import Any

__all__ = ["MiniYamlError", "load"]


class MiniYamlError(ValueError):
    """The text uses YAML that this reader does not support, or is not valid YAML."""

    def __init__(self, message: str, line: int | None = None) -> None:
        self.line = line
        super().__init__(f"line {line}: {message}" if line is not None else message)


_NULL = {"", "~", "null", "Null", "NULL"}
_TRUE = {"true", "True", "TRUE"}
_FALSE = {"false", "False", "FALSE"}
_INT = re.compile(r"[-+]?(?:0|[1-9][0-9_]*)")
_FLOAT = re.compile(
    r"[-+]?(?:[0-9][0-9_]*)?\.[0-9_]*(?:[eE][-+]?[0-9]+)?|[-+]?[0-9][0-9_]*[eE][-+]?[0-9]+"
)
_ESCAPES = {
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
    "L": " ",
    "P": " ",
}
_HEX_ESCAPES = {"x": 2, "u": 4, "U": 8}
_UNSUPPORTED_START = "&*!%@`{?"


def load(text: str) -> Any:
    """Return the single document of ``text`` (None for an empty document)."""
    return _Parser(text).document()


def _resolve(value: str) -> Any:
    if value in _NULL:
        return None
    if value in _TRUE:
        return True
    if value in _FALSE:
        return False
    if _INT.fullmatch(value):
        return int(value.replace("_", ""))
    if _FLOAT.fullmatch(value) and any(ch.isdigit() for ch in value):
        return float(value.replace("_", ""))
    lowered = value.lower()
    if lowered in {".inf", "+.inf"}:
        return float("inf")
    if lowered == "-.inf":
        return float("-inf")
    if lowered == ".nan":
        return float("nan")
    return value


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _is_blank_or_comment(line: str) -> bool:
    stripped = line.strip()
    return not stripped or stripped.startswith("#")


def _strip_comment(text: str) -> str:
    """Return ``text`` up to a ``#`` that follows whitespace (a plain scalar or a header)."""
    for index, char in enumerate(text):
        if char == "#" and (index == 0 or text[index - 1] in " \t"):
            return text[:index].rstrip(" \t")
    return text.rstrip(" \t")


def _is_sequence_entry(content: str) -> bool:
    return content == "-" or content.startswith(("- ", "-\t"))


class _Parser:
    def __init__(self, text: str) -> None:
        if text.startswith("﻿"):
            text = text[1:]
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        self.lines = text.split("\n")
        # A text that ends with a newline gives an empty last item: drop it, and remember that
        # every kept line ends with a line break.
        self.final_break = text.endswith("\n")
        if self.final_break:
            self.lines.pop()
        self.i = 0

    # -- helpers ------------------------------------------------------------------------------

    def error(self, message: str, index: int | None = None) -> MiniYamlError:
        line = (index if index is not None else self.i) + 1
        return MiniYamlError(message, line)

    def has_break(self, index: int) -> bool:
        return index < len(self.lines) - 1 or self.final_break

    def next_significant(self) -> int | None:
        while self.i < len(self.lines) and _is_blank_or_comment(self.lines[self.i]):
            self.i += 1
        return self.i if self.i < len(self.lines) else None

    # -- document -----------------------------------------------------------------------------

    def document(self) -> Any:
        index = self.next_significant()
        if index is not None and re.fullmatch(r"---(?:[ \t].*)?", self.lines[index]):
            rest = _strip_comment(self.lines[index][3:])
            if rest:
                raise self.error("content after the document marker is not supported", index)
            self.i += 1
        if self.next_significant() is None:
            return None
        node = self.block(-1)
        index = self.next_significant()
        if index is not None:
            line = self.lines[index]
            if line.startswith("..."):
                self.i += 1
                if self.next_significant() is None:
                    return node
            if line.startswith("---"):
                raise self.error("several documents are not supported", index)
            raise self.error("unexpected content after the document", index)
        return node

    # -- block nodes --------------------------------------------------------------------------

    def block(self, parent: int) -> Any:
        index = self.next_significant()
        if index is None:
            return None
        line = self.lines[index]
        column = _indent(line)
        if column <= parent:
            return None
        if "\t" in line[:column] or line[column : column + 1] == "\t":
            raise self.error("a tab in the indentation", index)
        content = line[column:]
        if _is_sequence_entry(content):
            return self.sequence(column)
        if self.key_of(content, index) is not None:
            return self.mapping(column)
        return self.scalar(parent)

    def mapping(self, column: int) -> dict[str, Any]:
        result: dict[str, Any] = {}
        while True:
            index = self.next_significant()
            if index is None:
                return result
            line = self.lines[index]
            current = _indent(line)
            if current < column:
                return result
            if current > column:
                raise self.error("bad indentation of a mapping entry", index)
            content = line[column:]
            if _is_sequence_entry(content):
                return result
            found = self.key_of(content, index)
            if found is None:
                raise self.error("expected a mapping key", index)
            key, rest = found
            result[key] = self.value(column, index, line, rest)

    def value(self, column: int, index: int, line: str, rest: str) -> Any:
        """Return the value of the mapping key on line ``index``; ``rest`` follows the colon."""
        rest = rest.lstrip(" \t")
        if not rest or rest.startswith("#"):
            self.i = index + 1
            nxt = self.next_significant()
            if nxt is None:
                return None
            nxt_line = self.lines[nxt]
            nxt_column = _indent(nxt_line)
            if nxt_column > column:
                return self.block(column)
            if nxt_column == column and _is_sequence_entry(nxt_line[column:]):
                return self.sequence(column)
            return None
        start = len(line) - len(rest)
        self.lines[index] = " " * start + rest
        self.i = index
        return self.scalar(column)

    def sequence(self, column: int) -> list[Any]:
        result: list[Any] = []
        while True:
            index = self.next_significant()
            if index is None:
                return result
            line = self.lines[index]
            current = _indent(line)
            if current < column:
                return result
            if current > column:
                raise self.error("bad indentation of a sequence entry", index)
            content = line[column:]
            if not _is_sequence_entry(content):
                return result
            rest = content[1:].lstrip(" \t")
            if not rest or rest.startswith("#"):
                self.i = index + 1
                nxt = self.next_significant()
                if nxt is not None and _indent(self.lines[nxt]) > column:
                    result.append(self.block(column))
                else:
                    result.append(None)
                continue
            start = len(line) - len(rest)
            self.lines[index] = " " * start + rest
            self.i = index
            result.append(self.block(column))

    def key_of(self, content: str, index: int) -> tuple[str, str] | None:
        """Return (key, text after the colon) when ``content`` starts a mapping entry."""
        if not content:
            return None
        first = content[0]
        if first in "\"'":
            end = _quoted_end(content, 0)
            if end is None:
                return None
            after = content[end + 1 :].lstrip(" \t")
            if after.startswith(":") and (len(after) == 1 or after[1] in " \t"):
                raw = content[: end + 1]
                key = (
                    _double(raw[1:-1], self, index)
                    if first == '"'
                    else raw[1:-1].replace("''", "'")
                )
                return key, after[1:]
            return None
        if first == "?":
            raise self.error("complex mapping keys are not supported", index)
        if first in "[{#|>" or _is_sequence_entry(content):
            return None
        for position, char in enumerate(content):
            if char == "#" and position > 0 and content[position - 1] in " \t":
                return None
            if char == ":" and (position + 1 == len(content) or content[position + 1] in " \t"):
                key = content[:position].rstrip(" \t")
                if not key:
                    return None
                if key[0] in _UNSUPPORTED_START:
                    raise self.error(f"unsupported key {key!r}", index)
                return key, content[position + 1 :]
        return None

    # -- scalars ------------------------------------------------------------------------------

    def scalar(self, parent: int) -> Any:
        index = self.i
        line = self.lines[index]
        column = _indent(line)
        text = line[column:]
        first = text[0]
        if first in "|>":
            return self.block_scalar(parent, index, text)
        if first == '"' or first == "'":
            return self.quoted(index, column)
        if first == "[":
            return self.flow(index, column)
        if first in _UNSUPPORTED_START:
            raise self.error(f"unsupported YAML feature {first!r}", index)
        return self.plain(parent, index, column)

    def plain(self, parent: int, index: int, column: int) -> Any:
        first_text = _strip_comment(self.lines[index][column:])
        commented = first_text != self.lines[index][column:].rstrip(" \t")
        _check_plain(first_text, self, index)
        parts = [first_text]
        pending_blank = 0
        cursor = index + 1
        end = cursor
        while not commented and cursor < len(self.lines):
            line = self.lines[cursor]
            if not line.strip():
                pending_blank += 1
                cursor += 1
                continue
            if _indent(line) <= parent:
                break
            stripped = line.strip(" \t")
            if stripped.startswith("#"):
                break
            piece = _strip_comment(stripped)
            commented = piece != stripped.rstrip(" \t")
            _check_plain(piece, self, cursor)
            parts.append("\n" * pending_blank if pending_blank else " ")
            parts.append(piece)
            pending_blank = 0
            cursor += 1
            end = cursor
        self.i = end
        return _resolve("".join(parts))

    def quoted(self, index: int, column: int) -> str:
        line = self.lines[index]
        quote = line[column]
        chunks: list[str] = []
        cursor = index
        position = column + 1
        text = line
        while True:
            end = _quoted_end(text, position - 1, quote)
            if end is not None:
                chunks.append(text[position:end])
                tail = _strip_comment(text[end + 1 :])
                if tail:
                    raise self.error("unexpected text after a quoted scalar", cursor)
                break
            chunks.append(text[position:])
            chunks.append("\n")
            cursor += 1
            if cursor >= len(self.lines):
                raise self.error("unterminated quoted scalar", index)
            text = self.lines[cursor]
            position = 0
        self.i = cursor + 1
        raw = "".join(chunks)
        if quote == '"':
            return _double(raw, self, index)
        return _fold(raw).replace("''", "'")

    def flow(self, index: int, column: int) -> list[Any]:
        source = "\n".join([self.lines[index][column:], *self.lines[index + 1 : index + 400]])
        value, position = _flow_sequence(source, 0, self, index)
        consumed = source.count("\n", 0, position)
        rest_of_line = source[position:].split("\n", 1)[0]
        if _strip_comment(rest_of_line):
            raise self.error("unexpected text after a flow sequence", index + consumed)
        self.i = index + consumed + 1
        return value

    def block_scalar(self, parent: int, index: int, header: str) -> str:
        style = header[0]
        indicators = _strip_comment(header[1:])
        chomping: bool | None = None
        increment: int | None = None
        for char in indicators:
            if char in "+-" and chomping is None:
                chomping = char == "+"
            elif char in "123456789" and increment is None:
                increment = int(char)
            else:
                raise self.error(f"bad block scalar header {header!r}", index)
        folded = style == ">"
        min_indent = max(parent + 1, 1)
        cursor = index + 1
        if increment is None:
            max_indent = 0
            probe = cursor
            while probe < len(self.lines):
                line = self.lines[probe]
                if not line.strip(" "):
                    max_indent = max(max_indent, len(line))
                    probe += 1
                    continue
                max_indent = max(max_indent, _indent(line))
                break
            indent = max(min_indent, max_indent)
        else:
            indent = min_indent + increment - 1

        def breaks_from(position: int) -> tuple[list[str], int, int]:
            found: list[str] = []
            while position < len(self.lines):
                line = self.lines[position]
                spaces = 0
                while spaces < indent and spaces < len(line) and line[spaces] == " ":
                    spaces += 1
                if spaces == len(line):
                    if not self.has_break(position):
                        return found, position, spaces
                    found.append("\n")
                    position += 1
                    continue
                return found, position, spaces
            return found, position, 0

        chunks: list[str] = []
        breaks, cursor, spaces = breaks_from(cursor)
        line_break = ""
        while cursor < len(self.lines) and spaces == indent and indent < len(self.lines[cursor]):
            chunks.extend(breaks)
            text = self.lines[cursor][indent:]
            leading_non_space = text[0] not in " \t"
            chunks.append(text)
            line_break = "\n" if self.has_break(cursor) else ""
            breaks, cursor, spaces = breaks_from(cursor + 1)
            if cursor < len(self.lines) and spaces == indent and indent < len(self.lines[cursor]):
                following = self.lines[cursor][indent]
                if folded and line_break == "\n" and leading_non_space and following not in " \t":
                    if not breaks:
                        chunks.append(" ")
                else:
                    chunks.append(line_break)
            else:
                break
        if chomping is not False:
            chunks.append(line_break)
        if chomping is True:
            chunks.extend(breaks)
        self.i = cursor
        return "".join(chunks)


def _check_plain(text: str, parser: _Parser, index: int) -> None:
    if ": " in text or "\t:" in text or text.endswith(":"):
        raise parser.error("a plain scalar must not contain ': '", index)


def _quoted_end(text: str, start: int, quote: str | None = None) -> int | None:
    """Return the index of the closing quote of the scalar that opens at ``start``, or None."""
    quote = quote or text[start]
    position = start + 1
    while position < len(text):
        char = text[position]
        if quote == "'" and char == "'":
            if position + 1 < len(text) and text[position + 1] == "'":
                position += 2
                continue
            return position
        if quote == '"':
            if char == "\\":
                position += 2
                continue
            if char == '"':
                return position
        position += 1
    return None


def _fold(raw: str) -> str:
    """Fold the line breaks of a quoted scalar (YAML flow scalar folding)."""
    if "\n" not in raw:
        return raw
    lines = raw.split("\n")
    out = [lines[0].rstrip(" \t")]
    blank = 0
    for number, line in enumerate(lines[1:], start=1):
        last = number == len(lines) - 1
        stripped = line.strip(" \t") if not last else line.lstrip(" \t")
        if not stripped and not last:
            blank += 1
            continue
        out.append("\n" * blank if blank else " ")
        out.append(stripped)
        blank = 0
    return "".join(out)


def _double(raw: str, parser: _Parser, index: int) -> str:
    """Decode the body of a double-quoted scalar: escapes and line folding."""
    out: list[str] = []
    pending = ""  # literal spaces and tabs; a line break drops them
    position = 0
    length = len(raw)
    while position < length:
        char = raw[position]
        if char in " \t":
            pending += char
            position += 1
            continue
        if char == "\\":
            if position + 1 >= length:
                raise parser.error("bad escape at the end of a double-quoted scalar", index)
            code = raw[position + 1]
            if code == "\n":  # an escaped line break joins the lines
                out.append(pending)
                pending = ""
                position += 2
                while position < length and raw[position] in " \t":
                    position += 1
                continue
            out.append(pending)
            pending = ""
            if code in _ESCAPES:
                out.append(_ESCAPES[code])
                position += 2
                continue
            if code in _HEX_ESCAPES:
                size = _HEX_ESCAPES[code]
                digits = raw[position + 2 : position + 2 + size]
                if len(digits) != size or not all(c in "0123456789abcdefABCDEF" for c in digits):
                    raise parser.error(f"bad escape \\{code}{digits}", index)
                out.append(chr(int(digits, 16)))
                position += 2 + size
                continue
            raise parser.error(f"unknown escape \\{code}", index)
        if char == "\n":
            pending = ""
            position += 1
            blank = 0
            while True:
                probe = position
                while probe < length and raw[probe] in " \t":
                    probe += 1
                if probe < length and raw[probe] == "\n":
                    blank += 1
                    position = probe + 1
                    continue
                position = probe
                break
            out.append("\n" * blank if blank else " ")
            continue
        out.append(pending)
        pending = ""
        out.append(char)
        position += 1
    out.append(pending)
    return "".join(out)


def _flow_sequence(source: str, position: int, parser: _Parser, index: int) -> tuple[list, int]:
    """Parse ``[ ... ]`` that starts at ``position``; return (items, index after ``]``)."""
    assert source[position] == "["
    position += 1
    items: list[Any] = []
    expect_item = True
    while True:
        position = _skip_flow_space(source, position)
        if position >= len(source):
            raise parser.error("unterminated flow sequence", index)
        char = source[position]
        if char == "]":
            return items, position + 1
        if char == ",":
            if expect_item:
                raise parser.error("empty entry in a flow sequence", index)
            expect_item = True
            position += 1
            continue
        if not expect_item:
            raise parser.error("missing ',' in a flow sequence", index)
        if char == "[":
            value, position = _flow_sequence(source, position, parser, index)
        elif char in "\"'":
            end = _quoted_end(source, position)
            if end is None:
                raise parser.error("unterminated quoted scalar in a flow sequence", index)
            body = source[position + 1 : end]
            value = _double(body, parser, index) if char == '"' else _fold(body).replace("''", "'")
            position = end + 1
        elif char in "{" or char in _UNSUPPORTED_START:
            raise parser.error(f"unsupported YAML feature {char!r} in a flow sequence", index)
        else:
            start = position
            while position < len(source) and source[position] not in ",[]{}\n":
                if source[position] == "#" and source[position - 1] in " \t":
                    break
                if source[position] == ":" and (
                    position + 1 >= len(source) or source[position + 1] in " \t\n,]"
                ):
                    raise parser.error("flow mappings are not supported", index)
                position += 1
            pieces = [source[start:position].strip(" \t")]
            # A plain scalar may continue on the next lines.
            while position < len(source) and source[position] in "\n#":
                if source[position] == "#":
                    position = source.find("\n", position)
                    if position < 0:
                        position = len(source)
                    continue
                probe = _skip_flow_space(source, position)
                if probe < len(source) and source[probe] not in ",[]{}":
                    position = probe
                    start = position
                    while position < len(source) and source[position] not in ",[]{}\n":
                        position += 1
                    pieces.append(source[start:position].strip(" \t"))
                    continue
                break
            value = _resolve(" ".join(piece for piece in pieces if piece))
        items.append(value)
        expect_item = False


def _skip_flow_space(source: str, position: int) -> int:
    while position < len(source):
        char = source[position]
        if char in " \t\n":
            position += 1
            continue
        if char == "#" and (position == 0 or source[position - 1] in " \t\n"):
            end = source.find("\n", position)
            position = len(source) if end < 0 else end + 1
            continue
        break
    return position
