#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Ported from vercel-labs/deepsec@4fa6722: packages/scanner/src/matchers/*.ts
# Copyright 2026 Vercel, Inc. and contributors. Changes: translated from TypeScript to Python;
# the 198 matcher plugins become JSON data specs; JavaScript regexes become Python regexes; the
# custom match() logic becomes gates, line-window conditions and path filters (see the notes
# field of each generated spec).
"""Port the deepsec matchers to kalkan matcher specs (``rules/matchers/<slug>.json``).

Usage::

    python scripts/port_deepsec_matchers.py            # check rules/matchers (exit 1 on drift)
    python scripts/port_deepsec_matchers.py --write    # write rules/matchers/*.json
    python scripts/port_deepsec_matchers.py --report   # print a port summary as JSON

The script reads ``third_party/deepsec/scanner/matchers/*.ts`` as text. A small lexer parses
the object literals. The script never imports, compiles or runs the TypeScript sources. Every
generated spec passes ``kalkan.matchers.spec.parse_spec`` before it is written. Only ``--write``
writes files, and only below ``rules/matchers``.

Most matchers call ``regexMatcher`` with a list of ``{regex, label}`` objects; the script takes
those lists verbatim. :data:`CURATION` holds what text extraction cannot see: the kalkan class
and CWE IDs, the translation of custom ``match()`` logic and the notes about approximations.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIR = REPO_ROOT / "third_party" / "deepsec" / "scanner" / "matchers"
RULES_DIR = REPO_ROOT / "rules" / "matchers"
UPSTREAM_REPO = "vercel-labs/deepsec"
UPSTREAM_COMMIT = "4fa6722"
UPSTREAM_PREFIX = "packages/scanner/src/matchers/"
NOT_MATCHERS = {"index.ts", "utils.ts"}

sys.path.insert(0, str(REPO_ROOT / "src"))

from kalkan.errors import ValidationError  # noqa: E402
from kalkan.matchers.spec import parse_spec  # noqa: E402

# ---------------------------------------------------------------------------------------------
# Lexer
# ---------------------------------------------------------------------------------------------

_REGEX_KEYWORDS = {
    "return",
    "typeof",
    "case",
    "in",
    "of",
    "new",
    "delete",
    "void",
    "throw",
    "else",
    "do",
    "instanceof",
    "yield",
    "await",
}
_SIMPLE_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "v": "\v", "0": "\0"}


@dataclass
class Tok:
    kind: str  # str, tpl, regex, ident, num, punct
    value: Any
    pos: int


def _cook_escape(src: str, index: int) -> tuple[str, int]:
    char = src[index + 1]
    if char in _SIMPLE_ESCAPES and not (char == "0" and src[index + 2 : index + 3].isdigit()):
        return _SIMPLE_ESCAPES[char], index + 2
    if char == "x":
        return chr(int(src[index + 2 : index + 4], 16)), index + 4
    if char == "u":
        if src[index + 2] == "{":
            end = src.index("}", index + 3)
            return chr(int(src[index + 3 : end], 16)), end + 1
        return chr(int(src[index + 2 : index + 6], 16)), index + 6
    if char == "\n":
        return "", index + 2
    return char, index + 2


def _read_string(src: str, index: int) -> tuple[str, int]:
    quote = src[index]
    pos = index + 1
    out = []
    while True:
        char = src[pos]
        if char == "\\":
            cooked, pos = _cook_escape(src, pos)
            out.append(cooked)
            continue
        if char == quote:
            return "".join(out), pos + 1
        if char == "\n":
            raise ValueError(f"unterminated string at {index}")
        out.append(char)
        pos += 1


def _read_template(src: str, index: int) -> tuple[list[tuple[str, str, str]], int]:
    """Return the parts of a template literal: ("str", cooked, raw) and ("expr", text, text)."""
    pos = index + 1
    parts: list[tuple[str, str, str]] = []
    cooked: list[str] = []
    raw: list[str] = []
    while True:
        char = src[pos]
        if char == "\\":
            text, end = _cook_escape(src, pos)
            cooked.append(text)
            raw.append(src[pos:end])
            pos = end
            continue
        if char == "`":
            parts.append(("str", "".join(cooked), "".join(raw)))
            return parts, pos + 1
        if char == "$" and src[pos + 1] == "{":
            parts.append(("str", "".join(cooked), "".join(raw)))
            cooked, raw = [], []
            end = pos + 2
            depth = 1
            while True:
                inner = src[end]
                if inner in "'\"":
                    _, end = _read_string(src, end)
                    continue
                if inner == "`":
                    _, end = _read_template(src, end)
                    continue
                if inner == "{":
                    depth += 1
                elif inner == "}":
                    depth -= 1
                    if depth == 0:
                        break
                end += 1
            parts.append(("expr", src[pos + 2 : end], src[pos + 2 : end]))
            pos = end + 1
            continue
        cooked.append(char)
        raw.append(char)
        pos += 1


def _read_regex(src: str, index: int) -> tuple[str, str, int]:
    pos = index + 1
    in_class = False
    while True:
        char = src[pos]
        if char == "\\":
            pos += 2
            continue
        if char == "\n":
            raise ValueError(f"unterminated regex at {index}")
        if in_class:
            if char == "]":
                in_class = False
        elif char == "[":
            in_class = True
        elif char == "/":
            break
        pos += 1
    end = pos + 1
    while end < len(src) and src[end].isalpha():
        end += 1
    return src[index + 1 : pos], src[pos + 1 : end], end


def tokenize(src: str) -> list[Tok]:
    tokens: list[Tok] = []
    pos = 0
    length = len(src)
    while pos < length:
        char = src[pos]
        if char.isspace():
            pos += 1
        elif src.startswith("//", pos):
            end = src.find("\n", pos)
            pos = length if end == -1 else end
        elif src.startswith("/*", pos):
            pos = src.index("*/", pos) + 2
        elif char in "'\"":
            value, end = _read_string(src, pos)
            tokens.append(Tok("str", value, pos))
            pos = end
        elif char == "`":
            value, end = _read_template(src, pos)
            tokens.append(Tok("tpl", value, pos))
            pos = end
        elif char == "/" and _regex_allowed(tokens):
            body, flags, end = _read_regex(src, pos)
            tokens.append(Tok("regex", (body, flags), pos))
            pos = end
        elif char.isalpha() or char in "_$":
            end = pos + 1
            while end < length and (src[end].isalnum() or src[end] in "_$"):
                end += 1
            tokens.append(Tok("ident", src[pos:end], pos))
            pos = end
        elif char.isdigit():
            end = pos + 1
            while end < length and (src[end].isalnum() or src[end] in "._"):
                end += 1
            tokens.append(Tok("num", src[pos:end], pos))
            pos = end
        else:
            tokens.append(Tok("punct", char, pos))
            pos += 1
    return tokens


def _regex_allowed(tokens: list[Tok]) -> bool:
    if not tokens:
        return True
    last = tokens[-1]
    if last.kind == "punct":
        return last.value not in (")", "]", "}")
    return last.kind == "ident" and last.value in _REGEX_KEYWORDS


# ---------------------------------------------------------------------------------------------
# Object-literal parser
# ---------------------------------------------------------------------------------------------


@dataclass
class Ref:
    """An identifier or member expression (``UNTRUSTED.source``)."""

    name: str


@dataclass
class Other:
    """Any expression that the parser does not evaluate (functions, calls, operators)."""

    text: str


def _is(token: Tok, value: str) -> bool:
    return token.kind == "punct" and token.value == value


def _skip_balanced(tokens: list[Tok], index: int) -> int:
    pairs = {"(": ")", "[": "]", "{": "}"}
    stack = [pairs[tokens[index].value]]
    index += 1
    while stack:
        token = tokens[index]
        if token.kind == "punct":
            if token.value in pairs:
                stack.append(pairs[token.value])
            elif token.value == stack[-1]:
                stack.pop()
        index += 1
    return index


def _template_value(parts: list[tuple[str, str, str]], raw: bool) -> Any:
    if len(parts) == 1:
        return parts[0][2] if raw else parts[0][1]
    return ("tpl", [(kind, raw_text if raw else cooked) for kind, cooked, raw_text in parts])


def parse_value(tokens: list[Tok], index: int, src: str) -> tuple[Any, int]:
    token = tokens[index]
    if token.kind == "str":
        value, index = token.value, index + 1
    elif token.kind == "tpl":
        value, index = _template_value(token.value, raw=False), index + 1
    elif token.kind == "regex":
        value, index = ("re", token.value[0], token.value[1]), index + 1
    elif _is(token, "["):
        items = []
        index += 1
        while not _is(tokens[index], "]"):
            item, index = parse_value(tokens, index, src)
            items.append(item)
            if _is(tokens[index], ","):
                index += 1
        value, index = items, index + 1
    elif _is(token, "{"):
        value, index = _parse_object(tokens, index, src)
    elif token.kind == "ident" and token.value == "new" and tokens[index + 1].value == "RegExp":
        end = _skip_balanced(tokens, index + 2)
        args = []
        pos = index + 3
        while pos < end - 1:
            item, pos = parse_value(tokens, pos, src)
            args.append(item)
            if _is(tokens[pos], ","):
                pos += 1
        value, index = ("newregexp", args), end
    elif (
        token.kind == "ident"
        and token.value == "String"
        and _is(tokens[index + 1], ".")
        and tokens[index + 2].value == "raw"
    ):
        value, index = _template_value(tokens[index + 3].value, raw=True), index + 4
    else:
        end = index
        while not (tokens[end].kind == "punct" and tokens[end].value in ",]});"):
            if tokens[end].kind == "punct" and tokens[end].value in "([{":
                end = _skip_balanced(tokens, end)
            else:
                end += 1
        text = src[tokens[index].pos : tokens[end].pos].strip()
        return (Ref(text) if re.fullmatch(r"[\w$.]+", text) else Other(text)), end
    if index < len(tokens) and tokens[index].kind == "ident" and tokens[index].value == "as":
        index += 2  # "as const"
    while index < len(tokens) and _is(tokens[index], "+") and isinstance(value, str):
        right, index = parse_value(tokens, index + 1, src)
        if not isinstance(right, str):
            return Other(f"{value!r} + ..."), index
        value += right
    return value, index


def _parse_object(tokens: list[Tok], index: int, src: str) -> tuple[dict[str, Any], int]:
    result: dict[str, Any] = {}
    index += 1
    while not _is(tokens[index], "}"):
        key = tokens[index]
        if key.kind in ("ident", "str") and _is(tokens[index + 1], ":"):
            result[key.value], index = parse_value(tokens, index + 2, src)
        elif key.kind == "ident" and _is(tokens[index + 1], "("):
            end = _skip_balanced(tokens, _skip_balanced(tokens, index + 1))
            result[key.value] = Other(src[key.pos : tokens[end - 1].pos + 1])
            index = end
        else:
            end = index
            while not (tokens[end].kind == "punct" and tokens[end].value in ",}"):
                if tokens[end].kind == "punct" and tokens[end].value in "([{":
                    end = _skip_balanced(tokens, end)
                else:
                    end += 1
            result[str(key.value)] = Other(src[key.pos : tokens[end].pos])
            index = end
        if _is(tokens[index], ","):
            index += 1
    return result, index + 1


# ---------------------------------------------------------------------------------------------
# JavaScript regex to Python regex
# ---------------------------------------------------------------------------------------------

_JS_LETTER_ESCAPES = set("bBdDsSwWfnrtvcxuk")


def js_regex_to_python(source: str) -> str:
    """Translate a JavaScript regex source (no ``u``/``v`` flag) to Python ``re`` syntax.

    ``\\/`` becomes ``/``; identity escapes of letters lose the backslash; a ``[`` inside a class
    and doubled set operators are escaped; ``[^]`` and ``[]`` are rewritten; ``(?<name>`` becomes
    ``(?P<name>``; ``{,n}`` and ``{,}`` become literals. ``\\c``, ``\\u{...}`` and ``\\k`` are
    refused.
    """
    out: list[str] = []
    pos = 0
    length = len(source)
    in_class = False
    class_start = False
    while pos < length:
        char = source[pos]
        if char == "\\":
            following = source[pos + 1]
            if following == "/":
                out.append("/")
            elif following in "ck" or (following == "u" and source[pos + 2 : pos + 3] == "{"):
                raise ValueError(f"unsupported escape \\{following} in {source!r}")
            elif following.isalpha() and following not in _JS_LETTER_ESCAPES:
                out.append(following)
            else:
                out.append(source[pos : pos + 2])
            pos += 2
            class_start = False
            continue
        if in_class:
            if char == "]" and not class_start:
                in_class = False
                out.append(char)
            elif char == "[":
                out.append("\\[")
            elif char in "&|~-" and source[pos + 1 : pos + 2] == char:
                out.append(char + "\\" + char)
                pos += 1
            else:
                out.append(char)
            class_start = False
            pos += 1
            continue
        if source.startswith("[^]", pos):
            out.append("[\\s\\S]")
            pos += 3
        elif source.startswith("[]", pos):
            out.append("(?!)")
            pos += 2
        elif char == "[":
            in_class = True
            class_start = True
            out.append(char)
            pos += 1
            if source[pos : pos + 1] == "^":
                out.append("^")
                pos += 1
        elif source.startswith("(?<", pos) and source[pos + 3 : pos + 4] not in ("=", "!"):
            out.append("(?P<")
            pos += 3
        elif char == "{" and re.match(r"\{,\d*\}", source[pos:]):
            out.append("\\{")
            pos += 1
        else:
            out.append(char)
            pos += 1
    return "".join(out)


# ---------------------------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------------------------


@dataclass
class Extracted:
    file: str
    slug: str
    description: str
    noise_tier: str
    file_patterns: list[str]
    tech: list[str]
    sentinel_files: list[str]
    has_sentinel_contains: bool
    examples: list[str]
    patterns: list[dict[str, Any]] = field(default_factory=list)
    path_skips: list[tuple[str, str]] = field(default_factory=list)


_PATH_SKIP = re.compile(r"if \(/(.+?)/([a-z]*)\.test\(filePath\)\) return \[\];")


def extract(path: Path) -> Extracted:
    src = path.read_text(encoding="utf-8")
    tokens = tokenize(src)
    consts = _constants(tokens, src)
    plugin: dict[str, Any] | None = None
    for index in range(len(tokens) - 2):
        token = tokens[index]
        if token.kind == "ident" and token.value == "MatcherPlugin" and _is(tokens[index + 1], "="):
            plugin, _ = parse_value(tokens, index + 2, src)
            break
    if not isinstance(plugin, dict):
        raise ValueError(f"{path.name}: no MatcherPlugin object literal")
    requires = plugin.get("requires") or {}
    extracted = Extracted(
        file=path.name,
        slug=_text(plugin["slug"], path, "slug"),
        description=_text(plugin["description"], path, "description"),
        noise_tier=_text(plugin["noiseTier"], path, "noiseTier"),
        file_patterns=_texts(plugin["filePatterns"], path, "filePatterns"),
        tech=_texts(requires.get("tech", []), path, "requires.tech"),
        sentinel_files=_texts(requires.get("sentinelFiles", []), path, "requires.sentinelFiles"),
        has_sentinel_contains="sentinelContains" in requires,
        examples=_texts(plugin.get("examples", []), path, "examples"),
    )
    extracted.patterns = _regex_label_objects(tokens, src, consts)
    extracted.path_skips = [(m.group(1), m.group(2)) for m in _PATH_SKIP.finditer(src)]
    return extracted


def _text(value: Any, path: Path, where: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{path.name}: {where} is not a string literal")
    return value


def _texts(value: Any, path: Path, where: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{path.name}: {where} is not a list of string literals")
    return list(value)


def _constants(tokens: list[Tok], src: str) -> dict[str, Any]:
    consts: dict[str, Any] = {}
    for index in range(len(tokens) - 3):
        token = tokens[index]
        if token.kind != "ident" or token.value not in ("const", "let"):
            continue
        if tokens[index + 1].kind != "ident":
            continue
        pos = index + 2
        if _is(tokens[pos], ":"):
            while not (_is(tokens[pos], "=") or _is(tokens[pos], ";")):
                if tokens[pos].kind == "punct" and tokens[pos].value in "([{":
                    pos = _skip_balanced(tokens, pos)
                else:
                    pos += 1
        if _is(tokens[pos], "="):
            try:
                consts[tokens[index + 1].value], _ = parse_value(tokens, pos + 1, src)
            except (IndexError, KeyError, ValueError):
                continue
    return consts


def _resolve_regex(value: Any, consts: dict[str, Any]) -> tuple[str, str] | None:
    """Return ``(python_source, flags)`` for a regex literal or a resolvable ``new RegExp``."""
    if isinstance(value, tuple) and value and value[0] == "re":
        return js_regex_to_python(value[1]), value[2]
    if isinstance(value, tuple) and value and value[0] == "newregexp":
        args = value[1]
        source = _resolve_string(args[0], consts)
        flags = args[1] if len(args) > 1 and isinstance(args[1], str) else ""
        if source is None:
            return None
        return js_regex_to_python(source), flags
    return None


def _resolve_string(value: Any, consts: dict[str, Any]) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, tuple) and value and value[0] == "tpl":
        pieces = []
        for kind, text in value[1]:
            if kind == "str":
                pieces.append(text)
                continue
            name = text.strip()
            if name.endswith(".source"):
                target = consts.get(name[: -len(".source")])
                if not (isinstance(target, tuple) and target and target[0] == "re"):
                    return None
                pieces.append(target[1])
                continue
            target = consts.get(name)
            resolved = _resolve_string(target, consts) if target is not None else None
            if resolved is None:
                return None
            pieces.append(resolved)
        return "".join(pieces)
    return None


def _regex_label_objects(tokens: list[Tok], src: str, consts: dict[str, Any]) -> list[dict]:
    """Every ``{ regex: ..., label: "..." }`` object in source order, translated to Python."""
    found = []
    for index in range(len(tokens) - 2):
        token = tokens[index]
        if not (token.kind == "ident" and token.value == "regex" and _is(tokens[index + 1], ":")):
            continue
        start = index - 1
        depth = 0
        while start >= 0:
            current = tokens[start]
            if current.kind == "punct" and current.value in ")]}":
                depth += 1
            elif current.kind == "punct" and current.value in "([{":
                if depth == 0:
                    break
                depth -= 1
            start -= 1
        obj, _ = parse_value(tokens, start, src)
        if not isinstance(obj, dict) or isinstance(obj.get("regex"), Ref):
            continue  # a TypeScript type annotation such as { regex: RegExp; label: string }
        label = obj.get("label")
        resolved = _resolve_regex(obj.get("regex"), consts)
        if resolved is None or not isinstance(label, str):
            raise ValueError(f"cannot resolve regex/label object near offset {token.pos}")
        found.append({"regex": resolved[0], "flags": resolved[1], "label": label})
    return found


# ---------------------------------------------------------------------------------------------
# Mapping tables
# ---------------------------------------------------------------------------------------------

TEST_SPEC = "**/*.{test,spec}.*"
TEST_SPEC_JS = "**/*.{test,spec}.{ts,tsx,js,jsx,mjs,cjs}"
NODE_MODULES = "**/node_modules/**"
NEXT_DIST = ["**/node_modules/**", "**/.next/**", "**/dist/**"]
DTS = "**/*.d.ts"
GO_TEST = "**/*_test.go"
TEST_WORD = [
    "**/{test,tests,Test,Tests}/**",
    "**/{test,tests,Test,Tests}.*",
    "**/*{.,-}{test,tests,Test,Tests}.*",
    "**/{test,tests}-*/**",
    "**/*-{test,tests}/**",
]

#: deepsec path-skip regexes (``if (/re/.test(filePath)) return [];``) as exclude globs.
#: Approximations: case-insensitive regexes list the common spellings; ``/dir/`` regexes
#: also exclude a folder at the root, which the upstream regex (relative paths) missed.
PATH_SKIP_GLOBS: dict[tuple[str, str], list[str]] = {
    (r"\.(test|spec)\.", "i"): [TEST_SPEC],
    (r"node_modules", ""): [NODE_MODULES],
    (r"\.d\.ts$", ""): [DTS],
    (r"\.(test|spec)\.(ts|tsx|js|jsx|mjs|cjs)$", ""): [TEST_SPEC_JS],
    (r"_test\.go$", ""): [GO_TEST],
    (r"\b(?:tests?|migrations)\b", "i"): [
        *TEST_WORD,
        "**/{migrations,Migrations}/**",
        "**/migrations.*",
    ],
    (r"\/(tests|examples)\/", ""): ["**/{tests,examples}/**"],
    (r"\.(test|spec|mock|stub)\.", "i"): ["**/*.{test,spec,mock,stub}.*"],
    (r"node_modules|\.next|dist\/", ""): NEXT_DIST,
    (r"\/(test|tests)\/", ""): ["**/{test,tests}/**"],
    (r"\/(tests|vendor)\/", ""): ["**/{tests,vendor}/**"],
    (r"_test\.lua$|_spec\.lua$", ""): ["**/*_{test,spec}.lua"],
    (r"\b(?:test|spec)\b", "i"): [
        "**/{test,spec,Test,Spec}/**",
        "**/{test,spec,Test,Spec}.*",
        "**/*{.,-}{test,spec,Test,Spec}.*",
        "**/{test,spec}-*/**",
        "**/*-{test,spec}/**",
    ],
    (r"\/(Tests|UnitTests|IntegrationTests)\/", ""): ["**/{Tests,UnitTests,IntegrationTests}/**"],
    (r"(?:^|\/)gen\/", ""): ["**/gen/**"],
    (r"content\/|docs\/|\.mdx?$", "i"): ["**/{content,docs,Content,Docs}/**", "**/*.{md,mdx}"],
    (r"_test\.|_spec\.|\.test\.|\.spec\.", ""): ["**/*{_,.}{test,spec}.*"],
    (r"\/(test|spec)\/", ""): ["**/{test,spec}/**"],
    (r"(?:^|\/)(?:node_modules|vendor|charts|\.github)\/", ""): [
        "**/{node_modules,vendor,charts,.github}/**"
    ],
    (r"scripts\/(?:build|generate-(?:go|ts)|test|publish[-_])", ""): [
        "**/scripts/{build,generate-go,generate-ts,test,publish-,publish_}*",
        "**/scripts/{build,generate-go,generate-ts,test,publish-,publish_}*/**",
    ],
    (r"node_modules|\.next|dist\/|\.d\.ts$", ""): [*NEXT_DIST, DTS],
    (r"__(tests|mocks|fixtures)__", "i"): ["**/__{tests,mocks,fixtures}__/**"],
    (r"\b(?:tests?|test)\b", "i"): TEST_WORD,
    (r"\b(?:tests?)\b", "i"): TEST_WORD,
    (r"\/procedures\/publicProcedure\.|\/publicViewer\/", ""): [
        "**/procedures/publicProcedure.*",
        "**/publicViewer/**",
    ],
    (r"\/build\/", ""): ["**/build/**"],
    (r"\/(test|tests)\/", "i"): ["**/{test,tests,Test,Tests,TEST,TESTS}/**"],
    (r"\/(tests|vendor|wp-includes|wp-admin)\/", ""): ["**/{tests,vendor,wp-includes,wp-admin}/**"],
    (r"\/(tests|vendor|dev\/tests)\/", ""): ["**/{tests,vendor}/**"],
    (r"\/(tests|vendor|core\/tests)\/", ""): ["**/{tests,vendor}/**"],
    (r"\/(spec|test)\/", ""): ["**/{spec,test}/**"],
    (r"\/(Tests|tests|build)\/", "i"): ["**/{Tests,tests,TESTS,build,Build,BUILD}/**"],
    (r"\/(Tests|tests)\/", ""): ["**/{Tests,tests}/**"],
    (r"\.terraform\/", ""): ["**/.terraform/**"],
    (r"\.client\.(ts|tsx|js|mjs)$", ""): ["**/*.client.{ts,tsx,js,mjs}"],
    (r"\.(test|spec|fixture|mock)\.", "i"): ["**/*.{test,spec,fixture,mock}.*"],
    (r"\.(test|spec)\.(ts|tsx)$", ""): ["**/*.{test,spec}.{ts,tsx}"],
    (r"(?:^|\/)__tests__\/", ""): ["**/__tests__/**"],
    (r"(?:^|\/)__(?:tests|mocks)__\/", ""): ["**/__{tests,mocks}__/**"],
}

NODE_PKG = ["**/package.json"]
PY_MANIFESTS = [
    "**/requirements*.txt",
    "**/pyproject.toml",
    "**/Pipfile",
    "**/setup.py",
    "**/setup.cfg",
]
GO_MOD = ["**/go.mod"]
CARGO = ["**/Cargo.toml"]
GEMFILES = ["**/Gemfile", "**/Gemfile.lock", "**/*.gemspec"]
COMPOSER = ["**/composer.json"]
JVM_BUILD = ["**/pom.xml", "**/build.gradle", "**/build.gradle.kts"]


@dataclass(frozen=True)
class Gate:
    tech: tuple[str, ...] = ()
    files: tuple[str, ...] = ()
    contains: tuple[str, ...] = ()
    how: str = ""


def _direct(tag: str) -> Gate:
    return Gate((tag,), how=f"the tech tag {tag}")


def _framework(language: str, tag: str, files: list[str], regex: str) -> Gate:
    return Gate(
        (language, tag),
        tuple(files),
        (regex,),
        how=f"tech {language} (or {tag}) and a manifest that names {tag}",
    )


def _presence(files: list[str], regex: str | None = None, what: str = "") -> Gate:
    return Gate((), tuple(files), (regex,) if regex else (), how=what)


#: deepsec ``detectTech`` tags mapped to kalkan gates. kalkan detects the tags of ENGINE-SPEC
#: section 10 (node, next, express, react, nestjs, fastify, koa, hono, python, django, flask,
#: fastapi, go, java, spring, ruby, rails, php, laravel, symfony, dotnet, rust, docker,
#: terraform, github-actions, ...). Framework tags that kalkan does not detect become the
#: language tag plus a manifest sentinel. Tags without a kalkan language become a sentinel.
TECH_GATES: dict[str, Gate] = {
    "nextjs": Gate(("next", "nextjs"), how="the tech tag next (or nextjs)"),
    "express": _direct("express"),
    "koa": _direct("koa"),
    "hono": _direct("hono"),
    "fastify": _direct("fastify"),
    "nestjs": _direct("nestjs"),
    "react": _direct("react"),
    "python": _direct("python"),
    "django": _direct("django"),
    "flask": _direct("flask"),
    "fastapi": _direct("fastapi"),
    "go": _direct("go"),
    "spring": _direct("spring"),
    "ruby": _direct("ruby"),
    "rails": _direct("rails"),
    "php": _direct("php"),
    "laravel": _direct("laravel"),
    "symfony": _direct("symfony"),
    "dotnet": _direct("dotnet"),
    "rust": _direct("rust"),
    "docker": _direct("docker"),
    "terraform": _direct("terraform"),
    "github-actions": _direct("github-actions"),
    "jvm": Gate(("java", "jvm"), how="the tech tag java (or jvm)"),
    "drizzle": _framework("node", "drizzle", NODE_PKG, r'"drizzle-orm"'),
    "prisma": _framework("node", "prisma", NODE_PKG, r'"(?:@prisma/client|prisma)"'),
    "trpc": _framework("node", "trpc", NODE_PKG, r'"@trpc/server"'),
    "graphql": _framework(
        "node",
        "graphql",
        NODE_PKG,
        r'"(?:graphql|@apollo/server|apollo-server[\w-]*|graphql-yoga|type-graphql|mercurius'
        r'|@nestjs/graphql)"',
    ),
    "socketio": _framework("node", "socketio", NODE_PKG, r'"socket\.io"'),
    "bullmq": _framework("node", "bullmq", NODE_PKG, r'"bullmq"'),
    "mcp": _framework("node", "mcp", NODE_PKG, r'"@modelcontextprotocol/sdk"'),
    "remix": _framework("node", "remix", NODE_PKG, r'"@remix-run/[\w-]+"'),
    "sveltekit": _framework("node", "sveltekit", NODE_PKG, r'"@sveltejs/kit"'),
    "nuxt": _framework("node", "nuxt", NODE_PKG, r'"nuxt[\w-]*"'),
    "astro": _framework("node", "astro", NODE_PKG, r'"astro"'),
    "solidstart": _framework("node", "solidstart", NODE_PKG, r'"(?:@solidjs/start|solid-start)"'),
    "hapi": _framework("node", "hapi", NODE_PKG, r'"(?:@hapi/hapi|hapi)"'),
    "starlette": _framework("python", "starlette", PY_MANIFESTS, r"(?i:\bstarlette\b)"),
    "aiohttp": _framework("python", "aiohttp", PY_MANIFESTS, r"(?i:\baiohttp\b)"),
    "tornado": _framework("python", "tornado", PY_MANIFESTS, r"(?i:\btornado\b)"),
    "sanic": _framework("python", "sanic", PY_MANIFESTS, r"(?i:\bsanic\b)"),
    "bottle": _framework("python", "bottle", PY_MANIFESTS, r"(?i:\bbottle\b)"),
    "falcon": _framework("python", "falcon", PY_MANIFESTS, r"(?i:\bfalcon\b)"),
    "celery": _framework("python", "celery", PY_MANIFESTS, r"(?i:\bcelery\b)"),
    "airflow": _framework("python", "airflow", PY_MANIFESTS, r"(?i:\bairflow\b)"),
    "sinatra": _framework("ruby", "sinatra", GEMFILES, r"\bsinatra\b"),
    "grape": _framework("ruby", "grape", GEMFILES, r"\bgrape\b"),
    "hanami": _framework("ruby", "hanami", GEMFILES, r"\bhanami\b"),
    "roda": _framework("ruby", "roda", GEMFILES, r"\broda\b"),
    "gin": _framework("go", "gin", GO_MOD, r"github\.com/gin-gonic/gin"),
    "echo": _framework("go", "echo", GO_MOD, r"github\.com/labstack/echo"),
    "fiber": _framework("go", "fiber", GO_MOD, r"github\.com/gofiber/fiber"),
    "chi": _framework("go", "chi", GO_MOD, r"github\.com/go-chi/chi"),
    "gorilla": _framework("go", "gorilla", GO_MOD, r"github\.com/gorilla/mux"),
    "buffalo": _framework("go", "buffalo", GO_MOD, r"github\.com/gobuffalo/buffalo"),
    "cobra": _framework("go", "cobra", GO_MOD, r"github\.com/spf13/cobra"),
    "connectrpc": _framework(
        "go", "connectrpc", GO_MOD, r"connectrpc\.com/connect|github\.com/bufbuild/connect-go"
    ),
    "actix": _framework("rust", "actix", CARGO, r"\bactix-web\b"),
    "axum": _framework("rust", "axum", CARGO, r"\baxum\b"),
    "rocket": _framework("rust", "rocket", CARGO, r"\brocket\b"),
    "warp": _framework("rust", "warp", CARGO, r"\bwarp\b"),
    "tide": _framework("rust", "tide", CARGO, r"\btide\b"),
    "poem": _framework("rust", "poem", CARGO, r"\bpoem\b"),
    "tonic": _framework("rust", "tonic", CARGO, r"\btonic\b"),
    "lambda-rs": _framework("rust", "lambda-rs", CARGO, r"\blambda_(?:runtime|http)\b"),
    "ktor": _framework("java", "ktor", JVM_BUILD, r"io\.ktor|ktor-server"),
    "micronaut": _framework("java", "micronaut", JVM_BUILD, r"(?i:micronaut)"),
    "jaxrs": _framework(
        "java", "jaxrs", JVM_BUILD, r"(?i:javax\.ws\.rs|jakarta\.ws\.rs|jersey|resteasy|quarkus)"
    ),
    "slim": _framework("php", "slim", COMPOSER, r'"slim/slim"'),
    "yii": _framework("php", "yii", COMPOSER, r'"yiisoft/yii2?"'),
    "cakephp": _framework("php", "cakephp", COMPOSER, r'"cakephp/cakephp"'),
    "codeigniter": _framework(
        "php", "codeigniter", COMPOSER, r'"codeigniter4?/(?:framework|appstarter)"'
    ),
    "drupal": Gate(
        ("php", "drupal"),
        ("**/composer.json", "**/*.info.yml", "**/*.routing.yml", "**/*.module"),
        (r"(?i:drupal)|core_version_requirement",),
        how="tech php (or drupal) and a Drupal manifest, routing or module file",
    ),
    "magento": Gate(
        ("php", "magento"),
        ("**/composer.json", "**/registration.php", "**/etc/module.xml"),
        (r"(?i:magento)",),
        how="tech php (or magento) and a Magento composer.json, registration.php or module.xml",
    ),
    "wordpress": Gate(
        ("php", "wordpress"),
        ("**/*.php", "**/style.css", "**/composer.json", "**/readme.txt"),
        (r"(?i:wordpress|wp-content|Plugin Name:|Theme Name:)",),
        how="tech php (or wordpress) and a plugin/theme header or a WordPress reference",
    ),
    "phoenix": _presence(["**/mix.exs"], r":phoenix\b", "a mix.exs that depends on :phoenix"),
    "kemal": _presence(["**/shard.yml"], r"\bkemal\b", "a shard.yml that names kemal"),
    "clojure": _presence(
        ["**/project.clj", "**/deps.edn", "**/build.boot", "**/shadow-cljs.edn"],
        what="a Clojure build file",
    ),
    "erlang": _presence(
        ["**/rebar.config", "**/*.app.src", "**/erlang.mk"], what="an Erlang build file"
    ),
    "vapor": _presence(["**/Package.swift"], r"(?i:vapor)", "a Package.swift that names vapor"),
    "dart": _presence(["**/pubspec.yaml"], what="a pubspec.yaml"),
    "ios": _presence(
        [
            "**/Info.plist",
            "**/*.xcodeproj/project.pbxproj",
            "**/Podfile",
            "**/*.entitlements",
        ],
        what="an iOS project file",
    ),
    "android": _presence(["**/AndroidManifest.xml"], what="an AndroidManifest.xml"),
    "apex": _presence(
        ["**/sfdx-project.json", "**/*.cls-meta.xml", "**/*.trigger-meta.xml"],
        what="a Salesforce DX project or Apex metadata file",
    ),
    "bun": _presence(
        ["**/bun.lockb", "**/bun.lock", "**/bunfig.toml"], what="a Bun lockfile or bunfig.toml"
    ),
    "deno": _presence(
        ["**/deno.json", "**/deno.jsonc", "**/deno.lock"], what="a Deno config or lockfile"
    ),
    "workers": _presence(
        ["**/wrangler.toml", "**/wrangler.json", "**/wrangler.jsonc"],
        what="a Cloudflare wrangler config",
    ),
    "gcp-cloud-functions": _presence(
        [*NODE_PKG, "**/requirements*.txt", "**/pyproject.toml", "**/go.mod"],
        r"functions-framework",
        "a manifest that depends on the Functions Framework",
    ),
    "azure-functions": _presence(["**/host.json"], what="an Azure Functions host.json"),
    "aws-lambda": _presence(
        [
            *NODE_PKG,
            "**/requirements*.txt",
            "**/pyproject.toml",
            *JVM_BUILD,
            "**/serverless.{yml,yaml}",
            "**/template.{yaml,yml}",
            "**/*.tf",
        ],
        r"(?i:aws-lambda|aws_lambda|AWS::Serverless|AWS::Lambda|lambda-powertools|aws-cdk"
        r"|\bfunctions\s*:)",
        "a manifest or IaC file that references AWS Lambda",
    ),
}


# ---------------------------------------------------------------------------------------------
# Curation helpers
# ---------------------------------------------------------------------------------------------


def P(  # noqa: N802 - short constructor names keep the curation table readable
    regex: str,
    label: str,
    flags: str = "",
    near: Iterable[dict] = (),
    not_near: Iterable[dict] = (),
    paths: Iterable[str] = (),
) -> dict[str, Any]:
    """A pattern."""
    pattern: dict[str, Any] = {"regex": regex, "flags": flags, "label": label}
    if near:
        pattern["near"] = list(near)
    if not_near:
        pattern["not_near"] = list(not_near)
    if paths:
        pattern["paths"] = list(paths)
    return pattern


def W(regex: str, before: int = 0, after: int = 0, flags: str = "") -> dict[str, Any]:  # noqa: N802
    """A condition on the lines ``[hit - before, hit + after]``."""
    condition: dict[str, Any] = {"regex": regex}
    if flags:
        condition["flags"] = flags
    if before:
        condition["before"] = before
    if after:
        condition["after"] = after
    return condition


def F(regex: str, flags: str = "") -> dict[str, Any]:  # noqa: N802
    """A condition on the whole file."""
    condition: dict[str, Any] = {"regex": regex, "scope": "file"}
    if flags:
        condition["flags"] = flags
    return condition


# Shared regexes of several Next.js matchers.
HTTP_HANDLER = (
    r"export\s+(async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)"
    r"|export\s+(const\s+)?(GET|POST|PUT|PATCH|DELETE)\s*="
)
USE_SERVER = r"""['"]use server['"]"""
FILE_USE_SERVER = r"""^['"]use server['"]"""
SURFACE = "surface: enumerates entry points for review; no vulnerability class."

#: Per-slug curation. Keys: class, cwe, surface, file_patterns, exclude, exclude_add, requires,
#: file_contains, file_excludes, patterns (full replacement), near_all, not_near_all,
#: label_format, replace (index -> pattern), drop (index -> reason), append, notes.
CURATION: dict[str, dict[str, Any]] = {}


def curate(slug: str, cls: str | None, cwe: list[str], **options: Any) -> None:
    if slug in CURATION:
        raise ValueError(f"duplicate curation entry {slug}")
    CURATION[slug] = {"class": cls, "cwe": cwe, **options}


def surface(slug: str, **options: Any) -> None:
    curate(slug, None, [], surface=True, **options)


# --- Surface enumerators (framework entry points) ---------------------------------------------
for _slug in (
    "apex-rest-resource",
    "azure-function-handler",
    "clj-ring-handler",
    "cr-kemal-route",
    "dart-shelf-handler",
    "dotnet-aspnet-controller",
    "dotnet-minimal-api",
    "dotnet-razor-pages",
    "erl-cowboy-handler",
    "ex-phoenix-controller",
    "gcp-cloud-function",
    "go-buffalo-route",
    "go-chi-route",
    "go-cobra-command",
    "go-echo-route",
    "go-fiber-route",
    "go-gin-route",
    "go-gorilla-route",
    "go-http-handler",
    "js-astro-endpoint",
    "js-bullmq-processor",
    "js-bun-serve",
    "js-deno-route",
    "js-express-route",
    "js-fastify-route",
    "js-graphql-resolver",
    "js-hapi-route",
    "js-hono-route",
    "js-koa-route",
    "js-nestjs-controller",
    "js-nuxt-route",
    "js-remix-route",
    "js-socketio-handler",
    "js-solidstart-action",
    "js-sveltekit-route",
    "js-workers-fetch",
    "jvm-jaxrs-resource",
    "jvm-ktor-route",
    "jvm-micronaut-controller",
    "jvm-spring-controller",
    "php-cakephp-controller",
    "php-codeigniter-controller",
    "php-drupal-controller",
    "php-laravel-route",
    "php-magento-controller",
    "php-slim-route",
    "php-symfony-controller",
    "php-wordpress-rest",
    "php-yii-controller",
    "py-aiohttp-route",
    "py-bottle-route",
    "py-celery-task",
    "py-falcon-resource",
    "py-fastapi-route",
    "py-flask-route",
    "py-sanic-route",
    "py-starlette-route",
    "py-tornado-handler",
    "rb-grape-endpoint",
    "rb-hanami-action",
    "rb-rails-controller",
    "rb-roda-route",
    "rb-sinatra-route",
    "rs-actix-route",
    "rs-axum-route",
    "rs-lambda-runtime",
    "rs-poem-route",
    "rs-rocket-route",
    "rs-tide-route",
    "rs-tonic-grpc",
    "rs-warp-filter",
    "service-entry-point",
    "swift-vapor-route",
    "tf-iac-surface",
):
    surface(_slug)

surface(
    "dotnet-azure-function",
    requires={"tech": ["dotnet", "azure-functions"]},
    notes="deepsec gates on azure-functions or dotnet; kalkan gates on dotnet (C# sources).",
)
surface(
    "py-airflow-dag",
    replace={3: P(r"\{\{[^}]{1,500}\}\}", "Jinja template — review for injection")},
    notes=r"'\{\{\s*[^}]+\s*\}\}' becomes '\{\{[^}]{1,500}\}\}': \s is part of [^}], and "
    "the bound stops quadratic backtracking on a crafted long line.",
)
surface(
    "py-django-view",
    requires={"tech": ["django", "djangorestframework"]},
)
surface(
    "lambda-aws-handler",
)
surface(
    "process-env-access",
    notes="Inventory of process.env reads. The deepsec label names the variable; the port uses "
    "one fixed label.",
    patterns=[
        P(r"""process\.env\.(\w+)|process\.env\[['"](\w+)['"]\]""", "process.env access"),
    ],
)
surface(
    "connectrpc-handler-impl",
    patterns=[
        P(
            r"^\s*func\s*\([^)]+\)\s+[A-Z]\w*\s*\(",
            "ConnectRPC handler method body",
            near=[
                W(r"\bcontext\.Context\b", after=7),
                W(r"\bconnect\.(?:Request|ClientStream|BidiStream|ServerStream)\b", after=7),
            ],
        ),
    ],
)
surface(
    "proto-rpc-surface",
    requires={
        "tech": [],
        "sentinel_files": [
            "**/go.mod",
            "**/package.json",
            "**/requirements*.txt",
            "**/pyproject.toml",
            "**/Cargo.toml",
            "**/pom.xml",
            "**/build.gradle",
            "**/build.gradle.kts",
            "**/*.csproj",
            "**/buf.gen.yaml",
        ],
        "sentinel_contains": [r"(?i:grpc|connectrpc|bufbuild|\btonic\b)"],
    },
    append=[
        P(
            r"^\s*(?:message|enum)\s+\w+",
            "proto message/enum (no service block)",
            not_near=[
                F(
                    r"^\s*service\s+\w+\s*\{|^\s*rpc\s+\w+\s*\("
                    r"|\b(?:source|destination|path|target_path|source_url|url|digest|command"
                    r"|arguments|args|env|environment|mode|owner|group|uid|gid|key_id|kernel_args"
                    r"|rootfs|cmdline)\s*=\s*\d+\s*;"
                )
            ],
        ),
    ],
    notes="deepsec gates on the grpc or connectrpc tag; kalkan reads the manifests for "
    "grpc/connect dependencies. The fallback flags every message/enum line of a proto file "
    "without service, rpc or sensitive-field lines (deepsec flags the first one).",
)
surface(
    "nextjs-middleware",
    file_contains=[
        r"(?i:export\s+(?:default\s+|async\s+)?function\s+middleware"
        r"|export\s+(?:const|let)\s+middleware)|export\s+default",
    ],
    patterns=[
        P(
            r"export\s+(default\s+|async\s+)?function\s+middleware|export\s+(const|let)\s+middleware",
            "Next.js middleware — security-critical request interceptor",
            flags="i",
        ),
        P(
            r"export\s+default\s+(async\s+)?function",
            "Next.js middleware — security-critical request interceptor",
        ),
        P(
            r"export\s+const\s+config",
            "Middleware route matcher config — controls scope of protection",
        ),
    ],
)
surface(
    "all-route-handlers",
    patterns=[
        P(
            r"export\s+(?:const|async\s+function|function)\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b",
            "Route handler — HTTP entry point (weak candidate)",
        ),
        P(
            r"export\s+default\s+(async\s+)?(function\s*)?\(",
            "Default export route handler — HTTP entry point (weak candidate)",
        ),
    ],
    notes="The deepsec label names the HTTP method; the port uses one fixed label.",
)
surface(
    "server-action",
    file_contains=[USE_SERVER],
    patterns=[
        P(
            r"export\s+(async\s+)?function\s+\w+|export\s+(const|let)\s+\w+\s*=\s*(async\s+)?\(",
            "Server Action (inline 'use server') — publicly callable POST endpoint",
            near=[W(USE_SERVER, after=1)],
        ),
        P(
            r"export\s+(async\s+)?function\s+\w+|export\s+(const|let)\s+\w+\s*=\s*(async\s+)?\(",
            "Server Action (file-level 'use server') — publicly callable POST endpoint",
            near=[F(FILE_USE_SERVER)],
        ),
    ],
    notes="A file-level directive is approximated by an unindented 'use server' line anywhere "
    "in the file (deepsec: the first statement of the file).",
)
surface(
    "all-server-actions",
    file_contains=[USE_SERVER],
    patterns=[
        P(
            r"export\s+(async\s+)?function\s+\w+|export\s+(const|let)\s+\w+\s*=\s*(async\s+)?\(",
            "Server Action export — public POST endpoint (weak candidate)",
            near=[F(FILE_USE_SERVER)],
        ),
        P(
            r"export\s+(async\s+)?function\s+\w+|export\s+(const|let)\s+\w+\s*=\s*(async\s+)?\(",
            "Server Action export — public POST endpoint (weak candidate)",
            near=[W(USE_SERVER, after=5)],
        ),
    ],
    notes="A file-level directive is approximated by an unindented 'use server' line anywhere "
    "in the file. The deepsec label names the function; the port uses one fixed label.",
)

# --- AI / agentic ---------------------------------------------------------------------------
curate(
    "agent-loop-no-cap",
    "llm-ai",
    ["CWE-770"],
    file_contains=[
        r"""\bfrom\s+["']ai["']|\bfrom\s+["']@ai-sdk/[^"']*["']"""
        r"""|\bfrom\s+["']@anthropic-ai/claude-agent-sdk["']|\bfrom\s+["']@openai/codex-sdk["']"""
    ],
    patterns=[
        P(
            r"\b(?:streamText|generateText|generateObject|streamObject)\s*\(|\bawait\s+query\s*\("
            r"|\bclaude\.\s*query\s*\(",
            "agent/LLM call without maxSteps/maxTurns/stopWhen/signal",
            not_near=[
                W(
                    r"\bmaxSteps\s*:\s*\d|\bmaxTurns\s*:\s*\d|\bstopWhen\s*:|\bsignal\s*:"
                    r"|\babortSignal\s*:|\btimeout\s*:\s*\d",
                    after=29,
                )
            ],
        ),
    ],
)
curate("agent-tool-definition", "llm-ai", [])
curate(
    "agentic-untrusted-prompt-input",
    "llm-ai",
    ["CWE-1427"],
    file_contains=[
        r"\b(?:streamText|generateText|generateObject|streamObject|messages\s*:\s*\[|anthropic\."
        r"|openai\.|gateway\(|getGatewayModelString|claude_agent|ClaudeAgent|claude-agent"
        r"|@ai-sdk/|ai/sdk)\b"
    ],
    patterns=[
        P(
            r"\$\{[^}]{0,300}\b(?:notes|description|body|content|text|summary|email|emailBody|transcript"
            r"|scraped|fetched|webpage|web_research|attachment|document|kb_?[A-Z]?[a-z]+"
            r"|salesforce[A-Z][a-z]+|sfdc[A-Z][a-z]+|snowflake[A-Z][a-z]+|bigquery[A-Z][a-z]+"
            r"|leadNotes|accountNotes|opportunityNotes|messageHistory|slackHistory|exaResult"
            r"|perplexity[A-Z]?|crawlResult|browserbaseResult|crawled|recon[A-Z][a-z]+)\b",
            "prompt interpolates an untrusted variable",
            near=[
                W(
                    r"""\b(?:system|user|prompt|content|messages|input|instructions)\s*:\s*[`'"[]""",
                    before=29,
                )
            ],
        ),
    ],
    notes="Every interpolation of an untrusted-looking variable within 29 lines after a prompt "
    "key is reported (deepsec reports the first per prompt key and reads only the first "
    "interpolation of a line). The text before the variable inside ${...} is bounded to 300 "
    "characters (quadratic backtracking on long lines). The deepsec label quotes the "
    "interpolated text; the port uses one fixed label.",
)
curate(
    "mcp-tool-handler",
    "llm-ai",
    [],
    file_contains=[
        r"""\bfrom\s+["']@modelcontextprotocol/sdk[^"']*["']|\bMcpServer\b|\bMcpAgent\b"""
    ],
)
curate(
    "prompt-leaks-system-prompt",
    "llm-ai",
    ["CWE-200"],
    file_contains=[
        r"""\b(?:streamText|generateText|generateObject|messages\s*:\s*\[|system\s*:\s*[`"']"""
        r"""|instructions\s*:\s*[`"'])"""
    ],
    patterns=[
        P(
            r"process\.env\.[A-Z_][A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASS|CREDS|CREDENTIAL"
            r"|API_KEY|BYPASS|AUTH)\b",
            "system prompt references a secret env var",
            near=[
                W(
                    r"""\b(?:system|instructions|prompt)\s*:\s*[`"']|\brole\s*:\s*["']system["']""",
                    before=49,
                )
            ],
        ),
        P(
            r"(?:sk-[A-Za-z0-9]{20,}|vck_[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{20,}|xoxb-[A-Za-z0-9-]+"
            r"|xoxp-[A-Za-z0-9-]+|AIza[A-Za-z0-9_-]{30,}|AKIA[0-9A-Z]{16})",
            "system prompt contains hardcoded secret-shaped string",
            near=[
                W(
                    r"""\b(?:system|instructions|prompt)\s*:\s*[`"']|\brole\s*:\s*["']system["']""",
                    before=49,
                )
            ],
        ),
    ],
    notes="Every secret line within 49 lines after a prompt opener is reported (deepsec "
    "reports the first per opener). The deepsec label quotes the variable; the port uses a "
    "fixed label.",
)
curate("streaming-endpoint", "llm-ai", [])
curate(
    "expensive-api-abuse",
    "rate-limit-bruteforce",
    ["CWE-770"],
    file_contains=[
        r"export\s+(async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)\b"
        r"|export\s+(const|let)\s+(GET|POST|PUT|PATCH|DELETE)\s*="
        r"|export\s+default\s+(async\s+)?function|" + USE_SERVER
    ],
    label_format="Expensive API call: {} — check for abuse protection (auth, rate limit, captcha)",
)

# --- Auth / sessions ------------------------------------------------------------------------
curate("auth-bypass", "authn", ["CWE-287"])
curate(
    "missing-auth",
    "authn",
    ["CWE-306"],
    file_excludes=[
        r"withSchema\s*\(",
        r"withAuthentication\s*\(",
        r"authMiddleware",
        r"withAuth\s*\(",
        r"requireAuth",
        r"authTeamOrUserReq",
        r"performOIDCOrTeamOrUserAuth",
    ],
    label_format="HTTP entry point: {} (weak candidate)",
)
curate("public-endpoint", "authn", ["CWE-306"])
curate(
    "cron-secret-check",
    "authn",
    ["CWE-306"],
    file_contains=[
        r"export\s+(async\s+)?function\s+(GET|POST)|export\s+(const\s+)?(GET|POST)",
    ],
    patterns=[
        P(
            r"export\s+(async\s+)?function|export\s+(const\s+)?(GET|POST)",
            "Cron route handler without CRON_SECRET validation",
            not_near=[F(r"CRON_SECRET")],
            paths=["**/*{cron,Cron,CRON}*/**", "**/*{cron,Cron,CRON}*"],
        ),
        P(
            r"CRON_SECRET",
            "CRON_SECRET check (verify not bypassable when env var unset)",
            paths=["**/*{cron,Cron,CRON}*/**", "**/*{cron,Cron,CRON}*"],
        ),
    ],
    notes="Only paths that contain 'cron' get candidates, as upstream. deepsec flags the first "
    "export of a cron route without CRON_SECRET; the port flags every export line.",
)
curate(
    "dev-auth-bypass",
    "authn",
    ["CWE-288"],
    not_near_all=[W(r"^\s*(?://|\*)")],
    notes="Comment lines (// or *) are skipped as upstream.",
)
curate(
    "test-header-bypass",
    "authn",
    ["CWE-288"],
    near_all=[W(r"if\s*\(|skip|bypass|disable|return\s+(true|next)|continue", before=3, after=2)],
    label_format="{} — may bypass security in production",
)
curate(
    "server-action-no-auth",
    "authn",
    ["CWE-306"],
    file_contains=[USE_SERVER],
    patterns=[
        P(
            r"export\s+(async\s+)?function\s+\w+",
            "Server Action WITHOUT any auth call — publicly callable",
            near=[F(FILE_USE_SERVER)],
            not_near=[W("{AUTH_CALLS}", after=29)],
        ),
        P(
            r"export\s+(async\s+)?function\s+\w+",
            "Server Action with auth call (verify correctness)",
            near=[F(FILE_USE_SERVER), W("{AUTH_CALLS}", after=29)],
        ),
        P(
            r"export\s+(async\s+)?function",
            "Server Action WITHOUT any auth call — publicly callable",
            near=[W(USE_SERVER, after=1)],
            not_near=[W("{AUTH_CALLS}", after=29)],
        ),
        P(
            r"export\s+(async\s+)?function",
            "Server Action with auth call (verify correctness)",
            near=[W(USE_SERVER, after=1), W("{AUTH_CALLS}", after=29)],
        ),
    ],
    notes="A file-level directive is approximated by an unindented 'use server' line anywhere "
    "in the file (deepsec: the first statement of the file).",
)
curate(
    "trpc-public-procedure",
    "authn",
    ["CWE-306"],
    file_contains=[r"\bpublicProcedure\b"],
    patterns=[
        P(
            r"\bpublicProcedure\s*\.\s*(?:input|query|mutation|use)\b",
            "publicProcedure handler reads ctx.session/user — verify it should not be "
            "authedProcedure",
            near=[
                W(
                    r"\bctx\.(?:session|user|userId|currentUser|prisma)|getSession\s*\(\s*ctx",
                    before=2,
                    after=11,
                )
            ],
        ),
        P(
            r"\bpublicProcedure\s*\.\s*(?:input|query|mutation|use)\b",
            "publicProcedure used in router that looks authenticated — verify intent",
            paths=[
                "**/{viewer,admin,organization,organizations,team,teams,settings,billing}/**",
                "**/{payment,payments,workflow,workflows}/**",
            ],
        ),
    ],
)
curate(
    "nextjs-middleware-only-auth",
    "missing-authz",
    ["CWE-862"],
    file_patterns=[
        "**/app/**/(protected)/**/route.{ts,tsx}",
        "**/app/**/(dashboard)/**/route.{ts,tsx}",
        "**/app/**/(auth)/**/route.{ts,tsx}",
        "**/app/api/**/route.{ts,tsx}",
    ],
    file_contains=[HTTP_HANDLER],
    file_excludes=[
        r"withSchema\s*\(",
        r"withAuthentication\s*\(",
        r"getSession\s*\(",
        r"auth\s*\(\s*\)",
        r"requireAuth",
        r"verifyToken",
        r"authMiddleware",
        r"withAuth\s*\(",
    ],
    patterns=[
        P(
            HTTP_HANDLER,
            "Route handler without backend auth check — relies on Next.js middleware",
        ),
    ],
    notes="deepsec globs '**/app/**(protected)**/route.*' are minimatch extended globs that "
    "match any single folder; the port matches the route groups (protected), (dashboard) and "
    "(auth). deepsec words the label by route group and flags the first handler; the port "
    "uses one label and flags every handler line.",
)
curate(
    "catch-all-route-auth",
    "missing-authz",
    ["CWE-862"],
    file_patterns=[
        "**/[[][[]...rest[]][]]/**/*.{ts,tsx}",
        "**/[[]...slug[]]/**/*.{ts,tsx}",
        "**/[[]...path[]]/**/*.{ts,tsx}",
        "**/(payload)/**/*.{ts,tsx}",
        "**/graphql/route.{ts,tsx}",
        "**/app/api/**/*.{ts,tsx}",
    ],
    patterns=[
        P(
            "{CATCH_HANDLER}",
            "Catch-all route handler — NO auth on catch-all",
            not_near=[F("{CATCH_AUTH}")],
            paths=["**/*[[]...[a-zA-Z]*/**", "**/*[[]...[a-zA-Z]*"],
        ),
        P(
            "{CATCH_HANDLER}",
            "Catch-all route handler (has auth)",
            near=[F("{CATCH_AUTH}")],
            paths=["**/*[[]...[a-zA-Z]*/**", "**/*[[]...[a-zA-Z]*"],
        ),
        P(
            "{CATCH_HANDLER}",
            "Payload/GraphQL endpoint — NO auth",
            near=[F(r"\(payload\)|payload.*graphql|GRAPHQL_POST|GRAPHQL_GET")],
            not_near=[F("{CATCH_AUTH}")],
        ),
        P(
            "{CATCH_HANDLER}",
            "Payload/GraphQL endpoint (has auth)",
            near=[F(r"\(payload\)|payload.*graphql|GRAPHQL_POST|GRAPHQL_GET"), F("{CATCH_AUTH}")],
        ),
        P(
            "{CATCH_HANDLER}",
            "Payload/GraphQL endpoint — NO auth",
            not_near=[F("{CATCH_AUTH}")],
            paths=[
                "**/(payload)/**",
                "**/*{graphql,GraphQL,Graphql,GRAPHQL}*/**",
                "**/*{graphql,GraphQL,Graphql,GRAPHQL}*",
            ],
        ),
        P(
            "{CATCH_HANDLER}",
            "Payload/GraphQL endpoint (has auth)",
            near=[F("{CATCH_AUTH}")],
            paths=[
                "**/(payload)/**",
                "**/*{graphql,GraphQL,Graphql,GRAPHQL}*/**",
                "**/*{graphql,GraphQL,Graphql,GRAPHQL}*",
            ],
        ),
    ],
    notes="deepsec globs such as '**/[[...rest]]/**' are minimatch character classes that never "
    "match the Next.js folder name; the port matches the folders literally with [[] and []]. "
    "The catch-all, Payload and GraphQL conditions (path or content) become pattern variants. "
    "deepsec flags the first handler with one label; the port flags every handler line and "
    "can give a line two labels.",
)
curate(
    "catchall-router",
    "missing-authz",
    ["CWE-862"],
    file_patterns=[
        "**/[[][[]...rest[]][]]/route.{ts,tsx}",
        "**/[[][[]...slug[]][]]/route.{ts,tsx}",
        "**/[[]...rest[]]/route.{ts,tsx}",
        "**/[[]...slug[]]/route.{ts,tsx}",
        "**/[[][[]...catchAll[]][]]/route.{ts,tsx}",
    ],
    append=[
        P(
            r"export\s+(const|async\s+function|function)\s+(GET|POST|PUT|PATCH|DELETE)\b",
            "Catch-all route handler — all sub-paths funneled here",
            not_near=[
                F(
                    r"""from\s+['"]elysia['"]|new\s+Elysia|from\s+['"]hono['"]|new\s+Hono"""
                    r"""|from\s+['"]express['"]|express\(\)|from\s+['"]itty-router['"]|Router\(\)"""
                    r"|createRouter|handleRequest"
                )
            ],
        ),
    ],
    notes="deepsec globs such as '**/[[...rest]]/route.*' are minimatch character classes that "
    "never match the Next.js folder name; the port matches the folders literally with [[] and "
    "[]]. deepsec reports the first line per router type; the port reports every line.",
)
curate(
    "use-server-export",
    "idor",
    ["CWE-639"],
    file_contains=[USE_SERVER],
    patterns=[
        P(
            r"export\s+(async\s+)?function\s+\w+",
            "Server Action exports function accepting identity/auth parameter — client can "
            "supply arbitrary values",
            near=[
                W(
                    r"\b(owner|authenticatedOwner|user|auth|session|identity|actor|caller)\b",
                    after=4,
                    flags="i",
                )
            ],
        ),
    ],
)
curate(
    "framework-internal-header",
    "missing-authz",
    ["CWE-285"],
    patterns=[
        P(
            r"""['"`](x-middleware-subrequest|x-middleware-prefetch|x-middleware-rewrite"""
            r"|x-middleware-redirect|x-middleware-next|x-middleware-cookie"
            r"|x-middleware-set-cookie|x-middleware-override-headers|x-middleware-skip)"
            r"""['"`]""",
            "Next.js internal x-middleware-* header",
            flags="i",
        ),
        P(
            r"""['"`](x-next-prerender-bypass|x-next-revalidated-tags|x-next-cache-tags"""
            r"|x-next-debug-logging|__Next-Action|next-action-id|next-router-state-tree"
            r"""|next-router-prefetch|next-router-segment-prefetch|rsc|next-url)['"`]""",
            "Next.js internal x-next-* / router header",
            flags="i",
        ),
    ],
    notes="The upstream header list is split in two regexes to stay below 500 characters. "
    "The deepsec label names the header; the port uses two fixed labels.",
)
curate(
    "jwt-handling",
    "jwt",
    ["CWE-347"],
    file_contains=[r"(?i:jwt|jose|jsonwebtoken|token|session[\w\s]{0,20}cookie)"],
)
curate(
    "algorithm-confusion",
    "jwt",
    ["CWE-347"],
    file_contains=[r"jwt\.verify|jwtVerify|verifyJwt|jwt_obj:verify|resty\.jwt"],
    patterns=[
        P(
            r"jwt\.verify|jwtVerify|verifyJwt|jwt_obj:verify",
            "JWT verification WITHOUT algorithm pinning — algorithm confusion risk",
            not_near=[W(r"algorithms?\s*:|alg.*(?:RS|HS|ES)256", after=4)],
        ),
        P(
            r"jwt\.verify|jwtVerify|verifyJwt|jwt_obj:verify",
            "JWT verification with algorithm pin (verify correct algorithm)",
            near=[W(r"algorithms?\s*:|alg.*(?:RS|HS|ES)256", after=4)],
        ),
    ],
    notes="The pin check 'algorithms\\s*:|algorithm\\s*:|alg.*RS256|alg.*HS256|alg.*ES256' is "
    "rewritten to the equivalent 'algorithms?\\s*:|alg.*(?:RS|HS|ES)256' (one wildcard).",
)
curate("oauth-flow", "oauth-oidc-saml", ["CWE-287"])
curate(
    "session-cookie-config",
    "security-misconfig",
    ["CWE-1004", "CWE-614"],
    file_contains=[
        r"""(?i:\bfrom\s+["'](?:better-auth|next-auth|@auth/core|iron-session|lucia|@lucia-auth"""
        r"""|@clerk/(?:nextjs|backend))[^"']*["']|\bcookies\(\)\s*\.\s*set\s*\("""
        r"""|\bres\.\s*setHeader\s*\(\s*["']Set-Cookie)"""
    ],
)

# --- Authorization / tenancy ----------------------------------------------------------------
curate("iam-permissions", "missing-authz", ["CWE-863"])
curate("cross-tenant-id", "idor", ["CWE-639"])
curate(
    "unverified-lookup",
    "idor",
    ["CWE-639"],
    patterns=[
        P(
            r"get\w+By(Id|Uid)\s*\(|find(One)?By(Id|Uid)\s*\(|\.findUnique\s*\(|\.findFirst\s*\(",
            "DB lookup by ID without ownership check in next 15 lines",
            not_near=[
                W(r"===?\s*auth\.|auth\.\w+\s*===?", after=14),
                W(r"ownerId\s*===?|===?\s*ownerId", after=14),
                W(r"\.teamId\s*===?|===?\s*\.teamId", after=14),
                W(r"\.userId\s*===?|===?\s*\.userId", after=14),
                W(r"throw.*(?:403|Forbidden|Unauthorized)", after=14),
                W(r"auth\.can\s*\(", after=14),
                W(r"if\s*\(\s*!\s*(installation|project|team|deployment)\.", after=14),
            ],
        ),
    ],
    notes="The lookup regex list is merged into one alternation (getTeamById and similar are "
    "covered by get\\w+By(Id|Uid)); 'throw.*403|throw.*Forbidden|throw.*Unauthorized' becomes "
    "'throw.*(?:403|Forbidden|Unauthorized)'.",
)
curate(
    "page-data-fetch",
    "idor",
    ["CWE-639"],
    file_contains=[
        r"searchParams|params\.\w+",
        r"fetch\(|fetchApi|getServerSideProps|getStaticProps",
    ],
    patterns=[
        P(
            r"searchParams\.get|searchParams\[|params\.\w+",
            "Page reads URL params and fetches data — verify auth scoping",
            near=[W(r"fetch|Api|query", after=9)],
        ),
    ],
    notes="deepsec reports the first line per file; the port reports every line.",
)
curate(
    "page-without-auth-fetch",
    "idor",
    ["CWE-639"],
    file_contains=[r"params\.\w+", r"fetch|fetchApi|getServerSession"],
    patterns=[
        P(
            r"params\.\w+",
            "Page fetches by URL param with auth (verify scoping)",
            near=[W(r"fetch|Api|query", after=7), F("{ACCESS_CHECK}")],
        ),
        P(
            r"params\.\w+",
            "Page fetches by URL param WITHOUT access check — IDOR risk",
            near=[W(r"fetch|Api|query", after=7)],
            not_near=[F("{ACCESS_CHECK}")],
        ),
    ],
    notes="deepsec reports the first line per file; the port reports every line.",
)
curate(
    "cache-key-scope",
    "multi-tenant",
    ["CWE-284"],
    not_near_all=[
        W(
            r"userId|user_id|teamId|team_id|ownerId|owner_id|auth\.|session\.|projectId|project_id",
            before=1,
            after=1,
            flags="i",
        )
    ],
    label_format="{} — no user/team scoping visible in key construction",
)
curate("android-manifest-export", "mobile-desktop-ipc", ["CWE-926"])
curate("ios-url-scheme", "mobile-desktop-ipc", ["CWE-939"])
curate("unix-socket-listener", "mobile-desktop-ipc", ["CWE-732"])

# --- Injection ------------------------------------------------------------------------------
for _slug in (
    "sql-injection",
    "dotnet-sql-raw",
    "go-sql-raw",
    "js-sql-raw",
    "jvm-sql-raw",
    "php-sql-raw",
    "prisma-raw-sql",
    "py-sql-raw",
    "rb-sql-raw",
    "rs-sql-raw",
):
    curate(_slug, "sqli", ["CWE-89"])
curate(
    "drizzle-raw-sql",
    "sqli",
    ["CWE-89"],
    file_contains=[
        r"""\bfrom\s+["'](?:drizzle-orm[^"']*|@repo/db[^"']*|drizzle-zod|drizzle-kit)["']"""
    ],
    patterns=[
        P(r"\bsql\.\s*raw\s*\(", "sql.raw() — bypasses parameterization"),
        P(r"\bsql\.\s*unsafe\s*\(", "sql.unsafe() — bypasses parameterization"),
        P(
            r"\bsql`[^`]*\$\{[^}]*\+[^}]*\}",
            "sql`` interpolates concatenated string — verify parameter binding",
        ),
        P(
            r"\bsql`[^`]*\$\{`[^`]*\$\{",
            "sql`` interpolates concatenated string — verify parameter binding",
        ),
    ],
)
curate(
    "snowflake-bigquery-sql",
    "sqli",
    ["CWE-89"],
    file_contains=[
        r"""\bfrom\s+["'](?:snowflake-sdk|@google-cloud/bigquery|@clickhouse/client"""
        r"""|@clickhouse/client-web|@databricks/sql|duckdb|@duckdb/[^"']*)["']"""
    ],
    patterns=[
        P(r"\bsqlText\s*:\s*`[^`]*\$\{", "Snowflake sqlText with template interpolation"),
        P(
            r"""\bsqlText\s*:\s*["'][^"']*["']\s*\+""",
            "Snowflake sqlText with string concatenation",
        ),
        P(
            r"\bcreateQueryJob\s*\(\s*\{[^}]*query\s*:\s*`[^`]*\$\{",
            "BigQuery createQueryJob with template interpolation",
        ),
        P(
            r"\b(?:bigquery|bq|clickhouse|client|connection)\.\s*query\s*\(\s*\{?\s*"
            r"(?:query\s*:\s*)?`[^`]*\$\{",
            "Analytics .query() with template interpolation",
        ),
        P(
            r"\b(?:connection|conn|client|db)\.\s*execute\s*\(\s*`[^`]*\$\{",
            ".execute() with template interpolation in analytics context",
        ),
    ],
)
curate(
    "soql-injection",
    "sqli",
    ["CWE-89"],
    requires={
        "tech": [],
        "sentinel_files": ["**/package.json", "**/sfdx-project.json"],
        "sentinel_contains": [r"(?i:jsforce|@salesforce/|packageDirectories)"],
    },
    file_contains=[
        r"""\bfrom\s+["'](?:jsforce[^"']*|@jsforce/[^"']*|@salesforce/[^"']*)["']"""
        r"""|\b(?:sf|salesforce|conn|sfConn)\.\s*query(?:All)?\s*\("""
    ],
    patterns=[
        P(
            r"\b(?:sf|salesforce|conn|sfConn|tooling)\.\s*query(?:All|More)?\s*\(\s*`[^`]*\$\{",
            "SOQL via template literal — possible SOQL injection",
        ),
        P(
            r"""\b(?:sf|salesforce|conn|sfConn|tooling)\.\s*query(?:All|More)?\s*\(\s*["'][^"']*"""
            r"""["']\s*\+""",
            "SOQL via string concat — possible SOQL injection",
        ),
        P(
            r"`(?:[^`]*?\bSELECT\s+[^`]*?\bFROM\s+[A-Za-z_][A-Za-z0-9_]*[^`]*?)\$\{",
            "SOQL-shaped template literal with interpolation",
            flags="i",
        ),
    ],
    notes="deepsec gates on the apex or salesforce tag; kalkan reads package.json (jsforce, "
    "@salesforce/*) and sfdx-project.json.",
)
curate("js-nosql-injection", "nosqli", ["CWE-943"])
curate("py-nosql-injection", "nosqli", ["CWE-943"])
curate("rce", "os-command-injection", ["CWE-78", "CWE-94"])
curate("go-command-injection", "os-command-injection", ["CWE-78"])
curate("lua-ngx-exec", "os-command-injection", ["CWE-78"])
curate(
    "sandbox-runtime-script",
    "os-command-injection",
    ["CWE-78"],
    append=[
        P(
            r"^#!",
            "container-runtime script (path-based)",
            not_near=[
                F(r"""\b(?:eval|exec)\s+["'`]?\$|\bbash\s+-c\s+["'`].*\$\{?[A-Z]"""),
                F(
                    r"""\$\{?[A-Z][A-Z0-9_]+\}?[^"'`)]|\b(?:sudo|su\s|chmod|chown)\s|\b0\.0\.0\.0\b"""
                ),
                F(
                    r"\bgit\s+(?:config|credential|push|fetch|clone)\b"
                    r"|\b(?:TARGET|SANDBOX|CONTAINER)_[A-Z0-9_]+\b"
                ),
                F(r"\bcurl\b[^|]*\|[\s]*(?:sh|bash)|\b(?:nohup|&\s*$|disown)\b"),
            ],
        ),
    ],
    notes="The path-based fallback flags the shebang line of a script without a risky line "
    "(deepsec flags the first code line; scripts without a shebang get no fallback).",
)
curate(
    "framework-edge-sandbox",
    "code-injection",
    ["CWE-94"],
    patterns=[
        P(r"\bnew\s+Function\s*\(", "new Function() in edge/sandbox code"),
        P(r"\beval\s*\(", "eval() in edge/sandbox code"),
        P(r"\bcontext\.evaluate\s*\(", "context.evaluate() sandbox execution"),
        P(
            r"\bvm\.(?:Script|runInNewContext|runInContext|createContext)\s*\(",
            "vm module execution",
        ),
        P(r"\b(?:globalThis|self)\.(?:Buffer|process|require|fetch)\s*=", "global shim assignment"),
        P(r"\bedge-?runtime\b", "edge-runtime reference", flags="i"),
        P(r"\bcreateBindings\s*\(|\bbuildSandboxFunction\s*\(", "sandbox bindings setup"),
        P(r"\bBuffer\s*as\s*any\b", "Buffer as any (shim leak)"),
    ],
    notes="deepsec labels with the first 40 characters of the regex; the port uses descriptive "
    "labels. The path-only fallback (flag line 1 of server/web/sandbox files without content "
    "hits) is dropped.",
)
curate(
    "framework-server-action",
    "deserialization",
    ["CWE-502"],
    patterns=[
        P(
            r"\b(?:decodeReply|decodeAction|decodeFormState|encodeReply|parseAction"
            r"|getActionFromManifest|callServer|parseActionId|registerServerReference)\s*\(",
            "Server Action decode/dispatch call",
        ),
        P(r"\b__Next[-_]Action\b", "__Next-Action header"),
        P(r"""['"]next-action(?:-id|-redirect)?['"]""", "next-action header name"),
        P(r"\baction\.id\s*===|actionManifest\b|actions\.json\b", "action manifest lookup"),
    ],
    notes="deepsec labels with the first 40 characters of the regex; the port uses descriptive "
    "labels. The path-only fallback (flag line 1 of action-handler files without content hits) "
    "is dropped. The upstream header regex starts with \\b before a quote, which cannot match "
    "after '(' or a space; the port drops that \\b, so the upstream example "
    "get('next-action-id') matches.",
)
curate("unsafe-deserialization", "deserialization", ["CWE-502"])
curate("object-injection", "prototype-pollution", ["CWE-1321"])
curate("spread-operator-injection", "mass-assignment", ["CWE-915"])
curate(
    "drizzle-mass-assignment",
    "mass-assignment",
    ["CWE-915"],
    file_contains=[r"""\bfrom\s+["'](?:drizzle-orm[^"']*|@repo/db[^"']*)["']"""],
)
curate(
    "zod-passthrough-mass-assignment",
    "mass-assignment",
    ["CWE-915"],
    file_contains=[r"""\bfrom\s+["']zod[^"']*["']|\bz\.\s*object\s*\(""", r"\.\s*passthrough\s*\("],
    patterns=[
        P(
            r"\.\s*passthrough\s*\(",
            ".passthrough() in file with DB insert/update — mass-assignment risk",
            near=[F("{DB_WRITE}")],
        ),
        P(
            r"\.\s*passthrough\s*\(",
            ".passthrough() — verify parsed output trust boundary",
            not_near=[F("{DB_WRITE}")],
        ),
    ],
)

# --- XSS / client -----------------------------------------------------------------------------
curate("xss", "xss", ["CWE-79"])
curate(
    "dangerous-html",
    "xss",
    ["CWE-79"],
    patterns=[
        P(
            r"dangerouslySetInnerHTML|\.innerHTML\s*=",
            "dangerouslySetInnerHTML from URL/request params (HIGH RISK)",
            near=[W(r"searchParams|query|params|req\.", before=3, after=4, flags="i")],
        ),
        P(
            r"dangerouslySetInnerHTML|\.innerHTML\s*=",
            "dangerouslySetInnerHTML from fetched data (MEDIUM RISK)",
            near=[W(r"data\.|response\.|result\.|await|fetch", before=3, after=4, flags="i")],
            not_near=[W(r"searchParams|query|params|req\.", before=3, after=4, flags="i")],
        ),
        P(
            r"dangerouslySetInnerHTML|\.innerHTML\s*=",
            "dangerouslySetInnerHTML from props (trace source)",
            not_near=[
                W(r"searchParams|query|params|req\.", before=3, after=4, flags="i"),
                W(r"data\.|response\.|result\.|await|fetch", before=3, after=4, flags="i"),
            ],
        ),
    ],
    notes="The upstream label chain is kept. Its 'props' test also matches 'html' and thus "
    "every hit line, so the 'static/safe' and 'classify source' labels never occur upstream "
    "and are not ported.",
)
curate(
    "unsafe-json-in-html",
    "xss",
    ["CWE-79"],
    patterns=[
        P(
            r"JSON\.stringify",
            "JSON.stringify into dangerouslySetInnerHTML/script — use safeJsonStringify to "
            "escape </script>",
            near=[W(r"dangerouslySetInnerHTML|<script", before=3, after=2)],
            not_near=[F(r"safeJsonStringify")],
        ),
        P(
            r"JSON\.stringify",
            "JSON.stringify near HTML injection point (safeJsonStringify in scope — verify usage)",
            near=[
                W(r"dangerouslySetInnerHTML|<script", before=3, after=2),
                F(r"safeJsonStringify"),
            ],
        ),
        P(
            r"dangerouslySetInnerHTML",
            "dangerouslySetInnerHTML with JSON.stringify — XSS via </script> in data",
            near=[W(r"JSON\.stringify", before=3, after=2)],
            not_near=[F(r"safeJsonStringify")],
        ),
        P(
            r"dangerouslySetInnerHTML",
            "dangerouslySetInnerHTML with JSON data (safeJsonStringify in scope)",
            near=[W(r"JSON\.stringify", before=3, after=2), F(r"safeJsonStringify")],
        ),
    ],
)
curate(
    "postmessage-origin",
    "xss",
    ["CWE-346"],
    file_contains=[r"addEventListener.*message|onmessage"],
    patterns=[
        P(
            r"""addEventListener\s*\(\s*['"]message['"]|\.onmessage\s*=""",
            "postMessage handler with origin check (verify strictness)",
            near=[W(r"event\.origin|\.origin\s*[!=]==?|origin.*check", after=9)],
        ),
        P(
            r"""addEventListener\s*\(\s*['"]message['"]|\.onmessage\s*=""",
            "postMessage handler with origin check (verify strictness)",
            near=[W(r"validat.*origin", after=9)],
        ),
        P(
            r"""addEventListener\s*\(\s*['"]message['"]|\.onmessage\s*=""",
            "postMessage handler WITHOUT origin validation",
            not_near=[
                W(r"event\.origin|\.origin\s*[!=]==?|origin.*check", after=9),
                W(r"validat.*origin", after=9),
            ],
        ),
    ],
    notes="The origin check 'event\\.origin|\\.origin\\s*[!=]==?|origin.*check|validat.*origin' "
    "is split in two regexes (one wildcard each).",
)

# --- SSRF / redirects -----------------------------------------------------------------------
curate(
    "ssrf",
    "ssrf",
    ["CWE-918"],
    drop={8: "replaced below", 9: "replaced below", 10: "replaced below"},
    notes="The three string-built URL rules skip lines that name a constant base URL "
    "(VERCEL_API_URL, API_BASE, ...), as upstream.",
    append=[
        P(
            r"fetch\s*\(\s*`[^`]*\$\{",
            "fetch with interpolated URL (non-constant base)",
            not_near=[W("{CONSTANT_BASE}")],
        ),
        P(
            r"https?://[^`]*\$\{",
            "string-built URL via template interpolation",
            not_near=[W("{CONSTANT_BASE}")],
        ),
        P(
            r"""["']https?://["']\s*\+""",
            "string-built URL via concatenation",
            not_near=[W("{CONSTANT_BASE}")],
        ),
    ],
)
curate("go-ssrf", "ssrf", ["CWE-918"])
curate("lua-string-concat-url", "ssrf", ["CWE-918"])
curate("git-provider-url-injection", "ssrf", ["CWE-918"])
curate(
    "framework-untrusted-fetch",
    "ssrf",
    ["CWE-918"],
    file_patterns=[
        "**/packages/{next,next-server,next-mdx,next-codemod,next-bundle-analyzer}/src/**/"
        "*.{ts,tsx,js,mjs}",
        "**/src/server/**/*.{ts,tsx,js,mjs}",
        "**/src/lib/router-utils/**/*.{ts,tsx,js,mjs}",
    ],
    patterns=[
        P(
            r"\b(?:globalThis\.|window\.)?fetch\s*\(",
            "fetch in framework code with URL from req/headers/query/body",
            near=[
                W(
                    r"\b(?:req\.(?:url|query|headers|body)|request\.(?:url|nextUrl|headers|query|body)"
                    r"|searchParams\.get\b|new\s+URL\s*\(\s*req\b|nextUrl\.(?:searchParams|pathname)"
                    r"|getRequestMeta\b|request\.cookies)",
                    before=8,
                    after=5,
                )
            ],
        ),
    ],
    notes="The framework-path check moves into file_patterns.",
)
curate(
    "framework-image-optimizer",
    "ssrf",
    ["CWE-918"],
    patterns=[
        P(r"\bimageOptimizer\s*\(|\boptimizeImage\s*\(", "image optimizer call"),
        P(r"\b(?:remotePatterns|domains|loaderFile)\b", "image remote-pattern config"),
        P(r"\bisPrivateIP\s*\(|\bIP_ADDRESS_REGEX\b", "private-IP check"),
        P(r"\bmatchRemotePattern\s*\(|\bmatchHost\s*\(", "remote pattern / host matching"),
        P(
            r"\b(?:169\.254\.169\.254|0\.0\.0\.0|127\.0\.0\.1|::1|::ffff:)",
            "internal address literal",
        ),
    ],
    notes="deepsec labels with the first 40 characters of the regex; the port uses descriptive "
    "labels. The path-only fallback (flag line 1 of image-optimizer files without content "
    "hits) is dropped.",
)
curate(
    "untrusted-redirect-following",
    "ssrf",
    ["CWE-918"],
    file_contains=[r"\bfetch\s*\(|\baxios\b|\bgot\s*\(|\bundici\b|\bnode-fetch\b|\bphin\b"],
    patterns=[
        P(
            r"""\bredirect\s*:\s*["']follow["']""",
            "explicit redirect: 'follow' — verify URL is allowlisted",
        ),
        P(
            r"\b(?:fetch|axios\.\s*(?:get|post|put|delete|head)|got|got\.\s*(?:get|post))\s*\(\s*"
            r"[^,)]{0,300}\b(?:url|targetUrl|callbackUrl|redirectUrl|webhookUrl|companyUrl|websiteUrl"
            r"|domainUrl|imageUrl|fetchUrl|next|return_to|returnTo|destination|location)\b",
            "fetch with a caller-style URL — default redirect: follow",
            not_near=[W(r"""\bredirect\s*:\s*["'](?:manual|error)["']""", after=4)],
        ),
    ],
    notes="The URL-variable check on the first call argument is folded into the regex; the "
    "argument text before the variable is bounded to 300 characters (quadratic backtracking "
    "on long lines). The deepsec label quotes the argument; the port uses a fixed label.",
)
curate(
    "url-regex-validation",
    "ssrf",
    ["CWE-185"],
    patterns=[
        P(
            r"https?.*\.[+*]",
            "URL validation regex with greedy wildcard (.+ or .*) — may be bypassable",
            near=[W(r"RegExp|/.*/|\.test|\.match")],
        ),
        P(
            r"new RegExp\s*\(.*https?",
            "URL validation regex with greedy wildcard (.+ or .*) — may be bypassable",
        ),
        P(
            r"/\^?https?:.*\.\+[^/]*/",
            "URL validation regex with greedy wildcard (.+ or .*) — may be bypassable",
        ),
        P(
            r"new\s+URL\s*\(",
            "new URL() from request input without hostname validation",
            near=[W(r"req\.|params\.|query\.|body\.|parsed\.")],
            not_near=[W(r"\.hostname\s*===|\.host\s*===", after=4)],
        ),
    ],
    notes="Equivalent one-wildcard rewrites: 'https?.*\\.\\+|https?.*\\.\\*' becomes "
    "'https?.*\\.[+*]' and '\\/\\^?https?:.*\\.\\+.*\\/' becomes '/\\^?https?:.*\\.\\+[^/]*/'.",
)
curate(
    "lua-regex-bypass",
    "ssrf",
    ["CWE-185"],
    patterns=[
        P(
            r"ngx\.re\.match\s*\(",
            "URL/host validation regex (verify not bypassable)",
            near=[W(r"https?|host|domain|\.com|\.sh")],
        ),
        P(
            r"string\.(match|find)\s*\(",
            "URL/host validation regex (verify not bypassable)",
            near=[W(r"https?|host|domain")],
        ),
        P(
            r"\.\+|\.\*|%.+",
            "Greedy pattern in URL/host context",
            near=[W(r"url|host|domain|redirect", flags="i")],
        ),
    ],
)
curate("open-redirect", "open-redirect", ["CWE-601"])
curate(
    "unsafe-redirect",
    "open-redirect",
    ["CWE-601"],
    file_contains=[
        r"(?i:redirect\s*\(|NextResponse\.redirect|router\.push|router\.replace|window\.location)"
    ],
    patterns=[
        P(
            r"redirect\s*\(\s*(req\.|request\.|params\.|query\.|searchParams|body\.)",
            "redirect() with request-derived URL (NO validNextRedirect — investigate)",
            not_near=[F(r"validNextRedirect")],
        ),
        P(
            r"redirect\s*\(\s*(req\.|request\.|params\.|query\.|searchParams|body\.)",
            "redirect() with request-derived URL (validNextRedirect in scope — verify usage)",
            near=[F(r"validNextRedirect")],
        ),
        P(
            r"redirect\s*\(\s*`[^`]*\$\{",
            "redirect() with interpolated URL (NO validNextRedirect — investigate)",
            not_near=[F(r"validNextRedirect")],
        ),
        P(
            r"redirect\s*\(\s*`[^`]*\$\{",
            "redirect() with interpolated URL (validNextRedirect in scope — verify usage)",
            near=[F(r"validNextRedirect")],
        ),
        P(
            r"NextResponse\.redirect\s*\(\s*new\s+URL\s*\(",
            "NextResponse.redirect with dynamic URL (NO validNextRedirect — investigate)",
            not_near=[F(r"validNextRedirect")],
        ),
        P(
            r"NextResponse\.redirect\s*\(\s*new\s+URL\s*\(",
            "NextResponse.redirect with dynamic URL (validNextRedirect in scope — verify usage)",
            near=[F(r"validNextRedirect")],
        ),
        P(
            r"x-app-redirect-uri|redirect.uri|redirectUrl|returnUrl|returnTo",
            "Redirect URL from header/param (NO validNextRedirect — investigate)",
            flags="i",
            not_near=[F(r"validNextRedirect")],
        ),
        P(
            r"x-app-redirect-uri|redirect.uri|redirectUrl|returnUrl|returnTo",
            "Redirect URL from header/param (validNextRedirect in scope — verify usage)",
            flags="i",
            near=[F(r"validNextRedirect")],
        ),
    ],
)

# --- Path traversal / files -----------------------------------------------------------------
curate("path-traversal", "path-traversal", ["CWE-22"])
curate(
    "fs-write-symlink-boundary",
    "path-traversal",
    ["CWE-22", "CWE-59"],
    not_near_all=[
        W(
            r"\b(?:realpath|fs\.realpath|path\.relative|startsWith\s*\(\s*(?:root|base)"
            r"|resolveWritablePathWithinRoot|withinRoot|insideRoot)\b",
            before=5,
            after=4,
        )
    ],
)

# --- Secrets / data exposure ----------------------------------------------------------------
curate("secrets-exposure", "hardcoded-secrets", ["CWE-798"])
curate("secret-in-fallback", "hardcoded-secrets", ["CWE-798", "CWE-1188"])
curate(
    "tf-secret-in-data",
    "hardcoded-secrets",
    ["CWE-798"],
    patterns=[
        P(
            r"""^\s*[\w-]+\s*=\s*"(?![^"]*\$\{)(?!(?:default|true|false|enabled|disabled|none"""
            r"""|public|private)")[^"]{8,}\"""",
            "kubernetes_secret.data with literal value",
            flags="i",
            near=[
                W(r'^\s*resource\s+"kubernetes_secret(?:_v1)?"\s+', before=30),
                W(r"^\s*data\s*=?\s*\{", before=15),
            ],
        ),
    ],
    notes="Brace tracking is approximated: the literal must be within 15 lines after a "
    "'data = {' line and 30 lines after a kubernetes_secret resource line.",
)
curate("secret-env-var", "sensitive-data-exposure", ["CWE-200"])
curate(
    "env-exposure",
    "sensitive-data-exposure",
    ["CWE-200"],
    patterns=[
        P(
            r"NEXT_PUBLIC_.*(SECRET|KEY|TOKEN|PASSWORD|CREDENTIAL)",
            "NEXT_PUBLIC_ variable with secret-like name",
            flags="i",
        ),
        P(
            r"process\.env\.\w*(SECRET|KEY|TOKEN|PASSWORD|CREDENTIAL|PRIVATE)",
            "Secret env var accessed in 'use client' component",
            flags="i",
            near=[F(r"""['"]use client['"]""")],
        ),
        P(
            r"^[A-Z_]+=.{8,}",
            "Secret value in committed .env file",
            near=[W(r"SECRET|KEY|TOKEN|PASSWORD|CREDENTIAL|PRIVATE", flags="i")],
            not_near=[W(r"<|placeholder|example|xxx", flags="i")],
            paths=["**/.env", "**/.env.*"],
        ),
    ],
    notes="The .env rule applies to .env and .env.* files (deepsec: any path that contains "
    "'.env').",
)
curate(
    "secret-in-log",
    "sensitive-data-exposure",
    ["CWE-532"],
    patterns=[
        P(
            r"console\.(log|error|warn|info)\s*\(|logger\.\w+\s*\(|migrationsLogger\.\w+\s*\("
            r"|log\.\w+\s*\("
            r"|\{\s*(token|secret|apiKey|password|credential|accessToken|refreshToken)\s*[,}:]"
            r"|JSON\.stringify\s*\(.*\b(token|secret|key|password)\b",
            "Secret variable in log statement",
            near=[W("{SECRET_NAMES}")],
        ),
        P(
            r"throw\s+new\s+\w*Error\s*\(|res\.(json|send|status)\s*\(",
            "Secret variable in error response",
            near=[W("{SECRET_NAMES}")],
        ),
        P(
            r"return.{0,200}\{.*error",
            "Secret variable in error response",
            near=[W("{SECRET_NAMES}")],
        ),
        P(
            r"return.{0,200}message.*:",
            "Secret variable in error response",
            near=[W("{SECRET_NAMES}")],
        ),
    ],
    notes="'return.*\\{.*error|return.*message.*:' has two wildcards per branch: each branch "
    "becomes a pattern and its first wildcard is bounded to 200 characters.",
)
curate(
    "secrets-plaintext-exposure",
    "sensitive-data-exposure",
    ["CWE-532", "CWE-200"],
    patterns=[
        P(
            "{PLAINTEXT_SINK}",
            "plaintext reference inside logger/response/error/span call",
            near=[W("{PLAINTEXT}", after=3)],
            not_near=[W(r"plaintext\s*\.\s*length\b", after=3)],
        ),
        P(
            "{PLAINTEXT_SINK}",
            "plaintext reference inside logger/response/error/span call",
            near=[W("{PLAINTEXT}", after=3), W(r"plaintext\s*[,)]", after=3)],
        ),
    ],
    notes="The '.length' exception is split in two patterns: flag when the window has no "
    "'plaintext.length', or when it also passes plaintext directly (as upstream).",
)
curate(
    "sensitive-data-in-traces",
    "sensitive-data-exposure",
    ["CWE-532"],
    file_contains=[
        r"(?i:password|secret|token|apiKey|api_key|credential|private.?key|client.?secret"
        r"|access.?token|payment|billing|invoice|stripe|credit.?card|req\.body|request\.body"
        r"|rawReqData|requestPayload)"
    ],
    label_format="{} in file with sensitive data — check what's being traced",
)
curate(
    "error-message-leak",
    "sensitive-data-exposure",
    ["CWE-209"],
    near_all=[
        W(
            r"Response\.json|NextResponse\.json|res\.json|res\.send|res\.status|new Response"
            r"|json\s*\(",
            before=3,
            after=2,
        )
    ],
    label_format="{} — may leak internal details to client",
)
curate("response-header-leak", "sensitive-data-exposure", ["CWE-200"])
curate(
    "k8s-secret-reference",
    "iac-cloud-container",
    ["CWE-312"],
    replace={0: P(r"^\s*(?:-\s*)?secretKeyRef\s*:", "env.valueFrom.secretKeyRef")},
    notes="'^\\s*-?\\s*secretKeyRef' becomes the equivalent '^\\s*(?:-\\s*)?secretKeyRef' "
    "(two adjacent \\s* backtrack quadratically on a long blank line).",
)
curate("k8s-secrets-init-container", "iac-cloud-container", ["CWE-312"])

# --- Crypto ---------------------------------------------------------------------------------
curate(
    "crypto-usage",
    "crypto",
    [],
    notes="Wide-net inventory of cryptographic primitives; deepsec stops at the first label per "
    "line, the port can give a line several labels.",
)
curate(
    "insecure-crypto",
    "crypto",
    ["CWE-327", "CWE-338", "CWE-208"],
    replace={
        8: P(
            r"Math\.random\s*\(",
            "Math.random in security context",
            near=[
                F(
                    r"\b(token|secret|key|password|nonce|salt|session|csrf|auth|credential|hash)\b",
                    flags="i",
                )
            ],
        )
    },
)
curate("lua-crypto-weakness", "crypto", ["CWE-327"])

# --- Race conditions / logic ----------------------------------------------------------------
curate(
    "missing-await",
    "race-condition",
    ["CWE-362"],
    patterns=[
        P(
            r"with\w*Mutex\s*\(",
            "mutex without await",
            not_near=[W(r"\b(?:await|return)\s+with\w*Mutex\s*\(|^\s*(?://|\*)")],
        ),
        P(
            r"with\w*Lock\s*\(",
            "lock without await",
            not_near=[W(r"\b(?:await|return)\s+with\w*Lock\s*\(|^\s*(?://|\*)")],
        ),
        P(
            r"with\w*Transaction\s*\(",
            "transaction without await",
            not_near=[W(r"\b(?:await|return)\s+with\w*Transaction\s*\(|^\s*(?://|\*)")],
        ),
        P(
            r"redis\.\w+\s*\(",
            "redis call without await",
            not_near=[W(r"\b(?:await|return)\s+redis\.\w+\s*\(|^\s*(?://|\*)")],
        ),
        P(
            r"prisma\.\w+\.\w+\s*\(",
            "prisma call without await",
            not_near=[W(r"\b(?:await|return)\s+prisma\.\w+\.\w+\s*\(|^\s*(?://|\*)")],
        ),
        P(
            r"db\.\w+\.\w+\s*\(",
            "db call without await",
            not_near=[W(r"\b(?:await|return)\s+db\.\w+\.\w+\s*\(|^\s*(?://|\*)")],
        ),
    ],
    notes="The lookbehinds '(?<!await\\s)(?<!return\\s)' fail the safety checks. They become "
    "line exclusions: a line with 'await <call>' or 'return <call>' does not count, even when "
    "it holds a second call without await.",
)
curate(
    "non-atomic-operation",
    "race-condition",
    ["CWE-367"],
    file_contains=[
        r"findById|getById|findOne|findUnique|findFirst",
        r"update|delete|remove|modify|save|create",
    ],
    file_excludes=[r"transaction\s*\(|\.transact\(|BEGIN|COMMIT|withLock|mutex|atomicUpdate"],
    patterns=[
        P(
            r"await.*find(ById|One|Unique|First)\s*\(",
            "Read-then-write without transaction — verify atomicity",
            near=[W(r"await.*(update|delete|remove|modify|save)\s*\(", after=14)],
        ),
        P(
            r"await.*get\w+By(Id|Uid)\s*\(",
            "Read-then-write without transaction — verify atomicity",
            near=[W(r"await.*(update|delete|remove|modify|save)\s*\(", after=14)],
        ),
    ],
)
curate(
    "non-atomic-read-delete",
    "race-condition",
    ["CWE-367"],
    patterns=[
        P(
            r"redis\.(get|hget|hgetall)\s*\(",
            "Redis get-then-delete/set without transaction — TOCTOU race",
            near=[W(r"redis\.(del|hdel|set|hset|expire)\s*\(", after=9)],
            not_near=[
                W(r"\.multi\s*\(|\.pipeline\s*\(|\.transaction\s*\(|WATCH", before=5, after=14)
            ],
        ),
        P(
            r"\b(SELECT|findFirst|findUnique|findOne)\b",
            "Read-then-modify without transaction — potential TOCTOU race",
            flags="i",
            near=[W(r"\b(DELETE|UPDATE|destroy|remove|deleteMany)\b", after=14, flags="i")],
            not_near=[
                W(r"\$transaction\s*\(|BEGIN|SERIALIZABLE|\.transaction\s*\(", before=5, after=19)
            ],
        ),
    ],
)
curate(
    "event-handler-mismatch",
    "business-logic",
    ["CWE-840"],
    file_contains=[
        r"""(?i:switch\s*\(.*event|case\s+['"][^'"]*\.(?:created|updated|deleted|removed|added))"""
    ],
    patterns=[
        P(
            r"""case\s+['"][\w.]*(?:removed|deleted)[\w.]*['"]""",
            "Event case calls a function with the opposite action — possible copy-paste bug",
            flags="i",
            near=[W(r"\b\w*(?:add|create|insert)\w*\s*\(", after=5, flags="i")],
        ),
        P(
            r"""case\s+['"][\w.]*(?:added|created)[\w.]*['"]""",
            "Event case calls a function with the opposite action — possible copy-paste bug",
            flags="i",
            near=[W(r"\b\w*(?:remove|delete|destroy)\w*\s*\(", after=5, flags="i")],
        ),
        P(
            r"""case\s+['"][\w.]*updated[\w.]*['"]""",
            "Event case calls a function with the opposite action — possible copy-paste bug",
            flags="i",
            near=[W(r"\b\w*(?:create|delete)\w*\s*\(", after=5, flags="i")],
        ),
    ],
    notes="The file gate 'case\\s+['\"].*\\.(created|...)' becomes "
    "'case\\s+['\"][^'\"]*\\.(?:created|...)' (one wildcard). The 5-line window also covers "
    "the case line. When an event name holds several actions, deepsec uses the first action "
    "in the order removed, deleted, added, created, updated; the port checks each. The deepsec "
    "label names the event and the function; the port uses a fixed label.",
)
curate(
    "security-behind-flag",
    "security-misconfig",
    ["CWE-636"],
    patterns=[
        P(
            r"feature_?flag|featureFlag|LaunchDarkly|variation\s*\(|statsig|flag_enabled",
            "Security operation gated by feature flag — verify fail-safe when flag is off",
            flags="i",
            near=[W("{SECURITY_OPS}", before=3, after=3, flags="i")],
        ),
        P(
            r"isEnabled\s*\(|isFeatureEnabled|experiment\s*\(|getFlag\s*\(",
            "Security operation gated by feature flag — verify fail-safe when flag is off",
            near=[W("{SECURITY_OPS}", before=3, after=3, flags="i")],
        ),
    ],
    notes="In the security-operation regex the first wildcard of 'strip.*header', "
    "'remove.*header', 'validate.*token' and 'check.*permission' is bounded to 200 characters "
    "(one unbounded wildcard per regex).",
)
curate(
    "env-var-as-bool",
    "security-misconfig",
    ["CWE-697"],
)
curate(
    "debug-endpoint",
    "security-misconfig",
    ["CWE-489"],
    patterns=[
        P(
            "{DEBUG_HANDLER}",
            "Debug/test endpoint — verify an env gate keeps it unreachable in production",
            paths=[
                "**/debug*/**",
                "**/debug*",
                "**/{test,dev,internal,admin}/**",
            ],
        ),
        *[
            P(
                "{DEBUG_HANDLER}",
                "Debug/test endpoint — verify an env gate keeps it unreachable in production",
                near=[F(regex)],
            )
            for regex in (
                r"debug.*endpoint",
                r"test.*endpoint",
                r"dev.*only",
                r"development.*only",
                r"x-debug|x-test-|x-internal",
            )
        ],
    ],
    notes="The path-or-content gate becomes pattern variants. deepsec flags the first handler "
    "and words the label by the NODE_ENV gate; the port flags every handler line with one "
    "label.",
)
curate(
    "cors-wildcard",
    "cors",
    ["CWE-942"],
    replace={
        1: P(
            r"Access-Control-Allow-Origin.*origin",
            "CORS origin reflection (verify validation)",
        ),
        2: P(
            r"Access-Control-Allow-Credentials.*true",
            "CORS credentials + origin (dangerous combo)",
            flags="i",
            near=[W(r"Allow-Origin", flags="i")],
        ),
    },
    append=[
        P(
            r"Allow-Origin.*Allow-Credentials",
            "CORS credentials + origin (dangerous combo)",
            flags="i",
            near=[W(r"Allow-Credentials.*true", flags="i")],
        ),
    ],
    notes="Two upstream regexes have two wildcards per branch. 'Origin.*req\\.headers\\.origin"
    "|Origin.*origin' equals its second branch. 'Credentials.*true.*Allow-Origin|Allow-Origin"
    ".*Credentials.*true' becomes two patterns with a same-line condition; the position of the "
    "second Allow-Origin is not checked.",
)
curate(
    "rate-limit-bypass",
    "rate-limit-bruteforce",
    ["CWE-307"],
    file_excludes=[r"(?i:rateLimit|rate.limit|checkRateLimit|rateLimiter|throttle)"],
    patterns=[
        P(
            "{RATE_HANDLER}",
            "Sensitive endpoint without rate limiting",
            near=[
                F(
                    r"(?i:login|signin|sign.in|authenticate|password|passwd|billing|charge|payment"
                    r"|refund|invoice|delete.{0,200}account|remove.{0,200}user|deactivate|export"
                    r"|download.{0,200}data|bulk|api.key|token.{0,200}create|generate.{0,200}token"
                    r"|invite|add.{0,200}member|transfer.{0,200}ownership)"
                )
            ],
        ),
        P(
            "{RATE_HANDLER}",
            "Sensitive endpoint without rate limiting",
            paths=[
                "**/*{login,signin,sign-in,authenticate,password,passwd,billing,charge}*/**",
                "**/*{payment,refund,invoice,deactivate,export,bulk,invite,api-key}*/**",
                "**/*{login,signin,sign-in,authenticate,password,passwd,billing,charge}*",
                "**/*{payment,refund,invoice,deactivate,export,bulk,invite,api-key}*",
            ],
        ),
    ],
    notes="The sensitive-operation test (content or path) becomes two pattern variants. In "
    "the content regex each 'a.*b' wildcard is bounded to 200 characters. Path matching uses "
    "lower-case keywords. deepsec flags the first handler line; the port flags every handler "
    "line.",
)
curate(
    "webhook-handler",
    "webhook-replay",
    ["CWE-345"],
    patterns=[
        P(
            r"webhook",
            "Webhook handler (verify signature validation) — has signature verification",
            flags="i",
            near=[W(r"export|handler|POST|route", flags="i"), F("{WEBHOOK_VERIFY}")],
        ),
        P(
            r"webhook",
            "Webhook handler (verify signature validation) — NO signature verification found",
            flags="i",
            near=[W(r"export|handler|POST|route", flags="i")],
            not_near=[F("{WEBHOOK_VERIFY}")],
        ),
    ],
    notes="deepsec reports the first line per file; the port reports every line.",
)
curate(
    "slack-signing-verification",
    "webhook-replay",
    ["CWE-345", "CWE-294"],
    near_all=[F("{HAS_SLACK}")],
    append=[
        P(
            r"\bexport\s+(?:async\s+)?function\s+(?:POST|GET|handle)\b",
            "Slack-context HTTP handler",
            paths=["{SLACK_PATHS}"],
        ),
        P(
            r"""\bcrypto\.\s*createHmac\s*\(\s*["']sha256["'].*?(?:slack|signing)""",
            "Slack HMAC-SHA256 verification",
            flags="i",
            paths=["{SLACK_PATHS}"],
        ),
    ],
    notes="The 'Slack import or Slack path' gate becomes a whole-file condition on every "
    "upstream pattern plus path-gated variants of the handler and HMAC patterns. deepsec stops "
    "at the first label per line.",
)
curate(
    "cache-key-poisoning",
    "request-smuggling-crlf-cache",
    ["CWE-349"],
)
curate(
    "lua-shared-dict-poisoning",
    "request-smuggling-crlf-cache",
    ["CWE-349"],
)

# --- Supply chain / IaC ---------------------------------------------------------------------
curate(
    "github-workflow-security",
    "supply-chain-cicd",
    ["CWE-829"],
    append=[
        P(
            r"^(?:on|jobs|name)\s*:",
            "GitHub workflow file (path-based, no specific risk pattern)",
            not_near=[
                F(
                    r"^\s*-\s*pull_request_target\b|^\s*pull_request_target\s*:"
                    r"|^\s*-\s*workflow_run\b|^\s*workflow_run\s*:"
                ),
                F(r"\buses\s*:\s*[\w-]+/[\w./-]+@(?:main|master|v?\d+|develop)\s*$", flags="m"),
                F(
                    r"\$\{\{\s*github\.event\.(?:pull_request|head_commit|comment|issue|review)\.\w+"
                    r"|\$\{\{\s*github\.head_ref\s*\}\}"
                ),
                F(
                    r"\bsecrets\.[A-Z_][A-Z0-9_]+|^\s*permissions\s*:\s*write-all\b"
                    r"|\bid-token\s*:\s*write\b"
                ),
                F(r"\brun\s*:\s*\|.*\$\{\{[^}]*\}\}", flags="s"),
                F(r"\bcurl\s+[^|]*\|\s*(?:sh|bash)\b"),
            ],
        ),
    ],
    notes="The fallback for workflow files without a risk pattern anchors on unindented on:, "
    "jobs: and name: lines (deepsec: the first such line, indented or not). deepsec stops at "
    "the first label per line.",
)
curate(
    "dockerfile-curl-pipe-unverified",
    "supply-chain-cicd",
    ["CWE-494"],
    patterns=[
        P(
            r"\b(curl|wget)\b[^|\n]*\|\s*(?:sh|bash|zsh|tar\b|gunzip\b|unzip\b)",
            "curl|wget | sh/tar with no checksum check",
            flags="i",
            not_near=[
                W(
                    r"(sha256sum|sha1sum|shasum|gpg\s+--?verify|cosign\s+verify|minisign"
                    r"|openssl\s+dgst)",
                    before=5,
                    after=5,
                    flags="i",
                )
            ],
        ),
    ],
    notes="RUN continuation lines are not joined. The checksum check looks 5 lines before and "
    "after the pipe line, and the candidate line is the pipe line (deepsec: the RUN line of the "
    "joined statement).",
)
curate(
    "dockerfile-from-mutable-tag",
    "supply-chain-cicd",
    ["CWE-829"],
    # kalkan extension (ADR-0005, K.12): Containerfile and lower-case names, and build stages.
    file_patterns=[
        "**/Dockerfile",
        "**/Dockerfile.*",
        "**/*.Dockerfile",
        "**/dockerfile",
        "**/*.dockerfile",
        "**/Containerfile",
        "**/Containerfile.*",
        "**/*.Containerfile",
    ],
    patterns=[
        P(
            r"^\s*FROM\s+(?:--platform=\S+\s+)?(?!\$)(?!\S*@sha256:)(?=\S*[:/.])\S+"
            r"(?:\s+AS\s+\S+)?\s*$",
            "FROM without @sha256 digest",
            flags="i",
        ),
        P(
            r"^\s*FROM\s+(?:--platform=\S+\s+)?(?!\$)(?!scratch(?:\s|$))[A-Za-z0-9_-]+"
            r"(?:\s+AS\s+\S+)?\s*$",
            "FROM without @sha256 digest",
            flags="i",
            not_near=[W(r"^\s*FROM\s.*\sAS\s+\S+\s*$", before=10000, flags="i")],
        ),
    ],
    notes="The image checks (ARG reference, scratch, @sha256 digest) become lookaheads. The "
    "scratch check is case-insensitive here. kalkan (ADR-0005, K.12): Containerfile and "
    "lower-case file names; an image with a tag, a registry or a path is always reported; a "
    "bare name (FROM alpine) is reported only when no FROM ... AS <name> line comes before it "
    "or on it, because such a name can be an earlier build stage (FROM build); an untagged "
    "image with its own AS clause is thus left out.",
)
curate(
    "dockerfile-run-as-root",
    "iac-cloud-container",
    ["CWE-250"],
    patterns=[
        P(
            r"^\s*FROM\s+(?:--platform=\S+\s+)?(?!scratch(?:\s|$))\S",
            "Final stage has no USER directive",
            flags="i",
            not_near=[W(r"^\s*USER\s+\S", after=10000, flags="i")],
        ),
        P(
            r"^\s*FROM\s+(?:--platform=\S+\s+)?scratch(?:\s|$)",
            "Final stage has no USER directive",
            flags="i",
            near=[W(r"^\s*(CMD|ENTRYPOINT|RUN)\b", after=10000, flags="i")],
            not_near=[W(r"^\s*USER\s+\S", after=10000, flags="i")],
        ),
        P(
            r"^\s*USER\s+(?:root|0)(?::|\s|$)",
            "Final stage ends with USER root",
            flags="i",
            not_near=[W(r"^\s*USER\s+(?!(?:root|0)(?::|\s|$))\S", after=10000, flags="i")],
        ),
    ],
    notes="Stage tracking is approximated: a FROM line is flagged when no USER line follows it, "
    "and a USER root line when no non-root USER line follows it. In a multi-stage file without "
    "USER every FROM line is listed (deepsec: the last FROM).",
)
curate(
    "go-embed-asset",
    "supply-chain-cicd",
    ["CWE-829"],
    patterns=[
        P(r"^\s*//go:embed\s+(.+?)\s*$", "//go:embed directive"),
    ],
    notes="The deepsec label lists the embedded paths; the port uses a fixed label.",
)
curate(
    "tf-module-unpinned",
    "supply-chain-cicd",
    ["CWE-829"],
    patterns=[
        P(
            r"""\bsource\s*=\s*"(?:git::|github\.com/|bitbucket\.org/|https?://|[\w.-]+@)"""
            r"""(?![^"]*\?ref=[0-9a-f]{7,40}\b)(?![^"]*[?&]tag=[\w.-]+)[^"]*\"""",
            "remote unpinned",
            flags="i",
            near=[W(r'^\s*module\s+"[^"]+"\s*\{', before=20)],
        ),
        P(
            r'\bsource\s*=\s*"[a-z0-9-]+/[a-z0-9-]+/[a-z0-9-]+(?://[\w/-]+)?"',
            "registry no version",
            flags="i",
            near=[W(r'^\s*module\s+"[^"]+"\s*\{', before=20)],
            not_near=[W(r'\bversion\s*=\s*"[^"]+"', before=20, after=20)],
        ),
    ],
    notes="Block parsing is approximated: the source line must be within 20 lines after a "
    "module line; a registry source needs a version line within 20 lines.",
)
curate(
    "tf-public-ingress",
    "iac-cloud-container",
    ["CWE-668"],
    patterns=[
        *[
            P(
                r"""\b(?:cidr_blocks|cidr_block)\s*=\s*\[?\s*['"]0\.0\.0\.0/0['"]|::/0""",
                "0.0.0.0/0 ingress on non-web port",
                near=[
                    W(
                        r'^\s*(?:ingress|egress)\s*\{|resource\s+"aws_(?:security_group_rule'
                        r'|network_acl_rule)"',
                        before=40,
                    ),
                    *extra_near,
                ],
                not_near=extra_not_near,
            )
            for extra_near, extra_not_near in (
                ([], [W(r"\bfrom_port\s*=\s*(?:80|443)\b", before=15, after=15)]),
                ([], [W(r"\bto_port\s*=\s*(?:80|443)\b", before=15, after=15)]),
                ([W("{SENSITIVE_PORTS}", before=15, after=15)], []),
            )
        ],
        P(
            r"\bendpoint_public_access\s*=\s*true",
            "EKS public endpoint without CIDR allow-list",
            not_near=[W(r"\bendpoint_public_access_cidrs\b", before=8, after=8)],
        ),
    ],
    notes="Block parsing is approximated: the CIDR line must be within 40 lines after an "
    "ingress/egress/rule line, and the port checks look 15 lines around it. The web-port "
    "exception (from_port and to_port 80/443, no sensitive port) becomes three pattern "
    "variants.",
)
curate(
    "tf-encryption-missing",
    "iac-cloud-container",
    ["CWE-311"],
    patterns=[
        P(
            r'^\s*resource\s+"aws_s3_bucket"\s+',
            "S3 bucket without encryption",
            flags="i",
            not_near=[
                F(
                    r"aws_s3_bucket_server_side_encryption_configuration"
                    r"|server_side_encryption_configuration\s*\{",
                    flags="i",
                )
            ],
        ),
        P(
            r'^\s*resource\s+"aws_(?:rds_cluster|db_instance|db_cluster)"\s+',
            "RDS/Aurora without encryption",
            flags="i",
            not_near=[F(r"\bstorage_encrypted\s*=\s*true\b", flags="i")],
        ),
        P(
            r'^\s*resource\s+"aws_ebs_volume"\s+',
            "EBS volume without encryption",
            flags="i",
            not_near=[F(r"\bencrypted\s*=\s*true\b", flags="i")],
        ),
        P(
            r'^\s*resource\s+"aws_dynamodb_table"\s+',
            "DynamoDB without encryption",
            flags="i",
            not_near=[F(r"\bserver_side_encryption\s*\{", flags="i")],
        ),
        P(
            r'^\s*resource\s+"aws_sns_topic"\s+',
            "SNS topic without encryption",
            flags="i",
            not_near=[F(r"\bkms_master_key_id\s*=", flags="i")],
        ),
        P(
            r'^\s*resource\s+"aws_sqs_queue"\s+',
            "SQS queue without encryption",
            flags="i",
            not_near=[
                F(r"\bkms_master_key_id\s*=|\bsqs_managed_sse_enabled\s*=\s*true", flags="i")
            ],
        ),
        P(
            r'^\s*resource\s+"aws_elasticache_replication_group"\s+',
            "ElastiCache without encryption",
            flags="i",
            not_near=[F(r"\bat_rest_encryption_enabled\s*=\s*true", flags="i")],
        ),
    ],
    notes="The DynamoDB check 'server_side_encryption { ... enabled = true }' spans lines; the "
    "port accepts any server_side_encryption block in the file.",
)
curate("tf-iam-wildcard", "iac-cloud-container", ["CWE-732"])

#: Placeholders shared by several curation entries (``"{NAME}"`` in a regex field).
SHARED: dict[str, str] = {
    "AUTH_CALLS": r"getSession\s*\(|auth\s*\(\s*\)|requireAuth|withAuth|verifyToken"
    r"|authUserAndTeamByAuthAPI|isAuthenticated|assertAuth|checkAuth|parseAuthToken"
    r"|withOidcTokenAuth",
    "CATCH_HANDLER": r"export\s+(async\s+)?function\s+(GET|POST|PUT|DELETE|PATCH)"
    r"|export\s+(const\s+)?(GET|POST|PUT|DELETE|PATCH)\s*=",
    "CATCH_AUTH": r"withAuthentication\s*\(|withSchema\s*\(|getSession\s*\(|auth\s*\(\s*\)"
    r"|requireAuth|verifyToken",
    "ACCESS_CHECK": r"auth|getSession|requireAuth|withAuthentication|checkAccess|verifyAccess"
    r"|can\s*\(",
    "DB_WRITE": r"\.\s*insert\s*\([^)]+\)\.\s*values\s*\(|\.\s*update\s*\([^)]+\)\.\s*set\s*\(",
    "CONSTANT_BASE": r"VERCEL_API_URL|API_BASE|API_URL|INTERNAL_URL|process\.env\.\w+_URL",
    "SECRET_NAMES": r"\b(token|accessToken|refreshToken|secret|apiKey|api_key|password|credential"
    r"|privateKey|bearerToken)\b",
    "PLAINTEXT": r"\b(?:plaintext|decryptedValue|decryptedSecret|decryptedEnv"
    r"|decryptResponse\.plaintext|nowDecryptResponse\.plaintext|decrypted\w*)\b",
    "PLAINTEXT_SINK": r"\b(?:console\.(?:log|info|warn|error|debug)"
    r"|logger\.(?:info|warn|error|debug|fatal|trace)|log\.(?:Info|Warn|Error|Debug|Printf|Println)"
    r"|ngx\.log|zap\.(?:String|Any|Error)|fmt\.(?:Errorf|Printf|Println)"
    r"|span\.(?:setAttribute|setAttributes|addEvent|recordException)"
    r"|res\.(?:send|json|write|end)|response\.(?:send|json|write|end)|reply\.(?:send|code)"
    r"|ctx\.(?:body|reply)|throw\s+new\s+\w*Error|new\s+Error)\s*\(",
    "SECURITY_OPS": r"sanitize|strip.{0,200}header|clear_header|remove.{0,200}header|auth|verify"
    r"|validate.{0,200}token|check.{0,200}permission|waf|firewall|block|deny|reject"
    r"|rate.?limit|throttle|csrf|cors|xss|injection|encrypt|decrypt|sign|hmac",
    "DEBUG_HANDLER": r"export\s+(async\s+)?function\s+(GET|POST|PUT|DELETE)"
    r"|export\s+(const\s+)?(GET|POST|PUT|DELETE)\s*=",
    "RATE_HANDLER": r"export\s+(const\s+)?(GET|POST|PUT|DELETE|PATCH)\s*="
    r"|export\s+(async\s+)?function\s+(GET|POST|PUT|DELETE|PATCH)|export\s+default"
    r"|withSchema\s*\(|withAuthentication\s*\(",
    "WEBHOOK_VERIFY": r"(?i:verifySignature|verify.*signature|hmac|createHmac|timingSafeEqual)",
    "HAS_SLACK": r"""\bfrom\s+["'](?:@slack/(?:bolt|web-api|events-api|interactive-messages"""
    r"""|oauth)|slack-bolt)["']|\bSlackRequestVerifier\b|\bverifySlackRequest\b"""
    r"|\bslack_signing_secret\b|\bSLACK_SIGNING_SECRET\b",
    "SENSITIVE_PORTS": r"\b(?:from_port|to_port|port)\s*=\s*(?:22|3389|5432|3306|6379|27017|9200"
    r"|9300|11211|5601|8086|9092|2049|445|1433|5984|9000|8080|3000|5000|8000|9090|9443|6443"
    r"|10250|2375|2376|2377|7000|7001|9999|11210|13316)\b",
}
#: Placeholder globs (``"{NAME}"`` in a paths list) that expand to several globs.
SHARED_GLOBS: dict[str, list[str]] = {
    "SLACK_PATHS": [
        "**/{slack,Slack,bolt,Bolt}/**",
        "**/{slack,Slack,bolt,Bolt}{-,_,.}*",
        "**/{slack,Slack,bolt,Bolt}{-,_,.}*/**",
    ],
}


# ---------------------------------------------------------------------------------------------
# Spec assembly
# ---------------------------------------------------------------------------------------------


def _expand(value: Any) -> Any:
    """Replace ``"{NAME}"`` placeholders in regex fields and path lists."""
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            if key == "regex" and isinstance(item, str) and item in _placeholders():
                result[key] = SHARED[item[1:-1]]
            elif key == "paths":
                result[key] = [
                    glob
                    for entry in item
                    for glob in SHARED_GLOBS.get(
                        entry[1:-1] if entry.startswith("{") else "", [entry]
                    )
                ]
            else:
                result[key] = _expand(item)
        return result
    if isinstance(value, list):
        return [_expand(item) for item in value]
    return value


def _placeholders() -> set[str]:
    return {f"{{{name}}}" for name in SHARED}


def _excludes(extracted: Extracted) -> list[str]:
    globs: list[str] = []
    for regex, flags in extracted.path_skips:
        key = (regex, flags)
        if key not in PATH_SKIP_GLOBS:
            raise ValueError(f"{extracted.file}: no exclude glob mapping for /{regex}/{flags}")
        for glob in PATH_SKIP_GLOBS[key]:
            if glob not in globs:
                globs.append(glob)
    return globs


def _requires(extracted: Extracted, curation: dict[str, Any]) -> tuple[dict[str, Any], str]:
    if "requires" in curation:
        requires = {"tech": [], "sentinel_files": [], "sentinel_contains": []}
        requires.update(curation["requires"])
        upstream = ", ".join(extracted.tech) or "none"
        return requires, f"deepsec gate tech [{upstream}] (curated kalkan gate)"
    if not extracted.tech:
        return {"tech": [], "sentinel_files": [], "sentinel_contains": []}, ""
    if len(extracted.tech) != 1:
        raise ValueError(f"{extracted.file}: several tech tags need a curated gate")
    tag = extracted.tech[0]
    gate = TECH_GATES.get(tag)
    if gate is None:
        raise ValueError(f"{extracted.file}: no gate mapping for tech tag {tag}")
    requires = {
        "tech": list(gate.tech),
        "sentinel_files": list(gate.files),
        "sentinel_contains": list(gate.contains),
    }
    note = "" if gate.tech == (tag,) else f"Gate: deepsec tech [{tag}]; kalkan uses {gate.how}."
    if extracted.sentinel_files:
        files = ", ".join(extracted.sentinel_files)
        note = (
            f"{note} The deepsec sentinel files ({files}) and their content check are "
            f"covered by the kalkan tech tag."
        ).strip()
    return requires, note


def _patterns(extracted: Extracted, curation: dict[str, Any]) -> list[dict[str, Any]]:
    if "patterns" in curation:
        patterns = [dict(item) for item in curation["patterns"]]
    else:
        if not extracted.patterns:
            raise ValueError(f"{extracted.file}: no regex/label list; curate 'patterns'")
        patterns = [dict(item) for item in extracted.patterns]
        label_format = curation.get("label_format")
        for pattern in patterns:
            if label_format:
                pattern["label"] = label_format.format(pattern["label"])
            if curation.get("near_all"):
                pattern["near"] = list(curation["near_all"])
            if curation.get("not_near_all"):
                pattern["not_near"] = list(curation["not_near_all"])
        for index, replacement in curation.get("replace", {}).items():
            patterns[index] = dict(replacement)
        for index in sorted(curation.get("drop", {}), reverse=True):
            del patterns[index]
    patterns.extend(dict(item) for item in curation.get("append", []))
    return _expand(patterns)


def build_spec(extracted: Extracted) -> dict[str, Any]:
    """Assemble, validate and return the canonical JSON form of one ported spec."""
    curation = CURATION.get(extracted.slug)
    if curation is None:
        raise ValueError(f"{extracted.file}: no curation entry for slug {extracted.slug}")
    requires, gate_note = _requires(extracted, curation)
    excludes = curation.get("exclude", _excludes(extracted))
    excludes = excludes + [g for g in curation.get("exclude_add", []) if g not in excludes]
    notes = [SURFACE] if curation.get("surface") else []
    if curation.get("notes"):
        notes.append(curation["notes"])
    if gate_note and "requires" not in curation:
        notes.append(gate_note)
    data = {
        "version": 1,
        "slug": extracted.slug,
        "description": extracted.description,
        "class": curation["class"],
        "cwe": list(curation["cwe"]),
        "noise_tier": extracted.noise_tier,
        "file_patterns": list(curation.get("file_patterns", extracted.file_patterns)),
        "exclude_file_patterns": excludes,
        "requires": requires,
        "file_contains": _expand(list(curation.get("file_contains", []))),
        "file_excludes": list(curation.get("file_excludes", [])),
        "patterns": _patterns(extracted, curation),
        "examples": list(extracted.examples),
        "source": {
            "repo": UPSTREAM_REPO,
            "commit": UPSTREAM_COMMIT,
            "path": UPSTREAM_PREFIX + extracted.file,
        },
        "notes": " ".join(notes),
    }
    return parse_spec(data, origin=extracted.file).to_dict()


def port_all() -> tuple[dict[str, dict[str, Any]], list[str]]:
    """Return ``({slug: spec}, errors)`` for every deepsec matcher."""
    specs: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    for path in sorted(SOURCE_DIR.glob("*.ts")):
        if path.name in NOT_MATCHERS:
            continue
        try:
            extracted = extract(path)
            spec = build_spec(extracted)
        except ValidationError as exc:
            errors.extend(exc.errors)
            continue
        except (ValueError, KeyError, IndexError) as exc:
            errors.append(f"{path.name}: {exc}")
            continue
        if spec["slug"] in specs:
            errors.append(f"{path.name}: duplicate slug {spec['slug']}")
        specs[spec["slug"]] = spec
    unused = sorted(set(CURATION) - set(specs))
    if unused and not errors:
        errors.append(f"curation entries without a matcher: {', '.join(unused)}")
    return specs, errors


def render(spec: dict[str, Any]) -> str:
    return json.dumps(spec, ensure_ascii=False, indent=2) + "\n"


def _native(path: Path) -> bool:
    """Return True for a kalkan-native spec (``source: null``): this script never writes it."""
    try:
        return json.loads(path.read_text(encoding="utf-8")).get("source") is None
    except (OSError, ValueError, AttributeError):
        return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--write", action="store_true", help="write rules/matchers/*.json")
    group.add_argument("--report", action="store_true", help="print a port summary as JSON")
    args = parser.parse_args(argv)

    specs, errors = port_all()
    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1
    if args.report:
        summary = {
            "matchers": len(specs),
            "patterns": sum(len(spec["patterns"]) for spec in specs.values()),
            "surface": sorted(s for s, spec in specs.items() if spec["class"] is None),
            "with_notes": {s: spec["notes"] for s, spec in specs.items() if spec["notes"]},
        }
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return 0
    if args.write:
        RULES_DIR.mkdir(parents=True, exist_ok=True)
        for slug, spec in specs.items():
            target = RULES_DIR / f"{slug}.json"
            target.write_text(render(spec), encoding="utf-8", newline="\n")
        stale = sorted(
            p.name for p in RULES_DIR.glob("*.json") if p.stem not in specs and not _native(p)
        )
        for name in stale:
            print(f"warning: {name} is not generated by this script", file=sys.stderr)
        print(f"wrote {len(specs)} specs to {RULES_DIR.relative_to(REPO_ROOT).as_posix()}")
        return 0
    drift = []
    for slug, spec in specs.items():
        target = RULES_DIR / f"{slug}.json"
        if not target.is_file() or target.read_text(encoding="utf-8") != render(spec):
            drift.append(target.name)
    if drift:
        print(
            f"{len(drift)} spec(s) differ from the port: {', '.join(drift[:10])}", file=sys.stderr
        )
        return 1
    print(f"{len(specs)} specs match the port")
    return 0


if __name__ == "__main__":
    sys.exit(main())
