# SPDX-License-Identifier: MIT
"""Render agent task prompts (docs/PHASES.md section 6, docs/ENGINE-SPEC.md section 19).

A prompt is ``_common.md`` + ``<type>.md`` + ``_footer.md`` from the ``kalkan/prompts`` package
data. :func:`render` replaces the placeholders in one pass: a ``{{NAME}}`` sequence inside an
inserted value (input JSON, knowledge, source excerpts) is never expanded again. Unknown
placeholders stay as they are.

- ``KNOWLEDGE`` per task type (ENGINE-SPEC 19): ``recon`` and ``critic`` get the methodology;
  ``hunt`` the methodology, the hunter extract of every unit class, the language packs of the
  detected tech and the ``Core discipline`` and ``Validation rules`` sections of the domain
  packs of the unit classes; ``verify`` and ``review`` the methodology and the verifier
  extract of the class; ``sca_reach`` the ``vulnerable-dependency`` verifier extract;
  ``poc_build`` the poc-builder extract of the class; ``translate`` and ``polish`` the glossary
  (the English terms that a Turkish text keeps). The block is capped at 24,000 characters and
  cut at a section boundary; with several classes each class extract gets an equal share, so
  every class keeps its summary.
- ``SOURCE_EXCERPTS`` (``verify``, ``review``, ``consolidate``, ``sca_reach``, ``poc_build``):
  numbered source (:func:`kalkan.findings.quote_verify.numbered_source`) around each cited
  location, at most 40 lines per location and 400 lines in total, read through
  :func:`kalkan.run.source.make_get_lines`. A ``consolidate`` task cites the first evidence item
  of every record first, then the other evidence items and quotes. Its template takes no
  ``KNOWLEDGE``.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterable
from importlib import resources
from typing import Any, Final

from kalkan.findings.fingerprint import GetLines
from kalkan.findings.quote_verify import numbered_source
from kalkan.run import knowledge
from kalkan.run.cleaning import clean_text
from kalkan.run.runfiles import run_tech
from kalkan.run.source import make_get_lines
from kalkan.run.state import RunContext
from kalkan.schema.loader import load_schema

__all__ = [
    "EXCERPT_LINES_PER_LOCATION",
    "EXCERPT_LINES_TOTAL",
    "KNOWLEDGE_MAX_CHARS",
    "LANG_NAMES",
    "cut_at_section",
    "knowledge_for",
    "render",
    "source_excerpts",
    "template",
]

LANG_NAMES: Final = {"tr": "Turkish", "en": "English"}
KNOWLEDGE_MAX_CHARS: Final = 24_000
CLASS_BLOCK_MAX_CHARS: Final = 12_000
EXCERPT_LINES_PER_LOCATION: Final = 40
EXCERPT_LINES_TOTAL: Final = 400
EXCERPT_LINE_CHARS: Final = 500
_MIN_BLOCK_CHARS: Final = 400
_PLACEHOLDER: Final = re.compile(r"\{\{([A-Z_]+)\}\}")
_DOMAIN_SECTIONS: Final = ("Core discipline", "Validation rules")
_BACKTICKS: Final = re.compile(r"`+")
_EXCERPT_TYPES: Final = frozenset({"verify", "review", "consolidate", "sca_reach", "poc_build"})


# ---------------------------------------------------------------------------------------------
# Templates


def _package_text(*parts: str) -> str:
    resource = resources.files("kalkan").joinpath("prompts")
    for part in parts:
        resource = resource.joinpath(part)
    return resource.read_text(encoding="utf-8")


def template(task_type: str) -> str:
    """Return the unrendered prompt of ``task_type``: common rules, task part and footer."""
    parts = [_package_text("_common.md"), _package_text(f"{task_type}.md")]
    parts.append(_package_text("_footer.md"))
    return "\n".join(part.rstrip("\n") + "\n" for part in parts)


def _example(task_type: str) -> str:
    try:
        return _package_text("examples", f"{task_type}.json").strip()
    except (FileNotFoundError, OSError):
        return "{}"


def _schema(task_type: str) -> str:
    return json.dumps(load_schema(f"task-{task_type}"), ensure_ascii=False, separators=(",", ":"))


# ---------------------------------------------------------------------------------------------
# Knowledge


def cut_at_section(text: str, limit: int) -> str:
    """Return ``text`` cut to at most ``limit`` characters at a heading or paragraph boundary."""
    if len(text) <= limit:
        return text
    head = text[:limit]
    for marker in ("\n## ", "\n### ", "\n#### "):
        index = head.rfind(marker)
        if index > limit // 4:
            return head[:index].rstrip() + "\n\n[...]"
    index = head.rfind("\n\n")
    if index > limit // 4:
        return head[:index].rstrip() + "\n\n[...]"
    return head.rstrip() + " [...]"


class _Blocks:
    """Collect knowledge blocks under the total character cap."""

    def __init__(self, limit: int = KNOWLEDGE_MAX_CHARS) -> None:
        self.limit = limit
        self.parts: list[str] = []
        self.used = 0

    @property
    def left(self) -> int:
        return self.limit - self.used

    def add(self, title: str, text: str, max_chars: int | None = None) -> None:
        body = text.strip()
        if not body:
            return
        heading = f"#### {title}\n\n"
        room = self.left - len(heading) - 2
        if max_chars is not None:
            room = min(room, max_chars)
        if room < _MIN_BLOCK_CHARS:
            return
        block = heading + cut_at_section(body, room)
        self.parts.append(block)
        self.used += len(block) + 2

    def text(self) -> str:
        return "\n\n".join(self.parts) if self.parts else "(No knowledge pack applies.)"


def _safe(loader: Callable[[], str]) -> str:
    try:
        return loader()
    except (FileNotFoundError, OSError, ValueError):
        return ""


def _class_extract(slug: object, role: str, tech: set[str], max_chars: int) -> str:
    if not isinstance(slug, str) or not slug:
        return ""
    return _safe(
        lambda: knowledge.extract_for_role(knowledge.load_class(slug), role, tech, max_chars)
    )


def _domain_text(name: str) -> str:
    pack = knowledge.load_domain(name)
    parts = []
    for title in _DOMAIN_SECTIONS:
        section = pack.section(title)
        if section is not None:
            body = [section.body] + [
                f"### {sub.title}\n\n{sub.body}" for sub in section.subsections
            ]
            parts.append(f"## {title}\n\n" + "\n\n".join(item for item in body if item))
    return "\n\n".join(parts)


def _language_text(name: str, tech: set[str], max_chars: int) -> str:
    return knowledge.extract_for_role(knowledge.load_language(name), "hunter", tech, max_chars)


def _unit_classes(task_input: dict[str, Any]) -> list[str]:
    units = task_input.get("units")
    classes: list[str] = []
    if isinstance(units, list):
        for unit in units:
            slug = unit.get("class") if isinstance(unit, dict) else None
            if isinstance(slug, str) and slug and slug not in classes:
                classes.append(slug)
    return classes


def _claim_class(task_input: dict[str, Any], key: str) -> str | None:
    claim = task_input.get(key)
    slug = claim.get("class") if isinstance(claim, dict) else None
    return slug if isinstance(slug, str) and slug else None


def knowledge_for(ctx: RunContext, task_type: str, task_input: dict[str, Any]) -> str:
    """Return the ``{{KNOWLEDGE}}`` block of a task (module docstring)."""
    tech = set(run_tech(ctx))
    blocks = _Blocks()
    if task_type in ("translate", "polish"):
        blocks.add(
            "Glossary",
            _safe(lambda: (knowledge.knowledge_dir() / "glossary.md").read_text(encoding="utf-8")),
        )
        return blocks.text()
    if task_type in ("recon", "critic", "hunt", "verify", "review"):
        blocks.add("Methodology", _safe(knowledge.methodology_text))
    if task_type == "hunt":
        classes = _unit_classes(task_input)
        share = max(1500, min(CLASS_BLOCK_MAX_CHARS, blocks.left // (len(classes) + 1)))
        for slug in classes:
            blocks.add(f"Class: {slug}", _class_extract(slug, "hunter", tech, share), share)
        for name in _safe_list(lambda: knowledge.languages_for_tech(tech)):
            limit = min(CLASS_BLOCK_MAX_CHARS, max(_MIN_BLOCK_CHARS, blocks.left - 100))
            text = _safe(lambda n=name, cap=limit: _language_text(n, tech, cap))
            blocks.add(f"Language: {name}", text)
        for name in _safe_list(lambda: knowledge.domains_for_classes(set(classes))):
            blocks.add(f"Domain: {name}", _safe(lambda n=name: _domain_text(n)))
    elif task_type in ("verify", "review"):
        slug = _claim_class(task_input, "claim" if task_type == "verify" else "finding")
        blocks.add(f"Class: {slug}", _class_extract(slug, "verifier", tech, CLASS_BLOCK_MAX_CHARS))
    elif task_type == "sca_reach":
        blocks.add(
            "Class: vulnerable-dependency",
            _class_extract("vulnerable-dependency", "verifier", tech, CLASS_BLOCK_MAX_CHARS),
        )
    elif task_type == "poc_build":
        slug = _claim_class(task_input, "finding")
        blocks.add(
            f"Class: {slug}", _class_extract(slug, "poc_builder", tech, CLASS_BLOCK_MAX_CHARS)
        )
    return blocks.text()


def _safe_list(loader: Callable[[], list[str]]) -> list[str]:
    try:
        return loader()
    except (FileNotFoundError, OSError, ValueError):
        return []


# ---------------------------------------------------------------------------------------------
# Source excerpts


def _locations(task_type: str, task_input: dict[str, Any]) -> list[tuple[str, int | None]]:
    items: list[Any] = []
    if task_type == "verify":
        claim = task_input.get("claim")
        if isinstance(claim, dict):
            items = [*(claim.get("trace") or []), *(claim.get("evidence") or [])]
    elif task_type in ("poc_build", "review"):
        finding = task_input.get("finding")
        if isinstance(finding, dict):
            items = [*(finding.get("trace") or []), *(finding.get("evidence") or [])]
    elif task_type == "sca_reach":
        items = list(task_input.get("locations") or [])
    elif task_type == "consolidate":
        records = [item for item in task_input.get("records") or [] if isinstance(item, dict)]
        # The first evidence item of every record first, so that the cap keeps one per record.
        items = [record["evidence"][0] for record in records if record.get("evidence")]
        for record in records:
            items += [*(record.get("evidence") or [])[1:], *(record.get("quotes") or [])]
    found: list[tuple[str, int | None]] = []
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get("file"), str):
            continue
        line = item.get("line")
        location = (item["file"], line if isinstance(line, int) and line >= 1 else None)
        if location not in found:
            found.append(location)
    return found


def _windows(lines: Iterable[int | None], length: int) -> list[tuple[int, int]]:
    half = EXCERPT_LINES_PER_LOCATION // 2
    spans = []
    for line in lines:
        if line is None:
            start, stop = 1, EXCERPT_LINES_PER_LOCATION
        else:
            start = max(1, line - (half - 1))
            stop = start + EXCERPT_LINES_PER_LOCATION - 1
        stop = min(stop, length)
        if start <= stop:
            spans.append((start, stop))
    merged: list[tuple[int, int]] = []
    for start, stop in sorted(spans):
        if merged and start <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(stop, merged[-1][1]))
        else:
            merged.append((start, stop))
    return merged


def _fence(text: str) -> str:
    longest = max((len(run) for run in _BACKTICKS.findall(text)), default=0)
    return "`" * max(3, longest + 1)


def source_excerpts(
    ctx: RunContext,
    task_type: str,
    task_input: dict[str, Any],
    get_lines: GetLines | None = None,
) -> str:
    """Return the ``{{SOURCE_EXCERPTS}}`` block of a task (module docstring)."""
    locations = _locations(task_type, task_input)
    if not locations:
        return "(No source location is cited in the input.)"
    lines_for = get_lines or make_get_lines(ctx.target_dir)
    by_file: dict[str, list[int | None]] = {}
    for file, line in locations:
        by_file.setdefault(file, []).append(line)
    blocks: list[str] = []
    total = 0
    for file, lines in by_file.items():
        shown = clean_text(file, 300) or "(unnamed file)"
        source = lines_for(file)
        if source is None:
            blocks.append(f"#### {shown}\n\n(The file is not available in the target copy.)")
            continue
        # numbered_source ends every row with a newline and drops a final empty line.
        numbered = numbered_source("\n".join(source)).split("\n")[:-1]
        for start, stop in _windows(lines, len(numbered)):
            if total >= EXCERPT_LINES_TOTAL:
                break
            stop = min(stop, start + EXCERPT_LINES_TOTAL - total - 1)
            excerpt = [
                row if len(row) <= EXCERPT_LINE_CHARS else row[:EXCERPT_LINE_CHARS] + " [...]"
                for row in numbered[start - 1 : stop]
            ]
            total += len(excerpt)
            body = "\n".join(excerpt)
            fence = _fence(body)
            blocks.append(f"#### {shown}, lines {start}-{stop}\n\n{fence}text\n{body}\n{fence}")
    if total >= EXCERPT_LINES_TOTAL:
        blocks.append(f"(Excerpts stop at {EXCERPT_LINES_TOTAL} lines; read the files for more.)")
    return "\n\n".join(blocks)


# ---------------------------------------------------------------------------------------------
# Rendering


def render(
    ctx: RunContext,
    task_type: str,
    task_id: str,
    task_input: dict[str, Any],
    *,
    get_lines: GetLines | None = None,
) -> str:
    """Return the rendered prompt of a task (module docstring)."""
    text = template(task_type)
    names = set(_PLACEHOLDER.findall(text))
    values: dict[str, str] = {
        "TASK_ID": task_id,
        "RUN_ID": ctx.run_id,
        "TARGET_DIR": ctx.target_dir.absolute().as_posix(),
        "RESULT_FILE": (ctx.task_dir(task_id) / "result.json").absolute().as_posix(),
        "LANG_NAME": LANG_NAMES.get(ctx.lang, "Turkish"),
        "INPUT_JSON": json.dumps(task_input, ensure_ascii=False, indent=2),
        "SCHEMA": _schema(task_type),
        "EXAMPLE": _example(task_type),
    }
    if "KNOWLEDGE" in names:
        values["KNOWLEDGE"] = knowledge_for(ctx, task_type, task_input)
    if "SOURCE_EXCERPTS" in names:
        values["SOURCE_EXCERPTS"] = (
            source_excerpts(ctx, task_type, task_input, get_lines)
            if task_type in _EXCERPT_TYPES
            else ""
        )
    return _PLACEHOLDER.sub(lambda match: values.get(match.group(1), match.group(0)), text)
