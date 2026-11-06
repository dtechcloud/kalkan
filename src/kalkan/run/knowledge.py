# SPDX-License-Identifier: MIT
"""Load and select knowledge packs for the audit agents (ENGINE-SPEC sections 19 and 20).

The ``knowledge/`` tree holds Markdown packs: one owner file per vulnerability class under
``classes/``, domain packs under ``domains/``, and language packs under ``languages/``. Each
file starts with a front matter block (``key: value`` lines, some values comma lists) between
two ``---`` lines, then H2 sections, some with H3 subsections.

This module parses those files and selects the parts that a task role and the detected tech
need. The engine pastes the result into an agent prompt. It never changes a pack on disk.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

__all__ = [
    "ClassPack",
    "Corpus",
    "DomainPack",
    "KnowledgePack",
    "LanguagePack",
    "ROLE_SECTIONS",
    "Section",
    "Subsection",
    "domains_for_classes",
    "extract_for_role",
    "glossary_terms",
    "knowledge_dir",
    "languages_for_tech",
    "load_all",
    "load_class",
    "load_domain",
    "load_language",
    "methodology_text",
]

#: The H2 section names each role receives, in order (ENGINE-SPEC section 20).
ROLE_SECTIONS: dict[str, tuple[str, ...]] = {
    "hunter": (
        "Summary",
        "What it is",
        "What it is not",
        "Where to look",
        "Safe patterns",
        "Weak mitigations",
        "Examples",
        "False positive traps",
    ),
    "verifier": (
        "Summary",
        "What it is not",
        "Safe patterns",
        "Weak mitigations",
        "Verification checklist",
        "False positive traps",
    ),
    "poc_builder": (
        "Summary",
        "Dynamic test hints",
        "Examples",
    ),
}

#: Sections whose H3 subsections are filtered by the detected tech (ENGINE-SPEC section 20).
_TECH_FILTERED_SECTIONS = frozenset({"Where to look", "Examples"})

#: Default character cap for one extracted block (ENGINE-SPEC section 20).
DEFAULT_MAX_CHARS = 12000

#: Detected tech tag -> keyword tokens that may appear in a subsection title. A detected tag
#: not in the map matches itself. Tokens use no dots, because the title tokenizer splits on them
#: (``ASP.NET`` becomes ``asp`` and ``net``).
TECH_ALIASES: dict[str, set[str]] = {
    "python": {
        "python",
        "django",
        "flask",
        "fastapi",
        "starlette",
        "tornado",
        "aiohttp",
        "celery",
        "sanic",
        "pyramid",
    },
    "django": {"django", "python"},
    "flask": {"flask", "python"},
    "fastapi": {"fastapi", "starlette", "python"},
    "node": {
        "node",
        "javascript",
        "typescript",
        "express",
        "koa",
        "fastify",
        "nest",
        "nestjs",
        "hono",
    },
    "next": {"next", "nextjs", "react", "javascript", "typescript", "node"},
    "react": {"react", "javascript", "typescript"},
    "vue": {"vue", "javascript", "typescript"},
    "angular": {"angular", "typescript"},
    "express": {"express", "node", "javascript"},
    "nestjs": {"nestjs", "nest", "node", "typescript"},
    "fastify": {"fastify", "node", "javascript"},
    "koa": {"koa", "node", "javascript"},
    "hono": {"hono", "node", "javascript"},
    "java": {"java", "spring", "kotlin", "jakarta", "micronaut", "ktor"},
    "spring": {"spring", "java"},
    "kotlin": {"kotlin", "java", "ktor"},
    "go": {"go", "golang", "gin", "echo", "fiber", "chi", "gorilla"},
    "php": {
        "php",
        "laravel",
        "symfony",
        "wordpress",
        "slim",
        "yii",
        "cakephp",
        "codeigniter",
        "drupal",
    },
    "laravel": {"laravel", "php"},
    "symfony": {"symfony", "php"},
    "ruby": {"ruby", "rails", "sinatra", "grape", "rack"},
    "rails": {"rails", "ruby"},
    "dotnet": {"dotnet", "csharp", "c#", "net", "asp", "aspnet", "blazor"},
    "csharp": {"csharp", "c#", "dotnet", "net"},
    "rust": {"rust", "actix", "axum", "rocket", "tonic", "warp"},
    "c": {"c", "c++", "cpp", "userland", "kernel"},
    "cpp": {"cpp", "c++", "c"},
    "solidity": {"solidity", "evm", "vyper", "smart"},
}

#: Words in a subsection title that mean "applies to every stack".
_ALL_STACKS_MARKERS = (
    "all stack",
    "all-stack",
    "any stack",
    "cross-stack",
    "language-agnostic",
    "all languages",
    "every stack",
)

_LIST_KEYS = frozenset({"cwe", "owasp", "classes", "tech"})
_FRONT_MATTER_LINE = re.compile(r"^([A-Za-z0-9_]+):\s*(.*)$")
_TOKEN_SPLIT = re.compile(r"[^a-z0-9+#]+")
_GLOSSARY_TERM = re.compile(r"^\s*-\s+\*\*(.+?)\*\*")


@dataclass
class Subsection:
    """An H3 subsection: a title and its body text."""

    title: str
    body: str = ""


@dataclass
class Section:
    """An H2 section: a title, the body before the first subsection, and the subsections."""

    title: str
    body: str = ""
    subsections: list[Subsection] = field(default_factory=list)


@dataclass
class KnowledgePack:
    """One parsed knowledge file.

    ``kind`` is ``class``, ``domain`` or ``language``. ``front_matter`` keeps every key as a
    string. :meth:`meta_list` splits a comma list.
    """

    kind: str
    name: str
    path: Path
    front_matter: dict[str, str] = field(default_factory=dict)
    preamble: str = ""
    sections: list[Section] = field(default_factory=list)

    def meta_list(self, key: str) -> list[str]:
        """Return a front matter value as a list, split on commas, empty items dropped."""
        raw = self.front_matter.get(key, "")
        return [item.strip() for item in raw.split(",") if item.strip()]

    def section(self, title: str) -> Section | None:
        """Return the section with this exact title, or None."""
        for item in self.sections:
            if item.title == title:
                return item
        return None

    def section_titles(self) -> list[str]:
        """Return the section titles in document order."""
        return [item.title for item in self.sections]


# Aliases so callers can import a kind-specific name. The parse is the same for every kind.
ClassPack = KnowledgePack
DomainPack = KnowledgePack
LanguagePack = KnowledgePack


@dataclass
class Corpus:
    """Every parsed pack, grouped by kind. Keys are file stems."""

    classes: dict[str, KnowledgePack] = field(default_factory=dict)
    domains: dict[str, KnowledgePack] = field(default_factory=dict)
    languages: dict[str, KnowledgePack] = field(default_factory=dict)


# --- repository location -------------------------------------------------------------------


def knowledge_dir(repo_root: str | Path | None = None) -> Path:
    """Return the ``knowledge/`` directory.

    With ``repo_root``, use ``<repo_root>/knowledge``. Else use
    :func:`kalkan.resources.knowledge_dir` (the package data of a wheel, or the source checkout).
    Raise :class:`FileNotFoundError` when none is found.
    """
    if repo_root is not None:
        candidate = Path(repo_root) / "knowledge"
        if candidate.is_dir():
            return candidate
        raise FileNotFoundError(f"no knowledge directory at {candidate}")
    from kalkan.errors import KalkanError  # noqa: PLC0415
    from kalkan.resources import knowledge_dir as located  # noqa: PLC0415

    try:
        return located()
    except KalkanError as exc:
        raise FileNotFoundError(str(exc)) from exc


# --- parsing -------------------------------------------------------------------------------


def _split_front_matter(text: str) -> tuple[dict[str, str], list[str]]:
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}, lines
    meta: dict[str, str] = {}
    body_start = len(lines)
    for index in range(1, len(lines)):
        if lines[index].strip() == "---":
            body_start = index + 1
            break
        match = _FRONT_MATTER_LINE.match(lines[index])
        if match:
            meta[match.group(1)] = match.group(2).strip()
    return meta, lines[body_start:]


def _is_fence(stripped: str) -> bool:
    return stripped.startswith("```") or stripped.startswith("~~~")


def parse_text(text: str, *, kind: str, name: str, path: Path) -> KnowledgePack:
    """Parse the text of a knowledge file into a :class:`KnowledgePack`."""
    meta, body_lines = _split_front_matter(text)
    pack = KnowledgePack(kind=kind, name=name, path=path, front_matter=meta)
    preamble: list[str] = []
    current_section: Section | None = None
    current_sub: Subsection | None = None
    section_body: list[str] = []
    sub_body: list[str] = []
    in_fence = False

    def flush_body() -> None:
        nonlocal section_body, sub_body
        if current_sub is not None:
            current_sub.body = "\n".join(sub_body).strip("\n")
            sub_body = []
        elif current_section is not None:
            current_section.body = "\n".join(section_body).strip("\n")
            section_body = []

    for line in body_lines:
        stripped = line.strip()
        if _is_fence(stripped):
            in_fence = not in_fence
        if not in_fence and line.startswith("## ") and not line.startswith("### "):
            flush_body()
            current_section = Section(title=line[3:].strip())
            pack.sections.append(current_section)
            current_sub = None
            section_body = []
            continue
        if not in_fence and line.startswith("### "):
            flush_body()
            if current_section is None:
                current_section = Section(title="")
                pack.sections.append(current_section)
            current_sub = Subsection(title=line[4:].strip())
            current_section.subsections.append(current_sub)
            sub_body = []
            continue
        if current_section is None:
            preamble.append(line)
        elif current_sub is None:
            section_body.append(line)
        else:
            sub_body.append(line)
    flush_body()
    pack.preamble = "\n".join(preamble).strip("\n")
    return pack


def _load_file(path: Path, kind: str) -> KnowledgePack:
    if not path.is_file():
        raise FileNotFoundError(f"no {kind} pack at {path}")
    text = path.read_text(encoding="utf-8")
    return parse_text(text, kind=kind, name=path.stem, path=path)


def load_class(slug: str, repo_root: str | Path | None = None) -> ClassPack:
    """Load the class pack ``classes/<slug>.md``."""
    return _load_file(knowledge_dir(repo_root) / "classes" / f"{slug}.md", "class")


def load_domain(name: str, repo_root: str | Path | None = None) -> DomainPack:
    """Load the domain pack ``domains/<name>.md``."""
    return _load_file(knowledge_dir(repo_root) / "domains" / f"{name}.md", "domain")


def load_language(name: str, repo_root: str | Path | None = None) -> LanguagePack:
    """Load the language pack ``languages/<name>.md``."""
    return _load_file(knowledge_dir(repo_root) / "languages" / f"{name}.md", "language")


def load_all(repo_root: str | Path | None = None) -> Corpus:
    """Load every class, domain and language pack under ``knowledge/``."""
    base = knowledge_dir(repo_root)
    corpus = Corpus()
    for sub, target, kind in (
        ("classes", corpus.classes, "class"),
        ("domains", corpus.domains, "domain"),
        ("languages", corpus.languages, "language"),
    ):
        directory = base / sub
        if not directory.is_dir():
            continue
        for path in sorted(directory.glob("*.md")):
            target[path.stem] = _load_file(path, kind)
    return corpus


# --- tech matching and selection -----------------------------------------------------------


def _title_tokens(title: str) -> set[str]:
    return {token for token in _TOKEN_SPLIT.split(title.lower()) if token}


def _is_all_stacks(title: str) -> bool:
    lower = title.lower()
    return any(marker in lower for marker in _ALL_STACKS_MARKERS)


def _tech_keywords(tech: set[str]) -> set[str]:
    keywords: set[str] = set()
    for tag in tech:
        lower = tag.lower()
        keywords |= TECH_ALIASES.get(lower, {lower})
    return keywords


def _subsection_matches(title: str, tech: set[str], keywords: set[str]) -> bool:
    if _is_all_stacks(title):
        return True
    if not tech:
        return True
    return bool(_title_tokens(title) & keywords)


def _render_section(section: Section, tech: set[str], keywords: set[str]) -> str:
    parts = [f"## {section.title}".rstrip()]
    if section.body:
        parts.append(section.body)
    filtered = section.title in _TECH_FILTERED_SECTIONS
    if filtered and not any(
        _subsection_matches(sub.title, tech, keywords) and not _is_all_stacks(sub.title)
        for sub in section.subsections
    ):
        # No subsection names a detected stack (for example IaC file types when the tech list
        # has only languages): keep every subsection rather than none.
        filtered = False
    for sub in section.subsections:
        if filtered and not _subsection_matches(sub.title, tech, keywords):
            continue
        parts.append(f"### {sub.title}".rstrip())
        if sub.body:
            parts.append(sub.body)
    return "\n\n".join(parts)


def _select_sections(pack: KnowledgePack, wanted: tuple[str, ...]) -> list[Section]:
    by_title = {section.title: section for section in pack.sections}
    picked = [by_title[title] for title in wanted if title in by_title]
    if picked:
        return picked
    # A domain or language pack has none of the class section names. Fall back to its own
    # sections, minus Sources, so the orchestrator still gets the whole pack.
    return [s for s in pack.sections if s.title.lower() != "sources"]


def _truncate_paragraphs(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    kept: list[str] = []
    total = 0
    for paragraph in text.split("\n\n"):
        sep = 2 if kept else 0
        if total + sep + len(paragraph) > limit:
            break
        kept.append(paragraph)
        total += sep + len(paragraph)
    if kept:
        return "\n\n".join(kept)
    return text[:limit]


def extract_for_role(
    pack: KnowledgePack,
    role: str,
    tech: set[str],
    max_chars: int = DEFAULT_MAX_CHARS,
) -> str:
    """Return the sections of ``pack`` that ``role`` needs, filtered by ``tech``.

    The role decides the H2 sections (ENGINE-SPEC section 20). Under ``Where to look`` and
    ``Examples``, only H3 subsections whose title matches a detected tech keyword, or that apply
    to all stacks, are kept. An empty ``tech`` set keeps every subsection. The output is cut at
    a section boundary so that it stays within ``max_chars``.
    """
    if role not in ROLE_SECTIONS:
        raise ValueError(f"unknown role: {role!r}")
    tech = {item.lower() for item in tech}
    keywords = _tech_keywords(tech)
    sections = _select_sections(pack, ROLE_SECTIONS[role])
    blocks = [_render_section(section, tech, keywords) for section in sections]

    chosen: list[str] = []
    total = 0
    for block in blocks:
        sep = 2 if chosen else 0
        if total + sep + len(block) <= max_chars:
            chosen.append(block)
            total += sep + len(block)
            continue
        if not chosen:
            chosen.append(_truncate_paragraphs(block, max_chars))
        break
    return "\n\n".join(chosen)


# --- simple accessors ----------------------------------------------------------------------


def methodology_text(repo_root: str | Path | None = None) -> str:
    """Return the full text of ``methodology.md``."""
    return (knowledge_dir(repo_root) / "methodology.md").read_text(encoding="utf-8")


def glossary_terms(repo_root: str | Path | None = None) -> list[str]:
    """Return the English glossary terms, in order, without duplicates.

    Each term is the bold label of a list item, with any trailing parenthetical dropped, so that
    ``**JWT (JSON Web Token)**`` yields ``JWT``.
    """
    text = (knowledge_dir(repo_root) / "glossary.md").read_text(encoding="utf-8")
    terms: list[str] = []
    seen: set[str] = set()
    for line in text.splitlines():
        match = _GLOSSARY_TERM.match(line)
        if match is None:
            continue
        head = match.group(1).split(" (")[0].strip()
        if head and head not in seen:
            seen.add(head)
            terms.append(head)
    return terms


def languages_for_tech(tech: set[str], repo_root: str | Path | None = None) -> list[str]:
    """Return the language pack names whose ``tech`` front matter intersects ``tech``."""
    wanted = {item.lower() for item in tech}
    out: list[str] = []
    for name, pack in load_all(repo_root).languages.items():
        pack_tech = {item.lower() for item in pack.meta_list("tech")}
        if pack_tech & wanted:
            out.append(name)
    return sorted(out)


def domains_for_classes(classes: set[str], repo_root: str | Path | None = None) -> list[str]:
    """Return the domain pack names whose ``classes`` front matter intersects ``classes``."""
    wanted = set(classes)
    out: list[str] = []
    for name, pack in load_all(repo_root).domains.items():
        if set(pack.meta_list("classes")) & wanted:
            out.append(name)
    return sorted(out)
