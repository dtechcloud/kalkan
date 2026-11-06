# SPDX-License-Identifier: MIT
"""Corpus tests for the real knowledge/ tree (ENGINE-SPEC sections 3 and 20).

Part (a) checks every file that exists today. Part (b),
test_all_taxonomy_classes_have_a_pack, checks that every taxonomy class has a pack. It fails
until all class packs are written. That is expected, so it is not marked xfail.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from kalkan.run import knowledge as k

KNOWLEDGE = k.knowledge_dir()
REPO = KNOWLEDGE.parent
SPEC = REPO / "docs" / "ENGINE-SPEC.md"

CLASS_KEYS = ("slug", "title_en", "title_tr", "cwe", "owasp", "sources")
CLASS_SECTIONS = (
    "Summary",
    "What it is",
    "What it is not",
    "Where to look",
    "Safe patterns",
    "Weak mitigations",
    "Verification checklist",
    "Examples",
    "Dynamic test hints",
    "False positive traps",
    "Sources",
)
DOMAIN_KEYS = ("name", "title", "classes", "when_to_use", "sources")
DOMAIN_SECTIONS = (
    "Core discipline",
    "Attack classes",
    "Universal moves",
    "Validation rules",
    "Sources",
)
LANGUAGE_KEYS = ("name", "title", "tech", "sources")
LANGUAGE_SECTIONS = (
    "Sources of attacker input",
    "Dangerous sinks",
    "Framework notes",
    "Safe idioms",
    "Common false positives",
    "Sources",
)

EXPECTED_DOMAINS = {
    "ai-and-llm",
    "client-side",
    "cloud-and-deployment",
    "data-isolation-and-lifecycle",
    "desktop-mobile-and-local-ipc",
    "memory-safety-and-binary",
    "protocols-rpc-and-messaging",
    "resource-exhaustion-and-availability",
    "supply-chain-and-release",
    "web-protocol-and-auth",
}

REQUIRED_GLOSSARY = (
    "SQL injection",
    "XSS",
    "SSRF",
    "IDOR",
    "CSRF",
    "payload",
    "sink",
    "source",
    "taint",
    "PoC",
    "SBOM",
    "CVE",
    "CWE",
    "CVSS",
    "SARIF",
    "race condition",
    "deserialization",
    "prototype pollution",
    "open redirect",
    "rate limiting",
    "brute force",
    "token",
    "JWT",
    "session",
    "cookie",
    "hardening",
    "false positive",
    "fingerprint",
    "lockfile",
    "reachability",
)

KIB = 1024


def _spec_slugs() -> list[str]:
    """Return the class slugs from the ENGINE-SPEC section 3 table, in table order."""
    text = SPEC.read_text(encoding="utf-8")
    start = text.index("## 3.")
    end = text.index("## 4.", start)
    rows = re.findall(r"^\|\s*`([a-z0-9-]+)`\s*\|", text[start:end], flags=re.MULTILINE)
    return rows


SLUGS = _spec_slugs()


def _files(sub: str) -> list[Path]:
    directory = KNOWLEDGE / sub
    return sorted(directory.glob("*.md")) if directory.is_dir() else []


def _ids(paths: list[Path]) -> list[str]:
    return [p.stem for p in paths]


#: Keys that may be empty: some classes have no default CWE or OWASP (ENGINE-SPEC section 3).
MAY_BE_EMPTY = frozenset({"cwe", "owasp"})


def _missing(pack: k.KnowledgePack, keys: tuple[str, ...]) -> list[str]:
    """Return keys that are absent, or empty when they must have a value."""
    meta = pack.front_matter
    return [key for key in keys if key not in meta or (not meta[key] and key not in MAY_BE_EMPTY)]


def _missing_sections(pack: k.KnowledgePack, names: tuple[str, ...]) -> list[str]:
    titles = set(pack.section_titles())
    return [name for name in names if name not in titles]


def test_spec_lists_42_class_slugs():
    assert len(SLUGS) == 42
    assert len(set(SLUGS)) == 42


# --- part (a): every existing file is valid ------------------------------------------------


@pytest.mark.parametrize("path", _files("classes"), ids=_ids(_files("classes")))
def test_class_pack_is_valid(path: Path):
    pack = k.load_class(path.stem)
    assert _missing(pack, CLASS_KEYS) == [], f"{path.name}: missing front matter keys"
    assert _missing_sections(pack, CLASS_SECTIONS) == [], f"{path.name}: missing sections"
    slug = pack.front_matter["slug"]
    assert slug == path.stem, f"{path.name}: slug {slug!r} does not match the file name"
    assert slug in SLUGS, f"{path.name}: slug {slug!r} is not in ENGINE-SPEC section 3"


@pytest.mark.parametrize("path", _files("domains"), ids=_ids(_files("domains")))
def test_domain_pack_is_valid(path: Path):
    pack = k.load_domain(path.stem)
    assert _missing(pack, DOMAIN_KEYS) == [], f"{path.name}: missing front matter keys"
    assert _missing_sections(pack, DOMAIN_SECTIONS) == [], f"{path.name}: missing sections"
    assert pack.front_matter["name"] == path.stem
    unknown = [c for c in pack.meta_list("classes") if c not in SLUGS]
    assert unknown == [], f"{path.name}: unknown class slugs {unknown}"
    attack = pack.section("Attack classes")
    assert attack is not None and attack.subsections, f"{path.name}: no attack classes"
    size = path.stat().st_size
    assert 4 * KIB <= size <= 10 * KIB, f"{path.name}: {size} bytes, expected 4-10 KiB"


@pytest.mark.parametrize("path", _files("languages"), ids=_ids(_files("languages")))
def test_language_pack_is_valid(path: Path):
    pack = k.load_language(path.stem)
    assert _missing(pack, LANGUAGE_KEYS) == [], f"{path.name}: missing front matter keys"
    assert _missing_sections(pack, LANGUAGE_SECTIONS) == [], f"{path.name}: missing sections"
    assert pack.front_matter["name"] == path.stem
    sinks = pack.section("Dangerous sinks")
    assert sinks is not None and sinks.subsections, f"{path.name}: no sink groups"
    for sub in sinks.subsections:
        slug = sub.title.split(":")[0].strip()
        assert slug in SLUGS, f"{path.name}: sink group {sub.title!r} is not a class slug"
    size = path.stat().st_size
    assert 4 * KIB <= size <= 12 * KIB, f"{path.name}: {size} bytes, expected 4-12 KiB"


def test_all_ten_domain_packs_exist():
    assert set(_ids(_files("domains"))) == EXPECTED_DOMAINS


def test_methodology_is_under_8_kib_and_names_the_three_questions():
    path = KNOWLEDGE / "methodology.md"
    assert path.stat().st_size < 8 * KIB
    text = k.methodology_text()
    for word in ("attacker_control", "privilege_boundary", "unmitigated", "needs_validation"):
        assert word in text


def test_glossary_has_required_terms():
    terms = k.glossary_terms()
    assert len(terms) >= 60
    missing = [t for t in REQUIRED_GLOSSARY if t not in terms]
    assert missing == []


@pytest.mark.parametrize("role", sorted(k.ROLE_SECTIONS))
def test_every_pack_extracts_within_budget(role: str):
    corpus = k.load_all()
    packs = [*corpus.classes.values(), *corpus.domains.values(), *corpus.languages.values()]
    for pack in packs:
        out = k.extract_for_role(pack, role, tech={"python"})
        assert len(out) <= k.DEFAULT_MAX_CHARS, f"{pack.kind} {pack.name}: block too large"


# --- part (b): every taxonomy class has a pack ---------------------------------------------


def test_all_taxonomy_classes_have_a_pack():
    present = set(_ids(_files("classes")))
    missing = [slug for slug in SLUGS if slug not in present]
    assert missing == [], f"class packs missing: {missing}"
