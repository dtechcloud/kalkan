# SPDX-License-Identifier: MIT
"""Tests for kalkan.run.knowledge: parsing, role selection, tech filtering, truncation."""

from __future__ import annotations

from pathlib import Path

import pytest

from kalkan.run import knowledge as k

CLASS_PACK = """\
---
slug: demo
title_en: Demo class
title_tr: Demo sinifi
cwe: CWE-1, CWE-2
owasp: A03:2021
sources: upstream
---

# Demo class

Intro line that is preamble.

## Summary

A short summary.

## What it is

The real thing.

## Where to look

Intro to where to look.

### Python

Python guidance.

### Node.js / Express

Node guidance.

### All stacks

Shared guidance.

## Verification checklist

Verifier only content.

## Examples

### Python

```python
# a comment with ## inside a fence, not a heading
query = "..."
```

### Go

Go example.

## Sources

Upstream credit.
"""


def _write(base: Path, rel: str, text: str) -> None:
    path = base / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def _mini_repo(tmp_path: Path) -> Path:
    """Create a tiny knowledge tree and return the repo root."""
    kd = tmp_path / "knowledge"
    _write(kd, "classes/demo.md", CLASS_PACK)
    _write(
        kd,
        "domains/web.md",
        "---\nname: web\ntitle: Web\nclasses: sqli, xss\n"
        "when_to_use: web apps\nsources: upstream\n---\n\n"
        "## Core discipline\n\nBe careful.\n\n## Sources\n\nx\n",
    )
    _write(
        kd,
        "languages/python.md",
        "---\nname: python\ntitle: Python\ntech: python, django, flask\nsources: upstream\n---\n\n"
        "## Dangerous sinks\n\nsinks.\n\n## Sources\n\nx\n",
    )
    _write(
        kd,
        "languages/go.md",
        "---\nname: go\ntitle: Go\ntech: go\nsources: upstream\n---\n\n"
        "## Dangerous sinks\n\nsinks.\n\n## Sources\n\nx\n",
    )
    _write(kd, "methodology.md", "# Method\n\nEvidence first.\n")
    _write(
        kd,
        "glossary.md",
        "# Glossary\n\n- **SQL injection** — bir aciklama.\n"
        "- **JWT (JSON Web Token)** — imzali token.\n"
        "- **JWT (JSON Web Token)** — tekrar, ayni terim.\n",
    )
    return tmp_path


# --- parsing -------------------------------------------------------------------------------


def test_parse_front_matter_and_comma_list():
    pack = k.parse_text(CLASS_PACK, kind="class", name="demo", path=Path("demo.md"))
    assert pack.front_matter["slug"] == "demo"
    assert pack.front_matter["title_en"] == "Demo class"
    assert pack.meta_list("cwe") == ["CWE-1", "CWE-2"]
    assert pack.meta_list("missing") == []


def test_parse_sections_and_subsections():
    pack = k.parse_text(CLASS_PACK, kind="class", name="demo", path=Path("demo.md"))
    assert "Summary" in pack.section_titles()
    assert "Where to look" in pack.section_titles()
    where = pack.section("Where to look")
    assert where is not None
    assert where.body.startswith("Intro to where to look")
    assert [s.title for s in where.subsections] == ["Python", "Node.js / Express", "All stacks"]


def test_parse_preamble_is_separate():
    pack = k.parse_text(CLASS_PACK, kind="class", name="demo", path=Path("demo.md"))
    assert "preamble" in pack.preamble
    assert "preamble" not in pack.section("Summary").body


def test_parse_ignores_heading_like_line_inside_code_fence():
    pack = k.parse_text(CLASS_PACK, kind="class", name="demo", path=Path("demo.md"))
    examples = pack.section("Examples")
    python_example = next(s for s in examples.subsections if s.title == "Python")
    assert "## inside a fence" in python_example.body
    # The fenced "##" line must not have become its own section.
    assert "inside a fence, not a heading" not in pack.section_titles()


# --- role selection ------------------------------------------------------------------------


def test_extract_for_role_hunter_keeps_hunter_sections_only():
    pack = k.parse_text(CLASS_PACK, kind="class", name="demo", path=Path("demo.md"))
    out = k.extract_for_role(pack, "hunter", tech=set())
    assert "## Summary" in out
    assert "## Where to look" in out
    assert "## Examples" in out
    assert "## Verification checklist" not in out
    assert "## Sources" not in out


def test_extract_for_role_verifier_keeps_checklist_not_where_to_look():
    pack = k.parse_text(CLASS_PACK, kind="class", name="demo", path=Path("demo.md"))
    out = k.extract_for_role(pack, "verifier", tech=set())
    assert "## Verification checklist" in out
    assert "## Where to look" not in out
    assert "## Examples" not in out


def test_extract_for_role_unknown_role_raises():
    pack = k.parse_text(CLASS_PACK, kind="class", name="demo", path=Path("demo.md"))
    with pytest.raises(ValueError):
        k.extract_for_role(pack, "critic", tech=set())


# --- tech filtering ------------------------------------------------------------------------


def test_tech_filter_keeps_matching_and_all_stacks():
    pack = k.parse_text(CLASS_PACK, kind="class", name="demo", path=Path("demo.md"))
    out = k.extract_for_role(pack, "hunter", tech={"python"})
    assert "### Python" in out
    assert "### All stacks" in out
    assert "### Node.js / Express" not in out
    # Examples subsections are tech-filtered too.
    assert "### Go" not in out


def test_tech_filter_django_maps_to_python_subsection():
    pack = k.parse_text(CLASS_PACK, kind="class", name="demo", path=Path("demo.md"))
    out = k.extract_for_role(pack, "hunter", tech={"django"})
    assert "### Python" in out
    assert "### Node.js / Express" not in out


def test_tech_filter_empty_tech_keeps_all_subsections():
    pack = k.parse_text(CLASS_PACK, kind="class", name="demo", path=Path("demo.md"))
    out = k.extract_for_role(pack, "hunter", tech=set())
    assert "### Python" in out
    assert "### Node.js / Express" in out
    assert "### All stacks" in out


def test_tech_token_does_not_overmatch_substring():
    # "go" must not match a subsection whose title merely contains the letters "go".
    text = (
        "---\nslug: d\ntitle_en: D\ntitle_tr: D\ncwe: CWE-1\nowasp: A01:2021\nsources: x\n---\n\n"
        "## Where to look\n\n### Django\n\nx\n\n### Go\n\ny\n"
    )
    pack = k.parse_text(text, kind="class", name="d", path=Path("d.md"))
    out = k.extract_for_role(pack, "hunter", tech={"go"})
    assert "### Go" in out
    assert "### Django" not in out


# --- truncation ----------------------------------------------------------------------------


def _many_section_pack() -> k.KnowledgePack:
    body = "x" * 200
    text = "---\nslug: t\ntitle_en: T\ntitle_tr: T\n"
    text += "cwe: CWE-1\nowasp: A01:2021\nsources: x\n---\n\n"
    text += f"## Summary\n\n{body}\n\n## What it is\n\n{body}\n\n## What it is not\n\n{body}\n"
    return k.parse_text(text, kind="class", name="t", path=Path("t.md"))


def test_truncation_stops_at_section_boundary():
    pack = _many_section_pack()
    out = k.extract_for_role(pack, "hunter", tech=set(), max_chars=260)
    assert len(out) <= 260
    assert "## Summary" in out
    # The second section does not fit, so it is dropped whole (clean boundary).
    assert "## What it is" not in out


def test_truncation_of_single_oversized_section_cuts_paragraphs():
    text = (
        "---\nslug: t\ntitle_en: T\ntitle_tr: T\ncwe: CWE-1\nowasp: A01:2021\nsources: x\n---\n\n"
        "## Summary\n\n" + "\n\n".join(f"paragraph {i} " + "y" * 40 for i in range(10))
    )
    pack = k.parse_text(text, kind="class", name="t", path=Path("t.md"))
    out = k.extract_for_role(pack, "hunter", tech=set(), max_chars=200)
    assert len(out) <= 200
    assert out.startswith("## Summary")
    assert "paragraph 0" in out


# --- file loading and accessors ------------------------------------------------------------


def test_knowledge_dir_from_repo_root(tmp_path):
    repo = _mini_repo(tmp_path)
    assert k.knowledge_dir(repo) == repo / "knowledge"


def test_knowledge_dir_missing_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        k.knowledge_dir(tmp_path / "nope")


def test_load_class_domain_language(tmp_path):
    repo = _mini_repo(tmp_path)
    cls = k.load_class("demo", repo_root=repo)
    assert cls.kind == "class"
    assert cls.name == "demo"
    dom = k.load_domain("web", repo_root=repo)
    assert dom.meta_list("classes") == ["sqli", "xss"]
    lang = k.load_language("python", repo_root=repo)
    assert lang.meta_list("tech") == ["python", "django", "flask"]


def test_load_class_missing_raises(tmp_path):
    repo = _mini_repo(tmp_path)
    with pytest.raises(FileNotFoundError):
        k.load_class("absent", repo_root=repo)


def test_load_all_groups_by_kind(tmp_path):
    repo = _mini_repo(tmp_path)
    corpus = k.load_all(repo)
    assert set(corpus.classes) == {"demo"}
    assert set(corpus.domains) == {"web"}
    assert set(corpus.languages) == {"python", "go"}


def test_languages_for_tech(tmp_path):
    repo = _mini_repo(tmp_path)
    assert k.languages_for_tech({"django"}, repo_root=repo) == ["python"]
    assert k.languages_for_tech({"go"}, repo_root=repo) == ["go"]
    assert k.languages_for_tech({"python", "go"}, repo_root=repo) == ["go", "python"]
    assert k.languages_for_tech({"rust"}, repo_root=repo) == []


def test_domains_for_classes(tmp_path):
    repo = _mini_repo(tmp_path)
    assert k.domains_for_classes({"sqli"}, repo_root=repo) == ["web"]
    assert k.domains_for_classes({"idor"}, repo_root=repo) == []


def test_methodology_text(tmp_path):
    repo = _mini_repo(tmp_path)
    assert "Evidence first" in k.methodology_text(repo)


def test_glossary_terms_dedupes_and_strips_parenthetical(tmp_path):
    repo = _mini_repo(tmp_path)
    terms = k.glossary_terms(repo)
    assert terms == ["SQL injection", "JWT"]


def test_extract_for_role_falls_back_for_language_pack(tmp_path):
    repo = _mini_repo(tmp_path)
    lang = k.load_language("python", repo_root=repo)
    out = k.extract_for_role(lang, "hunter", tech=set())
    # The language pack has none of the class section names, so its own sections are used,
    # minus Sources.
    assert "## Dangerous sinks" in out
    assert "## Sources" not in out


def test_filter_keeps_all_subsections_when_none_match_the_tech():
    from kalkan.run import knowledge

    pack = knowledge.parse_text(
        "---\nslug: demo\n---\n\n## Where to look\n\n### Terraform\n\ntf body\n\n"
        "### Kubernetes\n\nk8s body\n",
        kind="class",
        name="demo",
        path=Path("demo.md"),
    )
    out = knowledge.extract_for_role(pack, "hunter", {"python"})
    assert "### Terraform" in out and "### Kubernetes" in out
    narrowed = knowledge.extract_for_role(pack, "hunter", {"terraform"})
    assert "### Terraform" in narrowed and "### Kubernetes" not in narrowed
