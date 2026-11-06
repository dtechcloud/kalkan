# SPDX-License-Identifier: MIT
"""Tests for the Markdown and HTML renderers and the UI strings (escaping of hostile text)."""

from __future__ import annotations

import copy
import re
import shutil
from html.parser import HTMLParser
from pathlib import Path

import pytest

from kalkan.findings.merge import merge_run
from kalkan.report import i18n
from kalkan.report.model import build_model
from kalkan.report.render_html import h, render_html
from kalkan.report.render_md import md_code, md_fence, md_inline, md_text, render_markdown

GOLDEN = Path(__file__).resolve().parents[1] / "golden" / "report"
RUN_ID = "20261015T120000Z-shop-a1b2"
HOSTILE = "Evil | `tick` ``double`` <script>alert(1)</script> & <img src=x onerror=alert(2)>"


@pytest.fixture(scope="module")
def model(tmp_path_factory):
    target = tmp_path_factory.mktemp("report") / RUN_ID
    shutil.copytree(GOLDEN / "run" / RUN_ID, target)
    merge_run(target)
    built = build_model(
        target, generated_at="2026-10-15T12:30:00Z", installed_tools=GOLDEN / "installed.json"
    )
    # Make the confirmed SQL injection hostile, everywhere a target text can appear.
    finding = built.confirmed[0]
    finding["title"] = HOSTILE
    finding["description"] = f"# Heading\n- item\n1. step\n\n{HOSTILE}"
    finding["trace"][0]["description"] = HOSTILE
    finding["trace"][0]["scope"] = "a|b`c"
    finding["execution"]["payloads"] = ["```\n</code></pre><script>alert(3)</script>\n````"]
    finding["remediation"]["code_changes"][0]["fixed_code"] = "x = '</pre>'  # ```"
    built.tool_results[0]["title"] = HOSTILE
    return built


# ---------------------------------------------------------------------------------------------
# Markdown helpers


def test_md_inline_escapes_tables_backticks_and_html():
    text = md_inline(HOSTILE)
    assert "|" not in text.replace("\\|", "")
    assert "<" not in text and ">" not in text
    assert "&lt;script&gt;" in text
    assert "\\`tick\\`" in text
    assert "&amp; " in text
    assert md_inline("a\nb") == "a b"


def test_md_text_neutralizes_block_syntax():
    text = md_text("# title\n- item\n+ plus\n1. one\n2) two\n    indented code\n> quote\n=====")
    lines = text.split("\n")
    assert lines[0] == "\\# title"
    assert lines[1] == "\\- item"
    assert lines[2] == "\\+ plus"
    assert lines[3] == "1\\. one"
    assert lines[4] == "2\\) two"
    assert lines[5] == "indented code"
    assert lines[6] == "&gt; quote"
    assert lines[7] == "\\====="
    assert md_text("a\n\n\n\nb") == "a\n\nb"


def test_md_code_uses_a_longer_fence():
    assert md_code("plain") == "`plain`"
    assert md_code("a`b") == "``a`b``"
    assert md_code("``x``") == "``` ``x`` ```"
    assert md_code("a|b", table=True) == "`a\\|b`"
    assert md_code("") == ""


def test_md_fence_is_longer_than_any_backtick_run():
    block = md_fence("before\n````\nafter")
    first, *_, last = block.split("\n")
    assert first == "`````text" and last == "`````"
    assert md_fence("x").startswith("```text\n")


# ---------------------------------------------------------------------------------------------
# Markdown report


def test_markdown_escapes_hostile_text(model):
    markdown = render_markdown(model, "tr")
    # Outside fenced code blocks, no raw HTML survives. Inside a fence, text is never HTML.
    outside = re.sub(r"(?ms)^(`{3,})text\n.*?\n\1$", "", markdown)
    assert "<script>" not in outside
    assert "<img" not in outside
    assert "<" not in outside.replace("<br>", "")
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in markdown
    # Hostile text never adds a table column: every table row keeps the header's cell count.
    for block in markdown.split("\n\n"):
        rows = [line for line in block.split("\n") if line.startswith("| ")]
        if not rows:
            continue
        counts = {len(re.findall(r"(?<!\\)\|", row)) for row in rows}
        assert len(counts) == 1, block
    # The hostile payload stays inside its code fence.
    assert "``````text\n```\n</code></pre><script>" not in markdown
    fence = re.search(
        r"(`{5,})text\n```\n</code></pre><script>alert\(3\)</script>\n````\n\1", markdown
    )
    assert fence is not None
    assert "\\# Heading" in markdown and "\\- item" in markdown and "1\\. step" in markdown


def test_markdown_structure_and_last_line(model):
    markdown = render_markdown(model, "tr")
    for heading in (
        "## 1. Yönetici özeti",
        "## 2. Kapsam",
        "## 3. Doğrulanan bulgular",
        "## 4. Doğrulama gerektiren bulgular",
        "## 5. Reddedilen bulgular",
        "## 6. Hardening notları",
        "## 7. Araç sonuçları (doğrulanmadı)",
        "## 8. Bağımlılık zafiyetleri (SCA)",
        "## Ek A. Yöntem ve kaynaklar",
    ):
        assert heading in markdown
    last = markdown.rstrip("\n").split("\n")[-1]
    assert "/kalkan devam" in last
    assert "kalkan run answer english_report yes" in last
    assert "False positive içerebilir." in markdown


def test_english_markdown_uses_translations_and_marks_the_rest(model):
    markdown = render_markdown(model, "en")
    assert "## 3. Confirmed findings" in markdown
    assert "(not translated)" in markdown
    assert "Path traversal" in markdown
    assert "kalkan translates the title" in markdown
    assert (
        markdown.rstrip("\n").split("\n")[-1]
        == "The Turkish version of this report is `REPORT.md`."
    )


# ---------------------------------------------------------------------------------------------
# HTML report


class _Checker(HTMLParser):
    VOID = frozenset({"meta", "br", "hr", "img", "input", "link"})

    def __init__(self) -> None:
        super().__init__()
        self.stack: list[str] = []
        self.errors: list[str] = []
        self.tags: list[str] = []
        self.urls: list[str] = []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        for name, value in attrs:
            if name in ("href", "src") and value and not value.startswith("#"):
                self.urls.append(value)
            assert not name.startswith("on"), name
        if tag not in self.VOID:
            self.stack.append(tag)

    def handle_endtag(self, tag):
        if tag in self.VOID:
            return
        if not self.stack or self.stack[-1] != tag:
            self.errors.append(tag)
            return
        self.stack.pop()


def test_html_is_well_formed_self_contained_and_escaped(model):
    page = render_html(model, "tr")
    checker = _Checker()
    checker.feed(page)
    assert checker.errors == [] and checker.stack == []
    assert checker.tags.count("script") == 1  # the theme toggle only
    assert checker.urls == []  # no external request, no link out
    assert "img" not in checker.tags
    assert "<script>alert" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert "&lt;/code&gt;&lt;/pre&gt;&lt;script&gt;alert(3)" in page
    assert "@import" not in page and "url(" not in page


def test_html_design_contract(model):
    page = render_html(model, "en")
    assert page.startswith("<!doctype html>")
    assert '<html lang="en">' in page
    assert '<meta name="viewport" content="width=device-width, initial-scale=1">' in page
    assert "@media (prefers-color-scheme: dark)" in page
    assert ':root[data-theme="dark"]' in page
    assert "@media print" in page
    assert "overflow-x: auto" in page
    assert 'class="tbl-wrap"' in page
    for anchor in (
        "summary",
        "scope",
        "confirmed",
        "needs-validation",
        "rejected",
        "hardening",
        "tool-results",
        "sca",
        "appendix",
    ):
        assert f'<section id="{anchor}"' in page
        assert f'href="#{anchor}"' in page
    for finding in model.confirmed + model.needs_validation:
        assert f'id="f-{finding["id"]}"' in page
        assert f'href="#f-{finding["id"]}"' in page


def test_markdown_shows_malicious_dependencies_before_the_sca_table(model):
    markdown = render_markdown(model, "tr")
    assert "Dikkat: 1 bağımlılık bilinen zararlı paket sürümü." in markdown
    assert "| Zararlı bağımlılık | 1 |" in markdown
    section = markdown[markdown.index("## 8. ") :]
    box = section[section.index("### 8.1 Zararlı bağımlılık") : section.index("### 8.2 ")]
    assert "### 8.2 Bilinen zafiyetler" in section
    assert "> [!CAUTION]" in box
    assert "reachability sonucu önemli değil ve ciddiyet Kritik kalır" in box
    assert "> 1. Paketi ve bu sürümü kaldır. Lockfile dosyasını yeniden üret." in box
    assert "> 3. Kurulumun okuyabildiği sırları değiştir (rotate)" in box
    assert (
        "| `sample-module` | `0.0.1` | PyPI | `MAL-2025-41758`, `GHSA-2g5x-c76j-3h73` | Kritik "
        "| `requirements.txt` |"
    ) in box
    # The ordinary table leaves the malicious record out.
    assert "sample-module" not in section[section.index("### 8.2 ") :]
    english = render_markdown(model, "en")
    assert "### 8.1 Malicious dependency" in english
    assert "### 8.2 Known vulnerabilities" in english
    assert "> 2. Treat every machine that installed the package as exposed" in english
    assert "| Malicious dependencies | 1 |" in english


def test_html_shows_malicious_dependencies_before_the_sca_table(model):
    page = render_html(model, "tr")
    sca = page[page.index('<section id="sca"') :]
    assert sca.index('<div class="callout crit" role="note">') < sca.index("Bilinen zafiyetler")
    assert "<li>Paketi ve bu sürümü kaldır. Lockfile dosyasını yeniden üret.</li>" in sca
    assert "<code>MAL-2025-41758</code>" in sca
    assert '<div class="kpi sev-critical"><b>1</b><span>Zararlı bağımlılık</span></div>' in page
    assert ".callout.crit {" in page


def test_a_report_with_only_malicious_records_has_no_empty_table(model):
    only = copy.copy(model)
    only.sca = model.sca_malicious()
    markdown = render_markdown(only, "en")
    section = markdown[markdown.index("## 8. ") : markdown.index("## Appendix")]
    assert "### 8.1 Malicious dependency" in section
    assert "### 8.2" not in section and "No vulnerable dependency." not in section
    page = render_html(only, "en")
    assert "Known vulnerabilities" not in page


def test_h_escapes_quotes_and_controls():
    assert h("\"<a>'&") == "&quot;&lt;a&gt;&#x27;&amp;"
    assert h("‮") == "[U+202E]"


# ---------------------------------------------------------------------------------------------
# UI strings


def test_both_languages_have_the_same_keys():
    assert set(i18n.STRINGS["tr"]) == set(i18n.STRINGS["en"])


def test_t_formats_and_rejects_unknown_keys():
    assert i18n.t("tr", "summary_confirmed", n=3) == "kalkan 3 bulguyu doğruladı."
    assert i18n.t("xx", "sec_scope") == "Kapsam"
    with pytest.raises(KeyError):
        i18n.t("tr", "no_such_key")


def test_labels():
    assert [
        i18n.severity_label("tr", s) for s in ("critical", "high", "medium", "low", "info")
    ] == [
        "Kritik",
        "Yüksek",
        "Orta",
        "Düşük",
        "Bilgi",
    ]
    assert i18n.severity_label("tr", "informational") == "Bilgi"
    assert i18n.verdict_label("tr", "confirmed") == "Doğrulandı"
    assert i18n.verdict_label("tr", "needs_validation") == "Doğrulama gerekiyor"
    assert i18n.verdict_label("tr", "rejected") == "Reddedildi"
    assert i18n.verdict_label("en", "needs_validation") == "Needs validation"
    assert i18n.reachability_label("tr", "reachable") == "Erişilebilir"
    assert i18n.review_label("tr", "downgrade") == "Düşürüldü"
    assert i18n.review_label("en", "reject") == "Rejected"
    assert i18n.phase_label("tr", "new_phase") == "new_phase"
    assert i18n.severity_label("tr", None) == ""


def test_final_review_notes(model):
    built = copy.deepcopy(model)
    rejected = built.rejected[0]
    rejected["review"] = {"decision": "reject", "reason": "The query binds the value."}
    rejected["reason"] = "The query binds the value."
    markdown = render_markdown(built, "tr")
    assert "| Son inceleme | Doğrulandı: " in markdown
    assert "| Son inceleme | İncelenmedi |" in markdown
    assert "Son inceleme: The query binds the value." in markdown
    assert "**Son inceleme.** 3 kayıt ikinci, bağımsız bir incelemeden geçti" in markdown
    page = render_html(built, "en")
    assert "<dt>Final review</dt><dd>Verified: " in page
    assert "<strong>Final review:</strong> The query binds the value." in page
    built.profile = "fast"
    assert "The fast profile has no separate final review." in render_markdown(built, "en")
    assert "The fast profile has no separate final review." in render_html(built, "en")
