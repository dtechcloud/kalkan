# SPDX-License-Identifier: MIT
"""Tests for the executive summary page (``EXECUTIVE.html``, kalkan.report.render_exec)."""

from __future__ import annotations

import dataclasses
import json
import re
import shutil
from html.parser import HTMLParser
from pathlib import Path

import pytest

from kalkan.findings.merge import merge_run
from kalkan.report import i18n
from kalkan.report.commands import FORMATS, parse_formats, write_report
from kalkan.report.model import ReportModel, ScaRecord, UncheckedManifest, build_model
from kalkan.report.render_exec import (
    POSTURE_LEVELS,
    TOP_ACTIONS,
    TOP_FINDINGS,
    class_rows,
    component_of,
    components,
    one_line_summary,
    posture,
    priority_actions,
    render_executive,
    sca_packages,
    top_findings,
    upgrade_target,
)
from kalkan.report.render_html import render_html

GOLDEN = Path(__file__).resolve().parents[1] / "golden" / "report"
RUN_ID = "20261015T120000Z-shop-a1b2"
HOSTILE = "Evil | `tick` <script>alert(1)</script> & <img src=x onerror=alert(2)> \"q\" 'a'"


@pytest.fixture
def run(tmp_path) -> Path:
    target = tmp_path / RUN_ID
    shutil.copytree(GOLDEN / "run" / RUN_ID, target)
    merge_run(target)
    return target


def model_of(path: Path, **kwargs) -> ReportModel:
    kwargs.setdefault("generated_at", "2026-10-15T12:30:00Z")
    kwargs.setdefault("installed_tools", GOLDEN / "installed.json")
    return build_model(path, **kwargs)


def finding(
    number: int,
    severity: str = "high",
    likelihood: str = "medium",
    *,
    title: str | None = None,
    cls: str = "sqli",
    file: str = "app/db.py",
    strategy: str | None = None,
    impact: str = "The attacker reads every row.",
) -> dict:
    """A minimal confirmed finding."""
    return {
        "verdict": "confirmed",
        "id": f"KF-{number:016X}",
        "fingerprint": f"fp-{number}",
        "title": title or f"Finding {number:02d}",
        "class": cls,
        "trace": [{"kind": "sink", "file": file, "line": number}],
        "evidence": [],
        "severity": {
            "likelihood": {"score": likelihood, "reason": "Any user can send it."},
            "impact": {"score": severity, "reason": impact},
            "overall_severity": severity,
        },
        "remediation": {"strategy": strategy or f"Fix number {number:02d} at once."},
    }


def synthetic(*confirmed: dict, **fields) -> ReportModel:
    model = ReportModel(
        run_id="20261016T000000Z-app-0000",
        run_lang="tr",
        generated_at="2026-10-16T00:00:00Z",
        kalkan_version="0.0.0-test",
        findings_available=True,
        confirmed=list(confirmed),
    )
    for name, value in fields.items():
        setattr(model, name, value)
    return model


def sca(package: str, version: str, vuln: str, severity: str | None, reach: str, *fixed: str):
    return ScaRecord(
        ecosystem="PyPI",
        package=package,
        version=version,
        vuln_id=vuln,
        aliases=(),
        summary="",
        severity=severity,
        cvss_score=None,
        cvss_vector=None,
        fixed_versions=tuple(fixed),
        reachability=reach,
        engines=("osv-scanner",),
        locations=("requirements.txt",),
    )


class _Checker(HTMLParser):
    VOID = frozenset({"meta", "br", "hr", "img", "input", "link", "wbr"})

    def __init__(self) -> None:
        super().__init__()
        self.stack: list[str] = []
        self.errors: list[str] = []
        self.tags: list[str] = []
        self.hrefs: list[str] = []
        self.styles: list[str] = []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        for name, value in attrs:
            assert not name.startswith("on"), name
            if name == "href":
                self.hrefs.append(value)
            if name == "src":
                self.errors.append(f"src={value}")
            if name == "style":
                self.styles.append(value)
        if tag not in self.VOID:
            self.stack.append(tag)

    def handle_endtag(self, tag):
        if tag in self.VOID:
            return
        if not self.stack or self.stack[-1] != tag:
            self.errors.append(tag)
            return
        self.stack.pop()


def check_page(page: str, report: str = "REPORT.html") -> _Checker:
    checker = _Checker()
    checker.feed(page)
    assert checker.errors == [] and checker.stack == []
    assert checker.tags.count("script") == 1  # the theme toggle only
    for href in checker.hrefs:  # links go to the full report only: no external request
        assert href == report or re.fullmatch(re.escape(report) + r"#f-[A-Za-z0-9_-]+", href)
    for style in checker.styles:  # only the computed bar widths
        assert re.fullmatch(r"width: \d{1,3}%", style), style
    assert "@import" not in page and "url(" not in page
    return checker


# ---------------------------------------------------------------------------------------------
# Posture rule


@pytest.mark.parametrize(
    ("severities", "expected"),
    [
        (["critical", "low"], "critical"),
        (["high", "high", "medium"], "high"),
        (["medium", "info"], "medium"),
        (["low", "info"], "low"),
        (["info"], "low"),
        ([], "low"),
    ],
)
def test_posture_is_the_highest_confirmed_severity(severities, expected):
    model = synthetic(*(finding(n, severity) for n, severity in enumerate(severities, start=1)))
    assert posture(model) == expected
    assert expected in POSTURE_LEVELS


def test_posture_ignores_unconfirmed_findings_tool_results_and_sca():
    model = synthetic(finding(1, "low"))
    model.needs_validation = [{"verdict": "needs_validation", "title": "x", "id": "KF-2"}]
    model.tool_results = [{"id": "CAND-1", "engine": "bandit", "severity": "critical"}]
    model.sca = [sca("pyyaml", "5.3", "GHSA-1", "critical", "reachable", "5.4")]
    model.sca_source = "vulns"
    assert posture(model) == "low"
    page = render_executive(model, "en")
    # The page names the reachable critical package that the level leaves out.
    assert "reachable dependency packages with a severity above this level: 1" in page
    assert "Highest severity: Critical" in page


def test_an_empty_sca_section_names_the_manifests_without_a_lockfile():
    model = synthetic(finding(1, "low"))
    model.sca_source = "vulns"
    page = render_executive(model, "tr")
    assert "Bağımlılık zafiyeti yok." in page
    assert "lockfile yok. Bu dosyalarda" not in page
    # A .NET solution: 32 NuGet projects without packages.lock.json, no vulnerable pin.
    model.unchecked_manifests = [
        UncheckedManifest(f"P{n}/P{n}.csproj", "NuGet", "no lockfile", 5, 0) for n in range(32)
    ]
    page = render_executive(model, "tr")
    assert "Bağımlılık zafiyeti yok." in page
    assert "32 manifest dosyasında lockfile yok. Bu dosyalarda yalnızca tam sürümler" in page
    assert "Manifests without a lockfile: 32. Only their exact versions" in render_executive(
        model, "en"
    )


def test_malicious_dependencies_get_a_box_after_the_overall_risk():
    model = synthetic(finding(1, "low"))
    model.sca_source = "vulns"
    bad = dataclasses.replace(
        sca("sample-module", "0.0.1", "MAL-2025-41758", "critical", "unknown"),
        aliases=("GHSA-2g5x-c76j-3h73",),
        malicious=True,
    )
    model.sca = [bad, sca("pyyaml", "5.3", "GHSA-1", "high", "unknown", "5.4")]
    page = render_executive(model, "en")
    check_page(page, "REPORT.en.html")
    assert page.index('id="risk"') < page.index('id="malicious"') < page.index('id="top"')
    assert "Malicious dependencies: 1" in page
    assert (
        "<code>sample-module</code> <code>0.0.1</code> · PyPI · <code>MAL-2025-41758</code> +1"
        in (page)
    )
    assert "Action: remove the package, treat the machines that installed it as exposed" in page
    # The posture rule stays (SCA records do not change the level); the card names the box.
    assert posture(model) == "low"
    assert "known malicious package versions in the dependencies: 1" in page
    # The dependency section leaves the malicious version out: no upgrade target for it.
    assert [item.package for item in sca_packages(model)] == ["pyyaml"]
    assert "Malicious package versions: 1. They are in the box at the top" in page
    assert "Vulnerable packages: 1. Vulnerability records: 1." in page
    # Only malicious records: no "no vulnerable dependency" line.
    model.sca = [bad]
    page = render_executive(model, "tr")
    check_page(page)
    assert "Zararlı bağımlılık: 1 paket sürümü" in page
    assert "Bağımlılık zafiyeti yok." not in page
    assert "1 zararlı paket sürümü sayfanın başındaki kutuda" in page


def test_no_malicious_box_without_malicious_records():
    model = synthetic(finding(1, "low"))
    model.sca_source = "vulns"
    model.sca = [sca("pyyaml", "5.3", "GHSA-1", "high", "unknown", "5.4")]
    page = render_executive(model, "en")
    assert 'id="malicious"' not in page
    assert "malicious" not in page.split("</style>", 1)[1].lower()


def test_posture_is_unknown_without_findings_json():
    model = synthetic()
    model.findings_available = False
    assert posture(model) == "unknown"
    page = render_executive(model, "tr")
    assert '<span class="lvl">Bilinmiyor</span>' in page
    assert "<code>findings.json</code> yok. Seviye hesaplanamadı." in page
    # Unknown counts are a dash, not a misleading zero.
    assert page.count("<b>—</b>") == 7  # five severity tiles and two verdict tiles


# ---------------------------------------------------------------------------------------------
# Data helpers


def test_top_findings_order_by_severity_then_likelihood_then_title():
    findings = [
        finding(1, "medium", "critical", title="b medium"),
        finding(2, "high", "low", title="high low"),
        finding(3, "critical", "low", title="critical low"),
        finding(4, "high", "critical", title="high critical"),
        finding(5, "medium", "critical", title="A medium"),
        *(finding(n, "low", "low") for n in range(6, 14)),
    ]
    model = synthetic(*findings)
    top = top_findings(model)
    assert len(top) == TOP_FINDINGS
    assert [item["title"] for item in top[:5]] == [
        "critical low",
        "high critical",
        "high low",
        "A medium",
        "b medium",
    ]
    assert [item["title"] for item in top[5:]] == [f"Finding {n:02d}" for n in range(6, 11)]
    page = render_executive(model, "en")
    assert "Confirmed findings in total: 13." in page


def test_class_rows_and_components():
    model = synthetic(
        finding(1, "medium", cls="xss", file="web/ui/views/a.js"),
        finding(2, "critical", cls="sqli", file="api/db/q.py"),
        finding(3, "high", cls="xss", file="web/ui/b.js"),
        finding(4, "high", cls="ssrf", file="main.go"),
        finding(5, "low", cls="sqli", file="api/db/r.py"),
    )
    rows = class_rows(model)
    # Most critical first, then most high, then most medium: xss (high and medium) > ssrf.
    assert [slug for slug, _ in rows] == ["sqli", "xss", "ssrf"]
    assert rows[0][1] == {"critical": 1, "high": 0, "medium": 0, "low": 1, "info": 0}
    assert components(model) == [
        ("api/db", 2, "critical"),
        ("web/ui", 2, "high"),
        ("", 1, "high"),
    ]
    assert component_of("a/b/c/d.py") == "a/b"
    assert component_of("./x.py") == ""
    assert component_of("a\\b\\c.py") == "a/b"


def test_upgrade_target_and_packages():
    records = [
        sca("django", "3.2.0", "GHSA-a", "high", "unknown", "2.2.21", "3.2.4", "4.0.1"),
        sca("django", "3.2.0", "GHSA-b", "critical", "unknown", "3.2.10", "3.1.14"),
        sca("django", "3.2.0", "GHSA-c", "medium", "reachable", "2.2.1"),
        sca("requests", "2.19.0", "GHSA-d", "low", "not_reachable", "v2.20.0"),
        sca("lodash", "4.17.15", "GHSA-e", None, "unknown"),
    ]
    assert upgrade_target("3.2.0", records[:3]) == ("3.2.10", 1)
    assert upgrade_target("2.19.0", records[3:4]) == ("v2.20.0", 0)
    assert upgrade_target("1.0", []) == (None, 0)
    model = synthetic(sca=records, sca_source="vulns")
    packages = sca_packages(model)
    assert [item.package for item in packages] == ["django", "requests", "lodash"]
    django = packages[0]
    assert (django.severity, django.reachability, django.records) == ("critical", "reachable", 3)
    assert (django.fixed_in, django.unfixed) == ("3.2.10", 1)
    assert django.vuln_ids == ("GHSA-a", "GHSA-b", "GHSA-c")
    assert packages[2].severity is None and packages[2].fixed_in is None
    page = render_executive(model, "tr")
    assert "<code>3.2.10</code> veya üstü" in page
    assert "1 kaydın bilinen düzeltmesi yok" in page
    assert "Bilinen düzeltme yok" in page
    assert "3 zafiyetli paket, 5 zafiyet kaydı." in page


def test_priority_actions_take_one_line_per_distinct_strategy():
    model = synthetic(
        finding(1, "critical", strategy="Use a bound parameter. Then test it."),
        finding(2, "high", strategy="Use a bound parameter. Then test it."),
        finding(3, "high", strategy=" use a bound parameter. then test it "),
        *(finding(n, "medium") for n in range(4, 12)),
    )
    actions = priority_actions(model, "tr")
    assert len(actions) == TOP_ACTIONS
    assert actions[0].strategy == "Use a bound parameter. Then test it."
    assert actions[0].others == 2
    assert [action.finding["id"] for action in actions[1:]] == [
        finding(n)["id"] for n in range(4, 8)
    ]
    page = render_executive(model, "tr")
    assert "(+2 bulgu)" in page


def test_one_line_summary():
    assert one_line_summary("Short.", 50) == "Short."
    text = "First one is short. The second makes it long enough. The third is left out."
    assert one_line_summary(text, 200) == "First one is short. The second makes it long enough."
    assert one_line_summary("A\nB  c", 10) == "A B c"
    cut = one_line_summary("word " * 60, 40)
    assert len(cut) <= 40 and cut.endswith("…")


# ---------------------------------------------------------------------------------------------
# The page


def test_page_of_the_sample_run(run):
    model = model_of(run)
    page = render_executive(model, "tr")
    check_page(page)
    assert page.startswith("<!doctype html>")
    assert '<html lang="tr">' in page
    assert "<title>Yönetici özeti · 20261015T120000Z-shop-a1b2</title>" in page
    assert '<span class="lvl">Yüksek</span>' in page
    assert "Kısmi geçiş (partial pass)" in page
    assert "1 kapsam birimi açık · 1 manifest dosyasında lockfile yok" in page
    for heading in (
        "Genel risk",
        "En önemli 10 bulgu",
        "Sınıflar ve bileşenler",
        "Bağımlılıklar (SCA)",
        "Araç sonuçları (doğrulanmadı)",
        "Kapsam ve sınırlar",
        "Öncelikli aksiyonlar",
    ):
        assert f"</span>{heading}</h2>" in page
    assert "%80 kapandı (4 / 5 birim)" in page
    assert "13 / 150 kullanıldı" in page
    # A PoC of the golden run passed: the limit says that the sandbox ran, not that it is missing.
    assert "PoC sandbox bu denetimde çalıştı." in page
    assert "ADR-0004" not in page
    assert "2 kayıt incelendi: 1 doğrulandı, 1 düşürüldü, 0 reddedildi." in page
    assert "<code>opengrep</code> 1 dosyayı kısmen analiz etti." in page
    assert "Bağlanmış parametre kullan." in page


def test_the_poc_limit_says_that_the_sandbox_did_not_run(run):
    model = model_of(run)
    for item in model.findings:
        item.pop("poc", None)
    page = render_executive(model, "en")
    assert "The PoC verification sandbox did not run in this audit." in page
    assert "The PoC sandbox ran in this audit" not in page


def test_links_point_to_the_finding_anchors_of_the_full_report(run):
    model = model_of(run)
    for lang, report in (("tr", "REPORT.html"), ("en", "REPORT.en.html")):
        page = render_executive(model, lang)
        anchors = re.findall(re.escape(report) + r"#(f-[A-Za-z0-9_-]+)", page)
        assert anchors
        full = render_html(model, lang)
        for anchor in anchors:
            assert f'id="{anchor}"' in full


def test_english_page_uses_translations_and_marks_the_rest(run):
    page = render_executive(model_of(run), "en")
    check_page(page, "REPORT.en.html")
    assert '<html lang="en">' in page
    assert "SQL injection in user lookup" in page
    assert "Use a bound parameter." in page
    assert "(not translated)" in page
    assert "kalkan translates the title, the description and the remediation" in page
    assert "Partial pass" in page and "open coverage units: 1" in page


def test_hostile_text_is_escaped(run):
    model = model_of(run)
    model.target_source = f"C:/x/{HOSTILE}"
    model.git_ref = HOSTILE
    model.partial_reasons = [*model.partial_reasons, ("partial_reason", {"reason": HOSTILE})]
    target = model.confirmed[0]
    target["title"] = HOSTILE
    target["class"] = HOSTILE
    target["severity"]["impact"]["reason"] = HOSTILE
    target["remediation"]["strategy"] = HOSTILE
    target["trace"] = [{"kind": "sink", "file": f"src/{HOSTILE}.py", "line": 3}]
    model.sca = [dataclasses.replace(model.sca[0], package=HOSTILE, vuln_id=HOSTILE)]
    model.engines = [dataclasses.replace(model.engines[0], engine=HOSTILE)]
    model.scan_gaps = [dataclasses.replace(model.scan_gaps[0], engine=HOSTILE)]
    model.tool_results[0]["engine"] = HOSTILE
    for lang in ("tr", "en"):
        page = render_executive(model, lang)
        checker = check_page(page, "REPORT.en.html" if lang == "en" else "REPORT.html")
        assert "img" not in checker.tags
        assert "<script>alert" not in page and "<img" not in page
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
        assert "onerror=alert(2)" in page  # as escaped text inside an element, never an attribute
        assert "&quot;q&quot;" in page


def test_missing_inputs_give_a_partial_page(tmp_path):
    folder = tmp_path / RUN_ID
    folder.mkdir()
    model = model_of(folder, installed_tools=tmp_path / "none.json")
    page = render_executive(model, "tr")
    check_page(page)
    assert '<span class="lvl">Bilinmiyor</span>' in page
    assert "Kısmi geçiş (partial pass)" in page and "<code>state.json</code> yok" in page
    assert "<code>findings.json</code> yok. Bulgu listesi yok." in page
    assert "<code>sca/vulns.json</code> yok. SCA sonucu bilinmiyor." in page
    assert "<code>candidates.json</code> yok. Araç sonuçları bilinmiyor." in page
    assert "Tarayıcı durum dosyası yok" in page
    assert "<code>coverage-ledger.json</code> yok." in page
    assert "Bütçe bilgisi yok." in page
    # The page lists the missing inputs it needs; the tool versions are not on it.
    assert "<code>scans/*.status.json</code>" in page
    assert "<code>.tools/installed.json</code>" not in page
    english = render_executive(model, "en")
    assert '<span class="lvl">Unknown</span>' in english


def test_partial_reasons_are_short_and_in_one_line(run):
    path = run / "state.json"
    state = json.loads(path.read_text(encoding="utf-8"))
    state["options"]["profile"] = "fast"
    state["budget"]["max_agent_tasks"] = 40
    state["budget"]["used_agent_tasks"] = 40
    state["phase"] = "hunt"
    state["incomplete_reason"] = "validation_budget_exhausted"
    path.write_text(json.dumps(state), encoding="utf-8")
    page = render_executive(model_of(run), "tr")
    status = re.search(r'<p class="status">(.*?)</p>', page).group(1)
    for text in (
        "fast profili, en çok 40 ajan görevi",
        "ajan görevi bütçesi doldu (40 / 40)",
        "çalıştırma bitmedi (son aşama: Avlanma (hunt))",
        "eksik kalma sebebi: validation_budget_exhausted",
        "1 kapsam birimi açık",
    ):
        assert text in status
    assert "fast profilinde ayrı bir son inceleme yok." in page


def test_a_full_pass_says_so():
    model = synthetic(finding(1, "medium"), state_available=True, phase="done")
    model.ledger = {"covered": 3}
    page = render_executive(model, "tr")
    assert "Tam geçiş (full pass)" in page
    assert "Bu çalıştırma tamamlandı. Kapsam defterinde açık birim yok." in page
    assert "%100 kapandı (3 / 3 birim)" in page


def test_design_contract(run):
    page = render_executive(model_of(run), "tr")
    assert '<meta name="viewport" content="width=device-width, initial-scale=1">' in page
    assert "@media (prefers-color-scheme: dark)" in page
    assert ':root[data-theme="dark"]' in page
    assert "@page { size: A4;" in page and "@media print" in page
    assert "@media (max-width: 640px)" in page
    # The same design tokens as REPORT.html.
    from kalkan.report.render_html import TOKENS

    assert TOKENS in page and TOKENS in render_html(model_of(run), "tr")
    # Severity colors never stand alone: every badge carries the severity word.
    for css, word in re.findall(r'<span class="sev sev-(\w+)">([^<]*)</span>', page):
        assert word == i18n.severity_label("tr", css) or css == "none"


def test_write_report_writes_the_executive_page(run):
    model = model_of(run)
    assert "exec" in FORMATS
    assert parse_formats("exec") == ["exec"]
    written = write_report(run, model, lang="tr", formats=["exec", "json"])
    assert [path.name for path in written] == ["EXECUTIVE.html", "findings.json", "summary.json"]
    summary = json.loads((run / "report" / "summary.json").read_text(encoding="utf-8"))
    assert summary["paths"]["executive_html"] == "report/EXECUTIVE.html"
    written = write_report(run, model, lang="en", formats=["exec"])
    assert [path.name for path in written] == ["EXECUTIVE.en.html"]
