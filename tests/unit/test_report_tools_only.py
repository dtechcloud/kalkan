# SPDX-License-Identifier: MIT
"""The report of a tools-only run (``options.mode`` = ``tools-only``, docs/PHASES.md section 3).

The first partial pass reason says that no agent validated anything; the executive page shows
the posture ``unknown`` with that basis and a dash in the severity tiles. An agents run keeps
its report unchanged.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from kalkan.findings.merge import merge_run
from kalkan.report import i18n
from kalkan.report.commands import write_report
from kalkan.report.model import build_model
from kalkan.report.render_exec import posture, render_executive

GOLDEN = Path(__file__).resolve().parents[1] / "golden" / "report"
RUN_ID = "20261015T120000Z-shop-a1b2"


@pytest.fixture
def run(tmp_path) -> Path:
    target = tmp_path / RUN_ID
    shutil.copytree(GOLDEN / "run" / RUN_ID, target)
    merge_run(target)
    return target


def make_tools_only(run: Path, profile: str | None = None) -> None:
    path = run / "state.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    document["options"]["mode"] = "tools-only"
    if profile is not None:
        document["options"]["profile"] = profile
    path.write_text(json.dumps(document), encoding="utf-8")


def model_of(run: Path):
    return build_model(
        run, generated_at="2026-10-15T12:30:00Z", installed_tools=GOLDEN / "installed.json"
    )


def test_the_first_partial_reason_is_tools_only(run):
    assert model_of(run).tools_only is False
    make_tools_only(run, profile="fast")
    model = model_of(run)
    assert model.tools_only is True
    assert model.partial_reasons[0] == ("partial_tools_only", {})
    # The profile does not matter without agents: no fast-profile reason.
    assert all(key != "partial_fast" for key, _ in model.partial_reasons)


def test_the_posture_is_unknown_with_the_tools_only_basis(run):
    assert posture(model_of(run)) != "unknown"
    make_tools_only(run)
    model = model_of(run)
    assert posture(model) == "unknown"
    for lang in ("tr", "en"):
        page = render_executive(model, lang)
        assert i18n.t(lang, "exec_posture_unknown") in page
        assert i18n.t(lang, "exec_posture_tools_only").split("`")[0] in page
        assert i18n.t(lang, "exec_partial_tools_only") in page


def test_the_severity_tiles_show_a_dash(run):
    make_tools_only(run)
    page = render_executive(model_of(run), "en")
    risk = page.split('class="risk"', 1)[1].split("</section>", 1)[0]
    assert "<b>—</b>" in risk and "<b>0</b>" not in risk


def test_summary_json_and_markdown_name_the_mode(run):
    make_tools_only(run)
    model = model_of(run)
    write_report(run, model, lang="en", formats=("md", "json"))
    summary = json.loads((run / "report" / "summary.json").read_text(encoding="utf-8"))
    assert summary["partial"] is True
    assert summary["partial_reasons"][0] == {"code": "tools_only"}
    markdown = (run / "report" / "REPORT.en.md").read_text(encoding="utf-8")
    assert "Tools-only mode: no agent validation." in markdown


def test_both_languages_have_the_new_strings():
    for key in ("partial_tools_only", "exec_partial_tools_only", "exec_posture_tools_only"):
        assert i18n.t("tr", key) and i18n.t("en", key)
