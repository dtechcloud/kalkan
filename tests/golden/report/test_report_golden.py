# SPDX-License-Identifier: MIT
"""Golden tests: merge and report outputs of a small sample run (ENGINE-SPEC 15 and 16).

``run/20261015T120000Z-shop-a1b2`` is a run folder after the validate and poc phases: done
verify, poc_build, review and translate tasks (one failed verify task that merge must ignore;
a verified and a downgraded final review), a duplicate finding, a PoC promotion, candidates
with hostile text, SCA records (a manifest pin, a vendored JavaScript file and a known malicious
package version among them), the
SBOM inputs (a Syft SBOM with a secret in a package URL and an absolute path, the pins SBOM,
``sca/vendored.json``), scanner status files and a coverage ledger. ``expected/`` holds the
outputs. The report date and the kalkan version are fixed, so the outputs do not depend on the
clock or the release.

To regenerate the expected files after a deliberate change, run
``KALKAN_UPDATE_GOLDEN=1 pytest tests/golden/report`` and review every changed line.
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest

from kalkan.findings.merge import merge_run
from kalkan.report.commands import write_report
from kalkan.report.model import build_model

HERE = Path(__file__).resolve().parent
RUN_ID = "20261015T120000Z-shop-a1b2"
EXPECTED = HERE / "expected"
GENERATED_AT = "2026-10-15T12:30:00Z"
VERSION = "0.0.0-golden"
TR_FILES = (
    "REPORT.md",
    "REPORT.html",
    "EXECUTIVE.html",
    "findings.sarif",
    "findings.json",
    "summary.json",
    "sbom.cdx.json",
    "sbom.spdx.json",
)
EN_FILES = ("REPORT.en.md", "REPORT.en.html", "EXECUTIVE.en.html")
UPDATE = os.environ.get("KALKAN_UPDATE_GOLDEN") == "1"


@pytest.fixture(scope="module")
def outputs(tmp_path_factory) -> dict[str, str]:
    run = tmp_path_factory.mktemp("golden") / RUN_ID
    shutil.copytree(HERE / "run" / RUN_ID, run)
    summary = merge_run(run)
    assert summary["warnings"] == []
    model = build_model(
        run,
        generated_at=GENERATED_AT,
        kalkan_version=VERSION,
        installed_tools=HERE / "installed.json",
    )
    write_report(run, model, lang="tr")
    texts = {name: (run / "report" / name).read_text(encoding="utf-8") for name in TR_FILES}
    texts["merged-findings.json"] = (run / "findings.json").read_text(encoding="utf-8")
    write_report(run, model, lang="en", formats=["md", "html", "exec"])
    texts.update({name: (run / "report" / name).read_text(encoding="utf-8") for name in EN_FILES})
    if UPDATE:
        EXPECTED.mkdir(exist_ok=True)
        for name, text in texts.items():
            (EXPECTED / name).write_text(text, encoding="utf-8", newline="\n")
    return texts


@pytest.mark.parametrize("name", [*TR_FILES, *EN_FILES, "merged-findings.json"])
def test_output_matches_the_expected_file(outputs, name):
    expected = (EXPECTED / name).read_text(encoding="utf-8")
    assert outputs[name] == expected, f"{name} differs; see the module docstring to regenerate"


def test_report_copy_equals_the_merged_findings(outputs):
    assert json.loads(outputs["findings.json"]) == json.loads(outputs["merged-findings.json"])


def test_expected_files_are_complete():
    names = sorted(path.name for path in EXPECTED.iterdir())
    assert names == sorted([*TR_FILES, *EN_FILES, "merged-findings.json"])
