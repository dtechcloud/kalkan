# SPDX-License-Identifier: MIT
"""The version of kalkan: one value, and no logic that depends on it.

The public releases start at 1.0.0. A run, a state or a ledger never stores the version for a
decision: the engine keys every compatibility path on the data (a schema field, a missing key,
an older profile name), so a run of any version takes the current path.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import kalkan

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "src" / "kalkan"

#: A comparison or a parse of the version text.
_VERSION_LOGIC = re.compile(r"__version__\s*(?:[<>]=?|[!=]=)|(?:[<>]=?|[!=]=)\s*__version__")
_VERSION_PARSE = re.compile(r"__version__\s*\.\s*(?:split|startswith|partition)\b")
#: Release history in the code ("before 1.6.0", "removed in 1.15.0").
_HISTORY = re.compile(
    r"\b(?:before|since|after|until|removed in|added in|kalkan) v?\d+\.\d+\.\d+", re.IGNORECASE
)


def _sources() -> list[Path]:
    return sorted(path for path in SOURCE.rglob("*.py") if "__pycache__" not in path.parts)


def test_pyproject_and_the_package_name_the_same_version():
    with (ROOT / "pyproject.toml").open("rb") as handle:
        project = tomllib.load(handle)["project"]
    assert project["version"] == kalkan.__version__
    assert re.fullmatch(r"\d+\.\d+\.\d+", kalkan.__version__)


def test_no_code_compares_or_parses_the_kalkan_version():
    hits = []
    for path in _sources():
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if _VERSION_LOGIC.search(line) or _VERSION_PARSE.search(line):
                hits.append(f"{path.relative_to(ROOT).as_posix()}:{number}: {line.strip()}")
    assert hits == []


def test_the_code_names_no_release_history():
    hits = []
    for path in _sources():
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if _HISTORY.search(line):
                hits.append(f"{path.relative_to(ROOT).as_posix()}:{number}: {line.strip()}")
    assert hits == []


def test_the_compatibility_paths_key_on_the_data_not_on_a_version(monkeypatch):
    """A run of 1.0.0 (or any version) takes the current path."""
    from kalkan.findings.merge import POC_OUT_OF_SCOPE
    from kalkan.report import i18n
    from kalkan.run import budget, state

    monkeypatch.setattr(kalkan, "__version__", "1.0.0")
    # The current profile names stay as they are. Only an older name is mapped.
    run_state = {"options": {"profile": "fast"}}
    state._normalize_profile(run_state)
    assert run_state["options"]["profile"] == "fast"
    assert budget.canonical_profile("quick") == "fast"
    # A skipped PoC reads as "the sandbox did not run". Only the exact pre-release scope text
    # reads as "that run had no sandbox".
    assert i18n.poc_observed("en", "sandbox_unavailable") == i18n.t("en", "poc_sandbox_unavailable")
    assert i18n.poc_observed("en", POC_OUT_OF_SCOPE) == i18n.t("en", "poc_out_of_scope")
