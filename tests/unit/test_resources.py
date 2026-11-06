# SPDX-License-Identifier: MIT
"""Tests for kalkan.resources: read-only data and the home folder in a checkout and a wheel."""

from __future__ import annotations

from pathlib import Path

import pytest

from kalkan import resources
from kalkan.errors import KalkanError
from kalkan.matchers.spec import default_rules_dir as matcher_rules_dir
from kalkan.run import ids
from kalkan.run import knowledge as k
from kalkan.scanners.adapters.opengrep import default_rules_dir as opengrep_rules_dir
from kalkan.tools.resolve import default_repo_root
from kalkan.util.paths import KALKAN_HOME_ENV

REPOSITORY = Path(__file__).resolve().parents[2]


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv(KALKAN_HOME_ENV, raising=False)
    monkeypatch.delenv(ids.RUNS_DIR_ENV, raising=False)


def fake_package(monkeypatch, tmp_path: Path, *, data: bool) -> Path:
    """Pretend that kalkan is an installed wheel in ``tmp_path/site/kalkan``."""
    package = tmp_path / "site" / "kalkan"
    package.mkdir(parents=True)
    if data:
        for name in resources.DATA_NAMES:
            (package / "_data" / name).mkdir(parents=True)
    monkeypatch.setattr(resources, "_PACKAGE_DIR", package)
    return package


def test_a_checkout_reads_the_repository_folders():
    assert resources.checkout_root() == REPOSITORY
    assert resources.data_source() == "checkout"
    assert resources.knowledge_dir() == REPOSITORY / "knowledge"
    assert resources.rules_dir("matchers") == REPOSITORY / "rules" / "matchers"
    assert k.knowledge_dir() == REPOSITORY / "knowledge"
    assert matcher_rules_dir() == REPOSITORY / "rules" / "matchers"
    assert opengrep_rules_dir() == REPOSITORY / "rules" / "opengrep"


def test_a_checkout_keeps_its_home_and_runs_folder():
    found = resources.home_info(prefix=REPOSITORY / "no-venv")
    assert found == resources.Home(REPOSITORY, "checkout")
    assert ids.runs_root() == resources.home() / "runs"
    assert default_repo_root() == resources.home()


def test_the_wheel_data_wins_over_a_checkout(monkeypatch, tmp_path):
    package = fake_package(monkeypatch, tmp_path, data=True)
    assert resources.data_source() == "package"
    assert resources.knowledge_dir() == package / "_data" / "knowledge"
    assert resources.rules_dir("opengrep") == package / "_data" / "rules" / "opengrep"


def test_missing_data_raises(monkeypatch, tmp_path):
    fake_package(monkeypatch, tmp_path, data=False)
    assert resources.data_source() == "missing"
    with pytest.raises(KalkanError, match="knowledge"):
        resources.data_dir("knowledge")
    with pytest.raises(FileNotFoundError):
        k.knowledge_dir()
    with pytest.raises(ValueError):
        resources.data_dir("prompts")


def test_kalkan_home_wins_and_must_exist(monkeypatch, tmp_path):
    monkeypatch.setenv(KALKAN_HOME_ENV, str(tmp_path))
    assert resources.home_info() == resources.Home(tmp_path.resolve(), "env")
    assert ids.runs_root() == tmp_path.resolve() / "runs"
    # The data still comes from the package or the checkout, never from KALKAN_HOME.
    assert resources.knowledge_dir() == REPOSITORY / "knowledge"
    monkeypatch.setenv(KALKAN_HOME_ENV, str(tmp_path / "missing"))
    with pytest.raises(KalkanError, match=KALKAN_HOME_ENV):
        resources.home()


def test_the_venv_marker_names_the_home_and_the_runs(monkeypatch, tmp_path):
    fake_package(monkeypatch, tmp_path, data=True)
    venv = tmp_path / "data" / "venv"
    venv.mkdir(parents=True)
    marker = resources.write_home_marker(venv, tmp_path / "data")
    assert marker == venv / resources.HOME_MARKER
    found = resources.home_info(prefix=venv)
    assert found == resources.Home((tmp_path / "data").resolve(), "marker")
    assert resources.runs_root(prefix=venv) == (tmp_path / "data" / "runs").resolve()
    assert resources.marker_runs_root(prefix=venv) is None

    resources.write_home_marker(venv, tmp_path / "data", tmp_path / "kalkan-runs")
    runs = (tmp_path / "kalkan-runs").resolve()
    assert resources.home_info(prefix=venv).runs == runs
    assert resources.runs_root(prefix=venv) == runs
    assert resources.marker_runs_root(prefix=venv) == runs
    monkeypatch.setenv(ids.RUNS_DIR_ENV, str(tmp_path / "short"))
    assert resources.runs_root(prefix=venv) == (tmp_path / "short").resolve()
    monkeypatch.delenv(ids.RUNS_DIR_ENV)
    # KALKAN_HOME hides the marker completely.
    monkeypatch.setenv(KALKAN_HOME_ENV, str(tmp_path))
    assert resources.runs_root(prefix=venv) == tmp_path.resolve() / "runs"
    assert resources.marker_runs_root(prefix=venv) is None


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("not json", "not a JSON object"),
        ("[]", "not a JSON object"),
        ('{"home": ""}', "names no folder"),
        ('{"home": "relative/folder"}', "absolute"),
        ('{"home": "HOME", "runs": "relative"}', "absolute"),
        ('{"home": "GONE"}', "does not exist"),
    ],
)
def test_a_bad_marker_raises(monkeypatch, tmp_path, content, message):
    fake_package(monkeypatch, tmp_path, data=True)
    venv = tmp_path / "venv"
    venv.mkdir()
    text = content.replace("HOME", tmp_path.as_posix()).replace("GONE", (tmp_path / "x").as_posix())
    (venv / resources.HOME_MARKER).write_text(text, encoding="utf-8")
    with pytest.raises(KalkanError, match=message):
        resources.home_info(prefix=venv)


def test_an_installed_wheel_without_a_marker_uses_the_default_home(monkeypatch, tmp_path):
    fake_package(monkeypatch, tmp_path, data=True)
    monkeypatch.setattr(resources.Path, "home", classmethod(lambda cls: tmp_path / "user"))
    found = resources.home_info(prefix=tmp_path / "plain-venv")
    expected = (tmp_path / "user" / resources.DEFAULT_HOME_DIRNAME).resolve()
    assert found == resources.Home(expected, "default")
    assert expected.is_dir()


def test_doctor_check_reports_the_layout(monkeypatch, tmp_path):
    check = resources.doctor_check()
    assert check["name"] == "paths"
    assert check["status"] == "ok"
    assert check["data"]["data_source"] == "checkout"
    assert check["data"]["knowledge"] == (REPOSITORY / "knowledge").as_posix()
    monkeypatch.setenv(KALKAN_HOME_ENV, str(tmp_path / "missing"))
    assert resources.doctor_check()["status"] == "fail"
    monkeypatch.delenv(KALKAN_HOME_ENV)
    monkeypatch.setattr(resources.Path, "home", classmethod(lambda cls: tmp_path / "user"))
    fake_package(monkeypatch, tmp_path, data=False)
    assert resources.doctor_check()["status"] == "fail"


def test_plugin_install_needs_the_marker_and_no_checkout(monkeypatch, tmp_path):
    venv = tmp_path / "data" / "venv"
    venv.mkdir(parents=True)
    # A checkout is never a plugin install, also with a marker in its venv.
    resources.write_home_marker(venv, tmp_path / "data")
    assert resources.plugin_install(prefix=venv) is False
    fake_package(monkeypatch, tmp_path, data=True)
    assert resources.checkout_root() is None
    assert resources.plugin_install(prefix=venv) is True
    assert resources.plugin_install(prefix=tmp_path / "plain-venv") is False
    # KALKAN_HOME hides the marker for the home, but the plugin still runs the engine.
    monkeypatch.setenv(KALKAN_HOME_ENV, str(tmp_path))
    assert resources.plugin_install(prefix=venv) is True
