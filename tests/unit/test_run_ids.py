# SPDX-License-Identifier: MIT
"""Tests for kalkan.run.ids: run IDs, slugs, the runs root, LATEST and timestamps."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest

from kalkan.errors import StateError
from kalkan.run import ids
from kalkan.util.paths import KALKAN_HOME_ENV

MOMENT = datetime(2026, 10, 15, 22, 43, 5, tzinfo=UTC)


@pytest.mark.parametrize(
    ("name", "slug"),
    [
        ("WebApp", "webapp"),
        ("my_app.v2", "my-app-v2"),
        ("Gölge Şifre Kırıcı", "golge-sifre-kirici"),
        ("--weird--name--", "weird-name"),
        ("___", "target"),
        ("", "target"),
        ("a" * 40, "a" * 24),
        ("abcdefghijklmnopqrstuvw-xyz", "abcdefghijklmnopqrstuvw"),
    ],
)
def test_slugify(name, slug):
    assert ids.slugify(name) == slug


def test_new_run_id_has_the_documented_form():
    run_id = ids.new_run_id("My Repo", MOMENT)
    assert run_id.startswith("20261015T224305Z-my-repo-")
    assert ids.is_run_id(run_id)
    assert ids.RUN_ID_PATTERN.fullmatch(run_id)


def test_new_run_ids_differ():
    assert len({ids.new_run_id("x", MOMENT) for _ in range(20)}) > 1


@pytest.mark.parametrize(
    "value",
    [
        "../20261015T224305Z-x-abcd",
        "20261015T224305Z-x-abcd/..",
        "20261015T224305Z-X-abcd",
        "20261015T224305Z--abcd",
        "20261015T224305Z-x-abcg",
        "20261015T224305Z-x-abcd\n",
        "20261015T224305-x-abcd",
        "C:\\runs\\20261015T224305Z-x-abcd",
        "",
        None,
        42,
    ],
)
def test_is_run_id_rejects_malformed_values(value):
    assert not ids.is_run_id(value)


def test_runs_root_uses_the_environment_override(monkeypatch, tmp_path):
    monkeypatch.setenv(ids.RUNS_DIR_ENV, str(tmp_path / "runs"))
    assert ids.runs_root() == (tmp_path / "runs").resolve()


def test_runs_root_defaults_to_the_repository(monkeypatch):
    monkeypatch.delenv(ids.RUNS_DIR_ENV, raising=False)
    # A KALKAN_HOME of the developer (the plugin tool home for the tool tests) moves the root.
    monkeypatch.delenv(KALKAN_HOME_ENV, raising=False)
    root = ids.runs_root()
    assert root.name == "runs"
    assert (root.parent / "pyproject.toml").is_file()


def test_latest_round_trip(tmp_path):
    root = tmp_path / "runs"
    assert ids.read_latest(root) is None
    run_id = ids.new_run_id("app", MOMENT)
    ids.write_latest(run_id, root)
    assert (root / ids.LATEST_NAME).read_text(encoding="utf-8") == run_id + "\n"
    assert ids.read_latest(root) == run_id


def test_write_latest_rejects_a_bad_run_id(tmp_path):
    with pytest.raises(StateError):
        ids.write_latest("../evil", tmp_path)


def test_read_latest_rejects_bad_content(tmp_path):
    (tmp_path / ids.LATEST_NAME).write_text("../../etc\n", encoding="utf-8")
    with pytest.raises(StateError, match="valid run ID"):
        ids.read_latest(tmp_path)


def test_resolve_run_uses_latest(tmp_path):
    run_id = ids.new_run_id("app", MOMENT)
    (tmp_path / run_id).mkdir()
    ids.write_latest(run_id, tmp_path)
    assert ids.resolve_run(None, tmp_path) == tmp_path / run_id
    assert ids.resolve_run(run_id, tmp_path) == tmp_path / run_id


def test_resolve_run_without_any_run(tmp_path):
    with pytest.raises(StateError, match="no run found"):
        ids.resolve_run(None, tmp_path)


def test_resolve_run_rejects_unsafe_ids(tmp_path):
    with pytest.raises(StateError, match="invalid run ID"):
        ids.resolve_run("..", tmp_path)


def test_resolve_run_reports_a_missing_run(tmp_path):
    with pytest.raises(StateError, match="run not found"):
        ids.resolve_run(ids.new_run_id("app", MOMENT), tmp_path)


def test_resolve_run_rejects_a_file(tmp_path):
    run_id = ids.new_run_id("app", MOMENT)
    (tmp_path / run_id).write_text("x", encoding="utf-8")
    with pytest.raises(StateError, match="not a folder"):
        ids.resolve_run(run_id, tmp_path)


def test_timestamps_round_trip():
    text = ids.format_ts(MOMENT)
    assert text == "2026-10-15T22:43:05Z"
    assert ids.parse_ts(text) == MOMENT
    assert ids.parse_ts("2026-10-15T22:43:05.250Z") == MOMENT + timedelta(milliseconds=250)


def test_format_ts_converts_to_utc():
    local = datetime(2026, 10, 16, 1, 43, 5, tzinfo=timezone(timedelta(hours=3)))
    assert ids.format_ts(local) == "2026-10-15T22:43:05Z"
    assert ids.format_ts(datetime(2026, 10, 15, 22, 43, 5)) == "2026-10-15T22:43:05Z"


@pytest.mark.parametrize(
    "text", ["2026-10-15 22:43:05Z", "2026-10-15T22:43:05", "2026-13-45T22:43:05Z", None]
)
def test_parse_ts_rejects_other_text(text):
    with pytest.raises(ValueError):
        ids.parse_ts(text)
