# SPDX-License-Identifier: MIT
"""Tests for kalkan.util.fs: tree removal without following links (ENGINE-SPEC 11 and 12)."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from kalkan.util import fs
from kalkan.util.fs import is_link, remove_tree, tree_size


def make_tree(root: Path) -> None:
    (root / "a" / "b").mkdir(parents=True)
    (root / "top.txt").write_bytes(b"12345")
    (root / "a" / "one.bin").write_bytes(b"x" * 100)
    (root / "a" / "b" / "two.bin").write_bytes(b"y" * 1000)


def folder_link(link: Path, target: Path) -> None:
    """A junction on Windows (no special right needed), a symlink elsewhere."""
    if os.name == "nt":
        import _winapi

        _winapi.CreateJunction(str(target), str(link))
    else:
        os.symlink(target, link, target_is_directory=True)


def read_only(path: Path) -> None:
    os.chmod(path, stat.S_IREAD | (stat.S_IEXEC if path.is_dir() else 0))


def test_remove_tree_counts_and_removes_everything(tmp_path):
    root = tmp_path / "tree"
    make_tree(root)
    counted = tree_size(root)
    assert (counted.files, counted.bytes, counted.folders, counted.links) == (3, 1105, 3, 0)
    assert root.is_dir()  # tree_size removes nothing
    removed = remove_tree(root)
    assert removed.to_dict() == {
        "files": 3,
        "bytes": 1105,
        "links": 0,
        "folders": 3,
        "errors": [],
    }
    assert not root.exists()


def test_remove_tree_of_a_missing_path_or_a_single_file(tmp_path):
    assert remove_tree(tmp_path / "missing").to_dict()["files"] == 0
    single = tmp_path / "one.txt"
    single.write_bytes(b"abc")
    stats = remove_tree(single)
    assert (stats.files, stats.bytes, stats.folders) == (1, 3, 0)
    assert not single.exists()


def test_remove_tree_makes_read_only_files_and_folders_writable(tmp_path):
    # Go marks its module cache read-only; git marks its pack files read-only on Windows.
    root = tmp_path / "mod"
    make_tree(root)
    for path in (root / "a" / "b" / "two.bin", root / "a" / "one.bin", root / "top.txt"):
        read_only(path)
    for folder in (root / "a" / "b", root / "a"):
        read_only(folder)
    stats = remove_tree(root)
    assert stats.errors == [] and stats.files == 3
    assert not root.exists()


def test_remove_tree_never_follows_a_folder_link(tmp_path):
    outside = tmp_path / "outside"
    make_tree(outside)
    root = tmp_path / "run"
    (root / "target").mkdir(parents=True)
    (root / "target" / "file.txt").write_bytes(b"kept? no")
    folder_link(root / "target" / "escape", outside)
    assert is_link(os.lstat(root / "target" / "escape"))
    counted = tree_size(root)
    assert (counted.files, counted.links) == (1, 1)  # the outside files are not counted
    stats = remove_tree(root)
    assert stats.errors == [] and (stats.files, stats.links) == (1, 1)
    assert not root.exists()
    assert sorted(p.name for p in outside.rglob("*")) == ["a", "b", "one.bin", "top.txt", "two.bin"]


def test_remove_tree_of_a_link_removes_only_the_link(tmp_path):
    outside = tmp_path / "outside"
    make_tree(outside)
    link = tmp_path / "target"
    folder_link(link, outside)
    stats = remove_tree(link)
    assert (stats.files, stats.links, stats.errors) == (0, 1, [])
    assert not os.path.lexists(link)
    assert (outside / "a" / "b" / "two.bin").is_file()


@pytest.mark.skipif(os.name != "nt", reason="the extended-length path form is Windows only")
def test_remove_tree_removes_a_path_of_260_or_more_characters(tmp_path):
    root = tmp_path / "long"
    deep = Path("\\\\?\\" + str(root.resolve()))
    while len(str(deep)) < 300:
        deep = deep / ("d" * 40)
    os.makedirs(deep)
    with open(deep / "file.txt", "wb") as handle:
        handle.write(b"long")
    stats = remove_tree(root)
    assert stats.errors == [] and stats.files == 1
    assert not root.exists()


def test_remove_tree_reports_an_error_and_goes_on(tmp_path, monkeypatch):
    root = tmp_path / "tree"
    make_tree(root)
    real_unlink = os.unlink

    def unlink(path, *args, **kwargs):
        if str(path).endswith("one.bin"):
            raise PermissionError(13, "Access is denied")
        return real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(fs.os, "unlink", unlink)
    stats = remove_tree(root)
    assert "a/one.bin: Access is denied" in stats.errors
    assert (root / "a" / "one.bin").exists()
    assert not (root / "a" / "b").exists() and not (root / "top.txt").exists()
    assert any(error.startswith("a:") for error in stats.errors)  # its folder stays too


def test_size_text_uses_decimal_units():
    assert fs.size_text(0) == "0 B"
    assert fs.size_text(999) == "999 B"
    assert fs.size_text(4_200) == "4.2 KB"
    assert fs.size_text(999_960) == "1.0 MB"  # never "1000.0 KB"
    assert fs.size_text(93_339_943) == "93.3 MB"
    assert fs.size_text(3_400_000_000) == "3.40 GB"
