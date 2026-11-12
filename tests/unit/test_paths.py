# SPDX-License-Identifier: MIT
"""Tests for kalkan.util.paths: safe relative paths, POSIX conversion and the repository root."""

from __future__ import annotations

from pathlib import Path, PurePosixPath, PureWindowsPath

import pytest

from kalkan.errors import KalkanError
from kalkan.util import paths
from kalkan.util.paths import (
    KALKAN_HOME_ENV,
    PATH_FORBIDDEN_CHARACTER,
    WINDOWS_RESERVED_COMPONENT,
    find_repo_root,
    is_safe_relative_path,
    is_safe_relative_source_path,
    repo_root,
    to_posix,
)

KELVIN = "\U0000212a"
SUP1, SUP2, SUP3 = "\U000000b9", "\U000000b2", "\U000000b3"
LONE_HIGH, LONE_LOW = "\U0000d800", "\U0000dc00"
REPOSITORY = Path(__file__).resolve().parents[2]

# The bad paths of both upstream test suites.
UNSAFE_PATHS = [
    "",
    "/etc/passwd",
    "../src/file.c",
    "src/../file.c",
    "src/./file.c",
    "src//file.c",
    "src/",
    "C:\\src\\file.c",
    "src\\file.c",
    "C:/src/file.js",
    "src/file:name.c",
    "~home/file.c",
    "src/file\nname.c",
    "src/file\x01name.c",
    "src/file\x85name.c",
    "src/file\U00002028name.c",
    "src/file\U0000202ename.c",
    "src/file\U00002066name.c",
    "src/file\U0000200dname.c",
    "src/file\U0000200b.js",
    "src/file\U0000034fname.c",
    "src/file\U0000fe0fname.c",
    "src/file" + LONE_HIGH + "name.c",
    "src/file" + LONE_LOW + "name.c",
    "CON",
    "NUL.txt",
    "src/con.txt",
    "src/PRN",
    "src/AUX.c",
    "src/NUL",
    "src/COM1.log",
    "src/lpt9",
    "src/CONIN$",
    "src/conin$.txt",
    "src/CONOUT$.txt",
    "src/conout$",
    "src/CLOCK$.txt",
    "src/cloc" + KELVIN + "$.txt",
    "src/COM" + SUP1 + ".log",
    "src/COM" + SUP2 + ".log",
    "src/COM" + SUP3 + ".log",
    "src/LPT" + SUP2 + ".log",
    "src/lpt" + SUP1,
    "src/lpt" + SUP3,
    "src /file.c",
    "src./file.c",
    "src/file.c ",
    "src/file.c.",
    " src/file.c",
    "src/file.c\U0000feff",
]
SAFE_PATHS = [
    "src/handler.js",
    "src/caf\U000000e9/handler.js",
    "src/\U000065e5\U0000672c\U00008a9e/\U00000444\U00000430\U00000439\U0000043b.ts",
    "src/\U000065e5\U0000672c\U00008a9e/cafe\U00000301-\U0001f600.ts",
    "src/ma\U000000f1ana/\U00000444\U00000430\U00000439\U0000043b.ts",
    "src/\U00004fee\U00006b63/\U000000e9xito.ts",
    "agents/hunter-1/artifacts/result.txt",
    "src/console.txt",
    "src/com10.log",
    "src/nulx",
    "src/.hidden",
    "a",
]


@pytest.mark.parametrize("value", UNSAFE_PATHS, ids=ascii)
def test_rejects_unsafe_paths(value):
    assert is_safe_relative_path(value) is False


@pytest.mark.parametrize("value", SAFE_PATHS, ids=ascii)
def test_accepts_safe_paths(value):
    assert is_safe_relative_path(value) is True


def test_rejects_non_strings():
    for value in (None, 1, b"src/file.c", ["src/file.c"], Path("src/file.c")):
        assert is_safe_relative_path(value) is False


def test_source_path_check_is_the_same_function():
    assert is_safe_relative_source_path is is_safe_relative_path


def test_windows_reserved_component_folds_like_javascript_iu():
    assert WINDOWS_RESERVED_COMPONENT.search("CLOCK$")
    assert WINDOWS_RESERVED_COMPONENT.search("cloc" + KELVIN + "$.txt")
    assert WINDOWS_RESERVED_COMPONENT.search("Com" + SUP1)
    assert WINDOWS_RESERVED_COMPONENT.search("nul.tar.gz")
    # JavaScript simple case folding does not map dotless i or dotted capital I onto "i".
    assert not WINDOWS_RESERVED_COMPONENT.search("con\U00000131n$")
    assert not WINDOWS_RESERVED_COMPONENT.search("con\U00000130n$")
    # JavaScript "$" never matches before a trailing newline.
    assert not WINDOWS_RESERVED_COMPONENT.search("con\n")
    assert not WINDOWS_RESERVED_COMPONENT.search("com0")
    assert not WINDOWS_RESERVED_COMPONENT.search("connect")


def test_path_forbidden_character():
    for character in ("\x00", "\x7f", "\x9f", "\U000000ad", "\U00002028", "\U0000202e"):
        assert PATH_FORBIDDEN_CHARACTER.search("a" + character), ascii(character)
    for character in (" ", "\U000000e9", "\U00003000", "\U0001f600"):
        assert not PATH_FORBIDDEN_CHARACTER.search("a" + character), ascii(character)


def test_to_posix():
    assert to_posix(PureWindowsPath("src\\pkg\\mod.py")) == "src/pkg/mod.py"
    assert to_posix(PureWindowsPath("C:\\work\\target")) == "C:/work/target"
    assert to_posix(PurePosixPath("src/a.py")) == "src/a.py"
    assert to_posix(Path("src") / "a.py") == "src/a.py"
    assert to_posix("src/./a.py") == "src/a.py"
    assert to_posix("") == ""
    with pytest.raises(TypeError):
        to_posix(b"src/a.py")


def test_to_posix_converts_backslashes_on_windows_only():
    expected = "src/a.py" if paths.os.name == "nt" else "src\\a.py"
    assert to_posix("src\\a.py") == expected


def test_repo_root_finds_this_checkout(monkeypatch):
    monkeypatch.delenv(KALKAN_HOME_ENV, raising=False)
    assert repo_root() == REPOSITORY
    assert (repo_root() / "pyproject.toml").is_file()


def test_repo_root_honours_kalkan_home(monkeypatch, tmp_path):
    monkeypatch.setenv(KALKAN_HOME_ENV, str(tmp_path))
    assert repo_root() == tmp_path.resolve()
    monkeypatch.setenv(KALKAN_HOME_ENV, str(tmp_path / "missing"))
    with pytest.raises(KalkanError, match=KALKAN_HOME_ENV):
        repo_root()
    monkeypatch.setenv(KALKAN_HOME_ENV, "")
    assert repo_root() == REPOSITORY


def test_find_repo_root_checks_the_project_name(tmp_path):
    other = tmp_path / "outer" / "inner"
    other.mkdir(parents=True)
    (tmp_path / "outer" / "pyproject.toml").write_text(
        '[project]\nname = "other"\n', encoding="utf-8"
    )
    (other / "pyproject.toml").write_text("not = [valid toml", encoding="utf-8")
    assert find_repo_root(other) is None
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "kalkan"\n', encoding="utf-8")
    assert find_repo_root(other) == tmp_path.resolve()
