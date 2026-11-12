# SPDX-License-Identifier: MIT
"""Tests for kalkan.sarif.uri (ENGINE-SPEC 8.1, location rules)."""

from __future__ import annotations

import os
from pathlib import Path, PurePosixPath, PureWindowsPath

import pytest

from kalkan.sarif.uri import is_target_relative, normalize_uri

WIN_ROOT = "C:\\Users\\DevKüçük\\kalkan\\runs\\R1\\target"
POSIX_ROOT = "/home/runner/work/app"


@pytest.mark.parametrize(
    ("uri", "expected"),
    [
        ("app/db.py", "app/db.py"),
        ("./app/db.py", "app/db.py"),
        ("././app/db.py", "app/db.py"),
        (".\\app\\db.py", "app/db.py"),
        ("app\\handlers\\user.py", "app/handlers/user.py"),
        ("app//db.py", "app/db.py"),
        ("app/./sub/../db.py", "app/db.py"),
        ("Dockerfile", "Dockerfile"),
        (" app/db.py ", "app/db.py"),
    ],
)
def test_relative_paths(uri, expected):
    assert normalize_uri(uri, WIN_ROOT) == expected
    assert normalize_uri(uri, POSIX_ROOT) == expected
    assert normalize_uri(uri, None) == expected


@pytest.mark.parametrize(
    "uri",
    [
        # Bandit: PurePath.as_uri() percent-encodes the non-ASCII user name.
        "file:///C:/Users/DevK%C3%BC%C3%A7%C3%BCk/kalkan/runs/R1/target/app/db.py",
        # A lower-case drive letter and an encoded colon (VS Code style).
        "file:///c%3A/Users/DevK%C3%BC%C3%A7%C3%BCk/kalkan/runs/R1/target/app/db.py",
        # Windows paths compare case-insensitively.
        "file:///C:/USERS/devküçük/KALKAN/runs/r1/TARGET/app/db.py",
        "file://localhost/C:/Users/DevKüçük/kalkan/runs/R1/target/app/db.py",
        "FILE:///C:/Users/DevKüçük/kalkan/runs/R1/target/app/db.py",
        "file:/C:/Users/DevKüçük/kalkan/runs/R1/target/app/db.py",
        # A malformed form with the drive in the host position.
        "file://C:/Users/DevKüçük/kalkan/runs/R1/target/app/db.py",
        # gosec on Windows: an absolute path with backslashes.
        "C:\\Users\\DevKüçük\\kalkan\\runs\\R1\\target\\app\\db.py",
        "c:\\users\\devküçük\\kalkan\\runs\\r1\\target\\app\\db.py",
        "C:/Users/DevKüçük/kalkan/runs/R1/target/app/db.py",
        "/C:/Users/DevKüçük/kalkan/runs/R1/target/app/db.py",
        # A decomposed (NFD) "ü", as macOS tools can write it.
        "C:/Users/DevKu\u0308\u00e7\u00fck/kalkan/runs/R1/target/app/db.py",
    ],
)
def test_windows_absolute_forms_under_the_root(uri):
    assert normalize_uri(uri, WIN_ROOT) == "app/db.py"


def test_root_forms_are_accepted():
    uri = "C:\\work\\target\\app\\db.py"
    for root in (
        "C:\\work\\target",
        "C:\\work\\target\\",
        "C:/work/target/",
        "c:/WORK/target",
        PureWindowsPath("C:/work/target"),
    ):
        assert normalize_uri(uri, root) == "app/db.py", root


def test_posix_absolute_paths():
    assert normalize_uri("/home/runner/work/app/src/main.go", POSIX_ROOT) == "src/main.go"
    assert normalize_uri("/home/runner/work/app/src/main.go", POSIX_ROOT + "/") == "src/main.go"
    assert normalize_uri("file:///home/runner/work/app/x.py", POSIX_ROOT) == "x.py"
    assert normalize_uri("/home/runner/work/app/x.py", PurePosixPath(POSIX_ROOT)) == "x.py"


def test_posix_paths_compare_case_sensitively():
    assert normalize_uri("/home/runner/work/App/x.py", POSIX_ROOT) == "/home/runner/work/App/x.py"


def test_a_prefix_that_is_not_a_whole_segment_does_not_match():
    assert normalize_uri("/home/runner/work/app2/x.py", POSIX_ROOT) == "/home/runner/work/app2/x.py"
    assert normalize_uri("C:/work/target2/x.py", "C:/work/target") == "C:/work/target2/x.py"


def test_absolute_paths_outside_the_root_stay_absolute():
    assert normalize_uri("D:\\other\\x.py", WIN_ROOT) == "D:/other/x.py"
    assert normalize_uri("/package-lock.json", WIN_ROOT) == "/package-lock.json"
    assert normalize_uri("file:///etc/passwd", POSIX_ROOT) == "/etc/passwd"
    assert normalize_uri("C:\\x\\y.py", None) == "C:/x/y.py"


def test_the_root_itself_gives_an_empty_path():
    assert normalize_uri(WIN_ROOT, WIN_ROOT) == ""


def test_posix_root_slash():
    assert normalize_uri("/usr/lib/x.so", "/") == "usr/lib/x.so"


def test_unc_paths():
    root = "\\\\server\\share\\proj"
    assert normalize_uri("\\\\server\\share\\proj\\a.py", root) == "a.py"
    assert normalize_uri("file://server/share/proj/a.py", root) == "a.py"
    assert normalize_uri("file://SERVER/share/proj/a.py", root) == "a.py"


def test_turkish_dotted_capital_i_compares_without_a_length_change():
    # "İ".casefold() is two code points. A segment comparison keeps the remainder exact.
    assert (
        normalize_uri("C:/Users/İsmail/proj/src/a.py", "c:/users/i\u0307smail/proj") == "src/a.py"
    )
    assert normalize_uri("C:/Users/Ismail/proj/a.py", "C:/Users/İsmail/proj") == (
        "C:/Users/Ismail/proj/a.py"
    )


def test_percent_encoding_is_decoded():
    assert normalize_uri("my%20file.py", None) == "my file.py"
    assert normalize_uri("src/%C3%A7%C4%B1kt%C4%B1.py", None) == "src/çıktı.py"
    # An invalid escape stays as written.
    assert normalize_uri("100%done.py", None) == "100%done.py"


def test_parent_segments_are_kept():
    assert normalize_uri("../outside.py", WIN_ROOT) == "../outside.py"
    assert normalize_uri("a/../../outside.py", WIN_ROOT) == "../outside.py"


@pytest.mark.parametrize("uri", ["", "   ", None, 42, ["a.py"]])
def test_missing_uri_gives_an_empty_string(uri):
    assert normalize_uri(uri, WIN_ROOT) == ""  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "uri",
    ["https://example.com/a.py", "git+ssh://host/repo.git", "pkg:npm/lodash@4.17.20", "urn:x:y"],
)
def test_other_schemes_stay_unchanged(uri):
    assert normalize_uri(uri, WIN_ROOT) == uri


# --- uriBaseId -----------------------------------------------------------------------------------


def test_uri_base_id_under_the_root():
    bases = {"ROOTPATH": {"uri": "file:///C:/Users/DevK%C3%BC%C3%A7%C3%BCk/kalkan/runs/R1/target/"}}
    assert normalize_uri("requirements.txt", WIN_ROOT, bases, uri_base_id="ROOTPATH") == (
        "requirements.txt"
    )
    assert normalize_uri("src/app.py", WIN_ROOT, bases, uri_base_id="ROOTPATH") == "src/app.py"


def test_uri_base_id_below_the_root():
    bases = {"SRC": {"uri": "file:///home/runner/work/app/src/"}}
    assert normalize_uri("main.go", POSIX_ROOT, bases, uri_base_id="SRC") == "src/main.go"


def test_uri_base_id_without_a_trailing_slash():
    bases = {"SRC": {"uri": "file:///home/runner/work/app/src"}}
    assert normalize_uri("main.go", POSIX_ROOT, bases, uri_base_id="SRC") == "src/main.go"


def test_uri_base_id_outside_the_root_keeps_the_relative_uri():
    # Trivy writes ROOTPATH "file:///". The scan root of the tool is the target root.
    bases = {"ROOTPATH": {"uri": "file:///"}}
    assert normalize_uri("requirements.txt", WIN_ROOT, bases, uri_base_id="ROOTPATH") == (
        "requirements.txt"
    )
    bases = {"ROOTPATH": {"uri": "file:///src/"}}
    assert normalize_uri("app.py", POSIX_ROOT, bases, uri_base_id="ROOTPATH") == "app.py"


def test_chained_uri_base_ids():
    bases = {
        "SRC": {"uri": "src/", "uriBaseId": "ROOT"},
        "ROOT": {"uri": "file:///C:/Users/DevKüçük/kalkan/runs/R1/target/"},
    }
    assert normalize_uri("a.py", WIN_ROOT, bases, uri_base_id="SRC") == "src/a.py"


def test_relative_base_without_a_parent_is_relative_to_the_root():
    assert normalize_uri("a.py", WIN_ROOT, {"SRC": {"uri": "src"}}, uri_base_id="SRC") == "src/a.py"
    assert normalize_uri("a.py", WIN_ROOT, {"SRC": "lib/"}, uri_base_id="SRC") == "lib/a.py"


def test_a_cycle_of_base_ids_stops():
    bases = {"A": {"uri": "a/", "uriBaseId": "B"}, "B": {"uri": "b/", "uriBaseId": "A"}}
    result = normalize_uri("x.py", WIN_ROOT, bases, uri_base_id="A")
    assert result.endswith("x.py")
    assert not os.path.isabs(result)


@pytest.mark.parametrize(
    "bases",
    [
        {},
        {"OTHER": {"uri": "file:///x/"}},
        {"%SRCROOT%": {}},
        {"%SRCROOT%": {"uri": ""}},
        {"%SRCROOT%": 3},
    ],
)
def test_unknown_or_empty_base_uses_the_relative_uri(bases):
    assert normalize_uri("app/a.py", WIN_ROOT, bases, uri_base_id="%SRCROOT%") == "app/a.py"


def test_base_is_ignored_for_an_absolute_uri():
    bases = {"ROOTPATH": {"uri": "file:///elsewhere/"}}
    uri = "file:///C:/Users/DevKüçük/kalkan/runs/R1/target/a.py"
    assert normalize_uri(uri, WIN_ROOT, bases, uri_base_id="ROOTPATH") == "a.py"


def test_a_foreign_scheme_base_is_ignored():
    bases = {"WEB": {"uri": "https://example.com/repo/"}}
    assert normalize_uri("a.py", WIN_ROOT, bases, uri_base_id="WEB") == "a.py"


# --- target root forms ---------------------------------------------------------------------------


def test_relative_root_is_made_absolute_against_the_working_directory(tmp_path, monkeypatch):
    # resolve() expands Windows 8.3 short names, so the URI and the working directory agree.
    base = tmp_path.resolve()
    target = base / "target"
    target.mkdir()
    monkeypatch.chdir(base)
    uri = (target / "src" / "a.py").as_uri()
    assert normalize_uri(uri, "target") == "src/a.py"
    assert normalize_uri(uri, Path("target")) == "src/a.py"


def test_empty_root_is_no_root():
    assert normalize_uri("C:/x/a.py", "") == "C:/x/a.py"
    assert normalize_uri("C:/x/a.py", "   ") == "C:/x/a.py"


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("app/db.py", True),
        ("Dockerfile", True),
        ("", False),
        ("/abs/a.py", False),
        ("C:/abs/a.py", False),
        ("../a.py", False),
        ("..", False),
        ("https://example.com/a.py", False),
        ("..a/b.py", True),
    ],
)
def test_is_target_relative(path, expected):
    assert is_target_relative(path) is expected
