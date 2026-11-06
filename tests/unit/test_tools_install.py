# SPDX-License-Identifier: MIT
"""Tests for kalkan.tools.install: download, SHA-256 check, safe extraction, toolchains, pip and
go tools.

The binary tool archives come from tests/fixtures/tools (see make_fixtures.py); the toolchain
archives are written by the tests. All are served through file:// URLs. No test uses the
network.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import subprocess
import tarfile
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

import pytest

from kalkan.errors import ToolError
from kalkan.tools import install as install_mod
from kalkan.tools import toolhome
from kalkan.tools.install import (
    STATUS_FAILED,
    STATUS_INSTALLED,
    STATUS_PRESENT,
    STATUS_SKIPPED,
    VERIFY_MISMATCH,
    VERIFY_MISSING,
    VERIFY_OK,
    VERIFY_SKIPPED,
    download_verified,
    extract_member,
    extract_tree,
    hash_tree,
    install,
    tree_member_problem,
    verify,
    verify_dist_record,
)
from kalkan.tools.manifest import Manifest, Tool, parse_manifest, tree_digest
from kalkan.tools.platform import PLATFORMS
from kalkan.tools.resolve import installed_json_path, pyenv_dir, pyenv_python, read_installed

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "tools"
FAKE_BINARY = b"\x7fELF-kalkan-test-binary\x00faketool 1.2.3\n"
FAKE_SHA = hashlib.sha256(FAKE_BINARY).hexdigest()
KEY = "linux-amd64"  # a fixed platform key: the binary is "faketool" on every host


def file_sha(name: str) -> str:
    return hashlib.sha256((FIXTURES / name).read_bytes()).hexdigest()


def binary_entry(
    fixture: str,
    archive: str,
    member: str,
    *,
    sha256: str | None = None,
    binary_sha256: str | None = FAKE_SHA,
    platforms: tuple[str, ...] = PLATFORMS,
    notes: str = "",
) -> dict:
    asset = {
        "url": (FIXTURES / fixture).as_uri(),
        "sha256": sha256 or file_sha(fixture),
        "archive": archive,
        "binary": member,
    }
    if binary_sha256:
        asset["binary_sha256"] = binary_sha256
    return {
        "version": "1.2.3",
        "license": "MIT",
        "kind": "binary",
        "executable": "faketool",
        "version_args": ["--version"],
        "blocked_versions": ["1.2.2"],
        "sha256_source": "computed-at-pin-time",
        "notes": notes,
        "platforms": {key: dict(asset) for key in platforms},
    }


def make_manifest(**tools: dict) -> Manifest:
    return parse_manifest({"schema_version": 1, "tools": tools})


def bin_path(root: Path, name: str = "faketool", version: str = "1.2.3") -> Path:
    return root / ".tools" / name / version / "bin" / name


def install_one(root: Path, entry: dict, **kwargs):
    manifest = make_manifest(faketool=entry)
    (result,) = install(["faketool"], repo_root=root, manifest=manifest, key=KEY, **kwargs)
    return result


def assert_nothing_installed(root: Path) -> None:
    assert not bin_path(root).exists()
    assert not list((root / ".tools").rglob("*.part"))
    assert not list((root / ".tools").rglob(".extract-*"))
    assert "faketool" not in read_installed(root)["tools"]
    assert not list(root.rglob("evil.txt"))
    assert not (root / ".tools" / ".tmp").exists()


# --- binary tools -----------------------------------------------------------------------------


def test_install_from_zip(tmp_path):
    result = install_one(
        tmp_path, binary_entry("faketool-1.2.3.zip", "zip", "faketool-1.2.3/faketool")
    )
    assert result.status == STATUS_INSTALLED, result.message
    target = bin_path(tmp_path)
    assert target.read_bytes() == FAKE_BINARY
    assert result.path == ".tools/faketool/1.2.3/bin/faketool"
    assert result.sha256 == FAKE_SHA
    record = read_installed(tmp_path)["tools"]["faketool"]
    assert record["version"] == "1.2.3"
    assert record["path"] == ".tools/faketool/1.2.3/bin/faketool"
    assert record["sha256"] == FAKE_SHA
    assert record["asset_sha256"] == file_sha("faketool-1.2.3.zip")
    if os.name != "nt":
        assert os.stat(target).st_mode & 0o111
    assert not (tmp_path / ".tools" / ".tmp").exists()


def test_install_from_tar_gz(tmp_path):
    result = install_one(tmp_path, binary_entry("faketool-1.2.3.tar.gz", "tar.gz", "faketool"))
    assert result.status == STATUS_INSTALLED, result.message
    assert bin_path(tmp_path).read_bytes() == FAKE_BINARY


def test_install_raw_binary(tmp_path):
    entry = binary_entry("faketool-raw.bin", "none", "faketool-raw.bin")
    result = install_one(tmp_path, entry)
    assert result.status == STATUS_INSTALLED, result.message
    assert bin_path(tmp_path).read_bytes() == FAKE_BINARY


def test_windows_platform_key_adds_exe_suffix(tmp_path):
    manifest = make_manifest(faketool=binary_entry("faketool-1.2.3.tar.gz", "tar.gz", "faketool"))
    (result,) = install("all", repo_root=tmp_path, manifest=manifest, key="windows-amd64")
    assert result.status == STATUS_INSTALLED, result.message
    assert result.path == ".tools/faketool/1.2.3/bin/faketool.exe"


def test_second_install_is_present_and_force_reinstalls(tmp_path):
    entry = binary_entry("faketool-1.2.3.zip", "zip", "faketool-1.2.3/faketool")
    assert install_one(tmp_path, entry).status == STATUS_INSTALLED
    assert install_one(tmp_path, entry).status == STATUS_PRESENT
    assert install_one(tmp_path, entry, force=True).status == STATUS_INSTALLED


def test_tampered_binary_is_replaced_on_install(tmp_path):
    entry = binary_entry("faketool-1.2.3.zip", "zip", "faketool-1.2.3/faketool")
    install_one(tmp_path, entry)
    bin_path(tmp_path).write_bytes(b"tampered")
    assert install_one(tmp_path, entry).status == STATUS_INSTALLED
    assert bin_path(tmp_path).read_bytes() == FAKE_BINARY


def test_sha256_mismatch_is_refused(tmp_path):
    entry = binary_entry("faketool-1.2.3.zip", "zip", "faketool-1.2.3/faketool", sha256="0" * 64)
    result = install_one(tmp_path, entry)
    assert result.status == STATUS_FAILED
    assert "SHA-256 mismatch" in result.message
    assert_nothing_installed(tmp_path)


def test_binary_sha256_mismatch_is_refused(tmp_path):
    entry = binary_entry(
        "faketool-1.2.3.zip", "zip", "faketool-1.2.3/faketool", binary_sha256="1" * 64
    )
    result = install_one(tmp_path, entry)
    assert result.status == STATUS_FAILED
    assert "SHA-256 mismatch" in result.message
    assert_nothing_installed(tmp_path)


@pytest.mark.parametrize(
    ("fixture", "archive", "reason"),
    [
        ("traversal.zip", "zip", "'..'"),
        ("traversal.tar.gz", "tar.gz", "'..'"),
        ("absolute.tar.gz", "tar.gz", "absolute member path"),
        ("symlink.zip", "zip", "symbolic link member"),
        ("symlink.tar.gz", "tar.gz", "link member"),
        ("hardlink.tar.gz", "tar.gz", "link member"),
        ("device.tar.gz", "tar.gz", "device or special file"),
        ("duplicate.zip", "zip", "2 members named"),
    ],
)
def test_unsafe_archives_are_refused(tmp_path, fixture, archive, reason):
    result = install_one(tmp_path, binary_entry(fixture, archive, "faketool"))
    assert result.status == STATUS_FAILED
    assert reason in result.message
    assert_nothing_installed(tmp_path)


def test_missing_member_is_refused(tmp_path):
    result = install_one(tmp_path, binary_entry("faketool-1.2.3.zip", "zip", "faketool"))
    assert result.status == STATUS_FAILED
    assert "has no member 'faketool'" in result.message
    assert_nothing_installed(tmp_path)


def test_missing_platform_build_is_skipped(tmp_path):
    entry = binary_entry(
        "faketool-1.2.3.zip",
        "zip",
        "faketool-1.2.3/faketool",
        platforms=tuple(p for p in PLATFORMS if p != KEY),
        notes=f"No {KEY} build in this release.",
    )
    result = install_one(tmp_path, entry)
    assert result.status == STATUS_SKIPPED
    assert KEY in result.message


def test_blocked_version_is_refused(tmp_path):
    parsed = make_manifest(
        faketool=binary_entry("faketool-1.2.3.zip", "zip", "faketool-1.2.3/faketool")
    )
    good = parsed.get("faketool")
    blocked = Tool(
        name="faketool",
        version="1.2.3",
        kind="binary",
        license="MIT",
        executable="faketool",
        blocked_versions=("1.2.3",),
        platforms=good.platforms,
    )
    (result,) = install(
        ["faketool"], repo_root=tmp_path, manifest=Manifest(tools={"faketool": blocked}), key=KEY
    )
    assert result.status == STATUS_FAILED
    assert "blocked" in result.message
    assert_nothing_installed(tmp_path)


def test_unknown_tool_name_raises(tmp_path):
    manifest = make_manifest(
        faketool=binary_entry("faketool-1.2.3.zip", "zip", "faketool-1.2.3/faketool")
    )
    with pytest.raises(ToolError, match="unknown tool"):
        install(["nope"], repo_root=tmp_path, manifest=manifest, key=KEY)


def test_installed_json_is_valid_json_with_trailing_newline(tmp_path):
    install_one(tmp_path, binary_entry("faketool-1.2.3.tar.gz", "tar.gz", "faketool"))
    text = installed_json_path(tmp_path).read_text(encoding="utf-8")
    assert text.endswith("}\n")
    assert json.loads(text)["schema_version"] == 1


# --- download and extraction helpers ----------------------------------------------------------


def test_download_refuses_plain_http(tmp_path):
    with pytest.raises(ToolError, match="non-HTTPS"):
        download_verified("http://example.com/tool.zip", "0" * 64, dest_dir=tmp_path)


def test_download_stops_at_the_size_limit(tmp_path):
    url = (FIXTURES / "faketool-1.2.3.zip").as_uri()
    with pytest.raises(ToolError, match="larger than 10 bytes"):
        download_verified(url, file_sha("faketool-1.2.3.zip"), dest_dir=tmp_path, max_bytes=10)
    assert list(tmp_path.iterdir()) == []


def test_download_of_a_missing_file_fails_cleanly(tmp_path):
    url = (FIXTURES / "does-not-exist.zip").as_uri()
    with pytest.raises(ToolError, match="download failed"):
        download_verified(url, "0" * 64, dest_dir=tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_redirects_must_stay_on_https():
    handler = install_mod._HttpsOnlyRedirectHandler()
    request = urllib.request.Request("https://example.com/a")
    with pytest.raises(urllib.error.HTTPError):
        handler.redirect_request(request, None, 302, "Found", {}, "http://example.com/b")
    follow = handler.redirect_request(request, None, 302, "Found", {}, "https://example.com/b")
    assert follow.full_url == "https://example.com/b"


def test_extract_member_returns_path_and_hash(tmp_path):
    path, digest = extract_member(
        FIXTURES / "faketool-1.2.3.tar.gz", "tar.gz", "faketool", tmp_path
    )
    assert path.parent == tmp_path
    assert path.read_bytes() == FAKE_BINARY
    assert digest == FAKE_SHA


def test_extract_member_rejects_a_corrupt_archive(tmp_path):
    broken = tmp_path / "broken.zip"
    broken.write_bytes(b"PK\x03\x04 not really a zip")
    with pytest.raises(ToolError):
        extract_member(broken, "zip", "faketool", tmp_path / "out")


# --- verify -----------------------------------------------------------------------------------


def test_verify_reports_ok_mismatch_and_missing(tmp_path):
    entry = binary_entry("faketool-1.2.3.zip", "zip", "faketool-1.2.3/faketool")
    manifest = make_manifest(faketool=entry)
    (missing,) = verify(repo_root=tmp_path, manifest=manifest, key=KEY)
    assert missing.status == VERIFY_MISSING

    install(["faketool"], repo_root=tmp_path, manifest=manifest, key=KEY)
    (ok,) = verify(repo_root=tmp_path, manifest=manifest, key=KEY)
    assert ok.status == VERIFY_OK
    assert ok.actual_sha256 == FAKE_SHA

    bin_path(tmp_path).write_bytes(b"tampered")
    (bad,) = verify(repo_root=tmp_path, manifest=manifest, key=KEY)
    assert bad.status == VERIFY_MISMATCH
    assert not bad.ok


def test_verify_skips_a_platform_without_build(tmp_path):
    entry = binary_entry(
        "faketool-1.2.3.zip",
        "zip",
        "faketool-1.2.3/faketool",
        platforms=("windows-amd64",),
        notes="Only windows-amd64; no windows-arm64, linux-amd64, linux-arm64, darwin-amd64, "
        "darwin-arm64 builds.",
    )
    (result,) = verify(repo_root=tmp_path, manifest=make_manifest(faketool=entry), key=KEY)
    assert result.status == VERIFY_SKIPPED


def test_verify_dist_record(tmp_path):
    venv = tmp_path / "venv"
    site = venv / "Lib" / "site-packages"
    package = site / "fakepkg"
    package.mkdir(parents=True)
    module = package / "__init__.py"
    module.write_bytes(b"VALUE = 1\n")
    digest = base64.urlsafe_b64encode(hashlib.sha256(b"VALUE = 1\n").digest()).rstrip(b"=")
    info = site / "fakepkg-1.0.dist-info"
    info.mkdir()
    (info / "RECORD").write_text(
        f"fakepkg/__init__.py,sha256={digest.decode()},10\n"
        "fakepkg-1.0.dist-info/RECORD,,\n"
        "fakepkg/__pycache__/__init__.cpython-313.pyc,,\n",
        encoding="utf-8",
    )
    assert verify_dist_record(venv, "fakepkg", "1.0") == []
    module.write_bytes(b"VALUE = 2\n")
    assert verify_dist_record(venv, "fakepkg", "1.0") == ["fakepkg/__init__.py: SHA-256 differs"]
    assert verify_dist_record(venv, "fakepkg", "2.0") == ["no RECORD file for fakepkg 2.0"]


def test_verify_dist_record_rejects_paths_outside_the_venv(tmp_path):
    venv = tmp_path / "venv"
    info = venv / "Lib" / "site-packages" / "fakepkg-1.0.dist-info"
    info.mkdir(parents=True)
    (info / "RECORD").write_text("../../../../evil.py,sha256=AAAA,1\n", encoding="utf-8")
    assert verify_dist_record(venv, "fakepkg", "1.0") == ["../../../../evil.py: outside the venv"]


# --- pip tools --------------------------------------------------------------------------------


def pip_entry(package: str, requirement: str, version: str) -> dict:
    return {
        "version": version,
        "license": "MIT",
        "kind": "pip",
        "executable": package,
        "blocked_versions": [],
        "package": package,
        "requirement": requirement,
        "notes": "",
    }


def script_path(root: Path, name: str) -> Path:
    if os.name == "nt":
        return pyenv_dir(root) / "Scripts" / f"{name}.exe"
    return pyenv_dir(root) / "bin" / name


class FakePip:
    """Simulate ``python -m venv``, ``pip install`` and the package query."""

    def __init__(self, root: Path, versions: dict[str, str]) -> None:
        self.root = root
        self.versions = versions
        self.calls: list[list[str]] = []

    def __call__(self, argv, *, timeout, env=None, cwd=None):
        argv = [str(a) for a in argv]
        self.calls.append(argv)
        if argv[1:3] == ["-m", "venv"]:
            python = pyenv_python(self.root)
            python.parent.mkdir(parents=True, exist_ok=True)
            python.write_bytes(b"")
            return subprocess.CompletedProcess(argv, 0, "", "")
        if argv[1:4] == ["-m", "pip", "install"]:
            for name in ("fakepip", "otherpip"):
                script = script_path(self.root, name)
                script.parent.mkdir(parents=True, exist_ok=True)
                script.write_bytes(b"")
            return subprocess.CompletedProcess(argv, 0, "Successfully installed", "")
        if argv[1:3] == ["-I", "-c"]:
            return subprocess.CompletedProcess(argv, 0, json.dumps(self.versions) + "\n", "")
        raise AssertionError(f"unexpected command: {argv}")


def test_pip_tools_install_into_one_venv(tmp_path):
    manifest = make_manifest(
        fakepip=pip_entry("fakepip", "fakepip==3.3.22", "3.3.22"),
        otherpip=pip_entry("otherpip", "otherpip[sarif]==1.9.4", "1.9.4"),
    )
    runner = FakePip(tmp_path, {"fakepip": "3.3.22", "otherpip": "1.9.4", "PyYAML": "6.0.2"})
    results = install("all", repo_root=tmp_path, manifest=manifest, key=KEY, runner=runner)
    assert [r.status for r in results] == [STATUS_INSTALLED, STATUS_INSTALLED]
    venv_call, pip_call, _query = runner.calls
    assert venv_call[1:] == ["-m", "venv", str(pyenv_dir(tmp_path.resolve()))]
    assert "--disable-pip-version-check" in pip_call
    assert "--no-cache-dir" in pip_call  # no download stays in the pip cache of the user
    assert pip_call[-2:] == ["fakepip==3.3.22", "otherpip[sarif]==1.9.4"]
    data = read_installed(tmp_path)
    assert data["tools"]["fakepip"]["version"] == "3.3.22"
    assert data["tools"]["otherpip"]["requirement"] == "otherpip[sarif]==1.9.4"
    assert data["pyenv"]["packages"]["PyYAML"] == "6.0.2"

    runner.calls.clear()
    results = install("all", repo_root=tmp_path, manifest=manifest, key=KEY, runner=runner)
    assert [r.status for r in results] == [STATUS_PRESENT, STATUS_PRESENT]
    assert all(call[1:3] == ["-I", "-c"] for call in runner.calls)


def test_pip_version_drift_is_a_failure(tmp_path):
    manifest = make_manifest(fakepip=pip_entry("fakepip", "fakepip==3.3.22", "3.3.22"))
    runner = FakePip(tmp_path, {"fakepip": "3.3.21"})
    (result,) = install("all", repo_root=tmp_path, manifest=manifest, key=KEY, runner=runner)
    assert result.status == STATUS_FAILED
    assert "expected 3.3.22" in result.message


def test_pip_failure_is_reported(tmp_path):
    manifest = make_manifest(fakepip=pip_entry("fakepip", "fakepip==3.3.22", "3.3.22"))

    def runner(argv, *, timeout, env=None, cwd=None):
        return subprocess.CompletedProcess(argv, 1, "", "ERROR: No matching distribution")

    (result,) = install("all", repo_root=tmp_path, manifest=manifest, key=KEY, runner=runner)
    assert result.status == STATUS_FAILED
    assert "No matching distribution" in result.message


# --- toolchains (the Go tree) -----------------------------------------------------------------

GO_VERSION = "1.26.9"
GO_FILES = {
    "go/bin/go": b"\x7fELF-fake-go\n",
    "go/VERSION": b"go1.26.9\n",
    "go/src/fmt/print.go": b"package fmt\n",
}


def make_go_archive(folder: Path, kind: str, files: dict | None = None, extra=()) -> Path:
    """Write a small Go-like archive. ``extra`` adds raw members: (name, data or TarInfo)."""
    files = GO_FILES if files is None else files
    folder.mkdir(parents=True, exist_ok=True)
    if kind == "zip":
        path = folder / "go.zip"
        with zipfile.ZipFile(path, "w") as zf:
            for name, data in files.items():
                zf.writestr(name, data)
            for name, data in extra:
                zf.writestr(name, data)
        return path
    path = folder / "go.tar.gz"
    with tarfile.open(path, "w:gz") as tf:
        for directory in ("go", "go/bin", "go/src", "go/src/fmt"):
            info = tarfile.TarInfo(directory)
            info.type = tarfile.DIRTYPE
            info.mode = 0o755
            tf.addfile(info)
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o755 if name.endswith("bin/go") else 0o644
            tf.addfile(info, io.BytesIO(data))
        for name, member in extra:
            if isinstance(member, tarfile.TarInfo):
                tf.addfile(member)
            else:
                info = tarfile.TarInfo(name)
                info.size = len(member)
                tf.addfile(info, io.BytesIO(member))
    return path


def files_digest(files: dict) -> str:
    return tree_digest((name, hashlib.sha256(data).hexdigest()) for name, data in files.items())


def toolchain_entry(archive: Path, kind: str, content: dict | None = None, **overrides) -> dict:
    files = GO_FILES if content is None else content
    asset = {
        "url": archive.as_uri(),
        "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
        "archive": kind,
        "root": "go",
        "binary": "go/bin/go",
        "binary_sha256": hashlib.sha256(files["go/bin/go"]).hexdigest(),
        "files": len(files),
        "tree_sha256": files_digest(files),
        **overrides,
    }
    return {
        "version": GO_VERSION,
        "license": "BSD-3-Clause",
        "kind": "toolchain",
        "executable": "go",
        "version_args": ["env", "GOVERSION"],
        "blocked_versions": [],
        "sha256_source": "computed-at-pin-time",
        "notes": "",
        "platforms": {key: dict(asset) for key in PLATFORMS},
    }


def go_root(root: Path) -> Path:
    return root / ".tools" / "go" / GO_VERSION / "go"


def install_go(root: Path, entry: dict, **kwargs):
    (result,) = install(["go"], repo_root=root, manifest=make_manifest(go=entry), key=KEY, **kwargs)
    return result


def assert_no_go_tree(root: Path) -> None:
    assert not (root / ".tools" / "go").exists()
    assert not (root / ".tools" / ".tmp").exists()
    assert "go" not in read_installed(root)["tools"]


@pytest.mark.parametrize("kind", ["zip", "tar.gz"])
def test_toolchain_installs_the_whole_tree(tmp_path, kind):
    archive = make_go_archive(tmp_path / "dl", kind)
    entry = toolchain_entry(archive, kind)
    result = install_go(tmp_path / "repo", entry)
    root = tmp_path / "repo"
    assert result.status == STATUS_INSTALLED, result.message
    assert result.path == f".tools/go/{GO_VERSION}/go/bin/go"
    for name, data in GO_FILES.items():
        assert (root / ".tools" / "go" / GO_VERSION / name).read_bytes() == data
    if os.name != "nt" and kind == "tar.gz":
        assert os.access(go_root(root) / "bin" / "go", os.X_OK)
        assert not os.access(go_root(root) / "VERSION", os.X_OK)
    record = read_installed(root)["tools"]["go"]
    assert record["root"] == f".tools/go/{GO_VERSION}/go"
    assert record["tree_sha256"] == files_digest(GO_FILES)
    assert record["files"] == 3
    assert not (root / ".tools" / ".tmp").exists()
    manifest = make_manifest(go=entry)
    (deep,) = verify(["go"], repo_root=root, manifest=manifest, key=KEY)
    assert deep.status == VERIFY_OK and "tree SHA-256 ok" in deep.message
    (quick,) = verify(["go"], repo_root=root, manifest=manifest, key=KEY, deep=False)
    assert quick.status == VERIFY_OK


def test_toolchain_second_install_is_present_and_force_reinstalls(tmp_path):
    entry = toolchain_entry(make_go_archive(tmp_path / "dl", "zip"), "zip")
    assert install_go(tmp_path, entry).status == STATUS_INSTALLED
    assert install_go(tmp_path, entry).status == STATUS_PRESENT
    assert install_go(tmp_path, entry, force=True).status == STATUS_INSTALLED
    assert not list((tmp_path / ".tools").glob("go/*/*-old-*"))


def test_toolchain_damage_is_detected_and_repaired(tmp_path):
    entry = toolchain_entry(make_go_archive(tmp_path / "dl", "tar.gz"), "tar.gz")
    manifest = make_manifest(go=entry)
    install_go(tmp_path, entry)
    # A changed file: only the deep check reads it.
    (go_root(tmp_path) / "VERSION").write_bytes(b"go9.9.9\n")
    (deep,) = verify(["go"], repo_root=tmp_path, manifest=manifest, key=KEY)
    assert deep.status == VERIFY_MISMATCH and "tree SHA-256 differs" in deep.message
    # A planted file: the quick check counts it.
    (go_root(tmp_path) / "src" / "planted.go").write_bytes(b"package evil\n")
    (quick,) = verify(["go"], repo_root=tmp_path, manifest=manifest, key=KEY, deep=False)
    assert quick.status == VERIFY_MISMATCH and "4 files installed" in quick.message
    # install (no --force) sees the damage and installs the tree again.
    assert install_go(tmp_path, entry).status == STATUS_INSTALLED
    assert not (go_root(tmp_path) / "src" / "planted.go").exists()
    assert (go_root(tmp_path) / "VERSION").read_bytes() == GO_FILES["go/VERSION"]
    (deep,) = verify(["go"], repo_root=tmp_path, manifest=manifest, key=KEY)
    assert deep.status == VERIFY_OK


def test_toolchain_changed_executable_fails_the_quick_check(tmp_path):
    entry = toolchain_entry(make_go_archive(tmp_path / "dl", "zip"), "zip")
    install_go(tmp_path, entry)
    (go_root(tmp_path) / "bin" / "go").write_bytes(b"\x7fELF-other\n")
    (quick,) = verify(
        ["go"], repo_root=tmp_path, manifest=make_manifest(go=entry), key=KEY, deep=False
    )
    assert quick.status == VERIFY_MISMATCH and "go/bin/go" in quick.message


def test_toolchain_verify_reports_missing(tmp_path):
    entry = toolchain_entry(make_go_archive(tmp_path / "dl", "zip"), "zip")
    (checked,) = verify(["go"], repo_root=tmp_path, manifest=make_manifest(go=entry), key=KEY)
    assert checked.status == VERIFY_MISSING


@pytest.mark.parametrize(
    ("override", "reason"),
    [
        ({"tree_sha256": "0" * 64}, "tree SHA-256 mismatch"),
        ({"files": 4}, "the manifest pins 4"),
        ({"binary_sha256": "0" * 64}, "SHA-256 mismatch for go/bin/go"),
        ({"sha256": "0" * 64}, "SHA-256 mismatch for file:"),
    ],
)
def test_toolchain_pin_mismatch_is_refused(tmp_path, override, reason):
    entry = toolchain_entry(make_go_archive(tmp_path / "dl", "zip"), "zip", **override)
    result = install_go(tmp_path / "repo", entry)
    assert result.status == STATUS_FAILED
    assert reason in result.message
    assert_no_go_tree(tmp_path / "repo")


def test_toolchain_failed_install_keeps_the_previous_tree(tmp_path):
    good = toolchain_entry(make_go_archive(tmp_path / "dl", "zip"), "zip")
    install_go(tmp_path / "repo", good)
    bad = toolchain_entry(make_go_archive(tmp_path / "dl2", "zip"), "zip", tree_sha256="0" * 64)
    assert install_go(tmp_path / "repo", bad, force=True).status == STATUS_FAILED
    assert (go_root(tmp_path / "repo") / "bin" / "go").read_bytes() == GO_FILES["go/bin/go"]


def _tar_link(name: str, target: str, kind: bytes = tarfile.SYMTYPE) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.type = kind
    info.linkname = target
    return info


@pytest.mark.parametrize(
    ("kind", "extra", "reason"),
    [
        ("zip", [("other/readme.txt", b"x")], "outside the folder 'go'"),
        ("zip", [("go/../evil.txt", b"x")], "'..'"),
        ("zip", [("go/a:stream", b"x")], "Windows cannot store"),
        ("zip", [("go/src/CON.go", b"x")], "reserved Windows device name"),
        ("zip", [("go/src/trailing.", b"x")], "ends in a dot or a space"),
        ("zip", [("go/BIN/GO", b"x")], "duplicate member"),
        ("zip", [("go/VERSION/inner", b"x")], "below a file"),
        ("tar.gz", [("go/link", _tar_link("go/link", "/etc/passwd"))], "link member"),
        ("tar.gz", [("go/hard", _tar_link("go/hard", "go/VERSION", tarfile.LNKTYPE))], "link"),
        ("tar.gz", [("/go/abs", b"x")], "absolute member path"),
    ],
)
def test_unsafe_toolchain_archives_are_refused(tmp_path, kind, extra, reason):
    archive = make_go_archive(tmp_path / "dl", kind, extra=extra)
    result = install_go(tmp_path / "repo", toolchain_entry(archive, kind))
    assert result.status == STATUS_FAILED
    assert "unsafe archive, nothing extracted" in result.message
    assert reason in result.message
    assert_no_go_tree(tmp_path / "repo")
    assert not list(tmp_path.rglob("evil.txt"))


def test_extract_tree_needs_an_empty_folder(tmp_path):
    archive = make_go_archive(tmp_path / "dl", "zip")
    dest = tmp_path / "dest"
    dest.mkdir()
    (dest / "old.txt").write_text("x", encoding="utf-8")
    with pytest.raises(ToolError, match="empty folder"):
        extract_tree(archive, "zip", "go", dest)


def test_extract_tree_returns_count_and_digest(tmp_path):
    archive = make_go_archive(tmp_path / "dl", "tar.gz")
    dest = tmp_path / "dest"
    dest.mkdir()
    assert extract_tree(archive, "tar.gz", "go", dest) == (3, files_digest(GO_FILES))
    assert hash_tree(dest) == (3, files_digest(GO_FILES))
    assert hash_tree(dest, hash_files=False) == (3, "")


@pytest.mark.parametrize(
    ("name", "problem"),
    [
        ("go/bin/go.exe", None),
        ("go/src/a:b", "Windows cannot store"),
        ("go/src/aux.c", "reserved Windows device name"),
        ("go/src/x ", "ends in a dot or a space"),
        ("go/src/\x01", "Windows cannot store"),
        ("../go", "'..'"),
    ],
)
def test_tree_member_problem(name, problem):
    found = tree_member_problem(name)
    if problem is None:
        assert found is None
    else:
        assert found is not None and problem in found


# --- go-install tools -------------------------------------------------------------------------


def go_entry() -> dict:
    return {
        "version": "1.8.0",
        "license": "BSD-3-Clause",
        "kind": "go-install",
        "executable": "fakego",
        "version_args": ["-version"],
        "requires_go": True,
        "blocked_versions": [],
        "module": "example.com/fakego@v1.8.0",
        "min_go_version": "1.26",
        "notes": "",
    }


def fake_go(system_version: str, calls: list):
    """A runner: ``go env GOVERSION`` of a system Go, and ``go install`` into GOBIN."""

    def runner(argv, *, timeout, env=None, cwd=None):
        argv = [str(a) for a in argv]
        calls.append((argv, env, cwd))
        if argv[1:] == ["env", "GOVERSION"]:
            return subprocess.CompletedProcess(argv, 0, f"go{system_version}\n", "")
        if argv[1] == "install":
            target = Path(env["GOBIN"]) / "fakego"
            target.write_bytes(b"fake go binary")
            return subprocess.CompletedProcess(argv, 0, "", "")
        raise AssertionError(argv)

    return runner


def go_manifest(tmp_path: Path, **toolchain_overrides) -> Manifest:
    archive = make_go_archive(tmp_path / "dl", "tar.gz")
    return make_manifest(
        go=toolchain_entry(archive, "tar.gz", **toolchain_overrides), fakego=go_entry()
    )


SYSTEM_GO = Path("/usr/local/go/bin/go")


def test_go_install_installs_the_pinned_toolchain_first(tmp_path, monkeypatch):
    for name, value in {"GOFLAGS": "-mod=mod", "GONOSUMDB": "*", "GOOS": "plan9"}.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("GOPROXY", "https://proxy.example")
    calls: list = []
    root = tmp_path / "repo"
    results = install(
        ["fakego"],
        repo_root=root,
        manifest=go_manifest(tmp_path),
        key=KEY,
        runner=fake_go("1.26.1", calls),
        finder=lambda name: None,  # no Go on PATH
    )
    assert [(r.name, r.status) for r in results] == [
        ("go", STATUS_INSTALLED),
        ("fakego", STATUS_INSTALLED),
    ]
    assert results[1].path == ".tools/fakego/1.8.0/bin/fakego"
    argv, env, cwd = calls[-1]
    goroot = go_root(root.resolve())
    assert argv == [str(goroot / "bin" / "go"), "install", "example.com/fakego@v1.8.0"]
    assert env["GOROOT"] == str(goroot)
    assert env["PATH"].split(os.pathsep)[0] == str(goroot / "bin")
    build = root.resolve() / ".tools" / "go-build"
    assert env["GOPATH"] == str(build / "gopath")
    assert env["GOMODCACHE"] == str(build / "gopath" / "pkg" / "mod")
    assert env["GOCACHE"] == str(build / "cache")
    assert env["GOTMPDIR"] == str(build / "tmp")
    for name, value in toolhome.go_config_env(build / "config").items():
        assert env[name] == value  # telemetry off: no counters in the profile of the user
    assert env["GOBIN"] == str(root.resolve() / ".tools" / "fakego" / "1.8.0" / "bin")
    assert (env["GOTOOLCHAIN"], env["GOENV"], env["GOWORK"], env["CGO_ENABLED"]) == (
        "local",
        "off",
        "off",
        "0",
    )
    for removed in ("GOFLAGS", "GONOSUMDB", "GOOS"):
        assert removed not in env, removed
    assert env["GOPROXY"] == "https://proxy.example"
    assert cwd == str(build)
    record = read_installed(root)["tools"]["fakego"]
    assert (record["go_version"], record["go_source"]) == (GO_VERSION, "kalkan")


def test_go_install_uses_a_system_go_of_the_required_version(tmp_path):
    calls: list = []
    root = tmp_path / "repo"
    results = install(
        ["fakego"],
        repo_root=root,
        manifest=go_manifest(tmp_path),
        key=KEY,
        runner=fake_go("1.26.1", calls),
        finder=lambda name: SYSTEM_GO if name == "go" else None,
    )
    assert [(r.name, r.status) for r in results] == [("fakego", STATUS_INSTALLED)]
    assert "Go 1.26.1 (path)" in results[0].message
    argv, env, _cwd = calls[-1]
    assert argv[0] == str(SYSTEM_GO)
    assert "GOROOT" not in env  # a system Go finds its own tree
    assert not (root / ".tools" / "go").exists()


def test_go_install_with_an_old_system_go_installs_the_toolchain(tmp_path):
    calls: list = []
    root = tmp_path / "repo"
    results = install(
        ["fakego"],
        repo_root=root,
        manifest=go_manifest(tmp_path),
        key=KEY,
        runner=fake_go("1.25.3", calls),
        finder=lambda name: SYSTEM_GO if name == "go" else None,
    )
    assert [(r.name, r.status) for r in results] == [
        ("go", STATUS_INSTALLED),
        ("fakego", STATUS_INSTALLED),
    ]
    assert calls[-1][0][0] == str(go_root(root.resolve()) / "bin" / "go")


def test_go_install_fails_when_the_toolchain_cannot_be_installed(tmp_path):
    results = install(
        "all",
        repo_root=tmp_path / "repo",
        manifest=go_manifest(tmp_path, tree_sha256="0" * 64),
        key=KEY,
        runner=fake_go("1.26.1", []),
        finder=lambda name: None,
    )
    statuses = {r.name: r for r in results}
    assert statuses["go"].status == STATUS_FAILED
    assert statuses["fakego"].status == STATUS_FAILED
    assert "needs Go 1.26 or later" in statuses["fakego"].message
    assert "tree SHA-256 mismatch" in statuses["fakego"].message


def test_go_install_without_a_toolchain_in_the_manifest_fails(tmp_path):
    manifest = make_manifest(fakego=go_entry())
    (result,) = install(
        "all", repo_root=tmp_path, manifest=manifest, key=KEY, finder=lambda name: None
    )
    assert result.status == STATUS_FAILED
    assert "the manifest pins no Go toolchain" in result.message
    (checked,) = verify(repo_root=tmp_path, manifest=manifest, key=KEY, finder=lambda name: None)
    assert checked.status == VERIFY_MISSING


def test_go_install_passes_and_records_the_build_flags(tmp_path):
    calls: list = []
    flags = ["-trimpath", "-ldflags=-X main.version=1.8.0 -X main.commit=abc"]
    archive = make_go_archive(tmp_path / "dl", "tar.gz")
    manifest = make_manifest(
        go=toolchain_entry(archive, "tar.gz"), fakego={**go_entry(), "build_flags": flags}
    )
    root = tmp_path / "repo"
    runner = fake_go("1.26.1", calls)
    install(["fakego"], repo_root=root, manifest=manifest, key=KEY, runner=runner)
    argv = calls[-1][0]
    assert argv[1:] == ["install", *flags, "example.com/fakego@v1.8.0"]
    assert read_installed(root)["tools"]["fakego"]["build_flags"] == flags
    (again,) = install(["fakego"], repo_root=root, manifest=manifest, key=KEY, runner=runner)
    assert again.status == STATUS_PRESENT
    # A manifest with other flags builds the tool again; verify reports the old copy first.
    changed = make_manifest(
        go=toolchain_entry(archive, "tar.gz"), fakego={**go_entry(), "build_flags": flags[:1]}
    )
    (stale,) = verify(["fakego"], repo_root=root, manifest=changed, key=KEY)
    assert stale.status == VERIFY_MISMATCH and "build_flags" in stale.message
    (rebuilt,) = install(["fakego"], repo_root=root, manifest=changed, key=KEY, runner=runner)
    assert rebuilt.status == STATUS_INSTALLED
    assert calls[-1][0][1:] == ["install", "-trimpath", "example.com/fakego@v1.8.0"]


def test_go_install_all_builds_once_and_verifies(tmp_path):
    calls: list = []
    manifest = go_manifest(tmp_path)
    root = tmp_path / "repo"
    runner = fake_go("1.26.1", calls)
    first = install("all", repo_root=root, manifest=manifest, key=KEY, runner=runner)
    assert [(r.name, r.status) for r in first] == [
        ("go", STATUS_INSTALLED),
        ("fakego", STATUS_INSTALLED),
    ]
    second = install("all", repo_root=root, manifest=manifest, key=KEY, runner=runner)
    assert [r.status for r in second] == [STATUS_PRESENT, STATUS_PRESENT]
    assert sum(1 for argv, _env, _cwd in calls if argv[1] == "install") == 1
    checked = verify(repo_root=root, manifest=manifest, key=KEY)
    assert [c.status for c in checked] == [VERIFY_OK, VERIFY_OK]


def fake_go_with_caches(calls: list):
    """``go install`` as Go does it: module files and folders read-only, a build cache entry."""
    import stat

    def runner(argv, *, timeout, env=None, cwd=None):
        argv = [str(a) for a in argv]
        calls.append((argv, env, cwd))
        if argv[1:] == ["env", "GOVERSION"]:
            return subprocess.CompletedProcess(argv, 0, "go1.26.1\n", "")
        assert argv[1] == "install"
        module = Path(env["GOMODCACHE"]) / "example.com" / "fakego@v1.8.0"
        (module / "cmd").mkdir(parents=True)
        for name in ("go.mod", "main.go", "cmd/run.go"):
            (module / name).write_text("package main\n", encoding="utf-8")
            os.chmod(module / name, stat.S_IREAD)
        for folder in (module / "cmd", module):
            os.chmod(folder, stat.S_IREAD | stat.S_IEXEC)
        entry = Path(env["GOCACHE"]) / "ab" / "abcdef-a"
        entry.parent.mkdir(parents=True)
        entry.write_bytes(b"x" * 1000)
        (Path(env["GOBIN"]) / "fakego").write_bytes(b"fake go binary")
        return subprocess.CompletedProcess(argv, 0, "", "")

    return runner


def test_go_install_removes_the_build_folder_after_the_builds(tmp_path):
    calls: list = []
    messages: list[str] = []
    manifest = go_manifest(tmp_path)
    root = tmp_path / "repo"
    runner = fake_go_with_caches(calls)
    results = install(
        ["fakego"],
        repo_root=root,
        manifest=manifest,
        key=KEY,
        runner=runner,
        finder=lambda name: SYSTEM_GO if name == "go" else None,
        log=messages.append,
    )
    assert [(r.name, r.status) for r in results] == [("fakego", STATUS_INSTALLED)]
    build = root / ".tools" / "go-build"
    assert not build.exists()  # read-only module files included
    assert (root / ".tools" / "fakego" / "1.8.0" / "bin" / "fakego").is_file()
    [removed] = [m for m in messages if m.startswith("Removed the Go build folder")]
    assert "in 5 files" in removed  # 4 of the build, the telemetry mode file of the config
    # A later build creates the folders again and removes them again.
    (again,) = install(
        ["fakego"],
        repo_root=root,
        manifest=manifest,
        key=KEY,
        runner=runner,
        force=True,
        finder=lambda name: SYSTEM_GO if name == "go" else None,
    )
    assert again.status == STATUS_INSTALLED and not build.exists()
    assert sum(1 for argv, _env, _cwd in calls if argv[1] == "install") == 2


def test_a_present_go_tool_still_removes_an_old_build_folder(tmp_path):
    manifest = go_manifest(tmp_path)
    root = tmp_path / "repo"
    runner = fake_go("1.26.1", [])
    find = lambda name: SYSTEM_GO if name == "go" else None  # noqa: E731
    install(["fakego"], repo_root=root, manifest=manifest, key=KEY, runner=runner, finder=find)
    leftover = root / ".tools" / "go-build" / "gopath" / "pkg" / "mod" / "old.txt"
    leftover.parent.mkdir(parents=True)
    leftover.write_text("left by kalkan 1.6.1", encoding="utf-8")
    (present,) = install(
        ["fakego"], repo_root=root, manifest=manifest, key=KEY, runner=runner, finder=find
    )
    assert present.status == STATUS_PRESENT
    assert not (root / ".tools" / "go-build").exists()


def test_an_install_without_go_tools_keeps_the_build_folder(tmp_path):
    folder = tmp_path / ".tools" / "go-build" / "cache"
    folder.mkdir(parents=True)
    manifest = make_manifest(faketool=binary_entry("faketool-1.2.3.tar.gz", "tar.gz", "faketool"))
    (result,) = install(["faketool"], repo_root=tmp_path, manifest=manifest, key=KEY)
    assert result.status == STATUS_INSTALLED
    assert folder.is_dir()  # another call may be building with it


def test_remove_go_build_reports_a_missing_folder_and_a_failure(tmp_path, monkeypatch):
    assert install_mod.remove_go_build(tmp_path) is None
    (tmp_path / ".tools" / "go-build").mkdir(parents=True)
    failed = install_mod.TreeStats(files=1, bytes=10, errors=["cache/x: Access is denied"])
    monkeypatch.setattr(install_mod, "remove_tree", lambda path: failed)
    messages: list[str] = []
    assert install_mod.remove_go_build(tmp_path, messages.append) is failed
    assert messages[0].startswith("warning: could not remove all of the Go build folder")
    assert "cache/x: Access is denied" in messages[0]
