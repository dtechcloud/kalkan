# SPDX-License-Identifier: MIT
"""Tests for kalkan.tools.resolve with a fake .tools tree and a fake PATH."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from kalkan.errors import ToolError
from kalkan.tools import toolhome
from kalkan.tools.manifest import parse_manifest
from kalkan.tools.platform import PLATFORMS, find_on_path
from kalkan.tools.resolve import (
    SOURCE_KALKAN,
    SOURCE_PATH,
    binary_path,
    first_version,
    go_toolchain_version,
    go_version_in_output,
    probe_env,
    probe_tool_version,
    probe_version,
    pyenv_python,
    pyenv_script,
    required_go_version,
    resolve,
    toolchain_root,
    version_in_output,
)

KEY = "linux-amd64"
SHA = "a" * 64


def manifest():
    asset = {
        "url": "https://example.com/faketool.tar.gz",
        "sha256": SHA,
        "archive": "tar.gz",
        "binary": "faketool",
    }
    return parse_manifest(
        {
            "schema_version": 1,
            "tools": {
                "faketool": {
                    "version": "1.2.3",
                    "license": "MIT",
                    "kind": "binary",
                    "executable": "faketool",
                    "version_args": ["--version"],
                    "blocked_versions": ["1.2.0"],
                    "sha256_source": "computed-at-pin-time",
                    "notes": "",
                    "platforms": {key: dict(asset) for key in PLATFORMS},
                },
                "fakepip": {
                    "version": "3.3.22",
                    "license": "MIT",
                    "kind": "pip",
                    "executable": "fakepip",
                    "blocked_versions": [],
                    "package": "fakepip",
                    "requirement": "fakepip==3.3.22",
                    "notes": "",
                },
            },
        }
    )


def write_tools_copy(root: Path, *, record: dict | None = None) -> Path:
    target = root / ".tools" / "faketool" / "1.2.3" / "bin" / "faketool"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"binary")
    if record is not None:
        installed = root / ".tools" / "installed.json"
        installed.write_text(json.dumps({"schema_version": 1, "tools": record}), encoding="utf-8")
    return target


def fake_path_binary(directory: Path, name: str = "faketool") -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / (f"{name}.exe" if os.name == "nt" else name)
    path.write_bytes(b"binary")
    if os.name != "nt":
        path.chmod(0o755)
    return path


def runner_saying(text: str, calls: list | None = None):
    def run(argv, *, timeout, env=None, cwd=None):
        if calls is not None:
            calls.append([str(a) for a in argv])
        return subprocess.CompletedProcess(argv, 0, text, "")

    return run


def failing_runner(argv, *, timeout, env=None, cwd=None):
    raise AssertionError(f"no process expected: {argv}")


def test_prefers_the_kalkan_copy_from_installed_json(tmp_path):
    record = {"faketool": {"version": "1.2.3", "path": ".tools/faketool/1.2.3/bin/faketool"}}
    target = write_tools_copy(tmp_path, record=record)
    path_dir = tmp_path / "pathdir"
    fake_path_binary(path_dir)
    found = resolve(
        "faketool",
        repo_root=tmp_path,
        manifest=manifest(),
        key=KEY,
        runner=failing_runner,
        path_env=str(path_dir),
    )
    assert found is not None
    assert found.source == SOURCE_KALKAN
    assert found.path.resolve() == target.resolve()
    assert found.version == "1.2.3"
    assert found.argv == [str(found.path)]
    assert found.to_dict()["source"] == "kalkan"


def test_uses_the_conventional_path_without_installed_json(tmp_path):
    target = write_tools_copy(tmp_path)
    found = resolve("faketool", repo_root=tmp_path, manifest=manifest(), key=KEY, path_env="")
    assert found is not None and found.source == SOURCE_KALKAN
    assert found.path == target


def test_ignores_an_installed_json_path_outside_tools(tmp_path):
    outside = tmp_path / "evil"
    outside.write_bytes(b"evil")
    record = {"faketool": {"version": "1.2.3", "path": "evil"}}
    (tmp_path / ".tools").mkdir()
    (tmp_path / ".tools" / "installed.json").write_text(
        json.dumps({"schema_version": 1, "tools": record}), encoding="utf-8"
    )
    assert (
        resolve("faketool", repo_root=tmp_path, manifest=manifest(), key=KEY, path_env="") is None
    )


def test_ignores_a_corrupt_installed_json(tmp_path):
    target = write_tools_copy(tmp_path)
    (tmp_path / ".tools" / "installed.json").write_text("{broken", encoding="utf-8")
    found = resolve("faketool", repo_root=tmp_path, manifest=manifest(), key=KEY, path_env="")
    assert found is not None and found.path == target


def test_accepts_path_binary_with_the_pinned_version(tmp_path):
    path_dir = tmp_path / "pathdir"
    binary = fake_path_binary(path_dir)
    calls: list = []
    found = resolve(
        "faketool",
        repo_root=tmp_path,
        manifest=manifest(),
        key=KEY,
        runner=runner_saying("faketool version 1.2.3\n", calls),
        path_env=str(path_dir),
    )
    assert found is not None
    assert found.source == SOURCE_PATH
    assert found.path == binary
    assert calls == [[str(binary), "--version"]]


def test_rejects_path_binary_with_another_version(tmp_path):
    path_dir = tmp_path / "pathdir"
    fake_path_binary(path_dir)
    kwargs = dict(
        repo_root=tmp_path,
        manifest=manifest(),
        key=KEY,
        runner=runner_saying("faketool 1.3.0"),
        path_env=str(path_dir),
    )
    assert resolve("faketool", **kwargs) is None
    allowed = resolve("faketool", allow_path=True, **kwargs)
    assert allowed is not None
    assert allowed.source == SOURCE_PATH
    assert allowed.version == "1.3.0"


def test_never_accepts_a_blocked_path_version(tmp_path):
    path_dir = tmp_path / "pathdir"
    fake_path_binary(path_dir)
    found = resolve(
        "faketool",
        repo_root=tmp_path,
        manifest=manifest(),
        key=KEY,
        allow_path=True,
        runner=runner_saying("Version: 1.2.0"),
        path_env=str(path_dir),
    )
    assert found is None


def test_returns_none_when_nothing_is_found(tmp_path):
    assert (
        resolve("faketool", repo_root=tmp_path, manifest=manifest(), key=KEY, path_env="") is None
    )


def test_unknown_tool_raises(tmp_path):
    with pytest.raises(ToolError, match="unknown tool"):
        resolve("nope", repo_root=tmp_path, manifest=manifest(), key=KEY)


def test_pip_tool_resolves_from_the_tool_venv(tmp_path):
    scripts = tmp_path / ".tools" / "pyenv" / ("Scripts" if os.name == "nt" else "bin")
    scripts.mkdir(parents=True)
    script = scripts / ("fakepip.exe" if os.name == "nt" else "fakepip")
    script.write_bytes(b"")
    found = resolve(
        "fakepip",
        repo_root=tmp_path,
        manifest=manifest(),
        key=KEY,
        runner=runner_saying("3.3.22"),
        path_env="",
    )
    assert found is not None and found.source == SOURCE_KALKAN
    assert found.path == script
    wrong = resolve(
        "fakepip",
        repo_root=tmp_path,
        manifest=manifest(),
        key=KEY,
        runner=runner_saying("3.3.21"),
        path_env="",
    )
    assert wrong is None


def test_pip_script_without_exe_runs_through_the_venv_python(tmp_path):
    scripts = tmp_path / ".tools" / "pyenv" / ("Scripts" if os.name == "nt" else "bin")
    scripts.mkdir(parents=True)
    if os.name == "nt":
        (scripts / "fakepip.cmd").write_bytes(b"@echo off\r\n")
        assert pyenv_script(tmp_path, "fakepip") is None  # a .cmd launcher is never used
    script = scripts / "fakepip"
    script.write_bytes(b"#!python\n")
    assert pyenv_script(tmp_path, "fakepip") == script
    calls: list = []
    found = resolve(
        "fakepip",
        repo_root=tmp_path,
        manifest=manifest(),
        key=KEY,
        runner=runner_saying("3.3.22", calls),
        path_env="",
    )
    expected = [str(pyenv_python(tmp_path)), str(script)] if os.name == "nt" else [str(script)]
    assert found is not None
    assert found.argv == expected
    assert calls == [[*expected, "--version"]]


def test_find_on_path_skips_relative_entries(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    fake_path_binary(tmp_path)
    assert find_on_path("faketool", path_env=os.pathsep.join([".", "", "relative/dir"])) is None
    assert find_on_path("faketool", path_env=str(tmp_path)) is not None


@pytest.mark.parametrize(
    ("output", "version", "expected"),
    [
        ("Version: 0.75.0", "0.75.0", True),
        ("trivy v0.75.0 (abc)", "0.75.0", True),
        ("gitleaks version 8.30.1", "8.30.1", True),
        ("Version: 10.75.0", "0.75.0", False),
        ("Version: 0.75.01", "0.75.0", False),
        ("Version: 0.75.0-rc1", "0.75.0", False),
        ("Version: 0.75.0.1", "0.75.0", False),
        ("1.30.1\n", "1.30.1", True),
        ("Haskell Dockerfile Linter 2.15.1", "2.15.1", True),
    ],
)
def test_version_in_output(output, version, expected):
    assert version_in_output(output, version) is expected


def test_first_version():
    assert first_version("grype 0.119.0\nother 1.2.3") == "0.119.0"
    assert first_version("Version: v2.29.0") == "2.29.0"
    assert first_version("no version here") is None


# --- the Go toolchain -------------------------------------------------------------------------


def go_manifest(*, gotool_min: str | None = "1.26", blocked: tuple[str, ...] = ()):
    asset = {
        "url": "https://example.com/go.tar.gz",
        "sha256": SHA,
        "archive": "tar.gz",
        "root": "go",
        "binary": "go/bin/go",
        "binary_sha256": SHA,
        "files": 2,
        "tree_sha256": SHA,
    }
    gotool = {
        "version": "2.29.0",
        "license": "Apache-2.0",
        "kind": "binary",
        "executable": "gotool",
        "requires_go": True,
        "blocked_versions": [],
        "sha256_source": "computed-at-pin-time",
        "notes": "",
        "platforms": {
            key: {"url": asset["url"], "sha256": SHA, "archive": "tar.gz", "binary": "gotool"}
            for key in PLATFORMS
        },
    }
    if gotool_min:
        gotool["min_go_version"] = gotool_min
    return parse_manifest(
        {
            "schema_version": 1,
            "tools": {
                "go": {
                    "version": "1.26.9",
                    "license": "BSD-3-Clause",
                    "kind": "toolchain",
                    "executable": "go",
                    "version_args": ["env", "GOVERSION"],
                    "blocked_versions": list(blocked),
                    "sha256_source": "computed-at-pin-time",
                    "notes": "",
                    "platforms": {key: dict(asset) for key in PLATFORMS},
                },
                "gotool": gotool,
            },
        }
    )


def go_runner(version: str, calls: list | None = None):
    def run(argv, *, timeout, env=None, cwd=None):
        if calls is not None:
            calls.append(([str(a) for a in argv], env))
        return subprocess.CompletedProcess(argv, 0, f"go{version}\n", "")

    return run


def test_toolchain_binary_path_keeps_the_archive_tree(tmp_path):
    tool = go_manifest().get("go")
    assert binary_path(tmp_path, tool, KEY) == tmp_path / ".tools" / "go" / "1.26.9" / "go/bin/go"
    assert toolchain_root(tmp_path, tool, KEY) == tmp_path / ".tools" / "go" / "1.26.9" / "go"


def test_kalkan_go_comes_first(tmp_path):
    exe = tmp_path / ".tools" / "go" / "1.26.9" / "go" / "bin" / "go"
    exe.parent.mkdir(parents=True)
    exe.write_bytes(b"go")
    found = resolve(
        "go",
        repo_root=tmp_path,
        manifest=go_manifest(),
        key=KEY,
        runner=failing_runner,
        finder=lambda name: Path("/usr/local/go/bin/go"),
    )
    assert found is not None and found.source == SOURCE_KALKAN and found.path == exe


@pytest.mark.parametrize(
    ("version", "allow_path", "accepted"),
    [
        ("1.26.1", False, True),
        ("1.27.2", False, True),
        ("1.26", False, True),
        ("1.25.9", False, False),
        ("1.25.9", True, True),
    ],
)
def test_system_go_needs_the_required_version(tmp_path, version, allow_path, accepted):
    calls: list = []
    found = resolve(
        "go",
        repo_root=tmp_path,
        manifest=go_manifest(),
        key=KEY,
        runner=go_runner(version, calls),
        finder=lambda name: Path("/usr/local/go/bin/go") if name == "go" else None,
        allow_path=allow_path,
    )
    assert (found is not None) is accepted
    if found is not None:
        assert (found.source, found.version) == (SOURCE_PATH, version)
    argv, env = calls[0]
    assert argv[1:] == ["env", "GOVERSION"]
    assert env["GOTOOLCHAIN"] == "local"  # a go.mod in the working folder cannot switch Go


def test_blocked_system_go_is_refused(tmp_path):
    found = resolve(
        "go",
        repo_root=tmp_path,
        manifest=go_manifest(blocked=("1.26.1",)),
        key=KEY,
        runner=go_runner("1.26.1"),
        finder=lambda name: Path("/usr/local/go/bin/go"),
        allow_path=True,
    )
    assert found is None


def test_system_go_without_a_readable_version_is_refused(tmp_path):
    def run(argv, *, timeout, env=None, cwd=None):
        return subprocess.CompletedProcess(argv, 1, "", "go: broken\n")

    found = resolve(
        "go",
        repo_root=tmp_path,
        manifest=go_manifest(),
        key=KEY,
        runner=run,
        finder=lambda name: Path("/usr/local/go/bin/go"),
    )
    assert found is None


def test_required_go_version():
    assert required_go_version(go_manifest()) == "1.26"
    assert required_go_version(go_manifest(gotool_min=None)) == "1.26"  # toolchain major.minor
    assert required_go_version(manifest()) is None


@pytest.mark.parametrize(
    ("output", "expected"),
    [
        ("go1.26.9\n", "1.26.9"),
        ("go version go1.26.9 windows/amd64\n", "1.26.9"),
        ("go1.27rc1", "1.27"),
        ("version 1.26.9", None),
        ("", None),
    ],
)
def test_go_version_in_output(output, expected):
    assert go_version_in_output(output) == expected


def test_go_toolchain_version_sets_goroot_for_the_kalkan_copy(tmp_path):
    calls: list = []
    version = go_toolchain_version(
        tmp_path / "go" / "bin" / "go", runner=go_runner("1.26.9", calls), goroot=tmp_path / "go"
    )
    assert version == "1.26.9"
    assert calls[0][1]["GOROOT"] == str(tmp_path / "go")


# --- version probes: minimal environment, offline settings, empty working folder (K.1) -------

#: Variables of the user that no version probe may see: tokens, cloud keys and settings that
#: change how a Python or Go program runs.
USER_SECRETS = {
    "GITHUB_TOKEN": "ghp_" + "1" * 36,
    "GH_TOKEN": "gho_" + "2" * 36,
    "AWS_SECRET_ACCESS_KEY": "made-up-secret",
    "PYTHONPATH": "/tmp/planted",
    "GOFLAGS": "-mod=mod",
    "GOTOOLCHAIN": "auto",
    "CKV_SKIP_PACKAGE_UPDATE_CHECK": "false",
}
#: Every name that a probe environment may hold (ENGINE-SPEC 13.1 and probe_env).
PROBE_ENV_NAMES = {
    "PATH", "SYSTEMROOT", "TEMP", "TMP", "HOME", "USERPROFILE", "LANG", "PATHEXT", "COMSPEC",
    "WINDIR", "SYSTEMDRIVE", "LOCALAPPDATA", "APPDATA", "TMPDIR", "LC_ALL", "LC_CTYPE",
    "XDG_CACHE_HOME", "XDG_CONFIG_HOME", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy",
    "https_proxy", "no_proxy", "SSL_CERT_FILE", "SSL_CERT_DIR", "PYTHONUTF8", "PYTHONIOENCODING",
    "PYTHONNOUSERSITE", "GOTOOLCHAIN", "GOROOT", "CKV_SKIP_PACKAGE_UPDATE_CHECK",
}  # fmt: skip


def probe_manifest():
    return parse_manifest(
        {
            "schema_version": 1,
            "tools": {
                "fakepip": {
                    "version": "3.3.22",
                    "license": "MIT",
                    "kind": "pip",
                    "executable": "fakepip",
                    "version_args": ["--version"],
                    "version_env": {"CKV_SKIP_PACKAGE_UPDATE_CHECK": "true"},
                    "blocked_versions": [],
                    "package": "fakepip",
                    "requirement": "fakepip==3.3.22",
                },
                "fakego": {
                    "version": "1.8.0",
                    "license": "BSD-3-Clause",
                    "kind": "go-install",
                    "executable": "fakego",
                    "version_args": ["-db", "{workdir_url}", "-version"],
                    "requires_go": True,
                    "blocked_versions": [],
                    "module": "example.com/fakego@v1.8.0",
                },
            },
        }
    )


def recording_runner(calls: list, text: str = "fake 1.2.3"):
    def run(argv, *, timeout, env=None, cwd=None):
        folder = Path(cwd) if cwd is not None else None
        listing = sorted(p.name for p in folder.iterdir()) if folder is not None else None
        calls.append({"argv": [str(a) for a in argv], "env": env, "cwd": folder, "files": listing})
        return subprocess.CompletedProcess(argv, 0, text, "")

    return run


def assert_probe_env(env: dict) -> None:
    """No secret of the user, only the names of the minimal tool environment."""
    for name in ("GITHUB_TOKEN", "GH_TOKEN", "AWS_SECRET_ACCESS_KEY", "PYTHONPATH", "GOFLAGS"):
        assert name not in env, name
    assert set(env) <= PROBE_ENV_NAMES, set(env) - PROBE_ENV_NAMES


def test_version_probes_get_the_minimal_environment_and_an_empty_folder(monkeypatch, tmp_path):
    for name, value in USER_SECRETS.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")  # the proxy trap must still apply
    monkeypatch.chdir(tmp_path)
    (tmp_path / "trivy.yaml").write_text("cache-dir: /planted\n", encoding="utf-8")
    tools = probe_manifest()
    calls: list = []
    probe_tool_version(["python", "fakepip"], tools.get("fakepip"), runner=recording_runner(calls))
    probe_tool_version("/opt/fakego", tools.get("fakego"), runner=recording_runner(calls))
    pip_call, go_call = calls
    for call in calls:
        assert_probe_env(call["env"])
        assert call["env"]["HTTPS_PROXY"] == "http://127.0.0.1:9"
        # A new empty folder, not the folder of the caller (its trivy.yaml is never read).
        assert call["cwd"] is not None and call["cwd"].resolve() != tmp_path.resolve()
        assert not call["cwd"].exists()  # removed after the probe
    # Only kalkan's Go configuration (telemetry off) is in the folder of a Go program.
    go_top = "Library" if sys.platform == "darwin" else "go"  # toolhome.go_user_config_dir
    assert pip_call["files"] == [] and go_call["files"] == [go_top]
    assert pip_call["env"]["PYTHONUTF8"] == "1" and pip_call["env"]["PYTHONNOUSERSITE"] == "1"
    # version_env wins over a value of the user: the update check stays off.
    assert pip_call["env"]["CKV_SKIP_PACKAGE_UPDATE_CHECK"] == "true"
    assert pip_call["argv"] == ["python", "fakepip", "--version"]
    assert go_call["env"]["GOTOOLCHAIN"] == "local"
    # The placeholder becomes the file URL of the empty working folder (an empty local db).
    assert go_call["argv"] == ["/opt/fakego", "-db", go_call["cwd"].as_uri(), "-version"]


def test_probe_env_without_a_tool_is_the_minimal_tool_environment(monkeypatch):
    for name, value in USER_SECRETS.items():
        monkeypatch.setenv(name, value)
    env = probe_env()
    assert_probe_env(env)
    assert "GOTOOLCHAIN" not in env and "CKV_SKIP_PACKAGE_UPDATE_CHECK" not in env
    calls: list = []
    probe_version(["tool"], ["--version"], runner=recording_runner(calls))
    # The working folder of the probe is also its temporary folder (kalkan.tools.toolhome).
    temp = toolhome.temp_env(calls[0]["cwd"])
    assert calls[0]["env"] == {**env, **temp}


def test_the_path_probe_of_resolve_uses_the_probe_environment(tmp_path, monkeypatch):
    for name, value in USER_SECRETS.items():
        monkeypatch.setenv(name, value)
    path_dir = tmp_path / "pathdir"
    fake_path_binary(path_dir)
    calls: list = []
    found = resolve(
        "faketool",
        repo_root=tmp_path,
        manifest=manifest(),
        key=KEY,
        runner=recording_runner(calls, "faketool 1.2.3"),
        path_env=str(path_dir),
    )
    assert found is not None and found.source == SOURCE_PATH
    [call] = calls
    assert_probe_env(call["env"])
    assert call["files"] == []


def test_go_toolchain_version_runs_with_the_probe_environment(tmp_path, monkeypatch):
    for name, value in USER_SECRETS.items():
        monkeypatch.setenv(name, value)
    calls: list = []
    go_toolchain_version(tmp_path / "go", runner=recording_runner(calls, "go1.26.9\n"))
    [call] = calls
    assert_probe_env(call["env"])
    assert call["env"]["GOTOOLCHAIN"] == "local"
    # go/telemetry/mode: off (kalkan.tools.toolhome; on macOS below Library/Application Support)
    assert call["files"] == ["Library" if sys.platform == "darwin" else "go"]


def test_every_packaged_version_probe_keeps_its_tool_offline():
    """The version commands of the manifest carry the offline settings of their adapters
    (measured under the proxy trap on 2026-10-25, docs/SECURITY.md promise 3)."""
    from kalkan.tools.manifest import load_manifest

    tools = load_manifest()
    assert "--disable-version-check" in tools.get("poutine").version_args
    assert tools.get("poutine").version_env == {"POUTINE_DISABLE_VERSION_CHECK": "1"}
    assert "--disable-version-check" in tools.get("opengrep").version_args
    assert "--no-update-check" in tools.get("kingfisher").version_args
    # checkov --version asked pypi.org; govulncheck -version asked vuln.go.dev.
    assert tools.get("checkov").version_env == {"CKV_SKIP_PACKAGE_UPDATE_CHECK": "true"}
    assert tools.get("govulncheck").version_args == ("-db", "{workdir_url}", "-version")
    assert tools.get("syft").version_env == {"SYFT_CHECK_FOR_APP_UPDATE": "false"}
    assert tools.get("grype").version_env == {"GRYPE_CHECK_FOR_APP_UPDATE": "false"}
