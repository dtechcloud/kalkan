# SPDX-License-Identifier: MIT
"""Tests for kalkan.tools.golang: the Go toolchain of gosec and govulncheck (no processes)."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from kalkan.tools import toolhome
from kalkan.tools.golang import (
    GoToolchain,
    build_dirs,
    build_env,
    prepare_build,
    required_version,
    resolve_go,
    run_env,
    toolchain_tool,
)
from kalkan.tools.manifest import load_manifest, parse_manifest
from kalkan.tools.platform import PLATFORMS

KEY = "linux-amd64"
SHA = "a" * 64


def manifest(with_toolchain: bool = True):
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
    tools: dict = {
        "fakego": {
            "version": "1.8.0",
            "license": "BSD-3-Clause",
            "kind": "go-install",
            "executable": "fakego",
            "requires_go": True,
            "blocked_versions": [],
            "module": "example.com/fakego@v1.8.0",
            "min_go_version": "1.26",
        }
    }
    if with_toolchain:
        tools["go"] = {
            "version": "1.26.9",
            "license": "BSD-3-Clause",
            "kind": "toolchain",
            "executable": "go",
            "blocked_versions": [],
            "sha256_source": "computed-at-pin-time",
            "platforms": {key: dict(asset) for key in PLATFORMS},
        }
    return parse_manifest({"schema_version": 1, "tools": tools})


def kalkan_go(root: Path) -> Path:
    exe = root / ".tools" / "go" / "1.26.9" / "go" / "bin" / "go"
    exe.parent.mkdir(parents=True)
    exe.write_bytes(b"go")
    return exe


def no_process(argv, *, timeout, env=None, cwd=None):
    raise AssertionError(f"no process expected: {argv}")


def test_packaged_manifest_pins_go_as_the_toolchain():
    packaged = load_manifest()
    tool = toolchain_tool(packaged)
    assert tool is not None and tool.name == "go" and tool.kind == "toolchain"
    assert required_version(packaged) == "1.26"  # govulncheck 1.26, gosec 1.25


def test_resolve_go_returns_the_kalkan_copy_with_its_root(tmp_path):
    exe = kalkan_go(tmp_path)
    go = resolve_go(tmp_path, manifest=manifest(), key=KEY, runner=no_process)
    assert go == GoToolchain(exe, "1.26.9", "kalkan", exe.parent.parent)
    assert go.bin_dir == exe.parent
    assert json.loads(json.dumps(go.to_dict()))["root"] == exe.parent.parent.as_posix()


def test_resolve_go_accepts_a_system_go_without_a_root(tmp_path):
    def run(argv, *, timeout, env=None, cwd=None):
        return subprocess.CompletedProcess(argv, 0, "go1.26.4\n", "")

    system = Path("/usr/local/go/bin/go")
    go = resolve_go(tmp_path, manifest=manifest(), key=KEY, runner=run, finder=lambda name: system)
    assert go == GoToolchain(system, "1.26.4", "path", None)


def test_resolve_go_without_a_toolchain_entry_is_none(tmp_path):
    kalkan_go(tmp_path)
    assert resolve_go(tmp_path, manifest=manifest(False), key=KEY, runner=no_process) is None


def test_run_env_puts_go_first_on_path():
    go = GoToolchain(Path("/r/.tools/go/1.26.9/go/bin/go"), "1.26.9", "kalkan", Path("/r/go"))
    env = run_env(go, environ={"PATH": "/usr/bin"})
    assert env == {
        "PATH": str(go.bin_dir) + os.pathsep + "/usr/bin",
        "GOTOOLCHAIN": "local",
        "GOROOT": str(Path("/r/go")),
    }
    system = GoToolchain(Path("/usr/local/go/bin/go"), "1.26.1", "path")
    assert "GOROOT" not in run_env(system, environ={})
    assert run_env(system, environ={})["PATH"] == str(system.bin_dir)


def test_build_env_drops_the_go_settings_of_the_caller(tmp_path):
    go = GoToolchain(tmp_path / "go" / "bin" / "go", "1.26.9", "kalkan", tmp_path / "go")
    caller = {
        "PATH": "/usr/bin",
        "HOME": "/home/u",
        "GOFLAGS": "-mod=mod",
        "GONOSUMDB": "*",
        "GOPRIVATE": "*",
        "GOINSECURE": "*",
        "GOOS": "plan9",
        "CGO_CFLAGS": "-O0",
        "GOPROXY": "https://proxy.example",
        "GONOPROXY": "corp.example",
        "GOPATH": "/home/u/go",
    }
    env = build_env(tmp_path, go, tmp_path / "bin", environ=caller)
    for removed in ("GOFLAGS", "GONOSUMDB", "GOPRIVATE", "GOINSECURE", "GOOS", "CGO_CFLAGS"):
        assert removed not in env, removed
    assert env["GOPROXY"] == "https://proxy.example"
    assert env["GONOPROXY"] == "corp.example"
    assert env["HOME"] == "/home/u"
    build = tmp_path / ".tools" / "go-build"
    assert env["GOPATH"] == str(build / "gopath")
    assert env["GOMODCACHE"] == str(build / "gopath" / "pkg" / "mod")
    assert env["GOCACHE"] == str(build / "cache")
    assert env["GOBIN"] == str(tmp_path / "bin")
    assert env["GOROOT"] == str(tmp_path / "go")
    assert (env["GOTOOLCHAIN"], env["GOENV"], env["GOWORK"], env["CGO_ENABLED"]) == (
        "local",
        "off",
        "off",
        "0",
    )
    assert env["PATH"] == str(go.bin_dir) + os.pathsep + "/usr/bin"
    # No file of the build outside .tools/go-build: GOTMPDIR and the Go configuration folder
    # (telemetry off) are there too (kalkan.tools.toolhome).
    assert env["GOTMPDIR"] == str(build / "tmp")
    config = build / "config"
    assert {key: env[key] for key in toolhome.go_config_env(config)} == toolhome.go_config_env(
        config
    )
    assert build_dirs(tmp_path) == [build / "gopath", build / "cache", build / "tmp", config]
    prepare_build(tmp_path)
    mode = toolhome.go_user_config_dir(config) / "go" / "telemetry" / "mode"
    assert mode.read_text(encoding="utf-8") == "off"
    assert all(folder.is_dir() for folder in build_dirs(tmp_path))


@pytest.mark.skipif(os.name != "nt", reason="Windows names are case-insensitive")
def test_build_env_keeps_one_spelling_of_appdata(tmp_path):
    go = GoToolchain(tmp_path / "go" / "bin" / "go", "1.26.9", "kalkan", tmp_path / "go")
    env = build_env(tmp_path, go, tmp_path / "bin", environ={"AppData": "C:/u", "Path": "/b"})
    assert "AppData" not in env and "Path" not in env
    assert env["APPDATA"] == str(tmp_path / ".tools" / "go-build" / "config")
