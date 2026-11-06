# SPDX-License-Identifier: MIT
"""No tool writes outside the kalkan folders (kalkan.tools.toolhome, docs/SECURITY.md).

Measured on Windows 11 on 2026-10-29 before the change: opengrep wrote its log (with target
paths and matched code) to ``~/.opengrep/semgrep.log``, unpacked its runtime below
``%USERPROFILE%\\AppData\\Local\\opengrep`` and left 58 temporary files in the user temp folder;
gosec filled ``%LOCALAPPDATA%\\go-build``; Go wrote telemetry counters below
``%APPDATA%\\go\\telemetry``; pip filled its user cache. These tests check the environment and
the arguments that keep each of them in a kalkan folder. No test starts a real tool.
"""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

import pytest

from kalkan.scanners.adapters import _common
from kalkan.scanners.adapters import opengrep as opengrep_module
from kalkan.scanners.adapters.gosec import GosecAdapter
from kalkan.scanners.adapters.govulncheck import GovulncheckAdapter
from kalkan.scanners.adapters.opengrep import OpengrepAdapter
from kalkan.scanners.adapters.opengrep_packs import OpengrepPacksAdapter
from kalkan.scanners.base import ProcessOutcome, ScanContext, ToolAdapter, run_adapter
from kalkan.tools import toolhome
from kalkan.tools.golang import GoToolchain
from kalkan.tools.manifest import parse_manifest
from kalkan.tools.resolve import (
    ResolvedTool,
    go_toolchain_version,
    probe_env,
    probe_folders,
    probe_tool_version,
)

ROOT = Path(__file__).resolve().parents[2]
#: Taken at import, before tests/conftest.py replaces it for each test.
REAL_DEFAULT_HOME = opengrep_module.default_home
FAKE_GO = GoToolchain(Path("/k/.tools/go/1.26.9/go/bin/go"), "1.26.9", "kalkan", Path("/k/go"))


def make_ctx(tmp_path: Path, *, offline: bool = True, tech=()) -> ScanContext:
    run = (tmp_path / "run").resolve()
    target = run / "target"
    target.mkdir(parents=True, exist_ok=True)
    (target / "app.py").write_text("print(1)\n", encoding="utf-8")
    return ScanContext(run, target, None, frozenset(tech), offline=offline)


def resolver(name: str, *, allow_path: bool = False) -> ResolvedTool:
    return ResolvedTool(name, Path("/opt/tools") / name, "1.0.0", "kalkan")


class Recorder:
    """A fake process runner: records argv, cwd and env, writes the SARIF output."""

    def __init__(self, code: int = 0, during=None) -> None:
        self.calls: list[dict] = []
        self.code = code
        self.during = during

    def __call__(self, argv, *, cwd, env, timeout, stdout, stderr):
        self.calls.append({"argv": list(argv), "cwd": Path(cwd), "env": dict(env)})
        if self.during is not None:
            self.during(dict(env))
        if "--out" in argv:
            out = Path(argv[argv.index("--out") + 1])
            out.write_text(json.dumps(sarif()), encoding="utf-8")
        return ProcessOutcome(self.code)


def sarif() -> dict:
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "fake"}}, "results": []}]}


class FakeTool(ToolAdapter):
    """A JSON tool (no SARIF ingest): its work folder is ``sca/.work/syft``."""

    name = "syft"
    tool = "syft"
    output = "json-file"
    output_dir = "sca"
    output_name = "sbom.cdx.json"

    def arguments(self, ctx, out):
        return ["--out", str(out), str(ctx.target_dir)]


# --- kalkan.tools.toolhome -----------------------------------------------------------------


def test_the_variables_of_each_platform(tmp_path):
    folder = tmp_path / "x"
    assert toolhome.temp_env(folder, platform="win32") == {"TEMP": str(folder), "TMP": str(folder)}
    assert toolhome.temp_env(folder, platform="linux")["TMPDIR"] == str(folder)
    assert toolhome.temp_env(folder, platform="darwin")["TMPDIR"] == str(folder)
    assert toolhome.go_config_env(folder, platform="win32") == {"APPDATA": str(folder)}
    assert toolhome.go_config_env(folder, platform="linux") == {"XDG_CONFIG_HOME": str(folder)}
    assert toolhome.go_config_env(folder, platform="darwin") == {}  # not changed, not measured
    env = toolhome.opengrep_env(tmp_path / "home", tmp_path / "work")
    assert env == {
        "USERPROFILE": str(tmp_path / "home"),
        "HOME": str(tmp_path / "home"),
        "XDG_CACHE_HOME": str(tmp_path / "home" / ".cache"),
        "XDG_CONFIG_HOME": str(tmp_path / "work"),
        "SEMGREP_LOG_FILE": str(tmp_path / "work" / "opengrep.log"),
    }


def test_the_kalkan_folders(tmp_path):
    assert toolhome.cache_root(tmp_path) == tmp_path / ".tools" / "cache"
    home = toolhome.prepare_home(toolhome.opengrep_home(tmp_path))
    assert home == tmp_path / ".tools" / "cache" / "opengrep"
    assert (home / "AppData" / "Local").is_dir() and (home / "AppData" / "Roaming").is_dir()
    toolhome.prepare_home(home)  # a second call changes nothing
    mode = toolhome.go_telemetry_off(tmp_path / "cfg")
    assert mode == tmp_path / "cfg" / "go" / "telemetry" / "mode"
    assert mode.read_text(encoding="utf-8") == "off"


# --- every tool run: the temporary folder ------------------------------------------------------


def test_tool_runs_keep_their_temporary_files_in_the_run(tmp_path, monkeypatch):
    user_temp = tmp_path / "user-temp"
    user_temp.mkdir()
    for name in ("TEMP", "TMP", "TMPDIR"):
        monkeypatch.setenv(name, str(user_temp))
    ctx = make_ctx(tmp_path)
    work = ctx.run_dir / "sca" / ".work" / "syft"

    def leave_a_file(env):
        assert Path(env["TEMP"]).is_dir()
        (Path(env["TEMP"]) / "semgrep-abc.rules").write_text("rules", encoding="utf-8")

    runner = Recorder(during=leave_a_file)
    assert run_adapter(FakeTool(), ctx, runner=runner, resolver=resolver).status == "ok"
    env = runner.calls[0]["env"]
    assert env["TEMP"] == env["TMP"] == str(work / "tmp")
    if sys.platform != "win32":
        assert env["TMPDIR"] == str(work / "tmp")
    assert not work.exists()  # removed with the work folder after a successful run
    failed = Recorder(code=3, during=leave_a_file)
    assert run_adapter(FakeTool(), ctx, runner=failed, resolver=resolver).status == "failed"
    assert (work / "tmp" / "semgrep-abc.rules").is_file()  # kept in the run for diagnosis
    assert list(user_temp.iterdir()) == []


def test_an_adapter_value_wins_over_the_run_temporary_folder(tmp_path):
    class OwnTemp(FakeTool):
        def env(self, ctx):
            return {"TEMP": str(tmp_path / "own")}

    runner = Recorder()
    run_adapter(OwnTemp(), make_ctx(tmp_path), runner=runner, resolver=resolver)
    assert runner.calls[0]["env"]["TEMP"] == str(tmp_path / "own")


def test_a_stale_work_folder_with_read_only_files_is_removed(tmp_path):
    ctx = make_ctx(tmp_path)
    work = ctx.run_dir / "sca" / ".work" / "syft"
    stale = work / "go-path" / "pkg" / "mod" / "m@v1" / "go.mod"
    stale.parent.mkdir(parents=True)
    stale.write_text("module m\n", encoding="utf-8")
    os.chmod(stale, stat.S_IREAD)  # Go marks its module files read-only
    runner = Recorder()
    assert run_adapter(FakeTool(), ctx, runner=runner, resolver=resolver).status == "ok"
    assert not stale.exists() and not work.exists()


# --- opengrep ----------------------------------------------------------------------------------


@pytest.mark.parametrize("adapter_class", [OpengrepAdapter, OpengrepPacksAdapter])
def test_opengrep_keeps_its_runtime_log_and_temporary_files_in_kalkan_folders(
    tmp_path, adapter_class
):
    home = tmp_path / "kalkan" / ".tools" / "cache" / "opengrep"
    adapter = adapter_class(home=home)
    ctx = make_ctx(tmp_path)
    work = ctx.run_dir / "scans" / ".work" / adapter.name

    def check(env):
        # The runtime is unpacked below AppData/Local of USERPROFILE: it must exist first.
        assert (Path(env["USERPROFILE"]) / "AppData" / "Local").is_dir()

    runner = Recorder(during=check)
    run_adapter(adapter, ctx, runner=runner, resolver=resolver)
    env = runner.calls[0]["env"]
    assert env["USERPROFILE"] == env["HOME"] == str(home)
    assert env["XDG_CACHE_HOME"] == str(home / ".cache")
    assert env["SEMGREP_LOG_FILE"] == str(work / "opengrep.log")
    assert env["XDG_CONFIG_HOME"] == str(work)
    assert env["TEMP"] == env["TMP"] == str(work / "tmp")


def test_opengrep_uses_the_cache_folder_of_the_kalkan_home(tmp_path, monkeypatch):
    monkeypatch.setenv("KALKAN_HOME", str(tmp_path))
    expected = tmp_path.resolve() / ".tools" / "cache" / "opengrep"
    assert REAL_DEFAULT_HOME() == expected  # tests/conftest.py replaces it for unit tests
    monkeypatch.setattr(opengrep_module, "default_home", REAL_DEFAULT_HOME)
    assert OpengrepAdapter().home() == expected
    assert OpengrepPacksAdapter().home() == expected


# --- gosec and govulncheck ---------------------------------------------------------------------


@pytest.fixture
def with_go(monkeypatch):
    monkeypatch.setattr(_common, "go_resolver", lambda allow_path=False: FAKE_GO)
    monkeypatch.setattr(_common, "executable_finder", lambda name: None)


@pytest.mark.parametrize("adapter_class", [GosecAdapter, GovulncheckAdapter])
def test_go_tools_keep_their_build_cache_and_configuration_in_the_run(
    tmp_path, monkeypatch, with_go, adapter_class
):
    monkeypatch.setenv("GOCACHE", str(tmp_path / "user-go-build"))  # never passed on
    monkeypatch.setenv("GOPATH", str(tmp_path / "user-go"))
    adapter = adapter_class()
    ctx = make_ctx(tmp_path, tech={"go"})
    work = ctx.run_dir / adapter.output_dir / ".work" / adapter.name
    env = adapter.env(ctx)
    assert env["GOCACHE"] == str(work / "go-cache")
    for name, value in toolhome.go_config_env(work / "go-config").items():
        assert env[name] == value
    assert env["GOPATH"] == str(tmp_path / "user-go")  # local mode: Go only reads it
    assert env["GOPROXY"] == "off" and env["GOSUMDB"] == "off"
    adapter.prepare(ctx, work / adapter.output_name)
    assert (work / "go-config" / "go" / "telemetry" / "mode").read_text(encoding="utf-8") == "off"
    assert (work / "go-cache").is_dir()
    online = adapter.env(make_ctx(tmp_path, tech={"go"}, offline=False))
    assert online["GOPATH"] == str(work / "go-path")  # module downloads stay in the run
    assert online["GOMODCACHE"] == str(work / "go-path" / "pkg" / "mod")


def test_go_env_without_a_work_folder_names_no_folder(tmp_path, monkeypatch, with_go):
    monkeypatch.setenv("GOCACHE", str(tmp_path / "user-go-build"))
    env = _common.go_env(make_ctx(tmp_path))
    assert "GOCACHE" not in env and "APPDATA" not in env and "XDG_CONFIG_HOME" not in env


# --- version probes --------------------------------------------------------------------------


def probe_tools():
    return parse_manifest(
        {
            "schema_version": 1,
            "tools": {
                # The kind does not matter for the probe: the name decides (no platform assets).
                "opengrep": {
                    "version": "1.30.1",
                    "license": "LGPL-2.1",
                    "kind": "pip",
                    "executable": "opengrep",
                    "version_args": ["--version", "--disable-version-check"],
                    "blocked_versions": [],
                    "package": "opengrep",
                    "requirement": "opengrep==1.30.1",
                },
                "gotool": {
                    "version": "1.8.0",
                    "license": "BSD-3-Clause",
                    "kind": "go-install",
                    "executable": "gotool",
                    "version_args": ["-version"],
                    "requires_go": True,
                    "blocked_versions": [],
                    "module": "example.com/gotool@v1.8.0",
                },
            },
        }
    )


def recording(calls: list, text: str = "1.30.1"):
    def run(argv, *, timeout, env=None, cwd=None):
        mode = Path(cwd) / "go" / "telemetry" / "mode"
        calls.append(
            {
                "argv": [str(a) for a in argv],
                "env": dict(env or {}),
                "cwd": Path(cwd),
                "telemetry": mode.read_text(encoding="utf-8") if mode.is_file() else None,
            }
        )
        return __import__("subprocess").CompletedProcess(argv, 0, text, "")

    return run


def test_probes_keep_opengrep_and_go_out_of_the_profile(tmp_path, monkeypatch):
    monkeypatch.setenv("KALKAN_HOME", str(tmp_path))
    tools = probe_tools()
    calls: list = []
    probe_tool_version("/opt/opengrep", tools.get("opengrep"), runner=recording(calls))
    probe_tool_version("/opt/gotool", tools.get("gotool"), runner=recording(calls))
    go_toolchain_version("/opt/go", runner=recording(calls, "go1.26.9\n"))
    opengrep, gotool, go = calls
    home = tmp_path.resolve() / ".tools" / "cache" / "opengrep"
    assert opengrep["env"]["USERPROFILE"] == opengrep["env"]["HOME"] == str(home)
    assert (home / "AppData" / "Local").is_dir()
    assert opengrep["env"]["SEMGREP_LOG_FILE"] == str(opengrep["cwd"] / "opengrep.log")
    assert opengrep["env"]["XDG_CONFIG_HOME"] == str(opengrep["cwd"])
    for call in calls:
        # The empty working folder is also the temporary folder; it is removed afterwards.
        assert call["env"]["TEMP"] == call["env"]["TMP"] == str(call["cwd"])
        assert not call["cwd"].exists()
        assert not any("{workdir}" in value for value in call["env"].values())
    for call in (gotool, go):
        for name, value in toolhome.go_config_env(call["cwd"]).items():
            assert call["env"][name] == value
        # Telemetry off: without it Go kept a counter file open and the folder stayed behind.
        assert call["telemetry"] == "off"
    assert opengrep["telemetry"] is None
    assert "SEMGREP_LOG_FILE" not in gotool["env"]


def test_probe_folders_without_a_usable_home_leave_opengrep_as_it_is(monkeypatch, tmp_path):
    monkeypatch.setenv("KALKAN_HOME", str(tmp_path / "missing"))
    env = probe_folders(probe_tools().get("opengrep"), tmp_path)
    assert "SEMGREP_LOG_FILE" not in env and env["TEMP"] == str(tmp_path)


FOLDER_VARIABLES = (
    "APPDATA",
    "XDG_CONFIG_HOME",
    "XDG_CACHE_HOME",
    "TEMP",
    "TMP",
    "TMPDIR",
    "USERPROFILE",
    "HOME",
    "SEMGREP_LOG_FILE",
)


def test_probe_env_never_holds_a_placeholder_or_a_relative_folder(monkeypatch, tmp_path):
    """Regression: probe_env gave a Go program APPDATA="{workdir}". A caller that started a
    process with it directly (the control step of tests/integration/test_version_probes.py)
    made Go write its telemetry into a folder "{workdir}" below the current folder."""
    from kalkan.tools.manifest import load_manifest

    monkeypatch.setenv("KALKAN_HOME", str(tmp_path))
    for tool in [*load_manifest(), *probe_tools()]:
        env = probe_env(tool)
        assert not [key for key, value in env.items() if "{" in value], tool.name
        for key in FOLDER_VARIABLES:
            if key in env:
                assert os.path.isabs(env[key]), (tool.name, key, env[key])
        folders = probe_folders(tool, tmp_path / tool.name)
        assert not [key for key, value in folders.items() if "{" in value], tool.name
        assert all(os.path.isabs(folders[key]) for key in folders if key in FOLDER_VARIABLES)


# --- pip --------------------------------------------------------------------------------------


def test_the_setup_scripts_keep_pip_downloads_out_of_the_user_cache():
    setup = (ROOT / "plugins" / "kalkan" / "bin" / "kalkan-setup").read_text(encoding="utf-8")
    assert "--no-cache-dir --force-reinstall" in setup
    shell = (ROOT / "scripts" / "bootstrap.sh").read_text(encoding="utf-8")
    assert "pip install --disable-pip-version-check --no-cache-dir -e" in shell
    powershell = (ROOT / "scripts" / "bootstrap.ps1").read_text(encoding="utf-8")
    assert "'--disable-pip-version-check', '--no-cache-dir', '-e'" in powershell
