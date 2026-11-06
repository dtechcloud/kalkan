# SPDX-License-Identifier: MIT
"""Tests for the launchers of the Claude Code plugin and their setup.

- ``plugins/kalkan/bin/kalkan-audit`` and ``kalkan-unattended`` (sh: Linux, macOS, Git Bash);
- ``plugins/kalkan/bin/kalkan-audit.cmd`` and ``kalkan-unattended.cmd`` (PowerShell and cmd on
  Windows);
- the part of ``plugins/kalkan/bin/kalkan-setup`` that copies them to ``<data>/bin``.

Every launcher test runs for both launchers (``LAUNCHERS``: the launcher name and the engine
command that it starts). The tests run the scripts with their shell and skip when the shell is
missing. They never start kalkan or Claude Code: the fake engine prints its arguments and exits
with code 7. The ``.cmd`` tests build the fake ``kalkan.exe`` with the console-script launcher
of pip (distlib), the same kind of file that pip installs into a venv.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from kalkan.tools.platform import find_on_path

ROOT = Path(__file__).resolve().parents[2]
PLUGIN_BIN = ROOT / "plugins" / "kalkan" / "bin"
#: Launcher name -> the engine command that it starts.
LAUNCHERS = {"kalkan-unattended": "unattended", "kalkan-audit": "audit"}
TIMEOUT = 120
FAKE_EXIT = 7
RUN = "20261016T151915Z-billing-5fc6"


@pytest.fixture(params=sorted(LAUNCHERS))
def launcher(request) -> tuple[str, str]:
    """``(sh launcher name, engine command)``; the cmd launcher adds ``.cmd`` to the name."""
    return request.param, LAUNCHERS[request.param]


def run(argv: list[str], *, cwd: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=TIMEOUT,
        stdin=subprocess.DEVNULL,
        check=False,
        shell=False,
    )


def clean_env(**extra: str) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k != "CLAUDE_PLUGIN_DATA"}
    env.update(extra)
    return env


def make_executable(path: Path) -> None:
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def data_folder(tmp_path: Path) -> Path:
    """Return ``<tmp>/data ü`` (a space and a non-ASCII letter, as in a real user folder)."""
    data = tmp_path / "data ü"
    data.mkdir()
    return data


def install_launcher(data: Path, name: str) -> Path:
    """Copy a launcher to ``<data>/bin`` as kalkan-setup does."""
    target = data / "bin" / name
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(PLUGIN_BIN / name, target)
    if not name.endswith(".cmd"):
        make_executable(target)
    return target


def plugin_root_copy(tmp_path: Path, name: str) -> Path:
    """Copy a launcher to a fake plugin root, where no venv is next to it."""
    target = tmp_path / "cache" / "kalkan" / "1.0.0" / "bin" / name
    target.parent.mkdir(parents=True)
    shutil.copyfile(PLUGIN_BIN / name, target)
    return target


# ---------------------------------------------------------------------------------------------
# The files


def test_the_launchers_have_the_right_line_endings(launcher):
    name, command = launcher
    sh = (PLUGIN_BIN / name).read_bytes()
    assert sh.startswith(b"#!/bin/sh\n") and b"\r\n" not in sh
    assert f'exec "$engine" {command} "$@"'.encode() in sh
    cmd = (PLUGIN_BIN / f"{name}.cmd").read_bytes()
    cmd.decode("ascii")  # cmd.exe reads a batch file in the OEM code page
    lines = cmd.split(b"\r\n")
    assert lines[0] == b"@echo off" and lines[-1] == b""
    assert b"\n" not in b"".join(lines)  # every line ends with CRLF
    assert f'"%KALKAN_ENGINE%" {command} %*'.encode() in cmd


def test_the_cmd_launchers_have_no_percent_sign_in_a_comment(launcher):
    # cmd.exe expands % in a rem line too, and "%~" there stops the script with an error.
    name, _ = launcher
    for line in (PLUGIN_BIN / f"{name}.cmd").read_text(encoding="ascii").splitlines():
        if line.lower().startswith("rem"):
            assert "%" not in line, line


def test_the_sh_launchers_are_executable_in_git():
    proc = subprocess.run(
        ["git", "ls-files", "-s", "--", *(f"plugins/kalkan/bin/{name}" for name in LAUNCHERS)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0 or not proc.stdout.strip():
        pytest.skip("not a git checkout, or the launchers are not added yet")
    modes = {line.split("\t")[1]: line.split()[0] for line in proc.stdout.splitlines()}
    for name in LAUNCHERS:
        assert modes.get(f"plugins/kalkan/bin/{name}") == "100755", name


# ---------------------------------------------------------------------------------------------
# sh launchers


@pytest.fixture
def sh() -> str:
    found = find_on_path("sh")
    if found is None:
        pytest.skip("sh is not installed")
    return str(found)


def fake_posix_engine(data: Path) -> Path:
    engine = data / "venv" / "bin" / "kalkan"
    engine.parent.mkdir(parents=True)
    engine.write_bytes(b'#!/bin/sh\nfor arg in "$@"; do printf "[%s]" "$arg"; done\necho\nexit 7\n')
    make_executable(engine)
    return engine


def test_sh_copy_in_the_data_folder_passes_arguments_and_exit_code(sh, tmp_path, launcher):
    name, command = launcher
    data = data_folder(tmp_path)
    fake_posix_engine(data)
    copy = install_launcher(data, name)
    proc = run(
        [sh, str(copy), "devam", RUN, "--max-hours", "2", "--json", "my target"],
        cwd=tmp_path,
        env=clean_env(),
    )
    assert proc.returncode == FAKE_EXIT, proc.stderr
    expected = f"[{command}][devam][{RUN}][--max-hours][2][--json][my target]"
    assert proc.stdout.strip() == expected
    proc = run([sh, str(copy), "devam"], cwd=tmp_path, env=clean_env())
    assert proc.stdout.strip() == f"[{command}][devam]"


def test_sh_copy_in_the_data_folder_wins_over_claude_plugin_data(sh, tmp_path, launcher):
    name, command = launcher
    data = data_folder(tmp_path)
    fake_posix_engine(data)
    copy = install_launcher(data, name)
    env = clean_env(CLAUDE_PLUGIN_DATA=str(tmp_path / "elsewhere"))
    proc = run([sh, str(copy), "devam"], cwd=tmp_path, env=env)
    assert proc.returncode == FAKE_EXIT and f"[{command}][devam]" in proc.stdout


def test_sh_plugin_root_copy_uses_claude_plugin_data(sh, tmp_path, launcher):
    name, command = launcher
    data = data_folder(tmp_path)
    fake_posix_engine(data)
    copy = plugin_root_copy(tmp_path, name)
    env = clean_env(CLAUDE_PLUGIN_DATA=str(data))
    proc = run([sh, str(copy), "app", "--profile", "deep"], cwd=tmp_path, env=env)
    assert proc.returncode == FAKE_EXIT, proc.stderr
    assert proc.stdout.strip() == f"[{command}][app][--profile][deep]"


def test_sh_without_a_data_folder(sh, tmp_path, launcher):
    name, _ = launcher
    copy = plugin_root_copy(tmp_path, name)
    proc = run([sh, str(copy), "devam"], cwd=tmp_path, env=clean_env())
    assert proc.returncode == 1 and proc.stdout == ""
    assert f"{name}: error: cannot find the kalkan plugin data folder" in proc.stderr
    assert "/kalkan unattended" in proc.stderr


def test_sh_without_the_engine(sh, tmp_path, launcher):
    name, _ = launcher
    data = data_folder(tmp_path)
    (data / "venv").mkdir()  # setup started, but the engine is not installed yet
    copy = install_launcher(data, name)
    proc = run([sh, str(copy), "devam"], cwd=tmp_path, env=clean_env())
    assert proc.returncode == 1
    assert "the kalkan engine is missing" in proc.stderr and "/kalkan unattended" in proc.stderr


# ---------------------------------------------------------------------------------------------
# cmd launchers (Windows)


@pytest.fixture
def cmd() -> str:
    if os.name != "nt":
        pytest.skip("cmd.exe exists only on Windows")
    return str(Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "cmd.exe")


def fake_windows_engine(data: Path, tmp_path: Path) -> dict[str, str]:
    """Create ``<data>/venv/Scripts/kalkan.exe`` and return the environment that it needs."""
    scripts = pytest.importorskip("pip._vendor.distlib.scripts")
    module = tmp_path / "fake-module"
    module.mkdir()
    (module / "fake_kalkan_entry.py").write_text(
        "import sys\n\n\ndef main():\n"
        '    print("".join(f"[{arg}]" for arg in sys.argv[1:]))\n'
        f"    return {FAKE_EXIT}\n",
        encoding="utf-8",
    )
    maker = scripts.ScriptMaker(None, str(data / "venv" / "Scripts"))
    maker.executable = sys.executable
    maker.variants = {""}
    maker.make("kalkan = fake_kalkan_entry:main")
    assert (data / "venv" / "Scripts" / "kalkan.exe").is_file()
    return clean_env(PYTHONPATH=str(module), PYTHONIOENCODING="utf-8")


def run_cmd(cmd: str, copy: Path, *args: str, cwd: Path, env: dict[str, str]):
    return run([cmd, "/d", "/c", str(copy), *args], cwd=cwd, env=env)


def test_cmd_copy_in_the_data_folder_passes_arguments_and_exit_code(cmd, tmp_path, launcher):
    name, command = launcher
    data = data_folder(tmp_path)
    env = fake_windows_engine(data, tmp_path)
    copy = install_launcher(data, f"{name}.cmd")
    proc = run_cmd(cmd, copy, "devam", RUN, "--max-hours", "2", cwd=tmp_path, env=env)
    assert proc.returncode == FAKE_EXIT, proc.stderr
    assert proc.stdout.strip() == f"[{command}][devam][{RUN}][--max-hours][2]"
    proc = run_cmd(cmd, copy, "devam", cwd=tmp_path, env=env)
    assert proc.stdout.strip() == f"[{command}][devam]"


def test_cmd_from_powershell_keeps_a_quoted_path(cmd, tmp_path, launcher):
    shell = find_on_path("pwsh") or find_on_path("powershell")
    if shell is None:
        pytest.skip("PowerShell is not installed")
    name, command = launcher
    data = data_folder(tmp_path)
    env = fake_windows_engine(data, tmp_path)
    copy = install_launcher(data, f"{name}.cmd")
    script = f"& '{copy.as_posix()}' 'C:\\my app' --profile deep; exit $LASTEXITCODE"
    proc = run(
        [str(shell), "-NoProfile", "-NonInteractive", "-Command", script], cwd=tmp_path, env=env
    )
    assert proc.returncode == FAKE_EXIT, proc.stderr
    assert proc.stdout.strip() == f"[{command}][C:\\my app][--profile][deep]"


def test_cmd_plugin_root_copy_uses_claude_plugin_data(cmd, tmp_path, launcher):
    name, command = launcher
    data = data_folder(tmp_path)
    env = fake_windows_engine(data, tmp_path)
    env["CLAUDE_PLUGIN_DATA"] = data.as_posix()  # Claude Code gives forward slashes
    copy = plugin_root_copy(tmp_path, f"{name}.cmd")
    proc = run_cmd(cmd, copy, "devam", cwd=tmp_path, env=env)
    assert proc.returncode == FAKE_EXIT, proc.stderr
    assert proc.stdout.strip() == f"[{command}][devam]"


def test_cmd_without_a_data_folder(cmd, tmp_path, launcher):
    name, _ = launcher
    copy = plugin_root_copy(tmp_path, f"{name}.cmd")
    proc = run_cmd(cmd, copy, "devam", cwd=tmp_path, env=clean_env())
    assert proc.returncode == 1
    assert f"{name}: error: cannot find the kalkan plugin data folder" in proc.stderr


def test_cmd_without_the_engine(cmd, tmp_path, launcher):
    name, _ = launcher
    data = data_folder(tmp_path)
    (data / "venv").mkdir()
    copy = install_launcher(data, f"{name}.cmd")
    proc = run_cmd(cmd, copy, "devam", cwd=tmp_path, env=clean_env())
    assert proc.returncode == 1
    assert "the kalkan engine is missing" in proc.stderr and "/kalkan unattended" in proc.stderr


# ---------------------------------------------------------------------------------------------
# kalkan-setup copies the launchers


def test_setup_copies_the_launchers_and_prints_the_commands(sh, tmp_path):
    """The fast path (engine current) copies the launchers to <data>/bin and prints them before
    the last line ``engine: <path>``."""
    data = data_folder(tmp_path)
    if os.name == "nt":
        scripts = data / "venv" / "Scripts"
        scripts.mkdir(parents=True)
        (scripts / "python.exe").write_bytes(b"")
        (scripts / "kalkan.exe").write_bytes(b"")
    else:
        fake_posix_engine(data)
        python = data / "venv" / "bin" / "python"
        python.write_bytes(b"#!/bin/sh\nexit 1\n")
        make_executable(python)
    sums = (ROOT / "plugins" / "kalkan" / "engine" / "SHA256SUMS").read_text(encoding="utf-8")
    (data / "engine.sha256").write_text(sums.split()[0] + "\n", encoding="utf-8")
    # Guard: when the fast path is not taken, the full setup must stop at once (no venv, no
    # downloads). Fake interpreters that fail come first on PATH.
    guard = tmp_path / "no-python"
    guard.mkdir()
    for name in ("py", "python3", "python"):
        (guard / name).write_bytes(b"#!/bin/sh\nexit 1\n")
        make_executable(guard / name)
    env = clean_env(PATH=str(guard) + os.pathsep + os.environ.get("PATH", ""))
    setup = PLUGIN_BIN / "kalkan-setup"
    shown = data.as_posix()

    proc = run([sh, setup.as_posix(), shown], cwd=tmp_path, env=env)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "The kalkan engine is up to date." in proc.stdout
    for name in LAUNCHERS:
        for copy in (name, f"{name}.cmd"):
            assert (data / "bin" / copy).read_bytes() == (PLUGIN_BIN / copy).read_bytes()
    lines = proc.stdout.splitlines()
    assert lines[-1].startswith("engine: ")
    assert f'audit (sh): sh "{shown}/bin/kalkan-audit" <target>' in lines
    expected = f'unattended (sh): sh "{shown}/bin/kalkan-unattended" <target> --profile standard'
    assert expected in lines
    powershell = [line for line in lines if line.startswith("unattended (PowerShell): & ")]
    audit_ps = [line for line in lines if line.startswith("audit (PowerShell): & ")]
    if os.name == "nt":
        (line,) = powershell
        assert line.endswith('/bin/kalkan-unattended.cmd" <target> --profile standard')
        (line,) = audit_ps
        assert line.endswith('/bin/kalkan-audit.cmd" <target>')
    else:
        assert powershell == [] and audit_ps == []
        for name in LAUNCHERS:
            assert os.access(data / "bin" / name, os.X_OK)

    # A changed launcher is replaced on the next start; the output stays the same.
    (data / "bin" / "kalkan-audit").write_text("old\n", encoding="utf-8")
    again = run([sh, setup.as_posix(), shown], cwd=tmp_path, env=env)
    assert again.returncode == 0 and again.stdout == proc.stdout
    assert (data / "bin" / "kalkan-audit").read_bytes() == (
        PLUGIN_BIN / "kalkan-audit"
    ).read_bytes()
