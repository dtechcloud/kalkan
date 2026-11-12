# SPDX-License-Identifier: MIT
"""Tests for scripts/run-unattended.ps1 and scripts/run-unattended.sh.

The tests copy a script into a temporary repository and run it with its shell. They skip when
the shell is not installed. They never start kalkan or Claude Code: the temporary repository has
no venv, or a fake kalkan that prints its arguments.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

from kalkan.tools.platform import find_on_path

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
TIMEOUT = 120


def fake_repo(tmp_path: Path, name: str) -> Path:
    repo = tmp_path / "repo"
    (repo / "scripts").mkdir(parents=True)
    shutil.copyfile(SCRIPTS / name, repo / "scripts" / name)
    return repo


def run(argv: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=TIMEOUT,
        stdin=subprocess.DEVNULL,
        check=False,
        shell=False,
    )


# ---------------------------------------------------------------------------------------------
# POSIX shell


@pytest.fixture
def sh() -> str:
    found = find_on_path("sh")
    if found is None:
        pytest.skip("sh is not installed")
    return str(found)


def test_sh_help(sh, tmp_path):
    repo = fake_repo(tmp_path, "run-unattended.sh")
    for flag in ("-h", "--help"):
        proc = run([sh, "scripts/run-unattended.sh", "devam", flag], repo)
        assert proc.returncode == 0 and "Usage:" in proc.stdout


def test_sh_without_arguments(sh, tmp_path):
    repo = fake_repo(tmp_path, "run-unattended.sh")
    proc = run([sh, "scripts/run-unattended.sh"], repo)
    assert proc.returncode == 2 and "Usage:" in proc.stderr


def test_sh_without_venv(sh, tmp_path):
    repo = fake_repo(tmp_path, "run-unattended.sh")
    proc = run([sh, "scripts/run-unattended.sh", "devam"], repo)
    assert proc.returncode == 1
    assert "bootstrap.sh" in proc.stderr and ".venv/bin/kalkan" in proc.stderr


def test_sh_passes_arguments_and_exit_code(sh, tmp_path):
    repo = fake_repo(tmp_path, "run-unattended.sh")
    fake = repo / ".venv" / "bin" / "kalkan"
    fake.parent.mkdir(parents=True)
    fake.write_bytes(b'#!/bin/sh\necho "args: $*"\nexit 7\n')
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    proc = run([sh, "scripts/run-unattended.sh", "devam", "--max-hours", "2"], repo)
    assert proc.returncode == 7
    assert "args: unattended devam --max-hours 2" in proc.stdout


# ---------------------------------------------------------------------------------------------
# PowerShell


@pytest.fixture
def powershell() -> str:
    for name in ("pwsh", "powershell"):
        found = find_on_path(name)
        if found is not None:
            return str(found)
    pytest.skip("PowerShell is not installed")


def ps(shell: str, repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    script = str(repo / "scripts" / "run-unattended.ps1")
    command = [shell, "-NoProfile", "-NonInteractive"]
    if os.name == "nt":
        command += ["-ExecutionPolicy", "Bypass"]
    return run([*command, "-File", script, *args], repo)


def test_powershell_help(powershell, tmp_path):
    repo = fake_repo(tmp_path, "run-unattended.ps1")
    for flag in ("-h", "--help"):
        proc = ps(powershell, repo, "devam", flag)
        assert proc.returncode == 0 and "Usage:" in proc.stdout


def test_powershell_without_arguments(powershell, tmp_path):
    repo = fake_repo(tmp_path, "run-unattended.ps1")
    proc = ps(powershell, repo)
    assert proc.returncode == 2 and "Usage:" in proc.stderr


def test_powershell_without_venv(powershell, tmp_path):
    repo = fake_repo(tmp_path, "run-unattended.ps1")
    proc = ps(powershell, repo, "devam", "--max-hours", "2")
    assert proc.returncode == 1
    assert "bootstrap.ps1" in proc.stderr and "kalkan.exe" in proc.stderr
