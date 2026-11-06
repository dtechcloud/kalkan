# SPDX-License-Identifier: MIT
"""Tests for the one-command installers scripts/install.sh and scripts/install.ps1.

The installers never touch the real Claude Code installation here. A temporary folder holds
fake ``claude``, ``gh``, ``git`` and ``sh`` programs (one Python module behind them), and PATH
holds that folder, the folder of the test interpreter (the installers need Python 3.11) and the
system folders that the shell needs, so no real ``claude``, ``gh`` or ``git`` is found. The fake
``claude`` keeps its marketplace and plugin state in the temporary folder and logs every call;
the fake ``sh`` only logs the setup call. The tests skip when the shell is missing. On Windows
the fakes are console-script launchers made by pip's distlib, the same kind of file that pip
installs into a venv.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

from kalkan.tools.platform import find_on_path

ROOT = Path(__file__).resolve().parents[2]
INSTALL_SH = ROOT / "scripts" / "install.sh"
INSTALL_PS1 = ROOT / "scripts" / "install.ps1"
TIMEOUT = 120
PROGRAMS = ("claude", "gh", "git", "sh")

FAKE_CLI = r"""
import json
import os
import sys
from pathlib import Path

STATE = Path(os.environ["FAKE_STATE"])
ROOT = STATE / "cache" / "kalkan" / "kalkan" / "9.9.9"


def log(name, args):
    with (STATE / "calls.log").open("a", encoding="utf-8") as handle:
        handle.write(" ".join([name, *args]) + "\n")


def say(text, code=0):
    sys.stdout.write(text + "\n")
    sys.stdout.flush()
    return code


def claude(args):
    log("claude", args)
    if args == ["--version"]:
        return say("2.1.301 (Claude Code)")
    if args[:2] == ["auth", "status"]:
        if os.environ.get("FAKE_LOGIN") == "no":
            return say(json.dumps({"loggedIn": False}), 1)
        config = os.environ["FAKE_CONFIG"]
        return say(json.dumps({"loggedIn": True, "configDirectory": config}))
    if args[:3] == ["plugin", "marketplace", "list"]:
        known = (STATE / "marketplace").exists()
        return say(json.dumps([{"name": "kalkan", "source": "github"}] if known else []))
    if args[:3] == ["plugin", "marketplace", "add"]:
        (STATE / "marketplace").write_text(args[3], encoding="utf-8")
        return say("Successfully added marketplace: kalkan")
    if args[:3] == ["plugin", "marketplace", "update"]:
        return say("Successfully updated marketplace: kalkan")
    if args[:2] == ["plugin", "list"]:
        if not (STATE / "plugin").exists():
            return say("[]")
        item = {"id": "kalkan@kalkan", "scope": "user", "installPath": str(ROOT)}
        return say(json.dumps([item]))
    if args[:2] == ["plugin", "install"]:
        (ROOT / "bin").mkdir(parents=True, exist_ok=True)
        (ROOT / "bin" / "kalkan-setup").write_text("#!/bin/sh\n", encoding="utf-8")
        (STATE / "plugin").write_text("installed", encoding="utf-8")
        return say("Successfully installed plugin: kalkan@kalkan")
    if args[:2] == ["plugin", "update"]:
        return say("Plugin kalkan@kalkan updated")
    return say(f"unexpected arguments: {args}", 9)


def gh(args):
    log("gh", args)
    if args[:2] == ["auth", "status"]:
        return 1 if os.environ.get("FAKE_GH") == "no" else say("Logged in to github.com")
    return 9


def git(args):
    log("git", args)
    if args == ["--version"]:
        return say("git version 2.51.0")
    if args[:1] == ["ls-remote"]:
        return 128 if os.environ.get("FAKE_GIT_ACCESS") == "no" else say("0000\tHEAD")
    return 9


def sh(args):
    log("sh", args)
    return say("kalkan-setup (fake): done")


def _run(function):
    sys.exit(function(sys.argv[1:]))


def claude_main():
    _run(claude)


def gh_main():
    _run(gh)


def git_main():
    _run(git)


def sh_main():
    _run(sh)


if __name__ == "__main__":
    name = sys.argv.pop(1)
    sys.exit(globals()[name](sys.argv[1:]))
"""


@dataclass
class Fakes:
    """The fake programs and their environment."""

    bin: Path
    state: Path
    config: Path
    env: dict[str, str]

    @property
    def calls(self) -> list[str]:
        path = self.state / "calls.log"
        return path.read_text(encoding="utf-8").splitlines() if path.is_file() else []

    @property
    def data(self) -> str:
        return (self.config / "plugins" / "data" / "kalkan-kalkan").as_posix()

    @property
    def setup(self) -> str:
        return (self.state / "cache" / "kalkan" / "kalkan" / "9.9.9" / "bin").as_posix()

    def remove(self, name: str) -> None:
        for path in self.bin.glob(f"{name}*"):
            path.unlink()


def make_fakes(tmp_path: Path, system_dirs: list[str]) -> Fakes:
    module = tmp_path / "fake-module"
    module.mkdir()
    (module / "fake_cli.py").write_text(FAKE_CLI, encoding="utf-8")
    fake_bin, state, config = tmp_path / "fake-bin", tmp_path / "state", tmp_path / "claude config"
    for folder in (fake_bin, state, config):
        folder.mkdir()
    if os.name == "nt":
        scripts = pytest.importorskip("pip._vendor.distlib.scripts")
        maker = scripts.ScriptMaker(None, str(fake_bin))
        maker.executable = sys.executable
        maker.variants = {""}
        for name in PROGRAMS:
            maker.make(f"{name} = fake_cli:{name}_main")
    else:
        for name in PROGRAMS:
            path = fake_bin / name
            path.write_text(
                f'#!/bin/sh\nexec "{sys.executable}" -m fake_cli {name} "$@"\n', encoding="utf-8"
            )
            path.chmod(0o755)
    env = {
        key: value
        for key, value in os.environ.items()
        if key.upper() not in {"PATH", "CLAUDE_CONFIG_DIR", "PYTHONPATH"}
    }
    interpreter = str(Path(sys.executable).parent)  # python (and python3 outside Windows)
    env.update(
        PATH=os.pathsep.join([str(fake_bin), interpreter, *system_dirs]),
        PYTHONPATH=str(module),
        FAKE_STATE=str(state),
        FAKE_CONFIG=str(config),
        PYTHONIOENCODING="utf-8",
    )
    return Fakes(fake_bin, state, config, env)


def run(argv, fakes: Fakes, *, cwd: Path, stdin: str | None = None, **extra: str):
    env = {**fakes.env, **extra}
    return subprocess.run(
        argv,
        cwd=cwd,
        env=env,
        input=stdin,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=TIMEOUT,
        check=False,
        shell=False,
    )


def changes(calls: list[str]) -> list[str]:
    """The calls that change something (not the checks and listings)."""
    readers = ("--version", "auth status", "marketplace list", "plugin list", "ls-remote")
    return [call for call in calls if not any(word in call for word in readers)]


# ---------------------------------------------------------------------------------------------
# install.sh


@pytest.fixture
def sh_fakes(tmp_path) -> tuple[str, Fakes]:
    shell = find_on_path("sh")
    if shell is None:
        pytest.skip("sh is not installed")
    system = [str(Path(shell).parent)]
    if os.name == "nt":
        system.append(str(Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"))
    else:
        system += ["/usr/bin", "/bin"]
    return str(shell), make_fakes(tmp_path, system)


def test_sh_dry_run_runs_only_the_checks(sh_fakes, tmp_path):
    shell, fakes = sh_fakes
    proc = run([shell, str(INSTALL_SH), "--dry-run"], fakes, cwd=tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    lines = proc.stdout.splitlines()
    assert "dry run: would run: claude plugin marketplace add dtechcloud/kalkan" in lines
    assert "dry run: would run: claude plugin install kalkan@kalkan --scope user" in lines
    expected = f"dry run: would run: sh <plugin folder>/bin/kalkan-setup {fakes.data}"
    assert expected in lines
    assert changes(fakes.calls) == []
    assert "claude auth status --json" in fakes.calls and "gh auth status" not in fakes.calls
    assert any(c.startswith("git ls-remote --exit-code https://github.com/") for c in fakes.calls)


def test_sh_installs_then_updates(sh_fakes, tmp_path):
    shell, fakes = sh_fakes
    first = run([shell, str(INSTALL_SH)], fakes, cwd=tmp_path)
    assert first.returncode == 0, first.stdout + first.stderr
    assert changes(fakes.calls) == [
        "claude plugin marketplace add dtechcloud/kalkan",
        "claude plugin install kalkan@kalkan --scope user",
        f"sh {fakes.setup}/kalkan-setup {fakes.data}",
    ]
    assert f'    sh "{fakes.data}/bin/kalkan-audit" <folder or git URL>' in first.stdout
    assert "Done. Audit a project with one command:" in first.stdout
    log_size = len(fakes.calls)
    again = run([shell, str(INSTALL_SH)], fakes, cwd=tmp_path)
    assert again.returncode == 0, again.stdout + again.stderr
    assert changes(fakes.calls[log_size:]) == [
        "claude plugin marketplace update kalkan",
        "claude plugin update kalkan@kalkan",
        f"sh {fakes.setup}/kalkan-setup {fakes.data}",
    ]


def test_sh_stops_when_claude_is_signed_out(sh_fakes, tmp_path):
    shell, fakes = sh_fakes
    proc = run([shell, str(INSTALL_SH)], fakes, cwd=tmp_path, FAKE_LOGIN="no")
    assert proc.returncode == 1
    assert "Claude Code is not signed in. Run: claude auth login" in proc.stderr
    assert changes(fakes.calls) == []


def test_sh_stops_without_claude(sh_fakes, tmp_path):
    shell, fakes = sh_fakes
    fakes.remove("claude")
    proc = run([shell, str(INSTALL_SH)], fakes, cwd=tmp_path)
    assert proc.returncode == 1 and "the Claude Code CLI (claude) is not on PATH" in proc.stderr


def test_sh_needs_no_gh_when_git_can_read_the_repository(sh_fakes, tmp_path):
    shell, fakes = sh_fakes
    fakes.remove("gh")
    proc = run([shell, str(INSTALL_SH)], fakes, cwd=tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "claude plugin marketplace add dtechcloud/kalkan" in changes(fakes.calls)


def test_sh_stops_when_git_cannot_read_the_repository(sh_fakes, tmp_path):
    shell, fakes = sh_fakes
    proc = run([shell, str(INSTALL_SH)], fakes, cwd=tmp_path, FAKE_GIT_ACCESS="no")
    assert proc.returncode == 1 and "gh auth setup-git" in proc.stderr
    ls_remote = [call for call in fakes.calls if call.startswith("git ls-remote")]
    assert len(ls_remote) == 2  # https, then ssh
    assert changes(fakes.calls) == []


def test_sh_local_source_and_skip_setup(sh_fakes, tmp_path):
    shell, fakes = sh_fakes
    local = tmp_path / "kalkan-checkout"
    local.mkdir()
    proc = run(
        [shell, str(INSTALL_SH), "--source", local.as_posix(), "--skip-setup"],
        fakes,
        cwd=tmp_path,
        FAKE_GH="no",  # a local source needs no GitHub access
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert changes(fakes.calls) == [
        f"claude plugin marketplace add {local.as_posix()}",
        "claude plugin install kalkan@kalkan --scope user",
    ]
    assert "skipped (--skip-setup)" in proc.stdout


def test_sh_from_a_pipe(sh_fakes, tmp_path):
    shell, fakes = sh_fakes
    script = INSTALL_SH.read_text(encoding="utf-8")
    proc = run([shell, "-s", "--", "--dry-run"], fakes, cwd=tmp_path, stdin=script)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "dry run: would run: claude plugin install kalkan@kalkan --scope user" in proc.stdout


def test_sh_usage(sh_fakes, tmp_path):
    shell, fakes = sh_fakes
    proc = run([shell, str(INSTALL_SH), "--bogus"], fakes, cwd=tmp_path)
    assert proc.returncode == 2 and "unknown option: --bogus" in proc.stderr
    proc = run([shell, str(INSTALL_SH), "--help"], fakes, cwd=tmp_path)
    assert proc.returncode == 0 and proc.stdout.startswith("Usage: sh scripts/install.sh")


def test_the_sh_installer_file():
    data = INSTALL_SH.read_bytes()
    assert data.startswith(b"#!/bin/sh\n") and b"\r\n" not in data
    assert b"set -eu" in data


# ---------------------------------------------------------------------------------------------
# install.ps1 (Windows: the fakes are .exe launchers)


@pytest.fixture
def ps_fakes(tmp_path) -> tuple[str, Fakes]:
    if os.name != "nt":
        pytest.skip("the PowerShell installer is for Windows")
    shell = find_on_path("pwsh") or find_on_path("powershell")
    if shell is None:
        pytest.skip("PowerShell is not installed")
    system32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
    system = [str(system32), str(system32 / "WindowsPowerShell" / "v1.0"), str(Path(shell).parent)]
    return str(shell), make_fakes(tmp_path, system)


def ps_file(shell: str, *args: str) -> list[str]:
    return [shell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File"] + [
        str(INSTALL_PS1),
        *args,
    ]


def test_ps_dry_run_runs_only_the_checks(ps_fakes, tmp_path):
    shell, fakes = ps_fakes
    proc = run(ps_file(shell, "-DryRun"), fakes, cwd=tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "dry run: would run: claude plugin marketplace add dtechcloud/kalkan" in proc.stdout
    assert "dry run: would run: claude plugin install kalkan@kalkan --scope user" in proc.stdout
    assert "<plugin folder>/bin/kalkan-setup" in proc.stdout
    assert changes(fakes.calls) == []


def test_ps_installs_then_updates(ps_fakes, tmp_path):
    shell, fakes = ps_fakes
    first = run(ps_file(shell), fakes, cwd=tmp_path)
    assert first.returncode == 0, first.stdout + first.stderr
    assert changes(fakes.calls) == [
        "claude plugin marketplace add dtechcloud/kalkan",
        "claude plugin install kalkan@kalkan --scope user",
        f"sh {fakes.setup}/kalkan-setup {fakes.data}",
    ]
    # PowerShell writes redirected output in the console code page: compare the ASCII tail only.
    tail = r'claude config\plugins\data\kalkan-kalkan\bin\kalkan-audit.cmd" <folder or git URL>'
    (line,) = [line for line in first.stdout.splitlines() if "PowerShell: & " in line]
    assert line.endswith(tail)
    size = len(fakes.calls)
    again = run(ps_file(shell), fakes, cwd=tmp_path)
    assert again.returncode == 0, again.stdout + again.stderr
    assert changes(fakes.calls[size:])[:2] == [
        "claude plugin marketplace update kalkan",
        "claude plugin update kalkan@kalkan",
    ]


def test_ps_stops_when_claude_is_signed_out(ps_fakes, tmp_path):
    shell, fakes = ps_fakes
    proc = run(ps_file(shell), fakes, cwd=tmp_path, FAKE_LOGIN="no")
    assert proc.returncode == 1
    assert "Claude Code is not signed in. Run: claude auth login" in proc.stderr
    assert changes(fakes.calls) == []


def test_ps_one_line_form_keeps_the_window_open(ps_fakes, tmp_path):
    shell, fakes = ps_fakes
    path = str(INSTALL_PS1).replace("'", "''")
    command = (
        f"& ([scriptblock]::Create((Get-Content -Raw -LiteralPath '{path}'))) -DryRun; "
        'Write-Output "after: $LASTEXITCODE"'
    )
    proc = run([shell, "-NoProfile", "-NonInteractive", "-Command", command], fakes, cwd=tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "dry run: would run: claude plugin install kalkan@kalkan --scope user" in proc.stdout
    assert "after: 0" in proc.stdout
    failed = run(
        [shell, "-NoProfile", "-NonInteractive", "-Command", command],
        fakes,
        cwd=tmp_path,
        FAKE_LOGIN="no",
    )
    assert "after: 1" in failed.stdout  # the error returned; the session went on


def test_the_ps_installer_file():
    data = INSTALL_PS1.read_bytes()
    lines = data.split(b"\r\n")
    assert b"\n" not in b"".join(lines)  # CRLF, as the other PowerShell scripts
    assert data.decode("utf-8").isascii()  # Windows PowerShell 5.1 reads a BOM-less file as ANSI


@pytest.mark.parametrize("script", [INSTALL_SH, INSTALL_PS1])
def test_the_installers_name_the_one_line_form(script):
    text = script.read_text(encoding="utf-8")
    assert "https://raw.githubusercontent.com/dtechcloud/kalkan/main/scripts/" in text


def test_shutil_finds_no_real_claude_in_the_fake_path(sh_fakes):
    _, fakes = sh_fakes
    fakes.remove("claude")
    assert shutil.which("claude", path=fakes.env["PATH"]) is None
