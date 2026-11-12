# SPDX-License-Identifier: MIT
"""Tests for the doctor and tools commands through kalkan.cli.main (no network)."""

from __future__ import annotations

import hashlib
import io
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from kalkan import cli
from kalkan.cli import EXIT_OK, EXIT_TOOL_MISSING, EXIT_USAGE, main
from kalkan.tools import commands
from kalkan.tools import manifest as manifest_mod
from kalkan.tools.platform import PLATFORMS, exe_suffix, platform_key

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "tools"
FAKE_BINARY = b"\x7fELF-kalkan-test-binary\x00faketool 1.2.3\n"
FAKE_SHA = hashlib.sha256(FAKE_BINARY).hexdigest()


def binary_tool(fixture: str, member: str, sha256: str | None = None) -> dict:
    data = (FIXTURES / fixture).read_bytes()
    asset = {
        "url": (FIXTURES / fixture).as_uri(),
        "sha256": sha256 or hashlib.sha256(data).hexdigest(),
        "archive": "zip",
        "binary": member,
        "binary_sha256": FAKE_SHA,
    }
    return {
        "version": "1.2.3",
        "license": "MIT",
        "kind": "binary",
        "executable": "faketool",
        "version_args": ["--version"],
        "blocked_versions": [],
        "sha256_source": "computed-at-pin-time",
        "notes": "",
        "platforms": {key: dict(asset) for key in PLATFORMS},
    }


@pytest.fixture(autouse=True)
def only_tools_commands(monkeypatch):
    """Load only kalkan.tools.commands, so that other command modules cannot break these tests."""
    selected = {k: v for k, v in cli.COMMANDS.items() if v[0] == "kalkan.tools.commands"}
    monkeypatch.setattr(cli, "COMMANDS", selected)


@pytest.fixture
def repo(tmp_path, monkeypatch) -> Path:
    document = {
        "schema_version": 1,
        "tools": {
            "faketool": binary_tool("faketool-1.2.3.zip", "faketool-1.2.3/faketool"),
            "badtool": binary_tool("faketool-1.2.3.zip", "faketool-1.2.3/faketool", "0" * 64),
        },
    }
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    monkeypatch.setattr(manifest_mod, "DEFAULT_MANIFEST_PATH", path)
    root = tmp_path / "repo"
    root.mkdir()
    monkeypatch.setattr(commands, "_repo_root", lambda: root)
    monkeypatch.delenv("KALKAN_RUNS_DIR", raising=False)
    return root


def installed_binary(root: Path) -> Path:
    return (
        root / ".tools" / "faketool" / "1.2.3" / "bin" / ("faketool" + exe_suffix(platform_key()))
    )


def test_tools_without_subcommand_prints_help(repo, capsys):
    assert main(["tools"]) == EXIT_USAGE
    out = capsys.readouterr().out
    for name in ("install", "verify", "list"):
        assert name in out


def test_list_json(repo, capsys):
    assert main(["tools", "list", "--json"]) == EXIT_OK
    data = json.loads(capsys.readouterr().out)
    assert data["platform"] == platform_key()
    assert [tool["name"] for tool in data["tools"]] == ["faketool", "badtool"]
    assert data["tools"][0]["installed"] is False
    assert data["tools"][0]["available"] is True


def test_install_verify_and_list(repo, capsys):
    assert main(["tools", "install", "faketool", "--json"]) == EXIT_OK
    captured = capsys.readouterr()
    (result,) = json.loads(captured.out)["results"]
    assert result["status"] == "installed"
    assert "Downloading faketool 1.2.3" in captured.err
    assert installed_binary(repo).read_bytes() == FAKE_BINARY

    assert main(["tools", "install", "faketool", "--json"]) == EXIT_OK
    (again,) = json.loads(capsys.readouterr().out)["results"]
    assert again["status"] == "present"

    assert main(["tools", "verify", "faketool", "--json"]) == EXIT_OK
    (checked,) = json.loads(capsys.readouterr().out)["results"]
    assert checked["status"] == "ok"

    assert main(["tools", "verify", "--quick", "faketool", "--json"]) == EXIT_OK
    (quick,) = json.loads(capsys.readouterr().out)["results"]
    assert quick["status"] == "ok"

    assert main(["tools", "list", "--json"]) == EXIT_OK
    listing = json.loads(capsys.readouterr().out)
    assert listing["tools"][0]["installed"] is True
    assert listing["tools"][0]["path"].startswith(".tools/faketool/1.2.3/bin/faketool")


def test_install_table_output(repo, capsys):
    assert main(["tools", "install", "faketool"]) == EXIT_OK
    out = capsys.readouterr().out
    assert out.splitlines()[0].split() == ["TOOL", "VERSION", "STATUS", "PATH", "MESSAGE"]
    assert "installed" in out


@pytest.mark.parametrize(
    ("argv", "message"),
    [
        (["tools", "install"], "name the tools to install"),
        (["tools", "install", "--all", "faketool"], "not both"),
        (["tools", "install", "nope"], "unknown tool(s): nope"),
        (["tools", "verify", "nope"], "unknown tool(s): nope"),
    ],
)
def test_usage_errors(repo, capsys, argv, message):
    assert main(argv) == EXIT_USAGE
    assert message in capsys.readouterr().err


def test_sha_mismatch_exits_with_tool_error(repo, capsys):
    assert main(["tools", "install", "--all", "--json"]) == EXIT_TOOL_MISSING
    captured = capsys.readouterr()
    results = {r["name"]: r for r in json.loads(captured.out)["results"]}
    assert results["faketool"]["status"] == "installed"
    assert results["badtool"]["status"] == "failed"
    assert "SHA-256 mismatch" in results["badtool"]["message"]
    assert "1 tool(s) failed to install: badtool" in captured.err


def test_verify_reports_missing_and_tampered_tools(repo, capsys):
    assert main(["tools", "verify"]) == EXIT_TOOL_MISSING
    assert "not installed" in capsys.readouterr().err

    assert main(["tools", "install", "faketool"]) == EXIT_OK
    installed_binary(repo).write_bytes(b"tampered")
    capsys.readouterr()
    assert main(["tools", "verify", "faketool"]) == EXIT_TOOL_MISSING
    assert "differ from the pinned values" in capsys.readouterr().err


def fake_run(argv, *, timeout, env=None, cwd=None):
    name = Path(str(argv[0])).name.removesuffix(".exe")
    replies = {"git": "git version 2.47.1", "faketool": "faketool 1.2.3"}
    if name in replies:
        return subprocess.CompletedProcess(argv, 0, replies[name] + "\n", "")
    raise OSError(name)


@pytest.fixture
def fake_doctor(monkeypatch):
    real = commands.doctor_mod.run_doctor

    def run(root):
        return real(
            root,
            runner=fake_run,
            finder=lambda name: Path(f"/fake/{name}") if name == "git" else None,
            disk_usage=lambda path: SimpleNamespace(free=50 * 1000**3),
        )

    monkeypatch.setattr(commands.doctor_mod, "run_doctor", run)


def test_doctor_json(repo, fake_doctor, capsys):
    assert main(["tools", "install", "faketool"]) == EXIT_OK
    capsys.readouterr()
    code = main(["doctor", "--json"])
    data = json.loads(capsys.readouterr().out)
    # badtool is not installed: a missing manifest tool fails the doctor.
    assert code == data["exit_code"] == 1
    checks = {check["name"]: check for check in data["checks"]}
    assert checks["tool:faketool"]["status"] == "ok"
    assert checks["tool:badtool"]["status"] == "fail"
    assert "kalkan tools install badtool" in checks["tool:badtool"]["detail"]
    assert checks["docker-client"]["status"] == "warn"
    assert checks["runs-writable"]["status"] == "ok"
    assert (repo / "runs").is_dir()


def test_doctor_table(repo, fake_doctor, capsys):
    assert main(["doctor"]) == 1
    out = capsys.readouterr().out
    assert out.splitlines()[0].split() == ["STATUS", "CHECK", "DETAIL"]
    assert "Summary:" in out and "Exit code 1." in out


def test_doctor_exit_code_zero_when_every_tool_is_installed(repo, fake_doctor, capsys, monkeypatch):
    document = json.loads(manifest_mod.DEFAULT_MANIFEST_PATH.read_text(encoding="utf-8"))
    del document["tools"]["badtool"]
    manifest_mod.DEFAULT_MANIFEST_PATH.write_text(json.dumps(document), encoding="utf-8")
    assert main(["tools", "install", "faketool"]) == EXIT_OK
    capsys.readouterr()
    assert main(["doctor"]) == EXIT_OK  # Docker and Claude missing: warnings only


def test_json_output_is_utf8_on_an_ansi_pipe(monkeypatch):
    raw = io.BytesIO()
    stream = io.TextIOWrapper(raw, encoding="cp1254", newline="\n")
    monkeypatch.setattr(sys, "stdout", stream)
    commands._print_json({"path": "C:/Users/DevKüçük"})
    assert json.loads(raw.getvalue().decode("utf-8")) == {"path": "C:/Users/DevKüçük"}
