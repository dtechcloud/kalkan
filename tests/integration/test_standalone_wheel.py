# SPDX-License-Identifier: MIT
"""The bundled engine wheel works without a checkout (docs/ENGINE-SPEC.md, section 24).

The test unpacks ``plugins/kalkan/engine/*.whl`` into a temporary site folder (what pip does
for a pure-Python wheel) and runs the engine from there in a separate process, with
``KALKAN_HOME`` pointing to a temporary folder. The process is isolated (``python -I``), so it
cannot import kalkan from this checkout. ``run init`` and ``scan matcher`` must work and read
the knowledge and rules data from the wheel. A second test runs ``kalkan unattended --dry-run``
with the Python of a new venv that holds the plugin marker (a plugin install).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
ENGINE = ROOT / "plugins" / "kalkan" / "engine"

_RUNNER = (
    "import sys; sys.path.insert(0, sys.argv.pop(1)); "
    "from kalkan.cli import main; raise SystemExit(main(sys.argv[1:]))"
)


@pytest.fixture(scope="module")
def site(tmp_path_factory) -> Path:
    wheels = sorted(ENGINE.glob("kalkan-*.whl"))
    assert len(wheels) == 1, "run: python scripts/build_plugin.py"
    folder = tmp_path_factory.mktemp("site")
    with zipfile.ZipFile(wheels[0]) as archive:
        archive.extractall(folder)
    return folder


def engine(site: Path, home: Path, *args: str) -> subprocess.CompletedProcess:
    env = {key: value for key, value in os.environ.items() if not key.startswith("KALKAN_")}
    env["KALKAN_HOME"] = str(home)
    return subprocess.run(
        [sys.executable, "-I", "-c", _RUNNER, str(site), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=env,
        cwd=home,
        timeout=300,
        check=False,
    )


def test_the_wheel_runs_an_audit_start_without_a_checkout(site, tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text(
        "import os\n\ndef run(cmd):\n    os.system('ls ' + cmd)\n", encoding="utf-8"
    )

    version = engine(site, home, "--version")
    assert version.returncode == 0, version.stderr
    assert version.stdout.startswith("kalkan ")

    paths = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            "import sys, json; sys.path.insert(0, sys.argv[1]); "
            "from kalkan import resources; print(json.dumps(resources.doctor_check()))",
            str(site),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        env={**os.environ, "KALKAN_HOME": str(home)},
        timeout=60,
        check=False,
    )
    assert paths.returncode == 0, paths.stderr
    check = json.loads(paths.stdout)
    assert check["status"] == "ok"
    assert check["data"]["data_source"] == "package"
    assert check["data"]["home_source"] == "env"
    assert Path(check["data"]["knowledge"]).is_relative_to(site)

    init = engine(site, home, "run", "init", str(target), "--profile", "fast", "--json")
    assert init.returncode == 0, init.stderr
    run = json.loads(init.stdout)
    assert Path(run["run_dir"]).resolve().is_relative_to((home / "runs").resolve())

    scan = engine(site, home, "scan", "matcher", "--json")
    assert scan.returncode == 0, scan.stderr
    (result,) = json.loads(scan.stdout)["results"]
    assert result["engine"] == "matcher"
    assert result["status"] == "ok"
    assert "matchers applied" in result["message"]


def test_a_plugin_venv_runs_unattended_rounds_in_the_runs_root(site, tmp_path):
    """A venv with the plugin marker is a plugin install: ``kalkan unattended`` sends the plugin
    skill and runs the rounds in the runs root (a dry run: nothing starts)."""
    venv = tmp_path / "data" / "venv"
    created = subprocess.run(
        [sys.executable, "-m", "venv", "--without-pip", str(venv)],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert created.returncode == 0, created.stderr
    python = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    runs = tmp_path / "kalkan-runs"
    marker = {"home": str((tmp_path / "data").resolve()), "runs": str(runs.resolve())}
    (venv / "kalkan-home.json").write_text(json.dumps(marker), encoding="utf-8")
    target = tmp_path / "target"
    target.mkdir()
    env = {key: value for key, value in os.environ.items() if not key.startswith("KALKAN_")}
    argv = [str(python), "-I", "-c", _RUNNER, str(site)]
    proc = subprocess.run(
        [*argv, "unattended", str(target), "--dry-run", "--json"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=env,
        cwd=tmp_path,
        timeout=300,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert data["install"] == "plugin"
    assert Path(data["cwd"]) == runs.resolve()
    # The runner creates the run itself (init_argv) and binds every round to its run ID; a dry
    # run creates nothing, so the rounds name the placeholder.
    init = data["init_argv"]
    assert init[-6:] == [
        "run",
        "init",
        target.resolve().as_posix(),
        "--profile",
        "standard",
        "--json",
    ]
    assert data["run_id"] is None
    assert [item["argv"][2] for item in data["rounds"]] == [
        "/kalkan:kalkan devam RUN_ID --headless"
    ] * len(data["rounds"])
    assert not runs.exists()  # a dry run writes nothing
