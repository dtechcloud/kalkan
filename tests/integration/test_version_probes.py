# SPDX-License-Identifier: MIT
"""``kalkan doctor`` probes every installed tool without a network connection (PROGRESS K.1;
docs/SECURITY.md, promise 3).

The doctor starts the version command of every manifest tool. Before K.1 these probes ran with
the whole environment of the user, and two of them phoned home: ``checkov --version`` asked
PyPI for the newest release and ``govulncheck -version`` read its database date from
vuln.go.dev (measured on 2026-10-25). Now each probe gets the minimal tool environment, the
offline settings of the manifest (``version_args``, ``version_env``) and an empty working folder.

The test runs the doctor in a child process with every proxy variable pointing at the trap of
``conftest.py``: zero connections, and every installed tool reports its pinned version. The
Docker, Node.js and Claude Code checks are left out (``run_doctor(skip=...)``): they start
programs of the user, not kalkan tools. The control step runs the govulncheck version command
with its default database and sees the trap.

Run with ``pytest -m tools tests/integration/test_version_probes.py``.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

from kalkan.tools.manifest import load_manifest
from kalkan.tools.resolve import probe_env, probe_folders, resolve

pytestmark = pytest.mark.tools

#: The doctor of ``kalkan doctor --json`` without the checks of user programs.
DOCTOR = (
    "import json\n"
    "from kalkan.tools.doctor import run_doctor\n"
    "report = run_doctor(skip=('docker', 'node', 'claude'))\n"
    "print(json.dumps(report.to_dict()))\n"
)


def _installed() -> list[str]:
    manifest = load_manifest()
    return [tool.name for tool in manifest if resolve(tool.name, manifest=manifest) is not None]


def test_doctor_probes_every_installed_tool_without_a_connection(tmp_path, trap_proxy):
    installed = _installed()
    if not installed:
        pytest.skip("no manifest tool is installed (run: kalkan tools install --all)")
    proxy = trap_proxy()
    env = {
        **os.environ,
        **proxy.env(),
        "KALKAN_RUNS_DIR": str(tmp_path / "runs"),
        # A token of the user must never reach a version command (minimal environment).
        "GITHUB_TOKEN": "ghp_" + "4" * 36,
    }
    try:
        done = subprocess.run(
            [sys.executable, "-c", DOCTOR],
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=1800,
            check=False,
        )
    finally:
        proxy.close()
    assert proxy.connections == [], proxy.connections
    assert done.returncode == 0, done.stderr
    report = json.loads(done.stdout)
    rows = {check["name"]: check for check in report["checks"]}
    manifest = load_manifest()
    for name in installed:
        row = rows[f"tool:{name}"]
        assert row["status"] == "ok", (name, row["detail"])
        if row["data"].get("installed") and manifest.get(name).kind != "toolchain":
            # The version command ran and named the pinned version.
            assert row["data"]["reported_version"] is not None, name


def test_the_trap_sees_a_version_command_with_its_network_feature_on(tmp_path, trap_proxy):
    """Control: ``govulncheck -version`` with its default database (vuln.go.dev). It runs in
    a folder of the test with the probe folders of kalkan (temporary and Go configuration
    folder, telemetry off), so it writes nothing into the profile or the checkout."""
    tool = resolve("govulncheck")
    if tool is None:
        pytest.skip("govulncheck is not installed (run: kalkan tools install govulncheck)")
    control = trap_proxy()
    manifest_tool = load_manifest().get("govulncheck")
    env = {**probe_env(manifest_tool), **probe_folders(manifest_tool, tmp_path), **control.env()}
    try:
        subprocess.run(
            [*tool.argv, "-version"],
            env=env,
            cwd=tmp_path,
            capture_output=True,
            timeout=300,
            check=False,
            stdin=subprocess.DEVNULL,
        )
    finally:
        control.close()
    assert any(b"vuln.go.dev" in item for item in control.connections), control.connections
