# SPDX-License-Identifier: MIT
"""With the real tools, nothing appears outside the kalkan folders (docs/SECURITY.md).

The test gives the test process a profile of its own: ``USERPROFILE``, ``HOME``, ``APPDATA``,
``LOCALAPPDATA``, ``TEMP``, ``TMP`` and the ``XDG_*`` folders name empty folders in
``tmp_path``, laid out like a Windows profile, with the Go telemetry folder that a machine gets
once any Go program ran there. Then it runs the opengrep version probe, an opengrep scan, a
gosec scan and a govulncheck scan of a small target through the kalkan code paths. Before the
change these left ``.opengrep/semgrep.log``, ``AppData/Local/opengrep``, ``semgrep-*.rules``,
``AppData/Local/go-build`` and telemetry counters in the profile (measured on 2026-10-29).
Afterwards the profile must hold exactly the folders that the test created.

Each part is skipped when its tool is missing. Run it with ``pytest -m tools
tests/integration/test_tool_footprint.py``; ``KALKAN_HOME`` names the home with ``.tools``.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from kalkan.scanners.adapters.gosec import GosecAdapter
from kalkan.scanners.adapters.govulncheck import GovulncheckAdapter
from kalkan.scanners.adapters.opengrep import OpengrepAdapter
from kalkan.scanners.base import ScanContext, run_adapter
from kalkan.tools.manifest import load_manifest
from kalkan.tools.resolve import probe_tool_version, resolve

pytestmark = pytest.mark.tools

GO_MODULE = {
    "go.mod": "module example.com/footprint\n\ngo 1.22\n",
    "main.go": (
        'package main\n\nimport (\n\t"fmt"\n\t"os/exec"\n)\n\n'
        'func main() {\n\tfmt.Println(exec.Command("sh", "-c", "x").Run())\n}\n'
    ),
}
PYTHON_FILE = "import os\nos.system(input())\n"


def entries(folder: Path) -> set[str]:
    return {path.relative_to(folder).as_posix() for path in folder.rglob("*")}


@pytest.fixture
def profile(tmp_path, monkeypatch) -> Path:
    """An empty profile with the layout of a Windows profile, used by the test process."""
    home = tmp_path / "profile"
    local = home / "AppData" / "Local"
    roaming = home / "AppData" / "Roaming"
    for folder in (local / "Temp", roaming / "go" / "telemetry" / "local", home / ".config"):
        folder.mkdir(parents=True)
    values = {
        "USERPROFILE": home,
        "HOME": home,
        "LOCALAPPDATA": local,
        "APPDATA": roaming,
        "TEMP": local / "Temp",
        "TMP": local / "Temp",
        "TMPDIR": local / "Temp",
        "XDG_CACHE_HOME": home / ".cache",
        "XDG_CONFIG_HOME": home / ".config",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, str(value))
    for name in ("GOCACHE", "GOPATH", "GOMODCACHE", "GOENV", "GOFLAGS"):
        monkeypatch.delenv(name, raising=False)
    return home


def target(tmp_path: Path) -> ScanContext:
    run = (tmp_path / "run").resolve()
    folder = run / "target"
    folder.mkdir(parents=True)
    (folder / "app.py").write_text(PYTHON_FILE, encoding="utf-8")
    for name, text in GO_MODULE.items():
        (folder / name).write_text(text, encoding="utf-8")
    return ScanContext(run, folder, None, frozenset({"python", "go"}))


def test_the_tools_write_nothing_into_the_profile(tmp_path, profile):
    manifest = load_manifest()
    before = entries(profile)
    ctx = target(tmp_path)
    ran: list[str] = []
    opengrep = resolve("opengrep", manifest=manifest)
    if opengrep is not None:
        output = probe_tool_version(opengrep.argv, manifest.get("opengrep"))
        assert output is not None and manifest.get("opengrep").version in output
        result = run_adapter(OpengrepAdapter(), ctx)
        assert result.status == "ok", result.message
        ran.append("opengrep")
    for adapter in (GosecAdapter(), GovulncheckAdapter()):
        if not adapter.applies(ctx)[0] or resolve(adapter.tool, manifest=manifest) is None:
            continue
        result = run_adapter(adapter, ctx)
        assert result.status == "ok", (adapter.name, result.message)
        ran.append(adapter.name)
    if not ran:
        pytest.skip("opengrep, gosec and govulncheck are not installed")
    assert entries(profile) == before, sorted(entries(profile) - before)
    # Nothing of the tool runs stays in the run either: the work folders are gone.
    for folder in ("scans", "sca"):
        assert not (ctx.run_dir / folder / ".work").exists(), folder
    assert not os.listdir(profile / "AppData" / "Local" / "Temp")
