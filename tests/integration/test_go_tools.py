# SPDX-License-Identifier: MIT
"""gosec and govulncheck with the Go toolchain of kalkan, in local mode (ENGINE-SPEC 12, 13, 17;
docs/SECURITY.md, promise 3).

The tests run the installed tools: gosec 2.29.0 and govulncheck 1.8.0 with the Go of
:func:`kalkan.tools.golang.resolve_go` (``kalkan tools install go``). They skip when a tool or
Go is missing; the govulncheck tests also skip without the local Go vulnerability database
(``kalkan sca update-db``). No test uses the network:

- gosec on the vulnapp fixture: its Go code imports only the standard library.
- govulncheck on the vulnapp fixture in local mode (``-db file:///...``, ``GOPROXY=off``) with
  every proxy variable pointing at the trap of ``conftest.py``: zero connections, and the
  ``golang.org/x/text`` record becomes ``not_reachable`` as in the online run. A control step
  runs the opt-in online mode against a second trap and sees connections.
- A module that imports a module outside the module cache (made in ``tmp_path``): gosec records
  ``partial_packages``, govulncheck fails with ``partial_packages``. The same module with a
  ``vendor`` folder loads completely (``GOFLAGS=-mod=vendor``).

Run with ``pytest -m tools tests/integration/test_go_tools.py``.
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest

from kalkan.report.model import build_model
from kalkan.report.render_md import render_markdown
from kalkan.run import tech
from kalkan.sca import vulndb
from kalkan.sca.commands import run_reach
from kalkan.sca.merge import read_vulns, write_vulns
from kalkan.sca.normalize import new_record
from kalkan.scanners.adapters import _common
from kalkan.scanners.adapters.gosec import GosecAdapter
from kalkan.scanners.adapters.govulncheck import GovulncheckAdapter
from kalkan.scanners.base import load_scan_context, run_adapter
from kalkan.scanners.candidates import load_candidates
from kalkan.tools.golang import resolve_go
from kalkan.tools.resolve import resolve

pytestmark = pytest.mark.tools

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "vulnapp"
EXPECTED = FIXTURE / "EXPECTED.json"
#: Fixture root files that describe the answers; they are not part of the target.
ANSWER_FILES = frozenset({"README.md", "EXPECTED.json", "INJECTION-NOTE.md"})
#: Build output that an IDE can leave in the C# folder (csharp/bin, csharp/obj); not fixture
#: data. Only there: native/bin holds a fixture item (the committed binary).
BUILD_FOLDERS = frozenset({"obj", "bin"})
LINE_SLACK = 2
#: A module that imports example.com/dep, which no module cache holds.
APP_GO_MOD = "module example.com/app\n\ngo 1.22\n\nrequire example.com/dep v1.0.0\n"
APP_MAIN = """package main

import (
\t"os/exec"

\t"example.com/dep"
)

func main() {
\tcmd := exec.Command("sh", "-c", dep.Arg())
\t_ = cmd.Run()
}
"""
APP_UTIL = """package util

import "os/exec"

// Run starts a shell command.
func Run(arg string) error {
\treturn exec.Command("sh", "-c", arg).Run()
}
"""
DEP_SOURCE = 'package dep\n\n// Arg returns a value.\nfunc Arg() string { return "ls" }\n'
MODULES_TXT = "# example.com/dep v1.0.0\n## explicit; go 1.22\nexample.com/dep\n"


def _ignore(folder: str, names: list[str]) -> set[str]:
    in_csharp = Path(folder).name == "csharp"
    skipped = {name for name in names if in_csharp and name in BUILD_FOLDERS}
    if Path(folder).resolve() == FIXTURE:
        skipped |= {name for name in names if name in ANSWER_FILES}
    return skipped


def _require(*tools: str, go_db: bool = False) -> None:
    go = resolve_go()
    if go is None:
        pytest.skip("the Go toolchain is not installed (run: kalkan tools install go)")
    for name in tools:
        if resolve(name) is None:
            pytest.skip(f"{name} is not installed (run: kalkan tools install {name})")
    if go_db and not vulndb.go_db_ready():
        pytest.skip("no local Go vulnerability database (run: kalkan sca update-db)")


def _make_run(root: Path) -> Path:
    run = root / "run"
    shutil.copytree(FIXTURE, run / "target", ignore=_ignore)
    manifest = {"copy": "target", "source_dir": None, "tech": tech.detect(run / "target")}
    (run / "target-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return run


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def _go_app_run(root: Path, *, vendored: bool) -> Path:
    """Make a run whose target is one module that imports ``example.com/dep``."""
    run = root / ("vendored" if vendored else "partial") / "run"
    target = run / "target"
    _write(target / "go.mod", APP_GO_MOD)
    _write(target / "main.go", APP_MAIN)
    _write(target / "util" / "util.go", APP_UTIL)
    if vendored:
        _write(target / "vendor" / "modules.txt", MODULES_TXT)
        _write(target / "vendor" / "example.com" / "dep" / "dep.go", DEP_SOURCE)
    manifest = {"copy": "target", "source_dir": None, "tech": ["go"]}
    (run / "target-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return run


def _status(run: Path, group: str, engine: str) -> dict:
    return json.loads((run / group / f"{engine}.status.json").read_text(encoding="utf-8"))


def _gosec_items() -> list[dict]:
    entries = json.loads(EXPECTED.read_text(encoding="utf-8"))
    return [e for e in entries if "gosec" in e.get("expected_engines", [])]


def _matches(candidate: dict, entry: dict) -> bool:
    if candidate["engine"] != "gosec" or candidate["file"] != entry["file"]:
        return False
    if candidate["rule_id"] not in entry.get("rules", {}).get("gosec", []):
        return False
    start = candidate["start_line"]
    end = candidate["end_line"] or start
    return start - LINE_SLACK <= entry["line"] <= end + LINE_SLACK


def _x_text_record() -> dict:
    # The Go record that osv-scanner and grype report for go/go.mod (EXPECTED.json:
    # go-dep-x-text-01): golang.org/x/text v0.3.7 is required but not imported.
    return new_record(
        ecosystem="Go",
        package="golang.org/x/text",
        version="0.3.7",
        ids=["GHSA-69ch-w2m2-3vjp", "CVE-2022-32149", "GO-2022-1059"],
        label="high",
        locations=["go/go.mod"],
        engine="osv-scanner",
    )


def test_gosec_runs_with_the_kalkan_go_and_finds_the_expected_items(tmp_path):
    _require("gosec")
    run = _make_run(tmp_path)
    ctx = load_scan_context(run, offline=True)
    go = resolve_go()
    assert go is not None
    env = GosecAdapter().env(ctx)
    assert env["PATH"].split(os.pathsep)[0] == str(go.bin_dir)
    assert env["GOTOOLCHAIN"] == "local"
    assert _common.go_applies(ctx, "gosec") == (True, "")

    result = run_adapter(GosecAdapter(), ctx)
    assert result.status == "ok", result.message
    assert result.tool_version == "2.29.0"
    candidates = load_candidates(run)["candidates"]
    items = _gosec_items()
    assert len(items) == 8
    missing = [e["id"] for e in items if not any(_matches(c, e) for c in candidates)]
    assert missing == []
    status = _status(run, "scans", "gosec")
    assert status["status"] == "ok" and status["candidates"] == result.candidates
    assert "partial_packages" not in status  # only the standard library: complete


def test_govulncheck_local_mode_makes_no_connection_and_marks_x_text(
    tmp_path, monkeypatch, trap_proxy
):
    _require("govulncheck", go_db=True)
    run = _make_run(tmp_path)
    write_vulns(run, [_x_text_record()], [])
    proxy = trap_proxy()
    for name, value in proxy.env().items():
        monkeypatch.setenv(name, value)
    summary = run_reach(run)  # the default local mode
    assert proxy.connections == [], proxy.connections
    govulncheck = summary["govulncheck"]
    assert govulncheck["status"] == "ok", govulncheck["message"]
    assert govulncheck["module_dir"] == "go"
    assert govulncheck["counts"]["not_reachable"] == 1
    (checked,) = read_vulns(run)["records"]
    assert checked["reachability"] == "not_reachable"
    assert checked["reachability_source"] == "govulncheck"
    assert (checked["severity"], checked["severity_original"]) == ("medium", "high")
    assert "golang.org/x/text" in checked["reachability_reason"]
    assert checked["reach_searched"] and "go/go.mod" in checked["reach_searched"][0]
    assert not (read_vulns(run).get("database_gaps") or [])
    stream = (run / "sca" / "govulncheck.json").read_text(encoding="utf-8")
    assert '"scanner_version": "v1.8.0"' in stream
    go = resolve_go()
    assert go is not None and f'"go_version": "go{go.version}"' in stream
    uri = vulndb.go_db_uri()
    assert f'"db": "{uri}"' in stream and uri.startswith("file:///")
    status = _status(run, "sca", "govulncheck")
    assert status["command"][1:3] == ["-db", uri]
    assert status["database"]["source"] in ("official", "osv")
    assert status["database"]["modified"]

    # Control: the trap sees a tool that does use the network (the opt-in online mode).
    control = trap_proxy()
    for name, value in control.env().items():
        monkeypatch.setenv(name, value)
    run_reach(run, offline=False)
    assert control.connections, "the trap proxy did not see the online govulncheck run"


def test_gosec_records_the_packages_whose_modules_are_missing(tmp_path):
    _require("gosec")
    run = _go_app_run(tmp_path, vendored=False)
    result = run_adapter(GosecAdapter(), load_scan_context(run, offline=True))
    assert result.status == "ok", result.message
    status = _status(run, "scans", "gosec")
    partial = status["partial_packages"]
    assert (partial["count"], partial["mode"]) == (1, "local")
    [package] = partial["packages"]
    assert (package["package"], package["files"]) == (".", ["main.go"])
    assert package["missing_imports"] == ["example.com/dep"]
    assert "GOPROXY=off" in package["reason"]
    assert "kalkan scan gosec --online" in partial["hint"]
    assert "vendored_modules" not in status
    rules = {(c["file"], c["rule_id"]) for c in load_candidates(run)["candidates"]}
    assert ("util/util.go", "G204") in rules  # the package without errors is complete
    report = render_markdown(build_model(run), "en")
    assert "Go packages loaded with errors: 1" in report
    assert "kalkan scan gosec --online" in report and "example.com/dep" in report


def test_gosec_and_govulncheck_load_a_vendored_module_completely(tmp_path):
    _require("gosec", "govulncheck", go_db=True)
    run = _go_app_run(tmp_path, vendored=True)
    ctx = load_scan_context(run, offline=True)
    result = run_adapter(GosecAdapter(), ctx)
    assert result.status == "ok", result.message
    status = _status(run, "scans", "gosec")
    assert "partial_packages" not in status
    assert status["vendored_modules"] == ["."]
    assert status["invocation_env"] == {".": {"GOFLAGS": "-mod=vendor"}}
    rules = {(c["file"], c["rule_id"]) for c in load_candidates(run)["candidates"]}
    assert {("main.go", "G204"), ("util/util.go", "G204")} <= rules
    result = run_adapter(GovulncheckAdapter(), ctx)
    assert result.status == "ok", result.message
    stream = (run / "sca" / "govulncheck.json").read_text(encoding="utf-8")
    assert '"path": "example.com/dep"' in stream  # loaded from vendor/


def test_govulncheck_names_the_packages_whose_modules_are_missing(tmp_path):
    _require("govulncheck", go_db=True)
    run = _go_app_run(tmp_path, vendored=False)
    result = run_adapter(GovulncheckAdapter(), load_scan_context(run, offline=True))
    assert result.status == "failed"
    partial = _status(run, "sca", "govulncheck")["partial_packages"]
    [package] = partial["packages"]
    assert package["package"] == "." and package["missing_imports"] == ["example.com/dep"]
    assert "kalkan sca reach --online" in partial["hint"]
