# SPDX-License-Identifier: MIT
"""Tests for the gixy adapter (kalkan.scanners.adapters.gixy): nginx file discovery, the
launcher and the fallback command, the check mapping, and the SARIF conversion of recorded gixy
0.2.55 outputs (the launcher records and the grouped report of the gixy command)."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from kalkan.sarif.ingest import ingest_document
from kalkan.scanners.adapters.gixy import (
    LAUNCHER,
    LOW_IMPACT,
    PLUGINS,
    GixyAdapter,
    is_nginx_config,
    issues_to_sarif,
    nginx_configs,
)
from kalkan.scanners.base import ProcessOutcome, ScanContext, run_adapter
from kalkan.tools.resolve import ResolvedTool

OUTPUTS = Path(__file__).resolve().parents[1] / "fixtures" / "scanner-outputs"
FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "vulnapp"
SERVER = "server {\n    location /a {\n        alias /data/;\n    }\n}\n"


def make_ctx(tmp_path: Path) -> ScanContext:
    run = (tmp_path / "run").resolve()
    target = run / "target"
    target.mkdir(parents=True, exist_ok=True)
    return ScanContext(run_dir=run, target_dir=target, source_dir=None, tech=frozenset())


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")
    return path


@pytest.mark.parametrize(
    ("rel", "text", "expected"),
    [
        ("nginx.conf", "# empty\n", True),
        ("deploy/site.conf", SERVER, True),
        ("deploy/site.conf.template", SERVER, True),
        ("etc/sites-available/default", SERVER, True),
        ("etc/conf.d/upstreams", "upstream api {\n  server 10.0.0.1;\n}\n", True),
        ("deploy/apache.conf", "<VirtualHost *:80>\n</VirtualHost>\n", False),
        ("deploy/supervisord.conf", "[program:web]\ncommand=x\n", False),
        ("deploy/site.txt", SERVER, False),
        ("etc/sites-available/default", "just text\n", False),
    ],
)
def test_is_nginx_config(tmp_path, rel, text, expected):
    write(tmp_path / rel, text)
    assert is_nginx_config(tmp_path, rel) is expected


def test_nginx_configs_skip_vendored_folders(tmp_path):
    write(tmp_path / "ops" / "nginx.conf", SERVER)
    write(tmp_path / "vendor" / "x" / "nginx.conf", SERVER)
    assert nginx_configs(tmp_path) == ["ops/nginx.conf"]


def test_launcher_turns_off_includes_and_the_machine_policy():
    compile(LAUNCHER, "<gixy launcher>", "exec")
    assert "options = {'allow_includes': False, 'vars_dirs': None}" in LAUNCHER
    # gixy 0.2.58 reads the variable folders of the machine unless load_default_vars is False;
    # the pinned 0.2.55 has neither these folders nor the option.
    assert "if 'load_default_vars' in inspect.signature(Config).parameters:" in LAUNCHER
    assert "options['load_default_vars'] = False" in LAUNCHER
    for word in ("fix", "write_config", "GIXY_", "-c"):
        assert f"'{word}'" not in LAUNCHER


def _tool_with_python(tmp_path: Path) -> Path:
    scripts = tmp_path / "pyenv" / ("Scripts" if os.name == "nt" else "bin")
    write(scripts / ("python.exe" if os.name == "nt" else "python"), "")
    return write(scripts / "gixy", "")


def test_invocations_use_the_launcher_next_to_the_entry_point(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx.target_dir / "nginx.conf", SERVER)
    tool = _tool_with_python(tmp_path)
    out = ctx.run_dir / "scans" / ".work" / "gixy" / "gixy.sarif"
    adapter = GixyAdapter()
    [item] = adapter.invocations(ctx, tool, out)
    python = tool.parent / ("python.exe" if os.name == "nt" else "python")
    assert list(item.argv) == [
        str(python),
        "-I",
        "-X",
        "utf8",
        "-c",
        LAUNCHER,
        str(out.with_suffix(".json")),
        str(ctx.target_dir / "nginx.conf"),
    ]
    assert adapter.env(ctx)["PYTHONUTF8"] == "1"
    details = adapter.status_details(ctx, Path("o"), Path("e"), [])
    assert details["mode"].startswith("python API") and details["includes"] == "not followed"


def test_without_the_tool_venv_the_gixy_command_runs_without_includes(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx.target_dir / "nginx.conf", SERVER)
    out = ctx.run_dir / "scans" / ".work" / "gixy" / "gixy.sarif"
    adapter = GixyAdapter()
    tool = write(tmp_path / "path-bin" / "gixy", "")  # a gixy from PATH: no Python next to it
    [item] = adapter.invocations(ctx, tool, out)
    assert list(item.argv) == [
        str(tool),
        "-f",
        "json",
        "-o",
        str(out.with_suffix(".json")),
        "--disable-includes",
        str(ctx.target_dir / "nginx.conf"),
    ]
    assert adapter.status_details(ctx, Path("o"), Path("e"), [])["mode"].startswith("gixy command")


def test_mapping_covers_the_ssrf_traversal_and_misconfig_checks():
    assert PLUGINS["ssrf"] == ("ssrf", ("CWE-918",))
    assert PLUGINS["alias_traversal"] == ("path-traversal", ("CWE-22",))
    assert PLUGINS["host_spoofing"][0] == "security-misconfig"
    assert PLUGINS["add_header_redefinition"] == ("security-misconfig", ("CWE-693",))
    assert "version_disclosure" in LOW_IMPACT and "ssrf" not in LOW_IMPACT


def copy_shop_conf(ctx: ScanContext) -> None:
    rel = "infra/nginx/shop.conf"
    write(ctx.target_dir / rel, (FIXTURE / rel).read_text(encoding="utf-8"))


def recorded(name: str, ctx: ScanContext):
    text = (OUTPUTS / name).read_text(encoding="utf-8")
    return json.loads(text.replace("@TARGET@", ctx.target_dir.as_posix()))


def test_launcher_records_become_one_result_per_issue(tmp_path):
    ctx = make_ctx(tmp_path)
    copy_shop_conf(ctx)
    data = recorded("gixy-launcher.json", ctx)
    doc = issues_to_sarif(data["issues"], target=ctx.target_dir, version=data["gixy_version"])
    results = doc["runs"][0]["results"]
    assert [(r["ruleId"], r["level"]) for r in results] == [
        ("alias_traversal", "error"),
        ("ssrf", "error"),
    ]
    alias = results[0]
    place = alias["locations"][0]["physicalLocation"]
    assert place["artifactLocation"]["uri"] == "infra/nginx/shop.conf"
    assert place["region"] == {
        "startLine": 9,
        "endLine": 9,
        "snippet": {"text": "        alias /srv/vulnapp/static/;"},
    }
    related = alias["relatedLocations"][0]["physicalLocation"]["region"]["startLine"]
    assert related == 8  # the location block
    assert "$arg_host" in results[1]["message"]["text"]
    candidates = ingest_document(doc, "gixy", ctx.target_dir, "scans/g.sarif").candidates
    assert [(c["class"], c["cwe"], c["start_line"]) for c in candidates] == [
        ("path-traversal", ["CWE-22"], 9),
        ("ssrf", ["CWE-918"], 17),
    ]


def test_grouped_command_report_is_converted_too(tmp_path):
    ctx = make_ctx(tmp_path)
    copy_shop_conf(ctx)
    doc = issues_to_sarif(recorded("gixy-command.json", ctx), target=ctx.target_dir)
    places = [
        (r["ruleId"], r["locations"][0]["physicalLocation"]["region"]["startLine"])
        for r in doc["runs"][0]["results"]
    ]
    assert places == [("alias_traversal", 9), ("ssrf", 17)]


def test_low_impact_and_unknown_checks(tmp_path):
    ctx = make_ctx(tmp_path)
    conf = write(ctx.target_dir / "nginx.conf", SERVER).as_posix()
    issues = [
        {"plugin": "version_disclosure", "severity": "HIGH", "path": conf,
         "places": [{"file": conf, "line": 1}]},
        {"plugin": "brand_new_check", "severity": "MEDIUM", "path": conf,
         "places": [{"file": conf, "line": 3}]},
        {"plugin": "ssrf", "severity": "HIGH", "path": conf, "places": [{"file": conf}]},
    ]  # fmt: skip
    doc = issues_to_sarif(issues, target=ctx.target_dir)
    results = doc["runs"][0]["results"]
    assert [(r["ruleId"], r["level"]) for r in results] == [
        ("version_disclosure", "note"),
        ("brand_new_check", "warning"),
    ]  # the ssrf issue without a line has no location and is left out
    candidates = ingest_document(doc, "gixy", ctx.target_dir, "scans/g.sarif").candidates
    assert [c["class"] for c in candidates] == ["sensitive-data-exposure", "security-misconfig"]


def test_a_dump_file_location_falls_back_to_the_scanned_file(tmp_path):
    ctx = make_ctx(tmp_path)
    conf = write(ctx.target_dir / "dump.conf", SERVER).as_posix()
    issue = {"plugin": "alias_traversal", "severity": "HIGH", "path": conf,
             "places": [{"file": "/etc/nginx/conf.d/a.conf", "line": 3}]}  # fmt: skip
    doc = issues_to_sarif([issue], target=ctx.target_dir)
    uri = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
    assert uri == {"uri": "dump.conf"}


def test_run_adapter_records_parse_errors(tmp_path):
    ctx = make_ctx(tmp_path)
    copy_shop_conf(ctx)
    broken = write(ctx.target_dir / "conf.d" / "broken.conf", "server {\n")
    data = recorded("gixy-launcher.json", ctx)
    data["errors"] = [{"path": str(broken), "error": "InvalidConfiguration: char 9"}]
    tool = _tool_with_python(tmp_path)

    def runner(argv, *, cwd, env, timeout, stdout, stderr):
        Path(argv[6]).write_text(json.dumps(data), encoding="utf-8")
        return ProcessOutcome(0)

    def resolver(name, *, allow_path=False):
        return ResolvedTool(name, tool, "0.2.55", "kalkan")

    result = run_adapter(GixyAdapter(), ctx, runner=runner, resolver=resolver)
    assert result.status == "ok", result.message
    assert result.candidates == 2
    status = json.loads((ctx.run_dir / "scans" / "gixy.status.json").read_text("utf-8"))
    assert status["parse_errors"]["files"] == [
        {"file": "conf.d/broken.conf", "error": "InvalidConfiguration: char 9"}
    ]
    assert status["tool_version"] == "0.2.55"
