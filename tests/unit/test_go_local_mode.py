# SPDX-License-Identifier: MIT
"""Go in local mode (docs/SECURITY.md, promise 3): vendor folders, packages that load with
errors (``partial_packages``) for gosec and govulncheck, and their scan gap in the report.
No process starts: a fake runner plays the tools."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kalkan.report.model import build_model
from kalkan.report.render_html import render_html
from kalkan.report.render_md import render_markdown
from kalkan.report.summary import build_summary
from kalkan.sca import vulndb
from kalkan.scanners.adapters import _common
from kalkan.scanners.adapters.gosec import GosecAdapter
from kalkan.scanners.adapters.govulncheck import GovulncheckAdapter
from kalkan.scanners.base import ProcessOutcome, ScanContext, run_adapter
from kalkan.tools.golang import GoToolchain
from kalkan.tools.resolve import ResolvedTool

TOOL = Path("/opt/tool")
FAKE_GO = GoToolchain(
    Path("/repo/.tools/go/1.26.9/go/bin/go"), "1.26.9", "kalkan", Path("/repo/.tools/go/1.26.9/go")
)
IMPORT_ERROR = 'could not import example.com/dep (invalid package name: "")'


@pytest.fixture(autouse=True)
def with_go(monkeypatch):
    monkeypatch.setattr(_common, "executable_finder", lambda name: None)
    monkeypatch.setattr(_common, "go_resolver", lambda allow_path=False: FAKE_GO)
    monkeypatch.delenv("GOFLAGS", raising=False)


def make_ctx(tmp_path: Path, *, offline: bool = True) -> ScanContext:
    run = (tmp_path / "run").resolve()
    target = run / "target"
    target.mkdir(parents=True, exist_ok=True)
    return ScanContext(
        run_dir=run, target_dir=target, source_dir=None, tech=frozenset({"go"}), offline=offline
    )


def touch(path: Path, text: str = "x\n") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def resolver(name, *, allow_path=False):
    return ResolvedTool(name, Path("/opt") / name, "9.9.9", "kalkan")


def gosec_report(errors: dict, files: int = 2) -> dict:
    return {
        "Golang errors": errors,
        "Issues": [
            {
                "severity": "MEDIUM",
                "confidence": "HIGH",
                "cwe": {"id": "78"},
                "rule_id": "G204",
                "details": "Subprocess launched with variable",
                "file": "util/util.go",
                "code": "6: return exec.Command(arg).Run()\n",
                "line": "6",
                "column": "9",
                "nosec": False,
            }
        ],
        "Stats": {"files": files, "lines": 21, "nosec": 0, "found": 1},
        "GosecVersion": "2.29.0",
    }


def gosec_runner(errors: dict, seen: list | None = None):
    def run(argv, *, cwd, env, timeout, stdout, stderr):
        if seen is not None:
            seen.append((Path(cwd), env.get("GOFLAGS")))
        report = gosec_report(errors)
        Path(argv[argv.index("-out") + 1]).write_text(json.dumps(report), encoding="utf-8")
        return ProcessOutcome(0)

    return run


def status_of(ctx: ScanContext, group: str, engine: str) -> dict:
    path = ctx.run_dir / group / f"{engine}.status.json"
    return json.loads(path.read_text(encoding="utf-8"))


# --- helpers -----------------------------------------------------------------------------------


def test_go_module_env_uses_the_vendor_folder(tmp_path, monkeypatch):
    module = touch(tmp_path / "mod" / "go.mod", "module x\n").parent
    assert _common.go_vendored(module) is False
    assert _common.go_module_env(module) == ()
    touch(module / "vendor" / "modules.txt", "# example.com/dep v1.0.0\n")
    assert _common.go_vendored(module) is True
    assert _common.go_module_env(module) == (("GOFLAGS", "-mod=vendor"),)
    monkeypatch.setenv("GOFLAGS", "-tags=prod -mod=mod")
    assert _common.go_module_env(module) == (("GOFLAGS", "-tags=prod -mod=vendor"),)


def test_go_partial_packages_groups_errors_by_package():
    errors = [
        ("svc/main.go", f"svc/main.go:6:2: {IMPORT_ERROR}"),
        (
            "svc/main.go",
            "svc/main.go:6:2: missing go.sum entry for module providing package "
            "example.com/dep (imported by x)",
        ),
        ("svc/util/u.go", "svc/util/u.go:3:1: expected declaration, found x"),
    ]
    found = _common.go_partial_packages(errors, offline=True, hint="the hint")
    assert (found["count"], found["truncated"], found["mode"]) == (2, False, "local")
    assert found["hint"] == "the hint"
    svc, util = found["packages"]
    assert (svc["package"], svc["files"]) == ("svc", ["svc/main.go"])
    assert svc["missing_imports"] == ["example.com/dep"] and len(svc["errors"]) == 2
    assert "not in the local module cache or a vendor folder" in svc["reason"]
    assert "GOPROXY=off" in svc["reason"]
    assert util["missing_imports"] == [] and "syntax or type errors" in util["reason"]
    online = _common.go_partial_packages(errors[:1], offline=False, hint="")
    assert online["mode"] == "online"
    assert online["packages"][0]["reason"] == "the module of example.com/dep could not be loaded"
    assert _common.go_partial_packages([], offline=True, hint="") == {}
    many = [(f"p{i}/a.go", f"p{i}/a.go:1:1: could not import m{i}") for i in range(60)]
    capped = _common.go_partial_packages(many, offline=True, hint="")
    assert (capped["count"], len(capped["packages"]), capped["truncated"]) == (60, 50, True)


def test_go_relative_paths(tmp_path):
    target = tmp_path / "target"
    module = target / "svc"
    module.mkdir(parents=True)
    assert _common.go_relative(str(module / "main.go"), target, module) == "svc/main.go"
    assert _common.go_relative("util/u.go", target, module) == "svc/util/u.go"
    outside = str(tmp_path / "elsewhere" / "x.go")
    assert _common.go_relative(outside, target, module) == outside.replace("\\", "/")


# --- gosec -------------------------------------------------------------------------------------


def test_gosec_records_the_packages_that_load_with_errors(tmp_path):
    ctx = make_ctx(tmp_path)
    touch(ctx.target_dir / "go.mod", "module example.com/app\n")
    errors = {str(ctx.target_dir / "main.go"): [{"line": 6, "column": 2, "error": IMPORT_ERROR}]}
    res = run_adapter(GosecAdapter(), ctx, runner=gosec_runner(errors), resolver=resolver)
    assert res.status == "ok", res.message
    assert res.candidates == 1
    partial = status_of(ctx, "scans", "gosec")["partial_packages"]
    assert (partial["count"], partial["mode"]) == (1, "local")
    [package] = partial["packages"]
    assert (package["package"], package["files"]) == (".", ["main.go"])
    assert package["missing_imports"] == ["example.com/dep"]
    assert package["errors"] == [f"main.go:6:2: {IMPORT_ERROR}"]
    assert "kalkan scan gosec --online" in partial["hint"] and "vendor/" in partial["hint"]


def test_gosec_runs_a_vendored_module_with_mod_vendor(tmp_path):
    ctx = make_ctx(tmp_path)
    touch(ctx.target_dir / "go.mod", "module x\n")
    touch(ctx.target_dir / "vendor" / "modules.txt", "# example.com/dep v1.0.0\n")
    touch(ctx.target_dir / "plain" / "go.mod", "module y\n")
    out = ctx.run_dir / "scans" / "gosec.sarif"
    for adapter in (GosecAdapter(), GovulncheckAdapter()):
        vendored, plain = adapter.invocations(ctx, TOOL, out)
        assert vendored.env == (("GOFLAGS", "-mod=vendor"),)
        assert plain.env == ()
    seen: list = []
    res = run_adapter(GosecAdapter(), ctx, runner=gosec_runner({}, seen), resolver=resolver)
    assert res.status == "ok", res.message
    assert seen == [(ctx.target_dir, "-mod=vendor"), (ctx.target_dir / "plain", None)]
    status = status_of(ctx, "scans", "gosec")
    assert status["vendored_modules"] == ["."]
    assert status["invocation_env"] == {".": {"GOFLAGS": "-mod=vendor"}}
    assert "partial_packages" not in status


# --- govulncheck -------------------------------------------------------------------------------


def local_go_db(root: Path) -> None:
    touch(root / "go" / "index" / "db.json", '{"modified": "2026-10-08T22:31:09Z"}')
    touch(root / "go" / "index" / "modules.json", "[]")
    touch(
        root / "go" / "kalkan-source.json",
        '{"source": "official", "modified": "2026-10-08T22:31:09Z"}',
    )


def test_govulncheck_records_load_errors_in_local_mode(tmp_path, monkeypatch):
    root = tmp_path / "vulndb"
    monkeypatch.setattr(vulndb, "db_root", lambda home=None: root)
    local_go_db(root)
    ctx = make_ctx(tmp_path)
    touch(ctx.target_dir / "app" / "go.mod", "module example.com/app\n")
    absolute = ctx.target_dir / "app" / "main.go"
    lines = [
        "govulncheck: loading packages: ",
        "There are errors with the provided package patterns:",
        "",
        "main.go:6:2: missing go.sum entry for module providing package example.com/dep "
        "(imported by example.com/app); to add:",
        "\tgo get example.com/app",
        f"{absolute}:6:2: {IMPORT_ERROR}",
        "",
        "For details on package patterns, see https://pkg.go.dev/cmd/go.",
    ]

    def runner(argv, *, cwd, env, timeout, stdout, stderr):
        assert argv[argv.index("-db") + 1] == (root / "go").resolve().as_uri()
        assert (env["GOPROXY"], env["GOSUMDB"]) == ("off", "off")
        stderr.write(("\n".join(lines) + "\n").encode())
        return ProcessOutcome(1)

    res = run_adapter(GovulncheckAdapter(), ctx, runner=runner, resolver=resolver)
    assert res.status == "failed"
    status = status_of(ctx, "sca", "govulncheck")
    assert status["database"]["source"] == "official"
    assert status["database"]["modified"] == "2026-10-08T22:31:09Z"
    assert status["database"]["url"].startswith("file:///")
    partial = status["partial_packages"]
    [package] = partial["packages"]
    assert (package["package"], package["files"]) == ("app", ["app/main.go"])
    assert package["missing_imports"] == ["example.com/dep"]
    assert "kalkan sca reach --online" in partial["hint"]


# --- report ------------------------------------------------------------------------------------


@pytest.mark.parametrize("lang", ["tr", "en"])
def test_the_report_lists_partial_packages_as_a_scan_gap(tmp_path, lang):
    run = tmp_path / "run"
    (run / "target").mkdir(parents=True)
    status = {
        "engine": "gosec",
        "status": "ok",
        "message": "1 candidate",
        "partial_packages": {
            "count": 1,
            "packages": [
                {
                    "package": "svc",
                    "files": ["svc/main.go"],
                    "missing_imports": ["example.com/dep"],
                    "errors": [f"svc/main.go:6:2: {IMPORT_ERROR}"],
                    "reason": "the module of example.com/dep is not in the local module cache",
                }
            ],
            "truncated": False,
            "mode": "local",
            "hint": "kalkan scan gosec --online ...",
        },
    }
    touch(run / "scans" / "gosec.status.json", json.dumps(status))
    model = build_model(run)
    [gap] = model.scan_gaps
    assert (gap.engine, gap.package_count, gap.packages_local) == ("gosec", 1, True)
    assert gap.packages[0].missing_imports == ("example.com/dep",)
    markdown = render_markdown(model, lang)
    assert "kalkan scan gosec --online" in markdown and "`vendor/`" in markdown
    assert "example.com/dep" in markdown and "`svc`" in markdown
    page = render_html(model, lang)
    assert "<code>kalkan scan gosec --online</code>" in page
    assert "example.com/dep" in page
    summary = build_summary(model, lang=lang)
    assert summary["coverage_gaps"]["engines"]["gosec"]["partial_packages"] == 1
