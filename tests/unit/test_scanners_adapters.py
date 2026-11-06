# SPDX-License-Identifier: MIT
"""Tests for the scanner adapters and the registry: applies, command lines, environment,
working directories and status handling through a fake process runner."""

from __future__ import annotations

import dataclasses
import json
import os
from pathlib import Path

import pytest

from kalkan.sca import vulndb
from kalkan.scanners import registry
from kalkan.scanners.adapters import _common, helm_checkov
from kalkan.scanners.adapters.bandit import BanditAdapter
from kalkan.scanners.adapters.checkov import CheckovAdapter
from kalkan.scanners.adapters.gitleaks import (
    HISTORY_LOG_OPTS,
    GitleaksAdapter,
    GitleaksHistoryAdapter,
)
from kalkan.scanners.adapters.gosec import GosecAdapter
from kalkan.scanners.adapters.govulncheck import GovulncheckAdapter
from kalkan.scanners.adapters.grype import GrypeAdapter
from kalkan.scanners.adapters.hadolint import HadolintAdapter, dockerfiles, is_dockerfile
from kalkan.scanners.adapters.matcher import MatcherAdapter
from kalkan.scanners.adapters.opengrep import OpengrepAdapter
from kalkan.scanners.adapters.osv_scanner import OsvScannerAdapter
from kalkan.scanners.adapters.syft import SyftAdapter
from kalkan.scanners.adapters.trivy import TrivyAdapter
from kalkan.scanners.adapters.trivy_sbom import TrivySbomAdapter
from kalkan.scanners.base import ProcessOutcome, ScanContext, minimal_env, run_adapter
from kalkan.scanners.candidates import load_candidates
from kalkan.tools.golang import GoToolchain
from kalkan.tools.resolve import ResolvedTool

TOOL = Path("/opt/tool")


def make_ctx(tmp_path: Path, tech=(), *, offline=False, source=None, honor=False) -> ScanContext:
    run = (tmp_path / "run").resolve()
    target = run / "target"
    target.mkdir(parents=True, exist_ok=True)
    return ScanContext(
        run_dir=run,
        target_dir=target,
        source_dir=source,
        tech=frozenset(tech),
        offline=offline,
        honor_suppressions=honor,
    )


def touch(path: Path, text: str = "x\n") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


#: The Go toolchain that the ``with_go`` fixture reports (the kalkan copy).
FAKE_GO = GoToolchain(
    Path("/repo/.tools/go/1.26.9/go/bin/go"), "1.26.9", "kalkan", Path("/repo/.tools/go/1.26.9/go")
)


@pytest.fixture
def with_go(monkeypatch):
    found = {"git": Path("/usr/bin/git")}
    monkeypatch.setattr(_common, "executable_finder", lambda name: found.get(name))
    monkeypatch.setattr(_common, "go_resolver", lambda allow_path=False: FAKE_GO)


@pytest.fixture(autouse=True)
def fake_checkov_for_helm(monkeypatch):
    """helm-checkov resolves Checkov itself (its second tool): a fake installed copy."""
    tool = ResolvedTool("checkov", Path("/opt/checkov"), "9.9.9", "kalkan")
    monkeypatch.setattr(helm_checkov, "checkov_resolver", lambda allow_path=False: tool)


@pytest.fixture
def without_go(monkeypatch):
    monkeypatch.setattr(_common, "executable_finder", lambda name: None)
    monkeypatch.setattr(_common, "go_resolver", lambda allow_path=False: None)


# --------------------------------------------------------------------------------------------
# registry


def test_registry_order_and_names():
    assert [a.name for a in registry.SCANNERS] == [
        "trivy",
        "checkov",
        "helm-checkov",
        "hadolint",
        "gitleaks",
        "gitleaks-history",
        "kingfisher",
        "kingfisher-history",
        "opengrep",
        "opengrep-packs",
        "bandit",
        "gosec",
        "zizmor",
        "actionlint",
        "poutine",
        "scorecard",
        "shellcheck",
        "flawfinder",
        "gixy",
        "vacuum",
        "matcher",
    ]
    assert [a.name for a in registry.SCA_TOOLS] == [
        "syft",
        "trivy-sbom",
        "osv-scanner",
        "grype",
        "govulncheck",
    ]
    assert registry.get("grype").name == "grype"
    with pytest.raises(Exception, match="unknown engine"):
        registry.get("nope")


@pytest.mark.parametrize("adapter", [*registry.SCANNERS, *registry.SCA_TOOLS], ids=lambda a: a.name)
def test_adapter_declarations(adapter):
    assert adapter.output in (
        "sarif-file",
        "sarif-stdout",
        "json-file",
        "json-stdout",
        "candidates",
    )
    assert adapter.output_dir == ("sca" if adapter in registry.SCA_TOOLS else "scans")
    assert adapter.timeout_seconds > 0
    assert 0 in adapter.ok_exit_codes
    if adapter.output.startswith("sarif"):
        assert adapter.output_name == f"{adapter.name}.sarif"
    if adapter.tool is None:
        assert adapter.output == "candidates"


def test_sca_output_names():
    names = {a.name: a.output_name for a in registry.SCA_TOOLS}
    assert names == {
        "syft": "sbom.cdx.json",
        "trivy-sbom": "sbom.cdx.json",
        "osv-scanner": "osv.json",
        "grype": "grype.json",
        "govulncheck": "govulncheck.json",
    }


# --------------------------------------------------------------------------------------------
# command lines


def test_trivy_command(tmp_path):
    ctx = make_ctx(tmp_path)
    out = ctx.run_dir / "scans" / "trivy.sarif"
    argv = TrivyAdapter().command(ctx, TOOL, out)
    assert argv == [
        str(TOOL),
        "fs",
        "--scanners",
        "misconfig,secret",
        "--format",
        "sarif",
        "--output",
        str(out),
        "--disable-telemetry",
        "--skip-version-check",
        "--no-progress",
        "--offline-scan",
        "--timeout",
        "3600s",
        "--skip-db-update",
        "--skip-java-db-update",
        "--config",
        "",
        "--ignorefile",
        "",
        "--secret-config",
        "",
        str(ctx.target_dir),
    ]
    offline = TrivyAdapter().command(make_ctx(tmp_path, offline=True), TOOL, out)
    assert offline[-2:] == ["--skip-check-update", str(ctx.target_dir)]
    scanners = offline[offline.index("--misconfig-scanners") + 1].split(",")
    assert "helm" not in scanners and {"kubernetes", "dockerfile", "terraform"} <= set(scanners)
    assert "--misconfig-scanners" not in argv  # --online keeps the default list (with helm)
    assert TrivyAdapter().applies(ctx) == (True, "")


def test_checkov_command_cwd_and_env(tmp_path):
    ctx = make_ctx(tmp_path)
    adapter = CheckovAdapter()
    stage = ctx.run_dir / "scans" / ".work" / "checkov" / "checkov.sarif"
    [item] = adapter.invocations(ctx, TOOL, stage)
    folder = stage.parent / "results"
    assert list(item.argv) == [
        str(TOOL),
        "-d",
        str(ctx.target_dir),
        "-o",
        "sarif",
        "--output-file-path",
        str(folder),
        "--skip-download",
        "--quiet",
        "--compact",
        "--skip-framework",
        "helm,kustomize,sca_package,sca_image",
    ]
    assert item.cwd == ctx.target_dir
    assert item.output == folder / "results_sarif.sarif"
    env = adapter.env(ctx)
    assert env["CKV_SKIP_PACKAGE_UPDATE_CHECK"] == "true"
    assert env["PYTHONUTF8"] == "1"
    # An empty home folder: Checkov reads a platform API key from ~/.bridgecrew/credentials.
    assert env["HOME"] == env["USERPROFILE"] == str(stage.parent / "home")
    adapter.prepare(ctx, stage)
    assert (stage.parent / "home").is_dir() and not any((stage.parent / "home").iterdir())
    assert adapter.ok_exit_codes == (0, 1)


def test_hadolint_discovery_and_command(tmp_path):
    ctx = make_ctx(tmp_path)
    assert HadolintAdapter().applies(ctx) == (False, "no Dockerfile found in the target")
    touch(ctx.target_dir / "Dockerfile")
    touch(ctx.target_dir / "svc" / "Dockerfile.prod")
    touch(ctx.target_dir / "svc" / "worker.dockerfile")
    touch(ctx.target_dir / "Containerfile")
    touch(ctx.target_dir / "node_modules" / "x" / "Dockerfile")
    touch(ctx.target_dir / "docs" / "Dockerfile-notes.md")
    assert dockerfiles(ctx.target_dir) == [
        "Containerfile",
        "Dockerfile",
        "svc/Dockerfile.prod",
        "svc/worker.dockerfile",
    ]
    assert HadolintAdapter().applies(ctx) == (True, "")
    out = ctx.run_dir / "scans" / "hadolint.sarif"
    [item] = HadolintAdapter().invocations(ctx, TOOL, out)
    head = [str(TOOL), "-f", "sarif", "--no-fail", "--no-color", "--disable-ignore-pragma"]
    assert list(item.argv[:6]) == head
    assert item.argv[6:] == tuple(str(ctx.target_dir / rel) for rel in dockerfiles(ctx.target_dir))
    assert item.output == out
    assert item.cwd == ctx.run_dir / "scans"


def test_hadolint_batches(tmp_path, monkeypatch):
    from kalkan.scanners.adapters import hadolint

    monkeypatch.setattr(hadolint, "BATCH_SIZE", 2)
    ctx = make_ctx(tmp_path)
    for name in ("a", "b", "c"):
        touch(ctx.target_dir / name / "Dockerfile")
    out = ctx.run_dir / "scans" / "hadolint.sarif"
    items = HadolintAdapter().invocations(ctx, TOOL, out)
    assert [len(item.argv) - 6 for item in items] == [2, 1]
    assert [item.output.name for item in items] == ["000.sarif", "001.sarif"]


@pytest.mark.parametrize(
    "name,expected",
    [
        ("Dockerfile", True),
        ("dockerfile", True),
        ("Dockerfile.dev", True),
        ("api.Dockerfile", True),
        ("Containerfile", True),
        ("Dockerfile-notes.md", False),
        ("README.md", False),
    ],
)
def test_is_dockerfile(name, expected):
    assert is_dockerfile(name) is expected


def test_gitleaks_command(tmp_path):
    ctx = make_ctx(tmp_path)
    out = ctx.run_dir / "scans" / ".work" / "gitleaks" / "gitleaks.sarif"
    assert GitleaksAdapter().command(ctx, TOOL, out) == [
        str(TOOL),
        "dir",
        str(ctx.target_dir),
        "--report-format",
        "sarif",
        "--report-path",
        str(out),
        "--redact",
        "--no-banner",
        "--exit-code",
        "0",
        "--config",
        str(out.parent / "gitleaks.toml"),
        "--ignore-gitleaks-allow",
    ]
    out.parent.mkdir(parents=True)
    GitleaksAdapter().prepare(ctx, out)
    text = (out.parent / "gitleaks.toml").read_text(encoding="utf-8")
    assert "useDefault = true" in text and "allowlist" not in text


def test_gitleaks_history_applies_and_command(tmp_path, with_go):
    adapter = GitleaksHistoryAdapter()
    assert adapter.applies(make_ctx(tmp_path))[0] is False
    source = (tmp_path / "run" / "source").resolve()
    source.mkdir(parents=True)
    ctx = make_ctx(tmp_path, source=source)
    assert adapter.applies(ctx) == (
        False,
        "the history copy source/ has no git folder (no history to scan)",
    )
    (source / ".git").mkdir()
    assert adapter.applies(ctx) == (True, "")
    out = ctx.run_dir / "scans" / "gitleaks-history.sarif"
    argv = adapter.command(ctx, TOOL, out)
    assert argv[:4] == [str(TOOL), "git", str(source / ".git"), f"--log-opts={HISTORY_LOG_OPTS}"]
    assert "--no-textconv" in HISTORY_LOG_OPTS and "--no-ext-diff" in HISTORY_LOG_OPTS
    assert argv[4:] == [
        "--report-format",
        "sarif",
        "--report-path",
        str(out),
        "--redact",
        "--no-banner",
        "--exit-code",
        "0",
        "--config",
        str(out.parent / "gitleaks.toml"),
        "--ignore-gitleaks-allow",
    ]
    assert adapter.env(ctx)["GIT_TERMINAL_PROMPT"] == "0"
    ignored, honored = adapter.suppression_sources(ctx)
    assert any("reads the .git folder" in item for item in ignored) and honored == []
    honor = make_ctx(tmp_path, source=source, honor=True)
    assert adapter.command(honor, TOOL, out)[2] == str(source)


def test_gitleaks_history_needs_git(tmp_path, without_go):
    source = tmp_path / "run" / "source"
    (source / ".git").mkdir(parents=True)
    ok, reason = GitleaksHistoryAdapter().applies(make_ctx(tmp_path, source=source))
    assert (ok, reason) == (False, "git is not installed (git not on PATH)")


def test_gitleaks_history_reads_only_the_copy_inside_the_run(tmp_path, with_go):
    """Promise 1: the history scan never gets a folder outside the run (the original)."""
    adapter = GitleaksHistoryAdapter()
    outside = tmp_path / "original"
    (outside / ".git").mkdir(parents=True)
    ctx = make_ctx(tmp_path, source=outside)
    assert adapter.applies(ctx) == (
        False,
        "the source folder is outside the run folder (only source/ is scanned)",
    )
    link = tmp_path / "run" / "source"
    link.parent.mkdir(parents=True, exist_ok=True)
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        return  # no symlink privilege on this Windows host
    assert adapter.applies(make_ctx(tmp_path, source=link))[0] is False


def test_gitleaks_history_scans_a_bare_mirror(tmp_path, with_go):
    adapter = GitleaksHistoryAdapter()
    source = (tmp_path / "run" / "source").resolve()
    touch(source / "HEAD", "ref: refs/heads/main\n")
    (source / "objects").mkdir()
    (source / "refs").mkdir()
    ctx = make_ctx(tmp_path, source=source)
    assert adapter.applies(ctx) == (True, "")
    out = ctx.run_dir / "scans" / "gitleaks-history.sarif"
    assert adapter.command(ctx, TOOL, out)[2] == str(source)
    assert adapter.env(ctx)["GIT_NO_LAZY_FETCH"] == "1"
    ignored, honored = adapter.suppression_sources(ctx)
    assert any("bare mirror" in item for item in ignored) and honored == []


def test_gitleaks_history_skip_reason_names_the_manifest_history(tmp_path, with_go):
    ctx = make_ctx(tmp_path)
    touch(
        ctx.run_dir / "target-manifest.json",
        json.dumps({"history": {"status": "failed", "detail": "dubious ownership"}}),
    )
    ok, reason = GitleaksHistoryAdapter().applies(ctx)
    assert ok is False and reason.endswith(": dubious ownership")


def test_opengrep_command_and_rules_dir(tmp_path):
    rules = tmp_path / "rules"
    adapter = OpengrepAdapter(rules_dir=rules)
    ctx = make_ctx(tmp_path)
    assert adapter.applies(ctx)[0] is False
    rules.mkdir()
    assert "no YAML rule files" in adapter.applies(ctx)[1]
    touch(rules / "python.yaml", "rules: []\n")
    assert adapter.applies(ctx) == (True, "")
    out = ctx.run_dir / "scans" / "opengrep.sarif"
    assert adapter.command(ctx, TOOL, out) == [
        str(TOOL),
        "scan",
        "-f",
        str(rules),
        "--sarif",
        "--output",
        str(out),
        "--disable-version-check",
        "--no-rewrite-rule-ids",
        "--no-git-ignore",
        "--x-ignore-semgrepignore-files",
        "--disable-nosem",
        str(ctx.target_dir),
    ]
    assert not any("metrics" in arg for arg in adapter.command(ctx, TOOL, out))
    honor = adapter.command(make_ctx(tmp_path, honor=True), TOOL, out)
    assert "--disable-nosem" not in honor
    assert "--x-ignore-semgrepignore-files" in honor


def test_opengrep_default_rules_dir_is_the_repo_pack():
    assert OpengrepAdapter().rules_dir().parts[-2:] == ("rules", "opengrep")


def test_bandit_applies_and_command(tmp_path):
    adapter = BanditAdapter()
    assert adapter.applies(make_ctx(tmp_path))[0] is False
    ctx = make_ctx(tmp_path, tech={"python"})
    assert adapter.applies(ctx) == (True, "")
    out = ctx.run_dir / "scans" / ".work" / "bandit" / "bandit.sarif"
    assert adapter.command(ctx, TOOL, out) == [
        str(TOOL),
        "-r",
        str(ctx.target_dir),
        "-f",
        "sarif",
        "-o",
        str(out),
        "--exit-zero",
        "-q",
        "--ignore-nosec",
        "--ini",
        str(out.parent / "kalkan.bandit"),
    ]
    assert adapter.env(ctx)["PYTHONIOENCODING"] == "utf-8"
    out.parent.mkdir(parents=True)
    adapter.prepare(ctx, out)
    assert (out.parent / "kalkan.bandit").read_text(encoding="utf-8") == "[bandit]\n"


def test_gosec_applies(tmp_path, with_go):
    adapter = GosecAdapter()
    assert "tech tag 'go' missing" in adapter.applies(make_ctx(tmp_path))[1]
    ctx = make_ctx(tmp_path, tech={"go"})
    assert adapter.applies(ctx) == (False, "no go.mod found in the target")
    touch(ctx.target_dir / "go.mod", "module x\n")
    assert adapter.applies(ctx) == (True, "")


def test_gosec_without_go_is_skipped_with_reason(tmp_path, without_go):
    ctx = make_ctx(tmp_path, tech={"go"})
    touch(ctx.target_dir / "go.mod", "module x\n")
    ok, reason = GosecAdapter().applies(ctx)
    assert ok is False
    assert reason.startswith("Go is not installed")


def test_gosec_invocations_per_module(tmp_path, with_go):
    ctx = make_ctx(tmp_path, tech={"go"})
    touch(ctx.target_dir / "go.mod")
    touch(ctx.target_dir / "svc" / "api" / "go.mod")
    touch(ctx.target_dir / "vendor" / "dep" / "go.mod")
    touch(ctx.target_dir / "svc" / "testdata" / "go.mod")
    assert _common.go_modules(ctx.target_dir) == ["", "svc/api"]
    out = ctx.run_dir / "scans" / "gosec.sarif"
    items = GosecAdapter().invocations(ctx, TOOL, out)
    assert [item.cwd for item in items] == [ctx.target_dir, ctx.target_dir / "svc" / "api"]
    assert [item.base for item in items] == [None, "svc/api"]
    part = out.parent / "gosec.sarif.parts" / "001.sarif"
    report = part.with_suffix(".json")
    expected = [str(TOOL), "-fmt", "json", "-out", str(report), "-no-fail", "-nosec", "./..."]
    assert list(items[1].argv) == expected
    assert items[1].output == part
    honor = GosecAdapter().invocations(make_ctx(tmp_path, tech={"go"}, honor=True), TOOL, out)
    assert "-nosec" not in honor[0].argv


def test_go_env(tmp_path, monkeypatch, with_go):
    monkeypatch.setenv("GOPROXY", "https://proxy.example")
    monkeypatch.setenv("GITHUB_TOKEN", "secret")
    monkeypatch.setenv("GOROOT", "/usr/lib/go-1.19")  # another Go: must not win
    monkeypatch.setenv("PATH", os.pathsep.join(["/usr/bin", "/bin"]))
    env = _common.go_env(make_ctx(tmp_path))
    assert env["GOTOOLCHAIN"] == "local"
    assert env["GOPROXY"] == "https://proxy.example"
    assert "GITHUB_TOKEN" not in env
    # The kalkan Go comes first on PATH (gosec and govulncheck start "go list") and GOROOT
    # names its tree.
    assert env["PATH"].split(os.pathsep)[0] == str(FAKE_GO.bin_dir)
    assert env["PATH"].split(os.pathsep)[1:] == ["/usr/bin", "/bin"]
    assert env["GOROOT"] == str(FAKE_GO.root)
    offline = _common.go_env(make_ctx(tmp_path, offline=True))
    assert offline["GOPROXY"] == "off"
    assert offline["GOSUMDB"] == "off"


def test_go_env_with_a_system_go_keeps_its_goroot(tmp_path, monkeypatch):
    system = GoToolchain(Path("/usr/local/go/bin/go"), "1.26.1", "path")
    monkeypatch.setattr(_common, "go_resolver", lambda allow_path=False: system)
    monkeypatch.setenv("GOROOT", "/usr/local/go")
    env = _common.go_env(make_ctx(tmp_path))
    assert env["PATH"].split(os.pathsep)[0] == str(system.bin_dir)
    assert env["GOROOT"] == "/usr/local/go"


def test_go_env_reaches_the_process_environment(tmp_path, with_go):
    # minimal_env() takes PATH from the process; the adapter PATH must replace it.
    env = minimal_env(GosecAdapter().env(make_ctx(tmp_path)))
    assert env["PATH"].split(os.pathsep)[0] == str(FAKE_GO.bin_dir)
    assert env["GOTOOLCHAIN"] == "local"


def test_go_resolver_honors_allow_path_tools(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(
        _common, "go_resolver", lambda allow_path=False: calls.append(allow_path) or None
    )
    ctx = dataclasses.replace(make_ctx(tmp_path, tech={"go"}), allow_path_tools=True)
    touch(ctx.target_dir / "go.mod")
    assert GosecAdapter().applies(ctx)[0] is False
    assert calls == [True]


def test_syft_command(tmp_path):
    ctx = make_ctx(tmp_path)
    out = ctx.run_dir / "sca" / "sbom.cdx.json"
    assert SyftAdapter().command(ctx, TOOL, out) == [
        str(TOOL),
        "scan",
        f"dir:{ctx.target_dir}",
        "-o",
        f"cyclonedx-json={out}",
    ]
    env = SyftAdapter().env(ctx)
    assert env["SYFT_CHECK_FOR_APP_UPDATE"] == "false"
    assert env["SYFT_JAVA_USE_NETWORK"] == "false"
    assert env["SYFT_GOLANG_SEARCH_REMOTE_LICENSES"] == "false"
    assert env["SYFT_JAVASCRIPT_SEARCH_REMOTE_LICENSES"] == "false"
    assert env["SYFT_PYTHON_SEARCH_REMOTE_LICENSES"] == "false"


def test_trivy_sbom_command(tmp_path):
    ctx = make_ctx(tmp_path)
    out = ctx.run_dir / "sca" / "sbom.cdx.json"
    assert TrivySbomAdapter().command(ctx, TOOL, out) == [
        str(TOOL),
        "fs",
        "--format",
        "cyclonedx",
        "--output",
        str(out),
        "--disable-telemetry",
        "--skip-version-check",
        "--no-progress",
        "--offline-scan",
        "--skip-db-update",
        "--skip-java-db-update",
        str(ctx.target_dir),
    ]
    local = TrivySbomAdapter().command(make_ctx(tmp_path, offline=True), TOOL, out)
    assert local[-2:] == ["--skip-check-update", str(ctx.target_dir)]
    assert TrivySbomAdapter().tool == "trivy"


def test_osv_scanner_command(tmp_path):
    ctx = make_ctx(tmp_path)
    out = ctx.run_dir / "sca" / ".work" / "osv-scanner" / "osv.json"
    argv = OsvScannerAdapter().command(ctx, TOOL, out)
    assert argv == [
        str(TOOL),
        "scan",
        "source",
        "-r",
        "--no-ignore",
        "--allow-no-lockfiles",
        "--format",
        "json",
        "--output-file",
        str(out),
        "--config",
        str(out.parent / "osv-scanner.toml"),
        str(ctx.target_dir),
    ]
    offline = OsvScannerAdapter().command(make_ctx(tmp_path, offline=True), TOOL, out)
    assert offline[-2:] == ["--offline", str(ctx.target_dir)]
    assert OsvScannerAdapter().ok_exit_codes == (0, 1)
    out.parent.mkdir(parents=True)
    OsvScannerAdapter().prepare(ctx, out)
    assert (out.parent / "osv-scanner.toml").read_text(encoding="utf-8") == ""
    honor = make_ctx(tmp_path, honor=True)
    assert "--config" not in OsvScannerAdapter().command(honor, TOOL, out)


def test_osv_scanner_local_mode_needs_a_local_database(tmp_path, monkeypatch):
    root = tmp_path / "vulndb"
    monkeypatch.setattr(vulndb, "db_root", lambda home=None: root)
    adapter = OsvScannerAdapter()
    local = make_ctx(tmp_path, offline=True)
    assert adapter.applies(local) == (False, "no local OSV database (run: kalkan sca update-db)")
    assert adapter.applies(make_ctx(tmp_path)) == (True, "")  # online: api.osv.dev
    touch(root / "osv" / "osv-scalibr" / "npm" / "all.zip", "zip")
    assert adapter.applies(local) == (True, "")
    assert adapter.env(local) == {"OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": str(root / "osv")}
    out = local.run_dir / "sca" / ".work" / "osv-scanner" / "osv.json"
    assert "--offline" in adapter.command(local, TOOL, out)
    lines = [
        "could not load db for PyPI ecosystem: unable to fetch OSV database: no offline "
        "version of the OSV database is available",
        "could not load db for crates.io ecosystem: unable to fetch OSV database",
    ]
    stderr = touch(tmp_path / "err.txt", "".join(line + chr(10) for line in lines))
    details = adapter.status_details(local, tmp_path / "out.txt", stderr, [])
    assert details == {"missing_databases": ["PyPI", "crates.io"]}
    assert adapter.status_details(local, tmp_path / "out.txt", tmp_path / "none.txt", []) == {}


def test_grype_applies_command_and_env(tmp_path, monkeypatch):
    monkeypatch.setattr(vulndb, "db_root", lambda home=None: tmp_path / "vulndb")
    ctx = make_ctx(tmp_path)
    adapter = GrypeAdapter()
    assert adapter.applies(ctx)[0] is False
    sbom = touch(ctx.run_dir / "sca" / "sbom.cdx.json", "{}")
    assert adapter.applies(ctx) == (True, "")
    out = ctx.run_dir / "sca" / "grype.json"
    assert adapter.command(ctx, TOOL, out) == [
        str(TOOL),
        f"sbom:{sbom}",
        "-o",
        "json",
        "--file",
        str(out),
    ]
    online = adapter.env(ctx)
    assert online == {
        "GRYPE_DB_CACHE_DIR": str(tmp_path / "vulndb" / "grype"),
        "GRYPE_CHECK_FOR_APP_UPDATE": "false",
        "GRYPE_EXTERNAL_SOURCES_ENABLE": "false",
    }
    local_ctx = make_ctx(tmp_path, offline=True)
    local = adapter.env(local_ctx)
    assert local["GRYPE_DB_AUTO_UPDATE"] == "false"
    assert local["GRYPE_DB_VALIDATE_AGE"] == "false"
    assert local["GRYPE_DB_REQUIRE_UPDATE_CHECK"] == "false"
    assert local["GRYPE_DB_CACHE_DIR"] == str(tmp_path / "vulndb" / "grype")
    # Local mode without a database: skipped, never a download.
    reason = "no local Grype database (run: kalkan sca update-db)"
    assert adapter.applies(local_ctx) == (False, reason)
    touch(tmp_path / "vulndb" / "grype" / "6" / "vulnerability.db", "db")
    assert adapter.applies(local_ctx) == (True, "")


def test_govulncheck_applies_and_invocations(tmp_path, monkeypatch, with_go):
    root = tmp_path / "vulndb"
    monkeypatch.setattr(vulndb, "db_root", lambda home=None: root)
    adapter = GovulncheckAdapter()
    ctx = make_ctx(tmp_path, tech={"go"})
    touch(ctx.target_dir / "cmd" / "go.mod")
    assert adapter.applies(ctx) == (True, "")  # online: vuln.go.dev
    out = ctx.run_dir / "sca" / "govulncheck.json"
    [item] = adapter.invocations(ctx, TOOL, out)
    assert list(item.argv) == [str(TOOL), "-json", "./..."]
    assert item.cwd == ctx.target_dir / "cmd"
    assert item.base == "cmd"
    assert item.env == ()
    assert adapter.env(ctx)["GOTOOLCHAIN"] == "local"
    # Local mode (the default) needs the local Go database and never names vuln.go.dev.
    local = make_ctx(tmp_path, tech={"go"}, offline=True)
    assert adapter.applies(local) == (False, vulndb.GO_DB_MISSING)
    touch(root / "go" / "index" / "db.json", '{"modified": "2026-10-08T22:31:09Z"}')
    touch(root / "go" / "index" / "modules.json", "[]")
    assert adapter.applies(local) == (True, "")
    [item] = adapter.invocations(local, TOOL, out)
    uri = (root / "go").resolve().as_uri()
    assert uri.startswith("file:///")
    assert list(item.argv) == [str(TOOL), "-db", uri, "-json", "./..."]
    env = adapter.env(local)
    assert (env["GOPROXY"], env["GOSUMDB"]) == ("off", "off")


def test_govulncheck_without_go(tmp_path, without_go):
    ctx = make_ctx(tmp_path, tech={"go"})
    touch(ctx.target_dir / "go.mod")
    assert GovulncheckAdapter().applies(ctx)[1].startswith("Go is not installed")


def test_trivy_honor_mode_passes_target_ignore_files(tmp_path):
    ctx = make_ctx(tmp_path, honor=True)
    out = ctx.run_dir / "scans" / "trivy.sarif"
    argv = TrivyAdapter().command(ctx, TOOL, out)
    assert argv[argv.index("--ignorefile") + 1] == ""
    touch(ctx.target_dir / ".trivyignore", "DS-0002\n")
    touch(ctx.target_dir / "trivy-secret.yaml", "allow-rules: []\n")
    touch(ctx.target_dir / "trivy.yaml", "format: table\n")
    argv = TrivyAdapter().command(ctx, TOOL, out)
    assert argv[argv.index("--ignorefile") + 1] == str(ctx.target_dir / ".trivyignore")
    assert argv[argv.index("--secret-config") + 1] == str(ctx.target_dir / "trivy-secret.yaml")
    assert argv[argv.index("--config") + 1] == ""
    ignored, honored = TrivyAdapter().suppression_sources(ctx)
    assert any("trivy.yaml" in item for item in ignored)
    assert any(".trivyignore" in item for item in honored)
    strict = make_ctx(tmp_path)
    ignored, honored = TrivyAdapter().suppression_sources(strict)
    assert any(".trivyignore" in item for item in ignored)
    assert honored == ["trivy:ignore inline comments (Trivy 0.75.0 has no option to turn them off)"]


def test_hadolint_honor_mode(tmp_path):
    ctx = make_ctx(tmp_path, honor=True)
    touch(ctx.target_dir / "Dockerfile")
    out = ctx.run_dir / "scans" / "hadolint.sarif"
    [item] = HadolintAdapter().invocations(ctx, TOOL, out)
    assert "--disable-ignore-pragma" not in item.argv
    assert "-c" not in item.argv
    touch(ctx.target_dir / ".hadolint.yaml", "ignored: [DL3007]\n")
    [item] = HadolintAdapter().invocations(ctx, TOOL, out)
    assert item.argv[item.argv.index("-c") + 1] == str(ctx.target_dir / ".hadolint.yaml")
    assert HadolintAdapter().suppression_sources(ctx) == (
        [],
        ["# hadolint ignore= pragmas", ".hadolint.yaml of the target root (-c)"],
    )
    ignored, honored = HadolintAdapter().suppression_sources(make_ctx(tmp_path))
    assert honored == [] and len(ignored) == 2


def test_gitleaks_honor_mode_uses_tool_defaults(tmp_path):
    ctx = make_ctx(tmp_path, honor=True)
    out = ctx.run_dir / "scans" / ".work" / "gitleaks" / "gitleaks.sarif"
    argv = GitleaksAdapter().command(ctx, TOOL, out)
    assert "--config" not in argv and "--ignore-gitleaks-allow" not in argv
    out.parent.mkdir(parents=True)
    GitleaksAdapter().prepare(ctx, out)
    assert not (out.parent / "gitleaks.toml").exists()
    ignored, honored = GitleaksAdapter().suppression_sources(ctx)
    assert ignored == [] and len(honored) == 3


def test_gitleaks_history_follows_gitdir_file(tmp_path, with_go):
    from kalkan.scanners.adapters.gitleaks import git_dir

    real = tmp_path / "repo-git" / "worktrees" / "wt"
    real.mkdir(parents=True)
    source = tmp_path / "wt"
    source.mkdir()
    touch(source / ".git", f"gitdir: {real}\n")
    assert git_dir(source) == real
    touch(source / ".git", "gitdir: ../repo-git/worktrees/wt\n")
    assert git_dir(source) == source / "../repo-git/worktrees/wt"
    touch(source / ".git", "nonsense\n")
    assert git_dir(source) is None
    ctx = make_ctx(tmp_path, source=source)
    assert GitleaksHistoryAdapter().scan_root(ctx) == source
    ignored, honored = GitleaksHistoryAdapter().suppression_sources(ctx)
    assert any("git folder was not found" in item for item in honored)


def test_bandit_honor_mode(tmp_path):
    adapter = BanditAdapter()
    ctx = make_ctx(tmp_path, tech={"python"}, honor=True)
    out = ctx.run_dir / "scans" / ".work" / "bandit" / "bandit.sarif"
    argv = adapter.command(ctx, TOOL, out)
    assert "--ignore-nosec" not in argv and "--ini" not in argv
    out.parent.mkdir(parents=True)
    adapter.prepare(ctx, out)
    assert not (out.parent / "kalkan.bandit").exists()
    assert adapter.suppression_sources(ctx) == (
        [],
        ["# nosec comments", ".bandit files of the target"],
    )


# --------------------------------------------------------------------------------------------
# status handling through run_adapter with a fake runner

SARIF = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {"driver": {"name": "t", "rules": [{"id": "R1"}]}},
            "results": [
                {
                    "ruleId": "R1",
                    "level": "warning",
                    "message": {"text": "m"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "Dockerfile"},
                                "region": {"startLine": 1},
                            }
                        }
                    ],
                }
            ],
        }
    ],
}

# How each tool names its output: (flag, kind). kind "folder" means checkov's output folder.
OUTPUT_FLAGS = {
    "trivy": ("--output", "file"),
    "checkov": ("--output-file-path", "folder"),
    "gitleaks": ("--report-path", "file"),
    "gitleaks-history": ("--report-path", "file"),
    "opengrep": ("--output", "file"),
    "opengrep-packs": ("--output", "file"),
    "bandit": ("-o", "file"),
    "gosec": ("-out", "file"),
    "syft": ("-o", "syft"),
    "trivy-sbom": ("--output", "file"),
    "osv-scanner": ("--output-file", "file"),
    "grype": ("--file", "file"),
    "scorecard": ("--output", "file"),
}
#: Engines whose tool writes its report on stdout.
STDOUT_ENGINES = {"hadolint", "govulncheck", "zizmor", "actionlint", "poutine"}
#: Reports of the tools whose adapters convert JSON to SARIF (one result each, on Dockerfile or
#: on the repository root).
JSON_REPORTS = {
    "actionlint": [
        {"message": "m", "filepath": "Dockerfile", "line": 1, "column": 1, "kind": "syntax-check"}
    ],
    "poutine": {
        "findings": [{"rule_id": "injection", "meta": {"path": "Dockerfile", "line": 1}}],
        "rules": {"injection": {"id": "injection", "title": "t", "level": "warning"}},
    },
    "scorecard": {
        "checks": [
            {
                "name": "Security-Policy",
                "score": 0,
                "reason": "security policy file not detected",
                "details": ["Warn: no security policy file detected"],
            }
        ]
    },
}


GOSEC_REPORT = {
    "Golang errors": {},
    "Issues": [
        {
            "severity": "HIGH",
            "confidence": "MEDIUM",
            "cwe": {"id": "89", "url": "https://cwe.mitre.org/data/definitions/89.html"},
            "rule_id": "G201",
            "details": "SQL string formatting",
            "file": "main.go",
            "code": "49: q := fmt.Sprintf(x)\n50: db.Query(q)\n",
            "line": "49-50",
            "column": "2",
            "nosec": False,
        }
    ],
    "GosecVersion": "2.29.0",
}


def native_output(engine: str, argv) -> tuple[bytes, Path | None] | None:
    """Return ``(payload, file)`` for the tools whose native output the adapter converts to
    SARIF (``file`` None: stdout), or None for the other tools."""
    if engine in ("kingfisher", "kingfisher-history"):
        history = engine == "kingfisher-history"
        finding = {
            "snippet": "[REDACTED:0a1b2c3d]",
            "confidence": "medium",
            "line": 1,
            "column_start": 0,
            "column_end": 4,
            "path": "Dockerfile" if history else str(Path(argv[2]) / "Dockerfile"),
            "validation": {"outcome": "not_attempted", "response": "[REDACTED:0a1b2c3d]"},
        }
        if history:
            finding["git_metadata"] = {"commit": {"id": "ab" * 20}, "file": {"path": "Dockerfile"}}
        rule = {"id": "betterleaks.generic-api-key", "name": "generic-api-key", "description": "d"}
        report = {"findings": [{"rule": rule, "finding": finding}], "metadata": {}}
        return json.dumps(report).encode(), Path(argv[argv.index("--output") + 1])
    if engine == "shellcheck":
        comment = {"file": argv[-1], "line": 2, "column": 8, "level": "warning", "code": 2115}
        return json.dumps({"comments": [{**comment, "message": "m"}]}).encode(), None
    if engine == "flawfinder":
        result = {
            "ruleId": "FF1001",
            "level": "error",
            "rank": 0.8,
            "message": {"text": "buffer/strcpy"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": argv[-1], "uriBaseId": "SRCROOT"},
                        "region": {"startLine": 1},
                    }
                }
            ],
        }
        rule = {"id": "FF1001", "relationships": [{"target": {"id": "CWE-120"}}]}
        run = {"tool": {"driver": {"name": "Flawfinder", "rules": [rule]}}, "results": [result]}
        return json.dumps({"version": "2.1.0", "runs": [run]}).encode(), None
    if engine == "helm-checkov":
        if argv[1] == "template":  # helm: one rendered manifest
            out = Path(argv[argv.index("--output-dir") + 1]) / "c" / "templates" / "pod.yaml"
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text("---\n# Source: c/templates/pod.yaml\nkind: Pod\n", encoding="utf-8")
            return None
        doc = json.loads(json.dumps(SARIF))  # Checkov on the rendered folder
        location = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        location["artifactLocation"]["uri"] = "000/c/templates/pod.yaml"
        location["region"] = {"startLine": 3, "endLine": 3}
        folder = Path(argv[argv.index("--output-file-path") + 1])
        folder.mkdir(parents=True, exist_ok=True)
        return json.dumps(doc).encode(), folder / "results_sarif.sarif"
    if engine == "vacuum":
        item = {"code": "owasp-array-limit", "message": "m", "severity": 0, "path": ["a"]}
        item |= {"range": {"start": {"line": 1, "character": 1}}, "source": argv[-2]}
        return json.dumps([item]).encode(), Path(argv[-1])
    if engine == "gixy":
        issue = {"plugin": "ssrf", "severity": "HIGH", "summary": "s", "reason": "r"}
        issue |= {"file": argv[-1], "path": argv[-1], "line": 1}
        if "-o" in argv:  # the gixy command: no tool venv Python next to /opt/gixy
            return json.dumps([issue]).encode(), Path(argv[argv.index("-o") + 1])
        report = {"issues": [issue], "errors": []}  # the launcher: <python> ... -c <code> <report>
        return json.dumps(report).encode(), Path(argv[argv.index("-c") + 2])
    return None


def fake_tool(engine: str, exit_code: int = 0):
    def runner(argv, *, cwd, env, timeout, stdout, stderr):
        native = native_output(engine, argv)
        if native is None and engine == "helm-checkov":
            return ProcessOutcome(exit_code)  # helm wrote the rendered files
        if native is not None:
            data, path = native
            if path is None:
                stdout.write(data)
            else:
                path.write_bytes(data)
            return ProcessOutcome(exit_code)
        payload = SARIF if engine in registry.names() and engine not in _JSON else {"ok": True}
        if engine == "gosec":
            payload = GOSEC_REPORT
        payload = JSON_REPORTS.get(engine, payload)
        data = json.dumps(payload).encode()
        if engine in STDOUT_ENGINES:
            stdout.write(data)
            return ProcessOutcome(exit_code)
        flag, kind = OUTPUT_FLAGS[engine]
        value = argv[argv.index(flag) + 1]
        if kind == "folder":
            path = Path(value) / "results_sarif.sarif"
            path.parent.mkdir(parents=True, exist_ok=True)
        elif kind == "syft":
            path = Path(value.split("=", 1)[1])
        else:
            path = Path(value)
        path.write_bytes(data)
        return ProcessOutcome(exit_code)

    return runner


_JSON = {"syft", "trivy-sbom", "osv-scanner", "grype", "govulncheck"}


def resolver(name, *, allow_path=False):
    return ResolvedTool(name, Path("/opt") / name, "9.9.9", "kalkan")


def ready_ctx(tmp_path: Path) -> ScanContext:
    source = (tmp_path / "run" / "source").resolve()
    (source / ".git").mkdir(parents=True)
    ctx = make_ctx(tmp_path, tech={"python", "go", "c"}, source=source)
    touch(ctx.target_dir / "Dockerfile", "FROM alpine\n")
    touch(ctx.target_dir / "go.mod", "module x\n")
    touch(ctx.target_dir / ".github" / "workflows" / "ci.yml", "on: push\n")
    touch(ctx.target_dir / "azure-pipelines.yml", "steps: []\n")  # poutine reads it on Windows
    touch(ctx.target_dir / "run.sh", "#!/bin/sh\nrm -rf $X/\n")
    touch(ctx.target_dir / "labels.c", "void f(char *s) { char b[8]; strcpy(b, s); }\n")
    touch(ctx.target_dir / "nginx.conf", "server {\n  location /a { proxy_pass $arg_u; }\n}\n")
    touch(ctx.target_dir / "chart" / "Chart.yaml", "apiVersion: v2\nname: c\nversion: 0.1.0\n")
    touch(ctx.target_dir / "chart" / "templates" / "pod.yaml", "kind: Pod\n")
    touch(ctx.target_dir / "openapi.yaml", "openapi: 3.0.3\ninfo: {}\npaths: {}\n")
    touch(ctx.run_dir / "sca" / "sbom.cdx.json", "{}")
    return ctx


TOOL_ADAPTERS = [a for a in (*registry.SCANNERS, *registry.SCA_TOOLS) if a.tool is not None]


@pytest.mark.parametrize("adapter", TOOL_ADAPTERS, ids=lambda a: a.name)
def test_every_tool_adapter_ok_with_fake_tool(tmp_path, adapter, with_go):
    ctx = ready_ctx(tmp_path)
    res = run_adapter(adapter, ctx, runner=fake_tool(adapter.name), resolver=resolver)
    assert res.status == "ok", res.message
    assert res.tool_version == "9.9.9"
    out = ctx.run_dir / adapter.output_dir / adapter.output_name
    assert res.output_path == out and out.is_file()
    if adapter.output.startswith("sarif"):
        assert res.candidates == 1
        [candidate] = load_candidates(ctx.run_dir)["candidates"]
        assert candidate["engine"] == adapter.name
    else:
        assert res.candidates is None
    status = json.loads(
        (ctx.run_dir / adapter.output_dir / f"{adapter.name}.status.json").read_text(
            encoding="utf-8"
        )
    )
    assert status["status"] == "ok"
    assert status["tool_version"] == "9.9.9"


@pytest.mark.parametrize("adapter", TOOL_ADAPTERS, ids=lambda a: a.name)
def test_every_tool_adapter_fails_on_unexpected_exit_code(tmp_path, adapter, with_go):
    ctx = ready_ctx(tmp_path)
    code = next(code for code in (2, 3) if code not in adapter.ok_exit_codes)
    res = run_adapter(adapter, ctx, runner=fake_tool(adapter.name, code), resolver=resolver)
    assert res.status == "failed"
    assert f"exit code {code}" in res.message


@pytest.mark.parametrize("adapter", TOOL_ADAPTERS, ids=lambda a: a.name)
def test_every_tool_adapter_timeout(tmp_path, adapter, with_go):
    ctx = ready_ctx(tmp_path)

    def runner(argv, *, cwd, env, timeout, stdout, stderr):
        return ProcessOutcome(None, timed_out=True)

    res = run_adapter(adapter, ctx, runner=runner, resolver=resolver, timeout_seconds=3)
    assert res.status == "timeout"


@pytest.mark.parametrize("engine", ["checkov", "osv-scanner"])
def test_exit_code_one_counts_as_findings(tmp_path, engine, with_go):
    adapter = registry.get(engine)
    ctx = ready_ctx(tmp_path)
    res = run_adapter(adapter, ctx, runner=fake_tool(engine, exit_code=1), resolver=resolver)
    assert res.status == "ok", res.message
    assert res.exit_code == 1


def test_checkov_runs_in_the_target_folder(tmp_path, with_go):
    ctx = ready_ctx(tmp_path)
    seen = []
    tool = fake_tool("checkov")

    def runner(argv, **kwargs):
        seen.append(kwargs["cwd"])
        return tool(argv, **kwargs)

    run_adapter(CheckovAdapter(), ctx, runner=runner, resolver=resolver)
    assert seen == [ctx.target_dir]
    assert not (ctx.run_dir / "scans" / ".work").exists()


# --------------------------------------------------------------------------------------------
# matcher


SPEC = {
    "version": 1,
    "slug": "test-eval-call",
    "description": "eval() call",
    "class": "code-injection",
    "cwe": ["CWE-94"],
    "noise_tier": "precise",
    "file_patterns": ["**/*.py"],
    "requires": {"tech": ["python"], "sentinel_files": [], "sentinel_contains": []},
    "patterns": [{"regex": "\\beval\\s*\\(", "flags": "", "label": "eval("}],
    "examples": ["eval(user_input)"],
}


def test_matcher_collects_candidates_and_details(tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "test-eval-call.json").write_text(json.dumps(SPEC), encoding="utf-8")
    ctx = make_ctx(tmp_path, tech={"python"})
    touch(ctx.target_dir / "app.py", "x = 1\nresult = eval(data)\n")
    adapter = MatcherAdapter(rules_dir=rules)
    res = run_adapter(adapter, ctx)
    assert res.status == "ok", res.message
    assert res.candidates == 1
    assert res.tool_version is None
    [candidate] = load_candidates(ctx.run_dir)["candidates"]
    assert (candidate["engine"], candidate["rule_id"], candidate["start_line"]) == (
        "matcher",
        "test-eval-call",
        2,
    )
    assert candidate["raw"]["sarif_file"] == ""
    status = json.loads((ctx.run_dir / "scans" / "matcher.status.json").read_text(encoding="utf-8"))
    assert status["stats"]["matchers_applied"] == 1
    assert status["skipped"] == {}
    assert status["warnings"] == []


def test_matcher_tech_gate_is_reported_in_skipped(tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "test-eval-call.json").write_text(json.dumps(SPEC), encoding="utf-8")
    ctx = make_ctx(tmp_path, tech={"go"})
    res = run_adapter(MatcherAdapter(rules_dir=rules), ctx)
    assert res.status == "ok"
    assert res.candidates == 0
    status = json.loads((ctx.run_dir / "scans" / "matcher.status.json").read_text(encoding="utf-8"))
    assert status["skipped"] == {"test-eval-call": "tech"}


def test_matcher_bad_spec_gives_failed(tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "broken.json").write_text("{", encoding="utf-8")
    res = run_adapter(MatcherAdapter(rules_dir=rules), make_ctx(tmp_path))
    assert res.status == "failed"
    assert "matcher spec error" in res.message


def test_matcher_without_rules_is_skipped(tmp_path):
    res = run_adapter(MatcherAdapter(rules_dir=tmp_path / "none"), make_ctx(tmp_path))
    assert res.status == "skipped"
    assert res.message.startswith("matcher specs not found")


def test_matcher_default_rules_dir():
    assert MatcherAdapter().rules_dir().parts[-2:] == ("rules", "matchers")


# --------------------------------------------------------------------------------------------
# gosec JSON report conversion


def test_gosec_json_to_sarif():
    from kalkan.scanners.adapters.gosec import json_to_sarif

    report = dict(GOSEC_REPORT)
    report["Issues"] = [
        *GOSEC_REPORT["Issues"],
        {**GOSEC_REPORT["Issues"][0], "rule_id": "G104", "nosec": True},
        {**GOSEC_REPORT["Issues"][0], "file": r"C:\src\mod\db.go", "line": "7", "cwe": {"id": ""}},
    ]
    doc = json_to_sarif(report, "2.29.0")
    run = doc["runs"][0]
    assert doc["version"] == "2.1.0"
    assert run["tool"]["driver"]["version"] == "2.29.0"
    assert [r["ruleId"] for r in run["results"]] == ["G201", "G201"]
    first = run["results"][0]
    location = first["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "main.go"
    assert location["region"] == {
        "startLine": 49,
        "endLine": 50,
        "snippet": {"text": "q := fmt.Sprintf(x)\ndb.Query(q)"},
    }
    assert first["level"] == "error"
    assert first["properties"]["cwe"] == "CWE-89"
    assert run["results"][1]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == (
        "C:/src/mod/db.go"
    )
    assert run["tool"]["driver"]["rules"][0]["properties"]["tags"] == ["security", "CWE-89"]


def test_gosec_report_without_loaded_packages_is_an_error():
    from kalkan.errors import ToolError
    from kalkan.scanners.adapters.gosec import json_to_sarif

    report = {
        "Golang errors": {".": [{"line": 0, "error": "go command required, not found"}]},
        "Issues": [],
    }
    with pytest.raises(ToolError, match="could not load the Go packages"):
        json_to_sarif(report)
    assert json_to_sarif({"Golang errors": {}, "Issues": []})["runs"][0]["results"] == []
    # gosec checked files: the load errors are a scan gap (partial_packages), not a failure.
    checked = {**report, "Stats": {"files": 1, "lines": 5, "nosec": 0, "found": 0}}
    assert json_to_sarif(checked)["runs"][0]["results"] == []


def test_gosec_candidates_keep_module_paths(tmp_path, with_go):
    ctx = make_ctx(tmp_path, tech={"go"})
    touch(ctx.target_dir / "svc" / "go.mod", "module x\n")
    res = run_adapter(GosecAdapter(), ctx, runner=fake_tool("gosec"), resolver=resolver)
    assert res.status == "ok", res.message
    [candidate] = load_candidates(ctx.run_dir)["candidates"]
    assert candidate["file"] == "svc/main.go"
    assert (candidate["start_line"], candidate["end_line"]) == (49, 50)
    assert candidate["cwe"] == ["CWE-89"]
    assert candidate["severity"] == "high"
    assert candidate["confidence"] == "medium"
    assert candidate["class"] == "sqli"


def test_gosec_failed_package_load_gives_failed(tmp_path, with_go):
    ctx = make_ctx(tmp_path, tech={"go"})
    touch(ctx.target_dir / "go.mod", "module x\n")

    def runner(argv, *, cwd, env, timeout, stdout, stderr):
        report = {"Golang errors": {".": [{"error": "go command required"}]}, "Issues": []}
        Path(argv[argv.index("-out") + 1]).write_text(json.dumps(report), encoding="utf-8")
        return ProcessOutcome(0)

    res = run_adapter(GosecAdapter(), ctx, runner=runner, resolver=resolver)
    assert res.status == "failed"
    assert "could not load the Go packages" in res.message
