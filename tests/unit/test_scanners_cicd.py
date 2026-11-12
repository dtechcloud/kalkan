# SPDX-License-Identifier: MIT
"""Tests for the CI/CD and supply chain adapters: zizmor, actionlint, poutine, Scorecard.

The recorded outputs in ``tests/fixtures/cicd/`` are real outputs of the pinned tools on the
vulnapp fixture (2026-10-25, Windows 11), made with the command lines of the adapters; the
absolute path of the run folder is replaced with ``<target>``:

- ``zizmor.sarif`` (zizmor 1.30.1) and ``actionlint.json`` (actionlint 1.7.12).
- ``poutine-windows.json`` and ``scorecard-windows.json`` (Scorecard 5.5.0): the pinned builds on
  Windows. They cannot read the GitHub workflows there (they match paths with ``/``).
- ``poutine-posix.json`` and ``scorecard-posix.json``: development builds patched to use ``/``
  paths, as the Linux and macOS builds do: poutine 1.1.6 and Scorecard 5.6.0 (recorded before
  the re-pin to 5.5.0 on 2026-10-25; the Windows outputs of 5.5.0 and 5.6.0 differ only in the
  version, the commit and the documentation links). kalkan never installs them; they show the
  workflow results that Linux and macOS give.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from kalkan.findings import taxonomy
from kalkan.sarif.ingest import RULE_CLASS_ENGINES, ingest_document
from kalkan.scanners import registry
from kalkan.scanners.adapters import _cicd, actionlint, poutine, scorecard, zizmor
from kalkan.scanners.adapters._cicd import RuleClass, ci_files, target_path
from kalkan.scanners.adapters.actionlint import ActionlintAdapter
from kalkan.scanners.adapters.poutine import PoutineAdapter
from kalkan.scanners.adapters.scorecard import ScorecardAdapter
from kalkan.scanners.adapters.zizmor import ZizmorAdapter
from kalkan.scanners.base import ProcessOutcome, ScanContext, minimal_env, run_adapter
from kalkan.scanners.candidates import load_candidates
from kalkan.tools.resolve import ResolvedTool

ROOT = Path(__file__).resolve().parents[2]
RECORDED = ROOT / "tests" / "fixtures" / "cicd"
VULNAPP = ROOT / "tests" / "fixtures" / "vulnapp"
EXPECTED = VULNAPP / "EXPECTED.json"
#: The CI files of the vulnapp fixture.
CI_FIXTURE_FILES = (
    ".github/workflows/issue-triage.yml",
    ".github/workflows/issue-labels.yml",
    ".github/workflows/pr-preview.yml",
    ".github/workflows/pr-checks.yml",
    "azure-pipelines.yml",
)
TOOL = Path("/opt/tool")
TOKENS = {
    "GH_TOKEN": "ghp_fake",
    "GITHUB_TOKEN": "ghs_fake",
    "ZIZMOR_GITHUB_TOKEN": "fake",
    "GITHUB_AUTH_TOKEN": "fake",
    "GITLAB_AUTH_TOKEN": "fake",
    "ZIZMOR_CONFIG": "/tmp/evil.yml",
    "GH_HOST": "evil.example",
    "POUTINE_VERSION_CHECK_URL": "https://evil.example",
    "ENABLE_SARIF": "1",
}


def make_ctx(tmp_path: Path, *, honor: bool = False, offline: bool = True) -> ScanContext:
    run = (tmp_path / "run").resolve()
    target = run / "target"
    target.mkdir(parents=True, exist_ok=True)
    return ScanContext(
        run_dir=run,
        target_dir=target,
        source_dir=None,
        tech=frozenset({"github-actions"}),
        offline=offline,
        honor_suppressions=honor,
    )


def touch(path: Path, text: str = "x\n") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def fixture_ctx(tmp_path: Path, **kwargs) -> ScanContext:
    """A context whose target holds the CI files of the vulnapp fixture."""
    ctx = make_ctx(tmp_path, **kwargs)
    for rel in CI_FIXTURE_FILES:
        destination = ctx.target_dir / rel
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(VULNAPP / rel, destination)
    return ctx


def recorded(name: str):
    return json.loads((RECORDED / name).read_text(encoding="utf-8"))


def ingest(doc: dict, engine: str, ctx: ScanContext) -> list[dict]:
    result = ingest_document(doc, engine, ctx.target_dir, f"scans/{engine}.sarif")
    assert result.warnings == []
    return result.candidates


def expected_items(engine: str) -> list[dict]:
    items = json.loads(EXPECTED.read_text(encoding="utf-8"))
    return [item for item in items if engine in item.get("expected_engines", [])]


def twins_of(items: list[dict]) -> list[dict]:
    by_id = {item["id"]: item for item in json.loads(EXPECTED.read_text(encoding="utf-8"))}
    return [by_id[item["twin"]] for item in items]


def matches(candidate: dict, item: dict, engine: str, slack: int = 2) -> bool:
    if candidate["engine"] != engine or candidate["file"] != item["file"]:
        return False
    rules = item.get("rules", {}).get(engine)
    if rules and candidate["rule_id"] not in rules:
        return False
    start = candidate["start_line"]
    end = candidate["end_line"] or start
    return start is not None and start - slack <= item["line"] <= end + slack


def resolver(name, *, allow_path=False):
    return ResolvedTool(name, Path("/opt") / name, "9.9.9", "kalkan")


def stdout_runner(data: bytes, exit_code: int = 0, seen: list | None = None):
    def runner(argv, *, cwd, env, timeout, stdout, stderr):
        if seen is not None:
            seen.append({"argv": list(argv), "cwd": cwd, "env": dict(env)})
        stdout.write(data)
        return ProcessOutcome(exit_code)

    return runner


@pytest.fixture
def windows(monkeypatch):
    monkeypatch.setattr(_cicd, "on_windows", lambda: True)


@pytest.fixture
def posix(monkeypatch):
    monkeypatch.setattr(_cicd, "on_windows", lambda: False)


# --------------------------------------------------------------------------------------------
# shared helpers


def test_ci_files_uses_the_tool_patterns(tmp_path):
    target = tmp_path / "t"
    for rel in (
        ".github/workflows/ci.yml",
        ".github/workflows/release.yaml",
        ".github/workflows/nested/no.yml",
        ".github/workflows/readme.md",
        ".github/dependabot.yml",
        "action.yml",
        "actions/build/action.yaml",
        ".pre-commit-config.yaml",
        ".gitlab-ci.yml",
        "ci/deploy.gitlab-ci.yml",
        "azure-pipelines.yml",
        "build/azure-pipelines-release.yml",
        ".tekton/pr.yaml",
        "node_modules/x/action.yml",
    ):
        touch(target / rel)
    files = ci_files(target)
    assert files.workflows == (".github/workflows/ci.yml", ".github/workflows/release.yaml")
    assert files.actions == ("action.yml", "actions/build/action.yaml")
    assert files.dependabot == (".github/dependabot.yml",)
    assert files.pre_commit == (".pre-commit-config.yaml",)
    assert files.gitlab == (".gitlab-ci.yml", "ci/deploy.gitlab-ci.yml")
    # Unlike the matcher walk, the CI walk enters "build" folders (local actions live there).
    assert files.azure == ("azure-pipelines.yml", "build/azure-pipelines-release.yml")
    assert files.tekton == (".tekton/pr.yaml",)


def test_target_path_handles_tool_paths(tmp_path):
    target = (tmp_path / "work" / "runs" / "r1" / "target").resolve()
    touch(target / ".github" / "workflows" / "ci.yml")
    rel = ".github/workflows/ci.yml"
    assert target_path(rel, target) == rel
    assert target_path("./.github/workflows/ci.yml", target) == rel
    assert target_path(".github\\workflows\\ci.yml", target) == rel
    assert target_path(str(target / ".github" / "workflows" / "ci.yml"), target) == rel
    assert target_path("file://" + str(target / rel), target) == rel
    # zizmor inside a git work tree: relative to the repository root that holds the run folder.
    assert target_path("runs/r1/target/.github/workflows/ci.yml", target) == rel
    assert target_path("work/runs/r1/target/.github/workflows/ci.yml", target) == rel
    # A path relative to the working directory of the tool.
    scans = target.parent / "scans"
    scans.mkdir()
    assert target_path("..\\target\\.github\\workflows\\ci.yml", target, cwd=scans) == rel
    # Unknown paths stay as written (the ingest warns about them).
    assert target_path("elsewhere/x.yml", target) == "elsewhere/x.yml"
    assert target_path("../../etc/passwd", target) == "../../etc/passwd"
    assert target_path("", target) == ""


def test_rule_class_rejects_unknown_slugs():
    with pytest.raises(ValueError, match="unknown class"):
        RuleClass("pipeline-stuff")
    properties = _cicd.rule_properties(RuleClass("code-quality"), ("security", "style"))
    assert properties["tags"] == ["style"]
    assert properties["kalkan-class"] == "code-quality"
    properties = _cicd.rule_properties(RuleClass("code-injection", ("CWE-94",)), ("security",))
    assert properties["tags"] == ["security", "external/cwe/cwe-94"]


@pytest.mark.parametrize(
    ("engine", "expected"),
    [("zizmor", "supply-chain-cicd"), ("trivy", "sensitive-data-exposure")],
)
def test_ingest_takes_the_class_property_only_from_cicd_engines(tmp_path, engine, expected):
    ctx = make_ctx(tmp_path)
    touch(ctx.target_dir / "a.yml")
    doc = _cicd.sarif_document(
        engine,
        "1",
        "https://example.com",
        [_cicd.sarif_rule("R", RuleClass("supply-chain-cicd", ("CWE-522",)), title="t")],
        [_cicd.sarif_result("R", "m", file="a.yml", start_line=1)],
    )
    [candidate] = ingest(doc, engine, ctx)
    # CWE-522 maps to sensitive-data-exposure; the CI/CD engines keep their own class.
    assert candidate["class"] == expected
    assert candidate["cwe"] == ["CWE-522"]


def test_ingest_class_property_of_a_result_wins_and_unknown_slugs_are_ignored(tmp_path):
    ctx = make_ctx(tmp_path)
    touch(ctx.target_dir / "a.yml")
    rule = _cicd.sarif_rule("R", RuleClass("supply-chain-cicd", ("CWE-829",)))
    results = [
        _cicd.sarif_result(
            "R", "m", file="a.yml", start_line=1, properties={"kalkan-class": "xss"}
        ),
        _cicd.sarif_result(
            "R", "n", file="a.yml", start_line=2, properties={"kalkan-class": "bad"}
        ),
    ]
    doc = _cicd.sarif_document("poutine", "1", "https://example.com", [rule], results)
    first, second = ingest(doc, "poutine", ctx)
    assert first["class"] == "xss"
    assert second["class"] == "supply-chain-cicd"
    assert RULE_CLASS_ENGINES == {"zizmor", "actionlint", "poutine", "scorecard", "vacuum"}


def test_rule_tables_use_taxonomy_slugs_and_cwe_ids():
    tables = [
        *zizmor.RULES.values(),
        *(item for item, _ in actionlint.RULES.values()),
        *poutine.RULES.values(),
        *(item for item, _ in scorecard.CHECK_RULES.values()),
    ]
    for item in tables:
        assert item.vuln_class in taxonomy.SLUGS
        assert all(taxonomy.normalize_cwe(cwe) == cwe for cwe in item.cwe)


def test_registry_holds_the_cicd_adapters_before_the_matcher():
    names = [adapter.name for adapter in registry.SCANNERS]
    position = names.index("gosec")
    assert names[position + 1 : position + 10] == [
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


@pytest.mark.parametrize(
    "adapter",
    [ZizmorAdapter(), ActionlintAdapter(), PoutineAdapter(), ScorecardAdapter()],
    ids=lambda a: a.name,
)
def test_no_token_reaches_a_cicd_tool(tmp_path, adapter):
    ctx = fixture_ctx(tmp_path)
    env = minimal_env(adapter.env(ctx), environ={**TOKENS, "PATH": "/usr/bin"})
    assert not set(TOKENS) & set(env), env
    for invocation in adapter.invocations(ctx, TOOL, ctx.run_dir / "scans" / "x"):
        assert invocation.cwd.resolve().is_relative_to(ctx.run_dir)


# --------------------------------------------------------------------------------------------
# zizmor


def test_zizmor_applies_to_workflows_actions_and_dependabot(tmp_path):
    ctx = make_ctx(tmp_path)
    adapter = ZizmorAdapter()
    ok, reason = adapter.applies(ctx)
    assert not ok and "no GitHub Actions workflow" in reason
    touch(ctx.target_dir / ".github" / "dependabot.yml")
    assert adapter.applies(ctx) == (True, "")


def test_zizmor_command_lines(tmp_path):
    ctx = fixture_ctx(tmp_path)
    out = ctx.run_dir / "scans" / ".work" / "zizmor" / "zizmor.sarif"
    target = str(ctx.target_dir)
    assert ZizmorAdapter().command(ctx, TOOL, out) == [
        str(TOOL),
        "--offline",
        "--no-config",
        "--no-ignores",
        "--collect=all",
        "--persona=regular",
        "--format=sarif",
        "--color=never",
        target,
    ]
    honor = dataclass_replace(ctx, honor_suppressions=True)
    assert ZizmorAdapter().arguments(honor, out) == [
        "--offline",
        "--no-config",
        "--collect=all",
        "--persona=regular",
        "--format=sarif",
        "--color=never",
        target,
    ]
    config = touch(ctx.target_dir / ".github" / "zizmor.yml", "rules: {}\n")
    assert ZizmorAdapter().arguments(honor, out)[:3] == ["--offline", "--config", str(config)]
    # --online changes nothing: the online audits need a token, and kalkan passes none.
    online = dataclass_replace(ctx, offline=False)
    assert ZizmorAdapter().arguments(online, out) == ZizmorAdapter().arguments(ctx, out)
    assert ZizmorAdapter().env(ctx) == {}


def dataclass_replace(ctx: ScanContext, **changes) -> ScanContext:
    import dataclasses

    return dataclasses.replace(ctx, **changes)


def test_zizmor_suppression_sources(tmp_path):
    ctx = fixture_ctx(tmp_path)
    ignored, honored = ZizmorAdapter().suppression_sources(ctx)
    assert honored == [] and any("--no-ignores" in item for item in ignored)
    touch(ctx.target_dir / "zizmor.yml", "rules: {}\n")
    ignored, honored = ZizmorAdapter().suppression_sources(
        dataclass_replace(ctx, honor_suppressions=True)
    )
    assert honored == ["# zizmor: ignore[...] comments", "zizmor.yml of the target root (--config)"]


def test_zizmor_recorded_sarif_becomes_candidates(tmp_path):
    ctx = fixture_ctx(tmp_path)
    candidates = ingest(
        zizmor.rewrite_sarif(recorded("zizmor.sarif"), ctx.target_dir), "zizmor", ctx
    )
    found = {(c["rule_id"], c["file"], c["start_line"]): c for c in candidates}
    assert set(found) == {
        ("zizmor/excessive-permissions", ".github/workflows/issue-triage.yml", 7),
        ("zizmor/template-injection", ".github/workflows/issue-triage.yml", 19),
        # zizmor 1.30.1 marks the whole "on:" block (lines 3 to 5); 1.31.1 marked line 4.
        ("zizmor/dangerous-triggers", ".github/workflows/pr-preview.yml", 3),
        ("zizmor/unpinned-uses", ".github/workflows/pr-preview.yml", 23),
    }
    injection = found[("zizmor/template-injection", ".github/workflows/issue-triage.yml", 19)]
    assert (injection["class"], injection["cwe"]) == ("code-injection", ["CWE-94"])
    assert (injection["severity"], injection["confidence"]) == ("high", "high")
    assert injection["title"] == "code injection via template expansion"
    trigger = found[("zizmor/dangerous-triggers", ".github/workflows/pr-preview.yml", 3)]
    assert (trigger["class"], trigger["cwe"], trigger["confidence"]) == (
        "supply-chain-cicd",
        ["CWE-829"],
        "medium",
    )
    permissions = found[("zizmor/excessive-permissions", ".github/workflows/issue-triage.yml", 7)]
    assert (permissions["class"], permissions["cwe"]) == ("supply-chain-cicd", ["CWE-250"])
    items = expected_items("zizmor")
    assert len(items) == 4
    assert all(any(matches(c, item, "zizmor") for c in candidates) for item in items)
    for twin in twins_of(items):
        assert not any(c["file"] == twin["file"] for c in candidates), twin["id"]


def test_zizmor_uris_relative_to_a_parent_repository_are_fixed(tmp_path):
    ctx = fixture_ctx(tmp_path)
    doc = recorded("zizmor.sarif")
    text = json.dumps(doc).replace('"uri": ".github/', '"uri": "runs/r1/target/.github/')
    doc = json.loads(text.replace("runs/r1/target/", "/".join(ctx.target_dir.parts[-3:]) + "/"))
    candidates = ingest(zizmor.rewrite_sarif(doc, ctx.target_dir), "zizmor", ctx)
    assert {c["file"] for c in candidates} == {
        ".github/workflows/issue-triage.yml",
        ".github/workflows/pr-preview.yml",
    }


def test_zizmor_audit_classes():
    assert zizmor.rule_class("zizmor/template-injection") == RuleClass(
        "code-injection", ("CWE-94",)
    )
    assert zizmor.rule_class("github-env").vuln_class == "os-command-injection"
    assert zizmor.rule_class("artipacked") == RuleClass("supply-chain-cicd", ("CWE-522",))
    assert zizmor.rule_class("zizmor/some-future-audit") == RuleClass("supply-chain-cicd")
    assert zizmor.rule_class("undocumented-permissions").vuln_class == "code-quality"


def test_zizmor_adapter_end_to_end_with_a_fake_tool(tmp_path):
    ctx = fixture_ctx(tmp_path)
    seen: list = []
    data = (RECORDED / "zizmor.sarif").read_bytes()
    res = run_adapter(
        ZizmorAdapter(), ctx, runner=stdout_runner(data, seen=seen), resolver=resolver
    )
    assert res.status == "ok" and res.candidates == 4, res.message
    assert seen[0]["cwd"] == ctx.run_dir / "scans"
    status = json.loads((ctx.run_dir / "scans" / "zizmor.status.json").read_text(encoding="utf-8"))
    assert status["suppressions"]["mode"] == "ignore"
    sarif = json.loads((ctx.run_dir / "scans" / "zizmor.sarif").read_text(encoding="utf-8"))
    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["properties"]["kalkan-class"] and "shortDescription" in rule


def test_zizmor_invalid_output_fails_the_run(tmp_path):
    ctx = fixture_ctx(tmp_path)
    res = run_adapter(ZizmorAdapter(), ctx, runner=stdout_runner(b"not json"), resolver=resolver)
    assert res.status == "failed" and "zizmor did not write valid JSON" in res.message


# --------------------------------------------------------------------------------------------
# actionlint


def test_actionlint_applies_only_to_workflows(tmp_path):
    ctx = make_ctx(tmp_path)
    touch(ctx.target_dir / "action.yml")
    ok, reason = ActionlintAdapter().applies(ctx)
    assert not ok and reason == "no GitHub Actions workflow in the target"
    touch(ctx.target_dir / ".github" / "workflows" / "ci.yml")
    assert ActionlintAdapter().applies(ctx) == (True, "")


def test_actionlint_stages_the_workflows_in_its_own_project(monkeypatch, tmp_path):
    # Without an installed kalkan copy of ShellCheck, actionlint runs no shell check.
    monkeypatch.setattr(actionlint, "shellcheck_path", lambda: "")
    ctx = fixture_ctx(tmp_path)
    touch(ctx.target_dir / ".github" / "actions" / "setup" / "action.yml", "runs: {}\n")
    touch(ctx.target_dir / ".github" / "actionlint.yaml", "paths: {}\n")
    touch(ctx.target_dir / ".github" / "workflows" / "huge.yml", "#" * (1024 * 1024 + 1))
    adapter = ActionlintAdapter()
    stage = ctx.run_dir / "scans" / ".work" / "actionlint" / "actionlint.sarif"
    stage.parent.mkdir(parents=True)
    adapter.prepare(ctx, stage)
    repo = stage.parent / "repo"
    assert (repo / ".git").is_dir()
    assert (repo / ".github" / "workflows" / "issue-triage.yml").is_file()
    assert (repo / ".github" / "actions" / "setup" / "action.yml").is_file()
    assert not (repo / ".github" / "actionlint.yaml").exists()  # ignored by default
    assert not (repo / ".github" / "workflows" / "huge.yml").exists()  # larger than 1 MiB
    assert (stage.parent / "actionlint.yaml").read_text(encoding="utf-8").startswith("#")
    [invocation] = adapter.invocations(ctx, TOOL, stage)
    assert invocation.cwd == repo
    assert list(invocation.argv) == [
        str(TOOL),
        "-format",
        "{{json .}}",
        "-no-color",
        "-shellcheck=",
        "-pyflakes=",
        "-config-file",
        str(stage.parent / "actionlint.yaml"),
        ".github/workflows/issue-labels.yml",
        ".github/workflows/issue-triage.yml",
        ".github/workflows/pr-checks.yml",
        ".github/workflows/pr-preview.yml",
    ]


def test_actionlint_honor_mode_uses_the_target_configuration(monkeypatch, tmp_path):
    monkeypatch.setattr(actionlint, "shellcheck_path", lambda: "")
    ctx = dataclass_replace(fixture_ctx(tmp_path), honor_suppressions=True)
    touch(ctx.target_dir / ".github" / "actionlint.yaml", "paths: {}\n")
    adapter = ActionlintAdapter()
    stage = ctx.run_dir / "scans" / ".work" / "actionlint" / "actionlint.sarif"
    stage.parent.mkdir(parents=True)
    adapter.prepare(ctx, stage)
    assert (stage.parent / "repo" / ".github" / "actionlint.yaml").is_file()
    assert "-config-file" not in adapter.arguments(ctx, stage)
    assert adapter.suppression_sources(ctx) == (
        [],
        [".github/actionlint.yaml of the target (paths.*.ignore rules)"],
    )


def test_actionlint_uses_only_the_kalkan_shellcheck(monkeypatch, tmp_path):
    from kalkan.tools import manifest as manifest_mod
    from kalkan.tools import resolve as resolve_mod

    class FakeManifest:
        def __init__(self, names):
            self.names = names

        def __contains__(self, name):
            return name in self.names

    # A manifest without a shellcheck entry: no shell check.
    monkeypatch.setattr(manifest_mod, "load_manifest", lambda: FakeManifest(()))
    assert actionlint.shellcheck_path() == ""
    monkeypatch.setattr(manifest_mod, "load_manifest", lambda: FakeManifest(("shellcheck",)))
    copy = tmp_path / ".tools" / "shellcheck" / "0.11.0" / "bin" / "shellcheck"
    found = {"value": ResolvedTool("shellcheck", copy, "0.11.0", "kalkan")}
    monkeypatch.setattr(resolve_mod, "resolve", lambda name, **kwargs: found["value"])
    assert actionlint.shellcheck_path() == str(copy)
    ctx = fixture_ctx(tmp_path)
    assert f"-shellcheck={copy}" in ActionlintAdapter().arguments(ctx, tmp_path / "x.sarif")
    assert any(
        "shellcheck disable" in item for item in ActionlintAdapter().suppression_sources(ctx)[1]
    )
    found["value"] = ResolvedTool("shellcheck", Path("/usr/bin/shellcheck"), "0.11.0", "path")
    assert actionlint.shellcheck_path() == ""


def test_actionlint_recorded_report_becomes_candidates(tmp_path):
    ctx = fixture_ctx(tmp_path)
    doc = actionlint.report_to_sarif(
        recorded("actionlint.json"), ctx.target_dir, cwd=ctx.run_dir / "scans" / "repo"
    )
    [candidate] = ingest(doc, "actionlint", ctx)
    assert candidate["rule_id"] == "expression/untrusted-input"
    assert (candidate["class"], candidate["cwe"], candidate["severity"]) == (
        "code-injection",
        ["CWE-94"],
        "high",
    )
    assert (candidate["file"], candidate["start_line"]) == (
        ".github/workflows/issue-triage.yml",
        18,
    )
    assert "github.event.issue.title" in candidate["message"]
    [item] = expected_items("actionlint")
    assert matches(candidate, item, "actionlint")


def test_actionlint_lint_errors_are_code_quality(tmp_path):
    ctx = fixture_ctx(tmp_path)
    report = [
        {
            "message": "x",
            "filepath": ".github/workflows/pr-checks.yml",
            "line": 2,
            "kind": "syntax-check",
        },
        {
            "message": "y",
            "filepath": ".github/workflows/pr-checks.yml",
            "line": 3,
            "kind": "credentials",
        },
        {
            "message": "z",
            "filepath": ".github/workflows/pr-checks.yml",
            "line": 4,
            "kind": "expression",
        },
    ]
    doc = actionlint.report_to_sarif(report, ctx.target_dir, cwd=ctx.target_dir)
    found = {c["rule_id"]: c for c in ingest(doc, "actionlint", ctx)}
    assert (found["syntax-check"]["class"], found["syntax-check"]["severity"]) == (
        "code-quality",
        "info",
    )
    assert found["credentials"]["class"] == "hardcoded-secrets"
    assert found["expression"]["class"] == "code-quality"
    assert (
        actionlint.report_to_sarif(None, ctx.target_dir, cwd=ctx.target_dir)["runs"][0]["results"]
        == []
    )


def test_actionlint_adapter_end_to_end_with_a_fake_tool(tmp_path):
    ctx = fixture_ctx(tmp_path)
    seen: list = []
    data = (RECORDED / "actionlint.json").read_bytes()
    runner = stdout_runner(data, exit_code=1, seen=seen)
    res = run_adapter(ActionlintAdapter(), ctx, runner=runner, resolver=resolver)
    assert res.status == "ok" and res.candidates == 1 and res.exit_code == 1, res.message
    assert seen[0]["cwd"] == ctx.run_dir / "scans" / ".work" / "actionlint" / "repo"
    assert not (ctx.run_dir / "scans" / ".work").exists()  # the staging is removed
    empty = run_adapter(ActionlintAdapter(), ctx, runner=stdout_runner(b"[]\n"), resolver=resolver)
    assert empty.status == "ok" and empty.candidates == 0


# --------------------------------------------------------------------------------------------
# poutine


def test_poutine_applies_and_the_windows_gap(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    adapter = PoutineAdapter()
    ok, reason = adapter.applies(ctx)
    assert not ok and "no CI file that poutine reads" in reason
    touch(ctx.target_dir / ".github" / "workflows" / "ci.yml")
    monkeypatch.setattr(_cicd, "on_windows", lambda: False)
    assert adapter.applies(ctx) == (True, "")
    assert adapter.status_details(ctx, Path("o"), Path("e"), []) == {}
    monkeypatch.setattr(_cicd, "on_windows", lambda: True)
    ok, reason = adapter.applies(ctx)
    assert not ok and "poutine 1.1.6 on Windows" in reason
    touch(ctx.target_dir / "azure-pipelines.yml")
    assert adapter.applies(ctx) == (True, "")
    gap = adapter.status_details(ctx, Path("o"), Path("e"), [])["platform_gap"]
    assert gap["files"] == [".github/workflows/ci.yml"] and gap["count"] == 1


def test_poutine_windows_readable_files():
    files = [
        "action.yml",
        "sub/action.yml",
        ".gitlab-ci.yml",
        "ci/x.gitlab-ci.yml",
        ".tekton/p.yml",
    ]
    assert poutine.platform_gap_files(files, windows=True) == ["sub/action.yml", ".tekton/p.yml"]
    assert poutine.platform_gap_files(files, windows=False) == []


def test_poutine_command_line_and_environment(tmp_path):
    ctx = fixture_ctx(tmp_path)
    out = ctx.run_dir / "scans" / ".work" / "poutine" / "poutine.sarif"
    adapter = PoutineAdapter()
    assert adapter.command(ctx, TOOL, out) == [
        str(TOOL),
        "analyze_local",
        str(ctx.target_dir),
        "--format",
        "json",
        "--quiet",
        "--disable-version-check",
        "--config",
        str(out.parent / "poutine.yml"),
    ]
    assert adapter.env(ctx) == {"POUTINE_DISABLE_VERSION_CHECK": "1"}
    honor = dataclass_replace(ctx, honor_suppressions=True)
    assert adapter.arguments(honor, out) == adapter.arguments(ctx, out)
    ignored, honored = adapter.suppression_sources(honor)
    assert honored == [] and "never loaded" in ignored[0]
    out.parent.mkdir(parents=True)
    adapter.prepare(ctx, out)
    assert (out.parent / "poutine.yml").read_text(encoding="utf-8").startswith("#")


def test_poutine_recorded_posix_report_becomes_candidates(tmp_path):
    ctx = fixture_ctx(tmp_path)
    candidates = ingest(
        poutine.report_to_sarif(recorded("poutine-posix.json"), ctx.target_dir), "poutine", ctx
    )
    found = {(c["rule_id"], c["file"], c["start_line"]): c for c in candidates}
    assert set(found) == {
        ("injection", "azure-pipelines.yml", 14),
        ("injection", ".github/workflows/issue-triage.yml", 18),
        ("untrusted_checkout_exec", ".github/workflows/pr-preview.yml", 21),
        ("github_action_from_unverified_creator_used", ".github/workflows/pr-preview.yml", 23),
        ("github_action_from_unverified_creator_used", ".github/workflows/pr-checks.yml", 23),
    }
    azure = found[("injection", "azure-pipelines.yml", 14)]
    assert (azure["class"], azure["cwe"], azure["severity"]) == (
        "code-injection",
        ["CWE-94"],
        "medium",
    )
    assert "Sources: Build.SourceBranchName" in azure["message"] and "job build" in azure["message"]
    checkout = found[("untrusted_checkout_exec", ".github/workflows/pr-preview.yml", 21)]
    assert (checkout["class"], checkout["cwe"], checkout["severity"]) == (
        "supply-chain-cicd",
        ["CWE-829"],
        "high",
    )
    assert "Detected usage of `make`" in checkout["message"]
    creator = found[
        ("github_action_from_unverified_creator_used", ".github/workflows/pr-checks.yml", 23)
    ]
    assert (creator["class"], creator["severity"]) == ("supply-chain-cicd", "low")


def test_poutine_recorded_windows_report_has_only_the_azure_item(tmp_path):
    ctx = fixture_ctx(tmp_path)
    candidates = ingest(
        poutine.report_to_sarif(recorded("poutine-windows.json"), ctx.target_dir), "poutine", ctx
    )
    assert [(c["rule_id"], c["file"], c["start_line"]) for c in candidates] == [
        ("injection", "azure-pipelines.yml", 14)
    ]
    [item] = expected_items("poutine")
    assert matches(candidates[0], item, "poutine")
    [twin] = twins_of([item])
    assert not any(matches(c, twin, "poutine", slack=0) for c in candidates)


def test_poutine_finding_without_a_path_is_on_the_repository(tmp_path):
    ctx = make_ctx(tmp_path)
    report = {
        "findings": [
            {"rule_id": "known_vulnerability_in_build_platform", "meta": {"osv_id": "CVE-2024-1"}}
        ],
        "rules": {},
    }
    [candidate] = ingest(poutine.report_to_sarif(report, ctx.target_dir), "poutine", ctx)
    assert (candidate["file"], candidate["start_line"]) == ("", None)
    assert candidate["cwe"] == ["CWE-1395"] and candidate["class"] == "supply-chain-cicd"
    with pytest.raises(Exception, match="no findings list"):
        poutine.report_to_sarif({"rules": {}}, ctx.target_dir)


# --------------------------------------------------------------------------------------------
# Scorecard


def test_scorecard_command_line(tmp_path):
    ctx = fixture_ctx(tmp_path)
    out = ctx.run_dir / "scans" / ".work" / "scorecard" / "scorecard.sarif"
    assert ScorecardAdapter().command(ctx, TOOL, out) == [
        str(TOOL),
        "--local",
        str(ctx.target_dir),
        "--checks",
        "Binary-Artifacts,Dangerous-Workflow,Dependency-Update-Tool,License,Security-Policy,"
        "Token-Permissions",
        "--format",
        "json",
        "--show-details",
        "--output",
        str(out.with_suffix(".json")),
    ]
    assert not set(scorecard.CHECKS) & set(scorecard.CHECKS_NOT_RUN)
    assert {"Pinned-Dependencies", "Vulnerabilities", "Fuzzing"} <= set(scorecard.CHECKS_NOT_RUN)
    assert ScorecardAdapter().env(ctx) == {}


def test_scorecard_applies_to_any_target_with_a_file(tmp_path):
    ctx = make_ctx(tmp_path)
    assert ScorecardAdapter().applies(ctx) == (False, "the target has no file")
    touch(ctx.target_dir / "README.md")
    assert ScorecardAdapter().applies(ctx) == (True, "")


def test_scorecard_detail_lines(tmp_path):
    target = tmp_path / "t"
    touch(target / ".github" / "workflows" / "ci.yml")
    touch(target / "infra" / "Dockerfile")
    parse = scorecard.parse_detail
    assert parse("Info: topLevel 'contents' permission set to 'read': x.yml:8", target) is None
    assert parse(
        "Warn: script injection with untrusted input ' github.event.issue.title ': "
        ".github/workflows/ci.yml:18",
        target,
    ) == {
        "text": "script injection with untrusted input ' github.event.issue.title '",
        "file": ".github/workflows/ci.yml",
        "start_line": 18,
        "end_line": 18,
        "remediation": "",
    }
    windows = parse(
        "Warn: containerImage not pinned by hash: infra\\Dockerfile:1-3: pin your Docker image by "
        "updating python:latest to python:latest@sha256:00",
        target,
    )
    assert (windows["file"], windows["start_line"], windows["end_line"]) == (
        "infra/Dockerfile",
        1,
        3,
    )
    assert windows["remediation"].startswith("pin your Docker image")
    assert parse("Warn: no security policy file detected", target) == {
        "text": "no security policy file detected",
        "file": "",
        "start_line": None,
        "end_line": None,
        "remediation": "",
    }


def test_scorecard_recorded_posix_report_becomes_candidates(tmp_path):
    ctx = fixture_ctx(tmp_path)
    candidates = ingest(
        scorecard.report_to_sarif(recorded("scorecard-posix.json"), ctx.target_dir),
        "scorecard",
        ctx,
    )
    found = {(c["rule_id"], c["file"], c["start_line"]): c for c in candidates}
    assert set(found) == {
        ("Dangerous-Workflow", ".github/workflows/issue-triage.yml", 18),
        ("Dangerous-Workflow", ".github/workflows/pr-preview.yml", 16),
        ("Token-Permissions", ".github/workflows/issue-triage.yml", 7),
        ("Dependency-Update-Tool", "", None),
        ("License", "", None),
        ("Security-Policy", "", None),
    }
    injection = found[("Dangerous-Workflow", ".github/workflows/issue-triage.yml", 18)]
    assert (injection["class"], injection["cwe"], injection["severity"]) == (
        "code-injection",
        ["CWE-94"],
        "high",
    )
    checkout = found[("Dangerous-Workflow", ".github/workflows/pr-preview.yml", 16)]
    assert (checkout["class"], checkout["cwe"]) == ("supply-chain-cicd", ["CWE-829"])
    tokens = found[("Token-Permissions", ".github/workflows/issue-triage.yml", 7)]
    assert (tokens["class"], tokens["cwe"], tokens["severity"]) == (
        "supply-chain-cicd",
        ["CWE-250"],
        "medium",
    )
    policy = found[("Security-Policy", "", None)]
    assert (policy["class"], policy["severity"]) == ("supply-chain-cicd", "low")
    assert policy["message"].count("no security file to analyze") == 1
    assert found[("License", "", None)]["class"] == "code-quality"
    assert found[("License", "", None)]["severity"] == "info"
    assert found[("Dependency-Update-Tool", "", None)]["severity"] == "medium"


def test_scorecard_recorded_windows_report_has_only_root_candidates(tmp_path):
    ctx = fixture_ctx(tmp_path)
    candidates = ingest(
        scorecard.report_to_sarif(recorded("scorecard-windows.json"), ctx.target_dir),
        "scorecard",
        ctx,
    )
    assert sorted(c["rule_id"] for c in candidates) == [
        "Dependency-Update-Tool",
        "License",
        "Security-Policy",
    ]
    assert all(c["file"] == "" for c in candidates)


def test_scorecard_status_details(tmp_path, monkeypatch):
    ctx = fixture_ctx(tmp_path)
    stage = ctx.run_dir / "scans" / ".work" / "scorecard" / "scorecard.sarif"
    stage.parent.mkdir(parents=True)
    shutil.copyfile(RECORDED / "scorecard-windows.json", stage.with_suffix(".json"))
    monkeypatch.setattr(_cicd, "on_windows", lambda: True)
    details = ScorecardAdapter().status_details(ctx, Path("o"), Path("e"), [stage])
    scores = {item["name"]: item["score"] for item in details["scores"]}
    assert scores == {
        "Binary-Artifacts": 10,
        "Dangerous-Workflow": -1,
        "Dependency-Update-Tool": 0,
        "License": 0,
        "Security-Policy": 0,
        "Token-Permissions": -1,
    }
    assert details["checks_not_run"] == scorecard.CHECKS_NOT_RUN
    gap = details["platform_gap"]
    assert gap["checks"] == ["Dangerous-Workflow", "Token-Permissions"] and gap["count"] == 4
    monkeypatch.setattr(_cicd, "on_windows", lambda: False)
    assert "platform_gap" not in ScorecardAdapter().status_details(
        ctx, Path("o"), Path("e"), [stage]
    )


def test_scorecard_adapter_end_to_end_with_a_fake_tool(tmp_path):
    ctx = fixture_ctx(tmp_path)

    def runner(argv, *, cwd, env, timeout, stdout, stderr):
        report = Path(argv[argv.index("--output") + 1])
        shutil.copyfile(RECORDED / "scorecard-posix.json", report)
        return ProcessOutcome(0)

    res = run_adapter(ScorecardAdapter(), ctx, runner=runner, resolver=resolver)
    assert res.status == "ok" and res.candidates == 6, res.message
    status = json.loads(
        (ctx.run_dir / "scans" / "scorecard.status.json").read_text(encoding="utf-8")
    )
    assert {item["name"] for item in status["scores"]} == set(scorecard.CHECKS)
    assert "<target>" not in json.dumps(status)
    rules = {c["rule_id"] for c in load_candidates(ctx.run_dir)["candidates"]}
    assert rules == {
        "Dangerous-Workflow",
        "Token-Permissions",
        "Dependency-Update-Tool",
        "License",
        "Security-Policy",
    }


def test_scorecard_without_a_report_fails(tmp_path):
    ctx = fixture_ctx(tmp_path)
    res = run_adapter(ScorecardAdapter(), ctx, runner=stdout_runner(b""), resolver=resolver)
    assert res.status == "failed" and "no Scorecard report" in res.message
