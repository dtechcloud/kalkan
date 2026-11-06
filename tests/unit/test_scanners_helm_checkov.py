# SPDX-License-Identifier: MIT
"""Tests for the helm-checkov adapter (kalkan.scanners.adapters.helm_checkov): chart discovery,
the helm and Checkov command lines and environment, the chart gaps, and the mapping of a
recorded Checkov 3.3.22 SARIF of charts rendered by helm 4.3.0 back to the templates."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest

from kalkan.sarif.ingest import ingest_document
from kalkan.scanners.adapters import helm_checkov
from kalkan.scanners.adapters.checkov import LAUNCHER
from kalkan.scanners.adapters.helm_checkov import (
    GAP_DEPENDENCIES,
    GAP_EMPTY,
    GAP_ERROR,
    HelmCheckovAdapter,
    chart_gap,
    charts,
    map_result,
    split_documents,
)
from kalkan.scanners.base import ProcessOutcome, ScanContext, run_adapter
from kalkan.tools.resolve import ResolvedTool

OUTPUTS = Path(__file__).resolve().parents[1] / "fixtures" / "scanner-outputs"
FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "vulnapp"
CHART = FIXTURE / "infra" / "helm" / "shop"


def make_ctx(tmp_path: Path) -> ScanContext:
    run = (tmp_path / "run").resolve()
    target = run / "target"
    target.mkdir(parents=True, exist_ok=True)
    return ScanContext(run_dir=run, target_dir=target, source_dir=None, tech=frozenset())


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")
    return path


def checkov_tool(path: Path = Path("/opt/checkov")):
    return ResolvedTool("checkov", path, "3.3.22", "kalkan")


@pytest.fixture
def with_checkov(monkeypatch):
    monkeypatch.setattr(helm_checkov, "checkov_resolver", lambda allow_path=False: checkov_tool())


def resolver(name, *, allow_path=False):
    return ResolvedTool(name, Path("/opt") / name, "4.3.0", "kalkan")


# --------------------------------------------------------------------------------------------
# discovery


def test_charts_skip_subcharts_and_vendored_folders(tmp_path):
    write(tmp_path / "deploy" / "web" / "Chart.yaml", "name: web\n")
    write(tmp_path / "deploy" / "web" / "charts" / "redis" / "Chart.yaml", "name: redis\n")
    write(tmp_path / "charts" / "loose" / "Chart.yaml", "name: loose\n")  # no parent chart
    write(tmp_path / "vendor" / "x" / "Chart.yaml", "name: x\n")
    write(tmp_path / "deploy" / "web" / "chart.yaml.bak", "")
    assert charts(tmp_path) == ["charts/loose", "deploy/web"]


def test_a_chart_at_the_target_root(tmp_path):
    write(tmp_path / "Chart.yaml", "name: root\n")
    write(tmp_path / "charts" / "dep" / "Chart.yaml", "name: dep\n")
    assert charts(tmp_path) == [""]


def test_applies_needs_a_chart_and_checkov(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    adapter = HelmCheckovAdapter()
    monkeypatch.setattr(helm_checkov, "checkov_resolver", lambda allow_path=False: None)
    assert adapter.applies(ctx) == (False, "no Helm chart (Chart.yaml) in the target")
    write(ctx.target_dir / "chart" / "Chart.yaml", "name: c\n")
    ok, reason = adapter.applies(ctx)
    assert not ok and "kalkan tools install checkov" in reason
    monkeypatch.setattr(helm_checkov, "checkov_resolver", lambda allow_path=False: checkov_tool())
    assert adapter.applies(ctx) == (True, "")


# --------------------------------------------------------------------------------------------
# command lines and environment


def test_invocations_render_each_chart_offline_then_run_checkov(tmp_path, with_checkov):
    ctx = make_ctx(tmp_path)
    write(ctx.target_dir / "a" / "Chart.yaml", "name: a\n")
    write(ctx.target_dir / "b" / "Chart.yaml", "name: b\n")
    adapter = HelmCheckovAdapter()
    adapter.applies(ctx)
    work = ctx.run_dir / "scans" / ".work" / "helm-checkov"
    items = adapter.invocations(ctx, Path("/opt/helm"), work / "helm-checkov.sarif")
    assert [item.label for item in items] == ["chart a", "chart b", "checkov"]
    first = items[0]
    assert first.setup and first.cwd == work
    assert list(first.argv) == [
        str(Path("/opt/helm")),
        "template",
        "kalkan",
        str(ctx.target_dir / "a"),
        "--output-dir",
        str(work / "helm" / "000"),
        "--skip-schema-validation",
    ]
    for word in ("--dependency-update", "--repo", "dependency", "-f", "--values", "--set"):
        assert word not in first.argv
    assert Path(first.argv[3]).is_absolute()
    last = items[-1]
    assert not last.setup and last.cwd == work / "helm"
    assert last.output == work / "results" / "results_sarif.sarif"
    assert list(last.argv) == [
        str(Path("/opt/checkov")),
        "-d",
        str(work / "helm"),
        "-o",
        "sarif",
        "--output-file-path",
        str(work / "results"),
        "--framework",
        "kubernetes",
        "--skip-download",
        "--quiet",
        "--compact",
    ]


def test_checkov_runs_through_the_launcher_of_the_tool_venv(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    write(ctx.target_dir / "Chart.yaml", "name: a\n")
    scripts = tmp_path / "pyenv" / ("Scripts" if os.name == "nt" else "bin")
    python = write(scripts / ("python.exe" if os.name == "nt" else "python"), "")
    entry = write(scripts / "checkov", "")
    monkeypatch.setattr(
        helm_checkov, "checkov_resolver", lambda allow_path=False: checkov_tool(entry)
    )
    adapter = HelmCheckovAdapter()
    adapter.applies(ctx)
    argv = adapter.checkov_command(ctx)
    assert argv[:6] == [str(python), "-I", "-X", "utf8", "-c", LAUNCHER]
    assert argv[argv.index("--framework") + 1] == "kubernetes"


def test_env_keeps_helm_and_checkov_inside_the_work_folder(tmp_path):
    ctx = make_ctx(tmp_path)
    env = HelmCheckovAdapter().env(ctx)
    work = ctx.run_dir / "scans" / ".work" / "helm-checkov"
    assert env["HELM_CACHE_HOME"] == str(work / "helm-home" / "cache")
    assert env["HELM_CONFIG_HOME"] == str(work / "helm-home" / "config")
    assert env["HELM_DATA_HOME"] == str(work / "helm-home" / "data")
    assert env["HOME"] == env["USERPROFILE"] == str(work / "home")
    assert env["KUBECONFIG"] == str(work / "home" / "kubeconfig-none")
    assert env["CKV_SKIP_PACKAGE_UPDATE_CHECK"] == "true"
    assert not any("PROXY" in key.upper() for key in env)


# --------------------------------------------------------------------------------------------
# mapping


def test_split_documents():
    lines = ["---", "# Source: a", "x: 1", "---", "---", "y: 2"]
    assert split_documents(lines) == [(2, 3), (6, 6)]
    assert split_documents(["a: 1", "--- # doc", "b: 2"]) == [(1, 1), (3, 3)]


def _reader(files: dict[str, str]):
    return lambda rel: files[rel].split("\n") if rel in files else None


RENDERED = (OUTPUTS / "helm-template" / "shop" / "templates" / "log-agent.yaml").read_text(
    encoding="utf-8"
)
TEMPLATE = (CHART / "templates" / "log-agent.yaml").read_text(encoding="utf-8")


def test_map_result_to_the_template_document_and_key_line():
    read = _reader({"infra/helm/shop/templates/log-agent.yaml": TEMPLATE})
    rendered = RENDERED.split("\n")
    common = {"chart": "infra/helm/shop", "rendered": rendered, "start": 3, "end": 33}
    whole = map_result(rule_id="CKV_K8S_11", read_target=read, **common)
    assert whole["file"] == "infra/helm/shop/templates/log-agent.yaml"
    assert (whole["start"], whole["end"]) == (2, 30)  # not the {{- if }} and {{- end }} lines
    assert whole["mapping"] == "template-document"
    assert whole["snippet"] == "apiVersion: apps/v1"
    assert whole["rendered_source"] == "shop/templates/log-agent.yaml"
    privileged = map_result(rule_id="CKV_K8S_16", read_target=read, **common)
    assert (privileged["start"], privileged["end"], privileged["mapping"]) == (
        26,
        26,
        "template-key",
    )
    assert privileged["snippet"].strip() == "privileged: {{ .Values.logAgent.privileged }}"
    network = map_result(rule_id="CKV_K8S_19", read_target=read, **common)
    assert network["start"] == 17


def test_map_result_keeps_the_document_when_the_key_is_ambiguous():
    template = (
        "apiVersion: v1\nkind: Pod\nspec:\n  containers:\n    - name: a\n"
        "      securityContext:\n        privileged: true\n    - name: b\n"
        "      securityContext:\n        privileged: {{ .Values.b }}\n"
    )
    rendered = ["---", "# Source: c/templates/pod.yaml", *template.split("\n")]
    found = map_result(
        chart="c",
        rendered=rendered,
        start=3,
        end=12,
        rule_id="CKV_K8S_16",
        read_target=_reader({"c/templates/pod.yaml": template}),
    )
    assert (found["start"], found["end"], found["mapping"]) == (1, 10, "template-document")


def test_map_result_uses_the_document_index_of_a_multi_document_template():
    template = (
        "{{- range .Values.items }}\n---\napiVersion: v1\nkind: ConfigMap\n{{- end }}\n"
        "---\napiVersion: v1\nkind: Secret\n"
    )
    rendered = [
        "---",
        "# Source: c/templates/many.yaml",
        "apiVersion: v1",
        "kind: ConfigMap",
        "---",
        "# Source: c/templates/many.yaml",
        "apiVersion: v1",
        "kind: Secret",
    ]
    read = _reader({"c/templates/many.yaml": template})
    second = map_result(chart="c", rendered=rendered, start=7, end=8, rule_id="X", read_target=read)
    assert (second["start"], second["end"]) == (7, 8)
    first = map_result(chart="c", rendered=rendered, start=3, end=4, rule_id="X", read_target=read)
    assert (first["start"], first["end"]) == (3, 4)


def test_map_result_of_a_packaged_dependency_points_to_the_chart_file():
    rendered = ["---", "# Source: shop/charts/redis/templates/sts.yaml", "kind: StatefulSet"]
    found = map_result(
        chart="deploy/shop",
        rendered=rendered,
        start=3,
        end=3,
        rule_id="CKV_K8S_16",
        read_target=_reader({"deploy/shop/Chart.yaml": "apiVersion: v2\nname: shop\n"}),
    )
    assert found == {
        "file": "deploy/shop/Chart.yaml",
        "start": 1,
        "end": 1,
        "snippet": "apiVersion: v2",
        "mapping": "chart",
        "rendered_source": "shop/charts/redis/templates/sts.yaml",
    }


def test_map_result_refuses_a_source_that_leaves_the_chart():
    rendered = ["---", "# Source: shop/../../../etc/x.yaml", "kind: Pod"]
    found = map_result(
        chart="c",
        rendered=rendered,
        start=3,
        end=3,
        rule_id="X",
        read_target=_reader({"c/Chart.yaml": "name: c"}),
    )
    assert found["file"] == "c/Chart.yaml" and found["mapping"] == "chart"


# --------------------------------------------------------------------------------------------
# chart gaps


def test_chart_gap_reasons():
    stderr = (OUTPUTS / "helm-template-missing-deps.stderr.txt").read_text(encoding="utf-8")
    assert chart_gap(stderr) == (GAP_DEPENDENCIES, "missing in charts/: redis, pg")
    reason, detail = chart_gap("Error: template: shop/templates/a.yaml:3:4: bad\n")
    assert reason == GAP_ERROR and detail.startswith("Error: template:")
    assert chart_gap("") == (GAP_EMPTY, "")


# --------------------------------------------------------------------------------------------
# a run with the recorded outputs


def _recorded_runner(*, deps_chart: str = "missing"):
    rendered = OUTPUTS / "helm-template"
    sarif = json.loads((OUTPUTS / "helm-checkov.sarif.json").read_text(encoding="utf-8"))
    deps_stderr = (OUTPUTS / "helm-template-missing-deps.stderr.txt").read_bytes()

    def runner(argv, *, cwd, env, timeout, stdout, stderr):
        if argv[1] == "template":
            chart = Path(argv[3])
            out = Path(argv[argv.index("--output-dir") + 1])
            if chart.name == deps_chart:
                stderr.write(deps_stderr)
                return ProcessOutcome(1)
            shutil.copytree(rendered, out, dirs_exist_ok=True)
            return ProcessOutcome(0)
        doc = json.loads(json.dumps(sarif))
        root = Path(argv[argv.index("-d") + 1])
        [part] = [path.name for path in root.iterdir() if (path / "shop").is_dir()]
        for result in doc["runs"][0]["results"]:
            location = result["locations"][0]["physicalLocation"]["artifactLocation"]
            location["uri"] = f"{part}/{location['uri']}"
        folder = Path(argv[argv.index("--output-file-path") + 1])
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "results_sarif.sarif").write_text(json.dumps(doc), encoding="utf-8")
        return ProcessOutcome(1)

    return runner


def test_run_maps_the_recorded_results_and_records_the_dependency_gap(tmp_path, with_checkov):
    ctx = make_ctx(tmp_path)
    shutil.copytree(CHART, ctx.target_dir / "infra" / "helm" / "shop")
    write(ctx.target_dir / "infra" / "helm" / "missing" / "Chart.yaml", "name: missing\n")
    result = run_adapter(HelmCheckovAdapter(), ctx, runner=_recorded_runner(), resolver=resolver)
    assert result.status == "ok", result.message
    assert result.tool_version == "4.3.0"
    sarif = json.loads((ctx.run_dir / "scans" / "helm-checkov.sarif").read_text(encoding="utf-8"))
    found = ingest_document(sarif, "helm-checkov", ctx.target_dir, "scans/helm-checkov.sarif")
    rows = {(c["rule_id"], c["file"], c["start_line"], c["end_line"]) for c in found.candidates}
    assert rows == {
        ("CKV_K8S_16", "infra/helm/shop/templates/log-agent.yaml", 26, 26),
        ("CKV_K8S_19", "infra/helm/shop/templates/log-agent.yaml", 17, 17),
        ("CKV_K8S_20", "infra/helm/shop/templates/log-agent.yaml", 2, 30),
        ("CKV_K8S_43", "infra/helm/shop/templates/log-agent.yaml", 2, 30),
        ("CKV_K8S_43", "infra/helm/shop/templates/web.yaml", 1, 34),
    }
    assert {c["class"] for c in found.candidates} == {"iac-cloud-container"}
    assert found.warnings == []
    status = json.loads(
        (ctx.run_dir / "scans" / "helm-checkov.status.json").read_text(encoding="utf-8")
    )
    assert status["charts"]["rendered"] == ["infra/helm/shop"]
    assert status["skipped_files"] == {
        "count": 1,
        "reasons": {GAP_DEPENDENCIES: 1},
        "paths": ["infra/helm/missing/Chart.yaml"],
        "truncated": False,
    }
    assert status["chart_gaps"][0]["detail"] == "missing in charts/: redis, pg"
    assert status["mapping"] == {"template-document": 3, "template-key": 2}
    assert status["checkov_version"] == "3.3.22"
    assert len(status["commands"]) == 3
    assert not (ctx.run_dir / "scans" / ".work").exists()


def test_run_without_any_rendered_chart_is_ok_and_empty(tmp_path, with_checkov):
    ctx = make_ctx(tmp_path)
    write(ctx.target_dir / "missing" / "Chart.yaml", "name: missing\n")

    def runner(argv, *, cwd, env, timeout, stdout, stderr):
        if argv[1] == "template":
            stderr.write(b"Error: found in Chart.yaml, but missing in charts/ directory: x\n")
            return ProcessOutcome(1)
        return ProcessOutcome(0)  # Checkov writes no SARIF for an empty folder

    result = run_adapter(HelmCheckovAdapter(), ctx, runner=runner, resolver=resolver)
    assert result.status == "ok", result.message
    assert result.candidates == 0
    status = json.loads(
        (ctx.run_dir / "scans" / "helm-checkov.status.json").read_text(encoding="utf-8")
    )
    assert status["skipped_files"]["count"] == 1


def test_a_missing_sarif_after_a_rendered_chart_fails(tmp_path, with_checkov):
    ctx = make_ctx(tmp_path)
    shutil.copytree(CHART, ctx.target_dir / "shop")

    def runner(argv, *, cwd, env, timeout, stdout, stderr):
        if argv[1] == "template":
            out = Path(argv[argv.index("--output-dir") + 1])
            shutil.copytree(OUTPUTS / "helm-template", out, dirs_exist_ok=True)
        return ProcessOutcome(0)

    result = run_adapter(HelmCheckovAdapter(), ctx, runner=runner, resolver=resolver)
    assert result.status == "failed"
    assert "Checkov wrote no SARIF" in result.message


def test_suppression_sources(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    write(ctx.target_dir / "Chart.yaml", "name: a\n")
    scripts = tmp_path / "pyenv" / ("Scripts" if os.name == "nt" else "bin")
    write(scripts / ("python.exe" if os.name == "nt" else "python"), "")
    entry = write(scripts / "checkov", "")
    monkeypatch.setattr(
        helm_checkov, "checkov_resolver", lambda allow_path=False: checkov_tool(entry)
    )
    adapter = HelmCheckovAdapter()
    adapter.applies(ctx)
    adapter.checkov_command(ctx)
    ignored, honored = adapter.suppression_sources(ctx)
    assert any("config discovery (turned off" in item for item in ignored)
    assert any("checkov.io/skip" in item for item in ignored)
    assert any(".helmignore" in item for item in honored)
    # A Checkov without the tool venv Python (from PATH) cannot run through the launcher.
    monkeypatch.setattr(helm_checkov, "checkov_resolver", lambda allow_path=False: checkov_tool())
    other = HelmCheckovAdapter()
    other.applies(ctx)
    other.checkov_command(ctx)
    ignored, honored = other.suppression_sources(ctx)
    assert ignored == [] and any("could not be turned off" in item for item in honored)
