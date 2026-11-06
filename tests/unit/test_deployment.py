# SPDX-License-Identifier: MIT
"""Unit tests for the deployment scope of findings (kalkan.findings.deployment, N.2)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kalkan.cli import main
from kalkan.findings.deployment import (
    SCOPE_LIVE,
    SCOPE_TEMPLATE,
    check_live_paths,
    deployment_kind,
    deployment_scope,
    scan_deployments,
)
from kalkan.report.model import ReportModel
from kalkan.report.render_exec import posture, render_executive, top_findings


def make_target(root: Path) -> Path:
    files = {
        "docker-compose.yml": "services:\n  redis:\n    image: redis\n",
        "deploy/compose.prod.yaml": "services: {}\n",
        "charts/app/Chart.yaml": "name: app\n",
        "charts/app/templates/deploy.yaml": "kind: Deployment\n",
        "ops/helmish/Chart.yaml": "name: other\n",
        "ops/helmish/values.yaml": "replicas: 2\n",
        "k8s/aks/deployment.yaml": "apiVersion: apps/v1\nkind: Deployment\n",
        "infra/main.tf": 'resource "x" "y" {}\n',
        "app/settings.yaml": "debug: true\n",
        "app/main.py": "print('hi')\n",
        "Dockerfile": "FROM python:3.12\n",
    }
    for name, body in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    return root


def finding(*files: str, severity: str = "high", number: int = 1) -> dict:
    return {
        "verdict": "confirmed",
        "id": f"KF-{number:016X}",
        "fingerprint": f"fp-{number}",
        "title": f"Finding {number}",
        "class": "misconfiguration",
        "trace": [{"kind": "sink", "file": files[0], "line": 1}],
        "evidence": [{"file": file, "line": 1} for file in files[1:]],
        "severity": {
            "likelihood": {"score": "medium", "reason": "r"},
            "impact": {"score": severity, "reason": "r"},
            "overall_severity": severity,
        },
        "remediation": {"strategy": "Fix it."},
    }


def test_deployment_kinds_from_the_name():
    assert deployment_kind("docker-compose.yml") == "compose"
    assert deployment_kind("deploy/compose.prod.yaml") == "compose"
    assert deployment_kind("charts/app/templates/x.yaml") == "helm"
    assert deployment_kind("infra/main.tf") == "terraform"
    assert deployment_kind("k8s/kustomization.yaml") == "kustomize"
    assert deployment_kind("app/settings.yaml") is None
    assert deployment_kind("Dockerfile") is None
    assert deployment_kind("k8s/a.yaml", "apiVersion: v1\nkind: Service\n") == "kubernetes"


def test_scan_lists_the_sets_and_never_counts_application_files(tmp_path):
    scan = scan_deployments(make_target(tmp_path))
    sets = {(item.kind, item.path) for item in scan.sets}
    assert sets == {
        ("compose", "docker-compose.yml"),
        ("compose", "deploy/compose.prod.yaml"),
        ("helm", "charts/app"),
        ("helm", "ops/helmish"),
        ("kubernetes", "k8s/aks"),
        ("terraform", "infra"),
    }
    assert "ops/helmish/values.yaml" in scan.files
    for app_file in ("app/settings.yaml", "app/main.py", "Dockerfile"):
        assert app_file not in scan.files


def test_the_scope_rule_is_conservative(tmp_path):
    files = set(scan_deployments(make_target(tmp_path)).files)
    is_deploy = files.__contains__
    live = ["k8s/aks"]
    assert deployment_scope(finding("docker-compose.yml"), live, is_deploy) == SCOPE_TEMPLATE
    assert deployment_scope(finding("k8s/aks/deployment.yaml"), live, is_deploy) == SCOPE_LIVE
    # A finding that also touches application code is never template only.
    mixed = finding("docker-compose.yml", "app/main.py")
    assert deployment_scope(mixed, live, is_deploy) is None
    # Any file in the live deployment makes the finding live.
    both = finding("docker-compose.yml", "k8s/aks/deployment.yaml")
    assert deployment_scope(both, live, is_deploy) == SCOPE_LIVE
    # Without a live path nothing is classified.
    assert deployment_scope(finding("docker-compose.yml"), [], is_deploy) is None


def test_code_that_production_does_not_load_is_template_by_its_sinks(tmp_path):
    files = set(scan_deployments(make_target(tmp_path)).files)
    is_deploy = files.__contains__
    live, not_live = ["k8s/aks"], ["app/compose_plugin"]
    # The vulnerable operation runs only in the not-live plugin: template, also from live code.
    called = {
        "trace": [
            {"kind": "entrypoint", "file": "app/main.py", "line": 1},
            {"kind": "sink", "file": "app/compose_plugin/run.py", "line": 9},
        ],
        "evidence": [{"file": "app/main.py", "line": 2}],
    }
    assert deployment_scope(called, live, is_deploy, not_live) == SCOPE_TEMPLATE
    assert deployment_scope(called, [], is_deploy, not_live) == SCOPE_TEMPLATE
    # One sink in live code keeps the finding out of the template class.
    shared = {
        "trace": [
            {"kind": "sink", "file": "app/compose_plugin/run.py", "line": 9},
            {"kind": "sink", "file": "app/main.py", "line": 1},
        ]
    }
    assert deployment_scope(shared, live, is_deploy, not_live) is None
    # A sink in an unused deployment file alone is not enough: the plugin path names code only.
    mixed = finding("docker-compose.yml", "app/main.py")
    assert deployment_scope(mixed, live, is_deploy, not_live) is None
    assert (
        deployment_scope(
            finding("docker-compose.yml", "app/compose_plugin/x.py"), live, is_deploy, not_live
        )
        == SCOPE_TEMPLATE
    )
    # A live path wins over a not-live path.
    assert deployment_scope(finding("k8s/aks/deployment.yaml"), live, is_deploy, ["k8s"]) == (
        SCOPE_LIVE
    )
    # Without a not-live path an application sink keeps the old rule.
    assert deployment_scope(called, live, is_deploy) is None


@pytest.mark.parametrize("bad", ["../outside", "/abs/path", "", "a/../../b"])
def test_unsafe_live_paths_are_refused(bad):
    with pytest.raises(ValueError):
        check_live_paths([bad])


def test_a_missing_live_path_is_refused(tmp_path):
    make_target(tmp_path)
    assert check_live_paths(["k8s\\aks\\"], tmp_path) == ["k8s/aks"]
    with pytest.raises(ValueError, match="no such file"):
        check_live_paths(["k8s/gke"], tmp_path)


def test_the_overall_risk_leaves_template_findings_out(tmp_path):
    files = frozenset(scan_deployments(make_target(tmp_path)).files)
    template = finding("docker-compose.yml", severity="high", number=1)
    live = finding("app/main.py", severity="medium", number=2)
    model = ReportModel(
        run_id="20261102T000000Z-app-0000",
        run_lang="en",
        generated_at="2026-11-02T00:00:00Z",
        kalkan_version="0.0.0-test",
        findings_available=True,
        confirmed=[template, live],
        live_paths=["k8s/aks"],
        deployment_files=files,
    )
    assert posture(model) == "medium"
    assert model.template_confirmed == [template]
    assert [item["id"] for item in top_findings(model)] == [live["id"], template["id"]]
    page = render_executive(model, "en")
    assert "(template only)" in page
    assert "Live deployment: k8s/aks." in page
    # Without the live path both count, and the page names the deployments of the repository.
    model.live_paths = []
    model.deployments = [{"kind": "compose", "path": "docker-compose.yml", "files": 1}]
    assert posture(model) == "high"
    page = render_executive(model, "en")
    assert "Nobody named the one that runs in production" in page
    assert "<code>kalkan run set --live &lt;path&gt;</code>" in page
    # Code that production does not load: the page names it and counts the template findings.
    model.not_live_paths = ["app"]
    assert model.template_confirmed == [live]
    page = render_executive(model, "en")
    assert "Code that production does not load: app." in page
    assert "left out of the overall risk: 1." in page
    assert "not live app" in model.run_type()


def test_run_init_and_run_set_store_the_live_paths(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("KALKAN_RUNS_DIR", str(tmp_path / "runs"))
    target = make_target(tmp_path / "target")
    assert main(["run", "init", str(target), "--live", "k8s/aks", "--json"]) == 0
    run_id = json.loads(capsys.readouterr().out)["run_id"]
    run_dir = tmp_path / "runs" / run_id
    state = json.loads((run_dir / "state.json").read_text(encoding="utf-8"))
    assert state["options"]["live_paths"] == ["k8s/aks"]
    manifest = json.loads((run_dir / "target-manifest.json").read_text(encoding="utf-8"))
    assert {"kind": "kubernetes", "path": "k8s/aks", "files": 1} in manifest["deployments"]["sets"]

    assert main(["run", "set", "--live", "charts/app", "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["live_paths"] == ["charts/app"] and out["previous_live_paths"] == ["k8s/aks"]
    assert main(["run", "set", "--no-live", "--json"]) == 0
    capsys.readouterr()
    state = json.loads((run_dir / "state.json").read_text(encoding="utf-8"))
    assert "live_paths" not in state["options"]

    assert main(["run", "set", "--not-live", "app", "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["not_live_paths"] == ["app"] and out["previous_not_live_paths"] == []
    assert main(["run", "set", "--not-live", "app/missing", "--json"]) != 0
    assert main(["run", "set", "--no-not-live", "--json"]) == 0
    capsys.readouterr()
    state = json.loads((run_dir / "state.json").read_text(encoding="utf-8"))
    assert "not_live_paths" not in state["options"]


def test_run_init_stores_the_not_live_paths(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("KALKAN_RUNS_DIR", str(tmp_path / "runs"))
    target = make_target(tmp_path / "target")
    assert main(["run", "init", str(target), "--not-live", "app\\", "--json"]) == 0
    run_id = json.loads(capsys.readouterr().out)["run_id"]
    state = json.loads((tmp_path / "runs" / run_id / "state.json").read_text(encoding="utf-8"))
    assert state["options"]["not_live_paths"] == ["app"]
    assert main(["run", "init", str(target), "--not-live", "../etc", "--json"]) != 0
    capsys.readouterr()


def test_run_init_refuses_a_live_path_outside_the_target(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("KALKAN_RUNS_DIR", str(tmp_path / "runs"))
    target = make_target(tmp_path / "target")
    assert main(["run", "init", str(target), "--live", "../etc", "--json"]) != 0
    assert main(["run", "init", str(target), "--live", "k8s/missing", "--json"]) != 0
    capsys.readouterr()
