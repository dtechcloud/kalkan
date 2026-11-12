# SPDX-License-Identifier: MIT
"""Unit tests for the app-level sandbox policy (kalkan.sandbox.app), without Docker."""

from __future__ import annotations

from pathlib import Path

import pytest

from kalkan.sandbox import app


def service(**extra):
    base = {"image": "python:3.12-slim", "command": ["python", "-m", "http.server"]}
    base.update(extra)
    return base


def config(**services):
    return {"services": services or {"web": service()}}


def test_a_plain_stack_passes(tmp_path):
    assert app.policy_errors(config(), tmp_path) == []


@pytest.mark.parametrize(
    ("extra", "reason"),
    [
        ({"privileged": True}, "privileged"),
        ({"network_mode": "host"}, "network mode"),
        ({"pid": "host"}, "PID"),
        ({"ipc": "host"}, "IPC"),
        ({"cap_add": ["SYS_ADMIN"]}, "capabilities"),
        ({"devices": ["/dev/kmsg"]}, "devices"),
        ({"security_opt": ["seccomp=unconfined"]}, "security_opt"),
        ({"runtime": "runc-custom"}, "runtime"),
        ({"sysctls": {"net.ipv4.ip_forward": "1"}}, "kernel"),
    ],
)
def test_dangerous_service_settings_are_refused(tmp_path, extra, reason):
    errors = app.policy_errors(config(web=service(**extra)), tmp_path)
    assert errors and reason in errors[0]


def test_binds_outside_the_target_and_the_docker_socket_are_refused(tmp_path):
    inside = tmp_path / "public"
    inside.mkdir()
    outside = tmp_path.parent
    volumes = [
        {"type": "bind", "source": str(inside), "target": "/srv"},
        {"type": "bind", "source": str(outside), "target": "/host"},
        {"type": "bind", "source": "/var/run/docker.sock", "target": "/var/run/docker.sock"},
    ]
    errors = app.policy_errors(config(web=service(volumes=volumes)), tmp_path)
    assert any("outside the target" in e for e in errors)
    assert any("Docker socket" in e for e in errors)
    assert len(errors) == 2


def test_external_resources_and_outside_build_contexts_are_refused(tmp_path):
    document = config(web=service(build={"context": str(tmp_path.parent)}))
    document["volumes"] = {"data": {"external": True}}
    document["secrets"] = {"key": {"file": str(tmp_path.parent / "key.pem")}}
    errors = app.policy_errors(document, tmp_path)
    assert any("build context outside" in e for e in errors)
    assert any("volumes.data: external" in e for e in errors)
    assert any("secrets.key" in e for e in errors)


def test_sanitize_puts_every_service_on_one_internal_network(tmp_path):
    inside = tmp_path / "public"
    inside.mkdir()
    web = service(
        ports=[{"target": 8000, "published": "8000"}],
        networks={"front": None},
        volumes=[{"type": "bind", "source": str(inside), "target": "/srv"}],
        depends_on={"db": {"condition": "service_started"}},
        labels={"a": "b"},
    )
    clean = app.sanitize(config(web=web, db=service(image="redis:7")), tmp_path)
    assert clean["networks"] == {"kalkan": {"internal": True}}
    for item in clean["services"].values():
        assert item["networks"] == ["kalkan"]
        assert item["cap_drop"] == ["ALL"]
        assert set(item["cap_add"]) <= set(app.SERVICE_CAPS)
        assert item["security_opt"] == ["no-new-privileges:true"]
        assert "ports" not in item and "labels" not in item
    assert clean["services"]["web"]["volumes"][0]["read_only"] is True
    assert clean["services"]["web"]["depends_on"] == ["db"]


def test_compose_runs_without_host_secrets(monkeypatch):
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "do-not-leak")
    monkeypatch.setenv("PATH", "/usr/bin")
    env = app.compose_env()
    assert "AWS_SECRET_ACCESS_KEY" not in env and env["PATH"] == "/usr/bin"


def test_project_names_fit_compose_rules():
    name = app.project_name("20261102T000000Z-Shop.App-ab12", "T0042-poc_build")
    assert name == name.lower() and len(name) <= 60
    assert all(ch.isalnum() or ch in "-_" for ch in name)


def test_an_app_harness_outside_the_target_is_blocked(tmp_path):
    from types import SimpleNamespace

    target = tmp_path / "target"
    target.mkdir()
    ctx = SimpleNamespace(run_dir=tmp_path, run_id="r", target_dir=target, options={})
    harness = {
        "finding_id": "KF-1",
        "level": "app",
        "success_regex": "x",
        "app": {"compose_file": "../compose.yml", "service": "web", "port": 80, "requests": []},
    }
    result = app.run_app_poc(ctx, "T0001-poc_build", harness, Path("docker"))
    assert result["status"] == "blocked" and result["level"] == "app"
    assert "inside the target" in result["observed_result"]
