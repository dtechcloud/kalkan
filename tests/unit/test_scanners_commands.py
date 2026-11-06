# SPDX-License-Identifier: MIT
"""Tests for the ``kalkan scan`` command (kalkan.scanners.commands)."""

from __future__ import annotations

import json
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

from kalkan.cli import main
from kalkan.scanners import commands, registry
from kalkan.scanners.base import ScanResult


@pytest.fixture
def run_dir(tmp_path: Path, monkeypatch) -> SimpleNamespace:
    run = tmp_path / "20261015T120000Z-app-ab12"
    (run / "target").mkdir(parents=True)
    manifest = {"copy": "target", "source_dir": None, "tech": ["python"]}
    (run / "target-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    seen: list[str | None] = []

    def resolve(run_id):
        seen.append(run_id)
        return run

    monkeypatch.setattr(commands, "_resolve_run", resolve)
    return SimpleNamespace(path=run, seen=seen)


def fake_results(monkeypatch, statuses: dict[str, tuple[str, str]]):
    calls: list[tuple[str, object]] = []

    def fake_run(adapter, ctx, *, timeout_seconds=None):
        calls.append((adapter.name, timeout_seconds, ctx))
        status, message = statuses.get(adapter.name, ("ok", "0 candidates"))
        return ScanResult(
            engine=adapter.name,
            status=status,
            output_path=None,
            message=message,
            duration_seconds=0.5,
            exit_code=0,
            tool_version="1.0.0",
            candidates=0 if status == "ok" else None,
        )

    monkeypatch.setattr(commands, "run_adapter", fake_run)
    return calls


def test_scan_all_runs_scanners_in_order(run_dir, monkeypatch, capsys):
    calls = fake_results(monkeypatch, {})
    assert main(["scan", "all"]) == 0
    assert [name for name, _, _ in calls] == [a.name for a in registry.SCANNERS]
    out = capsys.readouterr()
    assert out.out.splitlines()[0].split()[:4] == ["ENGINE", "STATUS", "TIME", "CAND"]
    assert "trivy" in out.out
    assert "kalkan scan: running trivy" in out.err
    assert run_dir.seen == [None]


def test_scan_single_engine_with_options(run_dir, monkeypatch):
    calls = fake_results(monkeypatch, {})
    code = main(
        ["scan", "bandit", "--run", "X", "--timeout", "0", "--offline", "--allow-path-tools"]
    )
    assert code == 0
    [(name, timeout, ctx)] = calls
    assert name == "bandit"
    assert timeout == 0
    assert ctx.offline is True and ctx.allow_path_tools is True
    assert ctx.tech == frozenset({"python"})
    assert run_dir.seen == ["X"]


def test_scan_is_local_by_default_and_online_is_opt_in(run_dir, monkeypatch, capsys):
    calls = fake_results(monkeypatch, {})
    assert main(["scan", "bandit"]) == 0
    assert calls[-1][2].offline is True  # no tool may use the network
    assert main(["scan", "bandit", "--online"]) == 0
    assert calls[-1][2].offline is False
    with pytest.raises(SystemExit):
        main(["scan", "bandit", "--online", "--offline"])


def test_scan_sca_tool_by_name(run_dir, monkeypatch):
    calls = fake_results(monkeypatch, {})
    assert main(["scan", "syft"]) == 0
    assert [name for name, _, _ in calls] == ["syft"]


def test_scan_json_output(run_dir, monkeypatch, capsys):
    fake_results(monkeypatch, {"checkov": ("skipped", "tool not found: checkov is not installed")})
    assert main(["scan", "all", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["run"] == run_dir.path.name
    engines = {item["engine"]: item for item in payload["results"]}
    assert engines["checkov"]["status"] == "skipped"
    assert set(engines["trivy"]) == {
        "engine",
        "status",
        "output",
        "message",
        "duration_seconds",
        "exit_code",
        "tool_version",
        "candidates",
    }


def test_failed_engine_gives_exit_code_1(run_dir, monkeypatch):
    fake_results(monkeypatch, {"opengrep": ("failed", "exit code 2")})
    assert main(["scan", "all"]) == 1


def test_timeout_engine_gives_exit_code_1(run_dir, monkeypatch):
    fake_results(monkeypatch, {"trivy": ("timeout", "timed out after 5 s")})
    assert main(["scan", "trivy"]) == 1


def test_single_engine_with_missing_tool_gives_exit_code_5(run_dir, monkeypatch):
    fake_results(monkeypatch, {"trivy": ("skipped", "tool not found: trivy is not installed")})
    assert main(["scan", "trivy"]) == 5


def test_not_applicable_single_engine_is_ok(run_dir, monkeypatch):
    fake_results(monkeypatch, {"bandit": ("skipped", "no Python code")})
    assert main(["scan", "bandit"]) == 0


def test_unknown_engine_is_a_usage_error(run_dir, monkeypatch, capsys):
    calls = fake_results(monkeypatch, {})
    assert main(["scan", "nope"]) == 2
    assert "unknown engine 'nope'" in capsys.readouterr().err
    assert calls == []


def test_negative_timeout_is_a_usage_error(run_dir, monkeypatch, capsys):
    fake_results(monkeypatch, {})
    assert main(["scan", "all", "--timeout", "-3"]) == 2
    assert "--timeout" in capsys.readouterr().err


def test_missing_manifest_is_an_error(tmp_path, monkeypatch, capsys):
    run = tmp_path / "run"
    run.mkdir()
    monkeypatch.setattr(commands, "_resolve_run", lambda run_id: run)
    assert main(["scan", "all"]) == 1
    assert "target-manifest.json" in capsys.readouterr().err


def test_scan_help_lists_engines(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["scan", "--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    joined = re.sub(r"-\n\s*", "-", out)  # argparse may wrap a name at its hyphen
    assert "--online" in out and "--allow-path-tools" in out and "gitleaks-history" in joined
    assert "helm-checkov" in joined and "vacuum" in joined
    assert "--offline" not in out  # accepted for old scripts, not shown


def test_honor_suppressions_option(run_dir, monkeypatch):
    calls = fake_results(monkeypatch, {})
    assert main(["scan", "bandit"]) == 0
    assert calls[0][2].honor_suppressions is False
    assert main(["scan", "bandit", "--honor-suppressions"]) == 0
    assert calls[1][2].honor_suppressions is True
