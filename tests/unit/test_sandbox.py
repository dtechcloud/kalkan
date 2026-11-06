# SPDX-License-Identifier: MIT
"""Unit tests for the verification sandbox runner (kalkan.sandbox), with a fake container.

No test here starts a real container. The real engine is covered by
``tests/integration/test_sandbox_docker.py`` (marker ``docker``).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from kalkan.sandbox import evidence, runner


def fake_ctx(tmp_path: Path) -> SimpleNamespace:
    target = tmp_path / "run" / "target"
    target.mkdir(parents=True)
    (target / "app.py").write_text("x = 1\n", encoding="utf-8")
    return SimpleNamespace(
        run_dir=tmp_path / "run", run_id="20260101T000000Z-x-abcd", target_dir=target
    )


def harness(**over):
    base = {
        "finding_id": "KF-0000000000000001",
        "level": "unit",
        "base_image": "python:3.12-slim",
        "files": [{"path": "poc.py", "content": "print('hi')\n"}],
        "command": ["python", "/poc/poc.py"],
        "success_regex": "KALKAN_POC_OK",
    }
    base.update(over)
    return base


@pytest.fixture
def ready(monkeypatch):
    """Make the runner think Docker and the image are present."""
    monkeypatch.setattr(runner, "docker_path", lambda: Path("docker"))
    monkeypatch.setattr(runner, "docker_available", lambda: True)
    monkeypatch.setattr(runner, "_image_present", lambda docker, ref: True)


def run_with(monkeypatch, capture: runner._Capture, record: list):
    def fake_run(argv, *, timeout, name, out_dir):
        record.append(argv)
        return capture

    monkeypatch.setattr(runner, "_run_bounded", fake_run)


def test_allowlist_has_seven_images():
    images = runner.allowed_images()
    assert "python:3.12-slim" in images and len(images) == 7
    assert "mcr.microsoft.com/dotnet/sdk:10.0" in images


def test_the_allowlist_and_the_poc_build_schema_agree():
    import json

    from kalkan.schema.loader import load_schema

    text = json.dumps(load_schema("task-poc_build"))
    for image in runner.allowed_images():
        assert f'"{image}"' in text


def test_a_dotnet_harness_runs_offline_without_telemetry(tmp_path, monkeypatch, ready):
    ctx = fake_ctx(tmp_path)
    argv: list = []
    run_with(monkeypatch, runner._Capture(0, "KALKAN_POC_OK\n", ""), argv)
    runner.run_poc(ctx, "T0001-poc_build", harness(base_image="mcr.microsoft.com/dotnet/sdk:10.0"))
    flat = argv[0]
    envs = [flat[i + 1] for i, a in enumerate(flat) if a == "--env"]
    for value in (
        "DOTNET_CLI_TELEMETRY_OPTOUT=1",
        "DOTNET_CLI_HOME=/tmp",
        "NUGET_PACKAGES=/tmp/.nuget",
    ):
        assert value in envs
    assert "--network" in flat and flat[flat.index("--network") + 1] == "none"
    assert runner.image_env("python:3.12-slim") == []


def test_docker_available_is_forced_off_in_tests():
    # The autouse fixture of tests/conftest.py sets KALKAN_SANDBOX_FORCE_UNAVAILABLE.
    assert runner.docker_available() is False


def test_passed_when_the_success_pattern_matches(tmp_path, monkeypatch, ready):
    ctx = fake_ctx(tmp_path)
    argv: list = []
    run_with(monkeypatch, runner._Capture(0, "line one\nKALKAN_POC_OK rows crossed\n", ""), argv)
    result = runner.run_poc(ctx, "T0001-poc_build", harness())
    assert result["status"] == "passed"
    assert result["observed_result"] == "KALKAN_POC_OK rows crossed"
    assert "evidence/KF-0000000000000001/stdout.txt" in result["artifacts"]


def test_the_container_runs_under_the_isolation_profile(tmp_path, monkeypatch, ready):
    ctx = fake_ctx(tmp_path)
    argv: list = []
    run_with(monkeypatch, runner._Capture(0, "KALKAN_POC_OK\n", ""), argv)
    runner.run_poc(ctx, "T0001-poc_build", harness())
    flat = argv[0]
    for flag in (
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "--memory",
    ):
        assert flag in flat
    assert "65534:65534" in flat
    mounts = [flat[i + 1] for i, a in enumerate(flat) if a == "--mount"]
    assert any(m.endswith(",readonly") and "/target" in m for m in mounts)
    assert any(m.endswith(",readonly") and "/poc" in m for m in mounts)
    assert any("/out" in m and not m.endswith(",readonly") for m in mounts)


def test_failed_when_no_match(tmp_path, monkeypatch, ready):
    ctx = fake_ctx(tmp_path)
    run_with(monkeypatch, runner._Capture(1, "KALKAN_POC_FAIL no effect\n", ""), [])
    result = runner.run_poc(ctx, "T0001-poc_build", harness())
    assert result["status"] == "failed"
    assert result["observed_result"] == "KALKAN_POC_FAIL no effect"


def test_timeout_is_blocked(tmp_path, monkeypatch, ready):
    ctx = fake_ctx(tmp_path)
    run_with(monkeypatch, runner._Capture(None, "", "", timed_out=True), [])
    result = runner.run_poc(ctx, "T0001-poc_build", harness())
    assert result["status"] == "blocked" and result["blocker"] == "sandbox_timeout"


def test_missing_image_is_blocked(tmp_path, monkeypatch, ready):
    ctx = fake_ctx(tmp_path)
    monkeypatch.setattr(runner, "_image_present", lambda docker, ref: False)
    result = runner.run_poc(ctx, "T0001-poc_build", harness())
    assert result["status"] == "blocked" and result["blocker"] == "sandbox_image_missing"
    assert "kalkan sandbox pull" in result["observed_result"]


def test_app_level_goes_to_the_app_runner(tmp_path, monkeypatch, ready):
    ctx = fake_ctx(tmp_path)
    result = runner.run_poc(ctx, "T0001-poc_build", harness(level="app"))
    # The harness has no app section: the app runner blocks it, it is never run as a unit.
    assert result["status"] == "blocked" and result["level"] == "app"
    assert result["blocker"] == "sandbox_error"


def test_a_bad_success_pattern_is_blocked(tmp_path, monkeypatch, ready):
    ctx = fake_ctx(tmp_path)
    result = runner.run_poc(ctx, "T0001-poc_build", harness(success_regex="(unclosed"))
    assert result["status"] == "blocked" and result["blocker"] == "sandbox_error"


def test_no_docker_is_blocked_unavailable(tmp_path, monkeypatch):
    ctx = fake_ctx(tmp_path)
    monkeypatch.setattr(runner, "docker_path", lambda: None)
    result = runner.run_poc(ctx, "T0001-poc_build", harness())
    assert result["status"] == "blocked" and result["blocker"] == "sandbox_unavailable"


def test_an_image_outside_the_allowlist_is_blocked(tmp_path, ready):
    ctx = fake_ctx(tmp_path)
    result = runner.run_poc(ctx, "T0001-poc_build", harness(base_image="alpine:latest"))
    assert result["status"] == "blocked" and result["blocker"] == "sandbox_image_not_allowed"


def test_the_record_carries_the_run_facts(tmp_path, monkeypatch, ready):
    ctx = fake_ctx(tmp_path)
    run_with(monkeypatch, runner._Capture(3, "KALKAN_POC_OK\n", "", truncated=True), [])
    result = runner.run_poc(ctx, "T0001-poc_build", harness())
    assert result["exit_code"] == 3 and result["output_truncated"] is True
    assert result["started_at"].endswith("Z") and result["duration_ms"] >= 0


def test_an_out_folder_over_the_limit_is_blocked_and_deleted(tmp_path, monkeypatch, ready):
    ctx = fake_ctx(tmp_path)
    capture = runner._Capture(None, "KALKAN_POC_OK\n", "", out_limit="more than 64 MiB")

    def fake_run(argv, *, timeout, name, out_dir):
        (out_dir / "big.bin").write_bytes(b"x" * 10)
        return capture

    monkeypatch.setattr(runner, "_run_bounded", fake_run)
    result = runner.run_poc(ctx, "T0001-poc_build", harness())
    assert result["status"] == "blocked" and result["blocker"] == "sandbox_output_limit"
    assert not (ctx.run_dir / "poc" / "KF-0000000000000001" / "out").exists()
    assert not (ctx.run_dir / "evidence" / "KF-0000000000000001" / "big.bin").exists()


def test_secrets_in_the_output_and_the_evidence_are_redacted(tmp_path, monkeypatch, ready):
    ctx = fake_ctx(tmp_path)
    key = "AKIA" + "ABCDEFGHIJKLMNOP"
    capture = runner._Capture(0, f"KALKAN_POC_OK leaked {key}\npassword=hunter2hunter2\n", "")

    def fake_run(argv, *, timeout, name, out_dir):
        (out_dir / "dump.txt").write_text(f"DB_PASSWORD={key}x\n", encoding="utf-8")
        return capture

    monkeypatch.setattr(runner, "_run_bounded", fake_run)
    result = runner.run_poc(ctx, "T0001-poc_build", harness())
    assert result["status"] == "passed"
    assert key not in result["observed_result"] and "[REDACTED]" in result["observed_result"]
    evidence_dir = ctx.run_dir / "evidence" / "KF-0000000000000001"
    stdout = (evidence_dir / "stdout.txt").read_text(encoding="utf-8")
    assert key not in stdout and "hunter2hunter2" not in stdout
    assert key not in (evidence_dir / "dump.txt").read_text(encoding="utf-8")


def test_out_usage_reports_the_byte_and_the_file_limit(tmp_path):
    out = tmp_path / "out"
    (out / "sub").mkdir(parents=True)
    (out / "sub" / "a.bin").write_bytes(b"x" * 100)
    assert runner.out_usage(out, max_bytes=1000, max_files=10) is None
    assert runner.out_usage(out, max_bytes=50, max_files=10) == "more than 0 MiB"
    for i in range(5):
        (out / f"f{i}").write_bytes(b"")
    assert runner.out_usage(out, max_bytes=1000, max_files=3) == "more than 3 files"


def test_the_bounded_run_keeps_only_the_output_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "OUTPUT_CAP_BYTES", 1000)
    monkeypatch.setattr(runner, "_force_remove", lambda name: None)
    out = tmp_path / "out"
    out.mkdir()
    code = "import sys; sys.stdout.write('A' * 200000); sys.stderr.write('B' * 10)"
    capture = runner._run_bounded(
        [sys.executable, "-c", code], timeout=60, name="unused", out_dir=out
    )
    assert capture.exit_code == 0 and capture.truncated
    assert capture.stdout == "A" * 1000 and capture.stderr == "B" * 10


def test_the_bounded_run_stops_on_the_timeout(tmp_path, monkeypatch):
    removed: list[str] = []
    monkeypatch.setattr(runner, "_force_remove", removed.append)
    out = tmp_path / "out"
    out.mkdir()
    capture = runner._run_bounded(
        [sys.executable, "-c", "import time; time.sleep(30)"], timeout=1, name="c1", out_dir=out
    )
    assert capture.timed_out and capture.exit_code is None and removed == ["c1"]


def test_the_bounded_run_stops_when_out_grows_too_big(tmp_path, monkeypatch):
    removed: list[str] = []
    monkeypatch.setattr(runner, "_force_remove", removed.append)
    monkeypatch.setattr(runner, "OUT_MAX_BYTES", 1000)
    out = tmp_path / "out"
    out.mkdir()
    grow = (out / "grow.bin").as_posix()
    code = f"import pathlib, time; pathlib.Path({grow!r}).write_bytes(b'x' * 5000); time.sleep(30)"
    capture = runner._run_bounded([sys.executable, "-c", code], timeout=60, name="c2", out_dir=out)
    assert capture.out_limit and capture.exit_code is None and removed == ["c2"]


# ---------------------------------------------------------------------------------------------
# Evidence promotion


def test_promote_copies_regular_files_only(tmp_path):
    out = tmp_path / "out"
    (out / "sub").mkdir(parents=True)
    (out / "result.txt").write_text("ok", encoding="utf-8")
    (out / "sub" / "more.log").write_text("log", encoding="utf-8")
    dest = tmp_path / "evidence"
    written = evidence.promote(out, dest)
    names = sorted(p.relative_to(dest).as_posix() for p in written)
    assert names == ["result.txt", "sub/more.log"]
    assert (dest / "result.txt").read_text(encoding="utf-8") == "ok"


def test_promote_skips_oversize_and_respects_the_count_limit(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    (out / "big.bin").write_bytes(b"x" * 1024)
    for i in range(5):
        (out / f"f{i}.txt").write_text("y", encoding="utf-8")
    written = evidence.promote(out, tmp_path / "e", max_files=2, max_file_bytes=16)
    assert len(written) == 2
    assert all(p.name != "big.bin" for p in written)


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink semantics")
def test_promote_never_follows_a_symlink(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    secret = tmp_path / "secret.txt"
    secret.write_text("do not copy", encoding="utf-8")
    os.symlink(secret, out / "link.txt")
    (out / "real.txt").write_text("copy me", encoding="utf-8")
    written = evidence.promote(out, tmp_path / "e")
    assert [p.name for p in written] == ["real.txt"]


def test_promote_ignores_a_nonexistent_out_dir(tmp_path):
    assert evidence.promote(tmp_path / "nope", tmp_path / "e") == []
