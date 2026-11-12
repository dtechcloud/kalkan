# SPDX-License-Identifier: MIT
"""End-to-end checks of the verification sandbox with a real Docker engine (marker ``docker``).

Each test proves one property of the isolation profile with a small, benign harness: the target
is mounted read-only, the container has no network, and the harness output decides the verdict.
The tests skip when Docker or the base image ``python:3.12-slim`` is not present. The autouse
fixture of ``tests/conftest.py`` restores the real Docker check for a ``docker``-marked test.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from kalkan.sandbox import runner

pytestmark = pytest.mark.docker

IMAGE = "python:3.12-slim"


def _require_docker() -> None:
    if not runner.docker_available():
        pytest.skip("no Docker engine")
    if not runner._image_present(runner.docker_path(), IMAGE):
        pytest.skip(f"base image {IMAGE} not pulled (kalkan sandbox pull {IMAGE})")


def _ctx(tmp_path: Path) -> SimpleNamespace:
    target = tmp_path / "run" / "target"
    target.mkdir(parents=True)
    (target / "app.py").write_text("GREETING = 'hello from target'\n", encoding="utf-8")
    return SimpleNamespace(
        run_dir=tmp_path / "run", run_id="20260101T000000Z-s-abcd", target_dir=target
    )


def _harness(code: str, **over) -> dict:
    base = {
        "finding_id": "KF-0000000000000001",
        "level": "unit",
        "base_image": IMAGE,
        "files": [{"path": "poc.py", "content": code}],
        "command": ["python", "/poc/poc.py"],
        "success_regex": "KALKAN_POC_OK",
    }
    base.update(over)
    return base


def test_the_harness_reads_the_read_only_target(tmp_path):
    _require_docker()
    code = (
        "import sys\n"
        "sys.path.insert(0, '/target')\n"
        "import app\n"
        "print('KALKAN_POC_OK read', app.GREETING)\n"
    )
    result = runner.run_poc(_ctx(tmp_path), "T0001-poc_build", _harness(code))
    assert result["status"] == "passed"
    assert "hello from target" in result["observed_result"]
    assert result["artifacts"]


def test_the_container_has_no_network(tmp_path):
    _require_docker()
    code = (
        "import socket\n"
        "try:\n"
        "    socket.create_connection(('192.0.2.1', 53), timeout=3)\n"
        "    print('KALKAN_POC_FAIL network reachable')\n"
        "except OSError:\n"
        "    print('KALKAN_POC_OK network blocked')\n"
    )
    result = runner.run_poc(_ctx(tmp_path), "T0001-poc_build", _harness(code))
    assert result["status"] == "passed"
    assert "network blocked" in result["observed_result"]


def test_the_target_mount_is_read_only(tmp_path):
    _require_docker()
    code = (
        "try:\n"
        "    open('/target/app.py', 'a').write('tampered')\n"
        "    print('KALKAN_POC_FAIL target writable')\n"
        "except OSError:\n"
        "    print('KALKAN_POC_OK target read-only')\n"
    )
    ctx = _ctx(tmp_path)
    before = (ctx.target_dir / "app.py").read_text(encoding="utf-8")
    result = runner.run_poc(ctx, "T0001-poc_build", _harness(code))
    assert result["status"] == "passed"
    assert (ctx.target_dir / "app.py").read_text(encoding="utf-8") == before


def _no_container_left(name_part: str) -> bool:
    docker = runner.docker_path()
    listing = subprocess.run(
        [str(docker), "ps", "-a", "--filter", f"name={name_part}", "--format", "{{.Names}}"],
        capture_output=True,
        text=True,
        check=False,
    )
    return listing.returncode == 0 and not listing.stdout.strip()


def test_only_the_three_bind_mounts_reach_the_container(tmp_path):
    _require_docker()
    # The host home, the original repository and any other host folder stay outside: the
    # container sees exactly /target, /poc and /out from the host.
    code = (
        "binds = sorted(line.split()[4] for line in open('/proc/self/mountinfo')\n"
        "               if line.split()[4] in ('/target', '/poc', '/out')\n"
        "               or line.split()[3] not in ('/',))\n"
        "print('KALKAN_POC_OK mounts', binds)\n"
    )
    result = runner.run_poc(_ctx(tmp_path), "T0001-poc_build", _harness(code))
    assert result["status"] == "passed"
    for mount in ("/target", "/poc", "/out"):
        assert mount in result["observed_result"]
    home = Path.home().as_posix().split("/")[-1]
    assert home not in result["observed_result"]


def test_the_harness_runs_as_nobody_without_capabilities(tmp_path):
    _require_docker()
    code = (
        "import os\n"
        "caps = [l.split()[1] for l in open('/proc/self/status') if l.startswith('CapEff')][0]\n"
        "ok = os.getuid() == 65534 and os.getgid() == 65534 and int(caps, 16) == 0\n"
        "fail = f'KALKAN_POC_FAIL uid={os.getuid()} caps={caps}'\n"
        "print('KALKAN_POC_OK nobody' if ok else fail)\n"
    )
    result = runner.run_poc(_ctx(tmp_path), "T0001-poc_build", _harness(code))
    assert result["status"] == "passed", result["observed_result"]


def test_the_root_filesystem_is_read_only(tmp_path):
    _require_docker()
    code = (
        "try:\n"
        "    open('/usr/kalkan-probe', 'w').write('x')\n"
        "    print('KALKAN_POC_FAIL root writable')\n"
        "except OSError:\n"
        "    print('KALKAN_POC_OK root read-only')\n"
    )
    result = runner.run_poc(_ctx(tmp_path), "T0001-poc_build", _harness(code))
    assert result["status"] == "passed"


def test_the_memory_limit_stops_a_large_allocation(tmp_path):
    _require_docker()
    code = "block = bytearray(900 * 1024 * 1024)\nprint('KALKAN_POC_OK allocated', len(block))\n"
    result = runner.run_poc(_ctx(tmp_path), "T0001-poc_build", _harness(code))
    assert result["status"] == "failed"
    assert result.get("exit_code") not in (0, None)


def test_the_pid_limit_stops_a_process_flood(tmp_path):
    _require_docker()
    code = (
        "import subprocess\n"
        "procs = []\n"
        "try:\n"
        "    for _ in range(400):\n"
        "        procs.append(subprocess.Popen(['sleep', '20']))\n"
        "    print('KALKAN_POC_FAIL started', len(procs))\n"
        "except OSError as exc:\n"
        "    print('KALKAN_POC_OK pid limit after', len(procs), type(exc).__name__)\n"
        "finally:\n"
        "    for p in procs:\n"
        "        p.kill()\n"
    )
    result = runner.run_poc(_ctx(tmp_path), "T0001-poc_build", _harness(code))
    assert result["status"] == "passed", result["observed_result"]


def test_the_timeout_stops_and_removes_the_container(tmp_path, monkeypatch):
    _require_docker()
    monkeypatch.setattr(runner, "UNIT_TIMEOUT_SECONDS", 5)
    code = "import time\ntime.sleep(120)\nprint('KALKAN_POC_OK never')\n"
    ctx = _ctx(tmp_path)
    result = runner.run_poc(ctx, "T0009-poc_build", _harness(code))
    assert result["status"] == "blocked" and result["blocker"] == "sandbox_timeout"
    assert result["duration_ms"] < 60_000
    assert _no_container_left("T0009-poc_build")


def test_a_finished_container_is_removed(tmp_path):
    _require_docker()
    result = runner.run_poc(
        _ctx(tmp_path), "T0008-poc_build", _harness("print('KALKAN_POC_OK done')\n")
    )
    assert result["status"] == "passed" and result["exit_code"] == 0
    assert _no_container_left("T0008-poc_build")


def test_the_out_watchdog_stops_a_harness_that_fills_the_disk(tmp_path, monkeypatch):
    _require_docker()
    monkeypatch.setattr(runner, "OUT_MAX_BYTES", 1024 * 1024)
    code = (
        "import time\n"
        "with open('/out/fill.bin', 'wb') as f:\n"
        "    for _ in range(50):\n"
        "        f.write(b'x' * 1024 * 1024)\n"
        "        f.flush()\n"
        "        time.sleep(0.1)\n"
        "print('KALKAN_POC_OK wrote 50 MiB')\n"
    )
    ctx = _ctx(tmp_path)
    result = runner.run_poc(ctx, "T0007-poc_build", _harness(code))
    assert result["status"] == "blocked" and result["blocker"] == "sandbox_output_limit"
    assert not (ctx.run_dir / "poc" / "KF-0000000000000001" / "out").exists()
    assert _no_container_left("T0007-poc_build")


DOTNET = "mcr.microsoft.com/dotnet/sdk:10.0"


def test_a_csharp_harness_builds_and_runs_offline(tmp_path):
    _require_docker()
    if not runner._image_present(runner.docker_path(), DOTNET):
        pytest.skip(f"base image {DOTNET} not pulled (kalkan sandbox pull {DOTNET})")
    ctx = _ctx(tmp_path)
    (ctx.target_dir / "PathHelper.cs").write_text(
        "namespace Shop;\npublic static class PathHelper\n{\n"
        "    public static string Resolve(string root, string name) =>\n"
        "        System.IO.Path.Combine(root, name);\n}\n",
        encoding="utf-8",
    )
    project = (
        '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType>'
        "<TargetFramework>net10.0</TargetFramework><ImplicitUsings>enable</ImplicitUsings>"
        '</PropertyGroup><ItemGroup><Compile Include="/target/PathHelper.cs" /></ItemGroup>'
        "</Project>\n"
    )
    program = (
        'var full = System.IO.Path.GetFullPath(Shop.PathHelper.Resolve("/srv", "../etc/passwd"));\n'
        'Console.WriteLine(full.StartsWith("/srv/") ? "KALKAN_POC_FAIL inside" : '
        '$"KALKAN_POC_OK escaped {full}");\n'
    )
    harness = _harness(
        "",
        base_image=DOTNET,
        files=[
            {"path": "poc.csproj", "content": project},
            {"path": "Program.cs", "content": program},
        ],
        command=[
            "sh",
            "-c",
            "cp -r /poc /tmp/poc && dotnet run --project /tmp/poc/poc.csproj -p:UseAppHost=false",
        ],
    )
    result = runner.run_poc(ctx, "T0006-poc_build", harness)
    assert result["status"] == "passed", result["observed_result"]
    assert "escaped /etc/passwd" in result["observed_result"]


def test_a_harness_that_writes_out_promotes_the_evidence(tmp_path):
    _require_docker()
    code = (
        "open('/out/finding.txt', 'w').write('observed the effect')\n"
        "print('KALKAN_POC_OK wrote evidence')\n"
    )
    ctx = _ctx(tmp_path)
    result = runner.run_poc(ctx, "T0001-poc_build", _harness(code))
    assert result["status"] == "passed"
    promoted = ctx.run_dir / "evidence" / "KF-0000000000000001" / "finding.txt"
    assert promoted.read_text(encoding="utf-8") == "observed the effect"
    assert "evidence/KF-0000000000000001/finding.txt" in result["artifacts"]


# ---------------------------------------------------------------------------------------------
# App level: the compose stack of the target on an internal network


def _app_ctx(tmp_path: Path, compose: str) -> SimpleNamespace:
    ctx = _ctx(tmp_path)
    (ctx.target_dir / "public").mkdir()
    (ctx.target_dir / "public" / "report.txt").write_text("INVOICE-DUMMY-4711", encoding="utf-8")
    (ctx.target_dir / "compose.yml").write_text(compose, encoding="utf-8")
    ctx.options = {"allow_build_network": False}
    return ctx


_WEB = (
    "services:\n"
    "  web:\n"
    f"    image: {IMAGE}\n"
    '    command: ["python", "-m", "http.server", "8000", "--directory", "/srv"]\n'
    "    ports: ['18000:8000']\n"
    "    volumes: ['./public:/srv']\n"
)


def _app_harness(**app) -> dict:
    spec = {
        "compose_file": "compose.yml",
        "service": "web",
        "port": 8000,
        "requests": [{"method": "GET", "path": "/report.txt", "headers": [], "body": ""}],
    }
    spec.update(app)
    return _harness("", level="app", app=spec, success_regex=r"INVOICE-DUMMY-\d+")


def test_an_app_harness_reaches_the_service_on_the_internal_network(tmp_path):
    _require_docker()
    ctx = _app_ctx(tmp_path, _WEB)
    result = runner.run_poc(ctx, "T0005-poc_build", _app_harness())
    assert result["status"] == "passed", result["observed_result"]
    assert result["level"] == "app" and "INVOICE-DUMMY-4711" in result["observed_result"]
    engine_file = ctx.run_dir / "poc" / "KF-0000000000000001" / "app" / "compose.kalkan.json"
    text = engine_file.read_text(encoding="utf-8")
    assert '"internal": true' in text and "18000" not in text
    assert _no_container_left("kalkan-app")


def test_an_unsafe_compose_stack_is_never_started(tmp_path):
    _require_docker()
    unsafe = (
        _WEB + "    privileged: true\n    volumes: ['/var/run/docker.sock:/var/run/docker.sock']\n"
    )
    ctx = _app_ctx(tmp_path, unsafe.replace("    volumes: ['./public:/srv']\n", "", 1))
    result = runner.run_poc(ctx, "T0004-poc_build", _app_harness())
    assert result["status"] == "blocked" and result["blocker"] == "sandbox_app_unsafe"
    assert "privileged" in result["observed_result"]
    assert _no_container_left("kalkan-app")


def test_an_app_stack_that_needs_a_build_waits_for_consent(tmp_path):
    _require_docker()
    build = "services:\n  web:\n    build: .\n"
    ctx = _app_ctx(tmp_path, build)
    (ctx.target_dir / "Dockerfile").write_text(f"FROM {IMAGE}\n", encoding="utf-8")
    result = runner.run_poc(ctx, "T0003-poc_build", _app_harness())
    assert result["status"] == "blocked" and result["blocker"] == "sandbox_build_network_needed"


def test_a_csharp_harness_can_use_asp_net_core_offline(tmp_path):
    _require_docker()
    if not runner._image_present(runner.docker_path(), DOTNET):
        pytest.skip(f"base image {DOTNET} not pulled (kalkan sandbox pull {DOTNET})")
    project = (
        '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType>'
        "<TargetFramework>net10.0</TargetFramework><ImplicitUsings>enable</ImplicitUsings>"
        '</PropertyGroup><ItemGroup><FrameworkReference Include="Microsoft.AspNetCore.App" />'
        "</ItemGroup></Project>\n"
    )
    program = (
        "using Microsoft.AspNetCore.Http;\n"
        "var ctx = new DefaultHttpContext();\n"
        'ctx.Request.QueryString = new QueryString("?id=42");\n'
        'Console.WriteLine($"KALKAN_POC_OK query id={ctx.Request.Query["id"]}");\n'
    )
    harness = _harness(
        "",
        base_image=DOTNET,
        files=[
            {"path": "poc.csproj", "content": project},
            {"path": "Program.cs", "content": program},
        ],
        command=[
            "sh",
            "-c",
            "cp -r /poc /tmp/poc && dotnet run --project /tmp/poc/poc.csproj -p:UseAppHost=false",
        ],
    )
    result = runner.run_poc(_ctx(tmp_path), "T0002-poc_build", harness)
    assert result["status"] == "passed", result["observed_result"]
    assert "query id=42" in result["observed_result"]
