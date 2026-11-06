# SPDX-License-Identifier: MIT
"""App-level verification: the target's compose stack on an internal network (ENGINE-SPEC 23).

A unit harness cannot reach every finding: an IDOR or a missing authorization check needs the
running application. :func:`run_app_poc` starts the compose stack of the target copy under a
policy, sends the harness requests from a client container and matches the responses against
the success pattern.

Safety rules:

- ``docker compose`` runs with a minimal environment (:func:`compose_env`): host variables such
  as cloud keys never reach the interpolation of the compose file.
- The resolved configuration (``docker compose config``) must pass :func:`policy_errors`: no
  privileged service, no host or shared namespaces, no added capability, no device, no bind
  mount outside the target copy, no Docker socket, no external volume or network, no custom
  runtime. A refused stack is ``blocked`` with ``sandbox_app_unsafe``.
- The engine writes its own compose file (:func:`sanitize`): every service is on one internal
  network without internet access, no port is published to the host, a small capability set,
  ``no-new-privileges``, memory, CPU and PID limits, binds inside the target read-only.
- Images are never pulled and never built without the consent ``run init
  --allow-build-network`` (blocker ``sandbox_build_network_needed`` or
  ``sandbox_image_missing``). The build itself is the only step that uses the network.
- The client container has the unit-level isolation profile and only the internal network.
- ``docker compose down -v --remove-orphans --rmi local`` always runs at the end.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from kalkan.sandbox.redact import redact

__all__ = [
    "APP_TIMEOUT_SECONDS",
    "CLIENT_IMAGE",
    "compose_env",
    "policy_errors",
    "run_app_poc",
    "sanitize",
]

APP_TIMEOUT_SECONDS: Final = 300
BUILD_TIMEOUT_SECONDS: Final = 900
COMPOSE_TIMEOUT_SECONDS: Final = 120
CLIENT_IMAGE: Final = "python:3.12-slim"
MAX_SERVICES: Final = 12
LOG_CAP_CHARS: Final = 64 * 1024
NETWORK: Final = "kalkan"
#: Capabilities a service keeps (official database images change file owners and drop root).
SERVICE_CAPS: Final = ("CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID", "NET_BIND_SERVICE")
_SERVICE_LIMITS: Final = {"mem_limit": "1g", "memswap_limit": "1g", "pids_limit": 512, "cpus": 1.0}
#: Service keys copied into the engine's compose file; every other key is dropped.
_KEPT_KEYS: Final = (
    "image",
    "command",
    "entrypoint",
    "environment",
    "working_dir",
    "user",
    "healthcheck",
    "tmpfs",
    "init",
    "stop_signal",
    "stop_grace_period",
    "expose",
    "hostname",
)
_REFUSED_KEYS: Final = {
    "privileged": "privileged mode",
    "network_mode": "a custom network mode",
    "pid": "a shared PID namespace",
    "ipc": "a shared IPC namespace",
    "uts": "a shared UTS namespace",
    "userns_mode": "a custom user namespace",
    "cgroup_parent": "a custom cgroup parent",
    "cap_add": "added capabilities",
    "devices": "host devices",
    "device_cgroup_rules": "device rules",
    "runtime": "a custom runtime",
    "sysctls": "kernel parameters",
    "volumes_from": "volumes of another container",
    "gpus": "GPUs",
}
_ENV_KEEP: Final = (
    "PATH",
    "SYSTEMROOT",
    "SYSTEMDRIVE",
    "WINDIR",
    "TEMP",
    "TMP",
    "HOME",
    "USERPROFILE",
    "APPDATA",
    "LOCALAPPDATA",
    "PROGRAMDATA",
    "PROGRAMFILES",
    "DOCKER_HOST",
    "DOCKER_CONTEXT",
    "DOCKER_CONFIG",
    "DOCKER_CERT_PATH",
    "DOCKER_TLS_VERIFY",
    "XDG_RUNTIME_DIR",
)

_CLIENT_SCRIPT: Final = """\
import json, socket, sys, time, urllib.error, urllib.request

spec = json.load(open("/poc/requests.json", encoding="utf-8"))
host, port = spec["service"], spec["port"]
deadline = time.monotonic() + spec["wait_seconds"]
while True:
    try:
        socket.create_connection((host, port), timeout=3).close()
        break
    except OSError:
        if time.monotonic() > deadline:
            print("KALKAN_APP_UNREACHABLE", host, port)
            sys.exit(3)
        time.sleep(2)
for index, item in enumerate(spec["requests"], start=1):
    request = urllib.request.Request(
        f"http://{host}:{port}{item['path']}",
        data=item["body"].encode() if item["body"] else None,
        method=item["method"],
        headers={h["name"]: h["value"] for h in item["headers"]},
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            status, body = response.status, response.read(8192)
    except urllib.error.HTTPError as exc:
        status, body = exc.code, exc.read(8192)
    except OSError as exc:
        print(f"REQUEST {index} {item['method']} {item['path']} -> error {exc}")
        continue
    print(f"REQUEST {index} {item['method']} {item['path']} -> {status}")
    print(body.decode("utf-8", errors="replace"))
"""


def compose_env() -> dict[str, str]:
    """Return the minimal environment for ``docker compose`` (no host secret is interpolated)."""
    return {name: value for name, value in os.environ.items() if name.upper() in _ENV_KEEP}


def _inside(path: str, root: Path) -> bool:
    try:
        candidate = Path(path).resolve()
        return candidate == root or root in candidate.parents
    except (OSError, ValueError):
        return False


def _is_socket(text: str) -> bool:
    lowered = text.replace("\\", "/").lower()
    return "docker.sock" in lowered or "docker_engine" in lowered or lowered.startswith("//./pipe")


def policy_errors(config: dict[str, Any], target_dir: Path) -> list[str]:
    """Return why the resolved compose ``config`` is unsafe to start (module docstring)."""
    errors: list[str] = []
    root = target_dir.resolve()
    services = config.get("services")
    if not isinstance(services, dict) or not services:
        return ["the compose file has no services"]
    if len(services) > MAX_SERVICES:
        errors.append(f"more than {MAX_SERVICES} services")
    for name, service in services.items():
        if not isinstance(service, dict):
            errors.append(f"{name}: not an object")
            continue
        for key, reason in _REFUSED_KEYS.items():
            value = service.get(key)
            if value not in (None, False, [], {}, ""):
                errors.append(f"{name}: {reason} ({key})")
        for option in service.get("security_opt") or []:
            text = str(option).lower()
            if "unconfined" in text or "disable" in text or "systempaths" in text:
                errors.append(f"{name}: security_opt {option}")
        for volume in service.get("volumes") or []:
            if not isinstance(volume, dict):
                errors.append(f"{name}: a volume in an unknown form")
                continue
            kind, source = volume.get("type"), str(volume.get("source") or "")
            if _is_socket(source) or _is_socket(str(volume.get("target") or "")):
                errors.append(f"{name}: the Docker socket")
            elif kind == "bind" and not _inside(source, root):
                errors.append(f"{name}: a bind mount outside the target ({source})")
            elif kind not in ("bind", "volume", "tmpfs"):
                errors.append(f"{name}: a {kind} mount")
        build = service.get("build")
        if isinstance(build, dict):
            context = str(build.get("context") or "")
            if context and not _inside(context, root):
                errors.append(f"{name}: a build context outside the target ({context})")
            if build.get("network") not in (None, "", "default"):
                errors.append(f"{name}: a build network ({build.get('network')})")
            if build.get("entitlements") or build.get("privileged"):
                errors.append(f"{name}: build entitlements")
    for section in ("volumes", "networks", "secrets", "configs"):
        items = config.get(section)
        for key, item in items.items() if isinstance(items, dict) else []:
            if isinstance(item, dict) and item.get("external"):
                errors.append(f"{section}.{key}: external")
            source = item.get("file") if isinstance(item, dict) else None
            if isinstance(source, str) and not _inside(source, root):
                errors.append(f"{section}.{key}: a file outside the target ({source})")
    return errors


def _volumes(service: dict[str, Any], root: Path) -> list[dict[str, Any]]:
    kept = []
    for volume in service.get("volumes") or []:
        kind = volume.get("type")
        if kind == "bind" and _inside(str(volume.get("source") or ""), root):
            kept.append(
                {
                    "type": "bind",
                    "source": volume["source"],
                    "target": volume["target"],
                    "read_only": True,
                }
            )
        elif kind in ("volume", "tmpfs"):
            item = {key: volume[key] for key in ("type", "source", "target") if key in volume}
            kept.append(item)
    return kept


def sanitize(config: dict[str, Any], target_dir: Path) -> dict[str, Any]:
    """Return the engine's compose file for a ``config`` that passed :func:`policy_errors`."""
    root = target_dir.resolve()
    services: dict[str, Any] = {}
    for name, service in config["services"].items():
        clean: dict[str, Any] = {key: service[key] for key in _KEPT_KEYS if key in service}
        build = service.get("build")
        if isinstance(build, dict):
            clean["build"] = {
                key: build[key]
                for key in ("context", "dockerfile", "args", "target")
                if key in build
            }
        depends = service.get("depends_on")
        if isinstance(depends, dict):
            clean["depends_on"] = sorted(depends)
        elif isinstance(depends, list):
            clean["depends_on"] = sorted(str(item) for item in depends)
        volumes = _volumes(service, root)
        if volumes:
            clean["volumes"] = volumes
        clean.update(
            networks=[NETWORK],
            cap_drop=["ALL"],
            cap_add=list(SERVICE_CAPS),
            security_opt=["no-new-privileges:true"],
            **_SERVICE_LIMITS,
        )
        services[name] = clean
    named = {
        key: {}
        for key, item in (config.get("volumes") or {}).items()
        if isinstance(item, dict) and not item.get("external")
    }
    document: dict[str, Any] = {
        "services": services,
        "networks": {NETWORK: {"internal": True}},
    }
    if named:
        document["volumes"] = named
    return document


def project_name(run_id: str, task_id: str) -> str:
    """Return a compose project name: lowercase letters, digits, ``-`` and ``_`` only."""
    text = re.sub(r"[^a-z0-9_-]", "-", f"kalkan-app-{run_id}-{task_id}".lower())
    return text[:60].strip("-")


def _compose(
    docker: Path, project: str, compose_file: Path, *args: str, timeout: int
) -> subprocess.CompletedProcess[str] | None:
    argv = [str(docker), "compose", "-p", project, "-f", str(compose_file), *args]
    try:
        return subprocess.run(
            argv,
            shell=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
            env=compose_env(),
            cwd=compose_file.parent,
        )
    except (OSError, subprocess.SubprocessError):
        return None


def run_app_poc(ctx: Any, task_id: str, harness: dict[str, Any], docker: Path) -> dict[str, Any]:
    """Run one app-level harness and return its ``poc.json`` record (module docstring)."""
    from kalkan.sandbox import runner  # noqa: PLC0415 - runner imports this module

    finding_id = str(harness.get("finding_id") or "")

    def blocked(text: str, blocker: str, **extra: Any) -> dict[str, Any]:
        return runner._result(finding_id, "app", "blocked", text, blocker=blocker, **extra)

    app = harness.get("app")
    if not isinstance(app, dict):
        return blocked("The app-level harness has no app section.", "sandbox_error")
    target_dir = Path(ctx.target_dir)
    compose_rel = str(app.get("compose_file") or "")
    compose_path = target_dir / compose_rel
    if not compose_rel or not _inside(str(compose_path), target_dir.resolve()):
        return blocked("The compose file is not inside the target.", "sandbox_error")
    if not compose_path.is_file():
        return blocked(f"The compose file {compose_rel} does not exist.", "sandbox_error")
    pattern_text = harness.get("success_regex")
    try:
        pattern = re.compile(str(pattern_text))
    except re.error as exc:
        return blocked(f"The success pattern is not a valid expression: {exc}", "sandbox_error")

    project = project_name(str(ctx.run_id), task_id)
    shown = _compose(docker, project, compose_path, "config", "--format", "json", timeout=60)
    if shown is None or shown.returncode != 0:
        detail = (shown.stderr if shown else "docker compose did not start").strip()[:400]
        return blocked(f"docker compose config failed: {detail}", "sandbox_error")
    try:
        config = json.loads(shown.stdout)
    except ValueError:
        return blocked("docker compose config did not return JSON.", "sandbox_error")
    problems = policy_errors(config, target_dir)
    service, port = app.get("service"), app.get("port")
    if service not in (config.get("services") or {}):
        problems.append(f"the service {service!r} is not in the compose file")
    if problems:
        return blocked(
            "The compose stack is not started: " + "; ".join(problems[:8]), "sandbox_app_unsafe"
        )

    allow_network = (
        bool(ctx.options.get("allow_build_network")) if hasattr(ctx, "options") else False
    )
    images = sorted(
        {s["image"] for s in config["services"].values() if s.get("image") and not s.get("build")}
    )
    builds = sorted(name for name, s in config["services"].items() if s.get("build"))
    missing = [
        image for image in [*images, CLIENT_IMAGE] if not runner._image_present(docker, image)
    ]
    if builds and not allow_network:
        return blocked(
            "The stack builds images ("
            + ", ".join(builds)
            + "), and a build needs the network. Start the run with --allow-build-network.",
            "sandbox_build_network_needed",
        )
    if missing and (CLIENT_IMAGE in missing or not allow_network):
        return blocked(
            "Images are not present: " + ", ".join(missing) + ". Pull them first.",
            "sandbox_image_missing",
        )

    root = ctx.run_dir / "poc" / finding_id
    work = root / "app"
    runner._reset_dir(work)
    out_dir = root / "out"
    runner._reset_dir(out_dir)
    engine_file = work / "compose.kalkan.json"
    engine_file.write_text(json.dumps(sanitize(config, target_dir), indent=2), encoding="utf-8")
    spec = {
        "service": service,
        "port": port,
        "wait_seconds": 120,
        "requests": app.get("requests") or [],
    }
    (work / "requests.json").write_text(json.dumps(spec), encoding="utf-8")
    (work / "client.py").write_text(_CLIENT_SCRIPT, encoding="utf-8")

    evidence_dir = ctx.run_dir / "evidence" / finding_id
    evidence_dir.mkdir(parents=True, exist_ok=True)
    try:
        if missing:
            pulled = _compose(docker, project, engine_file, "pull", timeout=BUILD_TIMEOUT_SECONDS)
            if pulled is None or pulled.returncode != 0:
                return blocked("Pulling the stack images failed.", "sandbox_image_missing")
        if builds:
            built = _compose(docker, project, engine_file, "build", timeout=BUILD_TIMEOUT_SECONDS)
            if built is None or built.returncode != 0:
                detail = (built.stderr if built else "").strip()[-400:]
                return blocked(f"The stack build failed: {detail}", "sandbox_error")
        up = _compose(
            docker,
            project,
            engine_file,
            "up",
            "-d",
            "--no-build",
            "--pull",
            "never",
            timeout=COMPOSE_TIMEOUT_SECONDS,
        )
        if up is None or up.returncode != 0:
            detail = (up.stderr if up else "").strip()[-400:]
            return blocked(f"The stack did not start: {detail}", "sandbox_error")
        argv = runner._unit_argv(
            docker,
            CLIENT_IMAGE,
            f"{project}-client",
            target_dir,
            work,
            out_dir,
            ["python", "/poc/client.py"],
        )
        argv[argv.index("--network") + 1] = f"{project}_{NETWORK}"
        started, clock = datetime.now(UTC), time.monotonic()
        capture = runner._run_bounded(
            argv, timeout=APP_TIMEOUT_SECONDS, name=f"{project}-client", out_dir=out_dir
        )
        timing = {
            "started_at": started.isoformat(timespec="seconds").replace("+00:00", "Z"),
            "duration_ms": int((time.monotonic() - clock) * 1000),
        }
        logs = _compose(
            docker, project, engine_file, "logs", "--no-color", "--tail", "300", timeout=60
        )
        if logs is not None and logs.stdout:
            (evidence_dir / "app-logs.txt").write_text(
                redact(logs.stdout[-LOG_CAP_CHARS:]), encoding="utf-8"
            )
    finally:
        _compose(
            docker,
            project,
            engine_file,
            "down",
            "-v",
            "--remove-orphans",
            "--rmi",
            "local",
            "--timeout",
            "10",
            timeout=COMPOSE_TIMEOUT_SECONDS,
        )

    saved = runner._save_logs(evidence_dir, capture, argv)
    if (evidence_dir / "app-logs.txt").is_file():
        saved.append(evidence_dir / "app-logs.txt")
    artifacts = sorted(path.relative_to(ctx.run_dir).as_posix() for path in saved)
    run: dict[str, Any] = {**timing, "output_truncated": capture.truncated}
    if capture.exit_code is not None:
        run["exit_code"] = capture.exit_code
    if capture.timed_out:
        return blocked(
            f"The app-level check did not finish within {APP_TIMEOUT_SECONDS} seconds.",
            "sandbox_timeout",
            artifacts=artifacts,
            run=run,
        )
    if "KALKAN_APP_UNREACHABLE" in capture.stdout:
        return blocked(
            f"The service {service} did not open port {port} in time.",
            "sandbox_error",
            artifacts=artifacts,
            run=run,
        )
    matched = runner._match_line(pattern, capture.stdout)
    status = "passed" if matched is not None else "failed"
    observed = matched or "The responses did not match the success pattern; see the evidence files."
    return runner._result(finding_id, "app", status, observed, artifacts=artifacts, run=run)
