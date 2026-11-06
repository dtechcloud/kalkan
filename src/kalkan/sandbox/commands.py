# SPDX-License-Identifier: MIT
"""CLI command ``sandbox`` (docs/ENGINE-SPEC.md section 23).

- ``kalkan sandbox status [--json]``: report the Docker engine and which base images are present.
- ``kalkan sandbox pull [<image> ...] [--json]``: download the base images from the allowlist and
  record their digests in ``<home>/.tools/sandbox/pinned.json`` (an explicit, online step; the
  audit itself never pulls an image). No argument pulls every allowlisted image.

The base images stay small (language runtimes). The verification runner starts them with no
network, a read-only root, a non-root user and dropped capabilities (docs/SECURITY.md).
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Final

from kalkan.resources import home
from kalkan.sandbox.runner import allowed_images, docker_available, docker_path

__all__ = ["register"]

_PULL_TIMEOUT_SECONDS: Final = 600
_INSPECT_TIMEOUT_SECONDS: Final = 25


def register(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(
        "sandbox",
        help="Run or prepare the PoC verification sandbox (Docker).",
        description="Prepare and inspect the Docker sandbox that verifies findings.",
    )
    inner = parser.add_subparsers(dest="sandbox_command", metavar="<subcommand>")

    status = inner.add_parser("status", help="Show the Docker engine and the base images.")
    status.add_argument("--json", action="store_true", help="Machine-readable output.")
    status.set_defaults(func=_status)

    pull = inner.add_parser("pull", help="Download the base images and pin their digests.")
    pull.add_argument("images", nargs="*", help="Images to pull (default: all allowlisted).")
    pull.add_argument("--json", action="store_true", help="Machine-readable output.")
    pull.set_defaults(func=_pull)

    parser.set_defaults(func=_status, json=False)


def _pin_path() -> Path:
    return home() / ".tools" / "sandbox" / "pinned.json"


def _digest(docker: Path, ref: str) -> str | None:
    try:
        proc = subprocess.run(
            [str(docker), "image", "inspect", "--format", "{{index .RepoDigests 0}}", ref],
            shell=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=_INSPECT_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    out = proc.stdout.decode("utf-8", errors="replace").strip() if proc.returncode == 0 else ""
    return out or None


def _present(docker: Path, ref: str) -> bool:
    try:
        proc = subprocess.run(
            [str(docker), "image", "inspect", ref],
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=_INSPECT_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return proc.returncode == 0


def _load_pins() -> dict[str, str]:
    try:
        data = json.loads(_pin_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return (
        {k: v for k, v in data.items() if isinstance(k, str) and isinstance(v, str)}
        if (isinstance(data, dict))
        else {}
    )


def _save_pins(pins: dict[str, str]) -> None:
    path = _pin_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(pins, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _emit(args: argparse.Namespace, payload: dict[str, Any], lines: list[str]) -> None:
    if getattr(args, "json", False):
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        for line in lines:
            print(line)


def _status(args: argparse.Namespace) -> int:
    docker = docker_path()
    available = docker_available()
    pins = _load_pins()
    images = []
    lines = [
        f"docker: {'found' if docker else 'not found'}"
        + (f" ({docker.as_posix()})" if docker else ""),
        f"engine: {'reachable' if available else 'not reachable'}",
        "images:",
    ]
    for name in allowed_images():
        present = _present(docker, name) if docker else False
        images.append({"image": name, "present": present, "pinned": pins.get(name)})
        mark = "present" if present else "missing"
        lines.append(f"  {name}: {mark}" + (f" (pinned {pins[name]})" if name in pins else ""))
    if not available:
        lines.append("The sandbox is off. Findings rest on the static evidence and the review.")
    payload = {
        "docker": docker.as_posix() if docker else None,
        "engine": available,
        "images": images,
    }
    _emit(args, payload, lines)
    return 0


def _pull(args: argparse.Namespace) -> int:
    docker = docker_path()
    if docker is None:
        print("kalkan sandbox pull: docker was not found on PATH.", file=sys.stderr)
        return 1
    allow = allowed_images()
    wanted = args.images or allow
    bad = [name for name in wanted if name not in allow]
    if bad:
        print(f"kalkan sandbox pull: not in the allowlist: {', '.join(bad)}", file=sys.stderr)
        print(f"allowlist: {', '.join(allow)}", file=sys.stderr)
        return 1
    pins = _load_pins()
    results = []
    failed = False
    for name in wanted:
        print(f"==> pull {name}", file=sys.stderr)
        try:
            proc = subprocess.run(
                [str(docker), "pull", name],
                shell=False,
                stdin=subprocess.DEVNULL,
                timeout=_PULL_TIMEOUT_SECONDS,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            results.append({"image": name, "pulled": False, "error": str(exc)})
            failed = True
            continue
        ok = proc.returncode == 0
        failed = failed or not ok
        digest = _digest(docker, name) if ok else None
        if digest:
            pins[name] = digest
        results.append({"image": name, "pulled": ok, "digest": digest})
    _save_pins(pins)
    lines = [
        f"{r['image']}: {'pulled' if r['pulled'] else 'failed'}"
        + (f" ({r['digest']})" if r.get("digest") else "")
        for r in results
    ]
    _emit(args, {"results": results}, lines)
    return 1 if failed else 0
