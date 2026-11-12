# SPDX-License-Identifier: MIT
"""Benchmark the deterministic kalkan pipeline (phase 8, task 8.3).

Usage::

    python benchmarks/run_benchmark.py [--target NAME|all] [--offline]

For each target of ``benchmarks/targets.json`` the script prepares a source folder, then runs
``kalkan run init``, ``scan all``, ``sca sbom``, ``sca match``, ``merge`` and ``report`` through
the repository ``.venv`` (``python -m kalkan ... --json``). No LLM is involved and no target code
runs. It writes ``benchmarks/results/<name>.json`` per target and ``benchmarks/results/SUMMARY.md``
across all result files.

Isolation: every kalkan command runs with ``KALKAN_RUNS_DIR=<repo>/.bench-runs``, so the default
``runs/`` folder (and its ``LATEST`` pointer) is never used. Source folders live in
``.bench-runs/_src/<name>`` and step logs in ``.bench-runs/_logs/<name>/``.

Sources:

- ``git`` targets are fetched at the pinned commit with full history (``git init`` plus
  ``git fetch <url> <commit>``; ``kalkan run init`` cannot pin a ref). The history scan
  (``gitleaks-history``) then covers exactly the history of the pinned commit. An existing clone
  at the pinned commit is reused.
- ``fixture`` targets are copied without the answer files (``exclude``).

Fixture scoring (targets with ``expected``): an expected item counts as found by an engine when a
candidate of that engine is in the same file and its start line is within 2 lines of the item
line (``found_pm2``), or additionally its region covers the line (``found``, the rule of the
fixture README for resource-level engines). Dependency items match by package through
``sca/vulns.json``. A secure twin counts as a false positive under the fixture README rule: any
nearby result of kalkan's own rules (opengrep, matcher), else a nearby result with a rule ID of
the vulnerable counterpart. ``twin_hits_any_rule`` counts twins with any nearby result.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
BENCH_DIR = REPO / "benchmarks"
RESULTS_DIR = BENCH_DIR / "results"
TARGETS_FILE = BENCH_DIR / "targets.json"
RUNS_DIR = REPO / ".bench-runs"
SRC_DIR = RUNS_DIR / "_src"
LOG_DIR = RUNS_DIR / "_logs"

SCHEMA_VERSION = 1
SEVERITIES = ("critical", "high", "medium", "low", "info")
OWN_RULE_ENGINES = frozenset({"opengrep", "matcher"})
SCA_ENGINES = ("osv-scanner", "grype", "govulncheck")
AGENT_ENGINES = frozenset({"hunter"})
LINE_WINDOW = 2
SAMPLE_MAX = 20
STEP_TIMEOUTS = {
    "init": 3600,
    "scan": 6 * 3600,
    "sbom": 3600,
    "match": 3600,
    "merge": 1800,
    "report": 1800,
}
GIT_TIMEOUT = 3600


class BenchError(Exception):
    """A target cannot be benchmarked (preparation failed)."""


# --- helpers -----------------------------------------------------------------------------------


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _read_json_or_none(path: Path) -> Any:
    try:
        return _read_json(path)
    except (OSError, ValueError):
        return None


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(data, ensure_ascii=False, indent=2) + "\n"
    path.write_text(text, encoding="utf-8", newline="\n")


def _rmtree(path: Path) -> None:
    def retry(function: Any, target: str, _error: object) -> None:
        with contextlib.suppress(OSError):
            os.chmod(target, stat.S_IWRITE)
            function(target)

    if not path.exists():
        return
    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=retry)
    else:  # Python 3.11
        shutil.rmtree(path, onerror=retry)


def _venv_python() -> Path:
    if os.name == "nt":
        candidate = REPO / ".venv" / "Scripts" / "python.exe"
    else:
        candidate = REPO / ".venv" / "bin" / "python"
    if not candidate.is_file():
        raise BenchError(f"the repository venv is missing: {candidate}")
    return candidate


def _kalkan_env() -> dict[str, str]:
    env = dict(os.environ)
    env["KALKAN_RUNS_DIR"] = str(RUNS_DIR)
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    return env


def _git_env() -> dict[str, str]:
    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_LFS_SKIP_SMUDGE"] = "1"
    env["GIT_ALLOW_PROTOCOL"] = "https"
    return env


def _kill_tree(process: subprocess.Popen[str]) -> None:
    if os.name == "nt":
        taskkill = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32" / "taskkill.exe"
        subprocess.run(
            [str(taskkill), "/T", "/F", "/PID", str(process.pid)],
            capture_output=True,
            timeout=60,
            check=False,
        )
    else:
        with contextlib.suppress(OSError):
            os.killpg(process.pid, 9)
    with contextlib.suppress(OSError):
        process.kill()


def _run(argv: list[str], *, env: dict[str, str], timeout: int, cwd: Path = REPO) -> dict:
    """Run a process; return exit code, wall time, stdout and stderr. Never raises on failure."""
    started = time.perf_counter()
    try:
        process = subprocess.Popen(
            argv,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            start_new_session=os.name != "nt",
        )
    except OSError as exc:
        return {
            "exit_code": None,
            "duration": 0.0,
            "stdout": "",
            "stderr": str(exc),
            "timeout": False,
        }
    try:
        stdout, stderr = process.communicate(timeout=timeout)
        timed_out = False
    except subprocess.TimeoutExpired:
        _kill_tree(process)
        stdout, stderr = process.communicate()
        timed_out = True
    return {
        "exit_code": process.returncode,
        "duration": round(time.perf_counter() - started, 2),
        "stdout": stdout or "",
        "stderr": stderr or "",
        "timeout": timed_out,
    }


def _git(args: list[str], *, cwd: Path | None = None, timeout: int = GIT_TIMEOUT) -> str:
    git = shutil.which("git")
    if git is None:
        raise BenchError("git is not on PATH")
    argv = [git, *(["-C", str(cwd)] if cwd else []), *args]
    result = _run(argv, env=_git_env(), timeout=timeout)
    if result["exit_code"] != 0:
        tail = (result["stderr"] or result["stdout"]).strip()[-800:]
        raise BenchError(f"git {' '.join(args)} failed (exit {result['exit_code']}): {tail}")
    return result["stdout"].strip()


def _tail(text: str, limit: int = 1500) -> str:
    text = text.strip()
    return text if len(text) <= limit else "..." + text[-limit:]


# --- environment -------------------------------------------------------------------------------


def kalkan_info(python: Path) -> dict[str, Any]:
    result = _run([str(python), "-m", "kalkan", "--version"], env=_kalkan_env(), timeout=120)
    version = result["stdout"].strip().removeprefix("kalkan ").strip() or None
    info: dict[str, Any] = {"version": version, "commit": None, "dirty": None}
    if shutil.which("git") and (REPO / ".git").exists():
        with contextlib.suppress(BenchError):
            info["commit"] = _git(["rev-parse", "HEAD"], cwd=REPO, timeout=60)
            info["dirty"] = bool(_git(["status", "--porcelain"], cwd=REPO, timeout=120))
    return info


def tool_versions() -> dict[str, str]:
    data = _read_json_or_none(REPO / ".tools" / "installed.json") or {}
    tools = data.get("tools") or {}
    return {name: str(entry.get("version")) for name, entry in sorted(tools.items())}


def host_info() -> dict[str, Any]:
    return {
        "platform": platform.platform(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "cpu_count": os.cpu_count(),
    }


# --- target preparation ------------------------------------------------------------------------

# Agent instruction files and folders (ENGINE-SPEC section 10). The source folders live below
# the kalkan repository, so an agent session in the repository could load them as instructions.
INSTRUCTION_FILES = frozenset(
    name.casefold()
    for name in (
        "CLAUDE.md",
        "CLAUDE.local.md",
        "AGENTS.md",
        "AGENTS.override.md",
        "GEMINI.md",
        ".cursorrules",
        ".windsurfrules",
    )
)
INSTRUCTION_DIRS = frozenset(
    name.casefold() for name in (".claude", ".codex", ".agents", ".cursor", ".gemini", ".windsurf")
)
NEUTRAL_SUFFIX = ".kalkan-neutralized"


def _is_instruction(name: str, parent: str, *, is_dir: bool) -> bool:
    folded = name.casefold()
    if is_dir:
        return folded in INSTRUCTION_DIRS
    if folded in INSTRUCTION_FILES:
        return True
    return folded == "copilot-instructions.md" and parent.casefold() == ".github"


def neutralize_tree(root: Path) -> list[str]:
    """Rename agent instruction files and folders below ``root`` (``.git`` excluded).

    The suffix is the one of ``kalkan run init``. Deeper paths are renamed first, so the parent
    paths stay valid. Returns the renamed paths relative to ``root`` (original names).
    """
    matches: list[tuple[Path, bool]] = []
    for current, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d != ".git")
        folder = Path(current)
        for name in dirs:
            if _is_instruction(name, folder.name, is_dir=True):
                matches.append((folder / name, True))
        for name in sorted(files):
            if _is_instruction(name, folder.name, is_dir=False):
                matches.append((folder / name, False))
    renamed: list[str] = []
    for path, _ in sorted(matches, key=lambda item: len(item[0].parts), reverse=True):
        target = path.with_name(path.name + NEUTRAL_SUFFIX)
        counter = 2
        while target.exists():
            target = path.with_name(f"{path.name}{NEUTRAL_SUFFIX}-{counter}")
            counter += 1
        path.rename(target)
        renamed.append(path.relative_to(root).as_posix())
    return sorted(renamed)


def neutralized_paths(root: Path) -> list[str]:
    """Return the paths below ``root`` that carry the neutralization suffix (``.git`` excluded)."""
    found: list[str] = []
    for current, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d != ".git")
        for name in [*dirs, *files]:
            if NEUTRAL_SUFFIX in name:
                found.append((Path(current) / name).relative_to(root).as_posix())
    return sorted(found)


def prepare_git(target: dict[str, Any], *, offline: bool) -> tuple[Path, dict[str, Any]]:
    dest = SRC_DIR / target["name"]
    commit = target["commit"]
    started = time.perf_counter()
    if (dest / ".git").exists():
        try:
            head = _git(["rev-parse", "HEAD"], cwd=dest, timeout=60)
        except BenchError:
            head = None
        if head == commit:
            return dest, {"action": "reused", "duration_seconds": 0.0}
        _rmtree(dest)
    elif dest.exists():
        _rmtree(dest)
    if offline:
        raise BenchError(f"offline run and no clone of {target['name']} at {commit}")
    dest.mkdir(parents=True)
    _git(["init", "--quiet"], cwd=dest, timeout=120)
    for key, value in (
        ("core.symlinks", "false"),
        ("core.longpaths", "true"),
        ("core.autocrlf", "false"),
    ):
        _git(["config", key, value], cwd=dest, timeout=60)
    _git(["fetch", "--no-tags", "--quiet", target["url"], commit], cwd=dest)
    _git(["checkout", "--quiet", "--detach", "FETCH_HEAD"], cwd=dest)
    head = _git(["rev-parse", "HEAD"], cwd=dest, timeout=60)
    if head != commit:
        raise BenchError(f"checkout gave {head}, expected {commit}")
    commits = _git(["rev-list", "--count", "HEAD"], cwd=dest, timeout=600)
    return dest, {
        "action": "fetched",
        "duration_seconds": round(time.perf_counter() - started, 2),
        "history_commits": int(commits) if commits.isdigit() else None,
        "git_config": {
            "core.symlinks": "false",
            "core.longpaths": "true",
            "core.autocrlf": "false",
        },
    }


def prepare_fixture(target: dict[str, Any]) -> tuple[Path, dict[str, Any]]:
    source = (REPO / target["path"]).resolve()
    if not source.is_dir():
        raise BenchError(f"fixture folder not found: {source}")
    dest = SRC_DIR / source.name
    exclude = set(target.get("exclude") or [])
    started = time.perf_counter()
    _rmtree(dest)

    def ignore(directory: str, names: list[str]) -> list[str]:
        skipped = [name for name in names if name == "__pycache__"]
        if Path(directory).resolve() == source:
            skipped += [name for name in names if name in exclude]
        return skipped

    shutil.copytree(source, dest, ignore=ignore, symlinks=False)
    left = sorted(name for name in exclude if (dest / name).exists())
    if left:
        raise BenchError(f"answer files left in the fixture copy: {left}")
    return dest, {
        "action": "copied",
        "duration_seconds": round(time.perf_counter() - started, 2),
        "excluded": sorted(exclude),
    }


# --- pipeline ----------------------------------------------------------------------------------


def _display(arg: str) -> str:
    """Show paths inside the repository relative to it (result files carry no user paths)."""
    path = Path(arg)
    if path.is_absolute():
        with contextlib.suppress(ValueError):
            return path.relative_to(REPO).as_posix()
    return arg


def run_step(
    python: Path, name: str, args: list[str], target_name: str
) -> tuple[dict[str, Any], Any]:
    argv = [str(python), "-m", "kalkan", *args]
    result = _run(argv, env=_kalkan_env(), timeout=STEP_TIMEOUTS[name])
    log_dir = LOG_DIR / target_name
    log_dir.mkdir(parents=True, exist_ok=True)
    (log_dir / f"{name}.stdout.txt").write_text(result["stdout"], encoding="utf-8", newline="\n")
    (log_dir / f"{name}.stderr.txt").write_text(result["stderr"], encoding="utf-8", newline="\n")
    try:
        payload = json.loads(result["stdout"]) if result["stdout"].strip() else None
    except ValueError:
        payload = None
    record: dict[str, Any] = {
        "step": name,
        "command": "kalkan " + " ".join(_display(arg) for arg in args),
        "exit_code": result["exit_code"],
        "duration_seconds": result["duration"],
        "ok": result["exit_code"] == 0 and not result["timeout"],
    }
    if result["timeout"]:
        record["error"] = f"step timed out after {STEP_TIMEOUTS[name]} s"
    elif not record["ok"]:
        record["error"] = _tail(result["stderr"] or result["stdout"])
    return record, payload


def run_pipeline(
    python: Path, source: Path, target_name: str, *, offline: bool
) -> tuple[str | None, list[dict[str, Any]], dict[str, Any]]:
    """Run the six steps. Return the run ID, the step records and the JSON payloads."""
    steps: list[dict[str, Any]] = []
    payloads: dict[str, Any] = {}
    record, payload = run_step(python, "init", ["run", "init", str(source), "--json"], target_name)
    steps.append(record)
    payloads["init"] = payload
    run_id = payload.get("run_id") if isinstance(payload, dict) else None
    if not record["ok"] or not run_id:
        record.setdefault("error", "run init gave no run ID")
        return None, steps, payloads
    flag = ["--offline"] if offline else []
    plan = [
        ("scan", ["scan", "all", "--run", run_id, "--json", *flag]),
        ("sbom", ["sca", "sbom", "--run", run_id, "--json", *flag]),
        ("match", ["sca", "match", "--run", run_id, "--json", *flag]),
        ("merge", ["merge", "--run", run_id, "--json"]),
        ("report", ["report", "--run", run_id, "--json"]),
    ]
    for name, args in plan:
        print(f"  {target_name}: {name} ...", file=sys.stderr, flush=True)
        record, payload = run_step(python, name, args, target_name)
        steps.append(record)
        payloads[name] = payload
        print(
            f"  {target_name}: {name} exit {record['exit_code']} in "
            f"{record['duration_seconds']:.1f} s",
            file=sys.stderr,
            flush=True,
        )
    return run_id, steps, payloads


# --- collection --------------------------------------------------------------------------------


def _status_files(run_dir: Path) -> dict[str, dict[str, Any]]:
    engines: dict[str, dict[str, Any]] = {}
    for area in ("scans", "sca"):
        for path in sorted((run_dir / area).glob("*.status.json")):
            data = _read_json_or_none(path)
            if not isinstance(data, dict):
                continue
            engine = str(data.get("engine") or path.name.removesuffix(".status.json"))
            suppressed = data.get("suppressed_results")
            engines[engine] = {
                "area": area,
                "status": data.get("status"),
                "duration_seconds": data.get("duration_seconds"),
                "exit_code": data.get("exit_code"),
                "tool_version": data.get("tool_version"),
                "candidates": data.get("candidates"),
                "message": data.get("message"),
                "ingest_warnings": data.get("ingest_warnings"),
                "suppressed_results": (
                    suppressed.get("count") if isinstance(suppressed, dict) else None
                ),
            }
    return engines


def _count(values: list[Any]) -> dict[str, int]:
    return dict(sorted(Counter("null" if v is None else str(v) for v in values).items()))


def _by_severity(items: list[dict[str, Any]]) -> dict[str, int]:
    counts = Counter(str(item.get("severity")) for item in items)
    ordered = {level: counts.pop(level, 0) for level in SEVERITIES}
    ordered.update(sorted(counts.items()))
    return ordered


def collect_candidates(run_dir: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    data = _read_json_or_none(run_dir / "candidates.json")
    if not isinstance(data, dict):
        return {"present": False}, []
    candidates = [c for c in data.get("candidates") or [] if isinstance(c, dict)]
    warnings = [str(w) for w in data.get("warnings") or []]
    by_engine_severity: dict[str, dict[str, int]] = {}
    for engine in sorted({str(c.get("engine")) for c in candidates}):
        by_engine_severity[engine] = _by_severity(
            [c for c in candidates if str(c.get("engine")) == engine]
        )
    return {
        "present": True,
        "total": len(candidates),
        "by_engine": _count([c.get("engine") for c in candidates]),
        "by_class": _count([c.get("class") for c in candidates]),
        "by_severity": _by_severity(candidates),
        "by_engine_severity": by_engine_severity,
        "suppressed_in_source": sum(
            1 for c in candidates if "suppressed-in-source" in (c.get("tags") or [])
        ),
        "warnings": len(warnings),
        "warnings_by_source": _count([w.split(":", 1)[0] for w in warnings]),
        "warning_samples": warnings[:SAMPLE_MAX],
    }, candidates


def collect_sca(run_dir: Path, payloads: dict[str, Any]) -> tuple[dict[str, Any], list[dict]]:
    sbom = payloads.get("sbom") if isinstance(payloads.get("sbom"), dict) else {}
    match = payloads.get("match") if isinstance(payloads.get("match"), dict) else {}
    vulns = _read_json_or_none(run_dir / "sca" / "vulns.json")
    records = []
    if isinstance(vulns, dict):
        records = [r for r in vulns.get("records") or [] if isinstance(r, dict)]
    engines = match.get("engines") if isinstance(match.get("engines"), dict) else {}
    warnings = [str(w) for w in (match.get("warnings") or [])]
    pins = [r for r in records if r.get("pin_source") == "manifest"]
    return {
        "sbom": {
            "engine": sbom.get("engine"),
            "components": sbom.get("components"),
            "by_ecosystem": sbom.get("by_ecosystem"),
            "warnings": len(sbom.get("warnings") or []),
        },
        "raw_records": match.get("records"),
        "raw_by_engine": {
            name: {"status": info.get("status"), "records": info.get("records")}
            for name, info in engines.items()
            if isinstance(info, dict)
        },
        "merged_records": len(records) if isinstance(vulns, dict) else None,
        "merged_by_severity": _by_severity(records),
        "merged_by_engines": _count(["+".join(sorted(r.get("engines") or [])) for r in records]),
        "merged_by_ecosystem": _count([r.get("ecosystem") for r in records]),
        "manifest_pins": match.get("manifest_pins"),
        "pin_records": len(pins),
        "pin_records_by_severity": _by_severity(pins),
        "pin_records_by_package": _count(
            [f"{r.get('ecosystem')}/{r.get('package')}@{r.get('version')}" for r in pins]
        ),
        "candidates": match.get("candidates"),
        "warnings": len(warnings),
        "warning_samples": warnings[:SAMPLE_MAX],
    }, records


LOCKFILES = {
    "package.json": (
        "package-lock.json",
        "npm-shrinkwrap.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "bun.lock",
        "bun.lockb",
    ),
    "composer.json": ("composer.lock",),
    "Gemfile": ("Gemfile.lock",),
    "Pipfile": ("Pipfile.lock",),
    "Cargo.toml": ("Cargo.lock",),
}


def collect_manifests(run_dir: Path) -> dict[str, Any]:
    """Return the dependency manifests without a lockfile.

    ``sca match`` records them in ``unchecked_manifests`` of ``sca/vulns.json``
    (:mod:`kalkan.sca.manifests`). An older run without that field falls back to a walk of the
    target: manifests without a lockfile in their folder or a parent folder.
    """
    vulns = _read_json_or_none(run_dir / "sca" / "vulns.json")
    unchecked = vulns.get("unchecked_manifests") if isinstance(vulns, dict) else None
    if isinstance(unchecked, list):
        items = [item for item in unchecked if isinstance(item, dict)]
        return {
            "source": "sca/vulns.json",
            "without_lockfile": [str(item.get("file")) for item in items][: SAMPLE_MAX * 5],
            "details": items[: SAMPLE_MAX * 5],
        }
    return _walk_manifests(run_dir / "target")


def _walk_manifests(target_dir: Path) -> dict[str, Any]:
    manifests: list[str] = []
    unlocked: list[str] = []
    for current, dirs, files in os.walk(target_dir):
        dirs.sort()
        folder = Path(current)
        for name in sorted(files):
            if name not in LOCKFILES:
                continue
            relative = (folder / name).relative_to(target_dir).as_posix()
            manifests.append(relative)
            locked = False
            for parent in (folder, *folder.parents):
                if any((parent / lock).is_file() for lock in LOCKFILES[name]):
                    locked = True
                    break
                if parent == target_dir:
                    break
            if not locked:
                unlocked.append(relative)
    return {
        "source": "walk",
        "manifests": len(manifests),
        "without_lockfile": unlocked[: SAMPLE_MAX * 5],
    }


_OPENGREP_PATTERNS = {
    "partially_scanned_files": r"Partially scanned: (\d+) files",
    "skipped_large_files": r"Scan skipped: (\d+) files larger than",
    "rules_run": r"Ran (\d+) rules on \d+ files",
    "files_scanned": r"Ran \d+ rules on (\d+) files",
}


def opengrep_coverage(run_dir: Path) -> dict[str, Any] | None:
    """Return the files that Opengrep scanned, analyzed only partially or skipped.

    The status file holds them (``files_scanned``, ``partial_files``, ``skipped_files``); an
    older run falls back to the stderr summary.
    """
    status = _read_json_or_none(run_dir / "scans" / "opengrep.status.json")
    if isinstance(status, dict) and isinstance(status.get("partial_files"), dict):
        partial = status["partial_files"]
        skipped = (
            status.get("skipped_files") if isinstance(status.get("skipped_files"), dict) else {}
        )
        reasons = skipped.get("reasons") if isinstance(skipped.get("reasons"), dict) else {}
        return {
            "files_scanned": status.get("files_scanned"),
            "partially_scanned_files": partial.get("count", 0),
            "partial_samples": (partial.get("paths") or [])[:SAMPLE_MAX],
            "skipped_files": skipped.get("count", 0),
            "skipped_reasons": reasons,
            "skipped_samples": (skipped.get("paths") or [])[:SAMPLE_MAX],
        }
    try:
        text = (run_dir / "scans" / "opengrep.stderr.txt").read_text(
            encoding="utf-8", errors="replace"
        )
    except OSError:
        return None
    coverage: dict[str, int] = {}
    for key, pattern in _OPENGREP_PATTERNS.items():
        match = re.search(pattern, text)
        if match:
            coverage[key] = int(match.group(1))
    return coverage or None


def collect_report(run_dir: Path) -> dict[str, Any]:
    report_dir = run_dir / "report"
    if not report_dir.is_dir():
        return {"present": False, "files": {}}
    files = {
        path.name: path.stat().st_size for path in sorted(report_dir.iterdir()) if path.is_file()
    }
    return {"present": True, "files": files, "total_bytes": sum(files.values())}


def _merge_summary(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return None
    summary: dict[str, Any] = {}
    for key, value in payload.items():
        if isinstance(value, list):
            summary[key] = value[:SAMPLE_MAX] if key == "warnings" else len(value)
        else:
            summary[key] = value
    return summary


# --- fixture scoring ---------------------------------------------------------------------------


def _norm_version(version: str) -> str:
    text = str(version).strip().removeprefix("v")
    while text.endswith(".0") and text.count(".") > 0:
        text = text[:-2]
    return text


def _norm_package(ecosystem: str, name: str) -> str:
    text = str(name).strip().lower()
    if ecosystem.lower() == "pypi":
        text = re.sub(r"[-_.]+", "-", text)
    return text


def _package_key(ecosystem: str, name: str, version: str) -> tuple[str, str, str]:
    eco = str(ecosystem).strip().lower()
    return eco, _norm_package(eco, name), _norm_version(version)


def _near(candidate: dict[str, Any], item: dict[str, Any], *, region: bool) -> bool:
    if candidate.get("file") != item["file"]:
        return False
    start = candidate.get("start_line")
    if not isinstance(start, int):
        return False
    line = item["line"]
    if abs(start - line) <= LINE_WINDOW:
        return True
    if region:
        end = candidate.get("end_line")
        end = end if isinstance(end, int) else start
        return start <= line <= end
    return False


def _sca_matches(item: dict[str, Any], records: list[dict], engine: str | None) -> bool:
    package = item["package"]
    key = _package_key(package["ecosystem"], package["name"], package["version"])
    for record in records:
        if engine is not None and engine not in (record.get("engines") or []):
            continue
        if _package_key(record["ecosystem"], record["package"], record["version"]) == key:
            return True
    return False


def score_fixture(
    expected: list[dict[str, Any]],
    candidates: list[dict[str, Any]],
    records: list[dict[str, Any]],
    engine_status: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    by_id = {item["id"]: item for item in expected}
    vulnerable = [item for item in expected if item["kind"] == "vulnerable"]
    twins = [item for item in expected if item.get("twin_of")]
    located = [item for item in expected if "package" not in item]
    sca_records_by_engine = {
        engine: [r for r in records if engine in (r.get("engines") or [])] for engine in SCA_ENGINES
    }
    code_engines = {str(c.get("engine")) for c in candidates} - set(SCA_ENGINES)
    listed = {e for item in expected for e in item.get("expected_engines") or []}
    engines = sorted((code_engines | listed | {"osv-scanner", "grype"}) - AGENT_ENGINES)

    per_engine: dict[str, Any] = {}
    for engine in engines:
        is_sca = engine in SCA_ENGINES
        mine = [c for c in candidates if str(c.get("engine")) == engine and not is_sca]

        def hit(
            item: dict[str, Any], region: bool, engine: str = engine, mine: list = mine
        ) -> bool:
            if "package" in item:
                return engine in SCA_ENGINES and _sca_matches(item, records, engine)
            return any(_near(c, item, region=region) for c in mine)

        wanted = [item for item in vulnerable if engine in (item.get("expected_engines") or [])]
        found = [item for item in wanted if hit(item, True)]
        found_pm2 = [item for item in wanted if hit(item, False)]
        any_hits = [item for item in vulnerable if hit(item, True)]

        twin_fp: list[str] = []
        twin_any: list[str] = []
        for twin in twins:
            if "package" in twin:
                if is_sca and _sca_matches(twin, records, engine):
                    twin_fp.append(twin["id"])
                    twin_any.append(twin["id"])
                continue
            nearby = [c for c in mine if _near(c, twin, region=False)]
            if nearby:
                twin_any.append(twin["id"])
            if engine in OWN_RULE_ENGINES:
                if nearby:
                    twin_fp.append(twin["id"])
                continue
            rules = {
                rule
                for ref in twin.get("twin_of") or []
                for rule in (by_id.get(ref, {}).get("rules") or {}).get(engine, [])
            }
            regional = [c for c in mine if _near(c, twin, region=True)]
            if any(str(c.get("rule_id")) in rules for c in regional):
                twin_fp.append(twin["id"])

        if is_sca:
            pool = sca_records_by_engine.get(engine, [])
            planned = {
                _package_key(
                    i["package"]["ecosystem"], i["package"]["name"], i["package"]["version"]
                )
                for i in expected
                if "package" in i
            }
            unplanned = sum(
                1
                for r in pool
                if _package_key(r["ecosystem"], r["package"], r["version"]) not in planned
            )
            produced = len(pool)
        else:
            unplanned = sum(
                1 for c in mine if not any(_near(c, item, region=True) for item in located)
            )
            produced = len(mine)

        status = engine_status.get(engine, {}).get("status")
        per_engine[engine] = {
            "engine_status": status,
            "results": produced,
            "expected": len(wanted),
            "found": len(found),
            "recall": round(len(found) / len(wanted), 4) if wanted else None,
            "found_pm2": len(found_pm2),
            "recall_pm2": round(len(found_pm2) / len(wanted), 4) if wanted else None,
            "missed": sorted(item["id"] for item in wanted if item not in found),
            "vulnerable_items_hit": len(any_hits),
            "twin_fp": len(twin_fp),
            "twin_fp_ids": sorted(twin_fp),
            "twin_hits_any_rule": len(twin_any),
            "twin_hits_any_rule_ids": sorted(twin_any),
            "unplanned_results": unplanned,
        }

    def found_by(item: dict[str, Any], allowed: set[str] | None) -> bool:
        for engine in engines:
            if allowed is not None and engine not in allowed:
                continue
            if "package" in item:
                if engine in SCA_ENGINES and _sca_matches(item, records, engine):
                    return True
            elif engine not in SCA_ENGINES and any(
                _near(c, item, region=True) for c in candidates if str(c.get("engine")) == engine
            ):
                return True
        return False

    deterministic = [
        item for item in vulnerable if set(item.get("expected_engines") or []) - AGENT_ENGINES
    ]
    agent_only = [item["id"] for item in vulnerable if item not in deterministic]
    by_expected = [item for item in deterministic if found_by(item, set(item["expected_engines"]))]
    by_any = [item for item in deterministic if found_by(item, None)]
    twins_flagged = sorted({tid for info in per_engine.values() for tid in info["twin_fp_ids"]})
    return {
        "match_rule": (
            "same file and start line within 2 lines of the item line (found_pm2), or the "
            "candidate region covers the line (found); dependency items by package via "
            "sca/vulns.json"
        ),
        "twin_rule": (
            "twin_fp: any nearby result of kalkan's own rules (opengrep, matcher), else a "
            "nearby result with a rule ID of the vulnerable counterpart; dependency twins by "
            "package. twin_hits_any_rule: any result within 2 lines"
        ),
        "items": {
            "vulnerable": len(vulnerable),
            "secure_twins": len(twins),
            "deterministic": len(deterministic),
            "agent_only": len(agent_only),
        },
        "agent_only_items": agent_only,
        "overall": {
            "found_by_an_expected_engine": len(by_expected),
            "recall_expected_engines": (
                round(len(by_expected) / len(deterministic), 4) if deterministic else None
            ),
            "found_by_any_engine": len(by_any),
            "recall_any_engine": round(len(by_any) / len(deterministic), 4)
            if deterministic
            else None,
            "missed": sorted(item["id"] for item in deterministic if item not in by_expected),
            "twins_with_fp": len(twins_flagged),
            "twins_with_fp_ids": twins_flagged,
        },
        "engines": per_engine,
    }


# --- one target --------------------------------------------------------------------------------


def benchmark_target(
    target: dict[str, Any],
    *,
    python: Path,
    offline: bool,
    kalkan: dict[str, Any],
    tools: dict[str, str],
) -> dict[str, Any]:
    name = target["name"]
    result: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "target": name,
        "started_at": _now(),
        "finished_at": None,
        "offline": offline,
        "host": host_info(),
        "kalkan": kalkan,
        "tools": tools,
        "target_ref": {
            key: target.get(key)
            for key in ("kind", "url", "path", "ref", "tag", "tag_object", "commit")
            if key in target
        },
        "status": "failed",
        "failure": None,
    }
    started = time.perf_counter()
    try:
        print(f"{name}: preparing the source ...", file=sys.stderr, flush=True)
        if target["kind"] == "git":
            source, prepared = prepare_git(target, offline=offline)
        elif target["kind"] == "fixture":
            source, prepared = prepare_fixture(target)
        else:
            raise BenchError(f"unknown target kind: {target['kind']}")
        prepared["neutralized_now"] = len(neutralize_tree(source))
        prepared["neutralized"] = neutralized_paths(source)
        result["prepare"] = prepared
        result["source_dir"] = source.relative_to(REPO).as_posix()

        run_id, steps, payloads = run_pipeline(python, source, name, offline=offline)
        result["run_id"] = run_id
        result["steps"] = steps
        result["pipeline_seconds"] = round(sum(s["duration_seconds"] for s in steps), 2)
        if run_id is None:
            result["failure"] = {"step": "init", "error": steps[-1].get("error")}
            return result
        run_dir = RUNS_DIR / run_id
        result["run_dir"] = run_dir.relative_to(REPO).as_posix()

        manifest = _read_json_or_none(run_dir / "target-manifest.json") or {}
        result["target_ref"]["git_ref"] = manifest.get("git_ref")
        result["files"] = manifest.get("files")
        result["excluded"] = {
            str(entry.get("class")): entry.get("count")
            for entry in manifest.get("excluded") or []
            if isinstance(entry, dict) and entry.get("count")
        }
        result["neutralized_count"] = manifest.get("neutralized_count")
        result["tech"] = manifest.get("tech")
        long_paths = manifest.get("long_paths") or {}
        result["long_paths"] = {
            "count": long_paths.get("count", 0),
            "limit": long_paths.get("limit"),
            "condition": long_paths.get("condition"),
            "long_paths_enabled": long_paths.get("long_paths_enabled"),
            "root_length": long_paths.get("root_length"),
            "samples": (long_paths.get("paths") or [])[:SAMPLE_MAX],
        }

        engines = _status_files(run_dir)
        result["engines"] = engines
        candidate_summary, candidates = collect_candidates(run_dir)
        result["candidates"] = candidate_summary
        sca_summary, records = collect_sca(run_dir, payloads)
        result["sca"] = sca_summary
        result["merge"] = _merge_summary(payloads.get("merge"))
        result["report"] = collect_report(run_dir)
        result["dependency_manifests"] = collect_manifests(run_dir)
        if "opengrep" in engines:
            engines["opengrep"]["coverage"] = opengrep_coverage(run_dir)

        if target.get("expected"):
            expected = _read_json(REPO / target["expected"])
            result["fixture"] = score_fixture(expected, candidates, records, engines)

        failed_steps = [s["step"] for s in steps if not s["ok"]]
        failed_engines = sorted(
            engine for engine, info in engines.items() if info["status"] in ("failed", "timeout")
        )
        result["status"] = "ok" if not failed_steps and not failed_engines else "partial"
        if failed_steps or failed_engines:
            result["failure"] = {"steps": failed_steps, "engines": failed_engines}
    except BenchError as exc:
        result["failure"] = {"step": "prepare", "error": str(exc)}
    except Exception as exc:  # record the error and continue with the next target
        result["failure"] = {"step": "benchmark", "error": f"{type(exc).__name__}: {exc}"}
    finally:
        result["finished_at"] = _now()
        result["wall_seconds"] = round(time.perf_counter() - started, 2)
    return result


# --- summary -----------------------------------------------------------------------------------


def _fmt_seconds(value: Any) -> str:
    if not isinstance(value, int | float):
        return "-"
    if value >= 120:
        return f"{value / 60:.1f} min"
    return f"{value:.1f} s"


def _fmt_pct(value: Any) -> str:
    return "-" if value is None else f"{value * 100:.0f}%"


def _step_seconds(result: dict[str, Any], *names: str) -> float | None:
    values = [s["duration_seconds"] for s in result.get("steps") or [] if s["step"] in names]
    return round(sum(values), 2) if values else None


def write_summary(order: list[str]) -> Path:
    results: list[dict[str, Any]] = []
    for name in order:
        data = _read_json_or_none(RESULTS_DIR / f"{name}.json")
        if isinstance(data, dict):
            results.append(data)
    lines: list[str] = ["# Benchmark summary", ""]
    if not results:
        lines.append("No result files yet. Run `python benchmarks/run_benchmark.py`.")
        path = RESULTS_DIR / "SUMMARY.md"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
        return path

    first = results[0]
    kalkan = first.get("kalkan") or {}
    commit = (kalkan.get("commit") or "")[:7] or "unknown"
    dirty = " (uncommitted changes)" if kalkan.get("dirty") else ""
    lines += [
        "Deterministic pipeline only, no LLM: `run init`, `scan all`, `sca sbom`, `sca match`, "
        "`merge`, `report`. Produced by `benchmarks/run_benchmark.py`; details in "
        "`benchmarks/results/<target>.json`.",
        "",
        f"- kalkan {kalkan.get('version')} at commit {commit}{dirty}",
        f"- Host: {(first.get('host') or {}).get('platform')}, "
        f"{(first.get('host') or {}).get('cpu_count')} CPUs",
        "- Tools: " + ", ".join(f"{k} {v}" for k, v in (first.get("tools") or {}).items()),
        "",
        "## Targets",
        "",
        "| Target | Ref | Files | Tech | Status | Pipeline | Scan | SCA | Candidates "
        "| SCA records (raw / merged) | From manifest pins | Manifests without lockfile "
        "| Long paths |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for result in results:
        ref = result.get("target_ref") or {}
        commit = (ref.get("commit") or "")[:7]
        if ref.get("kind") == "fixture":
            label = f"fixture at kalkan {(ref.get('git_ref') or '')[:7] or '?'}"
        elif ref.get("tag"):
            label = f"{ref['tag']} ({commit})"
        else:
            label = f"{(ref.get('ref') or '').removeprefix('refs/heads/')} {commit}".strip()
        files = (result.get("files") or {}).get("copied", "-")
        tech = ", ".join(result.get("tech") or []) or "-"
        sca = result.get("sca") or {}
        raw = sca.get("raw_records")
        merged = sca.get("merged_records")
        lines.append(
            f"| {result['target']} | {label} | {files} | {tech} | {result.get('status')} "
            f"| {_fmt_seconds(result.get('pipeline_seconds'))} "
            f"| {_fmt_seconds(_step_seconds(result, 'scan'))} "
            f"| {_fmt_seconds(_step_seconds(result, 'sbom', 'match'))} "
            f"| {(result.get('candidates') or {}).get('total', '-')} "
            f"| {'-' if raw is None else raw} / {'-' if merged is None else merged} "
            f"| {sca.get('pin_records', '-')} "
            f"| {len((result.get('dependency_manifests') or {}).get('without_lockfile') or [])} "
            f"| {(result.get('long_paths') or {}).get('count', '-')} |"
        )

    engine_names: list[str] = []
    for result in results:
        for engine in result.get("engines") or {}:
            if engine not in engine_names:
                engine_names.append(engine)
    lines += [
        "",
        "## Engines",
        "",
        "Cell: candidates in `candidates.json` (SCA matchers: raw records of the tool; SBOM tool: "
        "components), status when not `ok`, wall time of the engine.",
        "",
        "| Engine | " + " | ".join(r["target"] for r in results) + " |",
        "|---|" + "---|" * len(results),
    ]
    for engine in engine_names:
        cells = []
        for result in results:
            info = (result.get("engines") or {}).get(engine)
            if info is None:
                cells.append("-")
                continue
            count = info.get("candidates")
            sca = result.get("sca") or {}
            if info.get("area") == "sca":
                raw = (sca.get("raw_by_engine") or {}).get(engine) or {}
                count = raw.get("records", count)
                sbom = sca.get("sbom") or {}
                if sbom.get("engine") == engine:
                    count = f"{sbom.get('components')} components"
            status = info.get("status")
            text = "" if count is None else str(count)
            if status != "ok":
                text = f"{text} {status}".strip()
            cells.append(f"{text} ({_fmt_seconds(info.get('duration_seconds'))})")
        lines.append(f"| {engine} | " + " | ".join(cells) + " |")

    lines += [
        "",
        "## SCA records by severity (merged)",
        "",
        "| Target | " + " | ".join(SEVERITIES) + " |",
        "|---|" + "---|" * len(SEVERITIES),
    ]
    for result in results:
        severity = (result.get("sca") or {}).get("merged_by_severity") or {}
        lines.append(
            f"| {result['target']} | "
            + " | ".join(str(severity.get(level, 0)) for level in SEVERITIES)
            + " |"
        )

    for result in results:
        fixture = result.get("fixture")
        if not fixture:
            continue
        overall = fixture["overall"]
        items = fixture["items"]
        lines += [
            "",
            f"## Fixture recall ({result['target']})",
            "",
            f"{items['vulnerable']} vulnerable items ({items['agent_only']} agent-only, not "
            f"scored), {items['secure_twins']} secure twins. Found by an expected engine: "
            f"{overall['found_by_an_expected_engine']} of {items['deterministic']} "
            f"({_fmt_pct(overall['recall_expected_engines'])}); by any engine: "
            f"{overall['found_by_any_engine']} ({_fmt_pct(overall['recall_any_engine'])}). "
            f"Twins with a false positive: {overall['twins_with_fp']}.",
            "",
            "Found: same file, start line within 2 lines, or the result region covers the line "
            "(±2 only in brackets). Twin FP: fixture README rule (own rules: any result; other "
            "engines: counterpart rule IDs). Any-rule: twins with any result within 2 lines.",
            "",
            "| Engine | Status | Expected | Found | Recall | Twin FP | Twin hits (any rule) "
            "| Results off planted items |",
            "|---|---|---|---|---|---|---|---|",
        ]
        for engine, info in fixture["engines"].items():
            if not info["expected"] and not info["results"]:
                continue
            found = f"{info['found']} ({info['found_pm2']})" if info["expected"] else "-"
            lines.append(
                f"| {engine} | {info['engine_status'] or 'not run'} | {info['expected']} "
                f"| {found} | {_fmt_pct(info['recall'])} | {info['twin_fp']} "
                f"| {info['twin_hits_any_rule']} | {info['unplanned_results']} |"
            )

    problems: list[str] = []
    for result in results:
        failure = result.get("failure")
        if failure:
            problems.append(f"{result['target']}: {json.dumps(failure, ensure_ascii=False)}")
        for engine, info in (result.get("engines") or {}).items():
            if info.get("status") not in ("ok", "skipped"):
                problems.append(
                    f"{result['target']}: {engine} {info.get('status')}: "
                    f"{(info.get('message') or '').strip()[:200]}"
                )
        count = (result.get("long_paths") or {}).get("count") or 0
        if count:
            problems.append(
                f"{result['target']}: {count} files have an absolute path of 260 or more "
                "characters; Opengrep skips them without a warning (`run init` records them)"
            )
        unlocked = (result.get("dependency_manifests") or {}).get("without_lockfile") or []
        if unlocked:
            shown = ", ".join(f"`{path}`" for path in unlocked[:5])
            more = f" and {len(unlocked) - 5} more" if len(unlocked) > 5 else ""
            sca = result.get("sca") or {}
            if sca.get("manifest_pins"):
                checked = (
                    f"SCA checked only their {sca['manifest_pins']} exact pins "
                    f"({sca.get('pin_records') or 0} records)"
                )
            else:
                checked = "they have no exact pins, so SCA checked none of their dependencies"
            problems.append(
                f"{result['target']}: {len(unlocked)} dependency manifests without a lockfile "
                f"({shown}{more}): {checked}; version ranges and transitive dependencies are "
                "not checked"
            )
        coverage = ((result.get("engines") or {}).get("opengrep") or {}).get("coverage") or {}
        partial = coverage.get("partially_scanned_files") or 0
        reasons = coverage.get("skipped_reasons")
        if isinstance(reasons, dict):
            skipped = "; ".join(f"{n} {reason}" for reason, n in reasons.items()) or "none"
        else:
            large = coverage.get("skipped_large_files") or 0
            skipped = f"{large} files larger than 1 MB" if large else "none"
        if partial or skipped != "none":
            problems.append(
                f"{result['target']}: opengrep analyzed {partial} files only partially (parse "
                f"errors); skipped: {skipped}"
            )
    lines += ["", "## Problems", ""]
    lines += [f"- {problem}" for problem in problems] or ["- None recorded."]
    path = RESULTS_DIR / "SUMMARY.md"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    return path


# --- main --------------------------------------------------------------------------------------


def load_targets() -> list[dict[str, Any]]:
    data = _read_json(TARGETS_FILE)
    return [t for t in data.get("targets") or [] if isinstance(t, dict) and t.get("name")]


def main(argv: list[str] | None = None) -> int:
    targets = load_targets()
    names = [t["name"] for t in targets]
    parser = argparse.ArgumentParser(
        description="Benchmark the deterministic kalkan pipeline on the targets of "
        "benchmarks/targets.json."
    )
    parser.add_argument(
        "--target", default="all", choices=[*names, "all"], help="target name or 'all'"
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="pass --offline to the scanners and SCA (cached databases, no clone)",
    )
    args = parser.parse_args(argv)

    if RUNS_DIR.resolve() == (REPO / "runs").resolve():
        print("refusing to use the default runs folder", file=sys.stderr)
        return 2
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    try:
        python = _venv_python()
    except BenchError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    kalkan = kalkan_info(python)
    tools = tool_versions()
    selected = targets if args.target == "all" else [t for t in targets if t["name"] == args.target]
    exit_code = 0
    for target in selected:
        print(f"== {target['name']}", file=sys.stderr, flush=True)
        result = benchmark_target(
            target, python=python, offline=args.offline, kalkan=kalkan, tools=tools
        )
        _write_json(RESULTS_DIR / f"{target['name']}.json", result)
        print(
            f"== {target['name']}: {result['status']} in {_fmt_seconds(result['wall_seconds'])}",
            file=sys.stderr,
            flush=True,
        )
        if result["status"] == "failed":
            exit_code = 1
    summary = write_summary(names)
    print(f"summary: {summary.relative_to(REPO).as_posix()}", file=sys.stderr)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
