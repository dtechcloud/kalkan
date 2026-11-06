# SPDX-License-Identifier: MIT
"""The security promises of docs/SECURITY.md, tested end to end.

Promise 1: ``run init``, the scanners and the SCA steps never write into the audited folder,
and no scanner gets its path. The fixture repository is built in ``tmp_path`` with traps that a
git process in the original would trigger: a ``core.fsmonitor`` command, a textconv driver, a
clean and smudge filter, hooks for every event, and a hidden ref. Every file and folder of the
repository (``.git`` included) is hashed with its size and modification time before and after.

Promise 3: with ``@pytest.mark.tools``, ``scan all`` and ``sca match`` run with every proxy
variable pointing at a local trap server (``trap_proxy`` of ``conftest.py``), which counts each
connection. Tools that honor the proxy variables (all Go tools, Python, git) therefore cannot
reach the network unnoticed. ``tests/integration/test_go_tools.py`` runs govulncheck with the
same trap.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from kalkan.run import init as init_mod
from kalkan.scanners import registry
from kalkan.scanners.adapters import _common, helm_checkov
from kalkan.scanners.base import load_scan_context
from kalkan.tools.resolve import ResolvedTool

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")
TOOL = Path("/opt/kalkan-fake-tool")

#: Hook names that a git process in the original could run.
HOOKS = (
    "applypatch-msg",
    "commit-msg",
    "fsmonitor-watchman",
    "post-checkout",
    "post-commit",
    "post-index-change",
    "post-merge",
    "post-rewrite",
    "pre-auto-gc",
    "pre-commit",
    "pre-push",
    "pre-rebase",
    "push-to-checkout",
    "reference-transaction",
    "update",
    "post-update",
    "pre-receive",
    "post-receive",
)


def _git_env(tmp_path: Path) -> dict[str, str]:
    config = tmp_path / "gitconfig"
    if not config.exists():
        config.write_text("", encoding="utf-8")
    return {
        **os.environ,
        "GIT_CONFIG_GLOBAL": str(config),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "kalkan test",
        "GIT_AUTHOR_EMAIL": "test@example.com",
        "GIT_COMMITTER_NAME": "kalkan test",
        "GIT_COMMITTER_EMAIL": "test@example.com",
    }


def _git(repo: Path, env: dict[str, str], *args: str) -> str:
    done = subprocess.run(
        ["git", *args], cwd=repo, env=env, check=True, capture_output=True, text=True, timeout=60
    )
    return done.stdout.strip()


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def make_trap_repo(tmp_path: Path) -> tuple[Path, Path, dict[str, str]]:
    """Build the fixture repository; return ``(repo, markers folder, facts)``."""
    env = _git_env(tmp_path)
    repo = tmp_path / "proje ü"  # a space and a non-ASCII letter in the path
    repo.mkdir()
    _git(repo, env, "init", "-q", "-b", "main")
    _write(repo / "app.py", "import os\nprint(os.environ.get('X'))\n")
    _write(repo / "Dockerfile", "FROM python:3.12-slim\nCOPY app.py /app.py\n")
    _write(repo / "go.mod", "module example.com/x\n\ngo 1.22\n")
    _write(repo / "main.go", "package main\n\nfunc main() {}\n")
    _write(repo / "requirements.txt", "flask==0.12\n")
    _write(repo / "deploy.sh", "#!/bin/sh\nrm -rf $1/\n")  # ShellCheck
    _write(repo / "util.c", "void f(char *s) { char b[8]; strcpy(b, s); }\n")  # flawfinder
    _write(repo / "nginx.conf", "server {\n  location /a { alias /data/; }\n}\n")  # gixy
    # helm-checkov: a chart with a remote values schema, a chart with remote dependencies.
    _write(repo / "chart" / "Chart.yaml", "apiVersion: v2\nname: web\nversion: 0.1.0\n")
    _write(repo / "chart" / "values.yaml", "replicas: 1\n")
    _write(
        repo / "chart" / "values.schema.json",
        '{"properties": {"replicas": {"$ref": "https://schemas.kalkan-trap.invalid/r.json"}}}\n',
    )
    _write(repo / "chart" / "templates" / "cm.yaml", "kind: ConfigMap\napiVersion: v1\n")
    _write(
        repo / "chart-deps" / "Chart.yaml",
        "apiVersion: v2\nname: deps\nversion: 0.1.0\ndependencies:\n  - name: redis\n"
        "    version: 1.0.0\n    repository: https://charts.kalkan-trap.invalid/stable\n",
    )
    # vacuum: an OpenAPI document with a remote reference.
    _write(
        repo / "openapi.yaml",
        "openapi: 3.0.3\ninfo:\n  title: t\n  version: '1'\npaths:\n  /a:\n    get:\n"
        "      responses:\n        '200':\n          description: ok\n          content:\n"
        "            application/json:\n              schema:\n"
        "                $ref: https://schemas.kalkan-trap.invalid/a.yaml\n",
    )
    _write(repo / ".gitattributes", "* diff=trap filter=trap\n")
    token = "ghp_" + "Xq7Lm2Pz9Vb4Nc8Rt1Kw6Hy3Jd5Sf0Ga2Uex"  # a made-up GitHub token
    _write(repo / "secret.txt", f"GITHUB_TOKEN = {token}\n")
    _git(repo, env, "add", "-A")
    _git(repo, env, "commit", "-q", "-m", "one")
    _git(repo, env, "rm", "-q", "secret.txt")
    _git(repo, env, "commit", "-q", "-m", "two")
    _git(repo, env, "checkout", "-q", "-b", "hidden")
    _write(repo / "hidden.txt", "only on a hidden branch\n")
    _git(repo, env, "add", "-A")
    _git(repo, env, "commit", "-q", "-m", "hidden")
    _git(repo, env, "checkout", "-q", "main")
    _write(repo / "work.txt", "stashed work\n")
    _git(repo, env, "stash", "push", "-q", "-u")
    _git(repo, env, "checkout", "-q", "--detach")
    _write(repo / "detached.txt", "a commit that no branch holds\n")
    _git(repo, env, "add", "-A")
    _git(repo, env, "commit", "-q", "-m", "detached")
    head = _git(repo, env, "rev-parse", "HEAD")
    hidden = _git(repo, env, "rev-parse", "refs/heads/hidden")

    # Traps, set after the history so that building it did not trigger them.
    markers = tmp_path / "markers"
    markers.mkdir()
    trap = tmp_path / "trap.sh"
    _write(trap, f'#!/bin/sh\necho "$0 $*" >> \'{markers.as_posix()}/\'"$1"\n')
    hooks = tmp_path / "hooks"
    for name in HOOKS:
        _write(hooks / name, f"#!/bin/sh\nsh '{trap.as_posix()}' hook-{name}\n")
        (hooks / name).chmod(0o755)
    command = f"sh '{trap.as_posix()}'"
    for key, value in (
        ("core.fsmonitor", f"{command} fsmonitor"),
        ("core.hooksPath", hooks.as_posix()),
        ("diff.trap.textconv", f"{command} textconv"),
        ("filter.trap.clean", f"{command} clean"),
        ("filter.trap.smudge", f"{command} smudge"),
        ("uploadpack.hideRefs", "refs/heads/hidden"),
        ("transfer.hideRefs", "refs/stash"),
    ):
        _git(repo, env, "config", key, value)
    return repo, markers, {"head": head, "hidden": hidden}


def snapshot(root: Path) -> dict[str, tuple]:
    """Return every file and folder under ``root`` (``.git`` included) with its content hash,
    size and modification time. A new, removed or rewritten entry changes the result."""
    found: dict[str, tuple] = {}
    for folder, dirs, files in os.walk(root):
        base = Path(folder)
        info = base.stat()
        found[base.relative_to(root).as_posix() + "/"] = ("dir", info.st_mtime_ns)
        for name in files:
            path = base / name
            data = path.read_bytes()
            stat = path.stat()
            found[path.relative_to(root).as_posix()] = (
                hashlib.sha256(data).hexdigest(),
                stat.st_size,
                stat.st_mtime_ns,
            )
        dirs.sort()
    return found


def _mentions(text: str, folder: Path) -> bool:
    forms = {str(folder), folder.as_posix(), str(folder.resolve()), folder.resolve().as_posix()}
    if os.name == "nt":
        return any(form.casefold() in text.casefold() for form in forms)
    return any(form in text for form in forms)


# ---------------------------------------------------------------------------------------------
# Promise 1


@needs_git
def test_run_init_never_writes_into_the_original_and_copies_every_ref(tmp_path, monkeypatch):
    repo, markers, facts = make_trap_repo(tmp_path)
    before = snapshot(repo)

    ctx = init_mod.init_run(str(repo), runs_dir=tmp_path / "runs")

    assert snapshot(repo) == before
    assert sorted(path.name for path in markers.iterdir()) == []
    manifest = json.loads((ctx.run_dir / "target-manifest.json").read_text(encoding="utf-8"))
    source = ctx.run_dir / "source"
    assert manifest["history"]["status"] == "copied"
    assert manifest["source_dir"] == source.absolute().as_posix()
    assert manifest["git_ref"] == facts["head"]  # the detached HEAD, read from the copy
    env = _git_env(tmp_path)
    refs = _git(source, env, "for-each-ref", "--format=%(refname)")
    assert "refs/heads/hidden" in refs.split()  # uploadpack.hideRefs did not hide it
    assert "refs/stash" in refs.split()  # transfer.hideRefs did not hide it
    assert _git(source, env, "rev-parse", "refs/heads/hidden") == facts["hidden"]
    config = (source / "config").read_text(encoding="utf-8")
    assert "remote" not in config and "hooksPath" not in config
    assert not (source / "hooks").exists()
    assert init_mod.read_head(repo) == facts["head"]  # the file reader agrees

    # Control: the traps work. A plain `git log -p` in the original runs the textconv driver.
    _git(repo, env, "log", "-p", "-3")
    assert "textconv" in {path.name for path in markers.iterdir()}


@needs_git
def test_no_scanner_gets_the_original_path(tmp_path, monkeypatch):
    repo, _markers, _facts = make_trap_repo(tmp_path)
    ctx = init_mod.init_run(str(repo), runs_dir=tmp_path / "runs")
    monkeypatch.setattr(_common, "executable_finder", lambda name: Path(f"/usr/bin/{name}"))
    # helm-checkov builds its Checkov command from an installed Checkov; a fake one keeps the
    # test independent of the installed tools (CI runs without them).
    monkeypatch.setattr(
        helm_checkov,
        "checkov_resolver",
        lambda **_: ResolvedTool(name="checkov", path=TOOL, version="0", source="kalkan"),
    )
    scan_ctx = load_scan_context(ctx.run_dir)
    assert scan_ctx.source_dir == (ctx.run_dir / "source").resolve()
    assert {"go", "python", "docker"} <= scan_ctx.tech
    (ctx.run_dir / "sca").mkdir()
    (ctx.run_dir / "sca" / "sbom.cdx.json").write_text("{}", encoding="utf-8")
    (ctx.run_dir / "sca" / "manifest-pins.cdx.json").write_text("{}", encoding="utf-8")
    checked = 0
    for name in registry.names():
        adapter = registry.get(name)
        if adapter.tool is None:
            continue
        out = ctx.run_dir / adapter.output_dir / ".work" / adapter.name / adapter.output_name
        for invocation in adapter.invocations(scan_ctx, TOOL, out):
            text = "\n".join(invocation.argv)
            assert not _mentions(text, repo), (name, invocation.argv)
            assert invocation.cwd.resolve().is_relative_to(ctx.run_dir.resolve()), name
            checked += 1
        env_text = "\n".join(f"{key}={value}" for key, value in adapter.env(scan_ctx).items())
        assert not _mentions(env_text, repo), name
    assert checked >= len(registry.names()) - 1


@needs_git
def test_a_failed_history_copy_is_recorded_not_fatal(tmp_path, monkeypatch):
    repo, _markers, facts = make_trap_repo(tmp_path)

    def broken(*args, **kwargs):
        raise init_mod.ToolError("the history copy failed (git clone exit 128): dubious ownership")

    monkeypatch.setattr(init_mod, "copy_history", broken)
    ctx = init_mod.init_run(str(repo), runs_dir=tmp_path / "runs")
    manifest = json.loads((ctx.run_dir / "target-manifest.json").read_text(encoding="utf-8"))
    assert manifest["source_dir"] is None
    assert manifest["history"] == {
        "status": "failed",
        "detail": "the history copy failed (git clone exit 128): dubious ownership",
    }
    assert manifest["git_ref"] == facts["head"]  # read from the files of the original
    assert not (ctx.run_dir / "source").exists()
    adapter = registry.get("gitleaks-history")
    ok, reason = adapter.applies(load_scan_context(ctx.run_dir))
    assert ok is False and "dubious ownership" in reason


@needs_git
def test_read_head_of_a_subfolder_reads_files_only(tmp_path, monkeypatch):
    repo, markers, facts = make_trap_repo(tmp_path)
    sub = repo / "pkg"
    sub.mkdir()
    (sub / "mod.py").write_text("x = 1\n", encoding="utf-8")
    before = snapshot(repo)
    monkeypatch.setattr(init_mod.shutil, "which", lambda name: None)  # no git process at all
    ctx = init_mod.init_run(str(sub), runs_dir=tmp_path / "runs")
    assert ctx.state["target"]["git_ref"] == facts["head"]
    manifest = json.loads((ctx.run_dir / "target-manifest.json").read_text(encoding="utf-8"))
    assert manifest["history"]["status"] == "none" and manifest["source_dir"] is None
    assert snapshot(repo) == before
    assert list(markers.iterdir()) == []


# ---------------------------------------------------------------------------------------------
# Promise 1 and 3 with the real tools


def _kalkan(args: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "kalkan", *args],
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=3600,
        check=False,
    )


@pytest.mark.tools
@needs_git
def test_scan_and_sca_never_touch_the_original_or_the_network(tmp_path, trap_proxy):
    from kalkan.sca import vulndb
    from kalkan.tools.resolve import resolve

    if resolve("gitleaks") is None or resolve("osv-scanner") is None:
        pytest.skip("the scanners are not installed (run: kalkan tools install --all)")
    repo, markers, _facts = make_trap_repo(tmp_path)
    before = snapshot(repo)
    runs = tmp_path / "runs"
    proxy = trap_proxy()
    env = {**os.environ, "KALKAN_RUNS_DIR": str(runs), **proxy.env()}
    try:
        init = _kalkan(["run", "init", str(repo), "--json"], env)
        assert init.returncode == 0, init.stderr
        run_dir = runs / ids_read_latest(runs)
        scan = _kalkan(["scan", "all", "--json"], env)
        assert scan.returncode in (0, 1), scan.stderr
        statuses = {item["engine"]: item["status"] for item in json.loads(scan.stdout)["results"]}
        sbom = _kalkan(["sca", "sbom", "--json"], env)
        assert sbom.returncode == 0, sbom.stderr
        match = _kalkan(["sca", "match", "--json"], env)
        assert match.returncode == 0, match.stderr
        summary = json.loads(match.stdout)
    finally:
        proxy.close()

    # No tool tried the network: every proxy-aware client would have connected to the trap.
    assert proxy.connections == [], proxy.connections
    # The original folder is byte for byte, time for time, unchanged; no trap fired.
    assert snapshot(repo) == before
    assert list(markers.iterdir()) == []
    for status in sorted(run_dir.glob("*/*.status.json")):
        assert not _mentions(status.read_text(encoding="utf-8"), repo), status.name
    assert statuses["gitleaks-history"] == "ok"
    assert all(status in ("ok", "skipped") for status in statuses.values()), statuses
    history = json.loads((run_dir / "scans" / "gitleaks-history.status.json").read_text("utf-8"))
    assert history["command"][2].replace("\\", "/").endswith("/source")
    sarif = (run_dir / "scans" / "gitleaks-history.sarif").read_text(encoding="utf-8")
    assert "secret.txt" in sarif  # the deleted secret was found in the copied history
    if vulndb.osv_ecosystems() and vulndb.grype_ready():
        assert summary["engines"]["osv-scanner"]["status"] == "ok"
        assert summary["engines"]["grype"]["status"] == "ok"
        assert summary["merged"] > 0  # flask==0.12 has known vulnerabilities
    else:
        assert summary["database_gaps"]

    # Control: the trap sees a tool that does use the network (the opt-in online match).
    control = trap_proxy()
    env.update(control.env())
    try:
        _kalkan(["sca", "match", "--online", "--json"], env)
    finally:
        control.close()
    assert control.connections, "the trap proxy did not see the online match"
    assert snapshot(repo) == before


def ids_read_latest(runs: Path) -> str:
    return (runs / "LATEST").read_text(encoding="utf-8").strip()
