# SPDX-License-Identifier: MIT
"""helm-checkov (K.3) and vacuum (K.9) with the real tools, in local mode, under the proxy trap
of ``conftest.py`` (ADR-0005; docs/SECURITY.md, promise 3).

The tests run the installed tools (``kalkan tools install helm checkov vacuum``) and skip when
one is missing:

- helm-checkov on the vulnapp fixture: zero connections, the two Helm items at their template
  lines, nothing of their rules on the twins.
- helm-checkov on charts with remote dependencies (https and oci) and with a values schema
  whose ``$ref`` is remote: zero connections, the dependency chart is a scan gap, no file of
  the target changes (no ``charts/`` download). Control: ``helm template`` without
  ``--skip-schema-validation`` connects to the schema host.
- vacuum on the vulnapp fixture: zero connections, exactly the planted OpenAPI items, nothing
  on the twin document.
- vacuum on a document with a remote ``$ref`` and on a document whose ``$ref`` leaves the
  target: zero connections, the first is partly linted, the second is refused and the content
  of the outside file reaches no kalkan file. Controls: vacuum without ``--remote=false``
  connects to the reference host, and vacuum with ``--remote=false`` still reads the outside
  file (the reason for the reference check).

Run with ``pytest -m tools tests/integration/test_k3_k9_tools.py``.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from kalkan.run import tech
from kalkan.scanners import registry
from kalkan.scanners.adapters.vacuum import RULESET
from kalkan.scanners.base import load_scan_context, minimal_env, run_adapter
from kalkan.scanners.candidates import load_candidates
from kalkan.tools.resolve import resolve

pytestmark = pytest.mark.tools

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "vulnapp"
EXPECTED = FIXTURE / "EXPECTED.json"
ANSWER_FILES = frozenset({"README.md", "EXPECTED.json", "INJECTION-NOTE.md"})
BUILD_FOLDERS = frozenset({"obj", "bin"})
LINE_SLACK = 2
OUTSIDE_MARKER = "kalkan_outside_marker_7f3a"


def _require(*tools: str) -> None:
    for name in tools:
        if resolve(name) is None:
            pytest.skip(f"{name} is not installed (run: kalkan tools install {name})")


def _ignore(folder: str, names: list[str]) -> set[str]:
    skipped = {name for name in names if name in BUILD_FOLDERS}
    if Path(folder).resolve() == FIXTURE:
        skipped |= {name for name in names if name in ANSWER_FILES}
    return skipped


def _run_with_target(root: Path, files: dict[str, str] | None = None) -> Path:
    run = root / "run"
    if files is None:
        shutil.copytree(FIXTURE, run / "target", ignore=_ignore)
    else:
        for rel, text in files.items():
            path = run / "target" / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8", newline="\n")
    manifest = {"copy": "target", "source_dir": None, "tech": tech.detect(run / "target")}
    (run / "target-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return run


def _trap(monkeypatch, trap_proxy):
    proxy = trap_proxy()
    for name, value in proxy.env().items():
        monkeypatch.setenv(name, value)
    return proxy


def _items(engine: str) -> list[dict]:
    entries = json.loads(EXPECTED.read_text(encoding="utf-8"))
    return [entry for entry in entries if engine in entry.get("expected_engines", [])]


def _twin(item: dict) -> dict:
    entries = {e["id"]: e for e in json.loads(EXPECTED.read_text(encoding="utf-8"))}
    return entries[item["twin"]]


def _found(candidates: list[dict], engine: str, entry: dict, rules: list[str]) -> bool:
    for candidate in candidates:
        if candidate["engine"] != engine or candidate["file"] != entry["file"]:
            continue
        if candidate["rule_id"] not in rules:
            continue
        start = candidate["start_line"] or 0
        end = candidate["end_line"] or start
        if start - LINE_SLACK <= entry["line"] <= end + LINE_SLACK:
            return True
    return False


def _status(run: Path, engine: str) -> dict:
    return json.loads((run / "scans" / f"{engine}.status.json").read_text(encoding="utf-8"))


def _snapshot(folder: Path) -> dict[str, tuple[int, int]]:
    return {
        path.relative_to(folder).as_posix(): (path.stat().st_size, path.stat().st_mtime_ns)
        for path in folder.rglob("*")
    }


def _kalkan_files_text(run: Path) -> str:
    paths = [*(run / "scans").rglob("*"), run / "candidates.json"]
    return "\n".join(
        path.read_text(encoding="utf-8", errors="replace") for path in paths if path.is_file()
    )


# --------------------------------------------------------------------------------------------
# helm-checkov


def test_helm_checkov_finds_the_fixture_chart_items_offline(tmp_path, monkeypatch, trap_proxy):
    _require("helm", "checkov")
    run = _run_with_target(tmp_path)
    proxy = _trap(monkeypatch, trap_proxy)
    result = run_adapter(registry.get("helm-checkov"), load_scan_context(run, offline=True))
    assert proxy.connections == [], proxy.connections
    assert result.status == "ok", result.message
    assert result.tool_version == "4.3.0"
    candidates = load_candidates(run)["candidates"]
    items = _items("helm-checkov")
    assert {item["id"] for item in items} == {"helm-privileged-01", "helm-host-network-01"}
    for item in items:
        rules = item["rules"]["helm-checkov"]
        assert _found(candidates, "helm-checkov", item, rules), item["id"]
        assert not _found(candidates, "helm-checkov", _twin(item), rules), item["twin"]
    lines = {
        (c["rule_id"], c["start_line"], c["end_line"])
        for c in candidates
        if c["engine"] == "helm-checkov" and c["rule_id"] in ("CKV_K8S_16", "CKV_K8S_19")
    }
    assert lines == {("CKV_K8S_16", 26, 26), ("CKV_K8S_19", 17, 17)}
    assert {c["file"] for c in candidates if c["engine"] == "helm-checkov"} == {
        "infra/helm/shop/templates/log-agent.yaml",
        "infra/helm/shop/templates/web.yaml",
    }
    status = _status(run, "helm-checkov")
    assert status["charts"]["rendered"] == ["infra/helm/shop"]
    assert status["checkov_version"] == "3.3.22"
    assert "--skip-schema-validation" in status["command"]


DEPS_CHART = (
    "apiVersion: v2\nname: deps\nversion: 0.1.0\ndependencies:\n"
    "  - name: redis\n    version: 1.0.0\n    repository: https://charts.kalkan-trap.invalid/stable\n"
    "  - name: pg\n    version: 2.0.0\n    repository: oci://registry.kalkan-trap.invalid/charts\n"
)
SCHEMA = (
    '{"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object", '
    '"properties": {"replicas": {"$ref": "https://schemas.kalkan-trap.invalid/replicas.json"}}}\n'
)
POD = (
    "apiVersion: v1\nkind: Pod\nmetadata:\n  name: {{ .Release.Name }}-web\nspec:\n"
    "  containers:\n    - name: web\n      image: nginx:latest\n      securityContext:\n"
    "        privileged: {{ .Values.privileged }}\n"
)
REMOTE_CHARTS = {
    "deps/Chart.yaml": DEPS_CHART,
    "deps/values.yaml": "privileged: true\n",
    "deps/templates/pod.yaml": POD,
    "schema/Chart.yaml": "apiVersion: v2\nname: schema\nversion: 0.1.0\n",
    "schema/values.yaml": "replicas: 1\nprivileged: true\n",
    "schema/values.schema.json": SCHEMA,
    "schema/templates/pod.yaml": POD,
}


def test_helm_checkov_downloads_no_chart_and_no_schema(tmp_path, monkeypatch, trap_proxy):
    _require("helm", "checkov")
    run = _run_with_target(tmp_path, REMOTE_CHARTS)
    before = _snapshot(run / "target")
    proxy = _trap(monkeypatch, trap_proxy)
    result = run_adapter(registry.get("helm-checkov"), load_scan_context(run, offline=True))
    assert proxy.connections == [], proxy.connections
    assert result.status == "ok", result.message
    assert _snapshot(run / "target") == before  # no charts/ folder, no Chart.lock
    status = _status(run, "helm-checkov")
    assert status["charts"]["rendered"] == ["schema"]
    assert status["skipped_files"]["paths"] == ["deps/Chart.yaml"]
    [gap] = status["chart_gaps"]
    assert gap["detail"] == "missing in charts/: redis, pg"
    found = {
        (c["rule_id"], c["file"], c["start_line"])
        for c in load_candidates(run)["candidates"]
        if c["rule_id"] == "CKV_K8S_16"
    }
    assert found == {("CKV_K8S_16", "schema/templates/pod.yaml", 10)}

    # Control: without --skip-schema-validation helm fetches the remote schema reference.
    helm = resolve("helm")
    assert helm is not None
    control = trap_proxy()
    work = tmp_path / "control"
    for folder in ("cache", "config", "data", "out"):
        (work / folder).mkdir(parents=True)
    env = minimal_env(
        {
            **control.env(),
            "HELM_CACHE_HOME": str(work / "cache"),
            "HELM_CONFIG_HOME": str(work / "config"),
            "HELM_DATA_HOME": str(work / "data"),
        }
    )
    argv = [*helm.argv, "template", "x", str(run / "target" / "schema")]
    subprocess.run(
        [*argv, "--output-dir", str(work / "out")],
        cwd=work,
        env=env,
        capture_output=True,
        timeout=120,
        check=False,
    )
    assert any(b"schemas.kalkan-trap.invalid" in item for item in control.connections), (
        control.connections
    )


# --------------------------------------------------------------------------------------------
# vacuum


def test_vacuum_finds_exactly_the_fixture_items_offline(tmp_path, monkeypatch, trap_proxy):
    _require("vacuum")
    run = _run_with_target(tmp_path)
    proxy = _trap(monkeypatch, trap_proxy)
    result = run_adapter(registry.get("vacuum"), load_scan_context(run, offline=True))
    assert proxy.connections == [], proxy.connections
    assert result.status == "ok", result.message
    assert result.tool_version == "0.33.0"
    candidates = [c for c in load_candidates(run)["candidates"] if c["engine"] == "vacuum"]
    items = _items("vacuum")
    assert len(items) == 5
    for item in items:
        rules = item["rules"]["vacuum"]
        assert _found(candidates, "vacuum", item, rules), item["id"]
        assert not _found(candidates, "vacuum", _twin(item), rules), item["twin"]
    planted = {(item["file"], item["line"]) for item in items}
    stray = [
        (c["rule_id"], c["file"], c["start_line"])
        for c in candidates
        if not any(
            f == c["file"] and abs(n - (c["start_line"] or 0)) <= LINE_SLACK for f, n in planted
        )
    ]
    assert stray == []
    assert not [c for c in candidates if c["file"] == "api/partner-api.yaml"]
    by_rule = {c["rule_id"]: c["class"] for c in candidates}
    assert by_rule["owasp-protection-global-unsafe"] == "authn"
    assert by_rule["owasp-no-api-keys-in-url"] == "sensitive-data-exposure"
    assert by_rule["owasp-no-additionalProperties"] == "mass-assignment"
    status = _status(run, "vacuum")
    assert status["documents"]["files"] == ["api/partner-api.yaml", "api/shop-api.yaml"]
    command = status["commands"][0] if "commands" in status else status["command"]
    assert "--remote=false" in command and "--no-update-check" in command


SPEC_HEAD = (
    "openapi: 3.0.3\ninfo:\n  title: t\n  version: '1'\nservers:\n  - url: https://a.example\n"
    "paths:\n  /a:\n    post:\n      requestBody:\n        content:\n          application/json:\n"
    "            schema:\n"
)


def test_vacuum_fetches_nothing_and_reads_nothing_outside_the_target(
    tmp_path, monkeypatch, trap_proxy
):
    _require("vacuum")
    outside = tmp_path / "outside.yaml"
    outside.write_text(
        f"Leak:\n  type: object\n  properties:\n    {OUTSIDE_MARKER}:\n      type: string\n",
        encoding="utf-8",
    )
    files = {
        "api/remote.yaml": SPEC_HEAD
        + "              $ref: https://schemas.kalkan-trap.invalid/order.yaml#/Order\n"
        + "      responses:\n        '201':\n          description: ok\n",
        "api/escape.yaml": SPEC_HEAD
        + "              $ref: ../../../outside.yaml#/Leak\n"
        + "      responses:\n        '201':\n          description: ok\n",
    }
    run = _run_with_target(tmp_path, files)
    assert (run / "target" / "api" / "../../../outside.yaml").resolve() == outside.resolve()
    proxy = _trap(monkeypatch, trap_proxy)
    result = run_adapter(registry.get("vacuum"), load_scan_context(run, offline=True))
    assert proxy.connections == [], proxy.connections
    assert result.status == "ok", result.message
    status = _status(run, "vacuum")
    assert status["documents"]["files"] == ["api/remote.yaml"]
    assert status["skipped_files"]["paths"] == ["api/escape.yaml"]
    assert status["partial_files"]["paths"] == ["api/remote.yaml"]
    assert OUTSIDE_MARKER not in _kalkan_files_text(run)

    vacuum = resolve("vacuum")
    assert vacuum is not None
    work = tmp_path / "control"
    work.mkdir()
    (work / "ruleset.yaml").write_text(RULESET, encoding="utf-8")
    (work / "empty.yaml").write_text("", encoding="utf-8")
    base = [*vacuum.argv, "spectral-report", "--no-update-check", "--no-style", "--no-pretty"]
    base += ["--config", str(work / "empty.yaml"), "--ruleset", str(work / "ruleset.yaml")]

    # Control 1: without --remote=false vacuum fetches the remote reference.
    control = trap_proxy()
    env = minimal_env(control.env())
    spec = str(run / "target" / "api" / "remote.yaml")
    subprocess.run(
        [*base, spec, str(work / "r1.json")],
        cwd=work,
        env=env,
        capture_output=True,
        timeout=180,
        check=False,
    )
    assert any(b"schemas.kalkan-trap.invalid" in item for item in control.connections), (
        control.connections
    )

    # Control 2: with --remote=false vacuum still reads the file outside the target, which is
    # why the adapter refuses such a document.
    spec = str(run / "target" / "api" / "escape.yaml")
    subprocess.run(
        [*base, "--remote=false", spec, str(work / "r2.json")],
        cwd=work,
        env=minimal_env(),
        capture_output=True,
        timeout=180,
        check=False,
    )
    assert OUTSIDE_MARKER in (work / "r2.json").read_text(encoding="utf-8")
    assert os.path.exists(outside)
