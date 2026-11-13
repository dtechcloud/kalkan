# SPDX-License-Identifier: MIT
"""Tests for kalkan.tools.doctor with a fake host (no real processes, no machine dependence).

The doctor is strict: a manifest tool that is missing or broken is a ``fail`` with the command
that fixes it. Docker, git and the Claude Code CLI stay warnings.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from kalkan.tools import doctor as doctor_mod
from kalkan.tools.doctor import (
    MIN_FREE_BYTES,
    STATUS_FAIL,
    STATUS_INFO,
    STATUS_OK,
    STATUS_WARN,
    run_doctor,
)
from kalkan.tools.manifest import parse_manifest, tree_digest
from kalkan.tools.platform import PLATFORMS

KEY = "linux-amd64"
FAKE_BINARY = b"\x7fELF-kalkan-test-binary\x00faketool 1.2.3\n"
FAKE_SHA = hashlib.sha256(FAKE_BINARY).hexdigest()
GO_VERSION = "1.26.9"
#: A tiny Go tree: the files of the fake toolchain and their content.
GO_TREE = {"go/bin/go": b"\x7fELF-fake-go\n", "go/VERSION": b"go1.26.9\n"}
GO_TREE_SHA = tree_digest(
    (name, hashlib.sha256(data).hexdigest()) for name, data in GO_TREE.items()
)
CHECK_NAMES = [
    "python",
    "platform",
    "git",
    "docker-client",
    "docker-engine",
    "sandbox-images",
    "manifest",
    "node",
    "claude",
    "unattended:print-mode",
    "unattended:auto-continue",
    "unattended:workspace-trust",
    "unattended:codex",
    "tool:faketool",
    "tool:go",
    "tool:gotool",
    "tool:fakego",
    "paths",
    "location",
    "vulndb",
    "disk",
    "footprint",
    "runs-writable",
]


def manifest_document() -> dict:
    """A fresh manifest document (no dict is shared between tools)."""
    return json.loads(json.dumps(_manifest_document()))


def _manifest_document() -> dict:
    asset = {
        "url": "https://example.com/faketool.tar.gz",
        "sha256": "a" * 64,
        "archive": "tar.gz",
        "binary": "faketool",
        "binary_sha256": FAKE_SHA,
    }
    binary = {
        "license": "MIT",
        "kind": "binary",
        "version_args": ["--version"],
        "sha256_source": "computed-at-pin-time",
        "notes": "",
        "platforms": {key: dict(asset) for key in PLATFORMS},
    }
    go_asset = {
        "url": "https://example.com/go.tar.gz",
        "sha256": "b" * 64,
        "archive": "tar.gz",
        "root": "go",
        "binary": "go/bin/go",
        "binary_sha256": hashlib.sha256(GO_TREE["go/bin/go"]).hexdigest(),
        "files": len(GO_TREE),
        "tree_sha256": GO_TREE_SHA,
    }
    return {
        "schema_version": 1,
        "tools": {
            "faketool": {
                **binary,
                "version": "1.2.3",
                "executable": "faketool",
                "blocked_versions": ["1.2.0"],
            },
            "go": {
                **binary,
                "kind": "toolchain",
                "version": GO_VERSION,
                "executable": "go",
                "version_args": ["env", "GOVERSION"],
                "blocked_versions": [],
                "platforms": {key: dict(go_asset) for key in PLATFORMS},
            },
            "gotool": {
                **binary,
                "version": "2.29.0",
                "executable": "gotool",
                "requires_go": True,
                "min_go_version": "1.25",
                "blocked_versions": [],
            },
            "fakego": {
                "version": "1.8.0",
                "license": "BSD-3-Clause",
                "kind": "go-install",
                "executable": "fakego",
                "version_args": ["-version"],
                "requires_go": True,
                "blocked_versions": [],
                "module": "example.com/fakego@v1.8.0",
                "min_go_version": "1.26",
                "notes": "",
            },
        },
    }


def manifest(document: dict | None = None):
    return parse_manifest(document or manifest_document())


class FakeHost:
    """A fake PATH and process runner. ``go`` is the version of a system Go on PATH."""

    def __init__(
        self,
        *,
        present: tuple[str, ...] = ("git", "docker", "node", "claude"),
        engine_up: bool = False,
        go: str = "1.26.1",
        managed_go: str = GO_VERSION,
        outputs: dict[str, str] | None = None,
        broken: tuple[str, ...] = (),
    ) -> None:
        self.present = set(present)
        self.engine_up = engine_up
        self.go = go
        self.managed_go = managed_go
        self.outputs = {
            "faketool": "faketool 1.2.3",
            "gotool": "Version: 2.29.0",
            "fakego": "govulncheck@v1.8.0",
        }
        self.outputs.update(outputs or {})
        self.broken = set(broken)

    def find(self, name: str) -> Path | None:
        return Path(f"/fake/bin/{name}") if name in self.present else None

    def run(self, argv, *, timeout, env=None, cwd=None):
        argv = [str(a) for a in argv]
        name = Path(argv[0]).name.removesuffix(".exe")
        if name in self.broken:
            raise OSError(f"cannot run {name}")
        if name == "docker" and argv[1] == "version":
            if self.engine_up:
                return self._ok(argv, "27.3.1\n")
            return subprocess.CompletedProcess(
                argv, 1, "\n", "Cannot connect to the Docker daemon. Is the daemon running?\n"
            )
        if name == "go":
            assert argv[1:] == ["env", "GOVERSION"]
            assert env is not None and env["GOTOOLCHAIN"] == "local"
            managed = ".tools" in argv[0].replace("\\", "/")
            return self._ok(argv, f"go{self.managed_go if managed else self.go}\n")
        replies = {
            "git": "git version 2.47.1.windows.1\n",
            "docker": "Docker version 27.3.1, build ce12230\n",
            "node": "v22.17.1\n",
            "claude": "2.1.280 (Claude Code)\n",
        }
        if name in replies:
            return self._ok(argv, replies[name])
        if name in self.outputs:
            return self._ok(argv, self.outputs[name] + "\n")
        raise OSError(f"unexpected command {argv}")

    @staticmethod
    def _ok(argv, out):
        return subprocess.CompletedProcess(argv, 0, out, "")


def _record(root: Path, name: str, record: dict) -> None:
    path = root / ".tools" / "installed.json"
    data = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {"tools": {}}
    data["schema_version"] = 1
    data["tools"][name] = record
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


def install_fake(root: Path, name: str = "faketool", version: str = "1.2.3", data=FAKE_BINARY):
    target = root / ".tools" / name / version / "bin" / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    return target


def install_go_tool(root: Path) -> Path:
    """A go-install tool as kalkan records it (the SHA-256 lives in installed.json)."""
    target = install_fake(root, "fakego", "1.8.0", b"fake govulncheck")
    sha = hashlib.sha256(b"fake govulncheck").hexdigest()
    rel = target.relative_to(root).as_posix()
    _record(root, "fakego", {"version": "1.8.0", "kind": "go-install", "path": rel, "sha256": sha})
    return target


def install_managed_go(root: Path, *, extra: dict[str, bytes] | None = None) -> Path:
    """The kalkan Go tree under .tools/go/<version>/ with its install record."""
    base = root / ".tools" / "go" / GO_VERSION
    for name, data in {**GO_TREE, **(extra or {})}.items():
        path = base / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    _record(
        root,
        "go",
        {
            "version": GO_VERSION,
            "kind": "toolchain",
            "path": f".tools/go/{GO_VERSION}/go/bin/go",
            "sha256": hashlib.sha256(GO_TREE["go/bin/go"]).hexdigest(),
            "files": len(GO_TREE),
            "tree_sha256": GO_TREE_SHA,
        },
    )
    return base / "go" / "bin" / "go"


def install_everything(root: Path) -> None:
    install_fake(root)
    install_fake(root, "gotool", "2.29.0")
    install_managed_go(root)
    install_go_tool(root)


def doctor(
    root: Path,
    host: FakeHost,
    *,
    free: float = 100e9,
    python=(3, 13, 5),
    document=None,
    environ=None,
):
    return run_doctor(
        root,
        manifest=manifest(document),
        runner=host.run,
        finder=host.find,
        key=KEY,
        disk_usage=lambda path: SimpleNamespace(free=int(free)),
        python_version=python,
        environ={} if environ is None else environ,  # never the developer's API keys
    )


@pytest.fixture(autouse=True)
def _no_runs_override(monkeypatch):
    monkeypatch.delenv("KALKAN_RUNS_DIR", raising=False)


def statuses(report) -> dict[str, str]:
    return {check.name: check.status for check in report.checks}


def test_json_shape(tmp_path):
    install_everything(tmp_path)
    report = doctor(tmp_path, FakeHost())
    data = json.loads(json.dumps(report.to_dict()))
    assert set(data) == {
        "schema_version",
        "kalkan_version",
        "platform",
        "repo_root",
        "ok",
        "exit_code",
        "summary",
        "checks",
    }
    assert data["schema_version"] == 1
    assert data["platform"] == KEY
    assert data["repo_root"] == tmp_path.resolve().as_posix()
    assert [check["name"] for check in data["checks"]] == CHECK_NAMES
    for check in data["checks"]:
        assert set(check) == {"name", "status", "detail", "data"}
        assert check["status"] in {"ok", "warn", "fail", "info"}
        assert isinstance(check["detail"], str) and check["detail"]
        assert isinstance(check["data"], dict)
    assert set(data["summary"]) == {"ok", "warn", "fail", "info"}
    assert sum(data["summary"].values()) == len(CHECK_NAMES)
    assert data["ok"] is True and data["exit_code"] == 0


def test_bootstrapped_machine_without_docker_engine_passes(tmp_path):
    install_everything(tmp_path)
    report = doctor(tmp_path, FakeHost())  # no Go on PATH: the kalkan copy is enough
    found = statuses(report)
    assert found["python"] == STATUS_OK
    assert found["docker-client"] == STATUS_OK
    assert found["docker-engine"] == STATUS_WARN  # only the PoC sandbox needs it
    for name in ("faketool", "go", "gotool", "fakego"):
        assert found[f"tool:{name}"] == STATUS_OK, report.check(f"tool:{name}").detail
    assert "runs with Go 1.26.9 (kalkan)" in report.check("tool:gotool").detail
    assert report.check("tool:go").data["source"] == "kalkan"
    assert found["disk"] == STATUS_OK
    assert found["runs-writable"] == STATUS_OK
    assert (tmp_path / "runs").is_dir()
    assert report.exit_code == 0
    assert report.check("tool:faketool").data["hash_ok"] is True


class RecordingHost(FakeHost):
    """A fake host that records the environment and the folder of every tool probe."""

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.probes: dict[str, dict] = {}

    def run(self, argv, *, timeout, env=None, cwd=None):
        name = Path(str(argv[0])).name.removesuffix(".exe")
        if name in self.outputs or name == "go":
            files = sorted(p.name for p in Path(cwd).iterdir()) if cwd is not None else None
            self.probes[name] = {"env": env, "cwd": cwd, "files": files}
        return super().run(argv, timeout=timeout, env=env, cwd=cwd)


def test_tool_version_probes_never_get_the_user_environment(tmp_path, monkeypatch):
    # K.1 (docs/SECURITY.md, promise 3): a version command that phones home must not see a
    # token, and the update checks of the manifest (version_env) apply.
    secrets = {"GITHUB_TOKEN": "ghp_" + "3" * 36, "AWS_SECRET_ACCESS_KEY": "made-up"}
    for name, value in secrets.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("GOFLAGS", "-mod=mod")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    document = manifest_document()
    document["tools"]["faketool"]["version_env"] = {"FAKETOOL_NO_UPDATE_CHECK": "1"}
    install_everything(tmp_path)
    host = RecordingHost()
    report = doctor(tmp_path, host, document=document)
    assert report.exit_code == 0
    assert set(host.probes) == {"faketool", "gotool", "fakego", "go"}
    for name, probe in host.probes.items():
        env = probe["env"]
        assert env is not None, name
        assert not set(secrets) & set(env), name
        assert "GOFLAGS" not in env and env["HTTPS_PROXY"] == "http://127.0.0.1:9", name
        # An empty folder; a Go program finds only kalkan's go/telemetry/mode (off) there.
        go_top = "Library" if sys.platform == "darwin" else "go"  # toolhome.go_user_config_dir
        expected = [] if name == "faketool" else [go_top]
        assert probe["cwd"] is not None and probe["files"] == expected, name
        assert Path(probe["cwd"]).resolve() != Path.cwd().resolve(), name
    assert host.probes["faketool"]["env"]["FAKETOOL_NO_UPDATE_CHECK"] == "1"
    for name in ("gotool", "fakego", "go"):
        assert host.probes[name]["env"]["GOTOOLCHAIN"] == "local", name


def test_missing_tools_fail_with_the_fix_command(tmp_path):
    report = doctor(tmp_path, FakeHost())
    found = statuses(report)
    for name in ("faketool", "go", "gotool", "fakego"):
        check = report.check(f"tool:{name}")
        assert check.status == STATUS_FAIL, (name, check.detail)
        assert f"kalkan tools install {name}" in check.detail
    assert found["docker-engine"] == STATUS_WARN
    assert report.exit_code == 1


def test_tool_that_needs_go_fails_without_go(tmp_path):
    install_fake(tmp_path)
    install_fake(tmp_path, "gotool", "2.29.0")
    install_go_tool(tmp_path)
    report = doctor(tmp_path, FakeHost())  # no kalkan Go, no Go on PATH
    for name in ("gotool", "fakego"):
        check = report.check(f"tool:{name}")
        assert check.status == STATUS_FAIL
        assert "needs Go 1.26 or later" in check.detail
        assert "kalkan tools install go" in check.detail
    assert report.check("tool:faketool").status == STATUS_OK
    assert report.exit_code == 1


def test_system_go_of_the_required_version_is_accepted(tmp_path):
    install_fake(tmp_path)
    install_fake(tmp_path, "gotool", "2.29.0")
    install_go_tool(tmp_path)
    host = FakeHost(present=("git", "go"), go="1.26.1")
    report = doctor(tmp_path, host)
    go = report.check("tool:go")
    assert go.status == STATUS_OK
    assert go.data["source"] == "path"
    assert "Go 1.26.1" in go.detail and "kalkan tools install go" in go.detail
    assert report.check("tool:gotool").status == STATUS_OK
    assert "runs with Go 1.26.1 (path)" in report.check("tool:gotool").detail
    assert report.exit_code == 0


def test_old_system_go_fails(tmp_path):
    install_fake(tmp_path, "gotool", "2.29.0")
    host = FakeHost(present=("git", "go"), go="1.25.3")
    report = doctor(tmp_path, host)
    go = report.check("tool:go")
    assert go.status == STATUS_FAIL
    assert "Go 1.25.3, older than 1.26" in go.detail
    assert "kalkan tools install go" in go.detail
    assert report.check("tool:gotool").status == STATUS_FAIL


def test_kalkan_go_wins_over_a_system_go(tmp_path):
    install_everything(tmp_path)
    report = doctor(tmp_path, FakeHost(present=("git", "go"), go="1.27.2"))
    assert report.check("tool:go").data["source"] == "kalkan"
    assert "runs with Go 1.26.9 (kalkan)" in report.check("tool:gotool").detail


def test_damaged_go_tree_fails(tmp_path):
    install_everything(tmp_path)
    install_managed_go(tmp_path, extra={"go/planted.go": b"package evil\n"})
    check = doctor(tmp_path, FakeHost()).check("tool:go")
    assert check.status == STATUS_FAIL
    assert "3 files installed, the manifest pins 2" in check.detail
    assert "kalkan tools install --force go" in check.detail


def test_go_that_reports_another_version_fails(tmp_path):
    install_everything(tmp_path)
    check = doctor(tmp_path, FakeHost(managed_go="1.26.8")).check("tool:go")
    assert check.status == STATUS_FAIL
    assert "1.26.8" in check.detail and "kalkan tools install --force go" in check.detail


def test_installed_tool_that_does_not_run_fails(tmp_path):
    install_everything(tmp_path)
    check = doctor(tmp_path, FakeHost(broken=("faketool",))).check("tool:faketool")
    assert check.status == STATUS_FAIL
    assert "does not run" in check.detail
    assert "kalkan tools install --force faketool" in check.detail


def test_missing_optional_programs_are_warnings(tmp_path):
    install_everything(tmp_path)
    report = doctor(tmp_path, FakeHost(present=()))
    found = statuses(report)
    assert found["git"] == STATUS_WARN
    assert found["docker-client"] == STATUS_WARN
    assert found["docker-engine"] == STATUS_WARN
    assert found["node"] == STATUS_INFO
    assert found["claude"] == STATUS_WARN
    assert report.exit_code == 0


def test_tool_without_a_build_for_the_platform_is_a_warning(tmp_path):
    install_everything(tmp_path)
    document = manifest_document()
    del document["tools"]["faketool"]["platforms"][KEY]
    document["tools"]["faketool"]["notes"] = f"The release ships no {KEY} build."
    check = doctor(tmp_path, FakeHost(), document=document).check("tool:faketool")
    assert check.status == STATUS_WARN
    assert f"no pinned 1.2.3 build for {KEY}" in check.detail


def test_old_python_fails(tmp_path):
    report = doctor(tmp_path, FakeHost(), python=(3, 10, 12))
    assert report.check("python").status == STATUS_FAIL
    assert report.exit_code == 1
    assert report.to_dict()["ok"] is False


def test_low_disk_space_is_a_warning(tmp_path):
    check = doctor(tmp_path, FakeHost(), free=MIN_FREE_BYTES - 1).check("disk")
    assert check.status == STATUS_WARN
    assert check.data["free_bytes"] == MIN_FREE_BYTES - 1


def test_unwritable_runs_folder_fails(tmp_path, monkeypatch):
    blocker = tmp_path / "not-a-folder"
    blocker.write_text("x", encoding="utf-8")
    monkeypatch.setenv("KALKAN_RUNS_DIR", str(blocker / "runs"))
    report = doctor(tmp_path, FakeHost())
    assert report.check("runs-writable").status == STATUS_FAIL
    assert report.exit_code == 1


def test_hash_mismatch_fails(tmp_path):
    install_fake(tmp_path, data=b"tampered")
    check = doctor(tmp_path, FakeHost()).check("tool:faketool")
    assert check.status == STATUS_FAIL
    assert "kalkan tools install --force faketool" in check.detail


def test_wrong_reported_version_fails(tmp_path):
    install_fake(tmp_path)
    check = doctor(tmp_path, FakeHost(outputs={"faketool": "faketool 9.9.9"})).check(
        "tool:faketool"
    )
    assert check.status == STATUS_FAIL
    assert "9.9.9" in check.detail


def test_blocked_version_on_path_fails(tmp_path):
    host = FakeHost(present=("faketool",), outputs={"faketool": "faketool 1.2.0"})
    check = doctor(tmp_path, host).check("tool:faketool")
    assert check.status == STATUS_FAIL
    assert "blocked version 1.2.0" in check.detail


def test_pinned_version_on_path_is_ok(tmp_path):
    host = FakeHost(present=("faketool",))
    check = doctor(tmp_path, host).check("tool:faketool")
    assert check.status == STATUS_OK
    assert check.data["source"] == "path"


def test_other_version_on_path_fails(tmp_path):
    host = FakeHost(present=("faketool",), outputs={"faketool": "faketool 1.3.0"})
    check = doctor(tmp_path, host).check("tool:faketool")
    assert check.status == STATUS_FAIL
    assert "1.3.0" in check.detail and "kalkan tools install faketool" in check.detail


def test_system_go_of_the_pinned_version_needs_no_fix(tmp_path):
    # The container image: /opt/go is the pinned Go, .tools/go is empty.
    install_fake(tmp_path, "gotool", "2.29.0")
    check = doctor(tmp_path, FakeHost(present=("git", "go"), go=GO_VERSION)).check("tool:go")
    assert check.status == STATUS_OK
    assert check.detail == f"not in .tools, but /fake/bin/go is the pinned Go {GO_VERSION}"


def test_vulndb_check_warns_without_local_databases(tmp_path):
    from kalkan.sca import vulndb
    from kalkan.tools import doctor as doctor_module

    check = doctor_module._check_vulndb(tmp_path)
    assert check.name == "vulndb" and check.status == "warn"
    assert "kalkan sca update-db" in check.detail
    root = vulndb.db_root(tmp_path)
    for name in vulndb.DEFAULT_ECOSYSTEMS:
        (root / "osv" / "osv-scalibr" / name).mkdir(parents=True)
        (root / "osv" / "osv-scalibr" / name / "all.zip").write_bytes(b"zip")
    (root / "grype" / "6").mkdir(parents=True)
    (root / "grype" / "6" / "vulnerability.db").write_bytes(b"db")
    (root / "status.json").write_text('{"updated_at": "2026-10-16T12:00:00Z"}', encoding="utf-8")
    no_go = doctor_module._check_vulndb(tmp_path, now=1792152000.0 + 3600)
    assert no_go.status == "warn" and "no Go database" in no_go.detail
    (root / "go" / "index").mkdir(parents=True)
    (root / "go" / "index" / "db.json").write_text('{"modified": "x"}', encoding="utf-8")
    (root / "go" / "index" / "modules.json").write_text("[]", encoding="utf-8")
    source = {"source": "official", "modified": "2026-10-08T22:31:09Z"}
    (root / "go" / "kalkan-source.json").write_text(json.dumps(source), encoding="utf-8")
    no_retire = doctor_module._check_vulndb(tmp_path, now=1792152000.0 + 3600)
    assert no_retire.status == "warn" and "no RetireJS repository" in no_retire.detail
    (root / "retire").mkdir()
    (root / "retire" / "jsrepository-v5.json").write_text("{}", encoding="utf-8")
    retire = {"source": "https://example.invalid/r.json", "libraries": 74}
    (root / "retire" / "kalkan-source.json").write_text(json.dumps(retire), encoding="utf-8")
    fresh = doctor_module._check_vulndb(tmp_path, now=1792152000.0 + 3600)
    assert fresh.status == "ok", fresh.detail
    assert "Go: the vuln.go.dev archive, modified 2026-10-08T22:31:09Z" in fresh.detail
    assert "RetireJS: 74 libraries" in fresh.detail
    assert fresh.data["go"]["source"] == "official"
    assert fresh.data["retire"]["libraries"] == 74
    stale = doctor_module._check_vulndb(tmp_path, now=1792152000.0 + 30 * 86400)
    assert stale.status == "warn" and "days old" in stale.detail
    # The oldest part decides the age: an update of one part alone does not hide it.
    parts = {
        "updated_at": "2026-11-20T12:00:00Z",
        "osv": {"updated_at": "2026-10-16T12:00:00Z"},
        "grype": {"updated_at": "2026-11-20T12:00:00Z"},
    }
    (root / "status.json").write_text(json.dumps(parts), encoding="utf-8")
    source = {"source": "osv", "modified": "2026-11-20T10:00:00Z"}
    source["updated_at"] = "2026-11-20T12:00:00Z"
    (root / "go" / "kalkan-source.json").write_text(json.dumps(source), encoding="utf-8")
    later = doctor_module._check_vulndb(tmp_path, now=1792152000.0 + 35 * 86400)
    assert later.status == "warn" and "35 days old" in later.detail


# ---------------------------------------------------------------------------------------------
# Generic tool rows, fix commands, check groups and the Claude Code login (kalkan audit)


def test_every_manifest_tool_gets_its_own_row(tmp_path):
    # Tools that other changes add to the manifest need no doctor change.
    document = manifest_document()
    document["tools"]["newscanner"] = {
        **document["tools"]["faketool"],
        "version": "0.4.0",
        "executable": "newscanner",
        "blocked_versions": [],
    }
    report = doctor(tmp_path, FakeHost(), document=document)
    check = report.check("tool:newscanner")
    assert check is not None and check.status == STATUS_FAIL
    assert check.detail == "not installed; run: kalkan tools install newscanner"
    names = [c.name for c in report.checks if c.name.startswith("tool:")]
    assert names == [f"tool:{name}" for name in document["tools"]]


def test_each_failing_row_names_its_fix(tmp_path, monkeypatch):
    blocker = tmp_path / "not-a-folder"
    blocker.write_text("x", encoding="utf-8")
    monkeypatch.setenv("KALKAN_RUNS_DIR", str(blocker / "runs"))
    install_fake(tmp_path, data=b"tampered")
    report = doctor(tmp_path, FakeHost(present=()))
    failing = [check for check in report.checks if check.status == STATUS_FAIL]
    assert {check.name for check in failing} >= {"tool:faketool", "tool:go", "runs-writable"}
    fixes = ("kalkan tools install", "KALKAN_RUNS_DIR", "reinstall kalkan")
    for check in failing:
        assert any(fix in check.detail for fix in fixes), (check.name, check.detail)
    assert "kalkan tools install --force faketool" in report.check("tool:faketool").detail


def test_fix_commands_name_the_engine_path_in_the_plugin_venv(tmp_path, monkeypatch):
    from kalkan import resources

    monkeypatch.setattr(resources, "engine_command", lambda **_: '"C:/d d/venv/kalkan.exe"')
    check = doctor(tmp_path, FakeHost()).check("tool:faketool")
    assert check.detail == 'not installed; run: "C:/d d/venv/kalkan.exe" tools install faketool'


def test_engine_command(tmp_path, monkeypatch):
    from kalkan import resources

    venv = tmp_path / "plugin data" / "venv"
    venv.mkdir(parents=True)
    assert resources.engine_command(prefix=venv) == "kalkan"  # this is a checkout
    monkeypatch.setattr(resources, "checkout_root", lambda: None)
    assert resources.engine_command(prefix=venv) == "kalkan"  # no marker: no plugin venv
    resources.write_home_marker(venv, tmp_path)
    script = venv / ("Scripts/kalkan.exe" if os.name == "nt" else "bin/kalkan")
    assert resources.engine_command(prefix=venv) == f'"{script.as_posix()}"'


def _doctor_with(tmp_path, host, skip):
    return run_doctor(
        tmp_path,
        manifest=manifest(),
        runner=host.run,
        finder=host.find,
        key=KEY,
        disk_usage=lambda path: SimpleNamespace(free=int(100e9)),
        skip=skip,
    )


def test_check_groups_can_be_left_out(tmp_path):
    install_everything(tmp_path)
    report = _doctor_with(tmp_path, FakeHost(), {"docker", "node", "claude"})
    names = [check.name for check in report.checks]
    for left_out in ("docker-client", "docker-engine", "node", "claude"):
        assert left_out not in names
    assert not [name for name in names if name.startswith("unattended:")]
    assert "tool:faketool" in names and "vulndb" in names
    names = [check.name for check in _doctor_with(tmp_path, FakeHost(), {"tools"}).checks]
    assert "vulndb" not in names and not [n for n in names if n.startswith("tool:")]
    assert "claude" in names and "runs-writable" in names
    with pytest.raises(ValueError, match="unknown doctor check group"):
        run_doctor(tmp_path, manifest=manifest(), skip={"printer"})


class LoginHost(FakeHost):
    """A fake host whose ``claude auth status --json`` prints ``status``."""

    def __init__(self, status: str, **kwargs) -> None:
        super().__init__(**kwargs)
        self.status = status

    def run(self, argv, *, timeout, env=None, cwd=None):
        words = [str(arg) for arg in argv]
        if Path(words[0]).name == "claude" and words[1:3] == ["auth", "status"]:
            return subprocess.CompletedProcess(words, 0, self.status, "")
        return super().run(argv, timeout=timeout, env=env, cwd=cwd)


def test_the_claude_check_reads_the_login(tmp_path):
    install_everything(tmp_path)
    signed_out = doctor(tmp_path, LoginHost('{"loggedIn": false}')).check("claude")
    assert signed_out.status == STATUS_WARN
    assert "not signed in: run: claude auth login" in signed_out.detail
    assert signed_out.data["logged_in"] is False
    signed_in = doctor(tmp_path, LoginHost('{"loggedIn": true, "email": "x@y"}')).check("claude")
    assert signed_in.status == STATUS_OK and signed_in.detail.endswith("; signed in")
    assert "x@y" not in json.dumps(signed_in.data)  # no account detail in the report
    unknown = doctor(tmp_path, LoginHost("unknown command: auth")).check("claude")
    assert unknown.status == STATUS_OK and unknown.data["logged_in"] is None
    missing = doctor(tmp_path, FakeHost(present=())).check("claude")
    assert missing.status == STATUS_WARN and "claude auth login" in missing.detail


def test_an_api_login_replaces_the_sign_in_check(tmp_path):
    install_everything(tmp_path)
    signed_out = LoginHost('{"loggedIn": false}')
    env = {"ANTHROPIC_API_KEY": "sk-ant-secret-value"}
    check = doctor(tmp_path, signed_out, environ=env).check("claude")
    assert check.status == STATUS_OK and "API: anthropic-api (ANTHROPIC_API_KEY)" in check.detail
    assert check.data["auth"] == "anthropic-api"
    assert "sk-ant-secret-value" not in json.dumps(check.data) + check.detail
    foundry = {
        "CLAUDE_CODE_USE_FOUNDRY": "1",
        "ANTHROPIC_FOUNDRY_RESOURCE": "my-resource",
        "ANTHROPIC_FOUNDRY_API_KEY": "secret",
        "ANTHROPIC_DEFAULT_OPUS_MODEL": "claude-opus-deployment",
    }
    check = doctor(tmp_path, signed_out, environ=foundry).check("claude")
    assert check.status == STATUS_OK and "API: foundry" in check.detail
    del foundry["ANTHROPIC_FOUNDRY_RESOURCE"]
    check = doctor(tmp_path, signed_out, environ=foundry).check("claude")
    assert check.status == STATUS_WARN
    assert "set ANTHROPIC_FOUNDRY_RESOURCE or ANTHROPIC_FOUNDRY_BASE_URL" in check.detail


# --- location (macOS iCloud Drive) and sandbox images -------------------------------------------


def test_icloud_folder_reads_only_the_path_and_its_parents(tmp_path):
    synced = tmp_path / "Desktop"
    repo = synced / "kalkantest" / "kalkan"
    asked: list[Path] = []

    def read(folder: Path) -> str:
        asked.append(folder)
        return "com.apple.CloudDocs.iCloudDriveFileProvider/ABC" if folder == synced else ""

    assert doctor_mod.icloud_folder(repo, read) == synced
    assert asked == [repo, repo.parent, synced]  # it stops at the synced root
    assert doctor_mod.icloud_folder(tmp_path / "kalkan", lambda folder: "") is None
    other = "com.getdropbox.dropbox.fileprovider/x"
    assert doctor_mod.icloud_folder(repo, lambda folder: other) is None


def test_location_fails_in_an_icloud_folder_on_macos(tmp_path):
    repo = tmp_path / "Desktop" / "kalkan"
    repo.mkdir(parents=True)

    def read(folder: Path) -> str:
        return "com.apple.CloudDocs.iCloudDriveFileProvider/ABC" if folder.name == "Desktop" else ""

    def location(**kwargs):
        return doctor_mod._check_location(repo, FakeHost().run, site=tmp_path, **kwargs)

    found = location(platform="darwin", read_attribute=read)
    assert found.status == doctor_mod.STATUS_FAIL
    assert "iCloud Drive" in found.detail and "~/kalkan" in found.detail
    assert found.data["icloud_folder"] == (tmp_path / "Desktop").as_posix()
    assert location(platform="darwin", read_attribute=lambda folder: "").status == "ok"
    assert location(platform="linux", read_attribute=read).status == "ok"


def test_location_fails_for_a_hidden_pth_file(tmp_path, monkeypatch):
    (tmp_path / "_editable_impl_kalkan.pth").write_text("/x/src\n", encoding="utf-8")
    monkeypatch.setattr(doctor_mod, "hidden_pth_files", lambda site: sorted(site.glob("*.pth")))
    found = doctor_mod._check_location(
        tmp_path, FakeHost().run, platform="darwin", read_attribute=lambda f: "", site=tmp_path
    )
    assert found.status == doctor_mod.STATUS_FAIL
    assert "_editable_impl_kalkan.pth" in found.detail and "hidden" in found.detail


class ImageHost(FakeHost):
    def __init__(self, missing: tuple[str, ...]) -> None:
        super().__init__(engine_up=True)
        self.missing = set(missing)

    def run(self, argv, *, timeout, env=None, cwd=None):
        argv = [str(a) for a in argv]
        if argv[1:3] == ["image", "inspect"]:
            code = 1 if argv[-1] in self.missing else 0
            return subprocess.CompletedProcess(argv, code, "sha256:x\n" if code == 0 else "", "")
        return super().run(argv, timeout=timeout, env=env, cwd=cwd)


def test_sandbox_images_name_the_missing_ones():
    from kalkan.sandbox.runner import allowed_images

    images = allowed_images()
    docker = Path("/fake/bin/docker")
    host = ImageHost(missing=(images[1], images[2]))
    found = doctor_mod._check_sandbox_images(host.run, docker, True)
    assert found.status == doctor_mod.STATUS_WARN
    assert f"2 of {len(images)} base images missing ({images[1]}, {images[2]})" in found.detail
    assert "sandbox pull" in found.detail
    assert found.data["missing"] == [images[1], images[2]]
    assert doctor_mod._check_sandbox_images(ImageHost(()).run, docker, True).status == "ok"
    skipped = doctor_mod._check_sandbox_images(host.run, docker, False)
    assert skipped.status == doctor_mod.STATUS_INFO
