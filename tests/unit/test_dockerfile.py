# SPDX-License-Identifier: MIT
"""Static checks for the container image and the CI workflow.

The tests read docker/Dockerfile, docker/entrypoint.sh, .dockerignore and
.github/workflows/ci.yml as text. They need neither Docker nor the network.
"""

from __future__ import annotations

import importlib.util
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from kalkan.tools.manifest import load_manifest

ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = ROOT / "docker" / "Dockerfile"
GROUPS_SCRIPT = ROOT / "docker" / "manifest_tools.py"
MANIFEST = ROOT / "src" / "kalkan" / "tools" / "manifest.json"
ENTRYPOINT = ROOT / "docker" / "entrypoint.sh"
DOCKERIGNORE = ROOT / ".dockerignore"
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"

SHA256_DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
COMPILERS = ("build-essential", "gcc", "g++", "clang", "make", "cmake", "golang-go", "rustc")


@dataclass
class Stage:
    """One FROM block of the Dockerfile."""

    image: str
    name: str | None
    instructions: list[tuple[str, str]] = field(default_factory=list)


@dataclass
class Dockerfile:
    """The parsed Dockerfile: global ARG defaults and the stages in order."""

    global_args: dict[str, str]
    stages: list[Stage]

    def stage(self, name: str) -> Stage:
        for stage in self.stages:
            if stage.name == name:
                return stage
        raise AssertionError(f"no stage named {name}")

    @property
    def final(self) -> Stage:
        return self.stages[-1]

    def runs(self) -> list[str]:
        return [args for stage in self.stages for op, args in stage.instructions if op == "RUN"]

    def arg_default(self, name: str) -> str:
        for stage in self.stages:
            for op, args in stage.instructions:
                if op == "ARG":
                    key, value = _parse_arg(args)
                    if key == name and value is not None:
                        return value
        if name in self.global_args:
            return self.global_args[name]
        raise AssertionError(f"no default for ARG {name}")


def _logical_lines(text: str) -> list[str]:
    """Join continued lines and drop comments and blank lines, as the Docker parser does."""
    lines: list[str] = []
    buffer = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.endswith("\\"):
            buffer += line[:-1] + " "
            continue
        lines.append(buffer + line)
        buffer = ""
    if buffer:
        lines.append(buffer)
    return lines


def _parse_arg(args: str) -> tuple[str, str | None]:
    name, sep, value = args.partition("=")
    if not sep:
        return name.strip(), None
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] == '"':
        value = value[1:-1]
    return name.strip(), value


def _substitute(value: str, args: dict[str, str]) -> str:
    return re.sub(r"\$\{(\w+)\}|\$(\w+)", lambda m: args.get(m[1] or m[2], m[0]), value)


def parse_dockerfile(text: str) -> Dockerfile:
    global_args: dict[str, str] = {}
    stages: list[Stage] = []
    for line in _logical_lines(text):
        op, _, args = line.partition(" ")
        op, args = op.upper(), args.strip()
        if op == "FROM":
            parts = args.split()
            image = _substitute(parts[0], global_args)
            name = parts[2] if len(parts) >= 3 and parts[1].upper() == "AS" else None
            stages.append(Stage(image, name))
        elif not stages:
            if op == "ARG":
                key, value = _parse_arg(args)
                if value is not None:
                    global_args[key] = value
        else:
            stages[-1].instructions.append((op, args))
    return Dockerfile(global_args, stages)


@pytest.fixture(scope="module")
def dockerfile_text() -> str:
    return DOCKERFILE.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def dockerfile(dockerfile_text: str) -> Dockerfile:
    return parse_dockerfile(dockerfile_text)


@pytest.fixture(scope="module")
def manifest():
    return load_manifest()


# ---------------------------------------------------------------------------------------------
# Base image and tags


def test_external_base_images_are_pinned_by_digest(dockerfile: Dockerfile) -> None:
    names = {stage.name for stage in dockerfile.stages if stage.name}
    external = [stage.image for stage in dockerfile.stages if stage.image not in names]
    assert external, "the Dockerfile names no base image"
    for image in external:
        assert "$" not in image, f"unresolved build argument in FROM {image}"
        assert SHA256_DIGEST.search(image), f"{image} is not pinned by a sha256 digest"


def test_base_image_is_python_312_slim(dockerfile: Dockerfile) -> None:
    image = dockerfile.stages[0].image
    repository_tag = image.split("@", 1)[0]
    assert repository_tag.startswith("python:3.12"), image
    assert "-slim" in repository_tag, image


def test_dockerfile_never_uses_a_latest_tag(dockerfile_text: str) -> None:
    assert re.search(r"latest", dockerfile_text, re.IGNORECASE) is None


def test_final_stage_derives_from_the_base_stage(dockerfile: Dockerfile) -> None:
    assert dockerfile.final.image == "base"
    assert dockerfile.stages[0].name == "base"


# ---------------------------------------------------------------------------------------------
# Tools


def _groups_module():
    spec = importlib.util.spec_from_file_location("manifest_tools", GROUPS_SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def groups():
    return _groups_module()


@pytest.fixture(scope="module")
def manifest_document() -> dict:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def _install_runs(dockerfile: Dockerfile) -> list[str]:
    return [run for run in dockerfile.runs() if "kalkan tools install" in run]


def test_no_tool_list_is_hard_coded(dockerfile_text: str, manifest) -> None:
    # Each layer asks docker/manifest_tools.py, so a new manifest tool needs no change here.
    for name in ("KALKAN_TOOL_PINS", "KALKAN_CORE_TOOLS", "KALKAN_GO_TOOLS"):
        assert name not in dockerfile_text, name
    for tool in manifest:
        if tool.kind != "toolchain":  # the go stage pins the toolchain (checked below)
            assert f"{tool.name}={tool.version}" not in dockerfile_text, tool.name
            assert f"tools install {tool.name}" not in dockerfile_text, tool.name


def test_every_tool_is_in_exactly_one_install_group(groups, manifest_document, manifest) -> None:
    found = {name: groups.tools_of(manifest_document, [name]) for name in groups.GROUPS}
    listed = [tool for names in found.values() for tool in names]
    assert len(listed) == len(set(listed)), "a tool is in more than one install layer"
    toolchains = {tool.name for tool in manifest if tool.kind == "toolchain"}  # the go stage
    assert set(listed) | toolchains == set(manifest.names())
    assert not set(listed) & toolchains


def test_new_manifest_tools_need_no_dockerfile_change(groups) -> None:
    document = {
        "tools": {
            "go": {"kind": "toolchain", "license": "BSD-3-Clause"},
            "newbinary": {"kind": "binary", "license": "MIT"},
            "newshell": {"kind": "binary", "license": "GPL-3.0-only"},
            "newpip": {"kind": "pip", "license": "GPL-2.0"},
            "newlgpl": {"kind": "binary", "license": "LGPL-2.1"},
            "newgoinstall": {"kind": "go-install", "license": "Apache-2.0"},
            "newgobinary": {"kind": "binary", "license": "Apache-2.0", "requires_go": True},
            "newgogpl": {"kind": "go-install", "license": "AGPL-3.0"},
        }
    }
    assert groups.tools_of(document, ["core"]) == ["newbinary", "newlgpl"]
    assert groups.tools_of(document, ["gpl"]) == ["newshell", "newpip"]
    assert groups.tools_of(document, ["go"]) == ["newgoinstall", "newgobinary"]
    assert groups.tools_of(document, ["go-gpl"]) == ["newgogpl"]
    assert groups.group_of(document["tools"]["go"]) is None


def test_go_groups_are_the_tools_that_need_go(groups, manifest_document, manifest) -> None:
    need_go = {
        tool.name
        for tool in manifest
        if (tool.requires_go or tool.kind == "go-install") and tool.kind != "toolchain"
    }
    assert set(groups.tools_of(manifest_document, ["go", "go-gpl"])) == need_go


def test_core_group_has_no_gpl_tool(groups, manifest_document, manifest) -> None:
    for name in groups.tools_of(manifest_document, ["core", "go"]):
        assert not groups.is_gpl(manifest.get(name).license), name
    for name in groups.tools_of(manifest_document, ["gpl", "go-gpl"]):
        assert groups.is_gpl(manifest.get(name).license), name


def test_the_groups_script_prints_one_line(groups, capsys, tmp_path) -> None:
    assert groups.main(["core", "go"]) == 0
    printed = capsys.readouterr().out
    assert printed.endswith("\n") and printed.count("\n") == 1
    broken = tmp_path / "manifest.json"
    broken.write_text("{", encoding="utf-8")
    assert groups.main(["core", "--manifest", str(broken)]) == 2
    assert "manifest_tools: error" in capsys.readouterr().err


def test_tools_go_through_the_kalkan_installer(dockerfile: Dockerfile) -> None:
    for run in _install_runs(dockerfile):
        assert "kalkan tools install $tools" in run and "kalkan tools verify $tools" in run
        assert "/opt/kalkan/docker/manifest_tools.py" in run
    assert any("KALKAN_HOME=/opt/kalkan" in args for _, args in dockerfile.final.instructions)


def test_each_install_layer_asks_the_groups_script(dockerfile: Dockerfile) -> None:
    core, gpl, go = _install_runs(dockerfile)
    assert "manifest_tools.py core)" in core and "WITH_" not in core
    assert "manifest_tools.py gpl)" in gpl and '"$WITH_GPL/$WITH_HADOLINT"' in gpl
    assert 'groups="go go-gpl"' in go and "manifest_tools.py $groups)" in go
    assert '[ "$WITH_GPL" = "true" ] && [ "$WITH_HADOLINT" = "true" ]' in go
    engine = [args for op, args in dockerfile.stage("engine").instructions if op == "RUN"]
    assert any("manifest_tools.py core gpl go go-gpl" in run for run in engine)


def test_every_install_layer_makes_installed_json_readable(dockerfile: Dockerfile) -> None:
    # The installer writes installed.json with mode 0600; the non-root user must read it.
    install_runs = _install_runs(dockerfile)
    assert len(install_runs) == 3
    for run in install_runs:
        assert "chmod 0644 /opt/kalkan/.tools/installed.json" in run, run[:80]


def test_gpl_layer_is_optional(dockerfile: Dockerfile) -> None:
    assert dockerfile.global_args.get("WITH_GPL") == "true"
    assert dockerfile.global_args.get("WITH_HADOLINT") == "true"  # the older name still works
    gpl_runs = [run for run in _install_runs(dockerfile) if "manifest_tools.py gpl" in run]
    assert len(gpl_runs) == 1, "the GPL tools must be installed in exactly one RUN layer"
    assert "true/true)" in gpl_runs[0] and "must be true or false" in gpl_runs[0]


def test_the_vulnerability_database_folder_belongs_to_the_user(dockerfile: Dockerfile) -> None:
    runs = [args for op, args in dockerfile.final.instructions if op == "RUN"]
    owned = [run for run in runs if "chown kalkan:kalkan" in run]
    assert owned and "/opt/kalkan/.tools/vulndb" in owned[-1]


def test_go_is_on_by_default_and_pinned_by_checksum(dockerfile: Dockerfile, manifest) -> None:
    assert dockerfile.global_args.get("WITH_GO") == "true"
    go_stage = dockerfile.stage("go")
    for arch in ("AMD64", "ARM64"):
        assert HEX64.match(dockerfile.arg_default(f"GO_SHA256_{arch}")), arch
    version = tuple(int(part) for part in dockerfile.arg_default("GO_VERSION").split("."))
    for tool in manifest:
        if tool.min_go_version:
            needed = tuple(int(part) for part in tool.min_go_version.split("."))
            assert version >= needed, f"{tool.name} needs Go {tool.min_go_version}"
    go_runs = [args for op, args in go_stage.instructions if op == "RUN"]
    assert any("sha256sum -c" in run and '"$WITH_GO" = "true"' in run for run in go_runs)
    go_tool_runs = [run for run in dockerfile.runs() if "manifest_tools.py $groups" in run]
    assert go_tool_runs and all('"$WITH_GO" = "true"' in run for run in go_tool_runs)


def test_go_stage_matches_the_manifest_toolchain(dockerfile: Dockerfile, manifest) -> None:
    # The image and a native install run the same Go: same version, same archive SHA-256.
    go = manifest.get("go")
    assert go.kind == "toolchain"
    assert dockerfile.arg_default("GO_VERSION") == go.version
    for arch in ("amd64", "arm64"):
        asset = go.asset(f"linux-{arch}")
        assert asset is not None
        assert asset.url == f"https://go.dev/dl/go{go.version}.linux-{arch}.tar.gz"
        assert dockerfile.arg_default(f"GO_SHA256_{arch.upper()}") == asset.sha256, arch
    go_runs = [args for op, args in dockerfile.stage("go").instructions if op == "RUN"]
    assert any('url="https://go.dev/dl/go${GO_VERSION}.linux-${arch}.tar.gz"' in r for r in go_runs)


def test_go_tool_layer_removes_the_build_folders(dockerfile: Dockerfile) -> None:
    go_tool_runs = [run for run in dockerfile.runs() if "manifest_tools.py $groups" in run]
    assert go_tool_runs
    assert all("rm -rf /opt/kalkan/.tools/go-build" in run for run in go_tool_runs)


# ---------------------------------------------------------------------------------------------
# Packages, user and entry point


def _apt_packages(run: str) -> list[str]:
    packages: list[str] = []
    for match in re.finditer(r"apt-get install((?:\s+[^\s&;|]+)*)", run):
        packages.extend(word for word in match[1].split() if not word.startswith("-"))
    return packages


def test_only_git_and_ca_certificates_come_from_apt(dockerfile: Dockerfile) -> None:
    packages = [pkg for run in dockerfile.runs() for pkg in _apt_packages(run)]
    assert not set(packages) & set(COMPILERS), "the image must not install a compiler"
    assert sorted(packages) == ["ca-certificates", "git"]


def test_pip_installs_skip_the_cache(dockerfile: Dockerfile) -> None:
    for run in dockerfile.runs():
        for command in run.split("&&"):
            if "pip install" in command:
                assert "--no-cache-dir" in command, command.strip()


def test_final_stage_runs_as_a_non_root_user(dockerfile: Dockerfile) -> None:
    users = [args for op, args in dockerfile.final.instructions if op == "USER"]
    assert users, "the final stage sets no USER"
    user = users[-1].split(":", 1)[0]
    assert user not in ("root", "0"), users[-1]
    last_op = [op for op, _ in dockerfile.final.instructions if op in ("USER", "RUN")][-1]
    assert last_op == "USER", "a RUN after the last USER runs as that user; keep USER last"


def test_entrypoint_runs_kalkan(dockerfile: Dockerfile) -> None:
    entrypoints = [args for op, args in dockerfile.final.instructions if op == "ENTRYPOINT"]
    assert entrypoints == ['["/usr/local/bin/kalkan-entrypoint"]']
    copies = [args for op, args in dockerfile.final.instructions if op == "COPY"]
    assert "docker/entrypoint.sh /usr/local/bin/kalkan-entrypoint" in copies
    script = ENTRYPOINT.read_bytes()
    assert script.startswith(b"#!/bin/sh\n")
    assert b"\r\n" not in script, "entrypoint.sh must use LF line endings"
    assert b'exec kalkan "$@"' in script


def test_dockerignore_keeps_local_state_out_of_the_image() -> None:
    entries = {
        line.strip()
        for line in DOCKERIGNORE.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    for required in (".git", ".venv", ".tools", "runs", "tests"):
        assert required in entries, required
    for kept in ("docker", "src", "rules", "knowledge", "pyproject.toml"):
        assert kept not in entries, f"{kept} is needed in the build context"


# ---------------------------------------------------------------------------------------------
# CI workflow


@pytest.fixture(scope="module")
def workflow_text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def test_actions_are_pinned_by_full_commit_sha(workflow_text: str) -> None:
    uses = re.findall(r"^\s*(?:-\s*)?uses:\s*(.+)$", workflow_text, re.MULTILINE)
    assert uses, "the workflow uses no actions"
    for value in uses:
        assert re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40} # v\d+(\.\d+)*", value.strip()), value


def test_workflow_reads_only_and_uses_no_secrets(workflow_text: str) -> None:
    assert re.search(r"^permissions:\n\s+contents: read\s*$", workflow_text, re.MULTILINE)
    assert "secrets." not in workflow_text
    assert "docker push" not in workflow_text


def test_workflow_matrix_and_test_command(workflow_text: str) -> None:
    assert "os: [windows-latest, ubuntu-latest, macos-latest]" in workflow_text
    assert 'python-version: ["3.11", "3.13"]' in workflow_text
    assert 'pytest -m "not tools and not docker"' in workflow_text
    assert "ruff check ." in workflow_text
    assert "ruff format --check ." in workflow_text
