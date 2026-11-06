# SPDX-License-Identifier: MIT
"""Tests for kalkan.run.tech.detect."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from kalkan.run import tech
from kalkan.schema.loader import shared_schema

TARGETS = Path(__file__).resolve().parents[1] / "fixtures" / "targets"


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_multistack_fixture_gives_every_tag():
    assert tech.detect(TARGETS / "multistack") == sorted(tech.TAGS)


def test_tags_match_the_manifest_schema():
    schema = shared_schema("target-manifest")
    assert schema["properties"]["tech"]["items"]["enum"] == list(tech.TAGS)


def test_webapp_fixture():
    assert tech.detect(TARGETS / "webapp") == ["docker", "flask", "python"]


def test_empty_folder(tmp_path):
    assert tech.detect(tmp_path) == []


def test_skipped_folders_do_not_count(tmp_path):
    write(tmp_path / "package.json", '{"dependencies": {"left-pad": "1.3.0"}}')
    write(tmp_path / "node_modules" / "react" / "package.json", '{"name": "react"}')
    write(tmp_path / "node_modules" / "x" / "package.json", '{"dependencies": {"next": "1"}}')
    write(tmp_path / ".venv" / "lib" / "django" / "pyproject.toml", "[project]\nname='django'\n")
    write(tmp_path / "build" / "Dockerfile", "FROM scratch\n")
    assert tech.detect(tmp_path) == ["node"]


def test_unparsable_manifests_give_only_the_base_tag(tmp_path):
    write(tmp_path / "a" / "package.json", "{not json")
    write(tmp_path / "b" / "pyproject.toml", "[project\n")
    write(tmp_path / "c" / "composer.json", "[1, 2]")
    (tmp_path / "d").mkdir()
    (tmp_path / "d" / "Pipfile").write_bytes(b"\xff\xfe\x00")
    assert tech.detect(tmp_path) == ["node", "php", "python"]


def test_byte_order_mark_and_dependency_sections(tmp_path):
    write(tmp_path / "package.json", '﻿{"optionalDependencies": {"koa": "2"}}')
    write(
        tmp_path / "pyproject.toml",
        "[tool.poetry.group.web.dependencies]\nFastAPI = '*'\n"
        "[dependency-groups]\ndev = ['Flask>=3']\n",
    )
    write(tmp_path / "requirements" / "base.txt", "django-environ\nDjango_REST_framework\n")
    assert tech.detect(tmp_path) == ["fastapi", "flask", "koa", "node", "python"]


def test_requirement_lines_are_parsed(tmp_path):
    write(
        tmp_path / "requirements-prod.txt",
        "# comment\n-r base.txt\n--hash=sha256:abc\nflask[async]>=3 ; python_version>'3.8'\n",
    )
    assert tech.detect(tmp_path) == ["flask", "python"]


def test_source_files_give_the_language(tmp_path):
    for name in ("a.py", "b.go", "C.JAVA", "d.kt", "e.rb", "f.php", "g.cs", "h.rs", "i.tsx"):
        write(tmp_path / "src" / name, "x")
    assert tech.detect(tmp_path) == [
        "dotnet",
        "go",
        "java",
        "kotlin",
        "node",
        "php",
        "python",
        "ruby",
        "rust",
    ]


def test_header_files_alone_give_no_tag(tmp_path):
    write(tmp_path / "include" / "x.h", "int x;")
    assert tech.detect(tmp_path) == []


@pytest.mark.parametrize(
    ("name", "tag"),
    [
        ("Dockerfile", "docker"),
        ("dockerfile.dev", "docker"),
        ("api.Dockerfile", "docker"),
        ("Containerfile", "docker"),
        ("docker-compose.prod.yaml", "docker-compose"),
        ("compose.yml", "docker-compose"),
        ("main.tf.json", "terraform"),
        ("App.sln", "dotnet"),
        ("sample.gemspec", "ruby"),
        ("Cargo.toml", "rust"),
    ],
)
def test_file_names(tmp_path, name, tag):
    write(tmp_path / name, "x")
    assert tech.detect(tmp_path) == [tag]


def test_kubernetes_needs_api_version_and_kind(tmp_path):
    write(tmp_path / "a.yaml", "kind: Deployment\n")
    write(tmp_path / "b.yml", "spec:\n  apiVersion: v1\n  kind: Pod\n")
    assert tech.detect(tmp_path) == []
    write(tmp_path / "c.yml", "---\napiVersion: v1\nkind: Service\n")
    assert tech.detect(tmp_path) == ["kubernetes"]


def test_workflows_only_under_github(tmp_path):
    write(tmp_path / "workflows" / "ci.yml", "on: push\n")
    write(tmp_path / "other" / ".github" / "ci.yml", "on: push\n")
    assert tech.detect(tmp_path) == []
    write(tmp_path / "sub" / ".github" / "workflows" / "ci.yaml", "on: push\n")
    assert tech.detect(tmp_path) == ["github-actions"]


def test_gradle_and_gemfile_frameworks(tmp_path):
    write(tmp_path / "build.gradle", "dependencies { implementation 'org.springframework:x' }\n")
    write(tmp_path / "Gemfile", "gem 'sinatra'\n")
    assert tech.detect(tmp_path) == ["java", "ruby", "spring"]
    write(tmp_path / "Gemfile", "source 'https://rubygems.org'\n  gem 'railties', '7.1'\n")
    assert tech.detect(tmp_path) == ["java", "rails", "ruby", "spring"]


def test_large_manifests_are_not_read(tmp_path):
    big = '{"dependencies": {"react": "18"}, "pad": "' + "x" * (1024 * 1024) + '"}'
    write(tmp_path / "package.json", big)
    assert tech.detect(tmp_path) == ["node"]


def test_the_copy_of_a_detected_target_matches(tmp_path):
    copy = tmp_path / "copy"
    shutil.copytree(TARGETS / "multistack", copy)
    assert tech.detect(copy) == tech.detect(TARGETS / "multistack")
