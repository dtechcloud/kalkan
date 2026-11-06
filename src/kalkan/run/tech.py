# SPDX-License-Identifier: MIT
"""Technology detection for a target folder (docs/ENGINE-SPEC.md, section 10).

:func:`detect` walks the whole tree (manifests in every folder, not only the root). It never
follows symlinks or Windows reparse points, skips the folders that ``run init`` does not copy
(``.git``, ``node_modules``, ``.venv``, ``venv``, ``__pycache__``, ``.tox``, ``.mypy_cache``,
``.pytest_cache``, ``dist``, ``build``, ``.next``, ``.nuxt``, ``.tools``), reads files only
through :func:`kalkan.util.safe_io.read_text_bounded` (manifests up to 1 MiB, YAML files up to
256 KiB, at most 5000 reads) and ignores content that it cannot read or parse. A manifest name
alone gives its base tag (``package.json`` gives ``node`` even when the JSON is broken).

Signals:

- node, and next, express, react, vue, angular, nestjs, fastify, koa, hono: ``package.json``;
  frameworks from ``dependencies``, ``devDependencies``, ``peerDependencies`` and
  ``optionalDependencies``.
- python, and django, flask, fastapi: ``requirements*.txt``, ``requirements/*.txt``,
  ``pyproject.toml`` (PEP 621, Poetry, PDM, PEP 735 groups), ``Pipfile``.
- go: ``go.mod``.
- java, spring, kotlin: ``pom.xml``, ``build.gradle``, ``build.gradle.kts``
  (``org.springframework``; the Kotlin plugin).
- ruby, rails: ``Gemfile`` (``gem "rails"``), ``*.gemspec``.
- php, laravel, symfony: ``composer.json`` ``require`` and ``require-dev``.
- dotnet: ``*.csproj``, ``*.fsproj``, ``*.vbproj``, ``*.sln``.
- rust: ``Cargo.toml``.
- docker: ``Dockerfile``, ``Dockerfile.*``, ``*.Dockerfile``, ``Containerfile``.
- docker-compose: ``docker-compose*.yml``, ``compose*.yml`` (also ``.yaml``).
- terraform: ``*.tf``, ``*.tf.json``.
- kubernetes: ``*.yml`` and ``*.yaml`` with top-level ``apiVersion:`` and ``kind:``.
- helm: ``Chart.yaml`` (a Helm chart; the ``helm-checkov`` adapter renders it).
- github-actions: ``.github/workflows/*.yml`` and ``*.yaml``.
- solidity: ``*.sol``.
- c, cpp: ``*.c``; ``*.cc``, ``*.cpp``, ``*.cxx``, ``*.c++``, ``*.hpp``, ``*.hh``, ``*.hxx``.

Source files also give the language tag when no manifest exists (an addition to section 10):
``*.py`` python, ``*.go`` go, ``*.java`` java, ``*.kt`` kotlin, ``*.rb`` ruby, ``*.php`` php,
``*.cs`` dotnet, ``*.rs`` rust, and ``*.js``, ``*.mjs``, ``*.cjs``, ``*.jsx``, ``*.ts``,
``*.tsx``, ``*.mts``, ``*.cts`` node. Name matching ignores case.
"""

from __future__ import annotations

import os
import re
import stat
import tomllib
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Final

from kalkan.errors import UnsafeInputError, ValidationError
from kalkan.schema.validator import parse_json_text
from kalkan.util.safe_io import read_text_bounded

__all__ = ["SKIP_DIRS", "TAGS", "detect"]

#: Every tag that :func:`detect` can return.
TAGS: Final = (
    "node",
    "next",
    "express",
    "react",
    "vue",
    "angular",
    "nestjs",
    "fastify",
    "koa",
    "hono",
    "python",
    "django",
    "flask",
    "fastapi",
    "go",
    "java",
    "spring",
    "kotlin",
    "ruby",
    "rails",
    "php",
    "laravel",
    "symfony",
    "dotnet",
    "rust",
    "docker",
    "docker-compose",
    "terraform",
    "kubernetes",
    "helm",
    "github-actions",
    "solidity",
    "c",
    "cpp",
)

#: Folder names that detection skips (compared case-insensitively).
SKIP_DIRS: Final = frozenset(
    {
        ".git",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        "dist",
        "build",
        ".next",
        ".nuxt",
        ".tools",
    }
)

_MANIFEST_MAX_BYTES: Final = 1024 * 1024
_YAML_MAX_BYTES: Final = 256 * 1024
_MAX_READS: Final = 5000

_NODE_FRAMEWORKS: Final = {
    "next": "next",
    "express": "express",
    "react": "react",
    "react-dom": "react",
    "vue": "vue",
    "nuxt": "vue",
    "@angular/core": "angular",
    "@nestjs/core": "nestjs",
    "fastify": "fastify",
    "koa": "koa",
    "hono": "hono",
}
_NODE_DEPENDENCY_KEYS: Final = (
    "dependencies",
    "devDependencies",
    "peerDependencies",
    "optionalDependencies",
)
_PYTHON_FRAMEWORKS: Final = {
    "django": "django",
    "djangorestframework": "django",
    "flask": "flask",
    "fastapi": "fastapi",
}
_PHP_FRAMEWORKS: Final = {
    "laravel/framework": "laravel",
    "laravel/lumen-framework": "laravel",
    "symfony/framework-bundle": "symfony",
    "symfony/symfony": "symfony",
    "symfony/http-kernel": "symfony",
    "symfony/flex": "symfony",
}
_SOURCE_TAGS: Final = {
    ".py": "python",
    ".go": "go",
    ".java": "java",
    ".kt": "kotlin",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "dotnet",
    ".rs": "rust",
    ".js": "node",
    ".mjs": "node",
    ".cjs": "node",
    ".jsx": "node",
    ".ts": "node",
    ".tsx": "node",
    ".mts": "node",
    ".cts": "node",
    ".sol": "solidity",
    ".c": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".c++": "cpp",
    ".hpp": "cpp",
    ".hh": "cpp",
    ".hxx": "cpp",
    ".tf": "terraform",
}
_DOTNET_SUFFIXES: Final = (".csproj", ".fsproj", ".vbproj", ".sln")
_COMPOSE: Final = re.compile(r"(?:docker-)?compose(?:\.[a-z0-9_-]+)*\.ya?ml")
_REQUIREMENT_NAME: Final = re.compile(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
_NAME_SEPARATORS: Final = re.compile(r"[-_.]+")
_GEM_RAILS: Final = re.compile(r"^\s*gem\s+[\"'](?:rails|railties)[\"']", re.MULTILINE)
_K8S_API_VERSION: Final = re.compile(r"^apiVersion:[ \t]*\S", re.MULTILINE)
_K8S_KIND: Final = re.compile(r"^kind:[ \t]*\S", re.MULTILINE)
_SPRING: Final = re.compile(r"org\.springframework")
_KOTLIN_BUILD: Final = re.compile(
    r"org\.jetbrains\.kotlin|kotlin-maven-plugin|kotlin\(\s*\"|id\s*\(?\s*[\"']kotlin"
)


class _Reader:
    """Bounded file reads with a total read budget."""

    def __init__(self) -> None:
        self.reads = 0

    def text(self, path: Path, limit: int) -> str | None:
        if self.reads >= _MAX_READS:
            return None
        self.reads += 1
        try:
            text = read_text_bounded(path, limit)
        except UnsafeInputError:
            return None
        return text.removeprefix("﻿")

    def json_object(self, path: Path) -> dict[str, Any] | None:
        text = self.text(path, _MANIFEST_MAX_BYTES)
        if text is None:
            return None
        try:
            data = parse_json_text(text)
        except ValidationError:
            return None
        return data if isinstance(data, dict) else None

    def toml(self, path: Path) -> dict[str, Any] | None:
        text = self.text(path, _MANIFEST_MAX_BYTES)
        if text is None:
            return None
        try:
            return tomllib.loads(text)
        except (tomllib.TOMLDecodeError, RecursionError, ValueError):
            return None


def _is_link(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
    )


def _walk(root: Path) -> Iterator[tuple[Path, str, tuple[str, ...]]]:
    """Yield ``(path, folded name, folded parent names)`` for every regular file."""
    stack: list[tuple[Path, tuple[str, ...]]] = [(root, ())]
    while stack:
        directory, parents = stack.pop()
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda entry: entry.name)
        except OSError:
            continue
        for entry in entries:
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError:
                continue
            if _is_link(info):
                continue
            folded = entry.name.casefold()
            if stat.S_ISDIR(info.st_mode):
                if folded not in SKIP_DIRS:
                    stack.append((Path(entry.path), (*parents, folded)))
            elif stat.S_ISREG(info.st_mode):
                yield Path(entry.path), folded, parents


def _python_name(text: str) -> str | None:
    match = _REQUIREMENT_NAME.match(text)
    if match is None:
        return None
    return _NAME_SEPARATORS.sub("-", match.group(1)).lower()


def _python_tags(names: list[str]) -> set[str]:
    found: set[str] = set()
    for name in names:
        normalized = _python_name(name)
        if normalized in _PYTHON_FRAMEWORKS:
            found.add(_PYTHON_FRAMEWORKS[normalized])
    return found


def _requirements_names(text: str) -> list[str]:
    names: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith(("#", "-")):
            names.append(stripped)
    return names


def _strings(value: object) -> list[str]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []


def _pyproject_names(data: dict[str, Any]) -> list[str]:
    names: list[str] = []
    project = data.get("project")
    if isinstance(project, dict):
        names += _strings(project.get("dependencies"))
        optional = project.get("optional-dependencies")
        if isinstance(optional, dict):
            for group in optional.values():
                names += _strings(group)
    groups = data.get("dependency-groups")
    if isinstance(groups, dict):
        for group in groups.values():
            names += _strings(group)
    tool = data.get("tool")
    if isinstance(tool, dict):
        poetry = tool.get("poetry")
        if isinstance(poetry, dict):
            for key in ("dependencies", "dev-dependencies"):
                table = poetry.get(key)
                if isinstance(table, dict):
                    names += [str(name) for name in table]
            poetry_groups = poetry.get("group")
            if isinstance(poetry_groups, dict):
                for group in poetry_groups.values():
                    table = group.get("dependencies") if isinstance(group, dict) else None
                    if isinstance(table, dict):
                        names += [str(name) for name in table]
        pdm = tool.get("pdm")
        if isinstance(pdm, dict) and isinstance(pdm.get("dev-dependencies"), dict):
            for group in pdm["dev-dependencies"].values():
                names += _strings(group)
    return names


def _pipfile_names(data: dict[str, Any]) -> list[str]:
    names: list[str] = []
    for key in ("packages", "dev-packages"):
        table = data.get(key)
        if isinstance(table, dict):
            names += [str(name) for name in table]
    return names


def _dependency_keys(data: dict[str, Any], keys: tuple[str, ...]) -> set[str]:
    found: set[str] = set()
    for key in keys:
        table = data.get(key)
        if isinstance(table, dict):
            found.update(str(name).lower() for name in table)
    return found


def _jvm_tags(text: str | None) -> set[str]:
    found = {"java"}
    if text is not None:
        if _SPRING.search(text):
            found.add("spring")
        if _KOTLIN_BUILD.search(text):
            found.add("kotlin")
    return found


def _is_dockerfile(name: str) -> bool:
    return (
        name in ("dockerfile", "containerfile")
        or name.startswith("dockerfile.")
        or name.endswith(".dockerfile")
    )


def _file_tags(path: Path, name: str, parents: tuple[str, ...], reader: _Reader) -> set[str]:
    """Return the tags of one file (``name`` and ``parents`` are case-folded)."""
    if name == "package.json":
        found = {"node"}
        data = reader.json_object(path)
        if data is not None:
            for dependency in _dependency_keys(data, _NODE_DEPENDENCY_KEYS):
                if dependency in _NODE_FRAMEWORKS:
                    found.add(_NODE_FRAMEWORKS[dependency])
        return found
    if name.endswith(".txt") and (
        name.startswith("requirements") or (parents and parents[-1] == "requirements")
    ):
        text = reader.text(path, _MANIFEST_MAX_BYTES)
        return {"python"} | (_python_tags(_requirements_names(text)) if text else set())
    if name == "pyproject.toml":
        data = reader.toml(path)
        return {"python"} | (_python_tags(_pyproject_names(data)) if data else set())
    if name == "pipfile":
        data = reader.toml(path)
        return {"python"} | (_python_tags(_pipfile_names(data)) if data else set())
    if name == "go.mod":
        return {"go"}
    if name in ("pom.xml", "build.gradle", "build.gradle.kts"):
        return _jvm_tags(reader.text(path, _MANIFEST_MAX_BYTES))
    if name == "gemfile":
        text = reader.text(path, _MANIFEST_MAX_BYTES)
        return {"ruby", "rails"} if text and _GEM_RAILS.search(text) else {"ruby"}
    if name.endswith(".gemspec"):
        return {"ruby"}
    if name == "composer.json":
        found = {"php"}
        data = reader.json_object(path)
        if data is not None:
            for dependency in _dependency_keys(data, ("require", "require-dev")):
                if dependency in _PHP_FRAMEWORKS:
                    found.add(_PHP_FRAMEWORKS[dependency])
        return found
    if name.endswith(_DOTNET_SUFFIXES):
        return {"dotnet"}
    if name == "cargo.toml":
        return {"rust"}
    if _is_dockerfile(name):
        return {"docker"}
    if name.endswith(".tf.json"):
        return {"terraform"}
    if name == "chart.yaml":
        return {"helm"}
    if name.endswith((".yml", ".yaml")):
        if _COMPOSE.fullmatch(name):
            return {"docker-compose"}
        if len(parents) >= 2 and parents[-2:] == (".github", "workflows"):
            return {"github-actions"}
        return set()  # Kubernetes check: see detect()
    tag = _SOURCE_TAGS.get(os.path.splitext(name)[1])
    return {tag} if tag else set()


def _is_kubernetes(path: Path, reader: _Reader) -> bool:
    text = reader.text(path, _YAML_MAX_BYTES)
    return bool(text and _K8S_API_VERSION.search(text) and _K8S_KIND.search(text))


def detect(target_dir: str | os.PathLike[str]) -> list[str]:
    """Return the sorted technology tags of the folder ``target_dir`` (see module docstring)."""
    root = Path(target_dir)
    reader = _Reader()
    tags: set[str] = set()
    for path, name, parents in _walk(root):
        found = _file_tags(path, name, parents, reader)
        tags |= found
        if (
            not found
            and "kubernetes" not in tags
            and name.endswith((".yml", ".yaml"))
            and _is_kubernetes(path, reader)
        ):
            tags.add("kubernetes")
    return sorted(tags)
