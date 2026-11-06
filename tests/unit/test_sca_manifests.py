# SPDX-License-Identifier: MIT
"""Tests for kalkan.sca.manifests: manifests without a lockfile and their exact pins."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kalkan.sca import manifests
from kalkan.sca.manifests import (
    PIN_PROPERTY,
    REASON_PINS_ONLY,
    REASON_RANGES,
    REASON_UNREADABLE,
    TRANSITIVE_PIN_PROPERTY,
    Pin,
    parse_manifest,
    pin_purl,
    pins_sbom,
    scan_manifests,
)
from kalkan.sca.sbom import parse_cyclonedx

VULNAPP = Path(__file__).resolve().parents[1] / "fixtures" / "vulnapp"
MSBUILD = "http://schemas.microsoft.com/developer/msbuild/2003"
DOCTYPE = '<!DOCTYPE Project [<!ENTITY v "1.0.0">]>'


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def package_json(**sections: dict[str, str]) -> str:
    return json.dumps({"name": "app", **sections})


def msbuild(*items: str, properties: str = "", namespace: bool = False) -> str:
    """Return a small MSBuild file: an optional PropertyGroup and one ItemGroup."""
    root = f'<Project ToolsVersion="15.0" xmlns="{MSBUILD}">' if namespace else "<Project>"
    lines = ['<?xml version="1.0" encoding="utf-8"?>', root]
    if properties:
        lines.append(f"  <PropertyGroup>{properties}</PropertyGroup>")
    lines += ["  <ItemGroup>", *(f"    {item}" for item in items), "  </ItemGroup>", "</Project>"]
    return "\n".join(lines) + "\n"


def central(*items: str, transitive: bool | None = None, enabled: bool = True) -> str:
    """Return a Directory.Packages.props file."""
    properties = f"<ManagePackageVersionsCentrally>{str(enabled).lower()}"
    properties += "</ManagePackageVersionsCentrally>"
    if transitive is not None:
        properties += f"<CentralPackageTransitivePinningEnabled>{str(transitive).lower()}"
        properties += "</CentralPackageTransitivePinningEnabled>"
    return msbuild(*items, properties=properties)


def reference(name: str, version: str | None = None) -> str:
    attributes = f' Include="{name}"' + (f' Version="{version}"' if version else "")
    return f"<PackageReference{attributes} />"


def package_version(name: str, version: str) -> str:
    return f'<PackageVersion Include="{name}" Version="{version}" />'


# --- parsers -----------------------------------------------------------------------------------


def test_npm_exact_pins_and_ranges():
    text = package_json(
        dependencies={
            "colors": "1.4.0",
            "jsonwebtoken": "=0.4.0",
            "express": "^4.18.2",
            "lodash": "~4.17.0",
            "debug": "*",
            "left-pad": "1.x",
            "semver": ">=7 <8",
            "beta": "2.0.0-rc.1",
            "alias": "npm:@scope/real@3.1.4",
            "local": "file:../local",
            "tagged": "latest",
            "git": "github:org/repo",
        },
        devDependencies={"@eslint/js": "9.33.0", "vitest": "^4.1.2"},
        optionalDependencies={"fsevents": "2.3.3"},
        peerDependencies={"react": "18.0.0"},
    )
    parsed = parse_manifest("package.json", text)
    assert parsed.pins == [
        ("colors", "1.4.0"),
        ("jsonwebtoken", "0.4.0"),
        ("beta", "2.0.0-rc.1"),
        ("@scope/real", "3.1.4"),
        ("@eslint/js", "9.33.0"),
        ("fsevents", "2.3.3"),
    ]
    # express, lodash, debug, left-pad, semver, tagged, git, vitest; file: is local.
    assert parsed.ranges == 8


def test_composer_skips_platform_packages():
    text = json.dumps(
        {
            "require": {
                "php": ">=8.2",
                "ext-curl": "*",
                "lib-libxml": "*",
                "composer-plugin-api": "^2.0",
                "twig/twig": "v3.0.0",
                "firebase/php-jwt": "^7.0",
                "monolog/monolog": "2.9.1",
            },
            "require-dev": {"phpunit/phpunit": "9.6.0.1", "symfony/var-dumper": "6.*"},
        }
    )
    parsed = parse_manifest("composer.json", text)
    assert parsed.pins == [
        ("twig/twig", "3.0.0"),
        ("monolog/monolog", "2.9.1"),
        ("phpunit/phpunit", "9.6.0.1"),
    ]
    assert parsed.ranges == 2


def test_gemfile_exact_requirements_only():
    text = "\n".join(
        [
            "# frozen_string_literal: true",
            'source "https://rubygems.org"',
            'gem "rails", "~> 8.0"',
            "gem 'nokogiri', '1.10.0'",
            'gem "jwt", "= 2.1.0", require: false',
            'gem("rack", "2.2.3")',
            'gem "puma", ">= 5.0", "< 7"',
            'gem "sqlite3"',
            'gem "local_gem", path: "vendor/local_gem"',
            'gem "edge", git: "https://github.com/org/edge.git"',
            "  # gem 'commented', '1.0.0'",
        ]
    )
    parsed = parse_manifest("gemfile", text)
    assert parsed.pins == [("nokogiri", "1.10.0"), ("jwt", "2.1.0"), ("rack", "2.2.3")]
    assert parsed.ranges == 3  # rails, puma, sqlite3


def test_pipfile():
    text = "\n".join(
        [
            "[packages]",
            'flask = "==0.12"',
            'requests = "*"',
            'django = {version = "==3.2.0", extras = ["bcrypt"]}',
            'local = {path = "."}',
            "[dev-packages]",
            'pytest = ">=7"',
            'black = "==24.1.*"',
        ]
    )
    parsed = parse_manifest("pipfile", text)
    assert parsed.pins == [("flask", "0.12"), ("django", "3.2.0")]
    assert parsed.ranges == 3


def test_pyproject_pep508_poetry_and_groups():
    text = "\n".join(
        [
            "[project]",
            'name = "app"',
            "dependencies = [",
            '  "PyYAML==5.3",',
            "  \"requests[socks] == 2.19.0 ; python_version >= '3.8'\",",
            '  "flask>=2",',
            '  "pkg @ https://example.com/pkg.whl",',
            '  "range>=1,<2",',
            "]",
            "[project.optional-dependencies]",
            'dev = ["pytest==8.0.0"]',
            "[dependency-groups]",
            'lint = ["ruff==0.6.0", {include-group = "dev"}]',
            "[tool.poetry.dependencies]",
            'python = "^3.11"',
            'jinja2 = "2.10"',
            'click = "^8.0"',
            'django = {version = "==3.2.0", optional = true}',
            "[tool.poetry.group.test.dependencies]",
            'mock = "==5.1.0"',
        ]
    )
    parsed = parse_manifest("pyproject.toml", text)
    assert parsed.pins == [
        ("PyYAML", "5.3"),
        ("requests", "2.19.0"),
        ("pytest", "8.0.0"),
        ("ruff", "0.6.0"),
        ("jinja2", "2.10"),
        ("django", "3.2.0"),
        ("mock", "5.1.0"),
    ]
    assert parsed.ranges == 4  # flask, the URL, range, click


def test_pyproject_without_dependencies_has_nothing():
    parsed = parse_manifest("pyproject.toml", "[tool.ruff]\nline-length = 100\n")
    assert parsed.pins == [] and parsed.ranges == 0


def test_cargo():
    text = "\n".join(
        [
            "[package]",
            'name = "app"',
            "[dependencies]",
            'serde = "1.0"',
            'time = "=0.1.43"',
            'tokio = { version = "=1.0.0", features = ["full"] }',
            'local = { path = "../local" }',
            "shared = { workspace = true }",
            'renamed = { package = "smallvec", version = "=1.6.0" }',
            "[target.'cfg(unix)'.dependencies]",
            'nix = "0.20"',
        ]
    )
    parsed = parse_manifest("cargo.toml", text)
    assert parsed.pins == [("time", "0.1.43"), ("tokio", "1.0.0"), ("smallvec", "1.6.0")]
    assert parsed.ranges == 2


def test_parse_errors_raise_value_error():
    with pytest.raises(ValueError):
        parse_manifest("package.json", "{not json")
    with pytest.raises(ValueError):
        parse_manifest("package.json", "[1, 2]")
    with pytest.raises(ValueError):
        parse_manifest("pyproject.toml", "[project\n")


def test_nuget_inline_exact_versions_and_ranges():
    text = msbuild(
        reference("Newtonsoft.Json", "13.0.1"),
        reference("Serilog", "[2.10.0]"),
        reference("Npgsql", "[ 8.0.3-preview.1 ]"),
        reference("Old.Style", "1.2"),
        reference("Range.Interval", "[1.0,2.0)"),
        reference("Range.Upper", "(,2.0]"),
        reference("Range.Lower", "(1.0,)"),
        reference("Floating.Minor", "1.*"),
        reference("Floating.Any", "*"),
        reference("From.Property", "$(LibVersion)"),
        reference("No.Version"),
        reference("$(DynamicName)", "1.0.0"),
    )
    parsed = parse_manifest("app.csproj", text)
    assert parsed.pins == [
        ("Newtonsoft.Json", "13.0.1"),
        ("Serilog", "2.10.0"),
        ("Npgsql", "8.0.3-preview.1"),
        ("Old.Style", "1.2"),
    ]
    assert parsed.ranges == 8


def test_nuget_version_override_child_elements_and_update_items():
    text = msbuild(
        '<PackageReference Include="Dapper" Version="2.0.0" VersionOverride="2.1.35" />',
        '<PackageReference Include="Polly">\n  <Version>7.2.4</Version>\n</PackageReference>',
        '<PackageReference Include="AutoMapper"><VersionOverride>[12.0.1]</VersionOverride>'
        "</PackageReference>",
        '<PackageReference Include="MediatR; FluentValidation" Version="11.1.0" />',
        '<PackageReference Update="Polly" Version="7.2.5" />',
        '<PackageReference Update="Only.Updated" Version="3.0.0" />',
        '<PackageReference Update="Metadata.Only" PrivateAssets="all" />',
        '<PackageReference Include="Empty.Version" Version="" />',
    )
    parsed = parse_manifest("app.vbproj", text, central={"Empty.Version": "5.0.0"})
    assert parsed.pins == [
        ("Dapper", "2.1.35"),
        ("Polly", "7.2.5"),
        ("AutoMapper", "12.0.1"),
        ("MediatR", "11.1.0"),
        ("FluentValidation", "11.1.0"),
        ("Only.Updated", "3.0.0"),
        ("Empty.Version", "5.0.0"),
    ]
    assert parsed.ranges == 0


def test_nuget_msbuild_namespace_and_central_versions():
    items = (
        reference("newtonsoft.json"),
        reference("Missing.Central"),
        '<x:PackageReference xmlns:x="urn:other" Include="Other" Version="1.0.0" />',
    )
    versions = {"Newtonsoft.Json": "13.0.3"}
    parsed = parse_manifest("app.csproj", msbuild(*items, namespace=True), central=versions)
    assert parsed.pins == [("newtonsoft.json", "13.0.3")]
    assert parsed.ranges == 1
    assert parse_manifest("app.csproj", msbuild(*items), central=versions).pins == parsed.pins
    opted_out = msbuild(
        *items, properties="<ManagePackageVersionsCentrally>false</ManagePackageVersionsCentrally>"
    )
    parsed = parse_manifest("app.csproj", opted_out, central=versions)
    assert parsed.pins == [] and parsed.ranges == 2


@pytest.mark.parametrize("declaration", [DOCTYPE, '<!ENTITY v "1.0.0">', "<!doctype Project>"])
def test_nuget_refuses_doctype_and_entity_declarations(declaration):
    text = msbuild(reference("A", "1.0.0")).replace("<Project>", f"{declaration}\n<Project>")
    with pytest.raises(ValueError, match="DOCTYPE or an ENTITY"):
        parse_manifest("app.csproj", text)


def test_nuget_invalid_xml_raises_value_error():
    with pytest.raises(ValueError):
        parse_manifest("app.csproj", "<Project><ItemGroup>")
    with pytest.raises(ValueError, match="not <Project>"):
        parse_manifest("app.csproj", "<Root />")


# --- discovery ---------------------------------------------------------------------------------


def test_scan_lists_manifests_without_a_lockfile(tmp_path):
    write(tmp_path / "package.json", package_json(dependencies={"a": "1.0.0", "b": "^2.0.0"}))
    write(tmp_path / "locked" / "package.json", package_json(dependencies={"c": "^1.0.0"}))
    write(tmp_path / "locked" / "yarn.lock", "")
    write(tmp_path / "php" / "composer.json", json.dumps({"require": {"x/y": "1.2.3"}}))
    write(tmp_path / "ruby" / "Gemfile", 'gem "rack", "~> 2.0"\n')
    write(tmp_path / "ruby2" / "Gemfile", 'gem "rack", "2.2.3"\n')
    write(tmp_path / "ruby2" / "Gemfile.lock", "GEM\n")
    write(tmp_path / "empty" / "package.json", package_json())
    write(tmp_path / "tool" / "pyproject.toml", "[tool.black]\n")
    write(tmp_path / "vendor" / "lib" / "composer.json", json.dumps({"require": {"a/b": "^1"}}))
    write(tmp_path / "node_modules" / "x" / "package.json", package_json(dependencies={"z": "1"}))
    write(tmp_path / "py" / "requirements.txt", "flask==0.12\n")
    result = scan_manifests(tmp_path)
    assert result.unchecked == [
        {
            "file": "package.json",
            "ecosystem": "npm",
            "reason": REASON_RANGES,
            "exact_pins": 1,
            "ranges": 1,
        },
        {
            "file": "php/composer.json",
            "ecosystem": "Packagist",
            "reason": REASON_PINS_ONLY,
            "exact_pins": 1,
            "ranges": 0,
        },
        {
            "file": "ruby/Gemfile",
            "ecosystem": "RubyGems",
            "reason": REASON_RANGES,
            "exact_pins": 0,
            "ranges": 1,
        },
    ]
    assert result.pins == [
        Pin("npm", "a", "1.0.0", "package.json"),
        Pin("Packagist", "x/y", "1.2.3", "php/composer.json"),
    ]
    assert result.warnings == []


def test_lockfile_names_compare_without_case(tmp_path):
    write(tmp_path / "Gemfile", 'gem "rack", "~> 2.0"\n')
    write(tmp_path / "GEMFILE.LOCK", "GEM\n")
    assert scan_manifests(tmp_path).unchecked == []


def test_workspace_members_are_covered_by_the_root_lockfile(tmp_path):
    write(tmp_path / "package.json", json.dumps({"workspaces": ["packages/*"]}))
    write(tmp_path / "package-lock.json", "{}")
    write(tmp_path / "packages" / "a" / "package.json", package_json(dependencies={"x": "^1"}))
    write(tmp_path / "rust" / "Cargo.toml", '[workspace]\nmembers = ["crate"]\n')
    write(tmp_path / "rust" / "Cargo.lock", "")
    write(tmp_path / "rust" / "crate" / "Cargo.toml", '[dependencies]\nserde = "1"\n')
    write(tmp_path / "uv" / "pyproject.toml", "[tool.uv.workspace]\nmembers = ['m']\n")
    write(tmp_path / "uv" / "uv.lock", "")
    write(tmp_path / "uv" / "m" / "pyproject.toml", '[project]\ndependencies = ["flask>=2"]\n')
    write(tmp_path / "pnpm" / "pnpm-lock.yaml", "")
    write(tmp_path / "pnpm" / "pnpm-workspace.yaml", "packages: ['*']\n")
    write(tmp_path / "pnpm" / "web" / "package.json", package_json(dependencies={"y": "^1"}))
    assert scan_manifests(tmp_path).unchecked == []


def test_a_parent_lockfile_without_a_workspace_does_not_cover(tmp_path):
    write(tmp_path / "package.json", package_json(dependencies={"a": "^1"}))
    write(tmp_path / "package-lock.json", "{}")
    write(tmp_path / "tools" / "package.json", package_json(dependencies={"b": "^1"}))
    assert [item["file"] for item in scan_manifests(tmp_path).unchecked] == ["tools/package.json"]


def test_an_unreadable_manifest_is_listed_with_a_warning(tmp_path):
    write(tmp_path / "package.json", "{broken")
    result = scan_manifests(tmp_path)
    assert result.unchecked == [
        {
            "file": "package.json",
            "ecosystem": "npm",
            "reason": REASON_UNREADABLE,
            "exact_pins": 0,
            "ranges": 0,
        }
    ]
    assert result.warnings and result.warnings[0].startswith("package.json: ")


def test_the_vulnapp_fixture(tmp_path):
    result = scan_manifests(VULNAPP)
    assert [(i["file"], i["reason"]) for i in result.unchecked] == [
        ("csharp/VulnApp.csproj", REASON_PINS_ONLY),
        ("php/composer.json", REASON_RANGES),
        ("ruby/Gemfile", REASON_RANGES),
    ]
    assert [(p.ecosystem, p.name, p.version, p.file) for p in result.pins] == [
        ("NuGet", name, version, "csharp/VulnApp.csproj")
        for name, version in (
            ("Microsoft.AspNetCore.Authentication.JwtBearer", "8.0.32"),
            ("Microsoft.CodeAnalysis.CSharp.Scripting", "5.9.0"),
            ("Microsoft.Data.SqlClient", "7.1.1"),
            ("MongoDB.Driver", "3.12.0"),
            ("Newtonsoft.Json", "13.0.4"),
            ("RazorEngineCore", "2026.1.1"),
        )
    ]


def test_pin_files_join_the_same_pin_of_several_manifests(tmp_path):
    write(tmp_path / "a" / "package.json", package_json(dependencies={"lodash": "4.17.15"}))
    write(tmp_path / "b" / "package.json", package_json(dependencies={"lodash": "4.17.15"}))
    result = scan_manifests(tmp_path)
    assert result.pin_files() == {
        ("npm", "lodash", "4.17.15"): ["a/package.json", "b/package.json"]
    }


# --- NuGet discovery ---------------------------------------------------------------------------


def nuget_entry(file: str, exact_pins: int, ranges: int = 0) -> dict:
    return {
        "file": file,
        "ecosystem": "NuGet",
        "reason": REASON_RANGES if ranges else REASON_PINS_ONLY,
        "exact_pins": exact_pins,
        "ranges": ranges,
    }


def test_nuget_projects_by_suffix_without_case(tmp_path):
    write(tmp_path / "App" / "App.CSPROJ", msbuild(reference("A", "1.0.0")))
    write(tmp_path / "Fs" / "Lib.fsproj", msbuild(reference("B", "2.0.0")))
    write(tmp_path / "Vb" / "Old.vbproj", msbuild(reference("C", "1.*")))
    write(tmp_path / "App" / "App.csproj.user", msbuild(reference("D", "1.0.0")))
    write(tmp_path / "Directory.Build.props", msbuild(reference("E", "1.0.0")))
    result = scan_manifests(tmp_path)
    assert result.unchecked == [
        nuget_entry("App/App.CSPROJ", 1),
        nuget_entry("Fs/Lib.fsproj", 1),
        nuget_entry("Vb/Old.vbproj", 0, 1),
    ]
    assert result.pins == [
        Pin("NuGet", "A", "1.0.0", "App/App.CSPROJ"),
        Pin("NuGet", "B", "2.0.0", "Fs/Lib.fsproj"),
    ]
    assert result.warnings == []


def test_nuget_central_versions_from_the_same_folder(tmp_path):
    api = tmp_path / "src" / "Api"
    write(api / "Api.csproj", msbuild(reference("Newtonsoft.Json"), reference("serilog")))
    write(
        api / "Directory.Packages.props",
        central(
            package_version("Newtonsoft.Json", "13.0.1"), package_version("Serilog", "[3.1.1]")
        ),
    )
    result = scan_manifests(tmp_path)
    assert result.unchecked == [nuget_entry("src/Api/Api.csproj", 2)]
    assert result.pins == [
        Pin("NuGet", "Newtonsoft.Json", "13.0.1", "src/Api/Api.csproj"),
        Pin("NuGet", "serilog", "3.1.1", "src/Api/Api.csproj"),
    ]


def test_nuget_the_nearest_props_in_a_parent_folder_wins(tmp_path):
    write(
        tmp_path / "Directory.Packages.props",
        central(package_version("A", "1.0.0"), package_version("B", "1.0.0")),
    )
    write(tmp_path / "src" / "Directory.Packages.props", central(package_version("A", "2.0.0")))
    write(tmp_path / "src" / "Web" / "Web.csproj", msbuild(reference("A"), reference("B")))
    write(tmp_path / "tools" / "Tool" / "Tool.csproj", msbuild(reference("A")))
    result = scan_manifests(tmp_path)
    assert result.unchecked == [
        nuget_entry("src/Web/Web.csproj", 1, 1),  # B is not in the nearest props file
        nuget_entry("tools/Tool/Tool.csproj", 1),
    ]
    assert result.pins == [
        Pin("NuGet", "A", "2.0.0", "src/Web/Web.csproj"),
        Pin("NuGet", "A", "1.0.0", "tools/Tool/Tool.csproj"),
    ]


def test_nuget_packages_lock_json_makes_the_project_checked(tmp_path):
    write(tmp_path / "Locked" / "Locked.csproj", msbuild(reference("A", "1.*")))
    write(tmp_path / "Locked" / "packages.lock.json", "{}")
    write(tmp_path / "Open" / "Open.csproj", msbuild(reference("A", "1.0.0")))
    write(tmp_path / "Open" / "obj" / "project.assets.json", "{}")
    result = scan_manifests(tmp_path)
    assert result.unchecked == [nuget_entry("Open/Open.csproj", 1)]
    assert result.pins == [Pin("NuGet", "A", "1.0.0", "Open/Open.csproj")]


def test_nuget_a_project_without_package_references_is_not_listed(tmp_path):
    write(
        tmp_path / "Directory.Packages.props",
        central(
            package_version("A", "1.0.0"),
            '<GlobalPackageReference Include="Analyzers" Version="3.3.4" />',
            transitive=True,
        ),
    )
    write(
        tmp_path / "Lib" / "Lib.csproj",
        '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0'
        "</TargetFramework></PropertyGroup></Project>",
    )
    write(
        tmp_path / "App" / "App.csproj",
        msbuild('<ProjectReference Include="..\\Lib\\Lib.csproj" />'),
    )
    result = scan_manifests(tmp_path)
    assert result.unchecked == [] and result.pins == [] and result.warnings == []


def test_nuget_global_package_references_apply_to_every_project(tmp_path):
    write(
        tmp_path / "Directory.Packages.props",
        central(
            package_version("A", "1.0.0"),
            '<GlobalPackageReference Include="Analyzers" Version="3.3.4" />',
            '<GlobalPackageReference Include="Build.Tool" Version="[1.0,)" />',
        ),
    )
    write(tmp_path / "One" / "One.csproj", msbuild(reference("A")))
    write(
        tmp_path / "Two" / "Two.csproj", msbuild(reference("A"), reference("Build.Tool", "1.5.0"))
    )
    result = scan_manifests(tmp_path)
    assert result.unchecked == [
        nuget_entry("One/One.csproj", 2, 1),  # A and Analyzers; Build.Tool is a range
        nuget_entry("Two/Two.csproj", 3),  # A, its own Build.Tool and Analyzers
    ]
    assert result.pins == [
        Pin("NuGet", "A", "1.0.0", "One/One.csproj"),
        Pin("NuGet", "A", "1.0.0", "Two/Two.csproj"),
        Pin("NuGet", "Build.Tool", "1.5.0", "Two/Two.csproj"),
        Pin("NuGet", "Analyzers", "3.3.4", "Directory.Packages.props"),
    ]


@pytest.mark.parametrize("transitive", [True, False, None])
def test_nuget_transitive_pins_need_transitive_pinning(tmp_path, transitive):
    write(
        tmp_path / "Directory.Packages.props",
        central(
            package_version("Direct", "1.0.0"),
            package_version("Transitive", "2.0.0"),
            package_version("Ranged", "[1.0,2.0)"),
            package_version("LockedOnly", "4.0.0"),
            transitive=transitive,
        ),
    )
    write(tmp_path / "App" / "App.csproj", msbuild(reference("Direct")))
    write(tmp_path / "Locked" / "Locked.csproj", msbuild(reference("LockedOnly")))
    write(tmp_path / "Locked" / "packages.lock.json", "{}")
    result = scan_manifests(tmp_path)
    assert result.unchecked == [nuget_entry("App/App.csproj", 1)]
    direct = Pin("NuGet", "Direct", "1.0.0", "App/App.csproj")
    if transitive:
        pin = Pin("NuGet", "Transitive", "2.0.0", "Directory.Packages.props", transitive=True)
        assert result.pins == [direct, pin]
    else:
        assert result.pins == [direct]


def test_nuget_transitive_pins_need_a_listed_project(tmp_path):
    write(
        tmp_path / "Directory.Packages.props",
        central(package_version("A", "1.0.0"), package_version("B", "2.0.0"), transitive=True),
    )
    write(tmp_path / "App" / "App.csproj", msbuild(reference("A")))
    write(tmp_path / "App" / "packages.lock.json", "{}")
    result = scan_manifests(tmp_path)
    assert result.unchecked == [] and result.pins == []


def test_nuget_unsafe_and_unreadable_projects_are_listed(tmp_path, monkeypatch):
    write(
        tmp_path / "Evil" / "Evil.csproj",
        msbuild(reference("A", "1.0.0")).replace("<Project>", f"{DOCTYPE}\n<Project>"),
    )
    write(tmp_path / "Broken" / "Broken.vbproj", "<Project><ItemGroup>")
    write(tmp_path / "Big" / "Big.csproj", msbuild(reference("A", "1.0.0")) + " " * 300)
    write(tmp_path / "Locked" / "Locked.csproj", "<Project><ItemGroup>")
    write(tmp_path / "Locked" / "packages.lock.json", "{}")
    monkeypatch.setattr(manifests, "MAX_MANIFEST_BYTES", 300)
    result = scan_manifests(tmp_path)
    assert [(item["file"], item["ecosystem"], item["reason"]) for item in result.unchecked] == [
        ("Big/Big.csproj", "NuGet", REASON_UNREADABLE),
        ("Broken/Broken.vbproj", "NuGet", REASON_UNREADABLE),
        ("Evil/Evil.csproj", "NuGet", REASON_UNREADABLE),
    ]
    assert result.pins == []
    assert len(result.warnings) == 3
    assert "DOCTYPE or an ENTITY" in result.warnings[2]


def test_nuget_an_unreadable_props_file_leaves_ranges(tmp_path):
    write(
        tmp_path / "Directory.Packages.props",
        central(package_version("A", "1.0.0")).replace("<Project>", f"{DOCTYPE}\n<Project>"),
    )
    write(tmp_path / "App" / "App.csproj", msbuild(reference("A"), reference("B", "2.0.0")))
    result = scan_manifests(tmp_path)
    assert result.unchecked == [nuget_entry("App/App.csproj", 1, 1)]
    assert result.pins == [Pin("NuGet", "B", "2.0.0", "App/App.csproj")]
    assert result.warnings == [
        "Directory.Packages.props: the manifest cannot be read: the XML has a DOCTYPE or an "
        "ENTITY declaration; refused; the central package versions are unknown"
    ]


def test_nuget_central_package_management_can_be_turned_off(tmp_path):
    write(
        tmp_path / "Directory.Packages.props",
        central(
            package_version("A", "1.0.0"),
            '<GlobalPackageReference Include="G" Version="1.0.0" />',
            enabled=False,
        ),
    )
    turn_on = "<ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally>"
    write(tmp_path / "Off" / "Off.csproj", msbuild(reference("A")))
    write(tmp_path / "On" / "On.csproj", msbuild(reference("A"), properties=turn_on))
    result = scan_manifests(tmp_path)
    assert result.unchecked == [
        nuget_entry("Off/Off.csproj", 0, 1),
        nuget_entry("On/On.csproj", 2),  # A and the global G
    ]
    assert result.pins == [
        Pin("NuGet", "A", "1.0.0", "On/On.csproj"),
        Pin("NuGet", "G", "1.0.0", "Directory.Packages.props"),
    ]


# --- the pins SBOM -----------------------------------------------------------------------------


def test_pin_purls():
    assert pin_purl("npm", "@scope/name", "1.0.0") == "pkg:npm/%40scope/name@1.0.0"
    assert pin_purl("npm", "lodash", "4.17.15") == "pkg:npm/lodash@4.17.15"
    assert pin_purl("Packagist", "twig/twig", "3.0.0") == "pkg:composer/twig/twig@3.0.0"
    assert pin_purl("RubyGems", "rack", "2.2.3") == "pkg:gem/rack@2.2.3"
    assert pin_purl("PyPI", "PyYAML", "5.3") == "pkg:pypi/pyyaml@5.3"
    assert pin_purl("crates.io", "time", "0.1.43") == "pkg:cargo/time@0.1.43"
    assert pin_purl("NuGet", "Newtonsoft.Json", "13.0.1") == "pkg:nuget/Newtonsoft.Json@13.0.1"
    assert pin_purl("NuGet", "Npgsql", "8.0.3-rc.1") == "pkg:nuget/Npgsql@8.0.3-rc.1"


def test_pins_sbom_round_trip():
    pins = [
        Pin("npm", "@scope/name", "1.0.0", "web/package.json"),
        Pin("npm", "@scope/name", "1.0.0", "api/package.json"),
        Pin("Packagist", "twig/twig", "3.0.0", "php/composer.json"),
        Pin("RubyGems", "rack", "2.2.3", "Gemfile"),
    ]
    doc = pins_sbom(pins)
    assert doc["bomFormat"] == "CycloneDX" and doc["specVersion"] == "1.5"
    assert len(doc["components"]) == 3
    first = doc["components"][0]
    assert first["properties"] == [
        {"name": PIN_PROPERTY, "value": "web/package.json"},
        {"name": PIN_PROPERTY, "value": "api/package.json"},
    ]
    parsed = parse_cyclonedx(json.loads(json.dumps(doc)))
    assert [(c.ecosystem, c.name, c.version) for c in parsed.components] == [
        ("npm", "@scope/name", "1.0.0"),
        ("Packagist", "twig/twig", "3.0.0"),
        ("RubyGems", "rack", "2.2.3"),
    ]


def test_pins_sbom_marks_the_nuget_transitive_pins():
    pins = [
        Pin("NuGet", "Newtonsoft.Json", "13.0.1", "src/Api/Api.csproj"),
        Pin("NuGet", "System.Text.Json", "8.0.4", "Directory.Packages.props", transitive=True),
        # A direct pin elsewhere: the component is not transitive only.
        Pin("NuGet", "Shared", "1.0.0", "a/Directory.Packages.props", transitive=True),
        Pin("NuGet", "Shared", "1.0.0", "b/B.csproj"),
    ]
    doc = pins_sbom(pins)
    assert [(c["purl"], c["properties"]) for c in doc["components"]] == [
        (
            "pkg:nuget/Newtonsoft.Json@13.0.1",
            [{"name": PIN_PROPERTY, "value": "src/Api/Api.csproj"}],
        ),
        (
            "pkg:nuget/System.Text.Json@8.0.4",
            [
                {"name": PIN_PROPERTY, "value": "Directory.Packages.props"},
                {"name": TRANSITIVE_PIN_PROPERTY, "value": "true"},
            ],
        ),
        (
            "pkg:nuget/Shared@1.0.0",
            [
                {"name": PIN_PROPERTY, "value": "a/Directory.Packages.props"},
                {"name": PIN_PROPERTY, "value": "b/B.csproj"},
            ],
        ),
    ]
    parsed = parse_cyclonedx(json.loads(json.dumps(doc)))
    assert [(c.ecosystem, c.name, c.version) for c in parsed.components] == [
        ("NuGet", "Newtonsoft.Json", "13.0.1"),
        ("NuGet", "System.Text.Json", "8.0.4"),
        ("NuGet", "Shared", "1.0.0"),
    ]


def test_scan_pins_go_into_the_pins_sbom(tmp_path):
    write(
        tmp_path / "Directory.Packages.props",
        central(package_version("A", "1.0.0"), package_version("B", "2.0.0"), transitive=True),
    )
    write(tmp_path / "App" / "App.csproj", msbuild(reference("A")))
    doc = pins_sbom(scan_manifests(tmp_path).pins)
    assert [c["purl"] for c in doc["components"]] == ["pkg:nuget/A@1.0.0", "pkg:nuget/B@2.0.0"]
    assert doc["components"][1]["properties"][-1] == {
        "name": TRANSITIVE_PIN_PROPERTY,
        "value": "true",
    }
