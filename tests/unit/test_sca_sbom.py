# SPDX-License-Identifier: MIT
"""Tests for kalkan.sca.sbom: CycloneDX parsing and package identity (ENGINE-SPEC 17)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kalkan.errors import ValidationError
from kalkan.sca.sbom import (
    display_version,
    load_json_file,
    manifest_ecosystem,
    normalize_package,
    package_key,
    parse_cyclonedx,
    parse_purl,
    purl_identity,
    read_sbom,
    relative_location,
    version_key,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "sca"
DEPAPP = FIXTURES / "depapp"


def identities(result):
    return {(c.ecosystem, c.name, c.version): c.locations for c in result.components}


# --- Syft --------------------------------------------------------------------------------------


def test_syft_sbom_components_and_locations():
    result = read_sbom(FIXTURES / "syft.cdx.json", DEPAPP)
    assert result.tool == "syft"
    assert result.spec_version == "1.7"
    found = identities(result)
    assert found[("PyPI", "pyyaml", "5.3")] == ["requirements.txt"]
    assert found[("PyPI", "jinja2", "2.10.1")] == ["requirements.txt"]
    assert found[("npm", "lodash", "4.17.20")] == ["package-lock.json"]
    # Syft writes Go versions with the "v" prefix; the record form drops it.
    assert found[("Go", "golang.org/x/text", "0.3.5")] == ["go.mod"]
    assert found[("Go", "github.com/dgrijalva/jwt-go", "3.2.0+incompatible")] == ["go.mod"]
    # File components never become packages.
    assert all(not c.name.startswith("/") for c in result.components)
    assert result.by_ecosystem() == {"Go": 2, "PyPI": 3, "npm": 4}
    assert result.warnings == []


def test_syft_component_keeps_purl_and_type():
    result = read_sbom(FIXTURES / "syft.cdx.json", DEPAPP)
    text = next(c for c in result.components if c.name == "golang.org/x/text")
    assert text.purl == "pkg:golang/golang.org/x/text@v0.3.5"
    assert text.package_type == "go-module"
    assert text.to_dict()["locations"] == ["go.mod"]


# --- Trivy -------------------------------------------------------------------------------------


def test_trivy_sbom_locations_come_from_the_dependency_graph():
    result = read_sbom(FIXTURES / "trivy.cdx.json", DEPAPP)
    assert result.tool == "trivy"
    found = identities(result)
    # Trivy keeps the written name ("PyYAML"); the PEP 503 form is "pyyaml".
    assert found[("PyPI", "pyyaml", "5.3")] == ["requirements.txt"]
    assert found[("npm", "minimist", "1.2.5")] == ["package-lock.json"]
    # Go packages hang below the main module, which hangs below go.mod.
    assert found[("Go", "golang.org/x/text", "0.3.5")] == ["go.mod"]
    # The main module has no version and the manifests have no package URL: skipped.
    assert ("Go", "example.com/depapp", "") not in found
    assert len(result.components) == 8


def test_trivy_file_path_property_and_evidence_occurrences():
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [
            {
                "type": "library",
                "name": "spring-core",
                "version": "5.3.0",
                "purl": "pkg:maven/org.springframework/spring-core@5.3.0",
                "properties": [
                    {"name": "aquasecurity:trivy:FilePath", "value": "lib/spring-core.jar"}
                ],
            },
            {
                "type": "library",
                "name": "left-pad",
                "version": "1.3.0",
                "purl": "pkg:npm/left-pad@1.3.0",
                "evidence": {"occurrences": [{"location": "web/package-lock.json"}]},
            },
        ],
    }
    result = parse_cyclonedx(doc, None)
    found = identities(result)
    assert found[("Maven", "org.springframework:spring-core", "5.3.0")] == ["lib/spring-core.jar"]
    assert found[("npm", "left-pad", "1.3.0")] == ["web/package-lock.json"]


def test_duplicate_components_join_locations():
    doc = {
        "bomFormat": "CycloneDX",
        "components": [
            {
                "type": "library",
                "name": "PyYAML",
                "version": "5.3",
                "purl": "pkg:pypi/pyyaml@5.3",
                "properties": [{"name": "syft:location:0:path", "value": "/a/requirements.txt"}],
            },
            {
                "type": "library",
                "name": "pyyaml",
                "version": "5.3.0",
                "purl": "pkg:pypi/pyyaml@5.3.0",
                "properties": [{"name": "syft:location:0:path", "value": "/b/requirements.txt"}],
            },
        ],
    }
    result = parse_cyclonedx(doc, None)
    assert len(result.components) == 1
    assert result.components[0].locations == ["a/requirements.txt", "b/requirements.txt"]


def test_location_outside_the_target_gives_a_warning():
    doc = {
        "bomFormat": "CycloneDX",
        "components": [
            {
                "type": "library",
                "name": "x",
                "version": "1.0.0",
                "purl": "pkg:npm/x@1.0.0",
                "properties": [{"name": "syft:location:0:path", "value": "/../../etc/passwd"}],
            }
        ],
    }
    result = parse_cyclonedx(doc, None)
    assert result.components[0].locations == []
    assert result.warnings and "not inside the target" in result.warnings[0]


def test_not_cyclonedx_raises():
    with pytest.raises(ValidationError):
        parse_cyclonedx({"spdxVersion": "SPDX-2.3"}, None)
    with pytest.raises(ValidationError):
        parse_cyclonedx([], None)


def test_load_json_file_accepts_bom_and_utf16(tmp_path):
    doc = {"bomFormat": "CycloneDX", "components": []}
    bom = tmp_path / "bom.json"
    bom.write_bytes(b"\xef\xbb\xbf" + json.dumps(doc).encode("utf-8"))
    assert load_json_file(bom) == doc
    utf16 = tmp_path / "utf16.json"
    utf16.write_bytes(json.dumps(doc).encode("utf-16"))
    assert load_json_file(utf16) == doc
    broken = tmp_path / "broken.json"
    broken.write_text("{", encoding="utf-8")
    with pytest.raises(ValidationError):
        load_json_file(broken)


# --- identity helpers --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("purl", "expected"),
    [
        ("pkg:npm/lodash@4.17.20", ("npm", "lodash", "4.17.20")),
        ("pkg:npm/%40babel/core@7.0.0", ("npm", "@babel/core", "7.0.0")),
        ("pkg:pypi/pyyaml@5.3", ("PyPI", "pyyaml", "5.3")),
        (
            "pkg:golang/github.com/dgrijalva/jwt-go@v3.2.0%2Bincompatible",
            ("Go", "github.com/dgrijalva/jwt-go", "v3.2.0+incompatible"),
        ),
        (
            "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?type=jar",
            ("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1"),
        ),
        ("pkg:deb/debian/openssl@3.0.11-1?distro=debian-12", ("Debian", "openssl", "3.0.11-1")),
        ("pkg:cargo/smallvec@1.6.0", ("crates.io", "smallvec", "1.6.0")),
        ("pkg:golang/example.com/depapp", ("Go", "example.com/depapp", "")),
    ],
)
def test_purl_identity(purl, expected):
    assert purl_identity(purl) == expected


def test_parse_purl_parts_and_rejects():
    purl = parse_purl("pkg:maven/org.example/lib@1.0?type=jar&classifier=sources#sub/dir")
    assert purl is not None
    assert (purl.type, purl.namespace, purl.name, purl.version) == (
        "maven",
        "org.example",
        "lib",
        "1.0",
    )
    assert purl.qualifiers == {"type": "jar", "classifier": "sources"}
    assert purl.subpath == "sub/dir"
    assert parse_purl("npm/lodash") is None
    assert parse_purl("pkg:npm") is None
    assert parse_purl(None) is None


def test_package_and_version_keys():
    assert normalize_package("PyPI", "PyYAML") == "pyyaml"
    assert package_key("PyPI", "Foo_Bar.baz") == package_key("PyPI", "foo-bar-baz")
    assert package_key("npm", "Lodash") != package_key("npm", "lodash")
    assert package_key("RubyGems", "Rails") == "rails"
    assert display_version("Go", "v0.3.5") == "0.3.5"
    assert display_version("Go", "version") == "version"
    assert display_version("npm", "v1.0.0") == "v1.0.0"
    assert version_key("PyPI", "5.3.0") == version_key("PyPI", "5.3") == "5.3"
    assert version_key("PyPI", "1.0.0") == "1"
    assert version_key("PyPI", "2.0rc1") == "2.0rc1"
    assert version_key("npm", "5.3.0") != version_key("npm", "5.3")
    assert version_key("Go", "v0.3.5") == version_key("Go", "0.3.5")


@pytest.mark.parametrize(
    ("path", "ecosystem"),
    [
        ("requirements.txt", "PyPI"),
        ("app/requirements-dev.txt", "PyPI"),
        ("web/package-lock.json", "npm"),
        ("go.mod", "Go"),
        ("Cargo.lock", "crates.io"),
        ("src/App.csproj", "NuGet"),
        ("README.md", None),
    ],
)
def test_manifest_ecosystem(path, ecosystem):
    assert manifest_ecosystem(path) == ecosystem


def test_relative_location(tmp_path):
    root = tmp_path / "target"
    root.mkdir()
    absolute = (root / "web" / "package-lock.json").as_posix()
    assert relative_location(absolute, root) == "web/package-lock.json"
    (root / "requirements.txt").write_text("pyyaml==5.3\n", encoding="utf-8")
    assert relative_location("/requirements.txt", root) == "requirements.txt"
    # An absolute POSIX path outside the target is not a scan-root path.
    assert relative_location("/opt/elsewhere/go.mod", root) is None
    assert relative_location("./go.mod", root) == "go.mod"
    assert relative_location("sub\\go.mod", root) == "sub/go.mod"
    assert relative_location("C:/elsewhere/go.mod", root) is None
    assert relative_location("/../secret", root) is None
    assert relative_location("", root) is None
    assert relative_location(None, root) is None
    assert relative_location("file:///" + absolute.lstrip("/"), root) == "web/package-lock.json"
