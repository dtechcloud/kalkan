# SPDX-License-Identifier: MIT
"""Tests for the pinned tool manifest and the platform keys (kalkan.tools.manifest, .platform)."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from urllib.parse import urlparse

import pytest

from kalkan.errors import ToolError, ValidationError
from kalkan.tools.manifest import (
    DEFAULT_MANIFEST_PATH,
    MIN_RELEASE_AGE_DAYS,
    is_safe_member_name,
    is_sha256,
    load_manifest,
    parse_manifest,
    release_age_errors,
    tree_digest,
    validate_manifest,
)
from kalkan.tools.platform import PLATFORMS, exe_suffix, normalize_arch, platform_key

EXPECTED_VERSIONS = {
    "trivy": ("0.75.0", "binary"),
    "gitleaks": ("8.30.1", "binary"),
    "opengrep": ("1.30.1", "binary"),
    "hadolint": ("2.15.1", "binary"),
    "go": ("1.26.9", "toolchain"),
    "gosec": ("2.29.0", "binary"),
    "osv-scanner": ("2.6.0", "binary"),
    "syft": ("1.54.0", "binary"),
    "grype": ("0.119.0", "binary"),
    "checkov": ("3.3.22", "pip"),
    "bandit": ("1.9.4", "pip"),
    "govulncheck": ("1.8.0", "go-install"),
    "zizmor": ("1.30.1", "binary"),
    "actionlint": ("1.7.12", "binary"),
    "poutine": ("1.1.6", "go-install"),
    "scorecard": ("5.5.0", "binary"),
    "kingfisher": ("2.11.1", "binary"),
    "shellcheck": ("0.11.0", "binary"),
    "flawfinder": ("2.0.20", "pip"),
    "gixy": ("0.2.55", "pip"),
    "helm": ("4.3.0", "binary"),
    "vacuum": ("0.33.0", "binary"),
}
#: Binary tools whose assets are PyPI wheels (a wheel is a zip archive), not GitHub releases.
PYPI_WHEEL_TOOLS = {"zizmor"}
#: Binary tools whose assets live on the download site of the project (get.helm.sh), with one
#: checksum file per asset (``<asset url>.sha256sum``).
SITE_ASSET_TOOLS = {"helm": "https://get.helm.sh/"}


@pytest.fixture(scope="module")
def raw_manifest() -> dict:
    return json.loads(DEFAULT_MANIFEST_PATH.read_text(encoding="utf-8"))


def test_packaged_manifest_is_valid(raw_manifest):
    assert validate_manifest(raw_manifest) == []
    manifest = load_manifest()
    assert manifest.names() == list(EXPECTED_VERSIONS)


@pytest.mark.parametrize("name", sorted(EXPECTED_VERSIONS))
def test_every_tool_is_pinned_to_the_expected_version(name):
    tool = load_manifest().get(name)
    assert (tool.version, tool.kind) == EXPECTED_VERSIONS[name]
    assert tool.license
    assert not tool.is_blocked(tool.version)


@pytest.mark.parametrize("name", [n for n, (_, k) in EXPECTED_VERSIONS.items() if k == "binary"])
def test_every_platform_has_an_asset_or_an_explained_omission(raw_manifest, name):
    entry = raw_manifest["tools"][name]
    assets = entry["platforms"]
    assert assets, name
    for key in PLATFORMS:
        if key not in assets:
            assert key in entry["notes"], f"{name}: {key} omitted without a note"
            continue
        asset = assets[key]
        if name in PYPI_WHEEL_TOOLS:
            assert asset["url"].startswith("https://files.pythonhosted.org/packages/"), key
            assert asset["url"].endswith(".whl") and asset["archive"] == "zip", key
            suffix = ".exe" if key.startswith("windows-") else ""
            scripts = f"{name}-{entry['version']}.data/scripts/{entry['executable']}{suffix}"
            assert asset["binary"] == scripts, key
            assert re.fullmatch(r"[0-9a-f]{64}", asset["binary_sha256"]), (name, key)
            continue
        if name in SITE_ASSET_TOOLS:
            assert asset["url"].startswith(SITE_ASSET_TOOLS[name]), (name, key)
            assert f"-{entry['tag']}-" in asset["url"], (name, key)
        else:
            assert asset["url"].startswith("https://github.com/"), (name, key)
            assert f"/releases/download/{entry['tag']}/" in asset["url"], (name, key)
        assert re.fullmatch(r"[0-9a-f]{64}", asset["sha256"]), (name, key)
        assert re.fullmatch(r"[0-9a-f]{64}", asset["binary_sha256"]), (name, key)
        assert asset["size"] > 0
        basename = urlparse(asset["url"]).path.rsplit("/", 1)[1]
        if basename.endswith(".zip"):
            assert asset["archive"] == "zip"
        elif basename.endswith((".tar.gz", ".tgz")):
            assert asset["archive"] == "tar.gz"
        else:
            assert asset["archive"] == "none"
            assert asset["binary"] == basename
            assert asset["binary_sha256"] == asset["sha256"]
        suffix = ".exe" if key.startswith("windows-") else ""
        assert asset["binary"].endswith(entry["executable"] + suffix) or asset["archive"] == "none"


def test_known_platform_gaps_are_recorded(raw_manifest):
    tools = raw_manifest["tools"]
    for name in ("trivy", "opengrep", "hadolint", "grype"):
        assert "windows-arm64" not in tools[name]["platforms"]
        assert "windows-arm64" in tools[name]["notes"]
    for name in (
        "gitleaks",
        "gosec",
        "osv-scanner",
        "syft",
        "actionlint",
        "scorecard",
        "zizmor",
        "kingfisher",
        "helm",
        "vacuum",
    ):
        assert set(tools[name]["platforms"]) == set(PLATFORMS)
    # ShellCheck ships one Windows build (x86_64); Windows on Arm runs it through emulation.
    shellcheck = tools["shellcheck"]
    assert shellcheck["platforms"]["windows-arm64"] == shellcheck["platforms"]["windows-amd64"]
    assert "windows-arm64" in shellcheck["notes"] and "emulation" in shellcheck["notes"]


def test_zizmor_windows_arm64_uses_the_x64_wheel(raw_manifest):
    # zizmor 1.30.1 publishes no windows-arm64 build: Windows 11 on Arm runs the x64 build
    # through emulation. The notes say so, and no native build header is claimed for it.
    entry = raw_manifest["tools"]["zizmor"]
    assets = entry["platforms"]
    assert assets["windows-arm64"] == assets["windows-amd64"]
    assert "windows-arm64" in entry["notes"] and "emulation" in entry["notes"]
    assert "windows-arm64" not in entry["cross_check"]["platforms"]
    assert entry["checksums_url"] == f"https://pypi.org/pypi/zizmor/{entry['version']}/json"


def test_sha256_sources(raw_manifest):
    tools = raw_manifest["tools"]
    computed = ("opengrep", "shellcheck")  # releases without a checksums file
    for name in computed:
        assert tools[name]["sha256_source"] == "computed-at-pin-time"
        assert "checksums_url" not in tools[name]
        assert "github-asset-digest" in tools[name]["cross_check"]["sources"]
    for name, (_, kind) in EXPECTED_VERSIONS.items():
        if kind != "binary" or name in computed or name in PYPI_WHEEL_TOOLS:
            continue
        assert tools[name]["sha256_source"] == "upstream-checksums", name
        if name in SITE_ASSET_TOOLS:
            continue  # one checksum file per asset (test_helm_entry)
        assert tools[name]["checksums_url"].startswith("https://github.com/"), name
        assert is_sha256(tools[name]["checksums_sha256"]), name


def test_every_pin_is_at_least_14_days_younger_than_its_release(raw_manifest):
    # ADR-0005 rule 1: the pin day is at least 14 days after the release day. Every entry,
    # also one that a later change adds, records both dates.
    assert MIN_RELEASE_AGE_DAYS == 14
    assert release_age_errors(raw_manifest) == []
    for name, entry in raw_manifest["tools"].items():
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", entry["released_at"]), name
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", entry["pinned_at"]), name
        tool = load_manifest().get(name)
        assert (tool.released_at, tool.pinned_at) == (entry["released_at"], entry["pinned_at"])
    assert "pinned_at" not in raw_manifest  # one pin day per entry, not one for the file


@pytest.mark.parametrize(
    ("released", "pinned", "problem"),
    [
        ("2026-10-12", "2026-10-25", "13 days after the release on 2026-10-12"),
        ("2026-10-25", "2026-10-25", "0 days after"),
        ("2026-10-11", "2026-10-25", None),  # exactly 14 days
        (None, "2026-10-25", "needs released_at and pinned_at"),
        ("2026-10-01", None, "needs released_at and pinned_at"),
        ("25.10.2026", "2026-10-25", "needs released_at and pinned_at"),
    ],
)
def test_release_age_errors_name_a_young_or_undated_pin(raw_manifest, released, pinned, problem):
    data = copy.deepcopy(raw_manifest)
    entry = data["tools"]["scorecard"]
    for key, value in (("released_at", released), ("pinned_at", pinned)):
        if value is None:
            entry.pop(key)
        else:
            entry[key] = value
    errors = release_age_errors(data)
    if problem is None:
        assert errors == []
    else:
        assert [e for e in errors if e.startswith("tools.scorecard:")] == errors
        assert len(errors) == 1 and problem in errors[0], errors


def test_helm_entry(raw_manifest):
    # Helm 4.3.0: binaries on get.helm.sh with one checksum file per asset; the release notes
    # list the same values and every archive has a PGP signature (checked at pin time).
    entry = raw_manifest["tools"]["helm"]
    assert entry["license"] == "Apache-2.0"
    assert (entry["released_at"], entry["pinned_at"]) == ("2026-09-09", "2026-10-25")
    assert entry["version_args"] == ["version", "--short"]
    assert entry["checksums_url"] == (
        "https://get.helm.sh/helm-v4.3.0-linux-amd64.tar.gz.sha256sum"
    )
    assert entry["checksums_url"] == entry["platforms"]["linux-amd64"]["url"] + ".sha256sum"
    assert set(entry["cross_check"]["sources"]) == {
        "download",
        "upstream-checksums",
        "github-release-notes",
        "pgp-signature",
    }
    assert entry["signature"]["key_fingerprint"] == "208DD36ED5BB3745A16743A4C7C6FBB5B91C1155"
    assert entry["signature"]["verified_by_kalkan"] is False
    for key, asset in entry["platforms"].items():
        os_name, arch = key.split("-")
        suffix = "zip" if os_name == "windows" else "tar.gz"
        assert asset["url"] == f"https://get.helm.sh/helm-v4.3.0-{os_name}-{arch}.{suffix}"
        assert asset["binary"] == f"{os_name}-{arch}/helm" + (
            ".exe" if os_name == "windows" else ""
        )


def test_vacuum_entry(raw_manifest):
    entry = raw_manifest["tools"]["vacuum"]
    assert entry["license"] == "MIT"
    assert (entry["released_at"], entry["pinned_at"]) == ("2026-10-10", "2026-10-25")
    assert entry["version_args"] == ["version", "--no-update-check"]
    assert entry["signature"]["type"] == "sigstore"
    assert {asset["archive"] for asset in entry["platforms"].values()} == {"tar.gz"}


def test_trivy_blocks_the_compromised_versions():
    trivy = load_manifest().get("trivy")
    assert {"0.69.4", "0.69.5", "0.69.6"} <= set(trivy.blocked_versions)
    assert trivy.is_blocked("v0.69.5")
    assert not trivy.is_blocked(trivy.version)


def test_no_tool_pins_a_blocked_version(raw_manifest):
    for name, entry in raw_manifest["tools"].items():
        blocked = {v.lstrip("v") for v in entry["blocked_versions"]}
        assert entry["version"] not in blocked, name


def test_python_and_go_tools(raw_manifest):
    manifest = load_manifest()
    assert manifest.get("checkov").requirement == "checkov==3.3.22"
    assert manifest.get("bandit").requirement == "bandit[sarif]==1.9.4"
    govulncheck = manifest.get("govulncheck")
    assert govulncheck.module == "golang.org/x/vuln/cmd/govulncheck@v1.8.0"
    assert govulncheck.min_go_version == "1.26"
    assert govulncheck.requires_go
    assert manifest.get("gosec").requires_go
    assert manifest.get("gosec").min_go_version == "1.25"
    assert not manifest.get("trivy").requires_go
    assert not manifest.get("go").requires_go
    poutine = manifest.get("poutine")
    assert poutine.module == "github.com/boostsecurityio/poutine@v1.1.6"
    assert poutine.requires_go and poutine.min_go_version == "1.26"
    assert poutine.build_flags[0] == "-trimpath"
    assert poutine.build_flags[1].startswith("-ldflags=-X main.version=1.1.6 ")
    # The version probe never starts the version check of poutine (it calls the network).
    assert "--disable-version-check" in poutine.version_args
    assert govulncheck.build_flags == ()
    assert manifest.get("flawfinder").requirement == "flawfinder==2.0.20"
    gixy = manifest.get("gixy")
    # The PyPI package of the maintained fork; no extra: the "deep" extra pulls in redoctor
    # (Business Source License 1.1, not OSI-approved), which the release binaries bundle.
    assert (gixy.package, gixy.requirement, gixy.executable) == (
        "gixy-ng",
        "gixy-ng==0.2.55",
        "gixy",
    )
    assert gixy.license == "MPL-2.0" and "redoctor" in gixy.notes


#: The subjects of the Kingfisher v2.11.1 SLSA provenance (multiple.intoto.jsonl, read on
#: 2026-10-25); they matched the downloads and the GitHub release asset digests.
KINGFISHER_SUBJECTS = {
    "windows-amd64": "6b41da5b091f131948d85568aae7da594af0b95c19599f9deb7a08d1f76b823c",
    "windows-arm64": "9617c17ff2ea57a40e2562edca475d2c5ddd6088f2b1d44b3536dbc57dc21aae",
    "linux-amd64": "84e4a4c45814f05e80aa8eee768e5170d758736fa116ffaf03565da4d5a77447",
    "linux-arm64": "da7508a90ff36337b41d12e63814cca3ac5586abdcf8c194898059c1ed5e1f81",
    "darwin-amd64": "e91b74c447b759fc72f993373b80ce7a6122a275f5793df61928b9c3c4eac1e3",
    "darwin-arm64": "131de009409be38ae595550acfa8811ff3d43912715687758ff6a84157f1ef5e",
}


def test_kingfisher_entry(raw_manifest):
    entry = raw_manifest["tools"]["kingfisher"]
    assert entry["checksums_url"].endswith("/v2.11.1/multiple.intoto.jsonl")
    assert entry["signature"]["type"] == "slsa-provenance"
    for key in PLATFORMS:
        asset = entry["platforms"][key]
        expected = "zip" if key.startswith("windows-") else "tar.gz"
        assert asset["archive"] == expected, key
        assert asset["binary"] == ("kingfisher.exe" if expected == "zip" else "kingfisher")
        assert asset["sha256"] == KINGFISHER_SUBJECTS[key], key


#: SHA-256 values of the Go 1.26.9 archives as https://go.dev/dl/?mode=json&include=all lists
#: them (2026-10-16). Every archive was downloaded and hashed at pin time, and again on
#: 2026-10-25 (pinned_at, ADR-0005 rule 1).
GO_ARCHIVES = {
    "windows-amd64": ("zip", "d722201a9c0c086d1610e111c48203009af690892ed708072bd5ae20160e7a59"),
    "windows-arm64": ("zip", "05215f9e71ea27c9e843409314b1e6bf12dc6a5516318126b2357d497fed42c5"),
    "linux-amd64": ("tar.gz", "42d158b4d8f7b61ac0a830567c940a86098fb7aac52e467a5ebec03ef5cc2f8d"),
    "linux-arm64": ("tar.gz", "4a97373d49fcacdcf3694fea368a500b00ee3e963974f3e7514132717632f052"),
    "darwin-amd64": ("tar.gz", "00c29e3d4c8562f547410daa18d2959b641bd691ab00c4a525ea817a0253d4bd"),
    "darwin-arm64": ("tar.gz", "f9bb7c0a02506c5d9bf0d1eb1f7ee6c7684f844ae49558308a0427b830e022cc"),
}


def test_go_toolchain_entry(raw_manifest):
    entry = raw_manifest["tools"]["go"]
    assert entry["kind"] == "toolchain"
    assert entry["license"] == "BSD-3-Clause"
    assert entry["sha256_source"] == "upstream-checksums"
    assert entry["checksums_url"] == "https://go.dev/dl/?mode=json&include=all"
    assert set(entry["platforms"]) == set(PLATFORMS)
    version = entry["version"]
    assert version.startswith("1.26.")
    for key, (archive, sha256) in GO_ARCHIVES.items():
        asset = entry["platforms"][key]
        os_name, arch = key.split("-")
        suffix = "zip" if archive == "zip" else "tar.gz"
        assert asset["url"] == f"https://go.dev/dl/go{version}.{os_name}-{arch}.{suffix}"
        assert (asset["archive"], asset["sha256"]) == (archive, sha256), key
        assert asset["root"] == "go"
        assert asset["binary"] == "go/bin/go" + exe_suffix(key)
        assert is_sha256(asset["binary_sha256"]) and is_sha256(asset["tree_sha256"])
        assert asset["files"] == 15045
        assert asset["size"] > 60_000_000


def test_tree_digest_is_sorted_sha256sum_lines():
    files = [("go/b", "2" * 64), ("go/a", "1" * 64)]
    text = "1" * 64 + "  go/a\n" + "2" * 64 + "  go/b\n"
    assert tree_digest(files) == hashlib.sha256(text.encode("utf-8")).hexdigest()
    assert tree_digest(reversed(files)) == tree_digest(files)
    assert tree_digest([]) == hashlib.sha256(b"").hexdigest()


def test_unknown_tool_raises_tool_error():
    with pytest.raises(ToolError, match="unknown tool"):
        load_manifest().get("semgrep")


# --- validation of broken manifests -----------------------------------------------------------


def _broken(raw_manifest: dict, mutate) -> list[str]:
    data = copy.deepcopy(raw_manifest)
    mutate(data)
    return validate_manifest(data)


@pytest.mark.parametrize(
    ("mutate", "expected"),
    [
        (
            lambda d: d["tools"]["trivy"]["platforms"]["linux-amd64"].update(sha256="ABC"),
            "linux-amd64.sha256",
        ),
        (
            lambda d: d["tools"]["trivy"]["platforms"]["linux-amd64"].update(sha256="A" * 64),
            "linux-amd64.sha256",
        ),
        (
            lambda d: d["tools"]["trivy"]["platforms"]["linux-amd64"].update(
                url="http://example.com/trivy.tar.gz"
            ),
            "linux-amd64.url",
        ),
        (
            lambda d: d["tools"]["trivy"]["platforms"]["linux-amd64"].update(binary="../trivy"),
            "linux-amd64.binary",
        ),
        (
            lambda d: d["tools"]["trivy"]["platforms"]["linux-amd64"].update(archive="rar"),
            "linux-amd64.archive",
        ),
        (lambda d: d["tools"]["trivy"].update(version="0.69.4"), "blocked version"),
        (lambda d: d["tools"]["trivy"].update(notes=""), "windows-arm64 is missing"),
        (lambda d: d["tools"]["trivy"].update(kind="docker"), "trivy.kind"),
        (lambda d: d["tools"]["trivy"].update(executable="bin/trivy"), "trivy.executable"),
        (lambda d: d["tools"]["trivy"].update(sha256_source="trust-me"), "sha256_source"),
        (lambda d: d["tools"]["checkov"].update(requirement="checkov>=3.3.22"), "requirement"),
        (lambda d: d["tools"]["checkov"].update(requirement="checkov==3.3.21"), "requirement"),
        (lambda d: d["tools"]["bandit"].update(requirement="other[sarif]==1.9.4"), "requirement"),
        (
            lambda d: d["tools"]["govulncheck"].update(module="golang.org/x/vuln@v1.7.0"),
            "govulncheck.module",
        ),
        (lambda d: d["tools"]["govulncheck"].update(requires_go=False), "requires_go"),
        (lambda d: d["tools"]["poutine"].update(build_flags=["-toolexec=evil"]), "build_flags"),
        (
            lambda d: d["tools"]["poutine"].update(build_flags=["-ldflags=-extld=/tmp/evil"]),
            "build_flags",
        ),
        (
            lambda d: d["tools"]["poutine"].update(build_flags=["-ldflags=-X a=b -linkmode x"]),
            "build_flags",
        ),
        (lambda d: d["tools"]["poutine"].update(build_flags="-trimpath"), "build_flags"),
        (lambda d: d["tools"]["trivy"].update(build_flags=["-trimpath"]), "build_flags"),
        (lambda d: d["tools"]["trivy"].update(min_go_version="1.26"), "min_go_version"),
        (lambda d: d["tools"]["gosec"].update(min_go_version="go1.25"), "min_go_version"),
        (lambda d: d["tools"]["go"].update(requires_go=True), "go.requires_go"),
        (lambda d: d["tools"]["go"]["platforms"]["linux-amd64"].pop("root"), "linux-amd64.root"),
        (
            lambda d: d["tools"]["go"]["platforms"]["linux-amd64"].update(root="go/sub"),
            "linux-amd64.root",
        ),
        (
            lambda d: d["tools"]["go"]["platforms"]["linux-amd64"].update(binary="bin/go"),
            "linux-amd64.binary",
        ),
        (
            lambda d: d["tools"]["go"]["platforms"]["linux-amd64"].update(tree_sha256="x"),
            "linux-amd64.tree_sha256",
        ),
        (
            lambda d: d["tools"]["go"]["platforms"]["linux-amd64"].update(files=0),
            "linux-amd64.files",
        ),
        (
            lambda d: d["tools"]["go"]["platforms"]["linux-amd64"].update(
                archive="none", binary="go"
            ),
            "linux-amd64.archive",
        ),
        (lambda d: d["tools"]["trivy"].update(released_at="2026/10/01"), "trivy.released_at"),
        (lambda d: d["tools"]["trivy"].update(pinned_at="2026-02-30"), "trivy.pinned_at"),
        (
            lambda d: d["tools"]["trivy"].update(released_at="2026-10-16"),
            "pinned_at: must not be before released_at",
        ),
        (lambda d: d["tools"]["trivy"].update(version_env={"lower": "1"}), "version_env"),
        (lambda d: d["tools"]["trivy"].update(version_env={"X_ON": 1}), "version_env"),
        (lambda d: d["tools"]["trivy"].update(version_env=["X=1"]), "version_env"),
        (
            lambda d: d["tools"]["govulncheck"].update(version_args=["-db", "{home}"]),
            "unknown placeholder {home}",
        ),
        (lambda d: d.update(schema_version=2), "schema_version"),
        (lambda d: d.update(tools={}), "tools"),
    ],
)
def test_validation_rejects_broken_entries(raw_manifest, mutate, expected):
    errors = _broken(raw_manifest, mutate)
    assert any(expected in error for error in errors), errors


def test_parse_manifest_raises_validation_error_with_all_messages(raw_manifest):
    data = copy.deepcopy(raw_manifest)
    data["tools"]["trivy"]["version"] = "0.69.5"
    data["tools"]["gitleaks"]["platforms"]["linux-amd64"]["sha256"] = "0" * 63
    with pytest.raises(ValidationError) as exc:
        parse_manifest(data)
    assert len(exc.value.errors) >= 2


def test_load_manifest_reports_invalid_json(tmp_path):
    path = tmp_path / "manifest.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValidationError):
        load_manifest(path)


@pytest.mark.parametrize(
    ("name", "safe"),
    [
        ("trivy", True),
        ("faketool-1.2.3/faketool", True),
        ("../evil", False),
        ("a/../../evil", False),
        ("/etc/passwd", False),
        ("C:/Windows/evil.exe", False),
        ("dir\\evil", False),
        ("", False),
        ("./trivy", False),
    ],
)
def test_safe_member_names(name, safe):
    assert is_safe_member_name(name) is safe


# --- platform keys ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("system", "machine", "expected"),
    [
        ("Windows", "AMD64", "windows-amd64"),
        ("Windows", "ARM64", "windows-arm64"),
        ("Linux", "x86_64", "linux-amd64"),
        ("Linux", "aarch64", "linux-arm64"),
        ("Darwin", "x86_64", "darwin-amd64"),
        ("Darwin", "arm64", "darwin-arm64"),
    ],
)
def test_platform_key_normalization(system, machine, expected):
    assert platform_key(system, machine) == expected


@pytest.mark.parametrize(("system", "machine"), [("SunOS", "x86_64"), ("Linux", "i686")])
def test_unsupported_platforms_raise_tool_error(system, machine):
    with pytest.raises(ToolError):
        platform_key(system, machine)


def test_exe_suffix_and_arch_aliases():
    assert exe_suffix("windows-amd64") == ".exe"
    assert exe_suffix("linux-arm64") == ""
    assert normalize_arch(" X86_64 ") == "amd64"
