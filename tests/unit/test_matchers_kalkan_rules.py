# SPDX-License-Identifier: MIT
"""The kalkan matcher rules of ADR-0005 K.4 and K.12: the native specs (``source: null`` in
rules/matchers) and the extended deepsec port ``dockerfile-from-mutable-tag``.

Part one runs each rule on small files. Part two runs these rules on a copy of the vulnapp
fixture and compares the results with EXPECTED.json: every planted item that expects
``matcher`` with one of these rules is found, no rule touches a secure twin, and every result
belongs to a planted vulnerable item.
"""

from __future__ import annotations

import json
import shutil
from functools import cache
from pathlib import Path

import pytest

from kalkan.findings.taxonomy import DEPENDENCY_CLASSES
from kalkan.findings.validate import validate_candidate
from kalkan.matchers.engine import run
from kalkan.matchers.spec import MatcherSpec, load_specs
from kalkan.run import tech

ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / "rules" / "matchers"
FIXTURE = ROOT / "tests" / "fixtures" / "vulnapp"
ANSWER_FILES = frozenset({"README.md", "EXPECTED.json", "INJECTION-NOTE.md"})
WINDOW = 2


#: The deepsec port that K.12 extends (Containerfile names, build stages).
FROM_RULE = "dockerfile-from-mutable-tag"


@cache
def native() -> dict[str, MatcherSpec]:
    """The rules of this file: the native specs plus :data:`FROM_RULE`."""
    return {
        spec.slug: spec
        for spec in load_specs(RULES)
        if spec.source is None or spec.slug == FROM_RULE
    }


def scan(root: Path, slug: str, files: dict[str, str | bytes], tags=()) -> list[dict]:
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8", newline="\n")
    candidates = run(root, tags, [native()[slug]]).candidates
    for candidate in candidates:
        assert validate_candidate(candidate) == [], candidate
    return candidates


def hits(candidates: list[dict]) -> dict[str, str]:
    """Return ``{file: message}``."""
    return {c["file"]: c["message"] for c in candidates}


# --- K.4: Namespace without an enforced Pod Security level ---------------------------------------

NS = "k8s-namespace-no-pod-security"


def test_namespace_without_or_with_a_privileged_enforce_label(tmp_path):
    found = hits(
        scan(
            tmp_path,
            NS,
            {
                "bare.yaml": "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: shop\n",
                "privileged.yml": (
                    "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: jobs\n  labels:\n"
                    '    "pod-security.kubernetes.io/enforce": "privileged"\n'
                ),
                "only-warn.yaml": (
                    "kind: Namespace\nmetadata:\n  name: x\n  labels:\n"
                    "    pod-security.kubernetes.io/warn: restricted\n"
                    "    pod-security.kubernetes.io/enforce-version: latest\n"
                ),
                "multi.yaml": (
                    "kind: Namespace\nmetadata:\n  name: a\n  labels:\n"
                    "    pod-security.kubernetes.io/enforce: baseline\n"
                    "---\nkind: Namespace\nmetadata:\n  name: b\n"
                ),
            },
            ["kubernetes"],
        )
    )
    assert found == {
        "bare.yaml": "Matched: Namespace without a pod-security.kubernetes.io/enforce label. "
        "Line: 2.",
        "privileged.yml": "Matched: Namespace enforces the privileged Pod Security level. Line: 6.",
        "only-warn.yaml": "Matched: Namespace without a pod-security.kubernetes.io/enforce label. "
        "Line: 1.",
        "multi.yaml": "Matched: Namespace without a pod-security.kubernetes.io/enforce label. "
        "Line: 7.",
    }


def test_namespace_rule_leaves_safe_and_out_of_scope_manifests_alone(tmp_path):
    found = scan(
        tmp_path,
        NS,
        {
            "restricted.yaml": (
                "kind: Namespace\nmetadata:\n  name: a\n  labels:\n"
                "    pod-security.kubernetes.io/enforce: restricted\n"
            ),
            "flow.yaml": (
                "kind: Namespace\nmetadata: {name: b, labels: "
                "{pod-security.kubernetes.io/enforce: baseline}}\n"
            ),
            "system.yaml": "kind: Namespace\nmetadata:\n  name: kube-system\n",
            "helm/templates/ns.yaml": (
                "kind: Namespace\nmetadata:\n  name: {{ .Release.Namespace }}\n"
            ),
            "deploy.yaml": "kind: Deployment\nmetadata:\n  namespace: shop\n",
            "list.yaml": "kind: List\nitems:\n  - kind: Namespace\n    metadata:\n      name: c\n",
        },
        ["kubernetes"],
    )
    assert found == []
    # The rule needs the kubernetes tech tag.
    assert scan(tmp_path, NS, {"bare.yaml": "kind: Namespace\n"}) == []


# --- K.12: Dockerfile FROM without a digest ----------------------------------------------------


def test_from_rule_covers_containerfiles_and_skips_build_stages(tmp_path):
    pinned = "@sha256:" + "a" * 64
    found = hits(
        scan(
            tmp_path,
            FROM_RULE,
            {
                "Containerfile": "FROM registry.example/app/base:1.2\n",
                "svc/dockerfile": "FROM alpine\n",
                "multi/Dockerfile": (
                    f"FROM golang:1.22{pinned} AS build\nRUN go build\n"
                    f"FROM build AS test\nFROM gcr.io/distroless/static{pinned}\n"
                    "FROM node\n"
                ),
                "pinned/Dockerfile": (
                    f"FROM python:3.12{pinned}\nFROM scratch\nARG BASE\nFROM $BASE\n"
                ),
            },
            ["docker"],
        )
    )
    assert found == {
        "Containerfile": "Matched: FROM without @sha256 digest. Line: 1.",
        "svc/dockerfile": "Matched: FROM without @sha256 digest. Line: 1.",
    }


# --- K.12: lockfile sources and integrity ------------------------------------------------------

PACKAGE_LOCK = """{
  "packages": {
    "node_modules/a": {
      "version": "1.0.0",
      "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz",
      "integrity": "sha512-AAAA"
    },
    "node_modules/b": {
      "version": "1.0.0",
      "resolved": "http://registry.npmjs.org/b/-/b-1.0.0.tgz",
      "integrity": "sha512-BBBB"
    },
    "node_modules/c": {
      "version": "1.0.0",
      "resolved": "https://npm.mirror.example/c/-/c-1.0.0.tgz",
      "integrity": "sha512-CCCC"
    },
    "node_modules/d": {
      "version": "1.0.0",
      "resolved": "https://registry.npmjs.org/d/-/d-1.0.0.tgz"
    },
    "node_modules/e": {
      "version": "1.0.0",
      "resolved": "git+ssh://git@github.com/example/e.git#0123456789abcdef"
    },
    "node_modules/f": {
      "resolved": "file:../f",
      "link": true
    }
  }
}
"""
YARN_LOCK = """# yarn lockfile v1

a@^1.0.0:
  version "1.0.0"
  resolved "https://registry.yarnpkg.com/a/-/a-1.0.0.tgz#abc"
  integrity sha512-AAAA

b@^1.0.0:
  version "1.0.0"
  resolved "http://registry.yarnpkg.com/b/-/b-1.0.0.tgz#abc"
  integrity sha512-BBBB

c@^1.0.0:
  version "1.0.0"
  resolved "https://registry.yarnpkg.com/c/-/c-1.0.0.tgz#abc"
"""
PNPM_LOCK = """lockfileVersion: '9.0'
packages:
  a@1.0.0:
    resolution: {integrity: sha512-AAAA}
  b@1.0.0:
    resolution: {integrity: sha512-BBBB, tarball: http://npm.example.internal/b/-/b-1.0.0.tgz}
  c@1.0.0:
    resolution: {tarball: https://npm.mirror.example/c/-/c-1.0.0.tgz}
  d@1.0.0:
    resolution: {commit: 0123456789abcdef, repo: https://github.com/example/d.git, type: git}
  e@file:../e:
    resolution: {directory: ../e, type: directory}
"""


@pytest.mark.parametrize(
    ("slug", "expected"),
    [
        (
            "lockfile-insecure-url",
            {
                "package-lock.json": "npm resolved URL over http. Line: 10.",
                "yarn.lock": "yarn resolved URL over http. Line: 10.",
                "pnpm-lock.yaml": "pnpm tarball URL over http. Line: 6.",
            },
        ),
        (
            "lockfile-missing-integrity",
            {
                "package-lock.json": "npm entry without integrity. Line: 20.",
                "yarn.lock": "yarn entry without integrity. Line: 15.",
                "pnpm-lock.yaml": "pnpm resolution without integrity. Line: 8.",
            },
        ),
        (
            "lockfile-unexpected-registry",
            {
                "package-lock.json": "npm registry host other than registry.npmjs.org; "
                "npm git dependency. Lines: 15, 24.",
                "pnpm-lock.yaml": "pnpm tarball from a host other than registry.npmjs.org; "
                "pnpm git dependency. Lines: 8, 10.",
            },
        ),
    ],
)
def test_lockfile_rules(tmp_path, slug, expected):
    found = hits(
        scan(
            tmp_path,
            slug,
            {
                "package-lock.json": PACKAGE_LOCK,
                "yarn.lock": YARN_LOCK,
                "pnpm-lock.yaml": PNPM_LOCK,
                "node_modules/x/package-lock.json": PACKAGE_LOCK,
            },
        )
    )
    assert found == {file: f"Matched: {text}" for file, text in expected.items()}


def test_clean_lockfiles_give_nothing(tmp_path):
    clean = {
        "package-lock.json": (
            '{"packages": {"node_modules/a": {\n  "version": "1.0.0",\n'
            '  "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz",\n'
            '  "integrity": "sha512-AAAA"\n}}}\n'
        ),
        "yarn.lock": (
            'a@^1.0.0:\n  version "1.0.0"\n'
            '  resolved "https://registry.yarnpkg.com/a/-/a-1.0.0.tgz#abc"\n'
            "  integrity sha512-AAAA\n"
        ),
        "pnpm-lock.yaml": "packages:\n  a@1.0.0:\n    resolution: {integrity: sha512-AAAA}\n",
    }
    for slug in (
        "lockfile-insecure-url",
        "lockfile-missing-integrity",
        "lockfile-unexpected-registry",
    ):
        assert scan(tmp_path / slug, slug, clean) == [], slug


# --- K.12: pip index over http -----------------------------------------------------------------


def test_pip_index_over_http(tmp_path):
    found = hits(
        scan(
            tmp_path,
            "pip-index-insecure",
            {
                "requirements.txt": "--index-url https://pypi.org/simple/\nflask==3.0.0\n",
                "requirements-dev.txt": "-i http://10.0.0.5/simple\npytest\n",
                "requirements/prod.txt": "--extra-index-url=http://mirror.example.internal/simple\n",
                "constraints.txt": "--find-links http://files.example.internal/wheels\n",
                "docs/notes.txt": "--index-url http://not.a.requirements.file/\n",
                "requirements-ok.txt": "# --extra-index-url http://commented.out/simple\n",
            },
        )
    )
    assert found == {
        "requirements-dev.txt": "Matched: package index over http. Line: 1.",
        "requirements/prod.txt": "Matched: package index over http. Line: 1.",
        "constraints.txt": "Matched: package index over http. Line: 1.",
    }


# --- K.12: committed executables ---------------------------------------------------------------

ELF = bytes.fromhex("7f454c46020101000000000000000000") + b"\x00" * 48
PE = b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 56
MACHO = bytes.fromhex("cffaedfe0c000001") + b"\x00" * 24


def test_committed_binaries(tmp_path):
    found = scan(
        tmp_path,
        "committed-binary",
        {
            "tools/helper": ELF,
            "bin/setup.EXE": PE,
            "bin/mac-tool": MACHO,
            "lib/libcrypto.so.3": b"stub",
            "app/libs/sdk.jar": b"PK\x03\x04",
            "scripts/run.sh": "#!/bin/sh\necho MZ\n",
            "notes/MZ.txt": "MZ is the start of this text file\n",
            "vendor/acme/tool.exe": PE,
            "third_party/x/libx.so": ELF,
            "tests/data/golden.elf": ELF,
            "gradle/wrapper/gradle-wrapper.jar": b"PK\x03\x04",
            "src/Main.java": "class Main {}\n",
        },
    )
    by_file = {c["file"]: c for c in found}
    assert sorted(by_file) == [
        "app/libs/sdk.jar",
        "bin/mac-tool",
        "bin/setup.EXE",
        "lib/libcrypto.so.3",
        "tools/helper",
    ]
    assert by_file["tools/helper"]["message"] == (
        "Matched: ELF executable or library. File-level result: helper."
    )
    assert by_file["bin/setup.EXE"]["message"] == (
        "Matched: Windows executable, library or driver; Windows PE executable or DLL (MZ "
        "header). File-level result: setup.EXE."
    )
    assert by_file["lib/libcrypto.so.3"]["snippet"] == "file name: libcrypto.so.3"
    assert {c["start_line"] for c in found} == {None}
    assert {(c["class"], c["severity"]) for c in found} == {("supply-chain-cicd", "medium")}


# --- part two: the vulnapp fixture -------------------------------------------------------------


def _skip_answer_files(folder: str, names: list[str]) -> set[str]:
    if Path(folder).resolve() == FIXTURE:
        return {name for name in names if name in ANSWER_FILES}
    return set()


@pytest.fixture(scope="module")
def vulnapp(tmp_path_factory) -> list[dict]:
    target = tmp_path_factory.mktemp("vulnapp") / "target"
    shutil.copytree(FIXTURE, target, ignore=_skip_answer_files)
    return run(target, tech.detect(target), list(native().values())).candidates


def _items() -> list[dict]:
    return json.loads((FIXTURE / "EXPECTED.json").read_text(encoding="utf-8"))


def _touches(candidate: dict, item: dict) -> bool:
    if candidate["file"] != item["file"]:
        return False
    if candidate["start_line"] is None:  # a file-level result
        return True
    return abs(candidate["start_line"] - item["line"]) <= WINDOW


def test_every_planted_native_item_is_found(vulnapp):
    expected = [
        item
        for item in _items()
        if item["kind"] == "vulnerable"
        and any(rule in native() for rule in item.get("rules", {}).get("matcher", []))
    ]
    assert expected, "no vulnapp item expects a kalkan-native matcher rule"
    missing = [
        item["id"]
        for item in expected
        if not any(
            _touches(c, item)
            and c["rule_id"] in item["rules"]["matcher"]
            and c["class"] == item["class"]
            for c in vulnapp
        )
    ]
    assert missing == []
    # Every native rule has at least one planted item.
    planted = {rule for item in expected for rule in item["rules"]["matcher"]}
    assert planted == set(native())


def test_no_native_rule_touches_a_secure_twin(vulnapp):
    # Dependency twins match by package, not by line (vulnapp README, "Match rules").
    twins = [
        item
        for item in _items()
        if item["kind"] == "secure-twin" and item["class"] not in DEPENDENCY_CLASSES
    ]
    touched = [(c["rule_id"], t["id"]) for t in twins for c in vulnapp if _touches(c, t)]
    assert touched == []


def test_every_native_result_belongs_to_a_planted_item(vulnapp):
    vulnerable = [item for item in _items() if item["kind"] == "vulnerable"]
    stray = [
        f"{c['file']}:{c['start_line']} {c['rule_id']}"
        for c in vulnapp
        if not any(_touches(c, item) for item in vulnerable)
    ]
    assert stray == []
