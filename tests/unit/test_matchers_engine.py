# SPDX-License-Identifier: MIT
"""Tests for kalkan.matchers.engine on small temporary trees."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from kalkan.errors import KalkanError
from kalkan.matchers import engine
from kalkan.matchers.engine import MAX_FILE_BYTES, list_files, read_lines, run
from kalkan.matchers.spec import MatcherSpec, parse_spec

CANDIDATE_KEYS = {
    "id",
    "engine",
    "rule_id",
    "class",
    "cwe",
    "title",
    "message",
    "file",
    "start_line",
    "end_line",
    "snippet",
    "severity",
    "tool_severity",
    "confidence",
    "tags",
    "fingerprints",
    "sca",
    "raw",
}


def make_spec(slug: str = "js-eval", **changes: Any) -> MatcherSpec:
    data: dict[str, Any] = {
        "version": 1,
        "slug": slug,
        "description": "eval and exec calls",
        "class": "code-injection",
        "cwe": ["CWE-94"],
        "noise_tier": "precise",
        "file_patterns": ["**/*.js"],
        "exclude_file_patterns": ["**/*.test.js"],
        "patterns": [
            {"regex": r"\beval\s*\(", "flags": "", "label": "eval"},
            {"regex": r"\bexec\s*\(", "flags": "", "label": "exec"},
        ],
        "examples": ["eval(x)", "exec(y)"],
        "source": None,
        "notes": "",
    }
    data.update(changes)
    return parse_spec(data)


def write(root: Path, rel: str, text: str | bytes) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(text, bytes):
        path.write_bytes(text)
    else:
        path.write_text(text, encoding="utf-8", newline="")
    return path


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    write(tmp_path, "src/app.js", "const a = 1;\nconst b = 2;\neval(input);\nok();\nexec(cmd);\n")
    write(tmp_path, "src/app.test.js", "eval(fixture);\n")
    write(tmp_path, "src/notes.txt", "eval(text);\n")
    for skipped in ("node_modules/x", ".git", ".venv/lib", "venv", "dist", "build"):
        write(tmp_path, f"{skipped}/bad.js", "eval(skipped);\n")
    return tmp_path


def test_candidate_shape(tree: Path) -> None:
    from kalkan.findings.fingerprint import candidate_id

    result = run(tree, [], [make_spec()])
    assert len(result.candidates) == 1
    candidate = result.candidates[0]
    assert set(candidate) == CANDIDATE_KEYS
    assert candidate["engine"] == "matcher"
    assert candidate["rule_id"] == "js-eval"
    assert candidate["class"] == "code-injection"
    assert candidate["cwe"] == ["CWE-94"]
    assert candidate["title"] == "eval and exec calls"
    assert candidate["file"] == "src/app.js"
    assert candidate["start_line"] == 3
    assert candidate["end_line"] == 3
    assert candidate["snippet"] == "const a = 1;\nconst b = 2;\neval(input);\nok();\nexec(cmd);"
    assert candidate["message"] == "Matched: eval; exec. Lines: 3, 5."
    assert candidate["severity"] == "medium"
    assert candidate["tool_severity"] == "precise"
    assert candidate["confidence"] == "medium"
    assert candidate["tags"] == ["noise:precise"]
    assert candidate["fingerprints"] == {}
    assert candidate["sca"] is None
    assert candidate["raw"] == {"sarif_file": "", "run_index": 0, "result_index": 0}
    assert candidate["id"] == candidate_id(
        "matcher", "js-eval", "src/app.js", 3, candidate["snippet"]
    )
    assert candidate["id"].startswith("CAND-")


def test_excludes_and_skipped_folders(tree: Path) -> None:
    files = list_files(tree)
    assert files == ["src/app.js", "src/app.test.js", "src/notes.txt"]
    result = run(tree, [], [make_spec()])
    assert [c["file"] for c in result.candidates] == ["src/app.js"]
    assert result.stats.files_total == 3
    assert result.stats.files_scanned == 1


def test_severity_and_confidence_by_tier(tree: Path) -> None:
    normal = run(tree, [], [make_spec(noise_tier="normal")]).candidates[0]
    assert (normal["severity"], normal["confidence"]) == ("low", "low")
    noisy = run(tree, [], [make_spec(noise_tier="noisy")]).candidates[0]
    assert (noisy["severity"], noisy["confidence"], noisy["tags"]) == (
        "info",
        "low",
        ["noise:noisy"],
    )
    surface = run(tree, [], [make_spec(**{"class": None, "cwe": []})]).candidates[0]
    assert surface["severity"] == "info"
    assert surface["class"] is None


def test_noisy_tier_can_be_skipped(tree: Path) -> None:
    result = run(tree, [], [make_spec(noise_tier="noisy")], include_noisy=False)
    assert result.candidates == []
    assert result.skipped == {"js-eval": "noisy"}
    assert result.stats.matchers_applied == 0


def test_tech_gate(tree: Path) -> None:
    gated = make_spec(requires={"tech": ["go", "node"]})
    assert run(tree, ["python"], [gated]).skipped == {"js-eval": "tech"}
    assert len(run(tree, ["NODE"], [gated]).candidates) == 1


def test_sentinel_gate(tree: Path) -> None:
    spec = make_spec(
        requires={"sentinel_files": ["**/package.json"], "sentinel_contains": ['"express"']}
    )
    assert run(tree, [], [spec]).skipped == {"js-eval": "sentinel"}
    write(tree, "package.json", '{"dependencies": {"koa": "2"}}\n')
    assert run(tree, [], [spec]).skipped == {"js-eval": "sentinel"}
    write(tree, "web/package.json", '{\n  "dependencies": {"express": "4"}\n}\n')
    assert len(run(tree, [], [spec]).candidates) == 1
    presence = make_spec(requires={"sentinel_files": ["**/package.json"]})
    assert len(run(tree, [], [presence]).candidates) == 1


def test_tech_and_sentinel_must_both_pass(tree: Path) -> None:
    write(tree, "go.mod", "module x\nrequire github.com/gin-gonic/gin v1\n")
    spec = make_spec(
        requires={
            "tech": ["go"],
            "sentinel_files": ["**/go.mod"],
            "sentinel_contains": [r"github\.com/gin-gonic/gin"],
        }
    )
    assert run(tree, ["node"], [spec]).skipped == {"js-eval": "tech"}
    assert len(run(tree, ["go"], [spec]).candidates) == 1


def test_file_contains_and_file_excludes(tree: Path) -> None:
    needs_import = make_spec(file_contains=[r"import\s+vm", r"\beval\b"])
    assert run(tree, [], [needs_import]).candidates == []
    write(tree, "src/app.js", "import vm from 'vm';\neval(x);\n")
    assert len(run(tree, [], [needs_import]).candidates) == 1
    guarded = make_spec(file_excludes=[r"(?i:sandboxed)"])
    write(tree, "src/app.js", "// SANDBOXED\neval(x);\n")
    assert run(tree, [], [guarded]).candidates == []


def test_near_not_near_and_paths(tree: Path) -> None:
    text = "\n".join(["query(sql)", "x", "y", "z", "db.run(sql)", "safe()", "db.run(sql2)"]) + "\n"
    write(tree, "src/db.js", text)
    near = make_spec(
        patterns=[
            {
                "regex": r"db\.run",
                "flags": "",
                "label": "run near query",
                "near": [{"regex": r"query\(", "before": 4}],
            }
        ],
        examples=["db.run(x)"],
    )
    candidate = run(tree, [], [near]).candidates[0]
    assert candidate["message"] == "Matched: run near query. Line: 5."

    not_near = make_spec(
        patterns=[
            {
                "regex": r"db\.run",
                "flags": "",
                "label": "run without safe",
                "not_near": [{"regex": r"safe\(", "after": 1}],
            }
        ],
        examples=["db.run(x)"],
    )
    assert run(tree, [], [not_near]).candidates[0]["message"].endswith("Line: 7.")

    whole_file = make_spec(
        patterns=[
            {
                "regex": r"db\.run",
                "flags": "",
                "label": "file has query",
                "near": [{"regex": r"^query", "scope": "file"}],
                "paths": ["src/db.*"],
            }
        ],
        examples=["db.run(x)"],
    )
    found = run(tree, [], [whole_file]).candidates
    assert [c["file"] for c in found] == ["src/db.js"]
    assert found[0]["message"].endswith("Lines: 5, 7.")


def test_binary_large_and_long_lines_are_skipped(tree: Path) -> None:
    write(tree, "src/blob.js", b"eval(x);\n\x00\x01\x02")
    write(tree, "src/huge.js", "eval(x);\n" + "a" * (MAX_FILE_BYTES + 1))
    write(tree, "src/long.js", "eval(" + "x" * 20_001 + ")\nok();\n")
    result = run(tree, [], [make_spec()])
    assert [c["file"] for c in result.candidates] == ["src/app.js"]
    assert result.stats.files_skipped_binary == 1
    assert result.stats.files_skipped_large == 1
    assert result.stats.lines_skipped_long == 1


def test_crlf_and_bom_are_normalized(tree: Path) -> None:
    write(tree, "src/win.js", "﻿eval(x);\r\nexec(y);\r\n")
    lines, status = read_lines(tree / "src/win.js")
    assert status == "ok"
    assert lines == ["eval(x);", "exec(y);", ""]
    anchored = make_spec(
        patterns=[{"regex": r"^eval\(x\);$", "flags": "", "label": "exact"}],
        examples=["eval(x);"],
    )
    files = [c["file"] for c in run(tree, [], [anchored]).candidates]
    assert "src/win.js" in files


def test_symlinks_are_not_followed(tree: Path, tmp_path_factory: pytest.TempPathFactory) -> None:
    outside = tmp_path_factory.mktemp("outside")
    write(outside, "secret.js", "eval(outside);\n")
    try:
        os.symlink(outside / "secret.js", tree / "src" / "link.js")
        os.symlink(outside, tree / "linked", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("creating symbolic links is not permitted here")
    assert "src/link.js" not in list_files(tree)
    assert not any(rel.startswith("linked/") for rel in list_files(tree))


def test_deterministic_order(tree: Path) -> None:
    write(tree, "a/first.js", "eval(1);\n")
    write(tree, "z/last.js", "exec(2);\n")
    specs = [make_spec("z-rule"), make_spec("a-rule")]
    first = run(tree, [], specs)
    second = run(tree, [], list(reversed(specs)))
    assert first.candidates == second.candidates
    keys = [(c["file"], c["start_line"], c["rule_id"]) for c in first.candidates]
    assert keys == sorted(keys)
    assert [c["raw"]["result_index"] for c in first.candidates] == list(range(len(keys)))
    assert keys[0] == ("a/first.js", 1, "a-rule")


def test_prefilter_gives_the_same_hits(tree: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    write(tree, "src/many.js", "\n".join(["eval(1)", "x", "exec(2)", "eval(3); exec(4)"]) + "\n")
    spec = make_spec()
    with_prefilter = run(tree, [], [spec]).candidates
    monkeypatch.setattr(engine, "_prefilter", lambda patterns: None)
    without_prefilter = run(tree, [], [spec]).candidates
    assert with_prefilter == without_prefilter


def test_time_budget_stops_a_slow_file(tree: Path) -> None:
    result = run(tree, [], [make_spec()], max_file_seconds=-1.0)
    assert result.candidates == []
    assert result.stats.files_timed_out == 1
    assert result.warnings and "src/app.js: matching stopped" in result.warnings[0]
    unbounded = run(tree, [], [make_spec()], max_file_seconds=None)
    assert len(unbounded.candidates) == 1


def test_missing_target_folder(tmp_path: Path) -> None:
    with pytest.raises(KalkanError):
        run(tmp_path / "missing", [], [])


def test_stats(tree: Path) -> None:
    result = run(tree, [], [make_spec(), make_spec("go-only", requires={"tech": ["go"]})])
    stats = result.stats.to_dict()
    assert stats["matchers_total"] == 2
    assert stats["matchers_applied"] == 1
    assert stats["candidates"] == 1
    assert stats["files_scanned"] == 1


# --- message cap, document scope, file matchers ------------------------------------------------


def test_the_message_lists_at_most_fifty_lines(tmp_path: Path) -> None:
    write(tmp_path, "a.js", "eval(1)\n" * 60)
    [candidate] = run(tmp_path, [], [make_spec()]).candidates
    assert candidate["message"].endswith(", 50 and 10 more.")
    assert candidate["start_line"] == 1


NAMESPACE = r"^kind\s*:\s*Namespace\s*$"
LABEL = r"pod-security\.kubernetes\.io/enforce\s*:"


def namespace_spec() -> MatcherSpec:
    return make_spec(
        "ns",
        file_patterns=["**/*.yaml"],
        exclude_file_patterns=[],
        patterns=[
            {
                "regex": NAMESPACE,
                "flags": "",
                "label": "no label",
                "not_near": [{"regex": LABEL, "scope": "document"}],
            }
        ],
        examples=["kind: Namespace"],
    )


def test_document_scope_stops_at_yaml_separators(tmp_path: Path) -> None:
    write(
        tmp_path,
        "ns.yaml",
        "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: a\n"
        "---\n"
        "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: b\n  labels:\n"
        "    pod-security.kubernetes.io/enforce: restricted\n"
        "...\n"
        "--- # c\nkind: Namespace\nmetadata:\n  name: c\n",
    )
    [candidate] = run(tmp_path, [], [namespace_spec()]).candidates
    # Document a (line 2) and document c (line 14) have no label; document b has one.
    assert candidate["start_line"] == 2
    assert candidate["message"] == "Matched: no label. Lines: 2, 14."


def test_document_scope_without_separators_is_the_whole_file(tmp_path: Path) -> None:
    write(tmp_path, "one.yaml", "kind: Namespace\nmetadata:\n  labels:\n    " + LABEL[:3])
    write(
        tmp_path,
        "two.yaml",
        "metadata:\n  labels:\n    pod-security.kubernetes.io/enforce: baseline\nkind: Namespace\n",
    )
    found = {c["file"] for c in run(tmp_path, [], [namespace_spec()]).candidates}
    assert found == {"one.yaml"}


ELF = bytes.fromhex("7f454c46020101000000000000000000") + b"\x02\x00\x3e\x00" + b"\x00" * 44


def binary_spec(**changes: Any) -> MatcherSpec:
    data: dict[str, Any] = {
        "file_patterns": ["**/*"],
        "exclude_file_patterns": ["**/testdata/**"],
        "file_signatures": [
            {"hex": "7f454c46", "label": "ELF executable"},
            {"hex": "4d5a", "label": "PE executable"},
        ],
        "name_patterns": [{"glob": "**/*.{exe,dll}", "label": "Windows executable"}],
        "patterns": [],
        "examples": ["bin/tool.exe", "hex:7f454c4602"],
        "class": "supply-chain-cicd",
        "cwe": ["CWE-829"],
    }
    data.update(changes)
    return make_spec("committed-binary", **data)


def test_file_matcher_reports_binaries_at_file_level(tmp_path: Path) -> None:
    write(tmp_path, "bin/labelprint", ELF)
    write(tmp_path, "bin/Tool.EXE", b"not really a PE")
    write(tmp_path, "docs/notes.txt", "MZ starts this text file, but it has no NUL byte\n")
    write(tmp_path, "testdata/golden.elf", ELF)
    write(tmp_path, "big.so.bin", ELF + b"\x00" * (MAX_FILE_BYTES + 1))
    write(tmp_path, "src/app.js", "eval(x)\n")
    result = run(tmp_path, [], [binary_spec(), make_spec()])
    by_file = {c["file"]: c for c in result.candidates}
    assert sorted(by_file) == ["big.so.bin", "bin/Tool.EXE", "bin/labelprint", "src/app.js"]
    elf = by_file["bin/labelprint"]
    assert set(elf) == CANDIDATE_KEYS
    assert (elf["start_line"], elf["end_line"]) == (None, None)
    assert elf["snippet"] == "file header: 7f 45 4c 46 02 01 01 00"
    assert elf["message"] == "Matched: ELF executable. File-level result: labelprint."
    assert elf["tags"] == ["noise:precise", "file-level"]
    assert elf["severity"] == "medium"
    assert by_file["bin/Tool.EXE"]["snippet"] == "file name: Tool.EXE"
    assert by_file["bin/Tool.EXE"]["message"].startswith("Matched: Windows executable.")
    # A file above the line limit is still sniffed; the line matcher still works.
    assert by_file["big.so.bin"]["rule_id"] == "committed-binary"
    assert by_file["src/app.js"]["start_line"] == 1
    assert [c["file"] for c in result.candidates] == sorted(by_file)


@pytest.mark.parametrize(
    ("changes", "fragment"),
    [
        (
            {"patterns": [{"regex": "x", "flags": "", "label": "x"}]},
            "empty list for a file matcher",
        ),
        ({"file_signatures": [{"hex": "7F45", "label": "x"}]}, "lower-case hex"),
        ({"file_signatures": [{"hex": "7f45", "label": "x", "at": 1}]}, "at: unknown key"),
        ({"name_patterns": [{"glob": "**/*.EXE", "label": "x"}]}, "must be lower case"),
        ({"examples": ["hex:1234"]}, "hex: bytes"),
        ({"file_excludes": ["x"]}, "no line gates"),
        # "**/*" is too broad for a name-only file matcher (it reads no bytes).
        ({"file_signatures": []}, "too broad"),
    ],
)
def test_file_matcher_validation(changes: dict[str, Any], fragment: str) -> None:
    from kalkan.errors import ValidationError

    with pytest.raises(ValidationError) as caught:
        binary_spec(**changes)
    assert any(fragment in error for error in caught.value.errors), caught.value.errors


def test_file_matcher_round_trip() -> None:
    from kalkan.errors import ValidationError

    with pytest.raises(ValidationError) as caught:  # too broad for a matcher that reads lines
        make_spec(file_patterns=["**/*"])
    assert any("too broad" in error for error in caught.value.errors)
    spec = binary_spec()
    assert spec.is_file_matcher and not make_spec().is_file_matcher
    assert parse_spec(spec.to_dict()) == spec
