# SPDX-License-Identifier: MIT
"""Tests for the vacuum adapter (kalkan.scanners.adapters.vacuum) and the OpenAPI reference
check (kalkan.scanners.adapters._openapi): document detection, the references that vacuum must
not follow, the command line, and the SARIF conversion of a recorded vacuum 0.33.0 report."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest

from kalkan.findings import taxonomy
from kalkan.sarif.ingest import ingest_document
from kalkan.scanners.adapters import _openapi
from kalkan.scanners.adapters._openapi import (
    check_references,
    classify_reference,
    is_openapi,
    openapi_files,
    reference_values,
)
from kalkan.scanners.adapters.vacuum import (
    RULES,
    RULESET,
    VacuumAdapter,
    report_to_sarif,
    rule_info,
)
from kalkan.scanners.base import ProcessOutcome, ScanContext, run_adapter
from kalkan.tools.resolve import ResolvedTool

OUTPUTS = Path(__file__).resolve().parents[1] / "fixtures" / "scanner-outputs"
FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "vulnapp"
SPEC = "openapi: 3.0.3\ninfo:\n  title: x\n  version: '1'\npaths: {}\n"


def make_ctx(tmp_path: Path, *, honor: bool = False) -> ScanContext:
    run = (tmp_path / "run").resolve()
    target = run / "target"
    target.mkdir(parents=True, exist_ok=True)
    return ScanContext(
        run_dir=run, target_dir=target, source_dir=None, tech=frozenset(), honor_suppressions=honor
    )


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")
    return path


def resolver(name, *, allow_path=False):
    return ResolvedTool(name, Path("/opt") / name, "0.33.0", "kalkan")


# --------------------------------------------------------------------------------------------
# detection


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (SPEC, True),
        ("swagger: '2.0'\ninfo: {}\n", True),
        ('swagger: "2.0"\n', True),
        ('"openapi": "3.1.0"\n', True),
        ('{"openapi":"3.0.1","info":{}}', True),
        ('{\n  "swagger": "2.0"\n}\n', True),
        ("openapi: 2.0\n", False),
        ("info:\n  openapi: 3.0.0\n", False),  # not a top-level key
        ('{"name": "pkg", "version": "3.0.0"}', False),
        ("apiVersion: v1\nkind: Pod\n", False),
    ],
)
def test_is_openapi(text, expected):
    assert is_openapi(text) is expected


def test_openapi_files_by_content_without_vendored_folders(tmp_path):
    write(tmp_path / "api" / "spec.yaml", SPEC)
    write(tmp_path / "api" / "spec.JSON", '{"openapi": "3.0.0"}')
    write(tmp_path / "api" / "other.yaml", "a: 1\n")
    write(tmp_path / "api" / "spec.txt", SPEC)
    write(tmp_path / "vendor" / "lib" / "spec.yaml", SPEC)
    assert openapi_files(tmp_path) == ["api/spec.JSON", "api/spec.yaml"]


def test_decode_text():
    assert _openapi.decode_text(b"\xef\xbb\xbfa: 1") == "a: 1"
    assert _openapi.decode_text("a: ü".encode("utf-16")) == "a: ü"
    assert _openapi.decode_text(b"\xff\x00\x01") is None


# --------------------------------------------------------------------------------------------
# references


@pytest.mark.parametrize(
    ("value", "kind"),
    [
        ("#/components/schemas/A", "internal"),
        ("schemas.yaml#/A", "local"),
        ("./schemas/a.yaml", "local"),
        ("../shared/a.yaml", "local"),  # from api/spec.yaml: shared/a.yaml, inside
        ("https://example.com/a.yaml#/A", "remote"),
        ("http://example.com/a.yaml", "remote"),
        ("../../outside.yaml", "unsafe"),
        ("/etc/passwd", "unsafe"),
        ("C:/Windows/win.ini", "unsafe"),
        ("c:win.ini", "unsafe"),
        ("//attacker.example/share/a.yaml", "unsafe"),
        ("\\\\attacker.example\\share\\a.yaml", "unsafe"),
        ("..\\..\\outside.yaml", "unsafe"),
        ("%2e%2e/%2e%2e/outside.yaml", "unsafe"),
        ("file:///etc/passwd", "unsafe"),
        ("urn:example:schema", "unsafe"),
        ("~/secrets.yaml", "unsafe"),
        ("schemas./a.yaml", "unsafe"),
        ("schemas /a.yaml", "unsafe"),
        ("NUL", "unsafe"),
        ("com1.yaml", "unsafe"),
        ("a.yaml:stream", "unsafe"),
        ("a\x01.yaml", "unsafe"),
    ],
)
def test_classify_reference(value, kind):
    assert classify_reference(value, "api/spec.yaml")[0] == kind


def test_classify_reference_resolves_relative_to_the_referencing_file():
    assert classify_reference("../shared/a.yaml#/X", "api/v1/spec.yaml") == (
        "local",
        "api/shared/a.yaml",
    )


def _values(text: str) -> list[tuple[str, str | None]]:
    return [(item.key, item.value) for item in reference_values(text)]


def test_reference_values_reads_the_plain_forms():
    text = (
        "a:\n  $ref: './x.yaml#/A'\n"
        'b: {"$ref": "y.json"}\n'
        "c:\n  $ref: z.yaml # comment\n"
        'd:\n  - $ref: "w.yaml"\n'
        "e:\n  $id: https://example.com/s/\n"
    )
    values = _values(text)
    assert ("$ref", "./x.yaml#/A") in values
    assert ("$ref", "y.json") in values
    assert ("$ref", "z.yaml") in values
    assert ("$ref", "w.yaml") in values
    assert ("$id", "https://example.com/s/") in values


@pytest.mark.parametrize(
    "text",
    [
        '"\\x24ref": "../../outside.yaml"\n',  # an escaped key
        '"$\\u0072ef": "../../outside.yaml"\n',
        '"$re\\\n  f": "../../outside.yaml"\n',  # an escaped line break inside the key
        '$ref: "\\x2e\\x2e/\\x2e\\x2e/outside.yaml"\n',  # an escaped value
        '{"$ref": "..\\/..\\/outside.yaml"}\n',
    ],
)
def test_escapes_cannot_hide_a_reference(tmp_path, text):
    write(tmp_path / "api" / "spec.yaml", SPEC + "x:\n  " + text)
    check = check_references(tmp_path, "api/spec.yaml")
    assert not check.ok and "outside the target" in check.problem


@pytest.mark.parametrize(
    ("text", "reason"),
    [
        ("x:\n  $ref: *anchor\n", "alias"),
        ("x:\n  $ref: >-\n    ../../outside.yaml\n", "block scalar"),
        ("x:\n  $ref:\n    ../../outside.yaml\n", "later line"),
        ("x:\n  ? $ref\n  : ../../outside.yaml\n", "explicit key"),
        ("x:\n  &a $ref: ok.yaml\n", "alias, anchor or tag"),
        ("x:\n  !!str $ref: ok.yaml\n", "alias, anchor or tag"),
        ("x:\n  $ref: ../..\n    /outside.yaml\n", "continues"),
        ('x:\n  $ref: "../..\n    /outside.yaml"\n', "next line"),
        ("x:\n  $ref: [a.yaml]\n", "flow collection"),
    ],
)
def test_unreadable_reference_values_refuse_the_document(tmp_path, text, reason):
    write(tmp_path / "api" / "spec.yaml", SPEC + text)
    check = check_references(tmp_path, "api/spec.yaml")
    assert not check.ok and reason in check.problem


def test_reference_words_in_text_are_no_keys(tmp_path):
    text = (
        "info:\n  description: |\n    Use a $ref to share schemas; `$ref`: siblings are ignored.\n"
        "    See $references and the $id keyword.\n"
    )
    write(tmp_path / "spec.yaml", SPEC + text)
    assert check_references(tmp_path, "spec.yaml").ok


def test_check_references_follows_local_files(tmp_path):
    write(tmp_path / "api" / "spec.yaml", SPEC + "c:\n  $ref: ./schemas/a.yaml\n")
    write(tmp_path / "api" / "schemas" / "a.yaml", "A:\n  $ref: '../common/b.yaml#/B'\n")
    write(tmp_path / "api" / "common" / "b.yaml", "B:\n  $ref: https://example.com/c.yaml\n")
    check = check_references(tmp_path, "api/spec.yaml")
    assert check.ok, check.problem
    assert check.files == ["api/spec.yaml", "api/schemas/a.yaml", "api/common/b.yaml"]
    assert check.remote == ["https://example.com/c.yaml"]


def test_check_references_refuses_an_escape_in_a_referenced_file(tmp_path):
    write(tmp_path / "api" / "spec.yaml", SPEC + "c:\n  $ref: ./a.yaml\n")
    write(tmp_path / "api" / "a.yaml", "A:\n  $ref: ../../../home/user/.kube/config\n")
    check = check_references(tmp_path, "api/spec.yaml")
    assert not check.ok
    assert check.where == "api/a.yaml" and "outside the target" in check.problem


@pytest.mark.parametrize(
    ("value", "ok"),
    [("'#node'", True), ("https://example.com/s/x.json", True), ("schemas/", False)],
)
def test_check_references_limits_id_values(tmp_path, value, ok):
    write(tmp_path / "spec.yaml", SPEC + f"s:\n  $id: {value}\n")
    assert check_references(tmp_path, "spec.yaml").ok is ok


def test_check_references_refuses_a_link(tmp_path):
    write(tmp_path / "real" / "a.yaml", "A: {}\n")
    try:
        os.symlink(tmp_path / "real", tmp_path / "api_link", target_is_directory=True)
    except OSError:
        pytest.skip("symbolic links are not available")
    write(tmp_path / "spec.yaml", SPEC + "c:\n  $ref: api_link/a.yaml\n")
    check = check_references(tmp_path, "spec.yaml")
    assert not check.ok and "link" in check.problem


def test_check_references_limits_the_number_of_files(tmp_path, monkeypatch):
    monkeypatch.setattr(_openapi, "MAX_REFERENCED_FILES", 2)
    refs = "".join(f"  r{n}:\n    $ref: f{n}.yaml\n" for n in range(3))
    write(tmp_path / "spec.yaml", SPEC + "c:\n" + refs)
    check = check_references(tmp_path, "spec.yaml")
    assert not check.ok and "too many" in check.problem


# --------------------------------------------------------------------------------------------
# adapter


def test_applies_and_refused_documents(tmp_path):
    ctx = make_ctx(tmp_path)
    adapter = VacuumAdapter()
    assert adapter.applies(ctx) == (False, "no OpenAPI or Swagger document in the target")
    write(ctx.target_dir / "bad.yaml", SPEC + "c:\n  $ref: /etc/passwd\n")
    ok, reason = adapter.applies(ctx)
    assert not ok and "1 refused" in reason and "bad.yaml" in reason
    write(ctx.target_dir / "good.yaml", SPEC)
    assert adapter.applies(ctx) == (True, "")


def test_command_line_ruleset_config_and_env(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx.target_dir / "api" / "a.yaml", SPEC)
    write(ctx.target_dir / "api" / "b.yaml", SPEC)
    adapter = VacuumAdapter()
    adapter.applies(ctx)
    work = ctx.run_dir / "scans" / ".work" / "vacuum"
    out = work / "vacuum.sarif"
    adapter.prepare(ctx, out)
    assert (work / "kalkan-owasp.yaml").read_text(encoding="utf-8") == RULESET
    assert (work / "vacuum.conf.yaml").read_text(encoding="utf-8") == ""
    items = adapter.invocations(ctx, Path("/opt/vacuum"), out)
    assert [item.label for item in items] == ["spec api/a.yaml", "spec api/b.yaml"]
    first = items[0]
    assert first.cwd == work and first.output == work / "vacuum.sarif.parts" / "000.sarif"
    assert list(first.argv) == [
        str(Path("/opt/vacuum")),
        "spectral-report",
        "--remote=false",
        "--no-update-check",
        "--no-style",
        "--no-pretty",
        "--config",
        str(work / "vacuum.conf.yaml"),
        "--ruleset",
        str(work / "kalkan-owasp.yaml"),
        str(ctx.target_dir / "api" / "a.yaml"),
        str(work / "vacuum.sarif.parts" / "000.json"),
    ]
    for word in ("--ignore-file", "--functions", "--base", "--ext-refs", "--fix", "--hard-mode"):
        assert word not in first.argv
    env = adapter.env(ctx)
    assert env == {"HOME": str(work / "home"), "USERPROFILE": str(work / "home")}


def test_ruleset_is_the_builtin_owasp_set_and_extends_nothing_remote():
    assert "[vacuum:owasp, all]" in RULESET and '[vacuum:oas, "off"]' in RULESET
    assert "http" not in RULESET and "functions" not in RULESET


def test_rule_table_uses_taxonomy_slugs_and_cwe_ids():
    for rule, severity, title in RULES.values():
        assert rule.vuln_class in taxonomy.SLUGS
        assert all(taxonomy.normalize_cwe(cwe) == cwe for cwe in rule.cwe)
        assert severity in ("high", "medium", "low", "info") and title
    assert rule_info("owasp-new-rule", 0)[0].vuln_class == "security-misconfig"
    assert rule_info("owasp-new-rule", 0)[1] == "medium"


def _recorded_report(spec: str) -> bytes:
    report = json.loads((OUTPUTS / "vacuum-spectral-report.json").read_text(encoding="utf-8"))
    for item in report:
        item["source"] = os.path.join("..", "..", "..", "target", *spec.split("/"))
    return json.dumps(report).encode()


def test_report_to_sarif_with_the_recorded_report(tmp_path):
    ctx = make_ctx(tmp_path)
    shutil.copy(FIXTURE / "api" / "shop-api.yaml", write(ctx.target_dir / "api" / "x", ""))
    shutil.move(ctx.target_dir / "api" / "x", ctx.target_dir / "api" / "shop-api.yaml")
    cwd = ctx.run_dir / "scans" / ".work" / "vacuum"
    cwd.mkdir(parents=True)
    report = json.loads(_recorded_report("api/shop-api.yaml"))
    doc, notes = report_to_sarif(report, target=ctx.target_dir, cwd=cwd, version="0.33.0")
    assert notes == {"unresolved": 0, "outside_target": 0}
    found = ingest_document(doc, "vacuum", ctx.target_dir, "scans/vacuum.sarif")
    assert found.warnings == []
    rows = {
        (c["rule_id"], c["class"], c["severity"], c["file"], c["start_line"], tuple(c["cwe"]))
        for c in found.candidates
    }
    assert rows == {
        (
            "owasp-security-hosts-https-oas3",
            "crypto",
            "medium",
            "api/shop-api.yaml",
            7,
            ("CWE-319",),
        ),
        ("owasp-protection-global-unsafe", "authn", "high", "api/shop-api.yaml", 10, ("CWE-306",)),
        (
            "owasp-protection-global-unsafe-strict",
            "authn",
            "high",
            "api/shop-api.yaml",
            10,
            ("CWE-306",),
        ),
        (
            "owasp-no-api-keys-in-url",
            "sensitive-data-exposure",
            "medium",
            "api/shop-api.yaml",
            61,
            ("CWE-598",),
        ),
        ("owasp-string-limit", "dos-redos", "low", "api/shop-api.yaml", 137, ("CWE-770",)),
        (
            "owasp-no-additionalProperties",
            "mass-assignment",
            "low",
            "api/shop-api.yaml",
            140,
            ("CWE-915",),
        ),
    }
    by_rule = {c["rule_id"]: c for c in found.candidates}
    assert by_rule["owasp-no-api-keys-in-url"]["snippet"] == "      in: query"


def test_report_to_sarif_notes_unresolved_and_outside_results(tmp_path):
    target = tmp_path / "target"
    write(target / "spec.yaml", SPEC)
    report = [
        {"code": "resolving-references", "message": "m", "severity": 0, "source": "spec.yaml"},
        {"code": "owasp-array-limit", "message": "m", "severity": 0, "source": "../out.yaml"},
        {"code": "owasp-array-limit", "message": "m", "severity": 0, "source": "spec.yaml"},
    ]
    doc, notes = report_to_sarif(report, target=target, cwd=target)
    assert notes == {"unresolved": 1, "outside_target": 1}
    [result] = doc["runs"][0]["results"]
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 1
    with pytest.raises(Exception, match="not a JSON array"):
        report_to_sarif({}, target=target, cwd=target)


def _runner(reports: dict[str, bytes | None]):
    """A fake vacuum: writes the report of each document, or none (exit code 2)."""

    def runner(argv, *, cwd, env, timeout, stdout, stderr):
        name = Path(argv[-2]).name
        data = reports.get(name)
        if data is None:
            stderr.write(f"Error: failed to parse specification '{argv[-2]}'\n".encode())
            return ProcessOutcome(2)
        Path(argv[-1]).write_bytes(data)
        return ProcessOutcome(0)

    return runner


def test_run_with_a_parse_error_and_partial_documents(tmp_path):
    ctx = make_ctx(tmp_path)
    shutil.copytree(FIXTURE / "api", ctx.target_dir / "api")
    write(ctx.target_dir / "api" / "broken.yaml", SPEC + "x: [\n")
    write(ctx.target_dir / "api" / "remote.yaml", SPEC + "c:\n  $ref: https://example.com/a.yaml\n")
    write(ctx.target_dir / "api" / "lint.yaml", SPEC + "x-lint-ignore: [owasp-string-limit]\n")
    write(ctx.target_dir / "evil" / "spec.yaml", SPEC + "c:\n  $ref: ../../../etc/passwd\n")
    unresolved = [{"code": "resolving-references", "message": "m", "severity": 0}]
    reports = {
        "shop-api.yaml": _recorded_report("api/shop-api.yaml"),
        "partner-api.yaml": b"[]",
        "remote.yaml": json.dumps(unresolved).encode(),
        "lint.yaml": b"[]",
        "broken.yaml": None,
    }
    result = run_adapter(VacuumAdapter(), ctx, runner=_runner(reports), resolver=resolver)
    assert result.status == "ok", result.message
    assert result.candidates == 6
    status = json.loads((ctx.run_dir / "scans" / "vacuum.status.json").read_text(encoding="utf-8"))
    assert status["documents"]["count"] == 5
    assert status["parse_errors"] == {"count": 1, "files": ["api/broken.yaml"]}
    skipped = status["skipped_files"]
    assert skipped["count"] == 2
    assert skipped["paths"] == ["evil/spec.yaml", "api/broken.yaml"]
    assert status["partial_files"]["paths"] == ["api/remote.yaml"]
    assert status["unresolved_references"]["api/remote.yaml"] == {
        "results": 1,
        "remote": ["https://example.com/a.yaml"],
    }
    assert status["inline_ignores"] == {"count": 1, "files": {"api/lint.yaml": 1}}
    assert status["suppressions"]["honored"] == [
        "x-lint-ignore keys in the OpenAPI documents (no option in vacuum 0.33.0)"
    ]


def test_run_fails_when_no_document_gives_a_report(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx.target_dir / "a.yaml", SPEC)
    write(ctx.target_dir / "b.yaml", SPEC)
    result = run_adapter(VacuumAdapter(), ctx, runner=_runner({}), resolver=resolver)
    assert result.status == "failed"
    assert "no report for any OpenAPI document" in result.message
