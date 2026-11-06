# SPDX-License-Identifier: MIT
"""Tests for kalkan.sca.vendored: the walk, the child process with its time limits, the outputs
and the records of the vendored JavaScript check. No network: the repository is the small test
file of tests/fixtures/sca, and the child process is the real ``python -I`` of this interpreter.
"""

from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from kalkan.sca import retirejs, vendored
from kalkan.sca.manifests import Pin, pins_sbom
from kalkan.sca.retirejs import Detection

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
REPOSITORY = FIXTURES / "sca" / "retire" / "jsrepository-v5.json"
VULNAPP_LIB = FIXTURES / "vulnapp" / "csharp" / "wwwroot" / "lib"
V = retirejs.VERSION_PLACEHOLDER


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")
    return path


def scan(target: Path, repository: Path | None, work: Path, **options) -> vendored.VendoredScan:
    return vendored.scan(target, repository, work_dir=work / ".work" / "retirejs", **options)


# --- the walk ------------------------------------------------------------------------------------


def test_the_walk_keeps_vendor_folders_and_skips_node_modules(tmp_path, monkeypatch):
    target = tmp_path / "target"
    for name in (
        "wwwroot/lib/a.js",
        "vendor/b.MJS",
        "bower_components/c.cjs",
        "node_modules/x/index.js",
        "Node_Modules/y/index.js",
        ".git/hooks/d.js",
        "venv/e.js",
        "app/readme.md",
        "app/big.js",
    ):
        write(target / name, "x")
    (target / "app" / "big.js").write_bytes(b"x" * 64)
    monkeypatch.setattr(vendored, "MAX_FILE_BYTES", 32)
    files, skipped = vendored.list_files(target)
    assert files == ["bower_components/c.cjs", "vendor/b.MJS", "wwwroot/lib/a.js"]
    assert skipped == {vendored.REASON_LARGE: ["app/big.js"]}


def test_the_walk_never_follows_a_link(tmp_path):
    target = tmp_path / "target"
    write(target / "lib" / "real.js", "x")
    outside = write(tmp_path / "outside" / "secret.js", "x")
    try:
        os.symlink(outside, target / "lib" / "link.js")
        os.symlink(outside.parent, target / "linked-dir", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("this system does not allow symbolic links")
    files, skipped = vendored.list_files(target)
    assert files == ["lib/real.js"]
    assert skipped == {vendored.REASON_LINK: ["lib/link.js"]}


# --- the scan ------------------------------------------------------------------------------------


def test_positive_control_and_secure_twin(tmp_path):
    target = tmp_path / "target"
    shutil.copytree(VULNAPP_LIB, target / "wwwroot" / "lib")
    write(target / "wwwroot" / "js" / "site.js", "// the application code\n")
    result = scan(target, REPOSITORY, tmp_path)
    assert result.status == "ok", result.message
    assert result.files_total == 3 and result.files_checked == 3 and not result.skipped
    found = {(d.library, d.version, d.path, d.line, d.extractor) for d in result.detections}
    assert found == {
        ("bootstrap", "3.3.7", "wwwroot/lib/bootstrap/js/bootstrap.min.js", 2, "filecontent"),
        (
            "bootstrap",
            "5.3.8",
            "wwwroot/lib/bootstrap-current/js/bootstrap.bundle.min.js",
            2,
            "filecontent",
        ),
    }
    records = vendored.retire_records(result.detections, result.repository)
    assert {record["version"] for record in records} == {"3.3.7"}  # the twin has none
    assert sorted(record["vuln_id"] for record in records) == [
        "GHSA-3wqf-4x89-9g79",
        "GHSA-9v3m-8fp8-mj99",
        "RETIRE-bootstrap-retid-72",
    ]
    record = next(r for r in records if r["vuln_id"] == "GHSA-9v3m-8fp8-mj99")
    assert record["ref"] == "npm/bootstrap@3.3.7/GHSA-9v3m-8fp8-mj99"
    assert record["aliases"] == ["CVE-2019-8331"] and record["engines"] == ["retirejs"]
    assert record["fixed_versions"] == ["3.4.1"] and record["severity"] == "medium"
    assert record["pin_source"] == "vendored"
    assert record["locations"] == ["wwwroot/lib/bootstrap/js/bootstrap.min.js"]
    assert record["vendored"] == [
        {
            "file": "wwwroot/lib/bootstrap/js/bootstrap.min.js",
            "line": 2,
            "library": "bootstrap",
            "version": "3.3.7",
            "extractor": "filecontent",
        }
    ]
    assert record["references"] == ["https://github.com/advisories/GHSA-9v3m-8fp8-mj99"]
    end_of_life = next(r for r in records if r["vuln_id"].startswith("RETIRE-"))
    assert end_of_life["fixed_versions"] == [] and end_of_life["severity"] == "low"
    assert not (tmp_path / ".work").exists()  # the work folder is removed


def test_a_missing_repository_is_a_gap_and_starts_no_process(tmp_path, monkeypatch):
    target = tmp_path / "target"
    write(target / "lib" / "jquery.js", "/*! jQuery v1.12.4 */")

    def no_process(*_args, **_kwargs):
        raise AssertionError("no process may start without a repository")

    monkeypatch.setattr(subprocess, "Popen", no_process)
    result = scan(target, None, tmp_path)
    assert result.status == "skipped" and result.message.startswith("no local RetireJS")
    assert "1 JavaScript files were not checked" in result.message
    assert result.detections == [] and result.skipped == {}
    missing = scan(target, tmp_path / "missing.json", tmp_path)
    assert missing.status == "skipped" and missing.message.startswith("no local ")


def test_a_target_without_javascript_is_skipped(tmp_path):
    write(tmp_path / "target" / "app.py", "print(1)\n")
    result = scan(tmp_path / "target", REPOSITORY, tmp_path)
    assert (result.status, result.message) == ("skipped", vendored.NO_FILES)


def test_a_broken_repository_fails_without_a_process(tmp_path):
    write(tmp_path / "target" / "a.js", "x")
    broken = write(tmp_path / "broken.json", "{oops")
    result = scan(tmp_path / "target", broken, tmp_path)
    assert result.status == "failed" and "cannot be used" in result.message


def test_a_hostile_file_times_out_and_the_check_goes_on(tmp_path):
    """Regex safety: a repository regex with catastrophic backtracking meets a hostile file.

    The child process is killed after the file limit, the file is listed as timed out, and a
    new process checks the next file.
    """
    repository = json.loads(REPOSITORY.read_text(encoding="utf-8"))
    repository["slowlib"] = {
        "vulnerabilities": [],
        "extractors": {"filecontent": [f"(a+)+X({V})"]},
    }
    path = write(tmp_path / "repo.json", json.dumps(repository))
    target = tmp_path / "target"
    write(target / "a-hostile.js", "a" * 64)
    write(target / "b-normal.js", "/*! jQuery v1.12.4 */\n")
    result = scan(target, path, tmp_path, file_seconds=1.0)
    assert result.status == "ok"
    assert result.skipped == {"timed out after 1 s": ["a-hostile.js"]}
    assert [(d.library, d.path) for d in result.detections] == [("jquery", "b-normal.js")]
    assert result.files_checked == 1
    status = result.status_document()
    assert status["skipped_files"]["reasons"] == {"timed out after 1 s": 1}


def test_too_many_hostile_files_stop_the_check(tmp_path, monkeypatch):
    repository = json.loads(REPOSITORY.read_text(encoding="utf-8"))
    repository["slowlib"] = {"vulnerabilities": [], "extractors": {"filecontent": [f"(a+)+X({V})"]}}
    path = write(tmp_path / "repo.json", json.dumps(repository))
    target = tmp_path / "target"
    write(target / "a.js", "a" * 64)
    write(target / "b.js", "/*! jQuery v1.12.4 */\n")
    monkeypatch.setattr(vendored, "MAX_TIMEOUTS", 1)
    result = scan(target, path, tmp_path, file_seconds=1.0)
    assert result.skipped == {
        "timed out after 1 s": ["a.js"],
        "not checked: 1 files stopped the check": ["b.js"],
    }
    assert result.detections == [] and any("check stopped" in w for w in result.warnings)


def test_the_time_limit_of_the_whole_scan(tmp_path):
    target = tmp_path / "target"
    write(target / "a.js", "/*! jQuery v1.12.4 */\n")
    result = scan(target, REPOSITORY, tmp_path, total_seconds=0)
    assert result.status == "timeout"
    assert result.skipped == {vendored.REASON_TOTAL: ["a.js"]}
    assert result.message.startswith("the time limit was used up")


def test_a_process_that_cannot_start_fails_the_check(tmp_path):
    target = tmp_path / "target"
    write(target / "a.js", "x")
    result = scan(target, REPOSITORY, tmp_path, python=str(tmp_path / "no-python.exe"))
    assert result.status == "failed" and "cannot start the detection process" in result.message
    assert result.skipped == {"not checked: the detection process failed": ["a.js"]}


def test_the_child_protocol(tmp_path, monkeypatch):
    target = tmp_path / "target"
    write(target / "lib" / "jquery-1.8.1.min.js", "")
    write(target / "lib" / "b.js", "/*! Bootstrap v3.3.7 */")
    job = write(
        tmp_path / "job.json",
        json.dumps(
            {
                "repository": str(REPOSITORY),
                "root": str(target),
                "files": ["lib/jquery-1.8.1.min.js", "lib/b.js", "lib/missing.js"],
            }
        ),
    )
    buffer = io.BytesIO()
    monkeypatch.setattr(sys, "stdout", io.TextIOWrapper(buffer, encoding="ascii"))
    assert vendored.worker_main([str(job)]) == 0
    messages = [json.loads(line) for line in buffer.getvalue().decode("ascii").splitlines()]
    assert messages[0]["ready"]["libraries"] == 4
    assert [list(m)[0] for m in messages[1:]] == ["start", "done"] * 3 + ["end"]
    first, second, third = (m for m in messages if "done" in m)
    assert first["detections"][0]["extractor"] == "filename"
    assert second["detections"][0]["version"] == "3.3.7"
    assert third == {"done": 2, "detections": [], "skipped": vendored.REASON_UNREADABLE}
    buffer.seek(0)
    buffer.truncate()
    bad = write(tmp_path / "bad.json", json.dumps({"repository": str(tmp_path / "x.json")}))
    assert vendored.worker_main([str(bad)]) == 3
    assert "fatal" in json.loads(buffer.getvalue().decode("ascii"))


# --- outputs and matching ------------------------------------------------------------------------


def test_the_documents(tmp_path):
    result = vendored.VendoredScan(status="ok", message="m", files_total=60, files_checked=3)
    result.detections.append(Detection("jquery", "jquery", "1.12.4", "lib/j.js", "filecontent", 1))
    result.skip("timed out after 20 s", [f"f{index}.js" for index in range(57)])
    result.repository_info = {"sha256": "ab" * 32, "updated_at": "2026-10-25T08:00:00Z"}
    status = result.status_document()
    assert status["tool_version"] == "jsrepository-v5 2026-10-25 sha256:abababababab"
    assert status["skipped_files"]["count"] == 57 and status["skipped_files"]["truncated"]
    assert len(status["skipped_files"]["paths"]) == vendored.MAX_LISTED_PATHS
    document = result.document()
    assert document["libraries"][0]["purl"] == "pkg:npm/jquery@1.12.4"
    assert document["repository"] == {"sha256": "ab" * 32, "updated_at": "2026-10-25T08:00:00Z"}
    vendored.write_outputs(tmp_path, result)
    written = json.loads((tmp_path / "sca" / "retirejs.status.json").read_text(encoding="utf-8"))
    assert written["engine"] == "retirejs" and written["output"] == "sca/vendored.json"
    assert (tmp_path / "sca" / "vendored.json").is_file()


def test_the_pins_sbom_carries_the_vendored_libraries():
    detections = [
        Detection("jquery", "jquery", "1.12.4", "a/jquery.js", "filecontent", 1),
        Detection("jquery", "jquery", "1.12.4", "a/jquery.min.js", "filecontent", 1),
        Detection("@angular/core", "@angular/core", "10.0.0", "b/core.js", "uri"),
    ]
    pins = [Pin("npm", "jquery", "1.12.4", "web/package.json")]
    doc = pins_sbom(pins, detections)
    by_purl = {component["purl"]: component for component in doc["components"]}
    assert set(by_purl) == {"pkg:npm/jquery@1.12.4", "pkg:npm/%40angular/core@10.0.0"}
    assert by_purl["pkg:npm/jquery@1.12.4"]["properties"] == [
        {"name": "kalkan:manifest:path", "value": "web/package.json"},
        {"name": "kalkan:vendored:path", "value": "a/jquery.js"},
        {"name": "kalkan:vendored:library", "value": "jquery"},
        {"name": "kalkan:vendored:path", "value": "a/jquery.min.js"},
    ]
    keys = vendored.pin_locations(detections)
    assert [d.path for d in keys[("npm", "jquery", "1.12.4")]] == ["a/jquery.js", "a/jquery.min.js"]
