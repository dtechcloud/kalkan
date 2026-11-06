# SPDX-License-Identifier: MIT
"""Tests for kalkan.sca.retirejs: the RetireJS repository as data, the extractors and the
vulnerability ranges. No network: the repository is the small test file of tests/fixtures/sca."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from kalkan.errors import ValidationError
from kalkan.sca import retirejs
from kalkan.sca.retirejs import (
    Detection,
    compile_extractor,
    detect_content,
    detect_name,
    expand_lookbehinds,
    is_at_or_above,
    load_repository,
    parse_repository,
)

REPOSITORY = (
    Path(__file__).resolve().parents[1] / "fixtures" / "sca" / "retire" / "jsrepository-v5.json"
)
V = retirejs.VERSION_PLACEHOLDER


@pytest.fixture(scope="module")
def repository() -> retirejs.Repository:
    return load_repository(REPOSITORY)


# --- the repository ------------------------------------------------------------------------------


def test_the_repository_skips_special_entries_and_counts_unsupported_extractors(repository):
    assert list(repository.libraries) == ["jquery", "bootstrap", "lodash", "dojo"]
    assert repository.unsupported == {"func": 1, "ast": 1}
    assert repository.skipped == [] and repository.warnings == []
    jquery = repository.libraries["jquery"]
    assert jquery.npm_name == "jquery" and len(jquery.vulnerabilities) == 2
    assert {extractor.kind for extractor in jquery.extractors} == {"uri", "filename", "filecontent"}
    assert repository.libraries["bootstrap"].npm_name == "bootstrap"  # no npmname: the name
    stats = repository.stats()
    assert stats["libraries"] == 4 and stats["hashes"] == 1
    assert stats["unsupported_extractors"] == {"ast": 1, "func": 1}


def test_a_library_without_a_usable_regex_is_skipped_with_counts():
    doc = {
        "broken": {
            "vulnerabilities": [],
            "extractors": {
                "filecontent": [
                    f"(unclosed ({V})",
                    f"(?<name>named) ({V})",
                    f"possessive a++ ({V})",
                    f"no capture group {V}",
                ]
            },
        },
        "good": {
            "vulnerabilities": [
                {"below": "nonsense!", "severity": "high", "identifiers": {}},
                {"below": "2.0.0", "atOrAbove": "x y", "severity": "high", "identifiers": {}},
                "not an object",
            ],
            "extractors": {"filename": [f"good-({V})\\.js"]},
        },
        "dont check": {"extractors": {"uri": ["(((("]}},
        "no extractors": {"vulnerabilities": []},
    }
    repository = parse_repository(doc)
    assert list(repository.libraries) == ["good"]
    assert [kind for _, kind, _ in repository.skipped] == ["filecontent"] * 4
    reasons = " ".join(reason for _, _, reason in repository.skipped)
    assert "does not compile" in reasons and "named groups" in reasons
    assert "possessive" in reasons and "no capture group" in reasons
    assert repository.libraries["good"].vulnerabilities == ()
    assert any("broken: no usable extractor" in w for w in repository.warnings)
    assert sum("vulnerability" in w and "skipped" in w for w in repository.warnings) == 3


def test_load_repository_refuses_unusable_files(tmp_path):
    cases = {
        "not-json.json": "{not json",
        "list.json": "[1, 2]",
        "empty.json": "{}",
    }
    for name, text in cases.items():
        path = tmp_path / name
        path.write_text(text, encoding="utf-8")
        with pytest.raises(ValidationError):
            load_repository(path)
    invalid = tmp_path / "latin1.json"
    invalid.write_bytes(b'{"x": "\xff"}')
    with pytest.raises(ValidationError, match="cannot be read"):
        load_repository(invalid)
    with pytest.raises(ValidationError, match="cannot be read"):
        load_repository(tmp_path / "missing.json")


# --- regex safety --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("kind", "text", "reason"),
    [
        ("filecontent", "x" * (retirejs.MAX_REGEX_CHARS + 1) + f"({V})", "longer than"),
        ("filecontent", f"a\0({V})", "NUL"),
        ("filecontent", f"(?<v>{V})", "named groups"),
        ("filecontent", f"a++({V})", "possessive"),
        ("filecontent", f"(?>a)({V})", "atomic"),
        ("filecontent", f"(?i)a({V})", "inline global flags"),
        ("filecontent", f"a{{20000}}({V})", "repeats more than"),
        ("filecontent", f"(?<=a+)({V})", "does not compile"),
        ("filecontent", "(a)?", "matches the empty string"),
        ("filecontent", "abc", "no capture group"),
        ("filecontentreplace", f"({V})", "not in the form"),
        ("filecontentreplace", f"/x({V})/$'/", "not supported"),
        ("filename", 17, "not a non-empty string"),
        ("func", "x", "unknown extractor kind"),
    ],
)
def test_unsafe_or_unsupported_regexes_are_refused(kind, text, reason):
    with pytest.raises(ValueError, match=re.escape(reason)):
        compile_extractor(kind, text)


def test_compiled_extractors_follow_the_retire_semantics():
    filename = compile_extractor("filename", f"jquery-({V})(\\.min)?\\.js")
    assert filename.pattern.pattern.startswith("^") and filename.pattern.pattern.endswith("$")
    # The version class takes ".min" too; the detection removes it (as retire does).
    assert filename.pattern.fullmatch("jquery-1.8.1.min.js").group(1) == "1.8.1.min"
    assert filename.pattern.search("xjquery-1.8.1.js") is None  # anchored like ^regex$
    assert compile_extractor("uri", f"/({V})/x\\.js").pattern.search("/a/2.0.0/x.js")
    replace = compile_extractor("filecontentreplace", "/v=([0-9]+)_([0-9]+)/$1.$2/")
    match = replace.pattern.search("v=3_14")
    assert match.expand(replace.template) == "3.14"
    dollars = compile_extractor("filecontentreplace", "/v=([0-9]+)/$$$1-$&-$9/")
    assert dollars.pattern.search("v=7").expand(dollars.template) == "$7-v=7-$9"
    unicode_digit = compile_extractor("filecontentreplace", "/v=([0-9]+)/$1$²/")
    assert unicode_digit.pattern.search("v=7").expand(unicode_digit.template) == "7$²"
    with_backreference = compile_extractor("filecontent", f'([a-z])="({V})";\\1\\.v')
    assert with_backreference.pattern.search('e="1.2.3";e.v').group(2) == "1.2.3"


def test_bounded_lookbehinds_become_fixed_width_alternatives():
    source = f'="({V})(?<=[0-9]{{1,2}}\\.[0-9]{{1,2}}\\.[0-9]{{1,2}})"x'
    expanded = expand_lookbehinds(source.replace(V, retirejs.VERSION_CLASS))
    assert expanded.count("(?<=") == 8 and "{1,2}" not in expanded
    extractor = compile_extractor("filecontent", source)
    assert extractor.pattern.search('t="4.17.15"x').group(1) == "4.17.15"
    assert extractor.pattern.search('t="4.17.155"x') is None  # three digits at the end
    assert extractor.pattern.search('t="104.1.1"x').group(1) == "104.1.1"
    negative = expand_lookbehinds("a(?<!b?c)d")
    assert negative == "a(?<!c)(?<!bc)d"
    assert re.search(negative, "xacd") is None and re.search(negative, "xad")
    assert expand_lookbehinds("(?<=a+)x") == "(?<=a+)x"  # unbounded: Python refuses it later
    assert expand_lookbehinds("[(?<=a?)](?<=b)") == "[(?<=a?)](?<=b)"  # classes and fixed widths


def test_versions_compare_like_retire():
    assert is_at_or_above("3.4.1", "3.4.0") and not is_at_or_above("3.4.0", "3.4.1")
    assert is_at_or_above("3.4", "3.4.0") and is_at_or_above("10.0.0", "9.9.9")
    assert not is_at_or_above("3.0.0-rc.1", "3.0.0") and is_at_or_above("3.0.0", "3.0.0-rc.1")
    assert not is_at_or_above("1.9.0b1", "1.9.0")
    assert is_at_or_above("4.0.0-beta.2", "4.0.0-beta")


def test_vulnerability_ranges_excludes_and_identifiers(repository):
    jquery = repository.libraries["jquery"]
    current, end_of_life = jquery.vulnerabilities
    assert [v.ids for v in jquery.affecting("1.12.4")] == [
        ("GHSA-jpcq-cgw6-v4j6", "CVE-2020-11023"),
        ("RETIRE-jquery-retid-73",),
    ]
    assert jquery.affecting("1.12.4-aem") == [current]  # excluded from the end-of-life range
    assert jquery.affecting("3.7.1") == []
    assert current.fixed_version() == "3.5.0" and end_of_life.fixed_version() is None
    assert current.range_text() == ">=1.0.3, <3.5.0"
    assert end_of_life.range_text() == "<2.999.999 (except 1.12.4-aem)"
    assert current.severity == "medium" and end_of_life.severity == "low"
    assert current.cwe == ("CWE-79",) and current.info[0].startswith("https://blog.jquery.com/")
    bootstrap = repository.libraries["bootstrap"]
    assert len(bootstrap.affecting("3.3.7")) == 3
    assert [v.ids[0] for v in bootstrap.affecting("3.4.1")] == ["RETIRE-bootstrap-retid-72"]
    assert bootstrap.affecting("4.3.1") == [] and bootstrap.affecting("5.3.8") == []


# --- detection -----------------------------------------------------------------------------------


def test_names_and_paths_identify_a_library(repository):
    [hit] = detect_name(repository, "wwwroot/lib/jquery-1.8.1.min.js")
    assert (hit.library, hit.version, hit.extractor, hit.line) == (
        "jquery",
        "1.8.1",
        "filename",
        None,
    )
    [uri] = detect_name(repository, "static/ajax/libs/jquery/3.4.1/jquery.min.js")
    assert (uri.version, uri.extractor) == ("3.4.1", "uri")
    [top] = detect_name(repository, "2.2.4/jquery.js")  # the path gets a leading "/"
    assert top.version == "2.2.4"
    assert detect_name(repository, "lib/jquery.min.js") == []


def test_content_detections_keep_the_line_and_the_match(repository):
    text = "/*!\n * Bootstrap v3.3.7 (http://getbootstrap.com)\n */\nvar a = 1;\n"
    [hit] = detect_content(repository, "lib/b.js", text.encode())
    assert (hit.library, hit.version, hit.line) == ("bootstrap", "3.3.7", 2)
    assert hit.match == "* Bootstrap v3.3.7" and hit.npm_name == "bootstrap"
    crlf = text.replace("\n", "\r\n").encode()
    assert detect_content(repository, "lib/b.js", crlf)[0].line == 2
    [minified] = detect_content(repository, "x.js", b"/*! jQuery v3.4.1.min */")
    assert minified.version == "3.4.1"  # the .min suffix is removed


def test_content_scan_order_filecontent_then_replace_then_hash(repository):
    both = b"/*! jQuery v1.12.4 */ dojo.version={major:1,minor:3,patch:2}"
    assert [d.library for d in detect_content(repository, "a.js", both)] == ["jquery"]
    [replaced] = detect_content(repository, "a.js", b"var x;dojo.version={major:1,minor:3,patch:2}")
    assert (replaced.library, replaced.version, replaced.extractor) == (
        "dojo",
        "1.3.2",
        "filecontentreplace",
    )
    content = (
        "// kalkan fixture: a build that only its hash identifies\nvar kalkanHashFixture = 1;\n"
    )
    [hashed] = detect_content(repository, "a.js", content.encode())
    assert (hashed.library, hashed.version, hashed.extractor) == ("dojo", "1.1.0", "hash")
    windows = content.replace("\n", "\r\n").encode()
    assert detect_content(repository, "a.js", windows)[0].extractor == "hash"  # LF before SHA-1
    assert retirejs.content_sha1(content) == "0e9b8ef495778bd1f1122bd6c5553a73cea67be5"
    assert detect_content(repository, "a.js", b"console.log('app');") == []


def test_garbage_versions_are_dropped(repository):
    long_version = "1." + "1" * 80
    assert detect_content(repository, "a.js", f"/*! jQuery v{long_version} */".encode()) == []


def test_detections_round_trip_through_the_child_protocol():
    item = Detection("jquery", "jquery", "1.12.4", "lib/j.js", "filecontent", 1, "/*! jQuery")
    assert Detection.from_dict(json.loads(json.dumps(item.to_dict()))) == item
    with pytest.raises(ValueError):
        Detection.from_dict({"library": "x", "version": "1"})
    with pytest.raises(ValueError):
        Detection.from_dict({**item.to_dict(), "line": "1"})
