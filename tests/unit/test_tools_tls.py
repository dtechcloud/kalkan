# SPDX-License-Identifier: MIT
"""Tests for kalkan.tools.tls: the macOS keychain roots when Python has no CA file."""

from __future__ import annotations

import ssl
import urllib.error

import pytest

from kalkan.errors import ToolError
from kalkan.tools import install, tls

#: A self-signed test certificate made for this test (its key was deleted); no store has it.
TEST_ROOT = """-----BEGIN CERTIFICATE-----
MIIBjjCCATOgAwIBAgIUYATE3WB9AJi8KExT3D46hZl0UoIwCgYIKoZIzj0EAwIw
GzEZMBcGA1UEAwwQa2Fsa2FuIHRlc3Qgcm9vdDAgFw0yNjExMTMxNDIyNTRaGA8y
MTI2MTAyMDE0MjI1NFowGzEZMBcGA1UEAwwQa2Fsa2FuIHRlc3Qgcm9vdDBZMBMG
ByqGSM49AgEGCCqGSM49AwEHA0IABEqm+n2mUXV30VB7rQx29+e+djeWDWwkEUvH
LLN4Q/zdwZL6CWf/i8QXypQ0XCY4lHoUGVlTpAF2K/BJi0nJsP6jUzBRMB0GA1Ud
DgQWBBRhoFA4wRUvrK89FUyjds0/Cqi5ZjAfBgNVHSMEGDAWgBRhoFA4wRUvrK89
FUyjds0/Cqi5ZjAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0kAMEYCIQCh
BD7iDpzPdGt9z708AJcV1vjQcWJ4wagbPMdb4kL5kwIhAKDAifIYU1m7OSOa9Thx
NPZSV1JujOFEK/JrE9CKvY5e
-----END CERTIFICATE-----
"""
TEST_SUBJECT = ((("commonName", "kalkan test root"),),)


def _paths(cafile: str | None = None, capath: str | None = None) -> ssl.DefaultVerifyPaths:
    return ssl.DefaultVerifyPaths(cafile, capath, "SSL_CERT_FILE", "", "SSL_CERT_DIR", "")


def _has_test_root(context: ssl.SSLContext) -> bool:
    return any(cert.get("subject") == TEST_SUBJECT for cert in context.get_ca_certs())


def test_ca_sources(tmp_path):
    bundle = tmp_path / "cert.pem"
    bundle.write_text(TEST_ROOT, encoding="utf-8")
    empty = tmp_path / "empty"
    empty.mkdir()
    full = tmp_path / "certs"
    full.mkdir()
    (full / "a.0").write_text(TEST_ROOT, encoding="utf-8")
    assert tls.has_ca_source(_paths(cafile=str(bundle)))
    assert tls.has_ca_source(_paths(capath=str(full)))
    # The python.org layout before "Install Certificates.command": the file does not exist.
    assert not tls.has_ca_source(_paths(cafile=str(tmp_path / "missing.pem")))
    assert not tls.has_ca_source(_paths(capath=str(empty)))
    assert not tls.has_ca_source(_paths())


@pytest.mark.parametrize(
    ("platform", "environ", "has_source", "expected"),
    [
        ("darwin", {}, False, True),
        ("darwin", {}, True, False),
        ("darwin", {"SSL_CERT_FILE": "/x/ca.pem"}, False, False),
        ("darwin", {"SSL_CERT_DIR": "/x/certs"}, False, False),
        ("linux", {}, False, False),
        ("win32", {}, False, False),
    ],
)
def test_needs_macos_roots(tmp_path, platform, environ, has_source, expected):
    bundle = tmp_path / "cert.pem"
    bundle.write_text(TEST_ROOT, encoding="utf-8")
    paths = _paths(cafile=str(bundle)) if has_source else _paths()
    assert tls.needs_macos_roots(platform=platform, environ=environ, paths=paths) is expected


def test_the_context_loads_the_keychain_roots():
    asked: list[str] = []

    def read(keychain: str) -> str:
        asked.append(keychain)
        # The first keychain holds something OpenSSL cannot read: the second one still loads.
        return "not a certificate" if keychain == tls.MACOS_KEYCHAINS[0] else TEST_ROOT

    context = tls.build_context(platform="darwin", environ={}, paths=_paths(), read=read)
    assert asked == list(tls.MACOS_KEYCHAINS)
    assert _has_test_root(context)
    assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname


def test_the_context_reads_no_keychain_when_not_needed(tmp_path):
    def read(keychain: str) -> str:
        raise AssertionError(f"read {keychain}")

    for platform, environ in (("linux", {}), ("darwin", {"SSL_CERT_FILE": "/x/ca.pem"})):
        context = tls.build_context(platform=platform, environ=environ, paths=_paths(), read=read)
        assert not _has_test_root(context)


def test_explain_adds_the_hint_only_to_a_failed_certificate_check():
    failed = "<urlopen error [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed>"
    assert tls.explain(failed).startswith(failed + "; the server certificate could not be")
    assert "SSL_CERT_FILE" in tls.explain(failed)
    assert tls.explain("timed out") == "timed out"


def test_a_failed_download_names_the_fix(tmp_path, monkeypatch):
    monkeypatch.setattr(install, "_sleep", lambda seconds: None)

    def opener(request, timeout=None):
        raise urllib.error.URLError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed")

    with pytest.raises(ToolError, match="Install Certificates.command"):
        install.download_verified(
            "https://example.com/tool.zip", "0" * 64, dest_dir=tmp_path, opener=opener
        )
