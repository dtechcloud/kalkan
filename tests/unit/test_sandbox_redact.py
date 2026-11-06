# SPDX-License-Identifier: MIT
"""Unit tests for the redaction of the sandbox output (kalkan.sandbox.redact)."""

from __future__ import annotations

import pytest

from kalkan.sandbox.redact import REDACTED, redact, redact_file

# Test values are split so that no secret scanner flags this file.
AWS = "AKIA" + "Z" * 16
GITHUB = "ghp_" + "a1" * 18
JWT = "eyJ" + "hbGciOiJIUzI1" + ".eyJ" + "zdWIiOiIxMjM0" + ".sig_" + "abcdefgh12"
KEY = "-----BEGIN RSA " + "PRIVATE KEY-----\nMIIEow\n-----END RSA " + "PRIVATE KEY-----"


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        (f"key {AWS} found", AWS),
        (f"token {GITHUB}", GITHUB),
        (f"Authorization: Bearer {JWT}", JWT),
        (f"pem:\n{KEY}\n", "MIIEow"),
        ("DATABASE_URL=postgres://app:s3cretpass@db:5432/x", "s3cretpass"),
        ('{"client_secret": "abcdef123456"}', "abcdef123456"),
        ("DefaultEndpointsProtocol=https;AccountKey=bWFkZS11cA==;", "bWFkZS11cA=="),
        ("export API_KEY=0123456789abcdef", "0123456789abcdef"),
    ],
)
def test_secret_values_are_replaced(text, secret):
    cleaned = redact(text)
    assert secret not in cleaned and REDACTED in cleaned


def test_the_harness_markers_and_plain_lines_stay():
    text = "KALKAN_POC_OK the query returned 3 rows\nKALKAN_POC_FAIL no effect"
    assert redact(text) == text


def test_the_name_of_a_secret_pair_stays_readable():
    assert redact("password=hunter2hunter2") == f"password={REDACTED}"


def test_redact_file_rewrites_text_and_leaves_binary(tmp_path):
    text_file = tmp_path / "a.txt"
    text_file.write_text(f"leak {AWS}\n", encoding="utf-8")
    binary = tmp_path / "b.bin"
    binary.write_bytes(b"\xff\xfe" + AWS.encode())
    redact_file(text_file)
    redact_file(binary)
    assert AWS not in text_file.read_text(encoding="utf-8")
    assert binary.read_bytes() == b"\xff\xfe" + AWS.encode()
