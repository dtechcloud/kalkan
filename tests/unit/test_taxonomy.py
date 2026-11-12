# SPDX-License-Identifier: MIT
"""Tests for kalkan.findings.taxonomy (ENGINE-SPEC 3)."""

from __future__ import annotations

import dataclasses
import re
from pathlib import Path

import pytest

from kalkan.findings import taxonomy
from kalkan.findings.taxonomy import (
    CLASSES,
    EXTENDED_CWE_MAP,
    SLUGS,
    VulnClass,
    class_for_cwe,
    get_class,
    normalize_cwe,
    owasp_for_class,
)

ROOT = Path(__file__).resolve().parents[2]
AUDIT_FAMILIES = ROOT / "third_party" / "codecrucible" / "prompts" / "core" / "audit_families.yaml"

# (slug, English title, Turkish title, default CWE IDs): ENGINE-SPEC 3 and the user's titles.
EXPECTED = [
    ("sqli", "SQL injection", "SQL injection", ["CWE-89"]),
    ("nosqli", "NoSQL injection", "NoSQL injection", ["CWE-943"]),
    ("os-command-injection", "OS command injection", "Command injection", ["CWE-78"]),
    ("code-injection", "Code injection / eval", "Code injection / eval", ["CWE-94"]),
    (
        "ssti",
        "Server-side template injection",
        "Server-side template injection (SSTI)",
        ["CWE-1336"],
    ),
    ("xss", "Cross-site scripting", "Cross-site scripting (XSS)", ["CWE-79"]),
    ("ssrf", "Server-side request forgery", "Server-side request forgery (SSRF)", ["CWE-918"]),
    ("path-traversal", "Path traversal / file read-write", "Path traversal", ["CWE-22"]),
    ("file-upload", "Unsafe file upload", "Güvensiz dosya yükleme (file upload)", ["CWE-434"]),
    ("xxe", "XML external entity", "XML external entity (XXE)", ["CWE-611"]),
    ("deserialization", "Insecure deserialization", "Insecure deserialization", ["CWE-502"]),
    ("authn", "Authentication flaws", "Kimlik doğrulama hataları (authentication)", ["CWE-287"]),
    ("jwt", "JWT / token handling", "JWT / token doğrulama", ["CWE-347"]),
    ("oauth-oidc-saml", "OAuth / OIDC / SAML", "OAuth / OIDC / SAML", ["CWE-287", "CWE-347"]),
    (
        "missing-authz",
        "Missing authorization",
        "Eksik yetkilendirme (missing authorization)",
        ["CWE-862"],
    ),
    ("idor", "IDOR / BOLA", "IDOR / BOLA", ["CWE-639"]),
    (
        "multi-tenant",
        "Multi-tenant isolation",
        "Kiracı izolasyonu (multi-tenant isolation)",
        ["CWE-284"],
    ),
    ("csrf", "CSRF", "CSRF", ["CWE-352"]),
    ("open-redirect", "Open redirect", "Open redirect", ["CWE-601"]),
    ("cors", "CORS misconfiguration", "CORS yapılandırması", ["CWE-942"]),
    ("mass-assignment", "Mass assignment", "Mass assignment", ["CWE-915"]),
    (
        "business-logic",
        "Business logic flaws",
        "İş mantığı hataları (business logic)",
        ["CWE-840"],
    ),
    (
        "race-condition",
        "Race condition / TOCTOU",
        "Race condition / TOCTOU",
        ["CWE-362", "CWE-367"],
    ),
    ("crypto", "Cryptographic misuse", "Kriptografi hataları", ["CWE-327"]),
    ("hardcoded-secrets", "Hardcoded secrets", "Gömülü sırlar (hardcoded secrets)", ["CWE-798"]),
    (
        "sensitive-data-exposure",
        "Sensitive data exposure / PII in logs",
        "Hassas veri ifşası",
        ["CWE-200", "CWE-532"],
    ),
    (
        "security-misconfig",
        "Security misconfiguration",
        "Güvenlik yapılandırma hataları (misconfiguration)",
        ["CWE-16"],
    ),
    ("graphql", "GraphQL-specific issues", "GraphQL", []),
    ("prototype-pollution", "Prototype pollution", "Prototype pollution", ["CWE-1321"]),
    ("dos-redos", "ReDoS / resource exhaustion", "DoS / ReDoS", ["CWE-400", "CWE-1333"]),
    (
        "request-smuggling-crlf-cache",
        "Request smuggling / CRLF / cache poisoning",
        "Request smuggling / CRLF / cache poisoning",
        ["CWE-444", "CWE-113"],
    ),
    (
        "webhook-replay",
        "Webhook signature / replay",
        "Webhook imzası / replay",
        ["CWE-345", "CWE-294"],
    ),
    (
        "rate-limit-bruteforce",
        "Rate limiting / brute force",
        "Rate limiting / brute force",
        ["CWE-307"],
    ),
    ("llm-ai", "LLM / AI-specific", "LLM / AI güvenliği", []),
    ("memory-safety", "Memory safety", "Bellek güvenliği (memory safety)", ["CWE-787", "CWE-416"]),
    ("smart-contract", "Smart contracts", "Akıllı kontrat (smart contract)", []),
    (
        "mobile-desktop-ipc",
        "Mobile / desktop / local IPC",
        "Mobil / masaüstü / yerel IPC",
        ["CWE-926"],
    ),
    (
        "vulnerable-dependency",
        "Vulnerable dependency (SCA)",
        "Zafiyetli bağımlılık (SCA)",
        ["CWE-1395"],
    ),
    ("malicious-dependency", "Malicious dependency", "Zararlı bağımlılık", ["CWE-506"]),
    ("supply-chain-cicd", "Supply chain / CI-CD", "Tedarik zinciri / CI-CD", ["CWE-829"]),
    (
        "iac-cloud-container",
        "IaC / cloud / container misconfiguration",
        "IaC / bulut / konteyner yapılandırması",
        ["CWE-16"],
    ),
    ("code-quality", "Non-security code quality", "Kod kalitesi (güvenlik dışı)", []),
]

OWASP_PATTERN = re.compile(r"A(0[1-9]|10):2021|LLM(0[1-9]|10):2025")


def test_there_are_42_classes_in_spec_order():
    assert len(CLASSES) == 42
    assert list(SLUGS) == [row[0] for row in EXPECTED]
    assert len(set(SLUGS)) == 42


def test_dependency_classes_are_the_two_sca_classes():
    assert taxonomy.DEPENDENCY_CLASSES == {"vulnerable-dependency", "malicious-dependency"}
    assert taxonomy.DEPENDENCY_CLASSES <= set(SLUGS)


@pytest.mark.parametrize(("slug", "title_en", "title_tr", "cwe"), EXPECTED)
def test_class_titles_and_default_cwes(slug, title_en, title_tr, cwe):
    item = get_class(slug)
    assert item is not None
    assert item.slug == slug
    assert item.title_en == title_en
    assert item.title_tr == title_tr
    assert list(item.cwe) == cwe


def test_classes_are_frozen():
    item = get_class("sqli")
    assert isinstance(item, VulnClass)
    with pytest.raises(dataclasses.FrozenInstanceError):
        item.slug = "other"  # type: ignore[misc]
    assert isinstance(item.cwe, tuple)
    assert isinstance(item.owasp, tuple)


def test_get_class_returns_none_for_an_unknown_slug():
    assert get_class("not-a-class") is None
    assert get_class("") is None


@pytest.mark.parametrize(
    ("slug", "owasp"),
    [
        ("sqli", ["A03:2021"]),
        ("ssrf", ["A10:2021"]),
        ("xxe", ["A05:2021"]),
        ("path-traversal", ["A01:2021"]),
        ("file-upload", ["A04:2021"]),
        ("deserialization", ["A08:2021"]),
        ("jwt", ["A02:2021", "A07:2021"]),
        ("cors", ["A01:2021", "A05:2021"]),
        ("sensitive-data-exposure", ["A01:2021", "A09:2021"]),
        ("request-smuggling-crlf-cache", ["A03:2021", "A04:2021"]),
        ("webhook-replay", ["A07:2021", "A08:2021"]),
        ("vulnerable-dependency", ["A06:2021"]),
        ("malicious-dependency", ["A06:2021", "A08:2021"]),
        ("hardcoded-secrets", ["A07:2021"]),
        ("llm-ai", ["LLM01:2025"]),
        ("memory-safety", []),
        ("smart-contract", []),
        ("code-quality", []),
    ],
)
def test_owasp_for_class(slug, owasp):
    assert owasp_for_class(slug) == owasp


def test_owasp_for_an_unknown_class_is_empty():
    assert owasp_for_class("not-a-class") == []


def test_owasp_for_class_returns_a_new_list():
    categories = owasp_for_class("sqli")
    categories.append("changed")
    assert owasp_for_class("sqli") == ["A03:2021"]


def test_owasp_values_are_well_formed_and_ordered():
    for item in CLASSES:
        for category in item.owasp:
            assert OWASP_PATTERN.fullmatch(category), (item.slug, category)
        assert list(item.owasp) == sorted(item.owasp), item.slug


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("CWE-89", "CWE-89"),
        ("cwe-89", "CWE-89"),
        ("Cwe-89", "CWE-89"),
        ("89", "CWE-89"),
        (" 89 ", "CWE-89"),
        (89, "CWE-89"),
        ("external/cwe/cwe-89", "CWE-89"),
        ("EXTERNAL/CWE/CWE-89", "CWE-89"),
        ("CWE-89: Improper Neutralization of Special Elements used in an SQL Command", "CWE-89"),
        ("CWE-89 (SQL injection)", "CWE-89"),
        ("CWE89", "CWE-89"),
        ("CWE 89", "CWE-89"),
        ("CWE_89", "CWE-89"),
        ("CWE-089", "CWE-89"),
        ("CWE-1333", "CWE-1333"),
    ],
)
def test_normalize_cwe_accepts_common_forms(value, expected):
    assert normalize_cwe(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "",
        "   ",
        "CWE-",
        "CWE-abc",
        "CWE-89abc",
        "A03:2021",
        "OWASP-A03:2021 - Injection",
        "security",
        "-89",
        "89a",
        "CWE-0",
        "0",
        0,
        -89,
        True,
        None,
        8.9,
        ["CWE-89"],
    ],
)
def test_normalize_cwe_rejects_other_values(value):
    assert normalize_cwe(value) is None


@pytest.mark.parametrize(
    ("cwe", "slug"),
    [
        ("CWE-89", "sqli"),
        ("CWE-78", "os-command-injection"),
        ("CWE-79", "xss"),
        ("CWE-918", "ssrf"),
        ("CWE-1395", "vulnerable-dependency"),
        ("CWE-506", "malicious-dependency"),
        # ENGINE-SPEC 3: the first class whose default list contains the CWE wins.
        ("CWE-287", "authn"),
        ("CWE-347", "jwt"),
        ("CWE-16", "security-misconfig"),
        ("CWE-284", "multi-tenant"),
        ("CWE-294", "webhook-replay"),
        # Any form that normalize_cwe accepts.
        ("external/cwe/cwe-89", "sqli"),
        ("cwe-79", "xss"),
        ("22", "path-traversal"),
    ],
)
def test_class_for_cwe_uses_the_default_lists_first(cwe, slug):
    assert class_for_cwe(cwe) == slug


@pytest.mark.parametrize(
    ("cwe", "slug"),
    [
        ("CWE-77", "os-command-injection"),
        ("CWE-88", "os-command-injection"),
        ("CWE-90", "sqli"),
        ("CWE-643", "sqli"),
        ("CWE-917", "code-injection"),
        ("CWE-95", "code-injection"),
        ("CWE-80", "xss"),
        ("CWE-83", "xss"),
        ("CWE-23", "path-traversal"),
        ("CWE-36", "path-traversal"),
        ("CWE-73", "path-traversal"),
        ("CWE-776", "xxe"),
        ("CWE-863", "missing-authz"),
        ("CWE-285", "missing-authz"),
        ("CWE-566", "idor"),
        ("CWE-306", "authn"),
        ("CWE-384", "authn"),
        ("CWE-640", "authn"),
        ("CWE-259", "hardcoded-secrets"),
        ("CWE-321", "hardcoded-secrets"),
        ("CWE-295", "crypto"),
        ("CWE-330", "crypto"),
        ("CWE-338", "crypto"),
        ("CWE-916", "crypto"),
        ("CWE-209", "sensitive-data-exposure"),
        ("CWE-548", "sensitive-data-exposure"),
        ("CWE-614", "security-misconfig"),
        ("CWE-1004", "security-misconfig"),
        ("CWE-693", "security-misconfig"),
        ("CWE-366", "race-condition"),
        ("CWE-119", "memory-safety"),
        ("CWE-476", "memory-safety"),
        ("CWE-190", "memory-safety"),
        ("CWE-409", "dos-redos"),
        ("CWE-770", "dos-redos"),
        ("CWE-937", "vulnerable-dependency"),
        ("CWE-1104", "vulnerable-dependency"),
    ],
)
def test_class_for_cwe_falls_back_to_the_extended_map(cwe, slug):
    assert class_for_cwe(cwe) == slug


@pytest.mark.parametrize("cwe", ["CWE-703", "CWE-20", "CWE-99999", "not a cwe", "", "0"])
def test_class_for_cwe_returns_none_for_unmapped_values(cwe):
    assert class_for_cwe(cwe) is None


def test_extended_map_is_well_formed():
    default_cwes = {cwe for item in CLASSES for cwe in item.cwe}
    for cwe, slug in EXTENDED_CWE_MAP.items():
        assert normalize_cwe(cwe) == cwe, cwe
        assert slug in SLUGS, (cwe, slug)
        # The default lists always win, so a repeated CWE would be a dead entry.
        assert cwe not in default_cwes, cwe


def test_maps_are_read_only():
    with pytest.raises(TypeError):
        EXTENDED_CWE_MAP["CWE-1"] = "sqli"  # type: ignore[index]


def test_every_cwe_of_the_codecrucible_families_has_a_class():
    text = AUDIT_FAMILIES.read_text(encoding="utf-8")
    family_cwes = [
        cwe
        for listing in re.findall(r"^\s*cwes:\s*\[(.*?)\]", text, re.MULTILINE)
        for cwe in re.findall(r"CWE-[0-9]+", listing)
    ]
    assert len(family_cwes) > 100
    unmapped = sorted({cwe for cwe in family_cwes if class_for_cwe(cwe) is None})
    assert unmapped == []


def test_module_exposes_the_documented_api():
    for name in ("CLASSES", "SLUGS", "get_class", "class_for_cwe", "normalize_cwe"):
        assert hasattr(taxonomy, name)
    assert callable(taxonomy.owasp_for_class)
