# SPDX-License-Identifier: MIT
"""Vulnerability class taxonomy: slugs, titles, default CWE IDs and OWASP categories.

ENGINE-SPEC section 3. The slug is the stable key in every file. Each class has an English
title, a Turkish title (established English terms stay in English), the default CWE IDs and
the OWASP Top 10 2021 categories.

``class_for_cwe`` looks at the default CWE lists first, in class order. Then it looks at
:data:`EXTENDED_CWE_MAP`. The extended map comes from the weakness families of codecrucible
(``third_party/codecrucible/prompts/core/audit_families.yaml``).
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType


@dataclass(frozen=True)
class VulnClass:
    """One vulnerability class of the kalkan taxonomy."""

    slug: str
    title_en: str
    title_tr: str
    cwe: tuple[str, ...]
    owasp: tuple[str, ...]


# OWASP Top 10 2021 categories (https://owasp.org/Top10/).
A01 = "A01:2021"  # Broken Access Control
A02 = "A02:2021"  # Cryptographic Failures
A03 = "A03:2021"  # Injection
A04 = "A04:2021"  # Insecure Design
A05 = "A05:2021"  # Security Misconfiguration
A06 = "A06:2021"  # Vulnerable and Outdated Components
A07 = "A07:2021"  # Identification and Authentication Failures
A08 = "A08:2021"  # Software and Data Integrity Failures
A09 = "A09:2021"  # Security Logging and Monitoring Failures
A10 = "A10:2021"  # Server-Side Request Forgery (SSRF)
# OWASP Top 10 for LLM Applications 2025. No category of the web Top 10 covers this class.
LLM01 = "LLM01:2025"  # Prompt Injection


def _vc(slug: str, title_en: str, title_tr: str, cwe: tuple[str, ...], owasp: tuple[str, ...]):
    return VulnClass(slug=slug, title_en=title_en, title_tr=title_tr, cwe=cwe, owasp=owasp)


# Rule for the OWASP column: a class lists the categories that the official OWASP Top 10 2021
# CWE mapping gives for its default CWE IDs, in category order. A comment marks each exception:
# a CWE without an official mapping, or a second category that the OWASP text names directly.
CLASSES: tuple[VulnClass, ...] = (
    _vc("sqli", "SQL injection", "SQL injection", ("CWE-89",), (A03,)),
    # CWE-943 has no official mapping. NoSQL injection is injection (A03).
    _vc("nosqli", "NoSQL injection", "NoSQL injection", ("CWE-943",), (A03,)),
    _vc("os-command-injection", "OS command injection", "Command injection", ("CWE-78",), (A03,)),
    _vc("code-injection", "Code injection / eval", "Code injection / eval", ("CWE-94",), (A03,)),
    # CWE-1336 has no official mapping. Template injection is injection (A03).
    _vc(
        "ssti",
        "Server-side template injection",
        "Server-side template injection (SSTI)",
        ("CWE-1336",),
        (A03,),
    ),
    _vc("xss", "Cross-site scripting", "Cross-site scripting (XSS)", ("CWE-79",), (A03,)),
    _vc(
        "ssrf",
        "Server-side request forgery",
        "Server-side request forgery (SSRF)",
        ("CWE-918",),
        (A10,),
    ),
    _vc(
        "path-traversal", "Path traversal / file read-write", "Path traversal", ("CWE-22",), (A01,)
    ),
    _vc(
        "file-upload",
        "Unsafe file upload",
        "Güvensiz dosya yükleme (file upload)",
        ("CWE-434",),
        (A04,),
    ),
    _vc("xxe", "XML external entity", "XML external entity (XXE)", ("CWE-611",), (A05,)),
    _vc(
        "deserialization",
        "Insecure deserialization",
        "Insecure deserialization",
        ("CWE-502",),
        (A08,),
    ),
    _vc(
        "authn",
        "Authentication flaws",
        "Kimlik doğrulama hataları (authentication)",
        ("CWE-287",),
        (A07,),
    ),
    # CWE-347 maps to A02. A07 is added because token validation is an authentication control.
    _vc("jwt", "JWT / token handling", "JWT / token doğrulama", ("CWE-347",), (A02, A07)),
    _vc(
        "oauth-oidc-saml",
        "OAuth / OIDC / SAML",
        "OAuth / OIDC / SAML",
        ("CWE-287", "CWE-347"),
        (A02, A07),
    ),
    _vc(
        "missing-authz",
        "Missing authorization",
        "Eksik yetkilendirme (missing authorization)",
        ("CWE-862",),
        (A01,),
    ),
    _vc("idor", "IDOR / BOLA", "IDOR / BOLA", ("CWE-639",), (A01,)),
    _vc(
        "multi-tenant",
        "Multi-tenant isolation",
        "Kiracı izolasyonu (multi-tenant isolation)",
        ("CWE-284",),
        (A01,),
    ),
    _vc("csrf", "CSRF", "CSRF", ("CWE-352",), (A01,)),
    _vc("open-redirect", "Open redirect", "Open redirect", ("CWE-601",), (A01,)),
    # CWE-942 maps to A05. A01 is added because the A01 text names CORS misconfiguration.
    _vc("cors", "CORS misconfiguration", "CORS yapılandırması", ("CWE-942",), (A01, A05)),
    _vc("mass-assignment", "Mass assignment", "Mass assignment", ("CWE-915",), (A08,)),
    _vc(
        "business-logic",
        "Business logic flaws",
        "İş mantığı hataları (business logic)",
        ("CWE-840",),
        (A04,),
    ),
    # CWE-362 and CWE-367 have no official mapping. A race is a design flaw (A04).
    _vc(
        "race-condition",
        "Race condition / TOCTOU",
        "Race condition / TOCTOU",
        ("CWE-362", "CWE-367"),
        (A04,),
    ),
    _vc("crypto", "Cryptographic misuse", "Kriptografi hataları", ("CWE-327",), (A02,)),
    _vc(
        "hardcoded-secrets",
        "Hardcoded secrets",
        "Gömülü sırlar (hardcoded secrets)",
        ("CWE-798",),
        (A07,),
    ),
    _vc(
        "sensitive-data-exposure",
        "Sensitive data exposure / PII in logs",
        "Hassas veri ifşası",
        ("CWE-200", "CWE-532"),
        (A01, A09),
    ),
    _vc(
        "security-misconfig",
        "Security misconfiguration",
        "Güvenlik yapılandırma hataları (misconfiguration)",
        ("CWE-16",),
        (A05,),
    ),
    # No default CWE. Most GraphQL-specific issues (introspection, depth and batching limits)
    # are configuration gaps (A05).
    _vc("graphql", "GraphQL-specific issues", "GraphQL", (), (A05,)),
    # CWE-1321 has no official mapping. Its parent CWE-915 maps to A08.
    _vc("prototype-pollution", "Prototype pollution", "Prototype pollution", ("CWE-1321",), (A08,)),
    # CWE-400 and CWE-1333 have no official mapping. A missing resource limit is a design
    # flaw (A04).
    _vc(
        "dos-redos",
        "ReDoS / resource exhaustion",
        "DoS / ReDoS",
        ("CWE-400", "CWE-1333"),
        (A04,),
    ),
    _vc(
        "request-smuggling-crlf-cache",
        "Request smuggling / CRLF / cache poisoning",
        "Request smuggling / CRLF / cache poisoning",
        ("CWE-444", "CWE-113"),
        (A03, A04),
    ),
    _vc(
        "webhook-replay",
        "Webhook signature / replay",
        "Webhook imzası / replay",
        ("CWE-345", "CWE-294"),
        (A07, A08),
    ),
    _vc(
        "rate-limit-bruteforce",
        "Rate limiting / brute force",
        "Rate limiting / brute force",
        ("CWE-307",),
        (A07,),
    ),
    _vc("llm-ai", "LLM / AI-specific", "LLM / AI güvenliği", (), (LLM01,)),
    # No OWASP Top 10 2021 category covers memory corruption.
    _vc(
        "memory-safety",
        "Memory safety",
        "Bellek güvenliği (memory safety)",
        ("CWE-787", "CWE-416"),
        (),
    ),
    # No OWASP Top 10 2021 category covers smart contracts.
    _vc("smart-contract", "Smart contracts", "Akıllı kontrat (smart contract)", (), ()),
    # CWE-926 has no official mapping. An exported component or a local IPC endpoint without
    # a caller check is an access control failure (A01).
    _vc(
        "mobile-desktop-ipc",
        "Mobile / desktop / local IPC",
        "Mobil / masaüstü / yerel IPC",
        ("CWE-926",),
        (A01,),
    ),
    # CWE-1395 is newer than the 2021 mapping. The class is A06 by definition.
    _vc(
        "vulnerable-dependency",
        "Vulnerable dependency (SCA)",
        "Zafiyetli bağımlılık (SCA)",
        ("CWE-1395",),
        (A06,),
    ),
    # CWE-506 has no official mapping. A malicious package is a third-party component (A06)
    # and breaks the integrity of the build (A08). ADR-0005, K.2.
    _vc(
        "malicious-dependency",
        "Malicious dependency",
        "Zararlı bağımlılık",
        ("CWE-506",),
        (A06, A08),
    ),
    _vc(
        "supply-chain-cicd",
        "Supply chain / CI-CD",
        "Tedarik zinciri / CI-CD",
        ("CWE-829",),
        (A08,),
    ),
    _vc(
        "iac-cloud-container",
        "IaC / cloud / container misconfiguration",
        "IaC / bulut / konteyner yapılandırması",
        ("CWE-16",),
        (A05,),
    ),
    # Not a security class.
    _vc("code-quality", "Non-security code quality", "Kod kalitesi (güvenlik dışı)", (), ()),
)

#: The class slugs in taxonomy order.
SLUGS: tuple[str, ...] = tuple(item.slug for item in CLASSES)

#: The classes of SCA records (``sca/vulns.json``): dependencies, not code. They never become
#: hunting units, deterministic verify tasks or PoC targets.
DEPENDENCY_CLASSES: frozenset[str] = frozenset({"vulnerable-dependency", "malicious-dependency"})

_BY_SLUG: Mapping[str, VulnClass] = MappingProxyType({item.slug: item for item in CLASSES})


def _default_owners() -> Mapping[str, str]:
    owners: dict[str, str] = {}
    for item in CLASSES:
        for cwe in item.cwe:
            owners.setdefault(cwe, item.slug)
    return MappingProxyType(owners)


# CWE -> the first class whose default CWE list contains it (ENGINE-SPEC 3).
_DEFAULT_OWNER: Mapping[str, str] = _default_owners()

# Extended CWE -> class map. Source: the "cwes" lists of the weakness families in
# third_party/codecrucible/prompts/core/audit_families.yaml, plus CWE-937 and CWE-1104.
# A CWE that is in a default list is not repeated here: the default list always wins.
# Each comment names the family and the reason for the choice.
EXTENDED_CWE_MAP: Mapping[str, str] = MappingProxyType(
    {
        # --- family "injection" (CWE-78, -89, -94, -943, -1336 are default CWE IDs) ---
        # CWE-74 is the generic injection parent. code-injection is the broadest
        # interpreter-injection class.
        "CWE-74": "code-injection",
        # Command injection and argument injection both reach a command line.
        "CWE-77": "os-command-injection",
        "CWE-88": "os-command-injection",
        # LDAP and XPath injection are injection into a query language, like SQL injection.
        "CWE-90": "sqli",
        "CWE-643": "sqli",
        # Eval injection and expression language injection evaluate attacker text as code.
        "CWE-95": "code-injection",
        "CWE-917": "code-injection",
        # --- family "output" (CWE-79 and CWE-113 are default CWE IDs) ---
        # Basic XSS and script in attributes are XSS variants.
        "CWE-80": "xss",
        "CWE-83": "xss",
        # Wrong output encoding: scanners report it for template auto-escape gaps (XSS).
        "CWE-116": "xss",
        # Log forging is CR/LF injection into a log line. The CRLF class owns CR/LF injection.
        "CWE-117": "request-smuggling-crlf-cache",
        # --- family "authorization" (CWE-639, -862, -915 are default CWE IDs) ---
        # CWE-284 is the default CWE of multi-tenant, so the default list wins for it.
        # Improper authorization, privilege management, incorrect authorization and forced
        # browsing are missing or wrong authorization checks.
        "CWE-285": "missing-authz",
        "CWE-269": "missing-authz",
        "CWE-863": "missing-authz",
        "CWE-425": "missing-authz",
        # Authorization bypass through a user-controlled key is IDOR.
        "CWE-566": "idor",
        # --- family "authentication" (CWE-287, -294, -307, -352 are default CWE IDs) ---
        # Alternate-path bypass, spoofing bypass, missing authentication, session fixation,
        # weak password rules, session expiry, unverified password change, weak password
        # recovery and weak authentication are authentication flaws.
        "CWE-288": "authn",
        "CWE-290": "authn",
        "CWE-306": "authn",
        "CWE-384": "authn",
        "CWE-521": "authn",
        "CWE-613": "authn",
        "CWE-620": "authn",
        "CWE-640": "authn",
        "CWE-1390": "authn",
        # --- family "parsing" (CWE-502, -611, -1321 are default CWE IDs) ---
        # XML entity expansion is an XML parser configuration flaw, like XXE.
        "CWE-776": "xxe",
        # Unsafe reflection lets the attacker select the class or code that runs.
        "CWE-470": "code-injection",
        # --- family "files" (CWE-22 and CWE-434 are default CWE IDs) ---
        # Relative and absolute traversal, link following and external control of a file
        # name are path traversal variants.
        "CWE-23": "path-traversal",
        "CWE-36": "path-traversal",
        "CWE-59": "path-traversal",
        "CWE-73": "path-traversal",
        # Files accessible to external parties: unauthorized file read, the "file read-write"
        # part of path-traversal.
        "CWE-552": "path-traversal",
        # --- family "network" (CWE-918 and CWE-601 are default CWE IDs) ---
        # An unintended proxy makes the server send requests for the attacker, like SSRF.
        "CWE-441": "ssrf",
        # --- family "secrets" (CWE-327, -347, -798 are default CWE IDs) ---
        # A hard-coded password or cryptographic key is a hardcoded secret.
        "CWE-259": "hardcoded-secrets",
        "CWE-321": "hardcoded-secrets",
        # Certificate validation, key strength, weak hashes, weak randomness, cleartext
        # transport, predictable salts and weak password hashing are cryptographic misuse.
        "CWE-295": "crypto",
        "CWE-326": "crypto",
        "CWE-328": "crypto",
        "CWE-330": "crypto",
        "CWE-338": "crypto",
        "CWE-319": "crypto",
        "CWE-760": "crypto",
        "CWE-916": "crypto",
        # Cleartext storage of sensitive data and unprotected credentials expose the data.
        "CWE-312": "sensitive-data-exposure",
        "CWE-522": "sensitive-data-exposure",
        # --- family "exposure" (CWE-16, -200, -532, -942 are default CWE IDs) ---
        # Error messages, debug output, system data and directory listings expose data.
        "CWE-209": "sensitive-data-exposure",
        "CWE-215": "sensitive-data-exposure",
        "CWE-497": "sensitive-data-exposure",
        "CWE-548": "sensitive-data-exposure",
        # Cookie flags, missing protection mechanisms (security headers) and clickjacking
        # protection are configuration settings.
        "CWE-614": "security-misconfig",
        "CWE-693": "security-misconfig",
        "CWE-1004": "security-misconfig",
        "CWE-1021": "security-misconfig",
        # --- family "concurrency" (CWE-362 and CWE-367 are default CWE IDs) ---
        "CWE-366": "race-condition",
        "CWE-820": "race-condition",
        "CWE-821": "race-condition",
        # --- family "memory" (CWE-416 and CWE-787 are default CWE IDs) ---
        # Buffer errors, out-of-bounds reads, index and size errors, format strings, integer
        # overflow and underflow, double free, NULL dereference and numeric conversion
        # errors: the family groups them as memory safety and integer errors.
        "CWE-119": "memory-safety",
        "CWE-120": "memory-safety",
        "CWE-121": "memory-safety",
        "CWE-122": "memory-safety",
        "CWE-125": "memory-safety",
        "CWE-129": "memory-safety",
        "CWE-131": "memory-safety",
        "CWE-134": "memory-safety",
        "CWE-190": "memory-safety",
        "CWE-191": "memory-safety",
        "CWE-415": "memory-safety",
        "CWE-476": "memory-safety",
        "CWE-681": "memory-safety",
        # --- family "resources" (CWE-400 and CWE-1333 are default CWE IDs) ---
        # Decompression bombs, uncontrolled recursion, unlimited allocation and excessive
        # iteration exhaust resources.
        "CWE-409": "dos-redos",
        "CWE-674": "dos-redos",
        "CWE-770": "dos-redos",
        "CWE-834": "dos-redos",
        # --- not in a family: vulnerable components (CWE-1395 is a default CWE ID) ---
        # CWE-937 (components with known vulnerabilities) and CWE-1104 (unmaintained
        # third-party components) are SCA findings.
        "CWE-937": "vulnerable-dependency",
        "CWE-1104": "vulnerable-dependency",
    }
)

# "CWE-89", "cwe-89", "CWE89", "CWE 89", "external/cwe/cwe-89", "CWE-89: description".
_PREFIXED_CWE = re.compile(r"(?:external/cwe/)?cwe[\s_:-]*([0-9]+)(?:$|[^\w])", re.IGNORECASE)
_BARE_CWE = re.compile(r"[0-9]+")


def normalize_cwe(value: object) -> str | None:
    """Return ``value`` as ``"CWE-<n>"``, or None when it is not a CWE reference.

    Accepted forms: ``CWE-89``, ``cwe-89``, ``89``, the integer ``89``,
    ``external/cwe/cwe-89`` and ``CWE-89: description``. Leading zeros are removed.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return f"CWE-{value}" if value > 0 else None
    if not isinstance(value, str):
        return None
    text = value.strip()
    match = _PREFIXED_CWE.match(text) or _BARE_CWE.fullmatch(text)
    if match is None:
        return None
    number = int(match.group(1) if match.re is _PREFIXED_CWE else match.group(0))
    return f"CWE-{number}" if number > 0 else None


def get_class(slug: str) -> VulnClass | None:
    """Return the class for ``slug``, or None for an unknown slug."""
    return _BY_SLUG.get(slug)


def class_for_cwe(cwe: str) -> str | None:
    """Return the class slug for a CWE ID, or None.

    The first class whose default CWE list contains the CWE wins. Else the extended map
    decides. ``cwe`` can have any form that :func:`normalize_cwe` accepts.
    """
    normalized = normalize_cwe(cwe)
    if normalized is None:
        return None
    return _DEFAULT_OWNER.get(normalized) or EXTENDED_CWE_MAP.get(normalized)


def owasp_for_class(slug: str) -> list[str]:
    """Return the OWASP categories of a class, or an empty list for an unknown slug."""
    item = _BY_SLUG.get(slug)
    return list(item.owasp) if item is not None else []
