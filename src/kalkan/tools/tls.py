# SPDX-License-Identifier: MIT
"""The TLS context of the downloads of kalkan (tools, the Go and RetireJS databases).

kalkan downloads with ``urllib``, which checks the server certificates against the CA file of
the OpenSSL that Python uses. Some Python builds for macOS have no such file:

- Python from python.org reads ``<framework>/etc/openssl/cert.pem``, which exists only after
  ``Install Certificates.command`` (part of that installer) ran.
- Some standalone builds (for example the Pythons of uv) name OpenSSL folders that do not exist
  on a Mac.

Every HTTPS download then fails with ``CERTIFICATE_VERIFY_FAILED`` (measured on two Macs on
2026-11-13, Python 3.13 and 3.14). The Go tools of kalkan do not have the problem: Go reads the
macOS keychains.

:func:`ssl_context` returns the default context of Python. On macOS, when that context has no
CA source, it also loads the root certificates of the macOS keychains (``security
find-certificate``): the system roots of Apple and the roots that an administrator added to
the System keychain (for example the CA of a company proxy). ``SSL_CERT_FILE`` and
``SSL_CERT_DIR`` stay the choice of the user: when one of them is set, kalkan loads nothing
else.
"""

from __future__ import annotations

import functools
import os
import ssl
import subprocess
import sys
from collections.abc import Callable, Mapping

#: The keychains whose certificates kalkan trusts on macOS when Python has no CA file.
MACOS_KEYCHAINS = (
    "/System/Library/Keychains/SystemRootCertificates.keychain",
    "/Library/Keychains/System.keychain",
)
SECURITY = "/usr/bin/security"
SECURITY_TIMEOUT_SECONDS = 30

#: What the error of a failed certificate check says (``ssl.SSLCertVerificationError``).
VERIFY_FAILED = "CERTIFICATE_VERIFY_FAILED"
CERTIFICATE_HINT = (
    "the server certificate could not be checked. Set SSL_CERT_FILE to a CA bundle (behind a "
    "company proxy: the bundle with the CA of the proxy). On macOS with Python from "
    "python.org, you can also run 'Install Certificates.command' in the Python folder of "
    "/Applications."
)

PemReader = Callable[[str], str]


def has_ca_source(paths: ssl.DefaultVerifyPaths | None = None) -> bool:
    """Return True when the default OpenSSL paths of Python name a CA file or a CA folder."""
    paths = paths or ssl.get_default_verify_paths()
    if paths.cafile and os.path.isfile(paths.cafile):
        return True
    if paths.capath and os.path.isdir(paths.capath):
        try:
            return any(os.scandir(paths.capath))
        except OSError:
            return False
    return False


def _security_pem(keychain: str) -> str:
    """Return the certificates of one macOS keychain as PEM text ('' when it cannot be read)."""
    try:
        proc = subprocess.run(
            [SECURITY, "find-certificate", "-a", "-p", keychain],
            capture_output=True,
            text=True,
            timeout=SECURITY_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return proc.stdout if proc.returncode == 0 else ""


def macos_roots(read: PemReader | None = None) -> list[str]:
    """Return the PEM certificates of each keychain of :data:`MACOS_KEYCHAINS` that has some."""
    reader = read or _security_pem
    return [pem for pem in (reader(keychain) for keychain in MACOS_KEYCHAINS) if pem.strip()]


def needs_macos_roots(
    *,
    platform: str | None = None,
    environ: Mapping[str, str] | None = None,
    paths: ssl.DefaultVerifyPaths | None = None,
) -> bool:
    """True on macOS when neither the user (``SSL_CERT_FILE``, ``SSL_CERT_DIR``) nor Python
    names a CA source."""
    if (platform or sys.platform) != "darwin":
        return False
    env = os.environ if environ is None else environ
    if env.get("SSL_CERT_FILE") or env.get("SSL_CERT_DIR"):
        return False
    return not has_ca_source(paths)


def build_context(
    *,
    platform: str | None = None,
    environ: Mapping[str, str] | None = None,
    paths: ssl.DefaultVerifyPaths | None = None,
    read: PemReader | None = None,
) -> ssl.SSLContext:
    """Return a new default context, with the macOS roots when :func:`needs_macos_roots`.

    Each keychain loads on its own: a certificate that OpenSSL cannot read in one keychain
    does not drop the other one. When nothing loads, the downloads report the failed check.
    """
    context = ssl.create_default_context()
    if needs_macos_roots(platform=platform, environ=environ, paths=paths):
        for pem in macos_roots(read):
            try:
                context.load_verify_locations(cadata=pem)
            except (ssl.SSLError, ValueError):
                continue
    return context


@functools.cache
def ssl_context() -> ssl.SSLContext:
    """Return the TLS context of every kalkan download (module docstring); built once."""
    return build_context()


def explain(error: object) -> str:
    """Return ``error`` as text, with :data:`CERTIFICATE_HINT` after a failed certificate check."""
    text = str(error)
    return f"{text}; {CERTIFICATE_HINT}" if VERIFY_FAILED in text else text
