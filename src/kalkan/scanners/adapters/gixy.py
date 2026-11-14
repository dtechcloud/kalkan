# SPDX-License-Identifier: MIT
"""gixy scan of the nginx configuration files (ENGINE-SPEC 13).

gixy is the maintained fork of yandex/gixy (PyPI ``gixy-ng``, MPL-2.0), installed with pip into
the tool venv. Command line, checked against ``gixy --help`` and the Python API of the pinned
version 0.2.55 (2026-10-25), in batches of :data:`~kalkan.scanners.adapters._sources.BATCH_SIZE`
files::

    <tool venv python> -I -X utf8 -c <LAUNCHER> <run>/scans/.work/gixy/<part>.json <file> [...]

1. Files (:func:`nginx_configs`): ``nginx.conf``, and ``*.conf``, ``*.conf.template``,
   ``*.nginx``, ``*.vhost`` files and files without an extension in ``sites-available``,
   ``sites-enabled``, ``conf.d`` or ``nginx`` folders whose text has an nginx block
   (``http {``, ``server {``, ``location ... {``, ``upstream ... {``, ``events {``); vendored
   folders are left out (:mod:`kalkan.scanners.adapters._sources`).
2. :data:`LAUNCHER` runs gixy through its Python API (``gixy.core.manager.Manager``), one file at
   a time, and writes one JSON record per issue with every directive location. The ``gixy``
   command groups equal issues of a file into one report that names only the first location
   (two vulnerable ``alias`` blocks give one result); the API keeps each one. The launcher runs
   in the tool venv Python next to the ``gixy`` entry point, in isolated mode (``-I``) with
   UTF-8 I/O. A parse error of one file is recorded (``errors``), the others go on.
3. ``Config(allow_includes=False, vars_dirs=None)``: gixy follows no ``include`` (the same as
   ``--disable-includes``). Every nginx file of the target is scanned on its own, and an
   ``include`` with an absolute path would make gixy read files of the auditing machine
   (``include /etc/nginx/mime.types``; checked). No variable policy folder is read; the built-in
   catalog of gixy applies. gixy 0.2.55 reads variable folders only from ``vars_dirs``; 0.2.58
   also reads the folders of the machine (``/usr/share/gixy/vars.d``, ``/etc/gixy/vars.d``)
   unless ``load_default_vars`` is False, so the launcher passes that option whenever ``Config``
   has it. The launcher reads no gixy config file (``/etc/gixy/gixy.cfg``,
   ``~/.config/gixy/gixy.conf``) and no ``GIXY_*`` variable, and it never applies fixes. Every
   check runs; ``nginx_cves`` stays silent without an nginx version.
4. Offline: gixy 0.2.55 has no network code (no update check, no telemetry; the ReDoS check
   with ``redoctor`` needs the ``deep`` extra, which kalkan does not install). Checked with the
   proxy trap: zero connections.

Without the tool venv Python (a gixy from PATH with ``--allow-path-tools``) the adapter runs
``gixy -f json -o <part>.json --disable-includes <file> [...]``, which groups equal issues; the
status file records the mode (``mode``).

Mapping (:data:`PLUGINS`): ``ssrf`` gives ``ssrf`` (CWE-918); ``alias_traversal`` and
``proxy_pass_normalized`` ``path-traversal`` (CWE-22), ``filesystem_root_exposure``
``path-traversal`` (CWE-552); ``http_splitting`` ``request-smuggling-crlf-cache`` (CWE-113);
``origins`` ``cors`` (CWE-942); ``allow_without_deny`` and ``return_bypasses_allow_deny``
``missing-authz`` (CWE-862); ``status_page_exposed`` and ``version_disclosure``
``sensitive-data-exposure`` (CWE-200); ``weak_ssl_tls`` and ``ssl_ecdh_curve`` ``crypto``
(CWE-327); ``regex_redos`` ``dos-redos`` (CWE-1333); ``nginx_cves`` ``vulnerable-dependency``;
the header, host and resolver checks and every unknown check ``security-misconfig`` (CWE-16,
CWE-693). The SARIF level follows the gixy severity (HIGH ``error``, MEDIUM ``warning``, LOW
and UNSPECIFIED ``note``), except for the tuning checks of :data:`LOW_IMPACT` (for example
``version_disclosure``, which gixy rates HIGH for a missing ``server_tokens off``), which give
``note``.

Suppressions (ADR-0003): gixy 0.2.55 has no inline suppression comment. Its config files and
``GIXY_*`` variables belong to the auditing machine and are never read.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path, PurePosixPath
from typing import Any, Final

from kalkan.errors import KalkanError, ToolError
from kalkan.scanners.adapters import _sources
from kalkan.scanners.base import (
    PYTHON_TOOL_ENV,
    Invocation,
    ScanContext,
    ToolAdapter,
    part_path,
)
from kalkan.util.safe_io import atomic_write_json, read_bounded

__all__ = [
    "LAUNCHER",
    "LOW_IMPACT",
    "PLUGINS",
    "GixyAdapter",
    "is_nginx_config",
    "issues_to_sarif",
    "nginx_configs",
]

#: Python code that runs gixy without its command line: ``sys.argv[1]`` is the JSON output,
#: the rest are nginx files.
LAUNCHER: Final = (
    "import inspect, json, sys\n"
    "import gixy\n"
    "from gixy.core.config import Config\n"
    "from gixy.core.manager import Manager\n"
    "options = {'allow_includes': False, 'vars_dirs': None}\n"
    "if 'load_default_vars' in inspect.signature(Config).parameters:\n"
    "    options['load_default_vars'] = False\n"
    "config = Config(**options)\n"
    "issues, errors = [], []\n"
    "for path in sys.argv[2:]:\n"
    "    try:\n"
    "        with Manager(config=config) as manager:\n"
    "            with open(path, 'rb') as handle:\n"
    "                manager.audit(path, handle)\n"
    "            for plugin in manager.results:\n"
    "                for issue in plugin.issues:\n"
    "                    issues.append({\n"
    "                        'path': path,\n"
    "                        'plugin': plugin.name,\n"
    "                        'severity': issue.severity or plugin.severity,\n"
    "                        'summary': issue.summary or plugin.summary,\n"
    "                        'description': issue.description or plugin.description,\n"
    "                        'reason': issue.reason or '',\n"
    "                        'help_url': issue.help_url or plugin.help_url,\n"
    "                        'places': [\n"
    "                            {'file': getattr(d, 'file', None),\n"
    "                             'line': getattr(d, 'line', None),\n"
    "                             'text': str(d).split('\\n', 1)[0]}\n"
    "                            for d in issue.directives\n"
    "                        ],\n"
    "                    })\n"
    "    except Exception as exc:\n"
    "        errors.append({'path': path, 'error': f'{type(exc).__name__}: {exc}'})\n"
    "with open(sys.argv[1], 'w', encoding='utf-8') as handle:\n"
    "    json.dump({'gixy_version': gixy.version, 'issues': issues, 'errors': errors}, handle)\n"
)

#: gixy check -> (class, CWE IDs). The first CWE decides the kalkan class.
PLUGINS: Final[dict[str, tuple[str, tuple[str, ...]]]] = {
    "ssrf": ("ssrf", ("CWE-918",)),
    "alias_traversal": ("path-traversal", ("CWE-22",)),
    "proxy_pass_normalized": ("path-traversal", ("CWE-22",)),
    "filesystem_root_exposure": ("path-traversal", ("CWE-552",)),
    "http_splitting": ("request-smuggling-crlf-cache", ("CWE-113",)),
    "origins": ("cors", ("CWE-942",)),
    "allow_without_deny": ("missing-authz", ("CWE-862",)),
    "return_bypasses_allow_deny": ("missing-authz", ("CWE-862",)),
    "status_page_exposed": ("sensitive-data-exposure", ("CWE-200",)),
    "version_disclosure": ("sensitive-data-exposure", ("CWE-200",)),
    "weak_ssl_tls": ("crypto", ("CWE-327",)),
    "ssl_ecdh_curve": ("crypto", ("CWE-327",)),
    "regex_redos": ("dos-redos", ("CWE-1333",)),
    "nginx_cves": ("vulnerable-dependency", ("CWE-1395",)),
    "host_spoofing": ("security-misconfig", ("CWE-16",)),
    "add_header_redefinition": ("security-misconfig", ("CWE-693",)),
    "add_header_multiline": ("security-misconfig", ("CWE-16",)),
    "add_header_content_type": ("security-misconfig", ("CWE-16",)),
    "hsts_header": ("security-misconfig", ("CWE-693",)),
    "valid_referers": ("security-misconfig", ("CWE-16",)),
    "unanchored_regex": ("security-misconfig", ("CWE-16",)),
    "invalid_regex": ("security-misconfig", ("CWE-16",)),
    "resolver_external": ("security-misconfig", ("CWE-16",)),
}
DEFAULT_PLUGIN: Final = ("security-misconfig", ("CWE-16",))
#: Tuning and correctness checks: reported with the level ``note`` whatever gixy says.
LOW_IMPACT: Final = frozenset(
    {
        "version_disclosure",
        "worker_rlimit_nofile_vs_connections",
        "low_keepalive_requests",
        "error_log_off",
        "default_server_flag",
        "missing_resolver",
        "hash_without_default",
        "if_is_evil",
        "try_files_is_evil_too",
        "regex_exact_match",
        "ssl_stapling_letsencrypt",
        "ssl_stapling_without_resolver",
        "http2_misdirected_request",
        "quic_bpf_reuseport",
    }
)
_LEVELS: Final = {"HIGH": "error", "MEDIUM": "warning", "LOW": "note", "UNSPECIFIED": "note"}
#: Folders whose files are nginx configs even without the ``.conf`` extension.
CONFIG_FOLDERS: Final = frozenset({"sites-available", "sites-enabled", "conf.d", "nginx"})
SUFFIXES: Final = (".conf", ".conf.template", ".nginx", ".vhost")
MAX_CONFIG_BYTES: Final = 1024 * 1024
MAX_OUTPUT_BYTES: Final = 50 * 1024 * 1024
_BLOCK = re.compile(
    # Possessive repeats: "location" and a run of spaces backtracked cubically (2,000 spaces took
    # 8.8 s; self-audit of 2026-11-13). [^{;\n]*+ already takes the spaces before the brace.
    r"^[ \t]*+(?:http|events|server|location\s[^{;\n]*+|upstream\s++[^{;\s]++|stream)\s*+\{",
    re.MULTILINE,
)


def is_nginx_config(target: Path, rel: str) -> bool:
    """Return True for an nginx configuration file (module docstring, item 1)."""
    path = PurePosixPath(rel)
    name = path.name.lower()
    folders = {part.lower() for part in path.parts[:-1]}
    if name == "nginx.conf":
        return True
    if not (name.endswith(SUFFIXES) or ("." not in name and folders & CONFIG_FOLDERS)):
        return False
    try:
        text = read_bounded(target / rel, MAX_CONFIG_BYTES).decode("utf-8", errors="replace")
    except (KalkanError, OSError):
        return False
    return _BLOCK.search(text) is not None


def nginx_configs(target: Path) -> list[str]:
    """Return the target-relative paths of the nginx configuration files, sorted."""
    return _sources.source_files(target, lambda rel: is_nginx_config(target, rel))


def launcher_python(tool_path: Path) -> Path | None:
    """Return the tool venv Python next to the gixy entry point, or None."""
    name = "python.exe" if os.name == "nt" else "python"
    python = Path(tool_path).parent / name
    return python if python.is_file() else None


def _place(place: dict[str, Any], target: Path, scanned: str | None) -> tuple[str, int] | None:
    line = place.get("line")
    if not isinstance(line, int) or isinstance(line, bool) or line < 1:
        return None
    rel = _sources.target_relative(str(place.get("file") or ""), target)
    if rel is None:
        rel = scanned  # an nginx -T dump names files that are not in the target
    return (rel, line) if rel else None


def _location(target: Path, rel: str, line: int, fallback: str) -> dict[str, Any]:
    text = _sources.read_line(target / rel, line) or fallback
    region: dict[str, Any] = {"startLine": line, "endLine": line}
    if text.strip():
        region["snippet"] = {"text": text}
    return {"physicalLocation": {"artifactLocation": {"uri": rel}, "region": region}}


def issues_to_sarif(
    issues: list[dict[str, Any]], *, target: Path, version: str = ""
) -> dict[str, Any]:
    """Convert gixy issue records (:data:`LAUNCHER`, or the grouped ``gixy -f json`` report) to
    SARIF: one result per issue at its first directive location, the other locations as
    related locations."""
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for issue in issues:
        if not isinstance(issue, dict):
            continue
        plugin = str(issue.get("plugin") or "").strip()
        if not plugin:
            continue
        scanned = _sources.target_relative(str(issue.get("path") or ""), target)
        places = issue.get("places")
        if not isinstance(places, list):  # the grouped report of the gixy command
            places = [{"file": issue.get("file") or issue.get("path"), "line": issue.get("line")}]
        located: list[tuple[str, int, str]] = []
        for place in places:
            if isinstance(place, dict):
                found = _place(place, target, scanned)
                if found and (found[0], found[1]) not in {(r, n) for r, n, _ in located}:
                    located.append((*found, str(place.get("text") or "")))
        if not located:
            continue
        vuln_class, cwes = PLUGINS.get(plugin, DEFAULT_PLUGIN)
        summary = str(issue.get("summary") or plugin)
        if plugin not in rules:
            rule: dict[str, Any] = {
                "id": plugin,
                "name": plugin,
                "shortDescription": {"text": summary},
                "properties": {
                    "tags": ["security", *(f"external/cwe/cwe-{cwe[4:]}" for cwe in cwes)]
                },
            }
            if issue.get("description"):
                rule["fullDescription"] = {"text": str(issue["description"])}
            help_url = issue.get("help_url") or issue.get("reference")
            if help_url:
                rule["helpUri"] = str(help_url)
            rules[plugin] = rule
        severity = str(issue.get("severity") or "UNSPECIFIED").upper()
        level = "note" if plugin in LOW_IMPACT else _LEVELS.get(severity, "note")
        reason = str(issue.get("reason") or "").strip()
        rel, line, text = located[0]
        result: dict[str, Any] = {
            "ruleId": plugin,
            "level": level,
            "message": {"text": f"{summary} {reason}".strip()},
            "locations": [_location(target, rel, line, text)],
            "properties": {"gixy_severity": severity, "kalkan_class": vuln_class},
        }
        related = [_location(target, r, n, t) for r, n, t in located[1:]]
        if related:
            result["relatedLocations"] = related
        results.append(result)
    driver: dict[str, Any] = {
        "name": "gixy",
        "informationUri": "https://github.com/dvershinin/gixy",
        "rules": list(rules.values()),
    }
    if version:
        driver["version"] = version
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": driver}, "results": results}],
    }


class GixyAdapter(ToolAdapter):
    """gixy over every nginx configuration file, through its Python API."""

    name = "gixy"
    tool = "gixy"
    output = "sarif-file"
    output_dir = "scans"
    output_name = "gixy.sarif"
    #: 0: the launcher finished (or the command found nothing); 1: the command found issues.
    #: A crash of the launcher also exits with 1, and then the missing report fails the run.
    ok_exit_codes = (0, 1)
    timeout_seconds = 600

    def __init__(self) -> None:
        self._launcher_used: bool | None = None
        self._errors: list[dict[str, str]] = []

    def applies(self, ctx: ScanContext) -> tuple[bool, str]:
        if not nginx_configs(ctx.target_dir):
            return False, "no nginx configuration found in the target"
        return True, ""

    def env(self, ctx: ScanContext) -> dict[str, str]:
        return dict(PYTHON_TOOL_ENV)

    @staticmethod
    def report_path(out: Path) -> Path:
        """Return the JSON report of the launcher that belongs to a staged SARIF output."""
        return out.with_suffix(".json")

    def _command(self, tool_path: Path, out: Path, files: list[str], ctx: ScanContext) -> list[str]:
        paths = [str(ctx.target_dir / rel) for rel in files]
        python = launcher_python(tool_path)
        report = str(self.report_path(out))
        if python is None:
            return [str(tool_path), "-f", "json", "-o", report, "--disable-includes", *paths]
        return [str(python), "-I", "-X", "utf8", "-c", LAUNCHER, report, *paths]

    def command(self, ctx: ScanContext, tool_path: Path, out: Path) -> list[str]:
        return self._command(tool_path, out, nginx_configs(ctx.target_dir), ctx)

    def invocations(self, ctx: ScanContext, tool_path: Path, out: Path) -> list[Invocation]:
        self._launcher_used = launcher_python(tool_path) is not None
        self._errors = []
        groups = list(_sources.batches(nginx_configs(ctx.target_dir)))
        items: list[Invocation] = []
        for index, batch in enumerate(groups):
            target = out if len(groups) == 1 else part_path(out, index)
            first = index * _sources.BATCH_SIZE + 1
            label = f"files {first}-{first + len(batch) - 1}"
            argv = tuple(self._command(tool_path, target, batch, ctx))
            items.append(Invocation(argv, self.cwd(ctx), target, label=label))
        return items

    def after_run(self, ctx: ScanContext, item: Invocation) -> None:
        """Convert the JSON report of one run into the SARIF output ``item.output``."""
        report_path = self.report_path(item.output)
        if not report_path.is_file():
            raise ToolError(f"no gixy report {report_path.name}")
        try:
            data = json.loads(read_bounded(report_path, MAX_OUTPUT_BYTES))
        except (KalkanError, ValueError) as exc:
            raise ToolError(f"the gixy report is not valid JSON: {exc}") from None
        if isinstance(data, dict):  # the launcher
            issues = data.get("issues") if isinstance(data.get("issues"), list) else []
            version = str(data.get("gixy_version") or "")
            for error in data.get("errors") or []:
                if isinstance(error, dict):
                    rel = _sources.target_relative(str(error.get("path") or ""), ctx.target_dir)
                    self._errors.append({"file": rel or "", "error": str(error.get("error"))})
        elif isinstance(data, list):  # the gixy command (grouped issues)
            issues, version = data, ""
        else:
            raise ToolError("the gixy report is neither a launcher record nor an issue list")
        atomic_write_json(
            item.output, issues_to_sarif(issues, target=ctx.target_dir, version=version)
        )

    def status_details(
        self, ctx: ScanContext, stdout_log: Path, stderr_log: Path, outputs: list[Path]
    ) -> dict[str, Any]:
        """Record the mode and the files that gixy could not parse."""
        mode = (
            "python API, one result per issue"
            if self._launcher_used
            else ("gixy command, equal issues of a file grouped")
        )
        details: dict[str, Any] = {"mode": mode, "includes": "not followed"}
        if self._errors:
            details["parse_errors"] = {
                "count": len(self._errors),
                "files": self._errors[:50],
            }
        return details

    def suppression_sources(self, ctx: ScanContext) -> tuple[list[str], list[str]]:
        return [
            "gixy config files and GIXY_* variables of the auditing machine (never read)",
        ], []
