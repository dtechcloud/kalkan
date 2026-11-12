# SPDX-License-Identifier: MIT
"""vacuum: OWASP API security rules on the OpenAPI documents of the target (ENGINE-SPEC 13,
ADR-0005 K.9).

Contract:

1. **Applies** when the target has an OpenAPI 3 or Swagger 2.0 document
   (:func:`kalkan.scanners.adapters._openapi.openapi_files`: detected by content) whose local
   references stay inside the target (:func:`kalkan.scanners.adapters._openapi.check_references`;
   vacuum 0.33.0 reads local files outside the target also with ``--remote=false``). A refused
   document is a scan gap (``skipped_files``); when every document is refused, the adapter is
   skipped with the first reason.
2. **Command line**, one run per document, checked against ``vacuum --help`` and ``vacuum
   spectral-report --help`` of the pinned 0.33.0 on 2026-10-25, working directory
   ``scans/.work/vacuum``::

       vacuum spectral-report --remote=false --no-update-check --no-style --no-pretty
           --config <work>/vacuum.conf.yaml --ruleset <work>/kalkan-owasp.yaml
           <absolute document> <work>/<part>.json

   - ``--remote=false``: no ``http``/``https`` reference is fetched (vacuum then reports it as
     unresolved; the status file lists the document as partly linted, ``partial_files``).
   - ``--no-update-check``: no release check. vacuum checks only when stderr is a terminal, and
     never for ``version``; the flag keeps it off in every case and keeps its cache file
     (``vacuum-update-check.json`` in the temporary folder) untouched.
   - ``--config``: an empty kalkan file, so no ``vacuum.conf.yaml`` of the working folder or of
     ``$XDG_CONFIG_HOME``/``~/.config`` is read (such a file can name rulesets, custom functions
     and ignore files). ``HOME`` and ``USERPROFILE`` name an empty folder (the default
     ``~/.config/changes-rules.yaml`` of the breaking-change rules); no ``VACUUM_*`` variable
     reaches the tool (minimal environment).
   - ``--ruleset``: :data:`RULESET`, the built-in OWASP rules only (``vacuum:owasp`` ``all``,
     ``vacuum:oas`` ``off``) plus ``oas2/oas3-operation-security-defined``: the documentation
     style rules of the default set are not security results. No ruleset of the target is read,
     and the ruleset extends nothing remote.
   - No ``--ignore-file``, no ``--functions``, no ``--base``, no ``--ext-refs``, no ``--fix``.
   - Exit code 0 writes the report. Exit code 2 is an input error: vacuum could not parse the
     document (``parse_errors``). When no document gives a report, the run fails (a broken
     ruleset gives exit code 2 for every document).
3. **Output**: :func:`report_to_sarif` converts the Spectral-format JSON report (1-based
   ``range`` lines and columns, ``source`` relative to the working folder or absolute for a
   referenced file) to SARIF: target-relative URIs, the source line as snippet, the class, CWE
   IDs and severity of :data:`RULES` (``kalkan-class``; an unknown rule is
   ``security-misconfig`` CWE-16 with the severity from the vacuum level). The
   ``resolving-references`` results are no security results: they mark the document as partly
   linted. A result outside the target is dropped (``outside_target``; the reference check
   makes it impossible).
4. **Suppressions** (ADR-0003): ``x-lint-ignore`` keys in the document stay effective; vacuum
   0.33.0 has no option to turn them off. The status file records them as honored and counts
   them (``inline_ignores``). The ignore files of the target are never passed.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Final

from kalkan.errors import KalkanError, ToolError
from kalkan.scanners.adapters import _openapi, _sources
from kalkan.scanners.adapters._cicd import RuleClass, sarif_document, sarif_result, sarif_rule
from kalkan.scanners.base import Invocation, ScanContext, ToolAdapter, part_path, work_dir
from kalkan.util.safe_io import atomic_write_json, atomic_write_text, read_bounded

__all__ = [
    "RULES",
    "RULESET",
    "VacuumAdapter",
    "report_to_sarif",
    "rule_info",
]

RULESET_NAME: Final = "kalkan-owasp.yaml"
CONFIG_NAME: Final = "vacuum.conf.yaml"
HOME_DIRNAME: Final = "home"
#: The kalkan ruleset (module docstring, point 2).
RULESET: Final = (
    "description: kalkan - the built-in OWASP API security rules of vacuum\n"
    "extends:\n"
    '  - [vacuum:oas, "off"]\n'
    "  - [vacuum:owasp, all]\n"
    "rules:\n"
    "  oas3-operation-security-defined: true\n"
    "  oas2-operation-security-defined: true\n"
)
UNRESOLVED_RULE: Final = "resolving-references"
MAX_REPORT_BYTES: Final = 50 * 1024 * 1024
_INFO_URI: Final = "https://quobix.com/vacuum/rules/owasp/"
_TOOL_URI: Final = "https://quobix.com/vacuum/"
_LEVELS: Final = {"high": "error", "medium": "warning", "low": "note", "info": "note"}
_VACUUM_SEVERITY: Final = {0: "medium", 1: "low", 2: "info", 3: "info"}
_IGNORE_KEY = re.compile(r"""["']?x-lint-ignore["']?\s*:""")

#: vacuum rule -> (class and CWE IDs, kalkan severity, title).
RULES: Final[dict[str, tuple[RuleClass, str, str]]] = {
    "owasp-protection-global-unsafe": (
        RuleClass("authn", ("CWE-306",)),
        "high",
        "Operation that changes data has no security requirement",
    ),
    "owasp-protection-global-unsafe-strict": (
        RuleClass("authn", ("CWE-306",)),
        "high",
        "Operation that changes data allows anonymous access",
    ),
    "owasp-protection-global-safe": (
        RuleClass("authn", ("CWE-306",)),
        "low",
        "Read operation has no security requirement",
    ),
    "oas3-operation-security-defined": (
        RuleClass("authn", ("CWE-287",)),
        "medium",
        "Security requirement names an undefined security scheme",
    ),
    "oas2-operation-security-defined": (
        RuleClass("authn", ("CWE-287",)),
        "medium",
        "Security requirement names an undefined security scheme",
    ),
    "owasp-no-http-basic": (
        RuleClass("authn", ("CWE-522",)),
        "medium",
        "HTTP Basic authentication",
    ),
    "owasp-auth-insecure-schemes": (
        RuleClass("authn", ("CWE-287",)),
        "medium",
        "Insecure HTTP authentication scheme",
    ),
    "owasp-jwt-best-practices": (
        RuleClass("jwt", ("CWE-347",)),
        "low",
        "JWT security scheme without RFC 8725 practices",
    ),
    "owasp-oauth-no-password": (
        RuleClass("oauth-oidc-saml", ("CWE-522",)),
        "medium",
        "OAuth2 password flow",
    ),
    "owasp-oauth-no-implicit": (
        RuleClass("oauth-oidc-saml", ("CWE-287",)),
        "medium",
        "OAuth2 implicit flow",
    ),
    "owasp-auth-urls-https": (
        RuleClass("crypto", ("CWE-319",)),
        "medium",
        "Authentication URL without TLS",
    ),
    "owasp-security-hosts-https-oas3": (
        RuleClass("crypto", ("CWE-319",)),
        "medium",
        "Server URL without TLS",
    ),
    "owasp-no-api-keys-in-url": (
        RuleClass("sensitive-data-exposure", ("CWE-598",)),
        "medium",
        "API key in the URL",
    ),
    "owasp-no-credentials-in-url": (
        RuleClass("sensitive-data-exposure", ("CWE-598",)),
        "medium",
        "Credential parameter in the URL",
    ),
    "owasp-no-numeric-ids": (
        RuleClass("idor", ("CWE-639",)),
        "low",
        "Guessable numeric resource ID",
    ),
    "owasp-rate-limit": (
        RuleClass("rate-limit-bruteforce", ("CWE-770",)),
        "low",
        "Response without rate limit headers",
    ),
    "owasp-rate-limit-retry-after": (
        RuleClass("rate-limit-bruteforce", ("CWE-770",)),
        "low",
        "429 response without Retry-After header",
    ),
    "owasp-define-error-responses-429": (
        RuleClass("rate-limit-bruteforce", ("CWE-770",)),
        "low",
        "Operation without a 429 response",
    ),
    "owasp-define-error-responses-401": (
        RuleClass("security-misconfig", ("CWE-16",)),
        "info",
        "Operation without a 401 response",
    ),
    "owasp-define-error-responses-500": (
        RuleClass("security-misconfig", ("CWE-16",)),
        "info",
        "Operation without a 500 response",
    ),
    "owasp-define-error-validation": (
        RuleClass("security-misconfig", ("CWE-20",)),
        "info",
        "Operation without a validation error response",
    ),
    "owasp-array-limit": (
        RuleClass("dos-redos", ("CWE-770",)),
        "low",
        "Array without maxItems",
    ),
    "owasp-string-limit": (
        RuleClass("dos-redos", ("CWE-770",)),
        "low",
        "String without maxLength",
    ),
    "owasp-integer-limit": (
        RuleClass("dos-redos", ("CWE-20",)),
        "low",
        "Integer without minimum and maximum",
    ),
    "owasp-string-restricted": (
        RuleClass("security-misconfig", ("CWE-20",)),
        "info",
        "String without format, pattern or enum",
    ),
    "owasp-integer-format": (
        RuleClass("security-misconfig", ("CWE-20",)),
        "info",
        "Integer without int32 or int64 format",
    ),
    "owasp-no-additionalProperties": (
        RuleClass("mass-assignment", ("CWE-915",)),
        "low",
        "Object accepts additional properties",
    ),
    "owasp-constrained-additionalProperties": (
        RuleClass("mass-assignment", ("CWE-915",)),
        "low",
        "Object accepts unbounded additional properties",
    ),
}


def rule_info(rule_id: str, vacuum_severity: object = None) -> tuple[RuleClass, str, str]:
    """Return the class, kalkan severity and title of a vacuum rule (module docstring, 3)."""
    if rule_id in RULES:
        return RULES[rule_id]
    severity = (
        _VACUUM_SEVERITY.get(vacuum_severity, "low") if isinstance(vacuum_severity, int) else "low"
    )
    return RuleClass("security-misconfig", ("CWE-16",)), severity, rule_id


def report_to_sarif(
    report: Any, *, target: Path, cwd: Path, version: str = ""
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Convert a Spectral-format vacuum report to SARIF (module docstring, point 3).

    Returns the SARIF document and the notes ``{"unresolved": int, "outside_target": int}``.
    Raises :class:`~kalkan.errors.ToolError` when ``report`` is not a list of results.
    """
    if not isinstance(report, list):
        raise ToolError("the vacuum report is not a JSON array")
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    notes = {"unresolved": 0, "outside_target": 0}
    for item in report:
        if not isinstance(item, dict):
            continue
        code = str(item.get("code") or "").strip()
        if not code:
            continue
        if code == UNRESOLVED_RULE:
            notes["unresolved"] += 1
            continue
        rel = _sources.target_relative(str(item.get("source") or ""), target, base=cwd)
        if rel is None:
            notes["outside_target"] += 1
            continue
        start, end = _range(item.get("range"))
        rule, severity, title = rule_info(code, item.get("severity"))
        if code not in rules:
            rules[code] = sarif_rule(code, rule, title=title, help_uri=_INFO_URI)
        path = item.get("path")
        properties: dict[str, Any] = {"severity": severity}
        if isinstance(path, list) and path:
            properties["json_path"] = ".".join(str(part) for part in path)
        results.append(
            sarif_result(
                code,
                str(item.get("message") or title),
                level=_LEVELS[severity],
                file=rel,
                start_line=start[0],
                end_line=end[0],
                start_column=start[1],
                snippet=_sources.read_line(target / rel, start[0]),
                properties=properties,
            )
        )
    doc = sarif_document("vacuum", version, _TOOL_URI, list(rules.values()), results)
    return doc, notes


def _range(value: Any) -> tuple[tuple[int, int | None], tuple[int | None, int | None]]:
    def point(raw: Any) -> tuple[int | None, int | None]:
        if not isinstance(raw, dict):
            return None, None
        line, char = raw.get("line"), raw.get("character")
        line = line if isinstance(line, int) and not isinstance(line, bool) and line >= 1 else None
        char = char if isinstance(char, int) and not isinstance(char, bool) and char >= 1 else None
        return line, char

    start = point(value.get("start")) if isinstance(value, dict) else (None, None)
    end = point(value.get("end")) if isinstance(value, dict) else (None, None)
    first = start[0] or 1
    return (first, start[1]), (end[0] if end[0] and end[0] >= first else first, end[1])


class VacuumAdapter(ToolAdapter):
    """``vacuum spectral-report`` with the OWASP rules per OpenAPI document (module docstring)."""

    name = "vacuum"
    tool = "vacuum"
    output = "sarif-file"
    output_dir = "scans"
    output_name = "vacuum.sarif"
    #: 0: report written; 2: vacuum could not parse the document (recorded, point 2).
    ok_exit_codes = (0, 2)
    timeout_seconds = 600

    def __init__(self) -> None:
        self._specs: list[str] = []
        self._checks: dict[str, _openapi.RefCheck] = {}
        self._refused: list[dict[str, str]] = []
        self._errors: list[str] = []
        self._unresolved: dict[str, int] = {}
        self._outside = 0
        self._done = 0
        self._seen = 0
        self._total = 0

    # --- discovery -------------------------------------------------------------------------

    def _discover(self, ctx: ScanContext) -> None:
        self._specs, self._checks, self._refused = [], {}, []
        for rel in _openapi.openapi_files(ctx.target_dir):
            check = _openapi.check_references(ctx.target_dir, rel)
            if check.ok:
                self._specs.append(rel)
                self._checks[rel] = check
            else:
                self._refused.append(
                    {"file": rel, "reason": check.problem, "where": check.where or rel}
                )

    def applies(self, ctx: ScanContext) -> tuple[bool, str]:
        self._discover(ctx)
        if self._specs:
            return True, ""
        if self._refused:
            first = self._refused[0]
            return False, (
                f"no OpenAPI document that vacuum may read: {len(self._refused)} refused, for "
                f"example {first['file']} ({first['reason']} in {first['where']})"
            )
        return False, "no OpenAPI or Swagger document in the target"

    # --- files and command lines -----------------------------------------------------------

    def work(self, ctx: ScanContext) -> Path:
        return work_dir(ctx.run_dir, self)

    def prepare(self, ctx: ScanContext, stage: Path) -> None:
        """Write the kalkan ruleset and the empty config file, create the empty home folder."""
        work = self.work(ctx)
        (work / HOME_DIRNAME).mkdir(parents=True, exist_ok=True)
        atomic_write_text(work / RULESET_NAME, RULESET)
        atomic_write_text(work / CONFIG_NAME, "")

    def env(self, ctx: ScanContext) -> dict[str, str]:
        home = str(self.work(ctx) / HOME_DIRNAME)
        return {"HOME": home, "USERPROFILE": home}

    def cwd(self, ctx: ScanContext) -> Path:
        return self.work(ctx)

    @staticmethod
    def report_path(out: Path) -> Path:
        """Return the JSON report that belongs to a staged SARIF part."""
        return out.with_suffix(".json")

    def arguments(self, ctx: ScanContext, out: Path, spec: str = "") -> list[str]:
        work = self.work(ctx)
        document = ctx.target_dir / (spec or (self._specs[0] if self._specs else ""))
        return [
            "spectral-report",
            "--remote=false",
            "--no-update-check",
            "--no-style",
            "--no-pretty",
            "--config",
            str(work / CONFIG_NAME),
            "--ruleset",
            str(work / RULESET_NAME),
            str(document),
            str(self.report_path(out)),
        ]

    def invocations(self, ctx: ScanContext, tool_path: Path, out: Path) -> list[Invocation]:
        self._discover(ctx)
        self._errors, self._unresolved, self._outside = [], {}, 0
        self._done = self._seen = 0
        self._total = len(self._specs)
        items = []
        for index, spec in enumerate(self._specs):
            target = out if len(self._specs) == 1 else part_path(out, index)
            argv = (str(tool_path), *self.arguments(ctx, target, spec))
            items.append(Invocation(argv, self.cwd(ctx), target, label=f"spec {spec}"))
        return items

    # --- results ---------------------------------------------------------------------------

    def after_run(self, ctx: ScanContext, item: Invocation) -> None:
        """Convert the JSON report of one document, or record a parse error (point 2)."""
        spec = item.label.removeprefix("spec ")
        report_path = self.report_path(item.output)
        self._seen += 1
        last = self._seen >= self._total
        if not report_path.is_file():
            self._errors.append(spec)
            if last and self._done == 0:
                raise ToolError("vacuum wrote no report for any OpenAPI document (exit code 2)")
            atomic_write_json(item.output, sarif_document("vacuum", "", _TOOL_URI, [], []))
            return
        try:
            report = json.loads(read_bounded(report_path, MAX_REPORT_BYTES))
        except (KalkanError, ValueError) as exc:
            raise ToolError(f"the vacuum report is not valid JSON: {exc}") from None
        doc, notes = report_to_sarif(report, target=ctx.target_dir, cwd=self.cwd(ctx))
        if notes["unresolved"]:
            self._unresolved[spec] = notes["unresolved"]
        self._outside += notes["outside_target"]
        self._done += 1
        atomic_write_json(item.output, doc)

    def status_details(
        self, ctx: ScanContext, stdout_log: Path, stderr_log: Path, outputs: list[Path]
    ) -> dict[str, Any]:
        """Record the documents, the refused ones, parse errors and inline ignores."""
        remote = {spec: check.remote for spec, check in self._checks.items() if check.remote}
        details: dict[str, Any] = {
            "documents": {"count": len(self._specs), "files": self._specs[:50]},
            "ruleset": "vacuum:owasp all, vacuum:oas off, oas2/oas3-operation-security-defined",
            "remote_references": "not fetched (--remote=false)",
        }
        skipped = [
            {"file": item["file"], "reason": f"references: {item['reason']} ({item['where']})"}
            for item in self._refused
        ] + [
            {"file": spec, "reason": "vacuum could not parse the document"} for spec in self._errors
        ]
        if skipped:
            reasons: dict[str, int] = {}
            for item in skipped:
                reasons[item["reason"]] = reasons.get(item["reason"], 0) + 1
            details["skipped_files"] = {
                "count": len(skipped),
                "reasons": reasons,
                "paths": [item["file"] for item in skipped[:50]],
                "truncated": len(skipped) > 50,
            }
        if self._errors:
            details["parse_errors"] = {"count": len(self._errors), "files": self._errors[:50]}
        partial = sorted(set(self._unresolved) | set(remote))
        if partial:
            details["partial_files"] = {
                "count": len(partial),
                "paths": partial[:50],
                "truncated": len(partial) > 50,
                "kinds": ["unresolved or remote references (vacuum lints the rest)"],
            }
            details["unresolved_references"] = {
                spec: {
                    "results": self._unresolved.get(spec, 0),
                    "remote": remote.get(spec, [])[:20],
                }
                for spec in partial[:50]
            }
        if self._outside:
            details["outside_target"] = self._outside
        ignores = self._inline_ignores(ctx)
        if ignores:
            details["inline_ignores"] = ignores
        return details

    def _inline_ignores(self, ctx: ScanContext) -> dict[str, Any]:
        files: dict[str, int] = {}
        for check in self._checks.values():
            for rel in check.files:
                text = _openapi.read_text(ctx.target_dir / rel)
                count = len(_IGNORE_KEY.findall(text or ""))
                if count:
                    files[rel] = count
        if not files:
            return {}
        return {"count": sum(files.values()), "files": dict(sorted(files.items())[:50])}

    def suppression_sources(self, ctx: ScanContext) -> tuple[list[str], list[str]]:
        return [
            "vacuum.conf.yaml, rulesets, custom functions and ignore files of the target and of "
            "the auditing machine (never read: --config names an empty kalkan file)",
        ], ["x-lint-ignore keys in the OpenAPI documents (no option in vacuum 0.33.0)"]
