# SPDX-License-Identifier: MIT
"""Kingfisher secret scan of the target copy and of the git history (ENGINE-SPEC 13).

The second secrets engine besides Gitleaks (ADR-0005). Command lines, checked against
``kingfisher --help`` and ``kingfisher scan --help`` of the pinned version 2.11.1::

    kingfisher scan <target> --no-update-check --quiet --no-validate --redact --no-ignore
        --confidence medium --no-rule-cache --git-history none --no-dedup
        --format json --output <run>/scans/.work/kingfisher/kingfisher.json

    kingfisher scan <git folder of <run>/source> --no-update-check --quiet --no-validate
        --redact --no-ignore --confidence medium --no-rule-cache
        --format json --output <run>/scans/.work/kingfisher-history/kingfisher-history.json

1. Offline (docs/SECURITY.md, promise 3), in every mode: ``--no-validate`` turns off the
   validation of found secrets against the live services of their providers, and
   ``--no-update-check`` turns off the release check (a request to ``api.github.com`` at start
   and at exit). Kingfisher 2.11.1 has no telemetry. Checked with the proxy trap: zero
   connections with both flags; without ``--no-update-check`` the trap saw
   ``CONNECT api.github.com:443``, and with validation on a made-up GitHub token was sent to
   ``api.github.com``.
2. Secret values never reach a kalkan file. ``--redact`` makes Kingfisher write every matched
   value and every validation response as ``[REDACTED:<salted hash>]`` (the hash changes with
   every run). The JSON report stays in the work folder: :meth:`KingfisherAdapter.after_run`
   checks that every snippet is redacted (a value that is not fails the run), writes the
   kalkan SARIF and deletes the report; :meth:`KingfisherAdapter.status_details` deletes it
   after a failed run too. The kalkan SARIF holds no value, no Kingfisher fingerprint (an
   XXH3-64 hash of the value and its offsets, which would let anyone confirm a guessed weak
   password) and no author or e-mail of a commit: the snippet is ``REDACTED``, or ``REDACTED
   (commit <12 hex>)`` for the history. ``--quiet`` keeps the logs free of findings.
3. Other options: ``--confidence medium`` is the Kingfisher default, written out so that a
   new default cannot change the results (``low`` adds generic patterns, mostly noise).
   ``--no-rule-cache``: without it Kingfisher writes its compiled rule database to
   ``%LOCALAPPDATA%\\Kingfisher`` or ``~/.cache``, outside the run folder; compiling takes about
   5 s per run. The tree scan adds ``--git-history none`` (the target copy has no ``.git``
   folder) and ``--no-dedup`` (every file that holds a credential is a place to fix; the
   default reports one location per credential). The history scan keeps the default
   deduplication: one finding per credential, not one per commit.
4. The history engine (``kingfisher-history``) reads only the private history copy of the run
   (``<run>/source``, docs/ENGINE-SPEC.md section 10), like ``gitleaks-history``: the git
   folder of a URL clone or the bare mirror of a local work tree, never the original folder.
   Kingfisher reads the objects with its own git library: it needs no git process (checked:
   the scan works with a PATH without git), so no textconv or other program of the repository
   config can run. Commit metadata stays on: without it Kingfisher names the object file, not
   the path in the repository.

Suppressions (ADR-0003), checked with Kingfisher 2.11.1:

- ``--no-ignore`` turns off the inline ``kingfisher:ignore`` directives. With
  ``honor_suppressions`` it is left out.
- Kingfisher reads no project config without ``--config`` (``kingfisher.yaml`` of the target is
  not loaded), no baseline without ``--baseline-file`` and no ``.gitignore`` of the target.
- Its rules drop matches with placeholder words (``ignore_if_contains``); that is part of the
  built-in rules, not of the target.

Output: Kingfisher's SARIF is experimental and holds absolute paths, so the adapter reads the
JSON report and writes SARIF itself (:func:`json_to_sarif`): one result per finding with the
rule ID (for example ``betterleaks.private-key``), a short title, the target-relative path,
the line and column range, the level from the confidence (high: ``error``, medium:
``warning``, low: ``note``) and the tags ``security`` and ``external/cwe/cwe-798`` (class
``hardcoded-secrets``). Kingfisher also reads archives of the target (two levels deep, with
its own size limits); a finding in an archive names the member after ``!``
(``dist/bundle.zip!conf/app.env``, checked). Exit codes: 0 (no findings) and 200 (findings).
205 means validated findings, which needs the network, so it fails the run.
"""

from __future__ import annotations

import contextlib
import json
import re
from pathlib import Path
from typing import Any, Final

from kalkan.errors import KalkanError, ToolError, UnsafeInputError
from kalkan.scanners.adapters import _sources
from kalkan.scanners.adapters.gitleaks import history_git_dir
from kalkan.scanners.base import MANIFEST_NAME, Invocation, ScanContext, ToolAdapter, work_dir
from kalkan.util.paths import is_safe_relative_path
from kalkan.util.safe_io import atomic_write_json, read_bounded

__all__ = [
    "CWE",
    "REDACTED",
    "KingfisherAdapter",
    "KingfisherHistoryAdapter",
    "json_to_sarif",
]

#: The flags of both engines that keep Kingfisher offline and the values out of its report.
OFFLINE_FLAGS: Final = ("--no-update-check", "--quiet", "--no-validate", "--redact")
#: The snippet text of every kalkan SARIF result.
REDACTED: Final = "REDACTED"
#: Every Kingfisher result is a hardcoded credential.
CWE: Final = "CWE-798"
MAX_REPORT_BYTES: Final = 50 * 1024 * 1024
_REDACTED_VALUE = re.compile(r"^\[REDACTED(?::[0-9A-Fa-f]*)?\]$")
_LEVELS: Final = {"high": "error", "medium": "warning", "low": "note"}
_ACRONYMS: Final = frozenset(
    {"api", "aws", "gcp", "jwt", "uri", "url", "ssh", "pat", "id", "pgp", "rsa", "dsa", "npm"}
)


def json_report_path(sarif_out: Path) -> Path:
    """Return the JSON report path that belongs to the staged SARIF output."""
    return sarif_out.with_suffix(".json")


def _title(rule: dict[str, Any], rule_id: str) -> str:
    name = str(rule.get("name") or rule_id.rsplit(".", 1)[-1])
    words = [w.upper() if w in _ACRONYMS else w for w in name.replace("_", "-").split("-") if w]
    text = " ".join(words)
    return text[:1].upper() + text[1:] if text else rule_id


def _is_redacted(value: object) -> bool:
    return value in (None, "") or (isinstance(value, str) and bool(_REDACTED_VALUE.match(value)))


def _int(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def json_to_sarif(
    report: dict[str, Any], *, target: Path, history: bool, version: str = ""
) -> dict[str, Any]:
    """Convert a Kingfisher JSON report to a kalkan SARIF 2.1.0 document.

    Raises :class:`~kalkan.errors.ToolError` when the report is not a Kingfisher report or when
    a finding carries a value that is not redacted. Findings outside the target (tree) or with
    an unsafe repository path (history) are skipped and counted in the run properties.
    """
    if not isinstance(report, dict) or not isinstance(report.get("findings"), list):
        raise ToolError("the Kingfisher report is not a JSON object with a 'findings' list")
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    skipped = 0
    for item in report["findings"]:
        if not isinstance(item, dict):
            continue
        rule = item.get("rule") if isinstance(item.get("rule"), dict) else {}
        finding = item.get("finding") if isinstance(item.get("finding"), dict) else {}
        validation = (
            finding.get("validation") if isinstance(finding.get("validation"), dict) else {}
        )
        if not _is_redacted(finding.get("snippet")) or not _is_redacted(validation.get("response")):
            raise ToolError("the Kingfisher report holds a value that is not redacted")
        rule_id = str(rule.get("id") or "").strip()
        if not rule_id:
            continue
        git = finding.get("git_metadata") if isinstance(finding.get("git_metadata"), dict) else {}
        commit = git.get("commit") if isinstance(git.get("commit"), dict) else {}
        file_info = git.get("file") if isinstance(git.get("file"), dict) else {}
        if history:
            path = str(file_info.get("path") or finding.get("path") or "").replace("\\", "/")
            uri = path if is_safe_relative_path(path) else None
        else:
            uri = _sources.target_relative(str(finding.get("path") or ""), target)
        if not uri:
            skipped += 1
            continue
        if rule_id not in rules:
            description = str(rule.get("description") or _title(rule, rule_id))
            rules[rule_id] = {
                "id": rule_id,
                "name": str(rule.get("name") or rule_id),
                "shortDescription": {"text": _title(rule, rule_id)},
                "fullDescription": {"text": description},
                "properties": {"tags": ["security", "secret", f"external/cwe/cwe-{CWE[4:]}"]},
            }
        confidence = str(finding.get("confidence") or "").lower()
        sha = str(commit.get("id") or "")
        snippet = f"{REDACTED} (commit {sha[:12]})" if history and sha else REDACTED
        region: dict[str, Any] = {"snippet": {"text": snippet}}
        line = _int(finding.get("line"))
        if line is not None and line >= 1:
            region["startLine"] = line
            region["endLine"] = line
            start, end = _int(finding.get("column_start")), _int(finding.get("column_end"))
            if start is not None and end is not None and end >= start >= 0:
                region["startColumn"] = start + 1
                region["endColumn"] = end + 1
        properties: dict[str, Any] = {
            "confidence": confidence or None,
            "validation": "not_attempted",
            "redacted": True,
        }
        if history and sha:
            properties["commit"] = sha
        message = str(rule.get("description") or _title(rule, rule_id))
        where = f" in commit {sha[:12]}" if history and sha else ""
        results.append(
            {
                "ruleId": rule_id,
                "level": _LEVELS.get(confidence, "warning"),
                "message": {"text": f"{message} The value is redacted{where}."},
                "locations": [
                    {"physicalLocation": {"artifactLocation": {"uri": uri}, "region": region}}
                ],
                "properties": {key: value for key, value in properties.items() if value},
            }
        )
    driver: dict[str, Any] = {
        "name": "kingfisher",
        "informationUri": "https://github.com/mongodb/kingfisher",
        "rules": list(rules.values()),
    }
    if version:
        driver["version"] = version
    metadata = report.get("metadata") if isinstance(report.get("metadata"), dict) else {}
    summary = metadata.get("summary") if isinstance(metadata.get("summary"), dict) else {}
    run_properties: dict[str, Any] = {
        "update_check_status": metadata.get("update_check_status"),
        "summary": {
            key: summary.get(key)
            for key in ("findings", "rules_applied", "blobs_scanned", "bytes_scanned")
            if key in summary
        },
    }
    if skipped:
        run_properties["skipped_findings"] = skipped
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": driver}, "results": results, "properties": run_properties}],
    }


class KingfisherAdapter(ToolAdapter):
    """``kingfisher scan`` over the target copy."""

    name = "kingfisher"
    tool = "kingfisher"
    output = "sarif-file"
    output_dir = "scans"
    output_name = "kingfisher.sarif"
    ok_exit_codes = (0, 200)
    timeout_seconds = 900
    history = False

    def scan_root(self, ctx: ScanContext) -> Path:
        """Return the folder that Kingfisher reads."""
        return ctx.target_dir

    def mode_flags(self) -> list[str]:
        """Return the flags of the tree scan."""
        return ["--git-history", "none", "--no-dedup"]

    def arguments(self, ctx: ScanContext, out: Path) -> list[str]:
        args = ["scan", str(self.scan_root(ctx)), *OFFLINE_FLAGS]
        if not ctx.honor_suppressions:
            args.append("--no-ignore")
        args += ["--confidence", "medium", "--no-rule-cache", *self.mode_flags()]
        return [*args, "--format", "json", "--output", str(json_report_path(out))]

    def invocations(self, ctx: ScanContext, tool_path: Path, out: Path) -> list[Invocation]:
        return [Invocation(tuple(self.command(ctx, tool_path, out)), self.cwd(ctx), out)]

    def after_run(self, ctx: ScanContext, item: Invocation) -> None:
        """Check the redaction, write the kalkan SARIF and delete the JSON report."""
        report_path = json_report_path(item.output)
        try:
            if not report_path.is_file():
                raise ToolError(f"no Kingfisher report {report_path.name}")
            try:
                report = json.loads(read_bounded(report_path, MAX_REPORT_BYTES))
            except UnsafeInputError as exc:
                raise ToolError(f"cannot read the Kingfisher report: {exc}") from None
            except ValueError as exc:
                raise ToolError(f"the Kingfisher report is not valid JSON: {exc}") from None
            metadata = report.get("metadata") if isinstance(report, dict) else None
            version = ""
            if isinstance(metadata, dict):
                version = str(metadata.get("kingfisher_version") or "")
            sarif = json_to_sarif(
                report, target=ctx.target_dir, history=self.history, version=version
            )
            atomic_write_json(item.output, sarif)
        finally:
            with contextlib.suppress(OSError):
                report_path.unlink(missing_ok=True)

    def status_details(
        self, ctx: ScanContext, stdout_log: Path, stderr_log: Path, outputs: list[Path]
    ) -> dict[str, Any]:
        """Delete a JSON report that a failed run left; record the scan summary."""
        for leftover in work_dir(ctx.run_dir, self).glob("*.json"):
            with contextlib.suppress(OSError):
                leftover.unlink()
        details: dict[str, Any] = {"redaction": "values redacted by Kingfisher (--redact)"}
        for output in outputs:
            try:
                doc = json.loads(read_bounded(output, MAX_REPORT_BYTES))
                properties = doc["runs"][0].get("properties") or {}
            except (KalkanError, OSError, ValueError, KeyError, IndexError, TypeError):
                continue
            details["update_check"] = properties.get("update_check_status")
            if properties.get("summary"):
                details["scan_summary"] = properties["summary"]
            if properties.get("skipped_findings"):
                details["skipped_findings"] = properties["skipped_findings"]
        return details

    def suppression_sources(self, ctx: ScanContext) -> tuple[list[str], list[str]]:
        directives = "kingfisher:ignore inline directives"
        if ctx.honor_suppressions:
            return [], [directives]
        return [
            f"{directives} (--no-ignore)",
            "kingfisher.yaml, baseline files and .gitignore of the target (Kingfisher 2.11.1 "
            "reads none of them without --config or --baseline-file)",
        ], []


def _history_detail(run_dir: Path) -> str:
    """Return the ``history.detail`` text of the run manifest, or an empty string."""
    try:
        data = json.loads(read_bounded(run_dir / MANIFEST_NAME, 4 * 1024 * 1024))
    except (UnsafeInputError, ValueError):
        return ""
    history = data.get("history") if isinstance(data, dict) else None
    detail = history.get("detail") if isinstance(history, dict) else None
    return detail.strip() if isinstance(detail, str) else ""


def _inside(path: Path, folder: Path) -> bool:
    try:
        resolved = path.resolve()
    except OSError:
        return False
    base = folder.resolve()
    return resolved != base and resolved.is_relative_to(base)


class KingfisherHistoryAdapter(KingfisherAdapter):
    """``kingfisher scan`` over the git folder of the private history copy ``<run>/source``."""

    name = "kingfisher-history"
    output_name = "kingfisher-history.sarif"
    timeout_seconds = 1200
    history = True

    def applies(self, ctx: ScanContext) -> tuple[bool, str]:
        if ctx.source_dir is None:
            detail = _history_detail(ctx.run_dir)
            reason = "the run has no private history copy (source/)"
            return False, f"{reason}: {detail}" if detail else reason
        if not _inside(ctx.source_dir, ctx.run_dir):
            return False, "the source folder is outside the run folder (only source/ is scanned)"
        folder = history_git_dir(ctx.source_dir)
        if folder is None or not _inside(folder, ctx.run_dir):
            return False, "the history copy source/ has no git folder (no history to scan)"
        return True, ""

    def scan_root(self, ctx: ScanContext) -> Path:
        """Return the git folder of the history copy (the copy itself when none is found)."""
        assert ctx.source_dir is not None  # applies() checked it
        return history_git_dir(ctx.source_dir) or ctx.source_dir

    def mode_flags(self) -> list[str]:
        """Return the flags of the history scan: the defaults (full history, deduplication)."""
        return []

    def suppression_sources(self, ctx: ScanContext) -> tuple[list[str], list[str]]:
        directives = "kingfisher:ignore inline directives in the history"
        if ctx.honor_suppressions:
            return [], [directives]
        return [f"{directives} (--no-ignore)"], []
