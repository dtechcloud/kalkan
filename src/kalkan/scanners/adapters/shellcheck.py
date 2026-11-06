# SPDX-License-Identifier: MIT
"""ShellCheck scan of the shell scripts of the target (ENGINE-SPEC 13).

Command line, checked against ``shellcheck --help`` of the pinned version 0.11.0, in batches of
:data:`~kalkan.scanners.adapters._sources.BATCH_SIZE` absolute file paths (JSON on stdout)::

    shellcheck --format=json1 --norc --include=<CODES> <script> [...]

1. Files (:func:`shell_scripts`): ``*.sh``, ``*.bash`` and ``*.ksh``, and files with another or
   no extension whose first line is a ``sh``, ``bash``, ``dash`` or ``ksh`` shebang
   (``#!/bin/sh``, ``#!/usr/bin/env bash``). ``gradlew`` and ``mvnw`` (generated build wrappers)
   and vendored folders are left out (:mod:`kalkan.scanners.adapters._sources`). ShellCheck
   picks the dialect from the shebang or the extension; a script without both still gets its
   checks (it adds SC2148, which is not kept).
2. ``--format=json1``: JSON with columns that count a tab as one character. The adapter writes
   SARIF itself (:func:`json_to_sarif`). ``--norc``: ShellCheck reads no ``.shellcheckrc``,
   neither of the target nor of a parent folder or the home folder. ``SHELLCHECK_OPTS`` does not
   reach the tool (minimal environment). No ``-x``: ShellCheck never opens a ``source`` file
   that is not in the list, so it reads no file outside the target.
3. ShellCheck is a linter. ``--include`` keeps only the curated codes of :data:`RULES` and
   :data:`SPLITTING`, each with a kalkan class and CWE:

   - SC2029, SC2087 (an ``ssh`` command string or here-document expands on the client),
     SC2156 (``find -exec sh -c`` with ``{}``), SC2091, SC2092 (the output of a command is
     executed): ``os-command-injection``, CWE-78, medium.
   - SC2294 (``eval`` of an array): ``code-injection``, CWE-95, medium. SC1090 (``source`` of a
     dynamic path): ``code-injection``, CWE-94, low.
   - SC2115 (``rm -rf "$var/"`` deletes ``/`` when the variable is empty): ``path-traversal``,
     CWE-73, medium.
   - SC2035 (a glob can expand to options) and SC2038 (``find | xargs`` without ``-0``):
     ``os-command-injection``, CWE-88 (argument injection), low.
   - SC2086, SC2046, SC2048, SC2068 (an unquoted expansion splits and globs): the most
     frequent ShellCheck message, so :func:`splitting_rule` keeps it only for a command that
     runs code, deletes files, changes permissions or opens a remote session
     (:data:`SENSITIVE_COMMANDS`): ``eval``, ``trap``: ``code-injection``, CWE-95;
     ``source``, ``.`` and interpreters (``python -c``, ``awk``, ``sed``): ``code-injection``,
     CWE-94; shells (``sh -c``, ``ssh host <command>``) and an expansion that is itself the
     command after a wrapper (``sudo $1``): ``os-command-injection``, CWE-78; all medium.
     ``rm``, ``xargs``, ``chmod``, ``curl``, ``scp`` and the rest of
     :data:`ARGUMENT_SINKS`: ``os-command-injection``, CWE-88, low. ShellCheck does not report
     an unquoted expansion that is the first word of a command (``$1 --force``).
     :func:`expansion_context` is a text heuristic on the source line: the last command
     separator before the column, then keywords, assignments and wrappers (``sudo -u root``,
     ``env``, ``timeout 10``) are skipped.

   Style and correctness codes are dropped. ShellCheck 0.11.0 has no check for ``eval`` of a
   quoted string (``eval "$1"``): only an unquoted ``eval $1`` is reported (SC2086 in an
   ``eval`` context).

Suppressions (ADR-0003): ``--norc`` turns off the ``.shellcheckrc`` files. ShellCheck 0.11.0
has no option to turn off the inline ``# shellcheck disable=`` directives (checked: SC2086
stays hidden under such a directive, with ``--norc`` and with ``--include``); the status file
records them as honored. With ``honor_suppressions`` the ``.shellcheckrc`` (or ``shellcheckrc``)
of the target root is passed with ``--rcfile`` when it exists; otherwise ``--norc`` stays, so a
file above the target is never read.

Exit codes 0 (no issue) and 1 (issues). 2 (a file could not be read) and higher fail the run.
"""

from __future__ import annotations

import json
import re
from pathlib import Path, PurePosixPath
from typing import Any, Final

from kalkan.errors import KalkanError, ToolError
from kalkan.scanners.adapters import _sources
from kalkan.scanners.base import Invocation, ScanContext, ToolAdapter, part_path
from kalkan.util.safe_io import atomic_write_json, read_bounded

__all__ = [
    "RULES",
    "SENSITIVE_COMMANDS",
    "SPLITTING",
    "ShellcheckAdapter",
    "expansion_context",
    "included_codes",
    "is_shell_script",
    "json_to_sarif",
    "shell_scripts",
    "splitting_rule",
]

#: Script extensions (compared case-insensitively).
EXTENSIONS: Final = (".sh", ".bash", ".ksh")
#: Interpreters of a shebang line that ShellCheck checks.
SHEBANG_SHELLS: Final = frozenset({"sh", "bash", "dash", "ksh"})
#: Generated build wrappers that every Gradle and Maven project carries.
GENERATED: Final = frozenset({"gradlew", "mvnw"})
RC_NAMES: Final = (".shellcheckrc", "shellcheckrc")
MAX_OUTPUT_BYTES: Final = 50 * 1024 * 1024

#: code -> (class, CWE IDs, severity, title). Always kept.
RULES: Final[dict[int, tuple[str, tuple[str, ...], str, str]]] = {
    2029: (
        "os-command-injection",
        ("CWE-78",),
        "medium",
        "A remote command string expands on the client (ssh)",
    ),
    2087: (
        "os-command-injection",
        ("CWE-78",),
        "medium",
        "A here-document sent to ssh expands on the client",
    ),
    2156: (
        "os-command-injection",
        ("CWE-78",),
        "medium",
        "File names are injected into a shell command (find -exec sh -c)",
    ),
    2091: ("os-command-injection", ("CWE-78",), "medium", "The output of a command is executed"),
    2092: ("os-command-injection", ("CWE-78",), "medium", "The output of a command is executed"),
    2294: ("code-injection", ("CWE-95",), "medium", "eval of an array"),
    1090: ("code-injection", ("CWE-94",), "low", "source of a dynamic path"),
    2115: (
        "path-traversal",
        ("CWE-73",),
        "medium",
        "rm -rf of a path that expands to / when the variable is empty",
    ),
    2035: ("os-command-injection", ("CWE-88",), "low", "A glob can expand to command options"),
    2038: (
        "os-command-injection",
        ("CWE-88",),
        "low",
        "find | xargs without -print0 / -0 splits file names",
    ),
}
#: Unquoted expansions: kept only in a sensitive command context (:func:`expansion_context`).
SPLITTING: Final[dict[int, str]] = {
    2086: "An unquoted variable expansion splits and globs",
    2046: "An unquoted command substitution splits and globs",
    2048: "An unquoted $* or $@ splits and globs",
    2068: "An unquoted array expansion splits and globs",
}
CODE_RUNNERS: Final = frozenset({"eval", "source", ".", "trap"})
#: Commands that run their arguments as shell code (``ssh host <command>`` on the remote side).
SHELLS: Final = frozenset(
    {"sh", "bash", "dash", "zsh", "ksh", "mksh", "ash", "busybox", "su", "ssh"}
)
INTERPRETERS: Final = frozenset(
    {
        "python",
        "python2",
        "python3",
        "perl",
        "ruby",
        "node",
        "php",
        "lua",
        "awk",
        "gawk",
        "mawk",
        "nawk",
        "sed",
        "expect",
        "tclsh",
    }
)
ARGUMENT_SINKS: Final = frozenset(
    {
        "rm",
        "rmdir",
        "mv",
        "cp",
        "ln",
        "install",
        "chmod",
        "chown",
        "chgrp",
        "truncate",
        "shred",
        "dd",
        "find",
        "xargs",
        "scp",
        "sftp",
        "rsync",
        "curl",
        "wget",
        "nc",
        "ncat",
        "socat",
        "tar",
        "unzip",
        "kill",
        "pkill",
        "killall",
        "docker",
        "podman",
        "kubectl",
        "helm",
        "git",
        "mount",
        "umount",
        "chroot",
        "crontab",
        "iptables",
        "openssl",
        "psql",
        "mysql",
        "sqlite3",
    }
)
#: Commands whose argument list ends the analysis of the expansion (code, files, network).
SENSITIVE_COMMANDS: Final = CODE_RUNNERS | SHELLS | INTERPRETERS | ARGUMENT_SINKS
#: Commands that run the next word as a command.
WRAPPERS: Final = frozenset(
    {"sudo", "doas", "exec", "command", "builtin", "nohup", "time", "nice", "env", "timeout"}
)
#: Wrapper options that take a value (``sudo -u root cmd``).
_WRAPPER_VALUE_OPTIONS: Final = {
    "sudo": frozenset({"-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U", "-T"}),
    "doas": frozenset({"-u", "-C"}),
    "nice": frozenset({"-n"}),
    "env": frozenset({"-u", "-C", "-S"}),
    "timeout": frozenset({"-s", "-k"}),
}
_DURATION = re.compile(r"^[0-9.]+[smhd]?$")
_KEYWORDS: Final = frozenset({"then", "do", "else", "elif", "if", "while", "until", "!", "{"})
_SEPARATORS = re.compile(r"\|\||&&|;;|[;|&(){}`]|\$\(|[<>]\(")
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]*\])?\+?=")
_SHEBANG = re.compile(rb"^#!\s*(\S+)(?:[ \t]+(\S+))?(?:[ \t]+(\S+))?")


def is_shell_script(target: Path, rel: str) -> bool:
    """Return True for a ShellCheck file: a script extension or a sh/bash/dash/ksh shebang."""
    name = PurePosixPath(rel).name
    if name.lower() in GENERATED:
        return False
    if name.lower().endswith(EXTENSIONS):
        return True
    head = _sources.read_head(target / rel, 128)
    match = _SHEBANG.match(head)
    if match is None:
        return False
    words = [part.decode("utf-8", "replace") for part in match.groups() if part]
    interpreter = words[0].rsplit("/", 1)[-1]
    if interpreter == "env":
        rest = [word for word in words[1:] if not word.startswith("-")]
        interpreter = rest[0].rsplit("/", 1)[-1] if rest else ""
    return interpreter in SHEBANG_SHELLS


def shell_scripts(target: Path) -> list[str]:
    """Return the target-relative paths of the shell scripts, sorted."""
    return _sources.source_files(target, lambda rel: is_shell_script(target, rel))


def expansion_context(line: str, column: int) -> tuple[str | None, bool]:
    """Return ``(command, is_command_word)`` for an expansion at a 1-based column.

    ``command`` is the name of the command whose arguments hold the expansion (the last word of
    its path), after keywords, assignments and wrappers (``sudo``, ``env``, ...); None when the
    expansion is the command word itself (then ``is_command_word`` is True).
    """
    prefix = line[: max(0, column - 1)]
    segment = _SEPARATORS.split(prefix)[-1]
    words = segment.split()
    index = 0
    while index < len(words):
        word = words[index]
        if word in _KEYWORDS or _ASSIGNMENT.match(word):
            index += 1
            continue
        name = word.rsplit("/", 1)[-1]
        if name in WRAPPERS:
            values = _WRAPPER_VALUE_OPTIONS.get(name, frozenset())
            index += 1
            while index < len(words) and words[index].startswith("-"):
                option = words[index]
                index += 2 if option in values else 1
            if name == "timeout" and index < len(words) and _DURATION.match(words[index]):
                index += 1
            continue
        return name, False
    return None, True


def splitting_rule(line: str, column: int) -> tuple[str, tuple[str, ...], str, str] | None:
    """Return ``(class, CWE IDs, severity, context)`` for an unquoted expansion at a 1-based
    column of a source line, or None when its command is not sensitive (the result is
    dropped). ``context`` is the command name or ``command word``."""
    command, is_command_word = expansion_context(line, column)
    if is_command_word or command is None:
        return "os-command-injection", ("CWE-78",), "medium", "command word"
    if command in ("eval", "trap"):
        return "code-injection", ("CWE-95",), "medium", command
    if command in ("source", "."):
        return "code-injection", ("CWE-94",), "medium", command
    if command in SHELLS:
        return "os-command-injection", ("CWE-78",), "medium", command
    if command in INTERPRETERS:
        return "code-injection", ("CWE-94",), "medium", command
    if command in ARGUMENT_SINKS:
        return "os-command-injection", ("CWE-88",), "low", command
    return None


def included_codes() -> str:
    """Return the ``--include`` value: every kept code."""
    return ",".join(f"SC{code}" for code in sorted({*RULES, *SPLITTING}))


_LEVELS: Final = {"high": "error", "medium": "warning", "low": "note"}


def json_to_sarif(
    report: dict[str, Any], *, target: Path, version: str = ""
) -> tuple[dict[str, Any], int]:
    """Convert a ShellCheck ``json1`` report to SARIF; return the document and the number of
    dropped comments (codes outside the curated set, or unquoted expansions outside a sensitive
    context)."""
    comments = report.get("comments") if isinstance(report, dict) else None
    if not isinstance(comments, list):
        raise ToolError("the ShellCheck report is not a json1 object with a 'comments' list")
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    dropped = 0
    lines_cache: dict[str, list[str] | None] = {}
    for comment in comments:
        if not isinstance(comment, dict):
            continue
        code = comment.get("code")
        rel = _sources.target_relative(str(comment.get("file") or ""), target)
        line_no = comment.get("line") if isinstance(comment.get("line"), int) else None
        if not isinstance(code, int) or rel is None or line_no is None or line_no < 1:
            dropped += 1
            continue
        if rel not in lines_cache:
            lines_cache[rel] = _sources.read_lines(target / rel)
        source = lines_cache[rel] or []
        text = source[line_no - 1].rstrip("\r") if line_no <= len(source) else ""
        column = comment.get("column") if isinstance(comment.get("column"), int) else 1
        context: str | None = None
        if code in RULES:
            vuln_class, cwes, severity, title = RULES[code]
        elif code in SPLITTING:
            decided = splitting_rule(text, column)
            if decided is None:
                dropped += 1
                continue
            vuln_class, cwes, severity, context = decided
            title = SPLITTING[code]
        else:
            dropped += 1
            continue
        rule_id = f"SC{code}"
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": title},
                "helpUri": f"https://www.shellcheck.net/wiki/{rule_id}",
                "properties": {"tags": ["security"]},
            },
        )
        region: dict[str, Any] = {"startLine": line_no}
        end_line = comment.get("endLine")
        region["endLine"] = (
            end_line if isinstance(end_line, int) and end_line >= line_no else line_no
        )
        if isinstance(column, int) and column >= 1:
            region["startColumn"] = column
            end_column = comment.get("endColumn")
            if isinstance(end_column, int) and end_column >= column:
                region["endColumn"] = end_column
        if text:
            region["snippet"] = {"text": text}
        properties: dict[str, Any] = {
            "tags": ["security", *(f"external/cwe/cwe-{cwe[4:]}" for cwe in cwes)],
            "kalkan_class": vuln_class,
            "shellcheck_level": str(comment.get("level") or ""),
        }
        if context is not None:
            properties["command"] = context
        message = str(comment.get("message") or title).strip()
        results.append(
            {
                "ruleId": rule_id,
                "level": _LEVELS[severity],
                "message": {"text": f"{message} ({rule_id})"},
                "locations": [
                    {"physicalLocation": {"artifactLocation": {"uri": rel}, "region": region}}
                ],
                "properties": properties,
            }
        )
    driver: dict[str, Any] = {
        "name": "shellcheck",
        "informationUri": "https://www.shellcheck.net",
        "rules": list(rules.values()),
    }
    if version:
        driver["version"] = version
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": driver}, "results": results}],
    }
    return doc, dropped


class ShellcheckAdapter(ToolAdapter):
    """``shellcheck --format=json1`` over the shell scripts, converted to SARIF."""

    name = "shellcheck"
    tool = "shellcheck"
    output = "sarif-stdout"
    output_dir = "scans"
    output_name = "shellcheck.sarif"
    ok_exit_codes = (0, 1)
    timeout_seconds = 600

    def __init__(self) -> None:
        self._dropped = 0

    def applies(self, ctx: ScanContext) -> tuple[bool, str]:
        if not shell_scripts(ctx.target_dir):
            return False, "no shell script found in the target"
        return True, ""

    @staticmethod
    def target_rc(ctx: ScanContext) -> Path | None:
        """Return the ``.shellcheckrc`` (or ``shellcheckrc``) of the target root, or None."""
        for name in RC_NAMES:
            path = ctx.target_dir / name
            if path.is_file() and not path.is_symlink():
                return path
        return None

    def _arguments(self, ctx: ScanContext, files: list[str]) -> list[str]:
        rc = self.target_rc(ctx) if ctx.honor_suppressions else None
        config = [f"--rcfile={rc}"] if rc is not None else ["--norc"]
        args = ["--format=json1", *config, f"--include={included_codes()}"]
        return [*args, *(str(ctx.target_dir / rel) for rel in files)]

    def arguments(self, ctx: ScanContext, out: Path) -> list[str]:
        return self._arguments(ctx, shell_scripts(ctx.target_dir))

    def invocations(self, ctx: ScanContext, tool_path: Path, out: Path) -> list[Invocation]:
        self._dropped = 0
        groups = list(_sources.batches(shell_scripts(ctx.target_dir)))
        items: list[Invocation] = []
        for index, batch in enumerate(groups):
            argv = (str(tool_path), *self._arguments(ctx, batch))
            target = out if len(groups) == 1 else part_path(out, index)
            first = index * _sources.BATCH_SIZE + 1
            label = f"files {first}-{first + len(batch) - 1}"
            items.append(Invocation(argv, self.cwd(ctx), target, label=label))
        return items

    def after_run(self, ctx: ScanContext, item: Invocation) -> None:
        """Convert the json1 report on stdout (``item.output``) into SARIF in place."""
        try:
            report = json.loads(read_bounded(item.output, MAX_OUTPUT_BYTES))
        except (KalkanError, ValueError) as exc:
            raise ToolError(f"the ShellCheck report is not valid JSON: {exc}") from None
        doc, dropped = json_to_sarif(report, target=ctx.target_dir)
        self._dropped += dropped
        atomic_write_json(item.output, doc)

    def status_details(
        self, ctx: ScanContext, stdout_log: Path, stderr_log: Path, outputs: list[Path]
    ) -> dict[str, Any]:
        """Record how many comments the curated set dropped."""
        return {
            "kept_codes": included_codes().split(","),
            "dropped_comments": self._dropped,
        }

    def suppression_sources(self, ctx: ScanContext) -> tuple[list[str], list[str]]:
        directives = (
            "# shellcheck disable= directives (ShellCheck 0.11.0 has no option to turn them off)"
        )
        rc = self.target_rc(ctx)
        if ctx.honor_suppressions:
            honored = [directives]
            if rc is not None:
                honored.append(f"{rc.name} of the target root (--rcfile)")
            return [], honored
        return [
            ".shellcheckrc of the target, its parent folders and the home folder (--norc)",
            "SHELLCHECK_OPTS (not in the minimal environment)",
        ], [directives]
