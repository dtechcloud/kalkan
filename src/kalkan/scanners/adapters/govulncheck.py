# SPDX-License-Identifier: MIT
"""govulncheck reachability data for Go modules (ENGINE-SPEC 17, ``sca reach``).

Command line, one run per Go module with the module folder as working directory::

    govulncheck -db file:///<home>/.tools/vulndb/go -json ./...    (local mode, the default)
    govulncheck -json ./...                                         (--online: vuln.go.dev)

Checked against ``govulncheck -h`` of the pinned 1.8.0 (built with ``kalkan tools install``
and Go 1.26.9) on 2026-10-16: ``-json`` (the "Go compatible legacy flag" of ``-format json``)
writes the JSON stream; with it the exit code is 0 whether or not vulnerabilities are found.
``-db`` takes a database URL with ``http://``, ``https://`` or ``file://``; a ``file`` URL
needs an absolute path, and govulncheck then reads only files (golang.org/x/vuln@v1.8.0
``internal/client``). The stream has a ``config`` message (with ``db`` and
``db_last_modified``), an ``SBOM`` message (the modules that provide a package of the build of
``./...``), ``progress``, ``osv`` and ``finding`` messages. A module that the ``go.mod``
requires but no package imports is not in the ``SBOM`` and gets no finding at all
(:mod:`kalkan.sca.reach` uses this).

Local mode (the default, docs/SECURITY.md) keeps every byte on the machine:

- ``-db`` names the local Go vulnerability database of ``kalkan sca update-db``
  (:mod:`kalkan.sca.govulndb`; the official ``vuln.go.dev/vulndb.zip`` archive, else a database
  built from the OSV Go entries). Without it the adapter is skipped with the reason
  ``no local Go vulnerability database (run: kalkan sca update-db)``, and ``sca reach``
  records a database gap.
- ``GOPROXY=off`` and ``GOSUMDB=off`` (:func:`~kalkan.scanners.adapters._common.go_env`): ``go
  list`` downloads no module. ``GOFLAGS=-mod=mod`` is not needed: with the default
  ``-mod=readonly`` a module whose imported packages come from the standard library, the module
  cache or a ``vendor`` folder loads completely (checked on 2026-10-16 on the vulnapp fixture,
  whose ``go.mod`` requires ``golang.org/x/text`` without importing it). ``-mod=mod`` would not
  help either: a missing module still needs a download. A module with ``vendor/modules.txt``
  runs with ``GOFLAGS=-mod=vendor``.
- A package whose module is neither in the module cache nor in a ``vendor`` folder stops
  govulncheck (``govulncheck: loading packages: There are errors with the provided package
  patterns``, exit code 1). ``status_details`` then records the packages and why in
  ``partial_packages`` (:func:`~kalkan.scanners.adapters._common.go_partial_packages`, with the
  hint ``kalkan sca reach --online`` or a ``vendor`` folder); the report lists them as a scan
  gap.

``--online`` (opt-in) asks vuln.go.dev and lets ``go list`` download modules: the module paths
of the target then leave the machine.

Runs only when the tech list has ``go``, a Go toolchain exists (the kalkan copy first, see
:func:`kalkan.tools.golang.resolve_go`) and the target has a ``go.mod``. The ``bin`` folder of
that Go comes first on PATH (govulncheck starts ``go list`` and reads the Go version for the
standard library). ``GOTOOLCHAIN=local`` stops Go from downloading the toolchain that a
``go.mod`` names.

``sca/govulncheck.json`` is one JSON stream: before the stream of each module the adapter
writes a marker object ``{"kalkan_invocation": {"index": n, "label": "<module>", "dir":
"<module folder relative to the target or null>"}}``, then the govulncheck messages
(``config``, ``progress``, ``osv``, ``finding``) of that module.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from kalkan.sca import vulndb
from kalkan.scanners.adapters import _common
from kalkan.scanners.base import Invocation, ScanContext, ToolAdapter, part_path, work_dir
from kalkan.util.safe_io import read_bounded

#: The fix that ``partial_packages`` names (docs/SECURITY.md, local mode).
PARTIAL_HINT = (
    "kalkan sca reach --online (downloads the Go modules of the target) or a vendor/ folder "
    "in the target lets govulncheck load these packages"
)
#: The stderr log holds at most this many bytes that ``status_details`` reads.
MAX_LOG_BYTES = 4 * 1024 * 1024
_HEADER = re.compile(r"== kalkan: run [0-9]+/[0-9]+ \((.*)\) ==")
_LOAD_ERROR = re.compile(r"(.+?\.go):([0-9]+):([0-9]+): (.+)")


class GovulncheckAdapter(ToolAdapter):
    """``govulncheck [-db file:///...] -json ./...`` in every Go module folder."""

    name = "govulncheck"
    tool = "govulncheck"
    output = "json-stdout"
    output_dir = "sca"
    output_name = "govulncheck.json"
    ok_exit_codes = (0,)
    timeout_seconds = 1200

    def applies(self, ctx: ScanContext) -> tuple[bool, str]:
        ok, reason = _common.go_applies(ctx, "govulncheck")
        if ok and ctx.offline and not vulndb.go_db_ready():
            return False, vulndb.GO_DB_MISSING
        return ok, reason

    def arguments(self, ctx: ScanContext, out: Path) -> list[str]:
        database = ["-db", vulndb.go_db_uri()] if ctx.offline else []
        return [*database, "-json", "./..."]

    def prepare(self, ctx: ScanContext, stage: Path) -> None:
        """Create the Go build cache and configuration folder in the work folder."""
        _common.go_prepare(work_dir(ctx.run_dir, self))

    def env(self, ctx: ScanContext) -> dict[str, str]:
        return _common.go_env(ctx, work_dir(ctx.run_dir, self))

    def invocations(self, ctx: ScanContext, tool_path: Path, out: Path) -> list[Invocation]:
        items: list[Invocation] = []
        for index, module in enumerate(_common.go_modules(ctx.target_dir)):
            folder = ctx.target_dir / module if module else ctx.target_dir
            items.append(
                Invocation(
                    (str(tool_path), *self.arguments(ctx, out)),
                    folder,
                    part_path(out, index),
                    base=module or None,
                    label=module or ".",
                    env=_common.go_module_env(folder),
                )
            )
        return items

    def status_details(
        self, ctx: ScanContext, stdout_log: Path, stderr_log: Path, outputs: list[Path]
    ) -> dict[str, Any]:
        """Return ``partial_packages`` from the load errors on stderr, and the database used."""
        details: dict[str, Any] = {}
        if ctx.offline:
            info = vulndb.go_db_info() or {}
            details["database"] = {
                "url": vulndb.go_db_uri(),
                "source": info.get("source"),
                "modified": info.get("modified"),
            }
        try:
            text = read_bounded(stderr_log, MAX_LOG_BYTES).decode("utf-8", errors="replace")
        except Exception:  # no log: no details
            return details
        modules = _common.go_modules(ctx.target_dir)
        module = modules[0] if len(modules) == 1 else ""
        errors: list[tuple[str, str]] = []
        for raw in text.splitlines():
            line = raw.strip()
            header = _HEADER.fullmatch(line)
            if header is not None:
                label = header.group(1)
                module = "" if label == "." else label
                continue
            match = _LOAD_ERROR.fullmatch(line)
            if match is None:
                continue
            folder = ctx.target_dir / module if module else ctx.target_dir
            file = _common.go_relative(match.group(1), ctx.target_dir, folder)
            where = f"{file}:{match.group(2)}:{match.group(3)}"
            errors.append((file, f"{where}: {match.group(4).strip()}"))
        partial = _common.go_partial_packages(errors, offline=ctx.offline, hint=PARTIAL_HINT)
        if partial:
            details["partial_packages"] = partial
        return details
