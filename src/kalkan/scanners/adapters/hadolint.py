# SPDX-License-Identifier: MIT
"""Hadolint Dockerfile lint (ENGINE-SPEC 13).

Command line, checked against ``hadolint --help`` of the pinned version 2.15.1::

    hadolint -f sarif --no-fail --no-color --disable-ignore-pragma <dockerfile> [...]
        (SARIF on stdout)

Files: ``Dockerfile``, ``Dockerfile.*``, ``*.Dockerfile``, and ``Containerfile`` and
``Containerfile.*`` (names compared case-insensitively), found with the walk of
:func:`kalkan.scanners.adapters._common.target_files`. The files are passed as absolute paths in
batches of :data:`BATCH_SIZE`, so a long list never exceeds the Windows command line limit;
the batches become one SARIF file. The working directory is ``scans/``, so a ``.hadolint.yaml``
of the target is not read.

Suppressions (ADR-0003): ``--disable-ignore-pragma`` turns off the ``# hadolint ignore=``
pragmas of the target (tested). The working directory is ``scans/``, so a ``.hadolint.yaml`` of
the target is never found. With ``honor_suppressions`` the pragmas count again and the
``.hadolint.yaml`` (or ``.hadolint.yml``) of the target root is passed with ``-c``.

Differences from section 13: ``--no-color``; ``--disable-ignore-pragma``; ``Containerfile``
names; batches.
"""

from __future__ import annotations

from pathlib import Path, PurePosixPath

from kalkan.scanners.adapters._common import target_files
from kalkan.scanners.base import Invocation, ScanContext, ToolAdapter, part_path

BATCH_SIZE = 100
CONFIG_NAMES = (".hadolint.yaml", ".hadolint.yml")


def is_dockerfile(name: str) -> bool:
    """Return True for a Dockerfile or Containerfile name."""
    lower = name.lower()
    for stem in ("dockerfile", "containerfile"):
        if lower == stem or lower.startswith(stem + "."):
            return True
    return lower.endswith(".dockerfile")


def dockerfiles(target: Path) -> list[str]:
    """Return the target-relative paths of the Dockerfiles in ``target``, sorted."""
    return [rel for rel in target_files(target) if is_dockerfile(PurePosixPath(rel).name)]


class HadolintAdapter(ToolAdapter):
    """``hadolint -f sarif`` over every Dockerfile of the target."""

    name = "hadolint"
    tool = "hadolint"
    output = "sarif-stdout"
    output_dir = "scans"
    output_name = "hadolint.sarif"
    ok_exit_codes = (0,)
    timeout_seconds = 300

    def applies(self, ctx: ScanContext) -> tuple[bool, str]:
        if not dockerfiles(ctx.target_dir):
            return False, "no Dockerfile found in the target"
        return True, ""

    @staticmethod
    def target_config(ctx: ScanContext) -> Path | None:
        """Return the ``.hadolint.yaml`` of the target root, or None."""
        for name in CONFIG_NAMES:
            path = ctx.target_dir / name
            if path.is_file() and not path.is_symlink():
                return path
        return None

    def _arguments(self, ctx: ScanContext, files: list[str]) -> list[str]:
        args = ["-f", "sarif", "--no-fail", "--no-color"]
        if ctx.honor_suppressions:
            config = self.target_config(ctx)
            if config is not None:
                args += ["-c", str(config)]
        else:
            args.append("--disable-ignore-pragma")
        return [*args, *(str(ctx.target_dir / f) for f in files)]

    def arguments(self, ctx: ScanContext, out: Path) -> list[str]:
        return self._arguments(ctx, dockerfiles(ctx.target_dir))

    def invocations(self, ctx: ScanContext, tool_path: Path, out: Path) -> list[Invocation]:
        files = dockerfiles(ctx.target_dir)
        batches = [files[i : i + BATCH_SIZE] for i in range(0, len(files), BATCH_SIZE)]
        items: list[Invocation] = []
        for index, batch in enumerate(batches):
            argv = [str(tool_path), *self._arguments(ctx, batch)]
            target = out if len(batches) == 1 else part_path(out, index)
            label = f"files {index * BATCH_SIZE + 1}-{index * BATCH_SIZE + len(batch)}"
            items.append(Invocation(tuple(argv), self.cwd(ctx), target, label=label))
        return items

    def suppression_sources(self, ctx: ScanContext) -> tuple[list[str], list[str]]:
        pragmas = "# hadolint ignore= pragmas"
        if not ctx.honor_suppressions:
            return [
                f"{pragmas} (--disable-ignore-pragma)",
                ".hadolint.yaml of the target (the working directory is scans/)",
            ], []
        config = self.target_config(ctx)
        honored = [pragmas]
        if config is not None:
            honored.append(f"{config.name} of the target root (-c)")
        return [], honored
