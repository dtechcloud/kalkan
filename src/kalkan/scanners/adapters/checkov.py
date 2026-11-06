# SPDX-License-Identifier: MIT
"""Checkov IaC scan (ENGINE-SPEC 13).

Command line, checked against ``checkov --help`` of the pinned version 3.3.22::

    <tool venv python> -I -X utf8 -c <LAUNCHER> -d <target> -o sarif
        --output-file-path <run>/scans/.work/checkov/results --skip-download --quiet --compact
        --skip-framework helm,kustomize,sca_package,sca_image

Checkov writes ``results_sarif.sarif`` into the output folder (inside the work folder
``scans/.work/checkov/``); :func:`run_adapter` checks it and moves it to
``scans/checkov.sarif``. Exit code 1 means "failed checks found" and counts as success when
the SARIF exists (2 is a crash). The working directory is the target: Checkov writes SARIF URIs
relative to its working directory and drops leading ``../`` parts, so any other folder gives
wrong paths. ``CKV_SKIP_PACKAGE_UPDATE_CHECK=true`` stops the PyPI version check;
``--skip-download`` stops the Prisma Cloud downloads.

Frameworks (checked on 2026-10-25 with a sample file per framework under the proxy trap):
without ``--framework`` Checkov runs every framework. These run offline and report results:
terraform (also ``terraform_json``, ``terraform_plan``), cloudformation, arm, bicep,
kubernetes, dockerfile, serverless, openapi, ansible, argo_workflows, github_actions,
gitlab_ci, azure_pipelines, bitbucket_pipelines, circleci_pipelines and secrets. ``cdk``,
``sast*``, ``json``, ``yaml``, ``3d_policy`` and the ``*_configuration`` frameworks report
nothing without custom policies, a platform key or a fetched VCS settings file, and opened no
connection. ``--skip-framework`` turns off four frameworks:

- ``helm`` and ``kustomize`` start ``helm``, ``kubectl`` or ``kustomize`` from PATH (kalkan
  installs none of them). ``helm template --dependency-update`` downloaded the chart
  dependencies and refreshed every repository of the user's helm config, and ``kubectl
  kustomize`` fetched a remote base: the trap saw 8 connections. On Windows the kustomize
  runner also crashed Checkov (``WinError 32``), so one ``kustomization.yaml`` failed the whole
  scan. Without them the kubernetes framework still checks the plain manifests of a
  kustomization (its resources), and Trivy renders Helm charts offline.
- ``sca_package`` and ``sca_image`` need a platform API key and send package and image data to
  Prisma Cloud.

Home folder: Checkov reads a platform API key from ``~/.bridgecrew/credentials`` when no
``--bc-api-key`` is given; with such a file (a made-up key) it connected to
``api0.prismacloud.io``. ``HOME`` and ``USERPROFILE`` therefore name an empty folder in the work
folder (``home``), and no API key variable reaches the tool (minimal environment), so nothing is
uploaded.

Launcher: Checkov loads every ``.checkov.yaml`` and ``.checkov.yml`` that it finds in the
``-d`` folder, the working directory (here the target) and the home folder
(``checkov.common.util.config_utils.get_default_config_paths``); ``--config-file`` only adds
one more file. A target config can skip checks and can name ``external-checks-dir`` folders,
whose Python code Checkov then runs (tested: a crafted target ran its own code and hid
CKV_DOCKER_7). :data:`LAUNCHER` starts Checkov with that discovery turned off. It runs in the
tool venv Python next to the ``checkov`` entry point, in isolated mode (``-I``: the working
directory, which is the target, never enters ``sys.path``) with UTF-8 I/O (``-X utf8``). When
no such Python exists (a Checkov from PATH), the entry point runs as is and the status file
records that the target config is honored.

Suppressions (ADR-0003): the target config is never loaded, also with ``honor_suppressions``,
because of the code execution risk. Inline ``checkov:skip`` comments: Checkov reports the
skipped checks as SARIF results with a ``suppressions`` entry; they are kept and tagged by
default and dropped with ``honor_suppressions``.

Differences from the first section 13 draft: the launcher; the working directory is the target.
"""

from __future__ import annotations

import os
from pathlib import Path

from kalkan.scanners.base import PYTHON_TOOL_ENV, Invocation, ScanContext, ToolAdapter, work_dir

#: The file name that Checkov writes into ``--output-file-path``.
RESULT_NAME = "results_sarif.sarif"
#: Frameworks that start helm, kubectl or kustomize (network) or need a platform API key.
SKIPPED_FRAMEWORKS = ("helm", "kustomize", "sca_package", "sca_image")
#: The empty folder in the work folder that ``HOME`` and ``USERPROFILE`` name.
HOME_DIRNAME = "home"

#: Python code that runs Checkov without config file discovery (``sys.argv[1:]`` are the
#: Checkov arguments). ``checkov.main`` calls ``get_default_config_paths`` through its module
#: global, so replacing that global turns the discovery off.
LAUNCHER = (
    "import sys, warnings\n"
    "import checkov.main as m\n"
    "m.get_default_config_paths = lambda argv: []\n"
    "with warnings.catch_warnings():\n"
    "    warnings.simplefilter('ignore', category=SyntaxWarning)\n"
    "    sys.exit(m.Checkov().run())\n"
)


def launcher_python(tool_path: Path) -> Path | None:
    """Return the tool venv Python next to the Checkov entry point, or None."""
    name = "python.exe" if os.name == "nt" else "python"
    python = Path(tool_path).parent / name
    return python if python.is_file() else None


class CheckovAdapter(ToolAdapter):
    """``checkov -d <target> -o sarif`` without config file discovery."""

    name = "checkov"
    tool = "checkov"
    output = "sarif-file"
    output_dir = "scans"
    output_name = "checkov.sarif"
    ok_exit_codes = (0, 1)
    timeout_seconds = 1200

    def __init__(self) -> None:
        self._launcher_used: bool | None = None

    @staticmethod
    def result_folder(out: Path) -> Path:
        """Return the ``--output-file-path`` folder for the output path ``out``."""
        return out.parent / "results"

    def arguments(self, ctx: ScanContext, out: Path) -> list[str]:
        return [
            "-d",
            str(ctx.target_dir),
            "-o",
            "sarif",
            "--output-file-path",
            str(self.result_folder(out)),
            "--skip-download",
            "--quiet",
            "--compact",
            "--skip-framework",
            ",".join(SKIPPED_FRAMEWORKS),
        ]

    def command(self, ctx: ScanContext, tool_path: Path, out: Path) -> list[str]:
        python = launcher_python(tool_path)
        if python is None:
            return [str(tool_path), *self.arguments(ctx, out)]
        return [str(python), "-I", "-X", "utf8", "-c", LAUNCHER, *self.arguments(ctx, out)]

    def home_dir(self, ctx: ScanContext) -> Path:
        """Return the empty home folder of the Checkov process (module docstring)."""
        return work_dir(ctx.run_dir, self) / HOME_DIRNAME

    def prepare(self, ctx: ScanContext, stage: Path) -> None:
        """Create the empty home folder next to the staging output."""
        self.home_dir(ctx).mkdir(parents=True, exist_ok=True)

    def env(self, ctx: ScanContext) -> dict[str, str]:
        home = str(self.home_dir(ctx))
        return {
            **PYTHON_TOOL_ENV,
            "CKV_SKIP_PACKAGE_UPDATE_CHECK": "true",
            "HOME": home,
            "USERPROFILE": home,
        }

    def cwd(self, ctx: ScanContext) -> Path:
        return ctx.target_dir

    def invocations(self, ctx: ScanContext, tool_path: Path, out: Path) -> list[Invocation]:
        self._launcher_used = launcher_python(tool_path) is not None
        return [
            Invocation(
                tuple(self.command(ctx, tool_path, out)),
                self.cwd(ctx),
                self.result_folder(out) / RESULT_NAME,
            )
        ]

    def suppression_sources(self, ctx: ScanContext) -> tuple[list[str], list[str]]:
        if self._launcher_used is False:
            config = (
                ".checkov.yaml/.checkov.yml of the target: config discovery could not be turned "
                "off (Checkov does not run from the kalkan tool venv)"
            )
            return [], [config]
        config = (
            ".checkov.yaml/.checkov.yml of the target, the working directory and the home folder "
            "(config discovery turned off in every mode: such a file can make Checkov run "
            "Python code from the target)"
        )
        comments = "checkov:skip, bridgecrew:skip and cortex:skip comments"
        if ctx.honor_suppressions:
            return [config], [f"{comments} (Checkov skips the checks)"]
        return [config, f"{comments} (Checkov keeps them as suppressed SARIF results)"], []
