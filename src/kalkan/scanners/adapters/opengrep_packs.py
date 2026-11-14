# SPDX-License-Identifier: MIT
"""Opengrep scan with the vendored rule packs ``<rules>/opengrep-packs`` (ENGINE-SPEC 13,
ADR-0005 K.8).

The packs: GitLab sast-rules (MIT and LGPL-3.0), Trail of Bits semgrep-rules (AGPL-3.0),
0xdea semgrep-rules (MIT) and, since ADR-0007, the Atlassian SAST ruleset (LGPL-2.1), elttam
semgrep-rules (MIT), njsscan and mobsfscan (LGPL-3.0), the mindedsecurity Android rules
(GPL-3.0), the Aikido rules (MIT) and a measured subset of semgrep-codeql (MIT). The verbatim copies
live in ``third_party/``; ``scripts/build_opengrep_packs.py`` writes the kept rules into a few
bundle files per pack and ``index.json`` (:mod:`kalkan.scanners.rulepacks`).

Command line, checked against ``opengrep scan --help`` of the pinned version 1.30.1::

    opengrep scan -f <pack> [-f <pack> ...] --sarif --output <run>/scans/opengrep-packs.sarif
        --timeout 10 --disable-version-check --rewrite-rule-ids --no-git-ignore
        --x-ignore-semgrepignore-files [--disable-nosem] [--exclude-rule <id> ...]
        --exclude third-party --exclude third_party --exclude thirdparty --exclude vendor
        --exclude vendors <target>

- Working directory: ``prepare`` copies the enabled pack folders (bundle files only) into the
  run-owned staging folder ``scans/.work/opengrep-packs/packs``, the working directory, and
  ``-f`` names each pack folder relative to it. With ``--rewrite-rule-ids`` Opengrep then
  reports a rule as ``<pack>.<folders>.<upstream ID>``: unique across the packs (a pack can
  repeat an upstream ID in several languages; with duplicate IDs the SARIF lists only one rule
  and the results of the other lose their metadata, tested) and
  the same on every machine. The working directory stays inside the run folder (docs/SECURITY.md,
  promise 1 test), and the copy is the exact rule set of the run.
- ``--exclude-rule``: the pack rules that repeat a rule of kalkan's own pack ``rules/opengrep``
  (:func:`kalkan.scanners.rulepacks.kalkan_duplicates`, computed at run time, so a new kalkan
  rule needs no rebuild of the packs). ``--exclude-rule`` takes the rewritten ID (tested).
- ``--timeout 10`` (:data:`RULE_TIMEOUT_SECONDS`; the Opengrep default is 5 s per rule and
  file, and three timeouts skip the rest of a file). Measured on 2026-10-27 on a large C#
  code base (Opengrep 1.30.1, 16 jobs, with the ``scope`` entry of ``curation.json``): 5 s lost
  results of a C# rule, 10 s kept them, and 15 s gave the same results in about 30 % more time.
- ``--exclude`` of the folders of :data:`kalkan.scanners.adapters._sources.VENDOR_DIRS`: the
  packs leave out third-party code that the target copied in, as the file-list adapters do.
  The ``opengrep`` adapter (kalkan's own pack) and the other scanners still scan these folders.
  Measured on 2026-11-14 on the repository of kalkan itself (2,257 files): the packs timed out
  after 1,800 s, and its ``third_party`` folder alone (1,052 vendored rule YAML files) timed
  out after 900 s; without it the rest took about 500 s. Seven Ansible rules of the Trail of
  Bits pack (``trailofbits.yaml.apt-key-unencrypted-url`` and others) hit the 10 s limit on
  most of these deeply nested YAML files. The status records the excluded folder names
  (``excluded_folders``).
- The other options and the suppressions as for the ``opengrep`` adapter (ADR-0003). A rule
  file that Opengrep cannot load stops the whole scan (exit code 7); the build keeps only
  rules that Opengrep 1.30.1 loads, and a ``tools`` test checks it.

Why a second adapter and not more ``-f`` options for the ``opengrep`` adapter:

- Failure isolation: a timeout, a crash of a third-party rule or a load error of a pack does
  not cost the results of kalkan's own pack.
- Its own status file: the switch, the enabled packs with their licenses, the run-time
  duplicates and the coverage gaps (``files_scanned``, ``partial_files``, ``skipped_files``).
- Its own engine name: the results are third-party rules (``kalkan-pack``, ``kalkan-license``
  on each SARIF rule), and the adapter writes the class of each rule as ``kalkan-class``
  (:data:`kalkan.sarif.ingest.PACK_CLASS_ENGINES`).
- Cost: one more Opengrep start. Measured on Windows 11 on the vulnapp fixture (2026-10-25):
  kalkan's own pack 18 s, the four packs 43 s. Opengrep loads each rule file with a fixed cost
  (about 0.2 s), so the build joins the rules into bundles: the same rules as 1,088 files
  took 211 s. On 2026-11-07 (Windows 11, vulnapp, adapter run only): the three packs of then
  14.7 s, the ten packs of ADR-0007 17.6 s.

The switch: ``KALKAN_RULE_PACKS`` (:func:`kalkan.scanners.rulepacks.selection`). ``all`` (the
default), ``osi`` (only the packs with an OSI-approved license, the LGPL and GPL packs
included; the AGPL pack stays off), ``none`` or pack names. The status file records it.

Secrets: a result of a ``hardcoded-secrets`` rule keeps no matched text. ``after_run`` replaces
its snippets with ``REDACTED``, its message with the rule title and drops its fingerprints (an
Opengrep fingerprint hashes the match and would confirm a guessed value).
"""

from __future__ import annotations

import json
import os
import shutil
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from kalkan.errors import KalkanError, ToolError
from kalkan.scanners import rulepacks
from kalkan.scanners.adapters._sources import VENDOR_DIRS
from kalkan.scanners.adapters.opengrep import OpengrepAdapter, default_rules_dir
from kalkan.scanners.base import Invocation, ScanContext, work_dir
from kalkan.util.safe_io import atomic_write_json, read_bounded

MAX_SARIF_BYTES: Final = 50 * 1024 * 1024
#: The staging folder of the packs below the work folder (the working directory).
STAGING_DIRNAME: Final = "packs"
#: The status file lists at most this many run-time duplicates.
MAX_LISTED_DUPLICATES: Final = 100
SECRET_CLASS: Final = "hardcoded-secrets"
REDACTED: Final = "REDACTED"
#: Opengrep ``--timeout``: seconds per rule and file (module docstring).
RULE_TIMEOUT_SECONDS: Final = 10


@dataclass(frozen=True)
class PackPlan:
    """What one run uses: the packs, the switch and the run-time duplicates."""

    folder: Path
    selection: rulepacks.Selection
    packs: tuple[dict[str, Any], ...]  # the index entries of the enabled packs
    rules: dict[str, dict[str, Any]]  # rule ID to index record, enabled packs only
    duplicates: dict[str, str]  # pack rule ID to the kalkan rule it repeats
    disabled: tuple[dict[str, Any], ...]
    error: str | None = None


class OpengrepPacksAdapter(OpengrepAdapter):
    """``opengrep scan`` with the vendored rule packs."""

    name = "opengrep-packs"
    tool = "opengrep"
    output = "sarif-file"
    output_dir = "scans"
    output_name = "opengrep-packs.sarif"
    ok_exit_codes = (0,)
    timeout_seconds = 1800

    def __init__(
        self,
        packs_dir: Path | None = None,
        kalkan_rules_dir: Path | None = None,
        environ: Mapping[str, str] | None = None,
        *,
        home: Path | None = None,
    ) -> None:
        super().__init__(kalkan_rules_dir, home=home)
        self._packs_dir = packs_dir
        self._environ = environ
        self._cache: tuple[tuple[Any, ...], PackPlan] | None = None

    def packs_dir(self) -> Path:
        """Return the packs folder."""
        return self._packs_dir if self._packs_dir is not None else rulepacks.packs_dir()

    def kalkan_rules_dir(self) -> Path:
        """Return kalkan's own pack, for the run-time duplicate check."""
        return self._rules_dir if self._rules_dir is not None else default_rules_dir()

    def plan(self) -> PackPlan:
        """Return the plan of a run (cached while the index, the kalkan rules and the switch
        stay the same)."""
        folder = self.packs_dir()
        environ = os.environ if self._environ is None else self._environ
        key = (
            str(folder),
            _mtime(folder / rulepacks.INDEX_FILE),
            _folder_mtime(self.kalkan_rules_dir()),
            environ.get(rulepacks.ENV_VAR, ""),
        )
        if self._cache is not None and self._cache[0] == key:
            return self._cache[1]
        plan = self._make_plan(folder, environ)
        self._cache = (key, plan)
        return plan

    def _make_plan(self, folder: Path, environ: Mapping[str, str]) -> PackPlan:
        empty = rulepacks.Selection("", "default", (), {})
        try:
            index = rulepacks.load_index(folder)
        except KalkanError as exc:
            return PackPlan(folder, empty, (), {}, {}, (), f"rule pack index: {exc}")
        packs = [pack for pack in index.get("packs", []) if isinstance(pack, dict)]
        chosen = rulepacks.selection(packs, environ)
        by_name = {str(pack["name"]): pack for pack in packs}
        enabled = tuple(by_name[name] for name in chosen.enabled if by_name[name].get("rules_kept"))
        disabled = tuple(
            {
                "name": name,
                "group": by_name[name].get("group"),
                "license": by_name[name].get("license"),
                "reason": reason,
            }
            for name, reason in chosen.disabled.items()
        )
        names = {str(pack["name"]) for pack in enabled}
        rules = {
            str(record["id"]): record
            for record in index.get("rules", [])
            if isinstance(record, dict) and record.get("pack") in names
        }
        own = rulepacks.kalkan_rules(self.kalkan_rules_dir())
        duplicates = rulepacks.kalkan_duplicates(rules.values(), own)
        error = chosen.error
        if error is None:
            missing = [name for name in sorted(names) if not (folder / name).is_dir()]
            if missing:
                error = f"rule pack folder not found: {(folder / missing[0]).as_posix()}"
        return PackPlan(folder, chosen, enabled, rules, duplicates, disabled, error)

    def applies(self, ctx: ScanContext) -> tuple[bool, str]:
        plan = self.plan()
        if plan.error:
            return False, plan.error
        if not plan.packs:
            setting = plan.selection.setting or "all"
            return False, f"{rulepacks.ENV_VAR}={setting}: no rule pack is on"
        return True, ""

    def cwd(self, ctx: ScanContext) -> Path:
        """Return the staging folder of the packs (module docstring: the relative ``-f``
        paths)."""
        return work_dir(ctx.run_dir, self) / STAGING_DIRNAME

    def prepare(self, ctx: ScanContext, stage: Path) -> None:
        """Create the profile folder of opengrep and copy the bundle files of the enabled packs
        into the staging folder."""
        super().prepare(ctx, stage)
        plan = self.plan()
        target = self.cwd(ctx)
        for pack in plan.packs:
            source = plan.folder / str(pack["name"])
            for path in sorted(source.rglob("*.yaml")):
                if not path.is_file() or path.is_symlink():
                    continue
                copy = target / path.relative_to(plan.folder)
                copy.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, copy)

    def arguments(self, ctx: ScanContext, out: Path) -> list[str]:
        plan = self.plan()
        configs: list[str] = []
        for pack in plan.packs:
            configs += ["-f", str(pack["name"])]
        excluded: list[str] = []
        for rule_id in sorted(plan.duplicates):
            excluded += ["--exclude-rule", rule_id]
        for folder in sorted(VENDOR_DIRS):
            excluded += ["--exclude", folder]
        return [
            "scan",
            *configs,
            "--sarif",
            "--output",
            str(out),
            "--timeout",
            str(RULE_TIMEOUT_SECONDS),
            "--disable-version-check",
            "--rewrite-rule-ids",
            "--no-git-ignore",
            "--x-ignore-semgrepignore-files",
            *([] if ctx.honor_suppressions else ["--disable-nosem"]),
            *excluded,
            str(ctx.target_dir),
        ]

    def after_run(self, ctx: ScanContext, item: Invocation) -> None:
        """Stamp the class, pack and license on each SARIF rule and redact secret results."""
        try:
            doc = json.loads(read_bounded(item.output, MAX_SARIF_BYTES))
        except (KalkanError, ValueError) as exc:
            raise ToolError(f"opengrep did not write a valid SARIF file: {exc}") from None
        atomic_write_json(item.output, annotate_sarif(doc, self.plan().rules))

    def status_details(
        self, ctx: ScanContext, stdout_log: Path, stderr_log: Path, outputs: Sequence[Path]
    ) -> dict[str, Any]:
        """Return the coverage gaps of the ``opengrep`` adapter, ``rule_packs`` and
        ``kalkan_duplicates``."""
        details = super().status_details(ctx, stdout_log, stderr_log, outputs)
        details.update(self.pack_details())
        details["excluded_folders"] = sorted(VENDOR_DIRS)
        return details

    def pack_details(self) -> dict[str, Any]:
        """Return the ``rule_packs`` and ``kalkan_duplicates`` keys of the status file."""
        plan = self.plan()
        excluded_per_pack: dict[str, int] = {}
        for rule_id in plan.duplicates:
            pack = str(plan.rules[rule_id]["pack"])
            excluded_per_pack[pack] = excluded_per_pack.get(pack, 0) + 1
        listed = dict(sorted(plan.duplicates.items())[:MAX_LISTED_DUPLICATES])
        return {
            "rule_packs": {
                "setting": plan.selection.setting or "all",
                "source": plan.selection.source,
                "variable": rulepacks.ENV_VAR,
                "enabled": [
                    {
                        "name": pack["name"],
                        "group": pack.get("group"),
                        "license": pack.get("license"),
                        "upstream": pack.get("upstream"),
                        "commit": pack.get("commit"),
                        "rules": int(pack.get("rules_kept") or 0)
                        - excluded_per_pack.get(str(pack["name"]), 0),
                    }
                    for pack in plan.packs
                ],
                "disabled": list(plan.disabled),
            },
            "kalkan_duplicates": {
                "count": len(plan.duplicates),
                "rules": listed,
                "truncated": len(plan.duplicates) > MAX_LISTED_DUPLICATES,
            },
        }


def annotate_sarif(doc: Any, rules: Mapping[str, Mapping[str, Any]]) -> Any:
    """Return the SARIF document with ``kalkan-class``, ``kalkan-pack``, ``kalkan-license`` and
    ``kalkan-upstream-id`` on every known rule, a short title ``<pack>: <upstream ID>``, and
    the results of ``hardcoded-secrets`` rules redacted (module docstring)."""
    if not isinstance(doc, dict):
        raise ToolError("opengrep did not write a SARIF object")
    for run in doc.get("runs") or []:
        if not isinstance(run, dict):
            continue
        tool = run.get("tool")
        driver = tool.get("driver") if isinstance(tool, dict) else None
        driver_rules = driver.get("rules") if isinstance(driver, dict) else None
        secret_rules: dict[str, str] = {}
        for rule in driver_rules if isinstance(driver_rules, list) else []:
            if not isinstance(rule, dict):
                continue
            record = rules.get(str(rule.get("id")))
            if record is None:
                continue
            title = f"{record['pack']}: {record['upstream_id']}"
            properties = rule.setdefault("properties", {})
            if isinstance(properties, dict):
                properties["kalkan-class"] = record["class"]
                properties["kalkan-pack"] = record["pack"]
                properties["kalkan-license"] = record["license"]
                properties["kalkan-upstream-id"] = record["upstream_id"]
            rule["shortDescription"] = {"text": title}
            if record["class"] == SECRET_CLASS:
                secret_rules[str(rule["id"])] = title
        for result in run.get("results") or []:
            if isinstance(result, dict) and str(result.get("ruleId")) in secret_rules:
                redact_result(result, secret_rules[str(result["ruleId"])])
    return doc


def redact_result(result: dict[str, Any], title: str) -> None:
    """Remove the matched text of a secret result: snippets, message and fingerprints."""
    result["message"] = {"text": f"{title}: hardcoded credential (value redacted by kalkan)"}
    result.pop("fingerprints", None)
    result.pop("partialFingerprints", None)

    def scrub(location: Any) -> None:
        physical = location.get("physicalLocation") if isinstance(location, dict) else None
        if not isinstance(physical, dict):
            return
        for key in ("region", "contextRegion"):
            region = physical.get(key)
            if isinstance(region, dict) and "snippet" in region:
                region["snippet"] = {"text": REDACTED}

    for key in ("locations", "relatedLocations"):
        for location in result.get(key) or []:
            scrub(location)
    for flow in result.get("codeFlows") or []:
        threads = flow.get("threadFlows") if isinstance(flow, dict) else None
        for thread in threads if isinstance(threads, list) else []:
            steps = thread.get("locations") if isinstance(thread, dict) else None
            for step in steps if isinstance(steps, list) else []:
                if isinstance(step, dict):
                    scrub(step.get("location"))


def _mtime(path: Path) -> float:
    try:
        return path.stat().st_mtime
    except OSError:
        return -1.0


def _folder_mtime(folder: Path) -> tuple[float, ...]:
    try:
        return tuple(sorted(_mtime(path) for path in folder.iterdir() if path.is_file()))
    except OSError:
        return ()
