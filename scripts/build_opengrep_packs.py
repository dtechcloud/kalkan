#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build the Opengrep rule packs ``rules/opengrep-packs`` from the vendored copies (ADR-0005 K.8).

Usage::

    python scripts/build_opengrep_packs.py            # write rules/opengrep-packs
    python scripts/build_opengrep_packs.py --check    # compare with the files on disk (exit 1)
    python scripts/build_opengrep_packs.py --report   # print the counts per pack and reason

Inputs: the vendored rule files of each pack in ``third_party/<component>/`` (their list is
the component ``FILES.sha256``), ``third_party/MANIFEST.json`` (upstream, commit, license
header) and ``rules/opengrep-packs/curation.json`` (written by hand). The script reads the rule
files as data with :mod:`kalkan.util.miniyaml`; it never runs them. It needs no tool.

**Rule IDs and bundles.** Opengrep 1.30.1 loads every rule file with a fixed cost (about
0.2 s per file on Windows: 381 GitLab rules took 93 s as 381 files and 15 s as one file), and
it rejects files with several YAML documents. So the build joins the kept rules of a pack into
a few bundle files ``<pack>/<key>/rules.yaml``. The key is the first ``bundle_depth`` folders
of the upstream path (after the leading folders of ``bundle_skip``); when the key already holds
a rule with the same upstream ID, the key takes the next folder. Opengrep runs from the packs
folder with ``--rewrite-rule-ids``, so the rule ID is ``<pack>.<key folders>.<upstream ID>``.
The bundle keeps the text of each rule (and the comment header of its file) and only changes
its indentation; the build parses every bundle again and requires the same rules as the
vendored files. A bundle starts with a comment that names the pack, the license, the change and
the source files.

**Decisions.** For each rule, the first matching reason drops it (``kind`` in ``index.json``):

1. ``yaml``: the file is not YAML that the reader supports.
2. ``id-collision``: a rule of the same folder has the same upstream ID.
3. ``category``, ``confidence``: the metadata filters of the pack in ``curation.json``.
4. a drop group of ``curation.json`` (its own ``kind``).
5. ``no-class``: no class decides. The class comes from ``classes`` of ``curation.json`` (by
   rule ID), else from ``language_classes`` (a language whose rules all belong to one class:
   Solidity), else from the CWE metadata, CWE by CWE in rule order: the kalkan taxonomy first,
   then ``cwe_classes`` of ``curation.json``.
6. ``duplicate``: the rule repeats a kept rule of a pack with a higher priority
   (:func:`kalkan.scanners.rulepacks.repeats`), unless ``keep`` names it.

**Scope.** ``scope`` of ``curation.json`` narrows the files of named kept rules: the build adds
``paths: {exclude: [...]}`` to each such rule in its bundle, records the globs as
``scope_exclude`` in ``index.json`` and names the change in the bundle header. The matching
logic of the rule stays unchanged; the parse check expects exactly the vendored rule plus that
key. A rule that already has ``paths``, or a scope entry that names a rule which is not kept,
stops the build. Each entry carries the measurement that justifies it.

Outputs: the bundles and ``rules/opengrep-packs/index.json``. Only the pack folders named in
``curation.json`` are written.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
import shutil
import sys
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
THIRD_PARTY = REPO_ROOT / "third_party"
PACKS_DIR = REPO_ROOT / "rules" / "opengrep-packs"

sys.path.insert(0, str(REPO_ROOT / "src"))

from kalkan.findings.taxonomy import SLUGS  # noqa: E402
from kalkan.scanners import rulepacks  # noqa: E402
from kalkan.util import miniyaml  # noqa: E402

BUNDLE_NAME = "rules.yaml"
BUNDLE_INDENT = 2
RULE_FILE_SUFFIXES = (".yaml", ".yml")
_RULES_LINE = re.compile(r"rules:\s*(?:#.*)?")


class BuildError(Exception):
    """A vendored file or the curation does not fit the build."""


# -- vendored files ---------------------------------------------------------------------------


def _components() -> dict[str, dict[str, Any]]:
    manifest = json.loads((THIRD_PARTY / "MANIFEST.json").read_text(encoding="utf-8"))
    return {component["name"]: component for component in manifest["components"]}


def _vendored_files(component: dict[str, Any]) -> list[str]:
    hashes = THIRD_PARTY / component["name"] / "FILES.sha256"
    files = []
    for line in hashes.read_text(encoding="utf-8").splitlines():
        path = line.split("  ", 1)[1]
        if path.endswith(RULE_FILE_SUFFIXES) and path not in component["license_files"]:
            files.append(path)
    return sorted(files)


def _file_license(component: dict[str, Any], text: str) -> str:
    spec = component.get("license_header")
    if not spec:
        return component["license"]
    pattern = re.compile(spec["regex"])
    for line in text.splitlines()[:20]:
        match = pattern.search(line)
        if match:
            return spec["allowed"].get(match.group(1).strip(), "unknown")
    return "unknown"


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _is_comment_or_blank(line: str) -> bool:
    stripped = line.strip()
    return not stripped or stripped.startswith("#")


def split_rules(text: str) -> tuple[list[str], list[list[str]]]:
    """Split a rule file into its comment header and the lines of each ``rules`` entry.

    Comment and blank lines between two entries (at most at the entry indentation) belong to
    the next entry. Raises :class:`BuildError` for any other top-level shape.
    """
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    start = next((i for i, line in enumerate(lines) if _RULES_LINE.fullmatch(line)), None)
    if start is None:
        raise BuildError("no top-level 'rules:' line")
    for line in lines[:start]:
        if not _is_comment_or_blank(line) and line.strip() != "---":
            raise BuildError("content before 'rules:'")
    header = [line.strip() for line in lines[:start] if line.strip().startswith("#")]
    items: list[list[str]] = []
    pending: list[str] = []  # comments and blank lines not yet placed
    item_indent: int | None = None
    for line in lines[start + 1 :]:
        stripped = line.strip()
        column = _indent(line)
        if item_indent is None:
            if _is_comment_or_blank(line):
                pending.append(line)
                continue
            if not (stripped == "-" or stripped.startswith("- ")):
                raise BuildError("'rules' is not a block sequence")
            item_indent = column
        is_entry = column == item_indent and (stripped == "-" or stripped.startswith("- "))
        if is_entry:
            items.append([*[p for p in pending if p.strip()], line])
            pending = []
            continue
        if not stripped:
            pending.append(line)
            continue
        if stripped.startswith("#") and column <= item_indent:
            pending.append(line)
            continue
        if column <= item_indent:
            raise BuildError(f"unexpected top-level content: {stripped[:40]!r}")
        if not items:
            raise BuildError("content before the first rule")
        items[-1] += pending
        pending = []
        items[-1].append(line)
    return header, items


def _reindent(lines: list[str], shift: int) -> list[str]:
    out = []
    for line in lines:
        if not line:
            out.append(line)
        elif shift >= 0:
            out.append(" " * shift + line)
        else:
            out.append(line[min(-shift, _indent(line)) :])
    return out


def _upper(value: object) -> str | None:
    return value.strip().upper() if isinstance(value, str) and value.strip() else None


def _bundle_key(
    pack: dict[str, Any], file: str, upstream_id: str, taken: set[tuple[tuple[str, ...], str]]
) -> tuple[str, ...] | None:
    parts = list(PurePosixPath(file).parent.parts)
    skip = set(pack.get("bundle_skip", ()))
    while parts and parts[0] in skip:
        parts.pop(0)
    depth = min(int(pack.get("bundle_depth", 1)), len(parts))
    while True:
        key = tuple(parts[:depth])
        if (key, upstream_id) not in taken:
            taken.add((key, upstream_id))
            return key
        if depth >= len(parts):
            return None
        depth += 1


def collect(curation: dict[str, Any]) -> list[dict[str, Any]]:
    """Return one record per vendored rule (and per unreadable file), in pack and file order."""
    components = _components()
    records: list[dict[str, Any]] = []
    for pack in curation["packs"]:
        component = components[pack["component"]]
        folder = THIRD_PARTY / component["name"]
        taken: set[tuple[tuple[str, ...], str]] = set()
        for file in _vendored_files(component):
            text = (folder / file).read_text(encoding="utf-8")
            base = {"pack": pack["name"], "file": file, "license": _file_license(component, text)}
            try:
                document = miniyaml.load(text)
                header, items = split_rules(text)
            except (miniyaml.MiniYamlError, BuildError) as exc:
                records.append({**base, "id": f"{pack['name']}/{file}", "error": str(exc)})
                continue
            rules = document.get("rules") if isinstance(document, dict) else None
            if not isinstance(rules, list) or len(rules) != len(items):
                message = "the rule entries and the parsed rules differ"
                records.append({**base, "id": f"{pack['name']}/{file}", "error": message})
                continue
            for position, (rule, item) in enumerate(zip(rules, items, strict=True)):
                if not isinstance(rule, dict) or not isinstance(rule.get("id"), str):
                    continue
                # The last rule of a file without a final line break: in a bundle, its last
                # block scalar gains that line break (the only change that a bundle can make).
                open_end = position == len(items) - 1 and not text.endswith("\n")
                key = _bundle_key(pack, file, rule["id"], taken)
                metadata = rule.get("metadata") if isinstance(rule.get("metadata"), dict) else {}
                languages = rule.get("languages") if isinstance(rule.get("languages"), list) else []
                bundle = "/".join([*(key or ()), BUNDLE_NAME])
                records.append(
                    {
                        **base,
                        "id": rulepacks.full_rule_id(pack["name"], bundle, rule["id"]),
                        "bundle": bundle,
                        "collision": key is None,
                        "upstream_id": rule["id"],
                        "languages": [str(item) for item in languages],
                        "severity": str(rule.get("severity") or ""),
                        "category": metadata.get("category"),
                        "confidence": _upper(metadata.get("confidence")),
                        "cwe": rulepacks.rule_cwes(rule),
                        "sinks": sorted(rulepacks.sink_patterns(rule)),
                        "restrictions": sorted(rulepacks.restriction_patterns(rule)),
                        "rule": rule,
                        "lines": item,
                        "header": header,
                        "open_end": open_end,
                    }
                )
    return records


# -- decisions --------------------------------------------------------------------------------


def _matches(group: dict[str, Any], record: dict[str, Any]) -> bool:
    if group.get("pack") and group["pack"] != record["pack"]:
        return False
    if record["id"] in group.get("rules", ()):
        return True
    path = f"{record['pack']}/{record['file']}"
    return any(fnmatch.fnmatchcase(path, pattern) for pattern in group.get("paths", ()))


def decide(curation: dict[str, Any], records: list[dict[str, Any]]) -> None:
    """Set ``kind`` and ``reason`` of every dropped record and ``class`` of every kept one."""
    packs = {pack["name"]: pack for pack in curation["packs"]}
    groups = curation.get("drop", [])
    keep = {item["rule"] for item in curation.get("keep", [])}
    overrides: dict[str, str] = {}
    for item in curation.get("classes", []):
        if item["class"] not in SLUGS:
            raise BuildError(f"curation.json: unknown class {item['class']!r}")
        for rule_id in item["rules"]:
            overrides[rule_id] = item["class"]
    cwe_classes: dict[str, str] = {}
    for item in curation.get("cwe_classes", []):
        if item["class"] not in SLUGS:
            raise BuildError(f"curation.json: unknown class {item['class']!r}")
        for cwe in item["cwe"]:
            cwe_classes[cwe] = item["class"]
    language_classes: dict[str, str] = {}
    for item in curation.get("language_classes", []):
        if item["class"] not in SLUGS:
            raise BuildError(f"curation.json: unknown class {item['class']!r}")
        for family in rulepacks.language_families(item["languages"]):
            language_classes[family] = item["class"]

    for record in records:
        if "error" in record:
            record.update(kind="yaml", reason=f"the build cannot read the file: {record['error']}")
            continue
        if record["collision"]:
            record.update(kind="id-collision", reason="a rule of the same folder has the same ID")
            continue
        filters = packs[record["pack"]].get("filters", {})
        categories = filters.get("category")
        if categories is not None and record["category"] not in categories:
            record.update(
                kind="category",
                reason=f"metadata category {record['category']!r} (kept: {', '.join(categories)})",
            )
            continue
        confidences = filters.get("confidence")
        if confidences is not None and record["confidence"] not in confidences:
            kept = ", ".join("none" if item is None else item for item in confidences)
            record.update(
                kind="confidence",
                reason=f"metadata confidence {record['confidence']!r} (kept: {kept})",
            )
            continue
        group = next((item for item in groups if _matches(item, record)), None)
        if group is not None:
            record.update(kind=group["kind"], reason=group["reason"], group=group["name"])
            continue
        if record["id"] in overrides:
            record["class"], record["class_source"] = overrides[record["id"]], "override"
            continue
        families = rulepacks.language_families(record["languages"])
        by_language = {
            language_classes[family] for family in families if family in language_classes
        }
        if len(by_language) == 1:
            record["class"], record["class_source"] = by_language.pop(), "language"
            continue
        for cwe in record["cwe"]:
            slug = rulepacks.rule_class([cwe])
            if slug is not None:
                record["class"], record["class_source"] = slug, "cwe"
                break
            if cwe in cwe_classes:
                record["class"], record["class_source"] = cwe_classes[cwe], "cwe-curation"
                break
        else:
            record.update(
                kind="no-class",
                reason="no class override names the rule and no CWE maps to a kalkan class",
            )

    priority = [name for name in curation["priority"] if name in packs]
    kept_higher: list[tuple[str, rulepacks.Signature]] = []
    for name in priority:
        current = []
        for record in records:
            if record["pack"] != name or "kind" in record:
                continue
            signature = rulepacks.Signature.from_record(record)
            if record["id"] not in keep:
                other = next(
                    (oid for oid, sig in kept_higher if rulepacks.repeats(signature, sig)), None
                )
                if other is not None:
                    record.update(kind="duplicate", reason=f"repeats {other}")
                    del record["class"], record["class_source"]
                    continue
            current.append((record["id"], signature))
        kept_higher += current

    names = {record["id"] for record in records}
    for group in groups:
        for rule_id in group.get("rules", ()):
            if rule_id not in names:
                raise BuildError(f"curation.json: drop group {group['name']!r} names {rule_id!r}")
    for rule_id in [*keep, *overrides]:
        if rule_id not in names:
            raise BuildError(f"curation.json: unknown rule {rule_id!r}")


# -- outputs ----------------------------------------------------------------------------------


def scope_excludes(curation: dict[str, Any], records: list[dict[str, Any]]) -> dict[str, list[str]]:
    """Return {kept rule ID: exclude globs} from ``scope`` of ``curation.json`` (module docstring,
    "Scope"); raise :class:`BuildError` for an entry that names no kept rule or no glob."""
    kept = {
        record["id"]: record for record in records if "kind" not in record and "error" not in record
    }
    found: dict[str, list[str]] = {}
    for entry in curation.get("scope", ()):
        globs = entry.get("exclude")
        if not entry.get("reason") or not isinstance(globs, list) or not globs:
            raise BuildError(f"scope entry {entry.get('rules')}: needs a reason and exclude globs")
        if not all(isinstance(glob, str) and glob.strip() for glob in globs):
            raise BuildError(f"scope entry {entry.get('rules')}: every exclude glob is a string")
        for rule_id in entry.get("rules", ()):
            record = kept.get(rule_id)
            if record is None:
                raise BuildError(f"scope: {rule_id} is not a kept rule")
            if "paths" in record["rule"]:
                raise BuildError(f"scope: {rule_id} already has paths; extend the build first")
            found[rule_id] = [*found.get(rule_id, []), *globs]
    return found


def _scoped_lines(item: list[str], globs: list[str]) -> list[str]:
    """Return the entry lines with ``paths.exclude`` inserted right after the ``- id:`` line."""
    position = next(i for i, line in enumerate(item) if line.strip().startswith("-"))
    key = " " * (_indent(item[position]) + 2)
    added = [f"{key}paths:", f"{key}  exclude:"] + [
        f"{key}  - {json.dumps(glob)}" for glob in globs
    ]
    return [*item[: position + 1], *added, *item[position + 1 :]]


def bundles(
    curation: dict[str, Any],
    records: list[dict[str, Any]],
    scope: dict[str, list[str]] | None = None,
) -> dict[str, str]:
    """Return {path below the packs folder: bundle text} and check each bundle by parsing it."""
    scope = scope or {}
    components = _components()
    packs = {pack["name"]: pack for pack in curation["packs"]}
    grouped: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        if "kind" not in record:
            grouped.setdefault(f"{record['pack']}/{record['bundle']}", []).append(record)
    texts: dict[str, str] = {}
    for path, members in sorted(grouped.items()):
        pack = packs[members[0]["pack"]]
        component = components[pack["component"]]
        sources = sorted({member["file"] for member in members})
        lines = [
            "# Generated by scripts/build_opengrep_packs.py. Do not edit.",
            f"# Pack: {pack['name']} ({component['upstream']}, commit {component['commit']}).",
            f"# License: {pack['license']}; see third_party/{component['name']}/"
            f"{', '.join(component['license_files'])}.",
            f"# Changed by kalkan on {curation['changed']}: the kept rules of {len(sources)} "
            "upstream file(s) are joined into this file",
            "# and re-indented. The rule text is unchanged. The unmodified files are in "
            f"third_party/{component['name']}/.",
        ]
        narrowed = sorted(member["id"] for member in members if member["id"] in scope)
        if narrowed:
            lines.append(
                f"# Scope: kalkan added paths.exclude to {len(narrowed)} rule(s) (curation.json "
                "scope); their matching logic is unchanged."
            )
        lines += [
            "rules:",
        ]
        last_file = None
        for member in members:
            if member["file"] != last_file:
                lines.append(" " * BUNDLE_INDENT + f"# source: {member['file']}")
                lines += [" " * BUNDLE_INDENT + line for line in member["header"]]
                last_file = member["file"]
            item = member["lines"]
            if member["id"] in scope:
                item = _scoped_lines(item, scope[member["id"]])
            first = next(line for line in item if line.strip().startswith("-"))
            lines += _reindent(item, BUNDLE_INDENT - _indent(first))
        text = "\n".join(lines) + "\n"
        parsed = miniyaml.load(text)
        found = parsed.get("rules") if isinstance(parsed, dict) else None
        if not isinstance(found, list) or len(found) != len(members):
            raise BuildError(f"{path}: the bundle does not parse to the vendored rules")
        for member, rule in zip(members, found, strict=True):
            expected = member["rule"]
            if member["id"] in scope:
                expected = {**expected, "paths": {"exclude": scope[member["id"]]}}
            if not _same(rule, expected, member["open_end"]):
                raise BuildError(f"{path}: {member['id']} differs from the vendored rule")
        texts[path] = text
    return texts


def _same(bundled: object, vendored: object, open_end: bool) -> bool:
    """Return True when a bundled rule equals the vendored one; with ``open_end`` a string may
    also differ by one final line break (the last block scalar of a file without one)."""
    if bundled == vendored:
        return True
    if not open_end:
        return False
    if isinstance(bundled, str) and isinstance(vendored, str):
        return bundled == vendored + "\n"
    if isinstance(bundled, dict) and isinstance(vendored, dict):
        return bundled.keys() == vendored.keys() and all(
            _same(bundled[key], vendored[key], open_end) for key in bundled
        )
    if isinstance(bundled, list) and isinstance(vendored, list):
        return len(bundled) == len(vendored) and all(
            _same(a, b, open_end) for a, b in zip(bundled, vendored, strict=True)
        )
    return False


def build_index(
    curation: dict[str, Any],
    records: list[dict[str, Any]],
    scope: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    scope = scope or {}
    components = _components()
    packs = []
    for pack in curation["packs"]:
        component = components[pack["component"]]
        mine = [record for record in records if record["pack"] == pack["name"]]
        dropped = Counter(record["kind"] for record in mine if "kind" in record)
        kept = [record for record in mine if "kind" not in record]
        packs.append(
            {
                "name": pack["name"],
                "component": component["name"],
                "group": pack["group"],
                "license": pack["license"],
                "upstream": component["upstream"],
                "commit": component["commit"],
                "files_vendored": len({record["file"] for record in mine}),
                "rules_vendored": sum(1 for record in mine if "error" not in record),
                "rules_kept": len(kept),
                "bundles": sorted({record["bundle"] for record in kept}),
                "dropped": dict(sorted(dropped.items())),
            }
        )
    rules = [
        {
            "id": record["id"],
            "pack": record["pack"],
            "bundle": record["bundle"],
            "file": record["file"],
            "upstream_id": record["upstream_id"],
            "license": record["license"],
            "languages": record["languages"],
            "severity": record["severity"],
            "class": record["class"],
            "class_source": record["class_source"],
            "cwe": record["cwe"],
            "sinks": record["sinks"],
            "restrictions": record["restrictions"],
            **({"scope_exclude": scope[record["id"]]} if record["id"] in scope else {}),
        }
        for record in sorted(records, key=lambda item: item["id"])
        if "kind" not in record
    ]
    reasons: dict[tuple[str, str, str], list[str]] = {}
    for record in records:
        if "kind" in record:
            key = (record["pack"], record["kind"], record["reason"])
            reasons.setdefault(key, []).append(record["id"])
    dropped = [
        {"pack": pack, "kind": kind, "reason": reason, "rules": sorted(ids)}
        for (pack, kind, reason), ids in sorted(reasons.items())
    ]
    return {
        "schema": 1,
        "generator": "scripts/build_opengrep_packs.py",
        "about": (
            "Generated from third_party/ and curation.json. Do not edit. Rule IDs are the IDs "
            "that Opengrep reports with --rewrite-rule-ids from this folder."
        ),
        "priority": curation["priority"],
        "packs": packs,
        "rules": rules,
        "dropped": dropped,
    }


def expected_outputs(curation: dict[str, Any]) -> tuple[str, dict[str, str], dict[str, Any]]:
    """Return (index.json text, {bundle path: text}, index)."""
    records = collect(curation)
    decide(curation, records)
    scope = scope_excludes(curation, records)
    texts = bundles(curation, records, scope)
    index = build_index(curation, records, scope)
    return dump_index(index), texts, index


def dump_index(index: dict[str, Any]) -> str:
    """Return ``index.json`` text with one line per pack, rule and drop group (short diffs)."""
    lines = ["{"]
    items = list(index.items())
    for position, (key, value) in enumerate(items):
        comma = "," if position < len(items) - 1 else ""
        if isinstance(value, list) and value and all(isinstance(item, dict) for item in value):
            lines.append(f" {json.dumps(key)}: [")
            for number, item in enumerate(value):
                tail = "," if number < len(value) - 1 else ""
                lines.append("  " + json.dumps(item, ensure_ascii=False) + tail)
            lines.append(" ]" + comma)
        else:
            lines.append(f" {json.dumps(key)}: {json.dumps(value, ensure_ascii=False)}{comma}")
    lines.append("}")
    return "\n".join(lines) + "\n"


def _disk_files(curation: dict[str, Any]) -> dict[str, Path]:
    found: dict[str, Path] = {}
    for pack in curation["packs"]:
        folder = PACKS_DIR / pack["name"]
        if folder.is_dir():
            for path in folder.rglob("*"):
                if path.is_file():
                    found[path.relative_to(PACKS_DIR).as_posix()] = path
    return found


def check(curation: dict[str, Any]) -> int:
    text, texts, _ = expected_outputs(curation)
    problems = []
    index_path = PACKS_DIR / rulepacks.INDEX_FILE
    if not index_path.is_file() or index_path.read_text(encoding="utf-8") != text:
        problems.append("index.json differs from a fresh build")
    disk = _disk_files(curation)
    for path in sorted(set(texts) - set(disk)):
        problems.append(f"missing file {path}")
    for path in sorted(set(disk) - set(texts)):
        problems.append(f"unexpected file {path}")
    for path in sorted(set(texts) & set(disk)):
        if disk[path].read_text(encoding="utf-8") != texts[path]:
            problems.append(f"modified file {path}")
    for problem in problems[:50]:
        print(problem, file=sys.stderr)
    print("opengrep packs check:", "FAILED" if problems else "OK")
    return 1 if problems else 0


def write(curation: dict[str, Any]) -> int:
    text, texts, index = expected_outputs(curation)
    for pack in curation["packs"]:
        folder = PACKS_DIR / pack["name"]
        if folder.exists():
            shutil.rmtree(folder)
    for path, content in sorted(texts.items()):
        target = PACKS_DIR / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8", newline="\n")
    (PACKS_DIR / rulepacks.INDEX_FILE).write_text(text, encoding="utf-8", newline="\n")
    report(index)
    return 0


def report(index: dict[str, Any]) -> None:
    for pack in index["packs"]:
        print(
            f"{pack['name']}: vendored {pack['rules_vendored']} rules in {pack['files_vendored']} "
            f"files, kept {pack['rules_kept']} rules in {len(pack['bundles'])} bundles, "
            f"dropped {pack['dropped']}"
        )
    classes = Counter(rule["class"] for rule in index["rules"])
    print("classes:", dict(sorted(classes.items())))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="compare with the files on disk")
    mode.add_argument("--report", action="store_true", help="print the counts of a fresh build")
    args = parser.parse_args(argv)
    curation = rulepacks.load_curation(PACKS_DIR)
    try:
        if args.check:
            return check(curation)
        if args.report:
            report(expected_outputs(curation)[2])
            return 0
        return write(curation)
    except BuildError as exc:
        print(f"build failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
