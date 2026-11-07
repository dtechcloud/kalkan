# SPDX-License-Identifier: MIT
"""The vendored Opengrep rule packs (ADR-0005 K.8): the duplicate check, the switch, the class
mapping, the build output and the ``opengrep-packs`` adapter command line. No tool needed."""

from __future__ import annotations

import fnmatch
import importlib.util
import json
from pathlib import Path

import pytest

from kalkan.findings.taxonomy import SLUGS
from kalkan.sarif.ingest import PACK_CLASS_ENGINES, ingest_document
from kalkan.scanners import registry, rulepacks
from kalkan.scanners.adapters.opengrep_packs import (
    REDACTED,
    OpengrepPacksAdapter,
    annotate_sarif,
)
from kalkan.scanners.base import ScanContext
from kalkan.scanners.rulepacks import Signature, repeats

ROOT = Path(__file__).resolve().parents[2]
PACKS = ROOT / "rules" / "opengrep-packs"
TOOL = Path("/opt/opengrep")


@pytest.fixture(scope="module")
def build():
    spec = importlib.util.spec_from_file_location(
        "build_opengrep_packs", ROOT / "scripts" / "build_opengrep_packs.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def index():
    return rulepacks.load_index(PACKS)


@pytest.fixture(scope="module")
def curation():
    return rulepacks.load_curation(PACKS)


def make_ctx(tmp_path: Path, *, honor: bool = False) -> ScanContext:
    run = (tmp_path / "run").resolve()
    (run / "target").mkdir(parents=True, exist_ok=True)
    return ScanContext(
        run_dir=run,
        target_dir=run / "target",
        source_dir=None,
        tech=frozenset(),
        honor_suppressions=honor,
    )


# --------------------------------------------------------------------------------------------
# rule IDs, patterns and the duplicate check


def test_full_rule_id_follows_the_rewrite_of_opengrep():
    assert rulepacks.full_rule_id("gitlab", "csharp/rules.yaml", "x") == "gitlab.csharp.x"
    assert rulepacks.full_rule_id("p", "a/b/rules.yaml", "r-1") == "p.a.b.r-1"


def test_language_families():
    assert rulepacks.language_families(["ts", "JavaScript"]) == {"javascript"}
    assert rulepacks.language_families(["cpp", "c"]) == {"c"}
    assert rulepacks.language_families(["C#"]) == {"csharp"}


def test_normalize_pattern():
    assert rulepacks.normalize_pattern("$CUR.execute( $Q ,  ...)") == "$X.execute($X,...)"
    assert rulepacks.normalize_pattern("$CUR.execute($Q, ...)", collapse=True) == "$X.execute(...)"
    assert rulepacks.normalize_pattern('Cipher.getInstance("DES")') == 'Cipher.getInstance("DES")'
    assert rulepacks.normalize_pattern("regex:a  b") == "regex:a  b"
    nested = rulepacks.normalize_pattern("foo(bar($X), [$Y])", collapse=True)
    assert nested == "foo(...)"


def test_sink_and_restriction_patterns():
    search = {
        "patterns": [
            {"pattern-either": [{"pattern": "eval($X)"}, {"pattern": "exec($X)"}]},
            {"pattern-not": 'eval("...")'},
            {"pattern-inside": "def $F(...): ..."},
            {"metavariable-regex": {"metavariable": "$X", "regex": "^req"}},
        ]
    }
    assert rulepacks.sink_patterns(search) == {"eval($X)", "exec($X)"}
    assert rulepacks.restriction_patterns(search) == {
        'not:eval("...")',
        "inside:def $X(...):...",
        'metavariable-regex:{"metavariable": "$X", "regex": "^req"}',
    }
    taint = {
        "mode": "taint",
        "pattern-sources": [{"pattern": "request.args"}],
        "pattern-sinks": [{"patterns": [{"pattern": "$C.execute($Q, ...)"}]}],
        "pattern-sanitizers": [{"pattern": "int(...)"}],
    }
    assert rulepacks.sink_patterns(taint) == {"$X.execute(...)"}
    assert rulepacks.restriction_patterns(taint) == frozenset()


def sig(slug="sqli", languages=("python",), sinks=("$X.execute(...)",), restrictions=()):
    return Signature(
        slug,
        rulepacks.language_families(languages),
        frozenset(sinks),
        frozenset(restrictions),
    )


def test_repeats():
    other = sig(sinks=("$X.execute(...)", "$X.executemany(...)"))
    assert repeats(sig(), other)
    assert not repeats(sig(slug="xss"), other)
    assert not repeats(sig(languages=("go",)), other)
    assert not repeats(sig(sinks=("$X.execute(...)", "$X.raw(...)")), other)
    assert not repeats(sig(sinks=()), other)
    # The other rule narrows its matches with a condition the candidate lacks: no repeat.
    assert not repeats(sig(), sig(restrictions=("not:$X.execute(...)",)))
    # The candidate narrows its matches: the other rule still covers it.
    assert repeats(sig(restrictions=("not:$X.execute(...)",)), sig())


def write_rules(folder: Path, name: str, text: str) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    (folder / name).write_text(text, encoding="utf-8")


KALKAN_RULE = """rules:
  - id: kalkan.python.deserialization.unsafe-pickle
    languages: [python]
    severity: ERROR
    message: m
    metadata:
      kalkan_class: deserialization
    pattern-either:
      - pattern: pickle.loads(...)
      - pattern: pickle.load(...)
"""


def test_kalkan_duplicates_follow_the_current_kalkan_rules(tmp_path):
    record = {
        "id": "pack.python.pickle",
        "class": "deserialization",
        "languages": ["python"],
        "sinks": ["pickle.loads(...)"],
        "restrictions": [],
    }
    other = {**record, "id": "pack.python.marshal", "sinks": ["marshal.loads(...)"]}
    own_dir = tmp_path / "opengrep"
    write_rules(own_dir, "python.yaml", KALKAN_RULE)
    own = rulepacks.kalkan_rules(own_dir)
    assert [rule.id for rule in own] == ["kalkan.python.deserialization.unsafe-pickle"]
    assert rulepacks.kalkan_duplicates([record, other], own) == {
        "pack.python.pickle": "kalkan.python.deserialization.unsafe-pickle"
    }
    # A new kalkan rule (another agent adds it) excludes the pack rule without a rebuild.
    write_rules(
        own_dir,
        "more.yaml",
        KALKAN_RULE.replace("unsafe-pickle", "unsafe-marshal").replace("pickle.", "marshal."),
    )
    found = rulepacks.kalkan_duplicates([record, other], rulepacks.kalkan_rules(own_dir))
    assert found["pack.python.marshal"] == "kalkan.python.deserialization.unsafe-marshal"


# --------------------------------------------------------------------------------------------
# the switch


PACK_ENTRIES = [
    {"name": "gitlab", "group": "osi"},
    {"name": "trailofbits", "group": "agpl"},
    {"name": "0xdea", "group": "osi"},
]


def test_selection_defaults_to_every_pack():
    chosen = rulepacks.selection(PACK_ENTRIES, {})
    assert chosen.enabled == ("gitlab", "trailofbits", "0xdea")
    assert (chosen.setting, chosen.source, chosen.disabled, chosen.error) == (
        "all",
        "default",
        {},
        None,
    )


def test_selection_osi_turns_the_agpl_pack_off():
    chosen = rulepacks.selection(PACK_ENTRIES, {"KALKAN_RULE_PACKS": "OSI"})
    assert chosen.enabled == ("gitlab", "0xdea")
    assert set(chosen.disabled) == {"trailofbits"}
    assert "'agpl'" in chosen.disabled["trailofbits"]
    assert chosen.source == "KALKAN_RULE_PACKS"


def test_selection_none_names_and_errors():
    assert rulepacks.selection(PACK_ENTRIES, {"KALKAN_RULE_PACKS": "none"}).enabled == ()
    named = rulepacks.selection(PACK_ENTRIES, {"KALKAN_RULE_PACKS": "0xdea, gitlab"})
    assert named.enabled == ("gitlab", "0xdea")
    bad = rulepacks.selection(PACK_ENTRIES, {"KALKAN_RULE_PACKS": "gitlab,nope"})
    assert bad.enabled == () and "not valid" in (bad.error or "")


def test_selection_ignores_a_removed_pack():
    old = rulepacks.selection(PACK_ENTRIES, {"KALKAN_RULE_PACKS": "gitlab,opengrep-rules"})
    assert old.enabled == ("gitlab",) and old.error is None
    only = rulepacks.selection(PACK_ENTRIES, {"KALKAN_RULE_PACKS": "opengrep-rules"})
    assert only.enabled == () and only.error is None
    assert "opengrep-rules" in rulepacks.REMOVED_PACKS


# --------------------------------------------------------------------------------------------
# the build output and the curation


def test_the_packs_are_current(build, curation):
    """``python scripts/build_opengrep_packs.py --check`` (no tool needed)."""
    assert build.check(curation) == 0


def test_curation_is_well_formed(curation, index):
    assert curation["priority"][0] == "kalkan"
    assert [pack["name"] for pack in curation["packs"]] == curation["priority"][1:]
    groups = {pack["name"]: pack["group"] for pack in curation["packs"]}
    assert groups == {
        "gitlab": "osi",
        "trailofbits": "agpl",
        "0xdea": "osi",
        "atlassian": "osi",
        "elttam": "osi",
        "njsscan": "osi",
        "mobsfscan": "osi",
        "mindedsecurity": "osi",
        "aikido": "osi",
        "semgrep-codeql": "osi",
    }
    kinds = {
        "twin-fp",
        "noisy",
        "audit",
        "non-security",
        "scope",
        "parse",
        "slow",
        "best-practice",
        "covered",
        "duplicate",
    }
    for group in curation["drop"]:
        assert group["name"] and group["reason"] and group["kind"] in kinds, group
        assert group.get("rules") or group.get("paths"), group
    for item in [*curation["classes"], *curation["cwe_classes"], *curation["language_classes"]]:
        assert item["class"] in SLUGS and item["reason"], item
    assert {pack["name"]: pack["group"] for pack in index["packs"]} == groups


def test_every_kept_rule_has_a_class_and_a_known_license(index):
    ids = [rule["id"] for rule in index["rules"]]
    assert len(ids) == len(set(ids))
    licenses = {
        "gitlab": {"MIT", "LGPL-3.0-only"},
        "trailofbits": {"AGPL-3.0-only"},
        "0xdea": {"MIT"},
        "atlassian": {"LGPL-2.1-only"},
        "elttam": {"MIT"},
        "njsscan": {"LGPL-3.0-or-later"},
        "mobsfscan": {"LGPL-3.0-or-later"},
        "mindedsecurity": {"GPL-3.0-only"},
        "aikido": {"MIT"},
        "semgrep-codeql": {"MIT"},
    }
    for rule in index["rules"]:
        assert rule["id"].startswith(rule["pack"] + "."), rule["id"]
        assert rule["class"] in SLUGS, rule["id"]
        assert rule["class_source"] in {"cwe", "cwe-curation", "language", "override"}
        assert rule["license"] in licenses[rule["pack"]], rule["id"]
        assert (PACKS / rule["pack"] / rule["bundle"]).is_file(), rule["id"]


def test_every_dropped_rule_has_a_reason(index):
    for group in index["dropped"]:
        assert group["kind"] and group["reason"] and group["rules"], group
    kept = {rule["id"] for rule in index["rules"]}
    dropped = {rule_id for group in index["dropped"] for rule_id in group["rules"]}
    assert not kept & dropped
    for pack in index["packs"]:
        assert pack["rules_kept"] + sum(pack["dropped"].values()) >= pack["rules_vendored"]


def test_scope_groups_leave_no_rule(index, curation):
    scoped = [group for group in curation["drop"] if group["kind"] == "scope"]
    for rule in index["rules"]:
        path = f"{rule['pack']}/{rule['file']}"
        for group in scoped:
            assert not any(fnmatch.fnmatchcase(path, p) for p in group.get("paths", ())), path


def test_no_kept_rule_repeats_a_rule_of_a_pack_with_a_higher_priority(index, curation):
    keep = {item["rule"] for item in curation["keep"]}
    order = [name for name in curation["priority"] if name != "kalkan"]
    for position, name in enumerate(order):
        higher = [
            Signature.from_record(rule)
            for rule in index["rules"]
            if rule["pack"] in order[:position]
        ]
        for rule in index["rules"]:
            if rule["pack"] != name or rule["id"] in keep:
                continue
            candidate = Signature.from_record(rule)
            assert not any(repeats(candidate, other) for other in higher), rule["id"]


def test_bundles_name_their_license_and_the_change(index):
    for pack in index["packs"]:
        for bundle in pack["bundles"]:
            head = (PACKS / pack["name"] / bundle).read_text(encoding="utf-8")[:900]
            assert pack["license"] in head and "Changed by kalkan" in head, bundle
            assert f"third_party/{pack['component']}/" in head


def test_split_rules_and_reindent(build):
    text = (
        "# License: MIT\n---\nrules:\n- id: a\n  pattern: |\n    x\n\n    y\n"
        "# between\n- id: b\n  pattern: z\n"
    )
    header, items = build.split_rules(text)
    assert header == ["# License: MIT"]
    assert items[0] == ["- id: a", "  pattern: |", "    x", "", "    y"]
    assert items[1] == ["# between", "- id: b", "  pattern: z"]
    assert build._reindent(["- id: a", "", "  x: 1"], 2) == ["  - id: a", "", "    x: 1"]
    assert build._reindent(["    - id: a"], -2) == ["  - id: a"]


def test_open_end_tolerates_one_final_line_break(build):
    assert build._same({"p": "x\n"}, {"p": "x"}, True)
    assert not build._same({"p": "x\n"}, {"p": "x"}, False)
    assert not build._same({"p": "x\n\n"}, {"p": "x"}, True)


# --------------------------------------------------------------------------------------------
# the adapter


def test_registry_runs_the_packs_after_kalkans_pack():
    names = [adapter.name for adapter in registry.SCANNERS]
    assert names[names.index("opengrep") + 1] == "opengrep-packs"
    assert "opengrep-packs" in PACK_CLASS_ENGINES


def test_command_line(tmp_path, index):
    adapter = OpengrepPacksAdapter(environ={})
    ctx = make_ctx(tmp_path)
    out = tmp_path / "out.sarif"
    argv = adapter.command(ctx, TOOL, out)
    assert argv[:2] == [str(TOOL), "scan"]
    configs = [argv[i + 1] for i, item in enumerate(argv) if item == "-f"]
    assert configs == [pack["name"] for pack in index["packs"]]
    for flag in (
        "--sarif",
        "--disable-version-check",
        "--rewrite-rule-ids",
        "--no-git-ignore",
        "--x-ignore-semgrepignore-files",
        "--disable-nosem",
    ):
        assert flag in argv
    assert argv[argv.index("--output") + 1] == str(out)
    # 5 s (the Opengrep default) lost real results to timeouts on a large C# project.
    assert argv[argv.index("--timeout") + 1] == "10"
    assert argv[-1] == str(ctx.target_dir)
    assert "--no-rewrite-rule-ids" not in argv and "--config" not in argv
    assert not any(item.startswith(("http", "git+", "p/")) for item in configs)
    excluded = [argv[i + 1] for i, item in enumerate(argv) if item == "--exclude-rule"]
    assert excluded == sorted(adapter.plan().duplicates)
    staging = ctx.run_dir / "scans" / ".work" / "opengrep-packs" / "packs"
    assert adapter.cwd(ctx) == staging
    assert adapter.applies(ctx) == (True, "")


def test_prepare_copies_the_bundles_into_the_run(tmp_path, index):
    adapter = OpengrepPacksAdapter(environ={"KALKAN_RULE_PACKS": "osi"})
    ctx = make_ctx(tmp_path)
    adapter.prepare(ctx, tmp_path / "stage.sarif")
    staging = adapter.cwd(ctx)
    assert staging.resolve().is_relative_to(ctx.run_dir)
    copied = sorted(path.relative_to(staging).as_posix() for path in staging.rglob("*.yaml"))
    expected = sorted(
        f"{pack['name']}/{bundle}"
        for pack in index["packs"]
        if pack["group"] == "osi"
        for bundle in pack["bundles"]
    )
    assert copied == expected
    first = expected[0]
    assert (staging / first).read_bytes() == (PACKS / first).read_bytes()


def test_honor_suppressions_keeps_nosem(tmp_path):
    adapter = OpengrepPacksAdapter(environ={})
    argv = adapter.command(make_ctx(tmp_path, honor=True), TOOL, tmp_path / "o")
    assert "--disable-nosem" not in argv


def test_switch_osi_and_none(tmp_path):
    ctx = make_ctx(tmp_path)
    osi = OpengrepPacksAdapter(environ={"KALKAN_RULE_PACKS": "osi"})
    argv = osi.command(ctx, TOOL, tmp_path / "o")
    assert [argv[i + 1] for i, item in enumerate(argv) if item == "-f"] == [
        "gitlab",
        "0xdea",
        "atlassian",
        "elttam",
        "njsscan",
        "mobsfscan",
        "mindedsecurity",
        "aikido",
        "semgrep-codeql",
    ]
    details = osi.pack_details()["rule_packs"]
    assert details["setting"] == "osi" and details["source"] == "KALKAN_RULE_PACKS"
    assert {item["name"] for item in details["disabled"]} == {"trailofbits"}
    assert all("osi" in item["reason"] for item in details["disabled"])
    none = OpengrepPacksAdapter(environ={"KALKAN_RULE_PACKS": "none"})
    applies, reason = none.applies(ctx)
    assert not applies and "KALKAN_RULE_PACKS=none" in reason
    bad = OpengrepPacksAdapter(environ={"KALKAN_RULE_PACKS": "everything"})
    applies, reason = bad.applies(ctx)
    assert not applies and "not valid" in reason


def test_status_details_list_the_packs_and_duplicates(index):
    details = OpengrepPacksAdapter(environ={}).pack_details()
    enabled = details["rule_packs"]["enabled"]
    assert [pack["name"] for pack in enabled] == [pack["name"] for pack in index["packs"]]
    assert all(pack["license"] and pack["commit"] for pack in enabled)
    count = details["kalkan_duplicates"]["count"]
    assert sum(pack["rules"] for pack in enabled) == len(index["rules"]) - count


def test_missing_index_skips_the_adapter(tmp_path):
    adapter = OpengrepPacksAdapter(packs_dir=tmp_path / "none", environ={})
    applies, reason = adapter.applies(make_ctx(tmp_path))
    assert not applies and "index" in reason


def sarif_with(rule_id: str, tags: list[str], snippet: str = "password = 'hunter2'") -> dict:
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Opengrep",
                        "rules": [
                            {
                                "id": rule_id,
                                "shortDescription": {"text": "Opengrep Finding: x"},
                                "properties": {"tags": tags},
                                "defaultConfiguration": {"level": "error"},
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": rule_id,
                        "message": {"text": f"secret {snippet}"},
                        "fingerprints": {"matchBasedId/v1": "abc"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "app.py"},
                                    "region": {
                                        "startLine": 3,
                                        "snippet": {"text": snippet},
                                    },
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }


def test_annotate_sarif_stamps_the_class_and_redacts_secrets(tmp_path):
    record = {
        "id": "pack.python.hardcoded",
        "pack": "pack",
        "upstream_id": "hardcoded",
        "class": "hardcoded-secrets",
        "license": "MIT",
    }
    doc = annotate_sarif(sarif_with(record["id"], ["CWE-798: x"]), {record["id"]: record})
    rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["properties"]["kalkan-class"] == "hardcoded-secrets"
    assert rule["properties"]["kalkan-pack"] == "pack"
    assert rule["properties"]["kalkan-license"] == "MIT"
    assert rule["shortDescription"]["text"] == "pack: hardcoded"
    result = doc["runs"][0]["results"][0]
    assert "hunter2" not in json.dumps(result)
    assert result["locations"][0]["physicalLocation"]["region"]["snippet"]["text"] == REDACTED
    assert "fingerprints" not in result


def test_ingest_takes_the_class_of_the_pack_rule():
    record = {
        "id": "pack.python.tainted-sql",
        "pack": "pack",
        "upstream_id": "tainted-sql",
        "class": "sqli",
        "license": "MIT",
    }
    # CWE-704 maps to no class; the stamped kalkan-class decides.
    doc = annotate_sarif(sarif_with(record["id"], ["CWE-704: x"], "q"), {record["id"]: record})
    outcome = ingest_document(doc, "opengrep-packs", None, "scans/opengrep-packs.sarif")
    assert [candidate["class"] for candidate in outcome.candidates] == ["sqli"]
    # Another engine ignores the property.
    other = ingest_document(doc, "opengrep", None, "scans/opengrep.sarif")
    assert [candidate["class"] for candidate in other.candidates] == [None]


def test_scope_narrows_a_rule_without_changing_its_logic():
    # curation.json scope: the slow Express-handler rule skips minified bundles; the bundle
    # holds the vendored rule plus exactly the added paths key, and index.json records it.
    curation = json.loads((PACKS / "curation.json").read_text(encoding="utf-8"))
    entry = next(item for item in curation["scope"] if item["exclude"] == ["*.min.js"])
    rule_id = "gitlab.lgpl.rules_lgpl_javascript_dos_rule-regex-dos"
    assert rule_id in entry["rules"] and "false positives" in entry["reason"]
    index = json.loads((PACKS / "index.json").read_text(encoding="utf-8"))
    record = next(rule for rule in index["rules"] if rule["id"] == rule_id)
    assert record["scope_exclude"] == ["*.min.js"]
    assert sum(1 for rule in index["rules"] if "scope_exclude" in rule) == sum(
        len(item["rules"]) for item in curation["scope"]
    )
    bundle = (PACKS / "gitlab" / "lgpl" / "rules.yaml").read_text(encoding="utf-8")
    assert "# Scope: kalkan added paths.exclude to 1 rule(s)" in bundle
    position = bundle.index('- id: "rules_lgpl_javascript_dos_rule-regex-dos"')
    assert bundle[position:].split("\n")[1:4] == [
        "    paths:",
        "      exclude:",
        '      - "*.min.js"',
    ]


def test_keep_only_drops_the_unmeasured_rules(curation, index):
    """A pack with ``keep_only`` (ADR-0007) keeps only the named rules; the others are dropped
    with the kind ``unmeasured`` and the reason of the curation."""
    packs = [pack for pack in curation["packs"] if pack.get("keep_only")]
    assert packs
    for pack in packs:
        only = pack["keep_only"]
        kept = {rule["id"] for rule in index["rules"] if rule["pack"] == pack["name"]}
        assert kept and kept <= set(only["rules"])
        groups = [
            group
            for group in index["dropped"]
            if group["pack"] == pack["name"] and group["kind"] == "unmeasured"
        ]
        assert [group["reason"] for group in groups] == [only["reason"]]
