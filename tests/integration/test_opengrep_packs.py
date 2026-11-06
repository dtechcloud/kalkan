# SPDX-License-Identifier: MIT
"""The vendored Opengrep rule packs with the pinned Opengrep, in local mode, under the proxy trap
of ``conftest.py`` (ADR-0005 K.8; docs/SECURITY.md, promise 3).

One scan of the vulnapp fixture (without the answer files) through the ``opengrep-packs``
adapter checks:

- zero connections and status ``ok``;
- the pack loading: Opengrep 1.30.1 loads every kept rule of ``rules/opengrep-packs/index.json``
  except the run-time duplicates of kalkan's own pack, and reports no load error;
- the fixture expectations: every item that lists ``opengrep-packs`` in ``EXPECTED.json`` is
  found by one of its rules, no result touches a secure twin, and the results outside the
  planted items are the known ones (:data:`KNOWN_UNPLANTED`);
- the status file: the switch, the enabled packs and the duplicates.

Run with ``pytest -m tools tests/integration/test_opengrep_packs.py`` (about one minute on
Windows).
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from kalkan.run import tech
from kalkan.scanners import registry, rulepacks
from kalkan.scanners.base import load_scan_context, run_adapter
from kalkan.scanners.candidates import load_candidates
from kalkan.tools.resolve import resolve

pytestmark = pytest.mark.tools

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "vulnapp"
EXPECTED = FIXTURE / "EXPECTED.json"
ANSWER_FILES = frozenset({"README.md", "EXPECTED.json", "INJECTION-NOTE.md"})
WINDOW = 2
#: Results outside the planted items, checked by hand on 2026-10-25: MongoDB connection strings
#: without TLS (the localhost defaults of the environment variables).
KNOWN_UNPLANTED = {
    ("trailofbits.generic.mongodb-insecure-transport", "node/server.js", 29),
    ("trailofbits.generic.mongodb-insecure-transport", "python/shop/storage.py", 9),
    ("trailofbits.generic.mongodb-insecure-transport", "ruby/app.rb", 33),
}


def _ignore(folder: str, names: list[str]) -> set[str]:
    skipped = {name for name in names if name in {"obj", "bin"}}
    if Path(folder).resolve() == FIXTURE:
        skipped |= {name for name in names if name in ANSWER_FILES}
    return skipped


def _touches(candidate: dict, item: dict) -> bool:
    start = candidate["start_line"] or 0
    end = candidate["end_line"] or start
    if candidate["file"] != item["file"]:
        return False
    return abs(start - item["line"]) <= WINDOW or start <= item["line"] <= end


def test_rule_packs_on_vulnapp_offline(tmp_path, monkeypatch, trap_proxy):
    if resolve("opengrep") is None:
        pytest.skip("opengrep is not installed (run: kalkan tools install opengrep)")
    monkeypatch.delenv(rulepacks.ENV_VAR, raising=False)
    run = tmp_path / "run"
    shutil.copytree(FIXTURE, run / "target", ignore=_ignore)
    manifest = {"copy": "target", "source_dir": None, "tech": tech.detect(run / "target")}
    (run / "target-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    proxy = trap_proxy()
    for name, value in proxy.env().items():
        monkeypatch.setenv(name, value)

    adapter = registry.get("opengrep-packs")
    result = run_adapter(adapter, load_scan_context(run, offline=True))
    assert proxy.connections == [], proxy.connections
    assert result.status == "ok", result.message

    # Pack loading: every kept rule loads, the run-time duplicates are left out.
    index = rulepacks.load_index()
    status = json.loads((run / "scans" / "opengrep-packs.status.json").read_text("utf-8"))
    duplicates = set(adapter.plan().duplicates)
    assert status["kalkan_duplicates"]["count"] == len(duplicates)
    doc = json.loads((run / "scans" / "opengrep-packs.sarif").read_text(encoding="utf-8"))
    sarif_run = doc["runs"][0]
    loaded = {rule["id"] for rule in sarif_run["tool"]["driver"]["rules"]}
    assert loaded == {rule["id"] for rule in index["rules"]} - duplicates
    notes = sarif_run["invocations"][0].get("toolExecutionNotifications", [])
    assert [note for note in notes if note.get("level") == "error"] == []
    assert all(
        rule["properties"]["kalkan-class"] and rule["properties"]["kalkan-license"]
        for rule in sarif_run["tool"]["driver"]["rules"]
    )
    assert [pack["name"] for pack in status["rule_packs"]["enabled"]] == [
        pack["name"] for pack in index["packs"]
    ]
    assert status["rule_packs"]["setting"] == "all"

    # Fixture expectations.
    items = json.loads(EXPECTED.read_text(encoding="utf-8"))
    candidates = [c for c in load_candidates(run)["candidates"] if c["engine"] == "opengrep-packs"]
    expected = [item for item in items if "opengrep-packs" in item["expected_engines"]]
    assert expected, "EXPECTED.json lists no item for opengrep-packs"
    missing = [
        item["id"]
        for item in expected
        if not any(
            _touches(c, item) and c["rule_id"] in item["rules"]["opengrep-packs"]
            for c in candidates
        )
    ]
    assert missing == []
    twins = [
        (c["rule_id"], item["id"])
        for item in items
        if item["kind"] == "secure-twin"
        for c in candidates
        if _touches(c, item)
    ]
    assert twins == []
    unplanted = {
        (c["rule_id"], c["file"], c["start_line"])
        for c in candidates
        if not any(_touches(c, item) for item in items)
    }
    assert unplanted == KNOWN_UNPLANTED
    for candidate in candidates:
        if candidate["class"] == "hardcoded-secrets":
            assert candidate["snippet"] in {"", "REDACTED"}, candidate["rule_id"]
