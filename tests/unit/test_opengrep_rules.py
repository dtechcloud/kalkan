# SPDX-License-Identifier: MIT
"""Checks for kalkan's own Opengrep rule pack (rules/opengrep).

The static tests read the rule files as text. The tests marked ``tools`` run the pinned Opengrep
on tests/fixtures/vulnapp and compare the results with EXPECTED.json:

- every vulnerable item that expects ``opengrep`` is reported by a rule of the same class,
- no rule fires on a secure twin,
- every result belongs to a planted vulnerable item, and every rule fires at least once.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from kalkan.findings import taxonomy
from kalkan.tools import toolhome

ROOT = Path(__file__).resolve().parents[2]
RULES_DIR = ROOT / "rules" / "opengrep"
FIXTURE = ROOT / "tests" / "fixtures" / "vulnapp"
EXPECTED = FIXTURE / "EXPECTED.json"

PINNED_VERSION = "1.30.1"
SCAN_TIMEOUT_SECONDS = 900
VERSION_TIMEOUT_SECONDS = 120
# A result counts for an item when it starts within WINDOW lines of the item line or covers it.
WINDOW = 2

LANGUAGES = ("python", "javascript", "go", "java", "php", "ruby", "csharp")
RULE_ID_RE = re.compile(
    r"^kalkan\.(python|javascript|go|java|php|ruby|csharp|generic)\.([a-z0-9-]+)\.([a-z0-9-]+)$"
)
LEVELS = {"HIGH", "MEDIUM", "LOW"}
REQUIRED_METADATA = (
    "cwe",
    "kalkan_class",
    "confidence",
    "likelihood",
    "impact",
    "owasp",
    "references",
)
# The classes that the task brief asks the pack to cover.
REQUIRED_CLASSES = {
    "sqli",
    "os-command-injection",
    "code-injection",
    "ssti",
    "xss",
    "ssrf",
    "path-traversal",
    "deserialization",
    "xxe",
    "open-redirect",
    "nosqli",
    "prototype-pollution",
    "jwt",
    "crypto",
    "cors",
}
# Classes that apply to most stacks; prototype pollution is JavaScript only, Go has no common
# deserialization, XXE, eval or NoSQL pattern in the standard library.
REQUIRED_PER_LANGUAGE = {
    "python": REQUIRED_CLASSES - {"prototype-pollution"},
    "javascript": REQUIRED_CLASSES,
    "go": {
        "sqli",
        "os-command-injection",
        "ssti",
        "xss",
        "ssrf",
        "path-traversal",
        "open-redirect",
        "jwt",
        "crypto",
        "cors",
    },
    "java": REQUIRED_CLASSES - {"prototype-pollution"},
    "php": REQUIRED_CLASSES - {"prototype-pollution"},
    "ruby": REQUIRED_CLASSES - {"prototype-pollution"},
    "csharp": REQUIRED_CLASSES - {"prototype-pollution"},
}


def rule_blocks() -> list[tuple[str, str, str]]:
    """Return (file name, rule id, rule text) for every rule of the pack."""
    blocks = []
    for path in sorted(RULES_DIR.glob("*.yaml")):
        text = path.read_text(encoding="utf-8")
        for part in re.split(r"(?m)^  - id: ", text)[1:]:
            rule_id, _, body = part.partition("\n")
            blocks.append((path.name, rule_id.strip(), body))
    return blocks


def rule_ids() -> set[str]:
    return {rule_id for _, rule_id, _ in rule_blocks()}


def class_of(rule_id: str) -> str:
    return rule_id.split(".")[2]


def load_items() -> list[dict]:
    return json.loads(EXPECTED.read_text(encoding="utf-8"))


def touches(result: dict, item: dict) -> bool:
    if result["file"] != item["file"]:
        return False
    start, end = result["start"], result["end"]
    return abs(start - item["line"]) <= WINDOW or start <= item["line"] <= end


# ---------------------------------------------------------------------------------------------
# Static checks (no tool needed)
# ---------------------------------------------------------------------------------------------


def test_rule_files_carry_the_license_header() -> None:
    files = sorted(RULES_DIR.glob("*.yaml"))
    assert files, "rules/opengrep holds no rule file"
    for path in files:
        first = path.read_text(encoding="utf-8").split("\n", 1)[0]
        assert first == "# SPDX-License-Identifier: MIT", path.name


def test_rule_ids_follow_the_naming_scheme() -> None:
    ids = [rule_id for _, rule_id, _ in rule_blocks()]
    duplicates = sorted({rule_id for rule_id in ids if ids.count(rule_id) > 1})
    assert not duplicates, f"duplicate rule ids: {duplicates}"
    errors = []
    for file_name, rule_id, _ in rule_blocks():
        match = RULE_ID_RE.match(rule_id)
        if match is None:
            errors.append(f"{file_name}: bad rule id {rule_id}")
            continue
        language, vuln_class, _ = match.groups()
        if vuln_class not in taxonomy.SLUGS:
            errors.append(f"{rule_id}: unknown class {vuln_class}")
        if file_name != f"{language}.yaml":
            errors.append(f"{rule_id}: belongs in {language}.yaml, found in {file_name}")
    assert not errors, "\n".join(errors)


def test_every_rule_has_the_required_fields() -> None:
    errors = []
    for _, rule_id, body in rule_blocks():
        for field in ("message", "severity", "languages", "metadata"):
            if not re.search(rf"(?m)^    {field}:", body):
                errors.append(f"{rule_id}: missing {field}")
        severity = re.search(r"(?m)^    severity: (\S+)", body)
        if severity and severity.group(1) not in {"ERROR", "WARNING", "INFO"}:
            errors.append(f"{rule_id}: bad severity {severity.group(1)}")
        for key in REQUIRED_METADATA:
            if not re.search(rf"(?m)^      {key}:", body):
                errors.append(f"{rule_id}: metadata misses {key}")
        for key in ("confidence", "likelihood", "impact"):
            value = re.search(rf"(?m)^      {key}: (\S+)", body)
            if value and value.group(1) not in LEVELS:
                errors.append(f"{rule_id}: {key} must be HIGH, MEDIUM or LOW")
        declared = re.search(r"(?m)^      kalkan_class: (\S+)", body)
        if declared and declared.group(1) != class_of(rule_id):
            errors.append(f"{rule_id}: kalkan_class {declared.group(1)} differs from the id")
        cwe_tags = re.findall(r'(?m)^        - "(CWE-[0-9]+: [^"]+)"', body)
        if not cwe_tags:
            errors.append(f"{rule_id}: needs CWE entries in the form 'CWE-89: <title>'")
        else:
            # Opengrep sorts the SARIF tags, and kalkan.sarif.ingest takes the class of the
            # first CWE tag. So the alphabetically first entry must map to the rule class.
            first = sorted(cwe_tags)[0].split(":", 1)[0]
            if taxonomy.class_for_cwe(first) != class_of(rule_id):
                errors.append(f"{rule_id}: CWE tag {first} sorts first and does not map to class")
        if not re.search(r'(?m)^        - "A[0-9]{2}:2021 - ', body):
            errors.append(f"{rule_id}: needs an OWASP Top 10 2021 entry")
        if not re.search(r"(?m)^        - https://", body):
            errors.append(f"{rule_id}: needs at least one reference URL")
    assert not errors, "\n".join(errors)


def test_rule_pack_covers_the_required_languages_and_classes() -> None:
    covered: dict[str, set[str]] = {language: set() for language in LANGUAGES}
    for _, rule_id, _ in rule_blocks():
        language = rule_id.split(".")[1]
        if language in covered:
            covered[language].add(class_of(rule_id))
    missing = {
        language: sorted(required - covered[language])
        for language, required in REQUIRED_PER_LANGUAGE.items()
        if required - covered[language]
    }
    assert not missing, f"classes without a rule: {missing}"


# ---------------------------------------------------------------------------------------------
# Scan of the fixture (needs Opengrep)
# ---------------------------------------------------------------------------------------------


def find_opengrep() -> list[str] | None:
    """Return the command prefix of the pinned Opengrep, or None."""
    try:
        from kalkan.tools.resolve import resolve
    except ImportError:
        resolve = None
    if resolve is not None:
        try:
            tool = resolve("opengrep")
        except Exception:  # noqa: BLE001 - an unusable manifest means "not installed" here
            tool = None
        if tool is not None:
            return tool.argv
    path = shutil.which("opengrep")
    if path is None:
        return None
    probe = subprocess.run(
        [path, "--version"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=VERSION_TIMEOUT_SECONDS,
        shell=False,
    )
    return [path] if PINNED_VERSION in probe.stdout else None


@pytest.fixture(scope="module")
def scan(tmp_path_factory: pytest.TempPathFactory) -> dict:
    """Run the rule pack on the fixture once and return the SARIF document and the results."""
    command = find_opengrep()
    if command is None:
        pytest.skip(f"Opengrep {PINNED_VERSION} is not installed")
    sarif_path = tmp_path_factory.mktemp("opengrep") / "vulnapp.sarif"
    work = tmp_path_factory.mktemp("opengrep-work")
    (work / "tmp").mkdir()
    # The folders of kalkan's opengrep adapter (kalkan.tools.toolhome): the runtime below
    # .tools/cache, the log and the temporary rule files in a test folder, never in the user
    # profile or the user temp folder.
    env = {
        **os.environ,
        **toolhome.opengrep_env(toolhome.prepare_home(toolhome.opengrep_home(ROOT)), work),
        **toolhome.temp_env(work / "tmp"),
    }
    # --x-ignore-semgrepignore-files: the default ignore list skips every "tests/" folder.
    # --no-git-ignore: kalkan scans run copies that live in git-ignored folders.
    # --no-rewrite-rule-ids: keep "kalkan.<language>.<class>.<name>" without a path prefix.
    proc = subprocess.run(
        [
            *command,
            "scan",
            "--config",
            str(RULES_DIR),
            f"--sarif-output={sarif_path}",
            "--no-rewrite-rule-ids",
            "--no-git-ignore",
            "--x-ignore-semgrepignore-files",
            "--quiet",
            ".",
        ],
        cwd=FIXTURE,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=SCAN_TIMEOUT_SECONDS,
        shell=False,
    )
    assert sarif_path.is_file(), f"no SARIF output (exit {proc.returncode}): {proc.stderr[-2000:]}"
    doc = json.loads(sarif_path.read_text(encoding="utf-8"))
    results = []
    for run in doc["runs"]:
        for res in run.get("results", []):
            location = res["locations"][0]["physicalLocation"]
            uri = location["artifactLocation"]["uri"].replace("\\", "/")
            while uri.startswith("./"):
                uri = uri[2:]
            region = location["region"]
            results.append(
                {
                    "rule": res["ruleId"],
                    "file": uri,
                    "start": region["startLine"],
                    "end": region.get("endLine", region["startLine"]),
                }
            )
    return {"returncode": proc.returncode, "doc": doc, "results": results, "path": sarif_path}


@pytest.mark.tools
def test_scan_loads_every_rule(scan: dict) -> None:
    assert scan["returncode"] == 0
    run = scan["doc"]["runs"][0]
    invocation = run["invocations"][0]
    assert invocation["executionSuccessful"] is True
    errors = [
        note
        for note in invocation.get("toolExecutionNotifications", [])
        if note.get("level") == "error"
    ]
    assert errors == []
    loaded = {rule["id"] for rule in run["tool"]["driver"]["rules"]}
    assert loaded == rule_ids()


@pytest.mark.tools
def test_every_rule_is_exercised_by_the_fixture(scan: dict) -> None:
    fired = {result["rule"] for result in scan["results"]}
    assert sorted(rule_ids() - fired) == []


@pytest.mark.tools
def test_every_planted_item_is_detected(scan: dict) -> None:
    misses = []
    for item in load_items():
        if item["kind"] != "vulnerable" or "opengrep" not in item["expected_engines"]:
            continue
        hits = [
            result
            for result in scan["results"]
            if touches(result, item) and class_of(result["rule"]) == item["class"]
        ]
        if not hits:
            misses.append(f"{item['id']}: {item['file']}:{item['line']} ({item['class']})")
    assert misses == [], "not detected:\n" + "\n".join(misses)


@pytest.mark.tools
def test_no_rule_fires_on_a_secure_twin(scan: dict) -> None:
    false_positives = []
    for item in load_items():
        if item["kind"] != "secure-twin":
            continue
        for result in scan["results"]:
            if touches(result, item):
                false_positives.append(f"{item['id']}: {result['rule']} at line {result['start']}")
    assert false_positives == [], "rules fire on secure twins:\n" + "\n".join(false_positives)


@pytest.mark.tools
def test_every_result_belongs_to_a_planted_item(scan: dict) -> None:
    vulnerable = [item for item in load_items() if item["kind"] == "vulnerable"]
    stray = [
        f"{result['file']}:{result['start']} {result['rule']}"
        for result in scan["results"]
        if not any(touches(result, item) for item in vulnerable)
    ]
    assert stray == [], "results outside the planted items:\n" + "\n".join(stray)


@pytest.mark.tools
def test_sarif_ingest_gives_each_result_the_class_of_its_rule(scan: dict) -> None:
    ingest = pytest.importorskip("kalkan.sarif.ingest")
    outcome = ingest.ingest_document(scan["doc"], "opengrep", FIXTURE, scan["path"])
    assert len(outcome.candidates) == len(scan["results"])
    wrong = [
        f"{cand['rule_id']}: class {cand['class']}"
        for cand in outcome.candidates
        if cand["class"] != class_of(cand["rule_id"])
    ]
    assert wrong == []
