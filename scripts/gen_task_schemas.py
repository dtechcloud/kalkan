# SPDX-License-Identifier: MIT
"""Generate the agent task result schemas (docs/ENGINE-SPEC.md section 18).

Usage: python scripts/gen_task_schemas.py [output-dir]

The default output folder is src/kalkan/schemas. Run the script again after a change to the
taxonomy or to a result shape; tests/unit/test_task_schemas.py checks that the files agree with
the taxonomy and with the sample results in tests/fixtures/task-results.
"""

import json
import sys
from pathlib import Path

from kalkan.findings.review import CHECKLISTS, DECISIONS
from kalkan.findings.taxonomy import SLUGS
from kalkan.schema.validator import check_schema, compile_pattern

REPO = Path(__file__).resolve().parents[1]
OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else REPO / "src" / "kalkan" / "schemas"

TEXT = {"type": "string", "minLength": 1, "visibleContent": True}
ANY_TEXT = {"type": "string"}
NAME = {"type": "string", "minLength": 1}
PATH = {"type": "string", "minLength": 1, "description": "Target-relative POSIX path."}
LINE = {"type": "integer", "minimum": 1}
NULLABLE_LINE = {"oneOf": [LINE, {"type": "null"}]}
CLASS = {"type": "string", "enum": list(SLUGS)}
CWES = {
    "type": "array",
    "uniqueItems": True,
    "items": {"type": "string", "pattern": "^CWE-[0-9]+$"},
}
LEVEL = {"type": "string", "enum": ["informational", "low", "medium", "high", "critical"]}
TEXT_LIST = {"type": "array", "items": TEXT}


def obj(required, properties, comment=None):
    node = {"type": "object", "additionalProperties": False}
    if comment:
        node["$comment"] = comment
    node["required"] = list(required)
    node["properties"] = properties
    return node


def array(items, min_items=0, unique=False):
    node = {"type": "array"}
    if min_items:
        node["minItems"] = min_items
    if unique:
        node["uniqueItems"] = True
    node["items"] = items
    return node


def task_id(kind):
    return {"type": "string", "pattern": "^T[0-9]{4,}-" + kind + "$"}


QUOTE = obj(
    ["file", "line", "quote"],
    {
        "file": PATH,
        "line": LINE,
        "quote": {
            "type": "string",
            "minLength": 1,
            "description": "Exact text from the cited line or the two lines around it.",
        },
    },
)
TRACE = obj(
    ["kind", "file", "line", "scope", "description"],
    {
        "kind": {"type": "string", "enum": ["entrypoint", "propagation", "sink"]},
        "file": PATH,
        "line": LINE,
        "scope": TEXT,
        "description": TEXT,
    },
)
FINDING_EVIDENCE = obj(
    ["file", "line", "description"], {"file": PATH, "line": LINE, "description": TEXT}
)
ANSWER = obj(
    ["status", "reason", "evidence"],
    {
        "status": {"type": "string", "enum": ["established", "refuted", "unknown"]},
        "reason": TEXT,
        "evidence": array(QUOTE),
    },
)
GAP = obj(
    ["surface_id", "class", "reason", "starting_paths"],
    {
        "surface_id": {
            "type": "string",
            "minLength": 1,
            "description": "A recon surface ID, or a short name for a surface that recon missed.",
        },
        "class": CLASS,
        "reason": TEXT,
        "starting_paths": array(PATH, 1, unique=True),
    },
)
SURFACE_KINDS = ["http", "rpc", "queue", "cron", "cli", "webhook", "agent-tool", "file", "other"]
CONDITION_KINDS = [
    "authentication_level",
    "authorization_role",
    "user_interaction",
    "system_configuration",
    "network_routing",
    "environmental_dependency",
    "data_state",
    "timing_dependency",
    "third_party_dependency",
]
BASE_IMAGES = [
    "python:3.12-slim",
    "node:22-slim",
    "golang:1.26",
    "eclipse-temurin:21-jdk",
    "php:8.3-cli",
    "ruby:3.3-slim",
    "mcr.microsoft.com/dotnet/sdk:10.0",
]
SEVERITY = obj(
    ["likelihood", "impact", "overall_severity"],
    {
        "likelihood": obj(["score", "reason"], {"score": LEVEL, "reason": TEXT}),
        "impact": obj(["score", "reason"], {"score": LEVEL, "reason": TEXT}),
        "overall_severity": LEVEL,
    },
)
REMEDIATION = obj(
    ["strategy"],
    {
        "strategy": TEXT,
        "code_changes": array(
            obj(
                ["file_name", "fixed_code"],
                {"file_name": PATH, "fixed_code": {"type": "string"}},
            )
        ),
    },
)
FINDING_ID = {"type": "string", "pattern": "^KF-[0-9A-F]{16}$"}
CHECK_ITEMS = list(dict.fromkeys(item for items in CHECKLISTS.values() for item in items))
POC_PATH = "^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}(/[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}){0,3}$"
METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]

schemas = {}

schemas["recon"] = obj(
    [
        "task_id",
        "kind",
        "summary_md",
        "facts",
        "surfaces",
        "classes_of_interest",
        "sensitive_data",
        "uncertainties",
    ],
    {
        "task_id": task_id("recon"),
        "kind": {"type": "string", "enum": ["product", "principals", "surfaces", "execution"]},
        "summary_md": TEXT,
        "facts": array(
            obj(["statement", "evidence"], {"statement": TEXT, "evidence": array(QUOTE, 1)})
        ),
        "surfaces": array(
            obj(
                [
                    "id",
                    "kind",
                    "name",
                    "file",
                    "line",
                    "auth",
                    "trust_boundary",
                    "subsystem",
                    "notes",
                ],
                {
                    "id": {"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"},
                    "kind": {"type": "string", "enum": SURFACE_KINDS},
                    "name": TEXT,
                    "file": PATH,
                    "line": NULLABLE_LINE,
                    "auth": {
                        "type": "string",
                        "enum": ["none", "user", "privileged", "service", "unknown"],
                    },
                    "trust_boundary": TEXT,
                    "subsystem": TEXT,
                    "notes": ANY_TEXT,
                },
            )
        ),
        "classes_of_interest": array(CLASS, unique=True),
        "sensitive_data": TEXT_LIST,
        "uncertainties": TEXT_LIST,
    },
    "kalkan recon task result (docs/ENGINE-SPEC.md section 18).",
)

schemas["hunt"] = obj(
    ["task_id", "units", "candidates", "hardening", "uncovered"],
    {
        "task_id": task_id("hunt"),
        "units": array(
            obj(
                ["coverage_id", "status", "checks", "notes", "unresolved"],
                {
                    "coverage_id": NAME,
                    "status": {"type": "string", "enum": ["covered", "candidate", "blocked"]},
                    "checks": array(
                        obj(
                            ["reviewed_paths", "invariant", "result"],
                            {
                                "reviewed_paths": array(PATH, 1, unique=True),
                                "invariant": TEXT,
                                "result": TEXT,
                            },
                        ),
                        1,
                    ),
                    "notes": ANY_TEXT,
                    "unresolved": TEXT_LIST,
                },
            ),
            1,
        ),
        "candidates": array(
            obj(
                [
                    "coverage_id",
                    "title",
                    "class",
                    "cwe",
                    "description",
                    "claimed_root_cause",
                    "trace",
                    "evidence",
                    "suggested_severity",
                    "dynamic_test",
                    "related_candidates",
                ],
                {
                    "coverage_id": NAME,
                    "title": TEXT,
                    "class": CLASS,
                    "cwe": CWES,
                    "description": TEXT,
                    "claimed_root_cause": TEXT,
                    "trace": array(TRACE, 1),
                    "evidence": array(QUOTE, 1),
                    "suggested_severity": obj(
                        ["likelihood", "impact"], {"likelihood": LEVEL, "impact": LEVEL}
                    ),
                    "dynamic_test": ANY_TEXT,
                    "related_candidates": array(NAME, unique=True),
                },
            )
        ),
        "hardening": array(
            obj(
                ["title", "file", "line", "note"],
                {"title": TEXT, "file": PATH, "line": NULLABLE_LINE, "note": TEXT},
            )
        ),
        "uncovered": array(GAP),
    },
    "kalkan hunt task result (docs/ENGINE-SPEC.md section 18).",
)

schemas["critic"] = obj(
    ["task_id", "missing_units", "reassign_ids", "stop", "notes"],
    {
        "task_id": task_id("critic"),
        "missing_units": array(GAP),
        "reassign_ids": array(
            obj(["coverage_id", "reason"], {"coverage_id": NAME, "reason": TEXT})
        ),
        "covered_ids": array(
            obj(
                ["coverage_id", "covered_by", "reason", "evidence"],
                {
                    "coverage_id": NAME,
                    "covered_by": array(NAME, 1, unique=True),
                    "reason": TEXT,
                    "evidence": array(QUOTE, 1),
                },
                "A blocked unit whose unresolved facts the covered_by units already settled. "
                "The evidence quotes the deciding code from files in their reviewed_paths.",
            )
        ),
        "stop": {"type": "boolean"},
        "notes": ANY_TEXT,
    },
    "kalkan critic task result (docs/ENGINE-SPEC.md section 18). covered_ids is optional. The "
    "engine checks every closure and its quotes.",
)

schemas["verify"] = obj(
    ["task_id", "subject", "audit_answers", "finding", "duplicate_of"],
    {
        "task_id": task_id("verify"),
        "subject": obj(
            ["kind", "ref"],
            {"kind": {"type": "string", "enum": ["hunter", "deterministic"]}, "ref": NAME},
        ),
        "audit_answers": obj(
            ["attacker_control", "privilege_boundary", "unmitigated"],
            {"attacker_control": ANSWER, "privilege_boundary": ANSWER, "unmitigated": ANSWER},
        ),
        "finding": obj(
            [
                "title",
                "description",
                "class",
                "cwe",
                "root_cause",
                "trace",
                "evidence",
                "validation_plan",
                "reason",
            ],
            {
                "title": TEXT,
                "description": TEXT,
                "class": CLASS,
                "cwe": CWES,
                "root_cause": TEXT,
                "intended_behavior": TEXT,
                "trace": array(TRACE, 1),
                "evidence": array(FINDING_EVIDENCE, 1),
                "conditions": array(
                    obj(
                        ["kind", "description"],
                        {"kind": {"type": "string", "enum": CONDITION_KINDS}, "description": TEXT},
                    )
                ),
                "execution": obj(
                    ["attacker_perspective", "payloads", "instructions", "observed_result"],
                    {
                        "attacker_perspective": TEXT,
                        "payloads": array({"type": "string"}, 1),
                        "instructions": array(TEXT, 1),
                        "observed_result": TEXT,
                    },
                ),
                "remediation": REMEDIATION,
                "severity": SEVERITY,
                "confidence": obj(
                    ["score", "reason"],
                    {
                        "score": {"type": "string", "enum": ["low", "medium", "high"]},
                        "reason": TEXT,
                    },
                ),
                "blockers": TEXT_LIST,
                "validation_plan": obj([], {"local": TEXT, "deployment": TEXT}),
                "reason": TEXT,
            },
        ),
        "duplicate_of": {"oneOf": [NAME, {"type": "null"}]},
    },
    "kalkan verify task result (docs/ENGINE-SPEC.md section 18). The engine computes the verdict.",
)

schemas["review"] = obj(
    ["task_id", "finding_id", "decision", "reason", "checks", "evidence"],
    {
        "task_id": task_id("review"),
        "finding_id": FINDING_ID,
        "decision": {"type": "string", "enum": list(DECISIONS)},
        "reason": TEXT,
        "checks": array(
            obj(
                ["item", "ok", "note"],
                {
                    "item": {"type": "string", "enum": CHECK_ITEMS},
                    "ok": {"type": "boolean"},
                    "note": TEXT,
                },
            ),
            1,
        ),
        "evidence": array(QUOTE),
        "severity": SEVERITY,
        "remediation": REMEDIATION,
    },
    "kalkan review task result (docs/ENGINE-SPEC.md section 18). The engine applies the decision.",
)

schemas["consolidate"] = obj(
    ["task_id", "groups", "distinct"],
    {
        "task_id": task_id("consolidate"),
        "groups": array(
            obj(
                ["ids", "reason", "evidence"],
                {
                    "ids": array(FINDING_ID, 2, unique=True),
                    "reason": TEXT,
                    "evidence": array(QUOTE, 1),
                },
                "Records with the same root cause and the same fix. The evidence quotes the code "
                "that proves the shared root cause.",
            )
        ),
        "distinct": array(obj(["id", "reason"], {"id": FINDING_ID, "reason": TEXT})),
    },
    "kalkan consolidate task result (docs/ENGINE-SPEC.md section 18). Every input id appears "
    "exactly once across groups[].ids and distinct[].id. The engine checks the quotes and picks "
    "the primary record of each group.",
)

POLISH_PATH = "^/[a-z_]+(/([a-z_]+|[0-9]+))*$"
schemas["polish"] = obj(
    ["task_id", "records"],
    {
        "task_id": task_id("polish"),
        "records": array(
            obj(
                ["id", "fields"],
                {
                    "id": FINDING_ID,
                    "fields": array(
                        obj(
                            ["path", "text"],
                            {
                                "path": {
                                    "type": "string",
                                    "pattern": POLISH_PATH,
                                    "description": "The path of an input field, unchanged.",
                                },
                                "text": TEXT,
                            },
                            "The whole field text with the Turkish letters restored. Every other "
                            "character stays as it was.",
                        )
                    ),
                },
            )
        ),
        "notes": ANY_TEXT,
    },
    "kalkan polish task result (docs/ENGINE-SPEC.md section 18). Only fields with a restored "
    "letter appear. The engine accepts a field only when it differs from the input text in the "
    "Turkish letters alone and keeps every code token.",
)

schemas["sca_reach"] = obj(
    ["task_id", "vuln_ref", "reachability", "reason", "evidence", "searched"],
    {
        "task_id": task_id("sca_reach"),
        "vuln_ref": NAME,
        "reachability": {"type": "string", "enum": ["reachable", "not_reachable", "unknown"]},
        "reason": TEXT,
        "evidence": array(QUOTE),
        "searched": TEXT_LIST,
    },
    "kalkan sca_reach task result (docs/ENGINE-SPEC.md section 18).",
)

POC_FEASIBLE = obj(
    [
        "task_id",
        "finding_id",
        "feasible",
        "level",
        "base_image",
        "files",
        "command",
        "success_regex",
        "expected_observation",
        "app",
    ],
    {
        "task_id": task_id("poc_build"),
        "finding_id": FINDING_ID,
        "feasible": {"type": "boolean", "const": True},
        "level": {"type": "string", "enum": ["unit", "app"]},
        "base_image": {"type": "string", "enum": BASE_IMAGES},
        "files": array(
            obj(
                ["path", "content"],
                {
                    "path": {
                        "type": "string",
                        "pattern": POC_PATH,
                        "description": "Path inside the PoC folder.",
                    },
                    "content": {"type": "string"},
                },
            ),
            1,
        ),
        "command": array(NAME, 1),
        "success_regex": NAME,
        "expected_observation": TEXT,
        "app": {
            "oneOf": [
                {"type": "null"},
                obj(
                    ["compose_file", "service", "port", "requests"],
                    {
                        "compose_file": PATH,
                        "service": NAME,
                        "port": {"type": "integer", "minimum": 1},
                        "requests": array(
                            obj(
                                ["method", "path", "headers", "body"],
                                {
                                    "method": {"type": "string", "enum": METHODS},
                                    "path": {"type": "string", "pattern": "^/"},
                                    "headers": array(
                                        obj(
                                            ["name", "value"],
                                            {"name": NAME, "value": {"type": "string"}},
                                        )
                                    ),
                                    "body": {"type": "string"},
                                },
                            ),
                            1,
                        ),
                    },
                ),
            ]
        },
    },
)
POC_INFEASIBLE = obj(
    ["task_id", "finding_id", "feasible", "reason"],
    {
        "task_id": task_id("poc_build"),
        "finding_id": FINDING_ID,
        "feasible": {"type": "boolean", "const": False},
        "reason": TEXT,
    },
)
schemas["poc_build"] = {
    "$comment": "kalkan poc_build task result (docs/ENGINE-SPEC.md sections 18 and 23).",
    "oneOf": [POC_FEASIBLE, POC_INFEASIBLE],
}

schemas["translate"] = obj(
    ["task_id", "translations"],
    {
        "task_id": task_id("translate"),
        "translations": array(
            obj(
                ["id", "title", "description", "remediation_strategy"],
                {
                    "id": {"type": "string", "pattern": "^KF-[0-9A-F]{16}$"},
                    "title": TEXT,
                    "description": TEXT,
                    "remediation_strategy": TEXT,
                },
            ),
            1,
        ),
    },
    "kalkan translate task result (docs/ENGINE-SPEC.md section 18).",
)

OUT.mkdir(parents=True, exist_ok=True)
for kind, schema in schemas.items():
    errors = check_schema(schema)
    if errors:
        raise SystemExit(f"{kind}: {errors}")
    path = OUT / f"task-{kind}.schema.json"
    text = json.dumps(schema, ensure_ascii=False, indent=2) + "\n"
    path.write_text(text, encoding="utf-8", newline="\n")
    print(path.name, path.stat().st_size)

for pattern in ["^T[0-9]{4,}-hunt$", "^KF-[0-9A-F]{16}$", POC_PATH, POLISH_PATH]:
    compile_pattern(pattern)
print("patterns ok")
