# SPDX-License-Identifier: MIT
"""Tests for prompt rendering (kalkan.run.prompts) and task creation with prompts."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from kalkan.run import ids, prompts, queue, tasks
from kalkan.run import init as init_mod
from kalkan.run.init import init_run
from kalkan.schema.loader import load_schema

TARGETS = Path(__file__).resolve().parents[1] / "fixtures" / "targets"


@pytest.fixture
def ctx(tmp_path, monkeypatch):
    monkeypatch.setenv(ids.RUNS_DIR_ENV, str(tmp_path / "runs"))
    monkeypatch.setattr(init_mod, "git_head", lambda directory: None)
    target = tmp_path / "webapp"
    shutil.copytree(TARGETS / "webapp", target)
    (target / "big.py").write_text(
        "\n".join(f"line_{n} = {n}" for n in range(1, 1001)) + "\n", encoding="utf-8"
    )
    return init_run(str(target), runs_dir=tmp_path / "runs")


@pytest.mark.parametrize(
    "task_type",
    [
        "recon",
        "hunt",
        "critic",
        "verify",
        "consolidate",
        "polish",
        "sca_reach",
        "poc_build",
        "translate",
    ],
)
def test_every_template_renders_without_placeholders(ctx, task_type):
    text = prompts.render(ctx, task_type, f"T0001-{task_type}", {"units": [], "claim": {}})
    assert "{{" not in text
    assert f"DONE T0001-{task_type}" in text
    assert ctx.target_dir.absolute().as_posix() in text
    assert "Turkish" in text
    schema = json.dumps(load_schema(f"task-{task_type}"), separators=(",", ":"))
    assert schema in text


def test_placeholders_are_replaced_in_one_pass(ctx):
    data = {"kind": "product", "note": "{{TASK_ID}} {{RESULT_FILE}} {{UNKNOWN}}"}
    text = prompts.render(ctx, "recon", "T0007-recon", data)
    assert '"note": "{{TASK_ID}} {{RESULT_FILE}} {{UNKNOWN}}"' in text
    assert (ctx.task_dir("T0007-recon") / "result.json").absolute().as_posix() in text
    assert '"task_id":{"type":"string"' in text  # compact schema
    assert '"kind": "surfaces"' in text  # the example


def test_knowledge_per_task_type(ctx):
    hunt = prompts.knowledge_for(ctx, "hunt", {"units": [{"class": "sqli"}, {"class": "idor"}]})
    assert "#### Methodology" in hunt
    assert "#### Class: sqli" in hunt and "#### Class: idor" in hunt
    assert "#### Language: python" in hunt
    assert "#### Domain: data-isolation-and-lifecycle" in hunt
    assert "Core discipline" in hunt and "Attack classes" not in hunt
    assert len(hunt) <= prompts.KNOWLEDGE_MAX_CHARS + 200
    verify = prompts.knowledge_for(ctx, "verify", {"claim": {"class": "sqli"}})
    assert "#### Class: sqli" in verify and "Verification checklist" in verify
    assert "Where to look" not in verify
    assert "Methodology" in prompts.knowledge_for(ctx, "recon", {})
    assert "Glossary" in prompts.knowledge_for(ctx, "translate", {})
    sca = prompts.knowledge_for(ctx, "sca_reach", {})
    assert "vulnerable-dependency" in sca and "Methodology" not in sca
    poc = prompts.knowledge_for(ctx, "poc_build", {"finding": {"class": "sqli"}})
    assert "Dynamic test hints" in poc
    unknown = prompts.knowledge_for(ctx, "verify", {"claim": {"class": None}})
    assert "#### Class" not in unknown


def test_cut_at_section():
    text = "## A\n\n" + "a" * 50 + "\n\n## B\n\n" + "b" * 50
    assert prompts.cut_at_section(text, 1000) == text
    assert prompts.cut_at_section(text, 70).startswith("## A") and "## B" not in (
        prompts.cut_at_section(text, 70)
    )


def test_source_excerpts(ctx):
    claim = {
        "trace": [{"file": "app/routes.py", "line": 12}, {"file": "big.py", "line": 500}],
        "evidence": [
            {"file": "big.py", "line": 510},
            {"file": "missing.py", "line": 3},
            {"file": "../escape.py", "line": 1},
        ],
    }
    text = prompts.source_excerpts(ctx, "verify", {"claim": claim})
    assert "#### app/routes.py, lines 1-15" in text
    assert '12|     user_id = request.args.get("id")' in text
    assert "#### big.py, lines 481-530" in text  # two windows merged
    assert "481| line_481 = 481" in text and "530| line_530 = 530" in text
    assert "missing.py\n\n(The file is not available" in text
    assert "../escape.py\n\n(The file is not available" in text


def test_source_excerpts_limits(ctx):
    evidence = [{"file": "big.py", "line": line} for line in range(20, 1000, 50)]
    text = prompts.source_excerpts(ctx, "verify", {"claim": {"evidence": evidence}})
    rows = [row for row in text.splitlines() if row[:1].isdigit() and "| line_" in row]
    assert len(rows) == prompts.EXCERPT_LINES_TOTAL
    assert "Excerpts stop at 400 lines" in text
    reach = prompts.source_excerpts(
        ctx, "sca_reach", {"locations": [{"file": "requirements.txt", "line": None}]}
    )
    assert "1| flask==3.0.3" in reach
    assert "No source location" in prompts.source_excerpts(ctx, "verify", {"claim": {}})


def test_new_task_writes_the_prompt_and_ensure_prompt_repairs_it(ctx):
    task_id = tasks.new_task(ctx, "recon", "recon", {"kind": "product"}, dedupe_key="recon:x")
    prompt = ctx.task_dir(task_id) / "prompt.md"
    assert prompt.is_file() and f"# kalkan task {task_id}" in prompt.read_text("utf-8")
    assert tasks.new_task(ctx, "recon", "recon", {"kind": "other"}, dedupe_key="recon:x") == (
        task_id
    )
    prompt.unlink()
    assert tasks.ensure_prompt(ctx, task_id) == prompt
    assert '"kind": "product"' in prompt.read_text("utf-8")
    assert tasks.find_by_dedupe_key(ctx.reload(), "recon:x") == task_id
    assert queue.get_task(ctx, task_id)["dedupe_key"] == "recon:x"
