# SPDX-License-Identifier: MIT
"""Unit tests for the cost, time and token usage of a run (kalkan.run.usage)."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from kalkan.audit.summary import usage_text
from kalkan.findings.merge import merge_run
from kalkan.report.commands import refresh_report, write_report
from kalkan.report.model import build_model
from kalkan.report.render_exec import render_executive
from kalkan.run import usage

GOLDEN = Path(__file__).resolve().parents[1] / "golden" / "report"
RUN_ID = "20261015T120000Z-shop-a1b2"


def result_line(cost: float, **extra) -> str:
    event = {
        "type": "result",
        "subtype": "success",
        "is_error": False,
        "duration_ms": 600000,
        "duration_api_ms": 420000,
        "num_turns": 31,
        "result": "SECRET-LOOKING final message that quotes the target code",
        "total_cost_usd": cost,
        "usage": {
            "input_tokens": 1200,
            "output_tokens": 3400,
            "cache_read_input_tokens": 90000,
            "cache_creation_input_tokens": 5000,
        },
        "modelUsage": {"claude-opus-5-5": {"costUSD": cost, "inputTokens": 1200}},
    }
    event.update(extra)
    return json.dumps(event)


def test_parse_result_keeps_numbers_and_drops_the_final_message():
    record = usage.parse_result(result_line(12.5))
    assert record["total_cost_usd"] == 12.5 and record["num_turns"] == 31
    assert record["tokens"]["cache_read_input_tokens"] == 90000
    assert record["models"]["claude-opus-5-5"]["cost_usd"] == 12.5
    assert "SECRET-LOOKING" not in json.dumps(record)


def test_other_lines_are_not_results():
    assert usage.parse_result('{"type": "assistant", "message": {}}') is None
    assert usage.parse_result("plain text with result in it") is None
    assert usage.parse_result('{"type": "result", "total_cost_usd": -3}') == {"subtype": ""}


def test_append_load_and_summarize(tmp_path):
    usage.append(
        tmp_path, {"round": 1, "wall_seconds": 1800, **usage.parse_result(result_line(10.0))}
    )
    usage.append(tmp_path, {"round": 2, "wall_seconds": 600, "result_event": False})
    (tmp_path / usage.USAGE_NAME).open("a", encoding="utf-8").write("not json\n")
    totals = usage.summarize(usage.load(tmp_path))
    assert totals["rounds"] == 2 and totals["rounds_with_cost"] == 1
    assert totals["cost_usd"] == 10.0 and totals["active_seconds"] == 2400
    assert totals["tokens"]["output_tokens"] == 3400
    assert usage.summarize([]) is None


def test_the_report_shows_the_run_type_time_and_cost(tmp_path):
    run = tmp_path / RUN_ID
    shutil.copytree(GOLDEN / "run" / RUN_ID, run)
    merge_run(run)
    usage.append(run, {"round": 1, "wall_seconds": 3000, **usage.parse_result(result_line(92.8))})
    model = build_model(run, installed_tools=GOLDEN / "installed.json")
    assert model.usage["cost_usd"] == 92.8
    assert model.run_type().startswith("standard")
    page = render_executive(model, "tr")
    assert "Maliyet: 92,80 USD (API eşdeğeri)." in page
    assert "aktif süre 50 dk (1 tur)" in page
    assert "cost USD 92.80" in usage_text(model.usage)


def test_the_report_is_written_again_with_the_last_round(tmp_path):
    run = tmp_path / RUN_ID
    shutil.copytree(GOLDEN / "run" / RUN_ID, run)
    merge_run(run)
    usage.append(run, {"round": 1, "wall_seconds": 3000, **usage.parse_result(result_line(90.0))})
    model = build_model(run, installed_tools=GOLDEN / "installed.json")
    write_report(run, model, lang=model.run_lang, formats=("md", "html", "exec", "json"))
    # The report step ran inside round 2: its cost arrives after the report exists.
    usage.append(run, {"round": 2, "wall_seconds": 600, **usage.parse_result(result_line(10.0))})
    names = {path.name for path in refresh_report(run)}
    assert {"summary.json", "findings.json", "findings.sarif"} <= names
    summary = json.loads((run / "report" / "summary.json").read_text(encoding="utf-8"))
    assert summary["run"]["usage"]["cost_usd"] == 100.0
    assert summary["run"]["usage"]["rounds"] == 2


def test_init_facts_and_cost_basis_are_kept_without_secrets():
    init = json.dumps(
        {
            "type": "system",
            "subtype": "init",
            "apiKeySource": "none",
            "model": "claude-opus-5-5",
            "claude_code_version": "2.1.301",
            "cwd": "C:/secret/path",
        }
    )
    assert usage.parse_init(init) == {
        "api_key_source": "none",
        "model": "claude-opus-5-5",
        "claude_code_version": "2.1.301",
    }
    assert usage.parse_init('{"type": "system", "subtype": "api_retry"}') is None
    line = result_line(3.0, modelUsage={"m": {"costUSD": 3.0, "costBasis": "list"}})
    assert usage.parse_result(line)["cost_basis"] == {"m": "list"}
    totals = usage.summarize([{"auth": "foundry"}, {"auth": "foundry"}, {}])
    assert totals["auth"] == ["foundry"]


def test_an_api_run_says_that_the_account_paid(tmp_path):
    run = tmp_path / RUN_ID
    shutil.copytree(GOLDEN / "run" / RUN_ID, run)
    merge_run(run)
    entry = {
        "round": 1,
        "wall_seconds": 600,
        "auth": "foundry",
        **usage.parse_result(result_line(7.5)),
    }
    usage.append(run, entry)
    model = build_model(run, installed_tools=GOLDEN / "installed.json")
    assert "api foundry" in model.run_type()
    page = render_executive(model, "tr")
    assert "Maliyet: 7,50 USD, API hesabından ödendi (foundry)" in page
    assert "billed to foundry, estimate" in usage_text(model.usage)
