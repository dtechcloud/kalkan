# SPDX-License-Identifier: MIT
"""Tests for the ``run`` and ``task`` CLI groups (kalkan.run.commands) through kalkan.cli.main."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from kalkan.cli import EXIT_USAGE, EXIT_VALIDATION, main
from kalkan.run import handlers, ids, queue, state
from kalkan.run import init as init_mod

TARGETS = Path(__file__).resolve().parents[1] / "fixtures" / "targets"
SAMPLES = Path(__file__).resolve().parents[1] / "fixtures" / "task-results"


@pytest.fixture
def runs(tmp_path, monkeypatch):
    root = tmp_path / "runs"
    monkeypatch.setenv(ids.RUNS_DIR_ENV, str(root))
    monkeypatch.setattr(init_mod, "git_head", lambda directory: None)
    monkeypatch.setattr(handlers, "get_handler", lambda task_type: handlers.default_handler)
    return root


@pytest.fixture
def target(tmp_path):
    folder = tmp_path / "webapp"
    shutil.copytree(TARGETS / "webapp", folder)
    (folder / "CLAUDE.md").write_text("instructions", encoding="utf-8")
    (folder / "node_modules").mkdir()
    return folder


def cli(capsys, *argv):
    code = main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def cli_json(capsys, *argv):
    code, out, err = cli(capsys, *argv, "--json")
    assert code == 0, err
    return json.loads(out)


def recon_sample(task_id):
    data = json.loads((SAMPLES / "recon.json").read_text(encoding="utf-8"))
    data["task_id"] = task_id
    return data


def recon_tasks(count):
    ctx = state.load_context()
    with state.transaction(ctx) as tx:
        tx.state["phase"] = "recon"
    return [queue.create_task(ctx, "recon", "recon", {"kind": "product"}) for _ in range(count)]


def test_run_init_json(runs, target, capsys):
    output = cli_json(capsys, "run", "init", str(target), "--profile", "fast")
    assert ids.is_run_id(output["run_id"])
    assert output["phase"] == "deterministic"
    assert output["options"]["profile"] == "fast"
    assert output["budget"]["max_agent_tasks"] == 40
    assert output["tech"] == ["docker", "flask", "python"]
    assert output["neutralized"] == 1
    assert output["excluded"] == {"node_modules": 1}
    assert output["files"]["copied"] == 6
    assert Path(output["run_dir"]) == runs / output["run_id"]
    assert ids.read_latest(runs) == output["run_id"]
    assert output["latest"] is True


def test_run_init_no_latest_leaves_latest_unchanged(runs, target, capsys):
    first = cli_json(capsys, "run", "init", str(target))["run_id"]
    code, out, err = cli(capsys, "run", "init", str(target), "--no-latest", "--json")
    assert code == 0, err
    second = json.loads(out)
    assert ids.is_run_id(second["run_id"]) and second["run_id"] != first
    assert second["latest"] is False
    assert f"Pass --run {second['run_id']} to every command" in err
    assert ids.read_latest(runs) == first
    # Each run answers to its own ID. The default (no --run) stays the first run.
    named = cli_json(capsys, "run", "status", "--run", second["run_id"])
    assert named["run_id"] == second["run_id"]
    assert cli_json(capsys, "run", "status")["run_id"] == first
    code, out, _ = cli(capsys, "run", "init", str(target), "--no-latest")
    assert code == 0 and "Next: kalkan run next --run " in out
    assert ids.read_latest(runs) == first


def test_run_wait_checks_the_named_run(runs, target, monkeypatch, capsys):
    from kalkan.run import commands as run_commands

    monkeypatch.setattr(run_commands.time, "sleep", lambda seconds: None)
    run_id = cli_json(capsys, "run", "init", str(target), "--no-latest")["run_id"]
    data = cli_json(capsys, "run", "wait", "--seconds", "1", "--run", run_id)
    assert data == {"waited_seconds": 1}
    code, _, err = cli(capsys, "run", "wait", "--seconds", "1", "--run", "20261016T151915Z-x-0000")
    assert code == 1 and "run not found" in err
    code, _, err = cli(capsys, "run", "wait", "--run", "../x")
    assert code == 1 and "invalid run ID" in err


def test_run_init_human(runs, target, capsys):
    code, out, err = cli(capsys, "run", "init", str(target), "--lang", "en", "--docker", "off")
    assert code == 0, err
    assert "created in" in out
    assert "neutralized 1 instruction paths" in out
    assert "Tech: docker, flask, python" in out


def test_run_init_errors(runs, tmp_path, capsys, monkeypatch):
    code, _, err = cli(capsys, "run", "init", "file:///etc")
    assert code == 1
    assert "unsupported target URL" in err
    monkeypatch.setattr(init_mod.shutil, "which", lambda name: None)
    code, _, err = cli(capsys, "run", "init", "https://example.com/org/repo.git")
    assert code == 5
    assert "git is not installed" in err
    with pytest.raises(SystemExit) as caught:
        main(["run", "init", str(tmp_path), "--max-parallel", "0"])
    assert caught.value.code == EXIT_USAGE


def test_run_status(runs, target, capsys):
    run_id = cli_json(capsys, "run", "init", str(target))["run_id"]
    summary = cli_json(capsys, "run", "status")
    assert summary["run_id"] == run_id
    assert summary["phase"] == "deterministic"
    assert [item["name"] for item in summary["phases"]] == list(state.PHASES)
    assert summary["phases"][0]["status"] == "done"
    assert summary["tasks"]["total"] == 0
    assert summary["budget"]["remaining"] == 150
    assert summary["incomplete_reason"] is None
    assert summary["report"] is None
    report = runs / run_id / "report" / "REPORT.md"
    report.parent.mkdir()
    report.write_text("# Rapor\n", encoding="utf-8")
    assert cli_json(capsys, "run", "status", "--run", run_id)["report"].endswith("report/REPORT.md")
    code, out, _ = cli(capsys, "run", "status")
    assert code == 0
    assert "Phase:   deterministic" in out
    assert "Budget:  0 of 150 agent tasks used, 150 left" in out
    assert "Report:" in out


def test_task_commands(runs, target, capsys):
    cli_json(capsys, "run", "init", str(target))
    first, second, third = recon_tasks(3)
    claimed = cli_json(capsys, "task", "claim", "--owner", "orchestrator", "--limit", "2")
    assert [item["id"] for item in claimed["tasks"]] == [first, second]
    assert claimed["tasks"][0]["agent"] == "kalkan-recon"

    Path(claimed["tasks"][0]["result_file"]).write_text(
        json.dumps(recon_sample(first)), encoding="utf-8"
    )
    assert cli_json(capsys, "task", "complete", first)["status"] == "done"
    assert cli_json(capsys, "task", "complete", first)["status"] == "unchanged"

    Path(claimed["tasks"][1]["result_file"]).write_text(
        json.dumps({"task_id": second}), encoding="utf-8"
    )
    code, out, err = cli(capsys, "task", "complete", second, "--json")
    assert code == EXIT_VALIDATION
    assert out == ""
    assert "attempt 1 of 3" in err
    assert "missing required field" in err

    failed = cli_json(capsys, "task", "fail", third, "--reason", "no access")
    assert failed == {"id": third, "status": "pending", "attempts": 1, "max_attempts": 3}

    code, out, _ = cli(capsys, "task", "complete", "T0009-recon")
    assert code == 1
    summary = cli_json(capsys, "run", "status")
    assert summary["tasks"]["by_status"]["done"] == 1
    assert summary["tasks"]["by_status"]["pending"] == 2


def test_task_claim_filters(runs, target, capsys):
    cli_json(capsys, "run", "init", str(target))
    ctx = state.load_context()
    queue.create_task(ctx, "sca_reach", "validate", {})
    queue.create_task(ctx, "hunt", "validate", {})
    assert cli_json(capsys, "task", "claim", "--owner", "w")["tasks"] == []
    claimed = cli_json(
        capsys, "task", "claim", "--owner", "w", "--phase", "validate", "--type", "hunt"
    )
    assert [item["type"] for item in claimed["tasks"]] == ["hunt"]
    code, _, err = cli(capsys, "task", "claim", "--owner", "w")
    assert code == 0
    assert "No ready task" in err


def test_run_resume_without_work(runs, target, capsys):
    cli_json(capsys, "run", "init", str(target))
    output = cli_json(capsys, "run", "resume")
    assert all(value == [] for value in output["resume"].values())
    assert output["status"]["phase"] == "deterministic"
    code, out, _ = cli(capsys, "run", "resume")
    assert code == 0
    assert "Nothing to recover." in out


@pytest.mark.parametrize(
    "argv",
    [
        ["run", "next", "--owner", "orchestrator", "--limit", "6", "--json"],
        ["run", "step", "--max-seconds", "480"],
        ["run", "answer", "english_report", "yes"],
        ["task", "prompt", "T0001-recon"],
    ],
)
def test_phase_engine_commands_need_a_run(runs, argv, capsys):
    # The phase engine commands are implemented (tests/unit/test_run_phases.py); without a
    # run they report the missing run like every other run command.
    code, out, err = cli(capsys, *argv)
    assert code == 1
    assert out == ""
    assert "no run found" in err


@pytest.mark.parametrize("group", ["run", "task"])
def test_groups_without_a_subcommand_print_help(group, capsys):
    code, out, _ = cli(capsys, group)
    assert code == EXIT_USAGE
    assert "usage:" in out


def test_commands_without_a_run(runs, capsys):
    code, _, err = cli(capsys, "run", "status")
    assert code == 1
    assert "no run found" in err
    code, _, err = cli(capsys, "run", "status", "--run", "../../x")
    assert code == 1
    assert "invalid run ID" in err


@pytest.mark.parametrize(
    "argv",
    [
        ["task", "complete", "not-a-task"],
        ["task", "claim"],
        ["task", "claim", "--owner", "bad owner"],
        ["task", "fail", "T0001-recon"],
        ["run", "init", "x", "--profile", "turbo"],
    ],
)
def test_usage_errors(argv):
    with pytest.raises(SystemExit) as caught:
        main(argv)
    assert caught.value.code == EXIT_USAGE


def test_run_wait_sleeps_at_most_300_seconds(monkeypatch, capsys):
    import json as _json

    from kalkan.run import commands as run_commands

    slept: list[float] = []
    monkeypatch.setattr(run_commands.time, "sleep", slept.append)
    from kalkan.cli import main as cli_main

    assert cli_main(["run", "wait", "--seconds", "900", "--json"]) == 0
    assert slept == [300]
    assert _json.loads(capsys.readouterr().out) == {"waited_seconds": 300}


def test_run_set_changes_max_parallel_under_the_lock(runs, target, capsys):
    cli_json(capsys, "run", "init", str(target))
    data = cli_json(capsys, "run", "set", "--max-parallel", "16")
    assert data["previous"] == 6 and data["max_parallel"] == 16
    status = cli_json(capsys, "run", "status")
    assert status["options"]["max_parallel"] == 16


def test_run_set_rejects_values_over_the_limit(runs, target, capsys):
    cli_json(capsys, "run", "init", str(target))
    with pytest.raises(SystemExit):
        main(["run", "set", "--max-parallel", "999"])
