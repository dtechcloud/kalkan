# SPDX-License-Identifier: MIT
"""Tests for ``kalkan clean``: the disk usage of kalkan and the safe deletion of its parts
(kalkan.tools.cleanup, kalkan.tools.commands)."""

from __future__ import annotations

import io
import json
import os
import stat
from pathlib import Path

import pytest

from kalkan import cli
from kalkan.errors import KalkanError
from kalkan.tools import cleanup
from kalkan.tools import commands as tool_commands

RUN_A = "20261029T151026Z-billing-4d58"
RUN_B = "20261029T160242Z-vulnapp-43c0"
TOOLS = ("trivy", "opengrep", "go", "pyenv", "installed.json")


def write(path: Path, size: int = 10) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"x" * size)
    return path


@pytest.fixture
def world(tmp_path, monkeypatch):
    """A kalkan home with every part, a runs root with two runs, an engine folder."""
    home = tmp_path / "home"
    tools = home / ".tools"
    write(tools / "installed.json", 100)
    write(tools / "trivy" / "0.75.0" / "bin" / "trivy.exe", 1000)
    write(tools / "opengrep" / "1.30.1" / "bin" / "opengrep.exe", 2000)
    write(tools / "go" / "1.26.9" / "go" / "bin" / "go.exe", 3000)
    write(tools / "pyenv" / "Scripts" / "python.exe", 400)
    write(tools / "vulndb" / "osv" / "osv-scalibr" / "npm" / "all.zip", 5000)
    write(tools / "vulndb" / "status.json", 50)
    write(
        tools / "cache" / "opengrep" / "AppData" / "Local" / "opengrep" / "v1.30.1" / "a.dll", 700
    )
    write(tools / "go-build" / "cache" / "ab" / "abc-d", 600)
    write(tools / ".tmp" / "download.part", 500)
    write(tools / "mine" / "notes.txt", 30)  # not a kalkan name: never deleted
    write(home / ".venv" / "Scripts" / "python.exe", 80)  # the engine of a checkout
    write(home / "src" / "kalkan" / "cli.py", 90)  # source files of a checkout
    runs = tmp_path / "runs"
    for run, phase in ((RUN_A, "done"), (RUN_B, "hunt")):
        state = json.dumps({"phase": phase}).ljust(20)  # 20 bytes, as the sizes below expect
        write(runs / run / "state.json").write_text(state, encoding="utf-8")
        write(runs / run / "target" / "app.py", 300)
        write(runs / run / "report" / "REPORT.md", 40)
    write(runs / "LATEST", 31)
    write(runs / "keep-me" / "x.txt", 5)  # not a run ID: never deleted
    engine = tmp_path / "engine"
    write(engine / "Lib" / "site-packages" / "kalkan" / "__init__.py", 70)
    monkeypatch.setenv("KALKAN_HOME", str(home))
    monkeypatch.setenv("KALKAN_RUNS_DIR", str(runs))
    monkeypatch.setattr(cleanup, "engine_root", lambda: engine)
    monkeypatch.setattr(cleanup, "tool_names", lambda: list(TOOLS))
    return home.resolve(), runs.resolve(), engine


def run_cli(capsys, *argv):
    code = cli.main(["clean", *argv])
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_the_usage_view_measures_every_part(world, capsys):
    home, runs, engine = world
    found = cleanup.usage()
    sizes = {name: found.parts[name].stats.bytes for name in cleanup.PARTS}
    assert sizes == {
        "engine": 70,
        "tools": 100 + 1000 + 2000 + 3000 + 400,
        "databases": 5050,
        "caches": 700 + 600 + 500,
        "runs": 2 * (20 + 300 + 40) + 31,
    }
    assert found.runs == 2 and found.home == home and found.runs_root == runs
    assert [item.path.name for item in found.other] == ["mine"]
    code, out, err = run_cli(capsys)
    assert code == 0, err
    lines = out.splitlines()
    assert lines[0].startswith(
        f"kalkan clean: what kalkan keeps on this machine (home {home.as_posix()}"
    )
    assert lines[1].split() == ["PART", "SIZE", "FILES", "FOLDER"]
    assert lines[2].startswith("Engine") and "never deleted" in lines[2]
    assert lines[3].split()[:4] == ["Tools", "6.5", "KB", "5"]
    assert lines[4].split()[:4] == ["Databases", "5.0", "KB", "2"]
    assert lines[5].split()[:4] == ["Caches", "1.8", "KB", "3"]
    assert lines[6].startswith("Runs") and "(2 runs)" in lines[6]
    assert lines[7].split()[:3] == ["Total", "14.2", "KB"]
    assert "Not kalkan's (not deleted)" in out and "Delete with: kalkan clean --runs" in out
    code, out, err = run_cli(capsys, "--json")
    data = json.loads(out)["usage"]
    assert [part["part"] for part in data["parts"]] == list(cleanup.PARTS)
    assert data["total"]["bytes"] == sum(sizes.values()) and data["runs"] == 2


def test_caches_databases_and_tools_go_by_fixed_names(world, capsys):
    home, runs, engine = world
    code, out, err = run_cli(capsys, "--caches", "--yes")
    assert code == 0, err
    assert not (home / ".tools" / "cache").exists()
    assert not (home / ".tools" / "go-build").exists() and not (home / ".tools" / ".tmp").exists()
    assert (home / ".tools" / "vulndb").is_dir() and (home / ".tools" / "trivy").is_dir()
    code, out, err = run_cli(capsys, "--databases", "--yes")
    assert code == 0 and not (home / ".tools" / "vulndb").exists()
    code, out, err = run_cli(capsys, "--tools", "--yes")
    assert code == 0, err
    for name in TOOLS:
        assert not (home / ".tools" / name).exists(), name
    assert (home / ".tools" / "mine" / "notes.txt").is_file()  # not a kalkan name
    assert (home / ".venv" / "Scripts" / "python.exe").is_file()  # the engine stays
    assert (home / "src" / "kalkan" / "cli.py").is_file()  # source files stay
    assert (runs / RUN_A).is_dir()


def test_runs_go_by_run_id_and_reports_can_stay(world, capsys):
    home, runs, engine = world
    code, out, err = run_cli(capsys, "--runs", "--keep-reports", "--yes")
    assert code == 0, err
    for run in (RUN_A, RUN_B):
        assert sorted(path.name for path in (runs / run).iterdir()) == ["report"]
        assert (runs / run / "report" / "REPORT.md").is_file()
    assert not (runs / "LATEST").exists()
    code, out, err = run_cli(capsys, "--runs", "--yes")
    assert code == 0, err
    assert sorted(path.name for path in runs.iterdir()) == ["keep-me"]


def test_the_dry_run_lists_and_deletes_nothing(world, capsys):
    home, runs, engine = world
    code, out, err = run_cli(capsys, "--all", "--dry-run")
    assert code == 0, err
    assert out.startswith("kalkan clean --all --dry-run: would delete ")
    # The phase of each run: an audit may still run a run that is not done.
    assert f"{RUN_A}  (done)" in out and f"{RUN_B}  (phase hunt, not finished)" in out
    assert (home / ".tools" / "cache").is_dir() and (runs / RUN_A).is_dir()
    code, out, err = run_cli(capsys, "--runs", "--dry-run", "--json")
    document = json.loads(out)
    assert document["delete"]["dry_run"] is True and document["delete"]["deleted"] is False
    names = sorted(Path(item["path"]).name for item in document["delete"]["items"])
    assert names == [RUN_A, RUN_B, "LATEST"]


def test_deletion_asks_first(world, capsys, monkeypatch):
    home, runs, engine = world
    code, out, err = run_cli(capsys, "--caches")  # stdin of the test is not a terminal
    assert code == 1 and "pass --yes" in err and (home / ".tools" / "cache").is_dir()
    monkeypatch.setattr(tool_commands, "_interactive", lambda: True)
    monkeypatch.setattr("sys.stdin", io.StringIO("n\n"))
    code, out, err = run_cli(capsys, "--caches")
    assert code == 0 and "Nothing was deleted." in out and (home / ".tools" / "cache").is_dir()
    assert "Delete these 3 items (1.8 KB)? [y/N]" in err
    monkeypatch.setattr("sys.stdin", io.StringIO("evet\n"))
    code, out, err = run_cli(capsys, "--caches")
    assert code == 0 and "Deleted 1.8 KB in 3 files." in out
    assert not (home / ".tools" / "cache").exists()


def test_all_removes_everything_but_the_engine_and_names_the_next_step(world, capsys):
    home, runs, engine = world
    code, out, err = run_cli(capsys, "--all", "--yes", "--json")
    assert code == 0, err
    document = json.loads(out)
    assert document["delete"]["deleted"] is True and document["delete"]["errors"] == []
    assert sorted(path.name for path in (home / ".tools").iterdir()) == ["mine"]
    assert sorted(path.name for path in runs.iterdir()) == ["keep-me"]
    assert (engine / "Lib" / "site-packages" / "kalkan" / "__init__.py").is_file()
    assert document["next_steps"] == [
        f"Remove the engine: pip uninstall kalkan, or delete the venv {engine.as_posix()}.",
        f"Then delete {home.as_posix()} when it is empty.",
    ]


def test_next_steps_of_the_plugin_and_of_a_checkout(world):
    found = cleanup.usage()
    found.home_source = "marker"
    steps = cleanup.next_steps(found)
    assert steps[0].startswith("claude plugin uninstall kalkan@kalkan")
    assert "--keep-data keeps the folder" in steps[0]
    assert steps[1] == "claude plugin marketplace remove kalkan"
    found.home_source = "checkout"
    checkout = cleanup.next_steps(found)[0]
    assert checkout.startswith(f"Delete the checkout folder {found.home.as_posix()}")


def test_usage_errors(world, capsys):
    assert run_cli(capsys, "--keep-reports", "--caches")[0] == 2
    assert run_cli(capsys, "--dry-run")[0] == 2
    assert run_cli(capsys, "--yes")[0] == 2


# --- safety rules -----------------------------------------------------------------------------


def test_the_home_must_be_a_kalkan_home(tmp_path, monkeypatch):
    drive = Path(os.path.abspath(os.sep))
    assert "is a drive root" in cleanup.home_problem(drive)
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    assert "is the user profile folder" in cleanup.home_problem(tmp_path)
    plain = tmp_path / "plain"
    plain.mkdir()
    assert "nothing marks" in cleanup.home_problem(plain)
    assert cleanup.home_problem(plain, "marker") == ""  # named by the plugin marker
    write(plain / ".tools" / "installed.json")
    assert cleanup.home_problem(plain) == ""
    checkout = cleanup.resources.checkout_root()
    assert checkout is not None and cleanup.home_problem(checkout) == ""


def test_a_home_without_a_marker_is_refused(world, capsys):
    home, runs, engine = world
    (home / ".tools" / "installed.json").unlink()
    code, out, err = run_cli(capsys, "--caches", "--yes")
    assert code == 1 and "refusing to delete: nothing marks" in err
    assert (home / ".tools" / "cache").is_dir()
    code, out, err = run_cli(capsys, "--runs", "--yes")  # the runs need no home marker
    assert code == 0 and not (runs / RUN_A).exists()


def make_link(link: Path, target: Path) -> None:
    if os.name == "nt":
        import _winapi

        _winapi.CreateJunction(str(target), str(link))
    else:
        os.symlink(target, link, target_is_directory=True)


def test_links_are_removed_as_links_and_their_targets_survive(world, tmp_path, capsys):
    home, runs, engine = world
    outside = tmp_path / "outside"
    write(outside / "precious.txt", 7)
    make_link(home / ".tools" / "cache" / "escape", outside)
    make_link(runs / "20261029T170000Z-linked-0000", outside)
    code, out, err = run_cli(capsys, "--caches", "--runs", "--yes")
    assert code == 0, err
    assert (outside / "precious.txt").is_file()
    assert not os.path.lexists(runs / "20261029T170000Z-linked-0000")


def test_keep_reports_never_walks_into_a_link_named_like_a_run(world, tmp_path, capsys):
    home, runs, engine = world
    outside = tmp_path / "outside-run"
    write(outside / "state.json", 5)
    write(outside / "report" / "REPORT.md", 5)
    link = runs / "20261029T170000Z-linked-0000"
    make_link(link, outside)
    code, out, err = run_cli(capsys, "--runs", "--keep-reports", "--yes")
    assert code == 0, err
    assert not os.path.lexists(link)  # the link went, as a link
    assert (outside / "state.json").is_file() and (outside / "report" / "REPORT.md").is_file()


def test_a_tools_folder_that_links_out_of_the_home_is_refused(world, tmp_path, capsys):
    home, runs, engine = world
    elsewhere = tmp_path / "elsewhere"
    (home / ".tools").rename(elsewhere)
    make_link(home / ".tools", elsewhere)
    with pytest.raises(KalkanError, match="links out of"):
        cleanup.plan(cleanup.usage(), ["caches"])
    assert (elsewhere / "cache").is_dir()


def test_read_only_files_long_paths_and_unicode_names_are_removed(world, capsys):
    home, runs, engine = world
    deep = runs / RUN_A / "target" / "çalışma-ğüşİö"
    while len(str(deep)) < 280:
        deep = deep / ("klasör-" + "x" * 30)
    text = str(deep / "dosya-ı.txt")
    if os.name == "nt":
        os.makedirs("\\\\?\\" + str(deep))
        with open("\\\\?\\" + text, "w", encoding="utf-8") as handle:
            handle.write("uzun")
    else:
        deep.mkdir(parents=True)
        Path(text).write_text("uzun", encoding="utf-8")
    locked = write(home / ".tools" / "go-build" / "gopath" / "pkg" / "mod" / "m@v1" / "go.mod")
    os.chmod(locked, stat.S_IREAD)  # Go marks its module files read-only
    code, out, err = run_cli(capsys, "--caches", "--runs", "--yes")
    assert code == 0, err
    assert not (home / ".tools" / "go-build").exists() and not (runs / RUN_A).exists()
