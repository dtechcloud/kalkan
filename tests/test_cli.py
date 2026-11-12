"""Tests for the command-line entry point."""

import importlib.util

import pytest

from kalkan import __version__
from kalkan.cli import COMMANDS, EXIT_NOT_IMPLEMENTED, EXIT_USAGE, main


def _module_exists(module_name: str) -> bool:
    try:
        return importlib.util.find_spec(module_name) is not None
    except ModuleNotFoundError:
        return False


STUB_COMMANDS = sorted(
    name for name, (module, _, _) in COMMANDS.items() if not _module_exists(module)
)


def test_help_lists_all_commands(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    for name in COMMANDS:
        assert name in out


def test_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_no_command_prints_help_and_returns_usage(capsys):
    assert main([]) == EXIT_USAGE
    assert "usage:" in capsys.readouterr().out


@pytest.mark.parametrize("name", STUB_COMMANDS)
def test_stub_commands_report_their_phase(name, capsys):
    assert main([name]) == EXIT_NOT_IMPLEMENTED
    err = capsys.readouterr().err
    assert f"planned for phase {COMMANDS[name][2]}" in err


def test_missing_parent_package_gives_a_stub(monkeypatch):
    from kalkan import cli

    monkeypatch.setitem(cli.COMMANDS, "ghost", ("kalkan.ghostpkg.commands", "Ghost.", 9))
    assert cli.main(["ghost"]) == EXIT_NOT_IMPLEMENTED


def test_broken_import_inside_a_command_module_is_not_hidden(monkeypatch):
    import sys
    import types

    from kalkan import cli

    def broken(name, *args, **kwargs):
        if name == "kalkan.brokenpkg.commands":
            raise ModuleNotFoundError("No module named 'yaml'", name="yaml")
        return original(name, *args, **kwargs)

    original = cli.importlib.import_module
    monkeypatch.setattr(cli.importlib, "import_module", broken)
    monkeypatch.setitem(sys.modules, "kalkan.brokenpkg", types.ModuleType("kalkan.brokenpkg"))
    monkeypatch.setitem(cli.COMMANDS, "broken", ("kalkan.brokenpkg.commands", "Broken.", 9))
    with pytest.raises(ModuleNotFoundError):
        cli.build_parser()
