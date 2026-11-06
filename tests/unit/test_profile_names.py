"""Profile names since 1.6.0: ``fast``, ``standard`` and ``deep``. The names before 1.6.0
(``quick``, ``hizli``, ``standart``, ``derin``) stay accepted, and an older run state resumes."""

import argparse
import json

import pytest

from kalkan.errors import KalkanError
from kalkan.run import budget, state
from kalkan.run.init import init_run
from kalkan.unattended import loop as loop_mod


@pytest.mark.parametrize(
    ("name", "canonical"),
    [
        ("fast", "fast"),
        ("quick", "fast"),
        ("hizli", "fast"),
        ("hızlı", "fast"),
        ("standard", "standard"),
        ("standart", "standard"),
        ("deep", "deep"),
        ("derin", "deep"),
        (" Deep ", "deep"),
    ],
)
def test_every_accepted_name_has_one_canonical_name(name, canonical):
    assert budget.canonical_profile(name) == canonical
    assert loop_mod.profile_arg(name) == canonical


def test_an_unknown_name_names_the_three_profiles():
    with pytest.raises(ValueError, match="use fast, standard, deep"):
        budget.canonical_profile("medium")
    with pytest.raises(argparse.ArgumentTypeError):
        loop_mod.profile_arg("medium")


def test_unattended_options_keep_the_canonical_name():
    assert loop_mod.UnattendedOptions(target="app", profile="derin").profile == "deep"
    with pytest.raises(KalkanError, match="unknown profile"):
        loop_mod.UnattendedOptions(target="app", profile="medium")


def test_a_run_state_from_before_1_6_0_loads_with_the_canonical_name(tmp_path):
    target = tmp_path / "app"
    target.mkdir()
    (target / "app.py").write_text("print('hi')\n", encoding="utf-8")
    ctx = init_run(str(target), runs_dir=tmp_path / "runs", profile="fast")
    path = ctx.run_dir / "state.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["options"]["profile"] = "quick"
    path.write_text(json.dumps(data), encoding="utf-8")
    assert state.load_state(ctx.run_dir)["options"]["profile"] == "fast"
