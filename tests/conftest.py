# SPDX-License-Identifier: MIT
"""Shared test setup.

The verification sandbox (``kalkan.sandbox``) starts a container when a Docker engine answers.
A development machine often has one, so without this fixture the ``poc`` phase would behave
differently on a machine with Docker than on one without. The autouse fixture forces
:func:`kalkan.sandbox.docker_available` to return False for every test, so the generic suite is
deterministic and never starts a container. A test that needs the real engine carries the
``docker`` marker and opts out.

A second autouse fixture moves the kalkan profile folder of the opengrep adapters into a
temporary folder for every test without the ``tools`` marker.
"""

from __future__ import annotations

import pytest

from kalkan.sandbox.runner import FORCE_UNAVAILABLE_ENV


@pytest.fixture(autouse=True)
def _sandbox_off(request, monkeypatch):
    if "docker" in request.keywords:
        monkeypatch.delenv(FORCE_UNAVAILABLE_ENV, raising=False)
    else:
        monkeypatch.setenv(FORCE_UNAVAILABLE_ENV, "1")
    yield


@pytest.fixture(autouse=True)
def _opengrep_home_in_tmp(request, monkeypatch, tmp_path_factory):
    """The opengrep adapters create their kalkan profile folder before a run
    (kalkan.tools.toolhome). Tests with fake processes get one in a temporary folder, so they
    never write into the ``.tools`` of the checkout. Tests with real tools (marker ``tools``)
    keep the real one."""
    if "tools" not in request.keywords:
        from kalkan.scanners.adapters import opengrep

        made: list = []

        def home():
            if not made:  # only a test that runs an opengrep adapter needs the folder
                made.append(tmp_path_factory.mktemp("opengrep-home"))
            return made[0]

        monkeypatch.setattr(opengrep, "default_home", home)
    yield
