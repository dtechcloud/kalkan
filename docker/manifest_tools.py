# SPDX-License-Identifier: MIT
"""Print the manifest tools of the install layers of docker/Dockerfile (docker/README.md).

Usage: python docker/manifest_tools.py GROUP [GROUP ...] [--manifest PATH]

The Dockerfile has no tool list of its own: each install layer asks this script for its tools,
so a tool that src/kalkan/tools/manifest.json gains arrives in the image without a Dockerfile
change. Every manifest tool belongs to exactly one group (:func:`group_of`):

- no group: a ``toolchain`` (Go); the ``go`` stage provides it as ``/opt/go``;
- ``go``: a tool that needs Go to build or to run (``requires_go``, or kind ``go-install``);
- ``go-gpl``: such a tool with a GPL or AGPL license;
- ``gpl``: another tool with a GPL or AGPL license (an LGPL license does not count); kalkan runs
  these unmodified binaries as separate processes, and the image keeps them in their own layer;
- ``core``: every other tool.

The script prints the names of the given groups on one line, separated by spaces, in manifest
order (an empty line when no tool matches). It reads the manifest with the standard library
only. Exit codes: 0 ok, 2 usage or an unreadable manifest.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Final

GROUPS: Final = ("core", "gpl", "go", "go-gpl")
DEFAULT_MANIFEST: Final = (
    Path(__file__).resolve().parents[1] / "src" / "kalkan" / "tools" / "manifest.json"
)
#: GPL or AGPL in an SPDX expression; LGPL does not match.
_GPL: Final = re.compile(r"(?<![A-Za-z])A?GPL", re.IGNORECASE)


def is_gpl(license_text: object) -> bool:
    """True when the SPDX license expression names a GPL or AGPL license."""
    return isinstance(license_text, str) and _GPL.search(license_text) is not None


def group_of(tool: Mapping[str, Any]) -> str | None:
    """Return the install group of one manifest tool (see the module docstring)."""
    kind = tool.get("kind")
    if kind == "toolchain":
        return None
    gpl = is_gpl(tool.get("license"))
    if tool.get("requires_go") is True or kind == "go-install":
        return "go-gpl" if gpl else "go"
    return "gpl" if gpl else "core"


def tools_of(manifest: Mapping[str, Any], groups: list[str]) -> list[str]:
    """Return the names of the manifest tools in ``groups``, in manifest order."""
    tools = manifest.get("tools")
    if not isinstance(tools, Mapping):
        raise ValueError("the manifest has no tool map")
    return [
        name
        for name, tool in tools.items()
        if isinstance(tool, Mapping) and group_of(tool) in groups
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("groups", nargs="+", choices=GROUPS, metavar="GROUP")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    args = parser.parse_args(argv)
    try:
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
        names = tools_of(manifest, args.groups)
    except (OSError, ValueError) as exc:
        print(f"manifest_tools: error: {exc}", file=sys.stderr)
        return 2
    print(" ".join(names))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
