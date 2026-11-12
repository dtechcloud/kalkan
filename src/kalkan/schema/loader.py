# SPDX-License-Identifier: MIT
"""Load the JSON Schemas that ship in ``kalkan/schemas`` and check each one once.

``load_schema("finding")`` reads ``kalkan/schemas/finding.schema.json`` through
:mod:`importlib.resources`, so it works from a source checkout, an editable install and a wheel.
The first call parses the file and runs :func:`kalkan.schema.validator.check_schema`; later calls
use the cached result.
"""

from __future__ import annotations

import copy
import functools
import re
from importlib import resources
from typing import Any, Final

from kalkan.errors import KalkanError, ValidationError
from kalkan.schema.validator import JsonStructureError, check_schema, parse_json_text

__all__ = ["load_schema", "shared_schema"]

_SCHEMA_NAME: Final = re.compile(r"[a-z][a-z0-9_-]*")


def shared_schema(name: str) -> dict[str, Any]:
    """Return the cached, checked schema ``name`` itself.

    The validators use this object directly. Callers must not change it; use
    :func:`load_schema` for a private copy.
    """
    return _checked_schema(name)


def load_schema(name: str) -> dict[str, Any]:
    """Return a private copy of the checked schema ``kalkan/schemas/<name>.schema.json``.

    Raises ``ValueError`` for a name that is not a plain schema name,
    :class:`~kalkan.errors.KalkanError` when the schema file is missing, and
    :class:`~kalkan.errors.ValidationError` when the file is not valid JSON or uses an
    unsupported schema construct.
    """
    return copy.deepcopy(_checked_schema(name))


@functools.cache
def _checked_schema(name: str) -> dict[str, Any]:
    if not isinstance(name, str) or not _SCHEMA_NAME.fullmatch(name):
        raise ValueError(f"invalid schema name: {name!r}")
    resource = resources.files("kalkan").joinpath("schemas").joinpath(f"{name}.schema.json")
    try:
        text = resource.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise KalkanError(f"schema not found: {name}") from None
    try:
        schema = parse_json_text(text)
    except JsonStructureError as exc:
        raise ValidationError(f"schema {name} is not valid JSON", exc.errors) from None
    errors = check_schema(schema)
    if errors:
        raise ValidationError(f"unsupported or invalid schema: {name}", errors)
    return schema
