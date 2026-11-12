# SPDX-License-Identifier: MIT
"""Cost, time and token usage of a run (``usage.jsonl`` in the run folder).

Every round of ``kalkan-audit`` / ``kalkan unattended`` is one ``claude -p --output-format
stream-json`` session. Its last event, ``{"type": "result", ...}``, reports the cost of the
session (``total_cost_usd``, subagents included), its time (``duration_ms``,
``duration_api_ms``), its turns and its tokens. :func:`parse_result` keeps only these numbers:
the event also holds the final message of the session, which can quote the audited code, and
that text never reaches the file. The first event, ``{"type": "system", "subtype": "init"}``,
names the key source and the model (:func:`parse_init`). The loop adds the login mode of the
environment (``auth``: ``subscription``, ``anthropic-api``, ``foundry``, ``bedrock`` or
``vertex``; :mod:`kalkan.unattended.auth`). :func:`append` adds one line per round;
:func:`summarize` adds them up for the report.

``total_cost_usd`` is the estimate of Claude Code at list prices (``cost_basis`` per model when
Claude Code names it). With a subscription it is the API-equivalent value; with an API login it
estimates the bill, and the bill of the API account is the authority.

An interactive ``/kalkan`` session has no such event that the engine can read, so its cost is
not recorded; the report says so.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any, Final

__all__ = ["USAGE_NAME", "append", "load", "parse_init", "parse_result", "summarize"]

USAGE_NAME: Final = "usage.jsonl"
_MAX_LINE_CHARS: Final = 4 * 1024 * 1024
_TOKEN_KEYS: Final = (
    "input_tokens",
    "output_tokens",
    "cache_creation_input_tokens",
    "cache_read_input_tokens",
)
_INIT_KEYS: Final = {
    "apiKeySource": "api_key_source",
    "model": "model",
    "claude_code_version": "claude_code_version",
}
_MODEL_KEYS: Final = {
    "costUSD": "cost_usd",
    "inputTokens": "input_tokens",
    "outputTokens": "output_tokens",
    "cacheReadInputTokens": "cache_read_input_tokens",
    "cacheCreationInputTokens": "cache_creation_input_tokens",
}


def _number(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        return None
    return float(value)


def _count(value: object) -> int | None:
    number = _number(value)
    return int(number) if number is not None else None


def parse_init(line: str) -> dict[str, Any] | None:
    """Return the login and model facts of a stream-json ``system``/``init`` event, or None.

    ``apiKeySource`` names the source of the key (``none`` for a subscription login); the event
    never holds the key itself. Only short strings are kept.
    """
    text = line.strip()
    if not text.startswith("{") or '"init"' not in text or len(text) > _MAX_LINE_CHARS:
        return None
    try:
        event = json.loads(text)
    except ValueError:
        return None
    if not isinstance(event, Mapping) or event.get("type") != "system":
        return None
    if event.get("subtype") != "init":
        return None
    record: dict[str, Any] = {}
    for theirs, ours in _INIT_KEYS.items():
        value = event.get(theirs)
        if isinstance(value, str) and value.strip():
            record[ours] = value.strip()[:80]
    return record


def parse_result(line: str) -> dict[str, Any] | None:
    """Return the numbers of a stream-json ``result`` event, or None for any other line."""
    text = line.strip()
    if not text.startswith("{") or '"result"' not in text or len(text) > _MAX_LINE_CHARS:
        return None
    try:
        event = json.loads(text)
    except ValueError:
        return None
    if not isinstance(event, Mapping) or event.get("type") != "result":
        return None
    record: dict[str, Any] = {"subtype": str(event.get("subtype") or "")[:40]}
    for key in ("total_cost_usd", "duration_ms", "duration_api_ms", "num_turns"):
        value = _number(event.get(key))
        if value is not None:
            record[key] = int(value) if key != "total_cost_usd" else round(value, 6)
    if isinstance(event.get("is_error"), bool):
        record["is_error"] = event["is_error"]
    usage = event.get("usage")
    if isinstance(usage, Mapping):
        tokens = {key: _count(usage.get(key)) for key in _TOKEN_KEYS}
        record["tokens"] = {key: value for key, value in tokens.items() if value is not None}
    models = event.get("modelUsage")
    if isinstance(models, Mapping):
        kept: dict[str, dict[str, float]] = {}
        bases: dict[str, str] = {}
        for name, item in list(models.items())[:20]:
            if not isinstance(name, str) or not isinstance(item, Mapping):
                continue
            values = {ours: _number(item.get(theirs)) for theirs, ours in _MODEL_KEYS.items()}
            kept[name[:80]] = {key: value for key, value in values.items() if value is not None}
            basis = item.get("costBasis")
            if isinstance(basis, str) and basis.strip():
                bases[name[:80]] = basis.strip()[:20]
        if kept:
            record["models"] = kept
        if bases:
            record["cost_basis"] = bases
    return record


def append(run_dir: Path, entry: Mapping[str, Any]) -> None:
    """Add one round to ``usage.jsonl`` (one JSON object per line, append only)."""
    with open(run_dir / USAGE_NAME, "a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(dict(entry), sort_keys=True) + "\n")


def load(run_dir: Path) -> list[dict[str, Any]]:
    """Return the rounds of ``usage.jsonl``; unreadable lines are skipped."""
    try:
        text = (run_dir / USAGE_NAME).read_text(encoding="utf-8")
    except OSError:
        return []
    rounds = []
    for line in text.splitlines()[:10000]:
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if isinstance(item, dict):
            rounds.append(item)
    return rounds


def summarize(rounds: Iterable[Mapping[str, Any]]) -> dict[str, Any] | None:
    """Return the totals of the rounds, or None without a round."""
    items = list(rounds)
    if not items:
        return None
    cost = sum(_number(item.get("total_cost_usd")) or 0.0 for item in items)
    tokens = dict.fromkeys(_TOKEN_KEYS, 0)
    models: dict[str, dict[str, float]] = {}
    for item in items:
        for key in _TOKEN_KEYS:
            tokens[key] += _count((item.get("tokens") or {}).get(key)) or 0
        for name, values in (item.get("models") or {}).items():
            total = models.setdefault(name, {})
            for key, value in values.items():
                number = _number(value)
                if number is not None:
                    total[key] = total.get(key, 0.0) + number
    return {
        "rounds": len(items),
        "rounds_with_cost": sum(1 for item in items if "total_cost_usd" in item),
        "cost_usd": round(cost, 4),
        "active_seconds": round(sum(_number(item.get("wall_seconds")) or 0.0 for item in items)),
        "api_seconds": round(
            sum(_number(item.get("duration_api_ms")) or 0.0 for item in items) / 1000
        ),
        "turns": sum(_count(item.get("num_turns")) or 0 for item in items),
        "tokens": tokens,
        "models": {
            name: {k: round(v, 4) for k, v in vals.items()} for name, vals in models.items()
        },
        "auth": sorted({str(item["auth"]) for item in items if isinstance(item.get("auth"), str)}),
    }
