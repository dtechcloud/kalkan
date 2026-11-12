# SPDX-License-Identifier: MIT
"""How Claude Code authenticates the agent rounds: a subscription or an API (docs/ENGINE-SPEC.md,
section 22).

kalkan starts ``claude -p`` with the environment of the user, so every Claude Code login method
works without a kalkan setting. :func:`detect_auth` reads the same environment variables as
Claude Code, in the same order (https://code.claude.com/docs/en/authentication.md):

1. A cloud provider flag: ``CLAUDE_CODE_USE_BEDROCK``, ``CLAUDE_CODE_USE_VERTEX`` or
   ``CLAUDE_CODE_USE_FOUNDRY`` (Microsoft Foundry). More than one flag is a setup problem.
2. ``ANTHROPIC_AUTH_TOKEN``, then ``ANTHROPIC_API_KEY``: the Claude API.
3. ``CLAUDE_CODE_OAUTH_TOKEN`` or the ``claude auth login`` session: a subscription.

The result names the mode, the variable that selected it and the required variables that are
missing. It never holds a value: a key or a token never reaches a log, a report or a run file.
With an API mode the cost of a round is billed, so ``kalkan audit --max-usd`` is advised; with
a subscription the cost is the API-equivalent estimate of Claude Code.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Final

__all__ = [
    "API_MODES",
    "AUTH_ANTHROPIC_API",
    "AUTH_BEDROCK",
    "AUTH_FOUNDRY",
    "AUTH_SUBSCRIPTION",
    "AUTH_VERTEX",
    "MODEL_PINS",
    "AuthInfo",
    "detect_auth",
]

AUTH_SUBSCRIPTION: Final = "subscription"
AUTH_ANTHROPIC_API: Final = "anthropic-api"
AUTH_FOUNDRY: Final = "foundry"
AUTH_BEDROCK: Final = "bedrock"
AUTH_VERTEX: Final = "vertex"
#: Modes that bill every round through an API account.
API_MODES: Final = frozenset({AUTH_ANTHROPIC_API, AUTH_FOUNDRY, AUTH_BEDROCK, AUTH_VERTEX})
#: The model variables of a cloud provider: deployment names (Foundry) or model IDs.
MODEL_PINS: Final = (
    "ANTHROPIC_MODEL",
    "ANTHROPIC_DEFAULT_OPUS_MODEL",
    "ANTHROPIC_DEFAULT_SONNET_MODEL",
    "ANTHROPIC_DEFAULT_HAIKU_MODEL",
)
_PROVIDER_FLAGS: Final = (
    ("CLAUDE_CODE_USE_BEDROCK", AUTH_BEDROCK),
    ("CLAUDE_CODE_USE_VERTEX", AUTH_VERTEX),
    ("CLAUDE_CODE_USE_FOUNDRY", AUTH_FOUNDRY),
)
_TRUE: Final = frozenset({"1", "true", "yes", "on"})


@dataclass(frozen=True)
class AuthInfo:
    """The login of the agent rounds. ``source`` names a variable or ``login``; ``missing``
    and ``notes`` hold variable names and advice, never values."""

    mode: str
    source: str
    missing: tuple[str, ...] = ()
    notes: tuple[str, ...] = field(default=())

    @property
    def api(self) -> bool:
        """True when every round is billed through an API account."""
        return self.mode in API_MODES

    def describe(self) -> str:
        """Return one line for the doctor and the log, for example ``API: foundry
        (CLAUDE_CODE_USE_FOUNDRY)``."""
        if not self.api:
            return "subscription" if self.source == "login" else f"subscription ({self.source})"
        return f"API: {self.mode} ({self.source})"


def _set(env: Mapping[str, str], name: str) -> bool:
    value = env.get(name)
    return isinstance(value, str) and bool(value.strip())


def _flag(env: Mapping[str, str], name: str) -> bool:
    value = env.get(name)
    return isinstance(value, str) and value.strip().lower() in _TRUE


def _provider(env: Mapping[str, str], mode: str, flag: str) -> AuthInfo:
    missing: list[str] = []
    notes: list[str] = []
    if mode == AUTH_FOUNDRY:
        if not (_set(env, "ANTHROPIC_FOUNDRY_RESOURCE") or _set(env, "ANTHROPIC_FOUNDRY_BASE_URL")):
            missing.append("ANTHROPIC_FOUNDRY_RESOURCE or ANTHROPIC_FOUNDRY_BASE_URL")
        if not (
            _set(env, "ANTHROPIC_FOUNDRY_API_KEY") or _set(env, "ANTHROPIC_FOUNDRY_AUTH_TOKEN")
        ):
            notes.append(
                "no ANTHROPIC_FOUNDRY_API_KEY: Claude Code uses Microsoft Entra ID (az login)"
            )
    elif mode == AUTH_BEDROCK:
        if not (_set(env, "AWS_REGION") or _set(env, "AWS_DEFAULT_REGION")):
            missing.append("AWS_REGION")
    elif mode == AUTH_VERTEX:
        missing += [
            n for n in ("CLOUD_ML_REGION", "ANTHROPIC_VERTEX_PROJECT_ID") if not _set(env, n)
        ]
    if not any(_set(env, name) for name in MODEL_PINS):
        notes.append(
            "no model pin: set ANTHROPIC_DEFAULT_OPUS_MODEL, ANTHROPIC_DEFAULT_SONNET_MODEL and "
            "ANTHROPIC_DEFAULT_HAIKU_MODEL to the model names of your account"
        )
    return AuthInfo(mode, flag, tuple(missing), tuple(notes))


def detect_auth(env: Mapping[str, str]) -> AuthInfo:
    """Return the login that Claude Code uses with ``env`` (module docstring)."""
    flags = [(name, mode) for name, mode in _PROVIDER_FLAGS if _flag(env, name)]
    if len(flags) > 1:
        names = ", ".join(name for name, _ in flags)
        return AuthInfo(flags[0][1], flags[0][0], (f"only one of {names}",))
    if flags:
        name, mode = flags[0]
        return _provider(env, mode, name)
    for name in ("ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_API_KEY"):
        if _set(env, name):
            return AuthInfo(AUTH_ANTHROPIC_API, name)
    if _set(env, "CLAUDE_CODE_OAUTH_TOKEN"):
        return AuthInfo(AUTH_SUBSCRIPTION, "CLAUDE_CODE_OAUTH_TOKEN")
    return AuthInfo(AUTH_SUBSCRIPTION, "login")
