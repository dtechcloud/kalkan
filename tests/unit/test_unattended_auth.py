# SPDX-License-Identifier: MIT
"""Unit tests for the login detection of the agent rounds (kalkan.unattended.auth)."""

from __future__ import annotations

from kalkan.unattended.auth import (
    AUTH_ANTHROPIC_API,
    AUTH_BEDROCK,
    AUTH_FOUNDRY,
    AUTH_SUBSCRIPTION,
    AUTH_VERTEX,
    detect_auth,
)


def test_without_variables_the_subscription_login_counts():
    info = detect_auth({})
    assert (info.mode, info.source, info.api) == (AUTH_SUBSCRIPTION, "login", False)
    assert detect_auth({"CLAUDE_CODE_OAUTH_TOKEN": "t"}).source == "CLAUDE_CODE_OAUTH_TOKEN"
    # An empty key or a false provider flag selects nothing.
    assert detect_auth({"ANTHROPIC_API_KEY": " ", "CLAUDE_CODE_USE_FOUNDRY": "0"}).api is False


def test_claude_api_keys_follow_the_claude_code_order():
    info = detect_auth({"ANTHROPIC_API_KEY": "k", "CLAUDE_CODE_OAUTH_TOKEN": "t"})
    assert (info.mode, info.source, info.api) == (AUTH_ANTHROPIC_API, "ANTHROPIC_API_KEY", True)
    both = detect_auth({"ANTHROPIC_API_KEY": "k", "ANTHROPIC_AUTH_TOKEN": "b"})
    assert both.source == "ANTHROPIC_AUTH_TOKEN"
    # A provider flag wins over a Claude API key.
    flagged = {"ANTHROPIC_API_KEY": "k", "CLAUDE_CODE_USE_BEDROCK": "true", "AWS_REGION": "x"}
    assert detect_auth(flagged).mode == AUTH_BEDROCK


def test_microsoft_foundry():
    env = {
        "CLAUDE_CODE_USE_FOUNDRY": "1",
        "ANTHROPIC_FOUNDRY_RESOURCE": "res",
        "ANTHROPIC_FOUNDRY_API_KEY": "secret-key",
        "ANTHROPIC_DEFAULT_OPUS_MODEL": "opus-deployment",
    }
    info = detect_auth(env)
    assert (info.mode, info.source, info.missing, info.notes) == (
        AUTH_FOUNDRY,
        "CLAUDE_CODE_USE_FOUNDRY",
        (),
        (),
    )
    assert info.describe() == "API: foundry (CLAUDE_CODE_USE_FOUNDRY)"
    assert "secret-key" not in repr(info)
    entra = detect_auth({"CLAUDE_CODE_USE_FOUNDRY": "1", "ANTHROPIC_FOUNDRY_BASE_URL": "https://x"})
    assert entra.missing == ()
    assert any("Entra ID" in note for note in entra.notes)
    assert any("ANTHROPIC_DEFAULT_OPUS_MODEL" in note for note in entra.notes)
    bare = detect_auth({"CLAUDE_CODE_USE_FOUNDRY": "1"})
    assert bare.missing == ("ANTHROPIC_FOUNDRY_RESOURCE or ANTHROPIC_FOUNDRY_BASE_URL",)


def test_bedrock_vertex_and_two_providers():
    assert detect_auth({"CLAUDE_CODE_USE_BEDROCK": "1"}).missing == ("AWS_REGION",)
    vertex = detect_auth({"CLAUDE_CODE_USE_VERTEX": "1", "CLOUD_ML_REGION": "us-east5"})
    assert (vertex.mode, vertex.missing) == (AUTH_VERTEX, ("ANTHROPIC_VERTEX_PROJECT_ID",))
    two = detect_auth({"CLAUDE_CODE_USE_VERTEX": "1", "CLAUDE_CODE_USE_FOUNDRY": "1"})
    assert two.missing == ("only one of CLAUDE_CODE_USE_VERTEX, CLAUDE_CODE_USE_FOUNDRY",)
