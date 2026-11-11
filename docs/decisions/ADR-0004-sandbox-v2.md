# ADR-0004: The PoC sandbox is out of the v1 scope
English | [Türkçe](ADR-0004-sandbox-v2.tr.md)

- Status: updated by ADR-0006 (2026-10-29) and ADR-0008 (2026-11-11). The sandbox is active at the unit level and at the app level. The out-of-scope
  decision below applied only to v1. Here v1 and v2 are stages of the first development plan, not release numbers.
- Date: 2026-10-16

## Context

Phase 7 was to run a PoC program from an agent in a Docker container with the network off. This part runs a program that an agent wrote from the target code. Thus, it is the most sensitive part of the project for security.

## Decision

- v1 does not include the PoC sandbox. The project owner made this decision on 2026-10-16.
- The `poc` stage always takes the `poc:skip` path. Code findings carry the blocker `sandbox_unavailable`. The verdict of a finding depends only on the verified evidence in the source code.
- v2 handles the sandbox as a separate design work together with the project owner.

## Consequences

- For `confirmed` findings, `confidence` is at most `medium`, because there is no dynamic evidence.
- The `kalkan sandbox` command continues to give a "planned phase" message.
