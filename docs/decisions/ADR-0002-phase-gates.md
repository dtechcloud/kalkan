# ADR-0002: Internal checks in place of owner approval at the phase gates
English | [Türkçe](ADR-0002-phase-gates.tr.md)

- **Status:** Accepted
- **Date:** 2026-10-15
- **Decided by:** the project owner
- **Replaces:** the rule "every phase ends with owner approval" in ADR-0001

## Context

At the Phase 0 gate, the project owner decided: all phases continue without a wait for approval, in a controlled way and with internal checks. When necessary, parallel agents share the work. The project finishes completely, with all its phases.

## Decision

1. **Phase gate = internal checklist.** A phase closes when these conditions are true:
   - `pytest` is green with all tests.
   - `ruff check .` and `ruff format --check .` are clean.
   - `python scripts/vendor_third_party.py --check` passes.
   - A demo command shows the acceptance criterion of the phase, and the result is recorded with the change.
2. After the gate, the session pushes the changes to the `origin` repository, and the next phase starts. The project owner gets a short status summary, but the work does not wait for approval.
3. **Parallel development:** subagents can take the independent modules of a phase.
   - Each subagent has its own files, and these files do not overlap.
   - A subagent does not commit and does not change the files of another agent.
   - The merging session reviews the output, runs the full test set and commits.
4. The contracts are in `docs/ENGINE-SPEC.md`. The subagents obey this file.

## Consequences

- Development continues without a wait for approval.
- Quality assurance depends on automatic checks and acceptance demos.
- If a check fails, the phase does not close. The session fixes the error and runs the checklist again from the start.
