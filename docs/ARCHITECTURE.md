# Architecture

This document describes the target design of kalkan. `docs/PHASES.md` has the phase list. The column "Phase" shows when a part becomes available.

## Layers

| Layer | Location | Role | Phase |
|---|---|---|---|
| Agent layer | `.claude/` | The `/kalkan` skill and the subagents. They read code, hunt for vulnerabilities and answer verification questions. | 5 |
| Engine layer | `src/kalkan/` | A deterministic CLI. It keeps the run state, runs the scanners, checks agent results, computes verdicts and writes the report. It never calls an LLM. | 0–7 |
| Knowledge layer | `knowledge/`, `rules/` | One owner file per vulnerability class, domain and language packs, matcher specs and Opengrep rules. | 2, 5 |

## Data flow of one audit run

```
/kalkan <target> <profile>
  kalkan run init     copy the target to runs/<id>/target, neutralize instruction files, write state.json
  loop:
    kalkan run next       return the next action: an engine step or ready tasks (phase graph, budget)
    kalkan run step       run one engine step (scanners, SCA, merge, report)
    subagent              do one task, return one JSON result
    kalkan task complete  check the schema and the quotes, compute the verdict
  phases: prep -> deterministic -> sca -> recon -> plan -> hunt <-> critic -> validate -> poc -> merge -> report
  kalkan report       REPORT.md (Turkish), findings.json, findings.sarif, REPORT.html,
                      EXECUTIVE.html (one-page executive summary)
```

## Invariants

- The engine never calls an LLM.
- The engine computes verdicts. It looks for each quote within two lines of the cited line in the source.
- All run state lives under `runs/<run-id>/`. Every write is atomic (temporary file, then `os.replace`).
- A task is claimed with a lease. A task with an expired lease can be claimed again. A second `complete` for the same result has no effect.
- A `needs_validation` record carries no severity. The overall severity never exceeds the impact. Rejected records stay in the output.
- Target code is data. The engine neutralizes instruction files (`CLAUDE.md`, `AGENTS.md`, `.claude/`, `.codex/`) in the target copy.

## Package map

| Package | Purpose | Phase |
|---|---|---|
| `kalkan.cli` | Command-line entry point | 0 |
| `kalkan.findings` | Finding schema, fingerprint, quote verifier, coverage ledger, merge, severity | 1–2 |
| `kalkan.sarif` | SARIF 2.1.0 ingest and emit | 1 |
| `kalkan.scanners` | Adapters for the external scanners | 2 |
| `kalkan.matchers` | Regex matcher engine (port of the deepsec matcher model) | 2 |
| `kalkan.tools` | `doctor`, tool install and verification, tool manifest | 2 |
| `kalkan.report` | Report rendering and language support | 2 |
| `kalkan.run` | Run state, phase graph, task queue, run lock | 3 |
| `kalkan.sca` | SBOM, vulnerability matching, reachability | 4 |
| `kalkan.sandbox` | Docker PoC runner, unit level (ADR-0006). The app level is deferred. | 7 |
| `kalkan.unattended` | Headless rounds and usage-limit handling | 6 |
| `kalkan.audit` | One-command audit: setup check, engine steps, end summary | v2 |
| `kalkan.resources`, `kalkan.plugin_hook` | Data and home locator, permission hook of the Claude Code plugin | plugin |
