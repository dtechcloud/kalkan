# ADR-0001: The basic decisions of kalkan
English | [Türkçe](ADR-0001-decisions.tr.md)

- **Status:** Accepted. Later decisions changed some rows: the phase gates (ADR-0002), the "PoC" row (ADR-0004, ADR-0006 and ADR-0008: the unit level and the app level are active) and the "Extra scanners" row (ADR-0005).
- **Date:** 2026-10-15
- **Decided by:** the project owner
- **Sources:** a comparative analysis of five open-source AI security tools (see the context below)

## Context

We examined five open-source AI security tools: sast-skills, deepsec, codecrucible, security-audit-skill and open-code-review. The goal is to combine these tools in one repository. The project also gets an SCA module and extra open-source scanners. With one request, the user must start an audit in Claude Code that runs for hours. When the usage limit resets, the audit must continue where it stopped.

## Decisions

| Topic | Decision |
|---|---|
| Name | `kalkan`. CLI: `kalkan`. Claude Code command: `/kalkan` |
| Architecture | Claude Code and its subagents do all LLM work. The engine never calls an LLM. |
| Language | A Python 3.11+ core. The Go logic of codecrucible and open-code-review moves to Python. External tools run with their own binaries. |
| Upstream | We port the content. A selective copy of the source files stays under `third_party/` at a pinned commit, with LICENSE and NOTICE. |
| Platform | Native Windows, Linux and macOS. A Docker image with all tools for those who want it. |
| SCA | SBOM generation, vulnerability matching with two databases, reachability analysis. No license compliance. |
| Extra scanners | IaC and containers: Trivy, Checkov, Hadolint. Secrets: Gitleaks. Code patterns: Opengrep (with our own rules), Bandit, gosec. No zizmor, TruffleHog, Semgrep rules or CodeQL. |
| Setup | The bootstrap scripts download pinned versions and verify checksums and signatures. `kalkan doctor` shows what is missing. |
| PoC | Part of v1. A Docker sandbox with the network off. Unit level and app level (compose). Without Docker, the finding stays `needs_validation`. |
| Resume | By hand (`/kalkan devam`) and automatic (`scripts/run-unattended`). |
| Host | v1 supports only Claude Code. The core does not depend on the host. Codex comes in Phase 9. |
| Report language | Turkish. Common technical terms stay in English. After the report, the agent asks whether the user wants an English version. |
| Interface language | Agent instructions and CLI messages are in English. The reports and `README.tr.md` are in Turkish. |
| License | MIT. Ported Apache-2.0 files keep their own license header and the NOTICE attribution. |
| Remote repository | GitHub: `dtechcloud/kalkan`. |

## Consequences

- The engine calls no LLM, so all quota stays in one host. The resume logic stays in one place.
- The Go logic moves to Python, so our own code has one runtime. The external tools install as separate binaries.
- Docker is optional for PoC. Without Docker, the findings stay `needs_validation`.
- Codex support moves to Phase 9. Thus, we design the core without a dependency on the host.
- The license is MIT. The attributions of the Apache-2.0 components stay in `NOTICE` and `THIRD_PARTY.md`.

## Rejected options

- **Run the upstream engines as LLM engines:** quota conflicts, Windows problems and scattered resume logic.
- **Git submodules:** cloning and setup become complex on Windows.
- **Write everything from zero:** too much work, and we lose proven content.
- **Only WSL2 or only Docker:** native Windows use becomes difficult.
- **Apache-2.0 or 0BSD license:** the project owner wanted the most permissive common license. MIT is the common OSI license that fits this choice best.
