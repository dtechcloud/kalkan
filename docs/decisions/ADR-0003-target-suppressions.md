# ADR-0003: kalkan ignores the suppression markers of the target
English | [Türkçe](ADR-0003-target-suppressions.tr.md)

- Status: accepted
- Date: 2026-10-16

## Context

The scanners obey the suppression markers in the scanned code. Examples: `# nosec` (Bandit, gosec), `gitleaks:allow` and `.gitleaksignore` (Gitleaks), `checkov:skip` and `.checkov.yaml` (Checkov), `nosem` (Opengrep), Hadolint ignore pragmas.

kalkan is an audit tool. The audited code is not trusted. A developer or an attacker can hide a real vulnerability from the report with these markers.

## Decision

- By default, the scanner adapters ignore the suppression markers and the suppression configuration of the target.
- The option `kalkan scan --honor-suppressions` restores the default behavior of the tool.
- Each `scans/<engine>.status.json` file records which suppression source the scan ignored or applied.
- The hunter and verifier agents can see a suppression comment as context. For example, they can use the fact "the developer suppressed this line on purpose". But the verdict still depends on the evidence.

## Consequences

- The tool results get noisier. The unverified tool results stay in a separate section of the report. Thus, the noise does not enter the list of findings.
- When a version of a tool has no flag that turns off a suppression, the status file states clearly that this source was applied.
- The SCA commands have no `--honor-suppressions`. The SCA always ignores the `osv-scanner.toml` file of the target. In one test target, this file hid all 66 vulnerabilities.
- The Checkov configuration file of the target does not load, also with `--honor-suppressions`. This file can make Checkov run Python code of the target.
- Trivy 0.75.0 has no flag that turns off the inline `trivy:ignore` comments. These comments continue to hide Trivy results. The status file records this.
