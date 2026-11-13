# Platform check: macOS 15.7.4 arm64: PASS

- kalkan 1.0.0, platform key `darwin-arm64`
- CPU: Apple M2 (8 CPUs)
- Python 3.14.10; git version 2.39.5 (Apple Git-154); Docker: not running

## Steps

| Step | Exit code | Time |
|---|---|---|
| bootstrap | 0 | 0 min 0 s |
| doctor | 0 | 0 min 4 s |
| dev-install | 0 | 0 min 1 s |
| tool-tests | 0 | 3 min 1 s |
| benchmark | 0 | 0 min 54 s |

## Tools (kalkan doctor)

| Check | Status | Detail |
|---|---|---|
| python | ok | Python 3.14.10 |
| platform | ok | darwin-arm64 |
| git | ok | git version 2.39.5 (Apple Git-154) |
| docker-client | warn | Docker not found: the PoC sandbox is unavailable |
| docker-engine | warn | skipped: no Docker client |
| manifest | ok | 22 tools pinned |
| node | ok | v23.6.0 |
| claude | warn | Claude Code CLI not found: the /kalkan skill and kalkan audit need it. Install Claude Code, then sign in: claude auth login |
| unattended:print-mode | warn | skipped: claude is not on PATH |
| unattended:auto-continue | info | ~/.claude/settings.json does not exist: autoContinueAtUsageLimit is not set. kalkan unattended waits for usage-limit resets by itself and does not need it. |
| unattended:workspace-trust | warn | cannot read the Claude Code state file to check folder trust. Claude Code does not trust this folder yet, so it ignores the project permissions and subagents ca |
| unattended:codex | info | codex is not on PATH. It is needed only for: kalkan unattended --host codex |
| tool:trivy | ok | 0.75.0 installed, SHA-256 ok |
| tool:gitleaks | ok | 8.30.1 installed, SHA-256 ok |
| tool:opengrep | ok | 1.30.1 installed, SHA-256 ok |
| tool:hadolint | ok | 2.15.1 installed, SHA-256 ok |
| tool:go | ok | 1.26.9 installed, executable SHA-256 ok, 15045 files, tree SHA-256 recorded at install |
| tool:gosec | ok | 2.29.0 installed, SHA-256 ok; runs with Go 1.26.9 (kalkan) |
| tool:osv-scanner | ok | 2.6.0 installed, SHA-256 ok |
| tool:syft | ok | 1.54.0 installed, SHA-256 ok |
| tool:grype | ok | 0.119.0 installed, SHA-256 ok |
| tool:checkov | ok | 3.3.22 installed, SHA-256 ok |
| tool:bandit | ok | 1.9.4 installed, SHA-256 ok |
| tool:govulncheck | ok | 1.8.0 installed, SHA-256 ok; runs with Go 1.26.9 (kalkan) |
| tool:zizmor | ok | 1.30.1 installed, SHA-256 ok |
| tool:actionlint | ok | 1.7.12 installed, SHA-256 ok |
| tool:poutine | ok | 1.1.6 installed, SHA-256 ok; runs with Go 1.26.9 (kalkan) |
| tool:scorecard | ok | 5.5.0 installed, SHA-256 ok |
| tool:kingfisher | ok | 2.11.1 installed, SHA-256 ok |
| tool:shellcheck | ok | 0.11.0 installed, SHA-256 ok |
| tool:flawfinder | ok | 2.0.20 installed, SHA-256 ok |
| tool:gixy | ok | 0.2.55 installed, SHA-256 ok |
| tool:helm | ok | 4.3.0 installed, SHA-256 ok |
| tool:vacuum | ok | 0.33.0 installed, SHA-256 ok |
| paths | ok | home ~/Desktop/Projects/kalkan (checkout); runs ~/Desktop/Projects/kalkan/runs; data from the checkout |
| vulndb | ok | OSV: 13 ecosystems, Grype: ready, Go: the vuln.go.dev archive, modified 2026-11-11T02:51:11Z, RetireJS: 75 libraries, updated 2026-11-13T10:57:30Z; updated 2026 |
| disk | ok | 11.2 GB free |
| footprint | info | 5.47 GB in 38,136 files: tools 1.47 GB, databases 3.74 GB, caches 257.1 MB, runs 0 B (0 runs); details and cleanup: kalkan clean |
| runs-writable | ok | ~/Desktop/Projects/kalkan/runs is writable |

## Tests

| Suite | Tests | Failed | Errors | Skipped |
|---|---|---|---|---|
| tool tests (-m tools) | 54 | 0 | 0 | 0 |
| Docker tests (-m docker) | not run | | | |

## Engines on the vulnapp fixture

Found: planted items found / expected. Reference: the committed Windows 11 result (`benchmarks/results/vulnapp.json`).

| Engine | Status | Candidates | Found | Reference found | Reference candidates |
|---|---|---|---|---|---|
| actionlint | ok | 1 | 1/1 | 1/1 | 1 |
| bandit | ok | 11 | 7/7 | 7/7 | 11 |
| checkov | ok | 54 | 9/9 | 9/9 | 54 |
| flawfinder | ok | 3 | 3/3 | 3/3 | 3 |
| gitleaks | ok | 2 | 2/2 | 2/2 | 2 |
| gitleaks-history | skipped | - | - | - | - |
| gixy | ok | 2 | 2/2 | 2/2 | 2 |
| gosec | ok | 19 | 8/8 | 8/8 | 19 |
| grype | ok | - | 10/10 | 10/10 | - |
| grype-pins | ok | - | - | - | - |
| hadolint | ok | 8 | 3/3 | 3/3 | 8 |
| helm-checkov | ok | 30 | 2/2 | 2/2 | 30 |
| kingfisher | ok | 2 | 2/2 | 2/2 | 2 |
| kingfisher-history | skipped | - | - | - | - |
| matcher | ok | 57 | 6/7 | 6/7 | 57 |
| opengrep | ok | 109 | 108/108 | 108/108 | 109 |
| opengrep-packs | ok | 58 | 34/34 | 35/35 | 54 |
| osv-scanner | ok | - | 10/10 | 10/10 | - |
| osv-scanner-pins | ok | - | - | - | - |
| poutine | ok | 5 | 1/1 | 1/1 | 1 |
| retirejs | ok | - | 0/1 | 0/1 | - |
| scorecard | ok | 7 | - | - | 5 |
| shellcheck | ok | 3 | 2/2 | 2/2 | 3 |
| syft | ok | - | - | - | - |
| trivy | ok | 38 | 9/9 | 9/9 | 38 |
| vacuum | ok | 6 | 5/5 | 5/5 | 6 |
| zizmor | ok | 4 | 4/4 | 4/4 | 4 |

Fixture recall: 0.9936 by the expected engines, 1.0 by any engine. Missed by the expected engines: native-committed-binary-01.

Verdict: **PASS**
