# Platform check: macOS 27.0.1 arm64: FAIL

- kalkan 1.0.0, platform key `darwin-arm64`
- CPU: Apple M1 Pro (10 CPUs)
- Python 3.12.10; git version 2.54.0 (Apple Git-157); Docker: 28.5.1

## Problems

- step tool-tests exited with 1
- tool tests: 2 failed, 0 errors

## Steps

| Step | Exit code | Time |
|---|---|---|
| bootstrap | 0 | 5 min 0 s |
| doctor | 0 | 0 min 5 s |
| dev-install | 0 | 0 min 6 s |
| tool-tests | 1 | 3 min 52 s |
| docker-tests | 0 | 0 min 6 s |
| benchmark | 0 | 1 min 3 s |

## Tools (kalkan doctor)

| Check | Status | Detail |
|---|---|---|
| python | ok | Python 3.12.10 |
| platform | ok | darwin-arm64 |
| git | ok | git version 2.54.0 (Apple Git-157) |
| docker-client | ok | Docker version 28.5.1, build e180ab8 |
| docker-engine | ok | engine 28.5.1 |
| manifest | ok | 22 tools pinned |
| node | ok | v22.18.0 |
| claude | ok | 2.1.310 (Claude Code); signed in |
| unattended:print-mode | ok | claude -p supports --permission-mode dontAsk and --output-format stream-json |
| unattended:auto-continue | info | autoContinueAtUsageLimit is not set in ~/.claude/settings.json. kalkan unattended waits for usage-limit resets by itself and does not need it. |
| unattended:workspace-trust | warn | Claude Code does not trust this folder yet, so it ignores the project permissions and subagents cannot write their results. Run `claude` in this folder once and |
| unattended:codex | info | codex-cli 0.160.0 (~/.nvm/versions/node/v22.18.0/bin/codex) |
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
| paths | ok | home ~/kalkan-platform-check (checkout); runs ~/kalkan-platform-check/runs; data from the checkout |
| vulndb | ok | OSV: 13 ecosystems, Grype: ready, Go: the vuln.go.dev archive, modified 2026-11-11T02:51:11Z, RetireJS: 75 libraries, updated 2026-11-12T20:22:53Z; updated 2026 |
| disk | ok | 21.1 GB free |
| footprint | info | 5.45 GB in 38,100 files: tools 1.46 GB, databases 3.73 GB, caches 257.1 MB, runs 0 B (0 runs); details and cleanup: kalkan clean |
| runs-writable | ok | ~/kalkan-platform-check/runs is writable |

## Tests

| Suite | Tests | Failed | Errors | Skipped |
|---|---|---|---|---|
| tool tests (-m tools) | 54 | 2 | 0 | 0 |
| Docker tests (-m docker) | 17 | 0 | 0 | 17 |

```
failure: tests.integration.test_tool_footprint::test_the_tools_write_nothing_into_the_profile: AssertionError: ['Library', 'Library/Application Support', 'Library/Application Support/go', 'Library/Application Support/go/telemetry...y/local', 'Library/Application Support/go/telemetry/local/asm@g
failure: tests.unit.test_sca_commands::test_real_syft_sbom_on_the_depapp: AssertionError: assert 3 == 2
skipped: tests.integration.test_sandbox_docker::test_the_harness_reads_the_read_only_target: base image python:3.12-slim not pulled (kalkan sandbox pull python:3.12-slim)
skipped: tests.integration.test_sandbox_docker::test_the_container_has_no_network: base image python:3.12-slim not pulled (kalkan sandbox pull python:3.12-slim)
skipped: tests.integration.test_sandbox_docker::test_the_target_mount_is_read_only: base image python:3.12-slim not pulled (kalkan sandbox pull python:3.12-slim)
skipped: tests.integration.test_sandbox_docker::test_only_the_three_bind_mounts_reach_the_container: base image python:3.12-slim not pulled (kalkan sandbox pull python:3.12-slim)
skipped: tests.integration.test_sandbox_docker::test_the_harness_runs_as_nobody_without_capabilities: base image python:3.12-slim not pulled (kalkan sandbox pull python:3.12-slim)
skipped: tests.integration.test_sandbox_docker::test_the_root_filesystem_is_read_only: base image python:3.12-slim not pulled (kalkan sandbox pull python:3.12-slim)
skipped: tests.integration.test_sandbox_docker::test_the_memory_limit_stops_a_large_allocation: base image python:3.12-slim not pulled (kalkan sandbox pull python:3.12-slim)
skipped: tests.integration.test_sandbox_docker::test_the_pid_limit_stops_a_process_flood: base image python:3.12-slim not pulled (kalkan sandbox pull python:3.12-slim)
skipped: tests.integration.test_sandbox_docker::test_the_timeout_stops_and_removes_the_container: base image python:3.12-slim not pulled (kalkan sandbox pull python:3.12-slim)
skipped: tests.integration.test_sandbox_docker::test_a_finished_container_is_removed: base image python:3.12-slim not pulled (kalkan sandbox pull python:3.12-slim)
skipped: tests.integration.test_sandbox_docker::test_the_out_watchdog_stops_a_harness_that_fills_the_disk: base image python:3.12-slim not pulled (kalkan sandbox pull python:3.12-slim)
skipped: tests.integration.test_sandbox_docker::test_a_csharp_harness_builds_and_runs_offline: base image python:3.12-slim not pulled (kalkan sandbox pull python:3.12-slim)
skipped: tests.integration.test_sandbox_docker::test_a_harness_that_writes_out_promotes_the_evidence: base image python:3.12-slim not pulled (kalkan sandbox pull python:3.12-slim)
skipped: tests.integration.test_sandbox_docker::test_an_app_harness_reaches_the_service_on_the_internal_network: base image python:3.12-slim not pulled (kalkan sandbox pull python:3.12-slim)
skipped: tests.integration.test_sandbox_docker::test_an_unsafe_compose_stack_is_never_started: base image python:3.12-slim not pulled (kalkan sandbox pull python:3.12-slim)
skipped: tests.integration.test_sandbox_docker::test_an_app_stack_that_needs_a_build_waits_for_consent: base image python:3.12-slim not pulled (kalkan sandbox pull python:3.12-slim)
skipped: tests.integration.test_sandbox_docker::test_a_csharp_harness_can_use_asp_net_core_offline: base image python:3.12-slim not pulled (kalkan sandbox pull python:3.12-slim)
```

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

Verdict: **FAIL**
