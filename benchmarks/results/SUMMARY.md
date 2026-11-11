# Benchmark summary

Deterministic pipeline only, no LLM: `run init`, `scan all`, `sca sbom`, `sca match`, `merge`, `report`. Produced by `benchmarks/run_benchmark.py`; details in `benchmarks/results/<target>.json`.

- kalkan: a pre-release build of 2026-11-01 (all runs on 2026-11-01)
- Host: Windows-11-10.0.26200-SP0, 20 CPUs
- Tools: actionlint 1.7.12, bandit 1.9.4, checkov 3.3.22, flawfinder 2.0.20, gitleaks 8.30.1, gixy 0.2.55, go 1.26.9, gosec 2.29.0, govulncheck 1.8.0, grype 0.119.0, hadolint 2.15.1, helm 4.3.0, kingfisher 2.11.1, opengrep 1.30.1, osv-scanner 2.6.0, poutine 1.1.6, scorecard 5.5.0, shellcheck 0.11.0, syft 1.54.0, trivy 0.75.0, vacuum 0.33.0, zizmor 1.30.1

## Targets

| Target | Ref | Files | Tech | Status | Pipeline | Scan | SCA | Candidates | SCA records (raw / merged) | From manifest pins | Manifests without lockfile | Long paths |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| juice-shop | v20.3.0 (f189f52) | 1466 | angular, docker, docker-compose, express, github-actions, node, python, solidity, terraform | ok | 19.5 min | 18.8 min | 22.3 s | 1200 | 30 / 15 | 15 | 2 | 1 |
| dvwa | master 068d974 | 252 | docker, docker-compose, github-actions, node, php, python | ok | 62.1 s | 52.8 s | 3.9 s | 361 | 2 / 1 | 0 | 0 | 0 |
| vulnapp | fixture of the pre-release build | 76 | c, django, docker, dotnet, express, flask, github-actions, go, helm, java, kubernetes, node, php, python, rails, ruby, spring, terraform | ok | 104.4 s | 73.8 s | 28.6 s | 476 | 140 / 67 | 0 | 3 | 0 |

## Engines

Cell: candidates in `candidates.json` (SCA matchers: raw records of the tool; SBOM tool: components), status when not `ok`, wall time of the engine.

| Engine | juice-shop | dvwa | vulnapp |
|---|---|---|---|
| actionlint | 13 (1.2 s) | 2 (0.2 s) | 1 (0.2 s) |
| bandit | 0 (0.6 s) | 1 (0.5 s) | 11 (0.5 s) |
| checkov | 143 (112.0 s) | 10 (6.5 s) | 54 (7.0 s) |
| flawfinder | skipped (0.0 s) | skipped (0.0 s) | 3 (0.4 s) |
| gitleaks-history | 184 (5.9 s) | 2 (0.6 s) | skipped (0.0 s) |
| gitleaks | 68 (1.0 s) | 1 (0.4 s) | 2 (0.4 s) |
| gixy | skipped (0.2 s) | skipped (0.0 s) | 2 (0.4 s) |
| gosec | skipped (0.0 s) | skipped (0.0 s) | 19 (27.5 s) |
| hadolint | 16 (0.5 s) | 3 (0.2 s) | 8 (0.1 s) |
| helm-checkov | skipped (0.1 s) | skipped (0.0 s) | 30 (5.5 s) |
| kingfisher-history | 16 (5.6 s) | 0 (3.1 s) | skipped (0.0 s) |
| kingfisher | 15 (3.2 s) | 0 (3.0 s) | 2 (3.0 s) |
| matcher | 385 (8.4 s) | 39 (0.9 s) | 57 (0.8 s) |
| opengrep-packs | 99 (16.0 min) | 33 (31.4 s) | 54 (22.3 s) |
| opengrep | 33 (18.4 s) | 53 (3.4 s) | 109 (3.4 s) |
| poutine | skipped (0.2 s) | skipped (0.0 s) | 1 (0.4 s) |
| scorecard | 4 (0.9 s) | 3 (0.2 s) | 5 (0.1 s) |
| shellcheck | 0 (1.0 s) | skipped (0.1 s) | 3 (0.2 s) |
| trivy | 92 (6.6 s) | 4 (1.2 s) | 38 (0.8 s) |
| vacuum | 18 (0.9 s) | 181 (0.3 s) | 6 (0.3 s) |
| zizmor | 99 (1.3 s) | 28 (0.3 s) | 4 (0.2 s) |
| grype-pins | 15 (1.7 s) | - | 7 (1.8 s) |
| grype | 0 (8.1 s) | 1 (1.8 s) | 59 (1.9 s) |
| osv-scanner-pins | 15 (9.5 s) | - | 7 (9.7 s) |
| osv-scanner | 0 (0.4 s) | 1 (0.5 s) | 59 (13.3 s) |
| retirejs | 0 (0.5 s) | 0 (0.2 s) | 8 (0.3 s) |
| syft | 23 components (1.2 s) | 12 components (0.7 s) | 24 components (0.7 s) |

## SCA records by severity (merged)

| Target | critical | high | medium | low | info |
|---|---|---|---|---|---|
| juice-shop | 2 | 3 | 10 | 0 | 0 |
| dvwa | 0 | 1 | 0 | 0 | 0 |
| vulnapp | 14 | 27 | 25 | 1 | 0 |

## Fixture recall (vulnapp)

160 vulnerable items (3 agent-only, not scored), 154 secure twins. Found by an expected engine: 156 of 157 (99%); by any engine: 157 (100%). Twins with a false positive: 1.

Found: same file, start line within 2 lines, or the result region covers the line (±2 only in brackets). Twin FP: fixture README rule (own rules: any result; other engines: counterpart rule IDs). Any-rule: twins with any result within 2 lines.

| Engine | Status | Expected | Found | Recall | Twin FP | Twin hits (any rule) | Results off planted items |
|---|---|---|---|---|---|---|---|
| actionlint | ok | 1 | 1 (1) | 100% | 0 | 0 | 0 |
| bandit | ok | 7 | 7 (7) | 100% | 0 | 1 | 2 |
| checkov | ok | 9 | 9 (5) | 100% | 0 | 0 | 15 |
| flawfinder | ok | 3 | 3 (3) | 100% | 0 | 0 | 0 |
| gitleaks | ok | 2 | 2 (2) | 100% | 0 | 0 | 0 |
| gixy | ok | 2 | 2 (2) | 100% | 0 | 0 | 0 |
| gosec | ok | 8 | 8 (8) | 100% | 1 | 1 | 7 |
| grype | ok | 10 | 10 (10) | 100% | 0 | 0 | 0 |
| hadolint | ok | 3 | 3 (3) | 100% | 0 | 0 | 0 |
| helm-checkov | ok | 2 | 2 (2) | 100% | 0 | 0 | 0 |
| kingfisher | ok | 2 | 2 (2) | 100% | 0 | 0 | 0 |
| matcher | ok | 7 | 6 (6) | 86% | 0 | 0 | 27 |
| opengrep | ok | 108 | 108 (108) | 100% | 0 | 0 | 0 |
| opengrep-packs | ok | 35 | 35 (35) | 100% | 0 | 0 | 3 |
| osv-scanner | ok | 10 | 10 (10) | 100% | 0 | 0 | 0 |
| poutine | ok | 1 | 1 (1) | 100% | 0 | 0 | 0 |
| retirejs | ok | 1 | 0 (0) | 0% | 0 | 0 | 1 |
| scorecard | ok | 0 | - | - | 0 | 1 | 3 |
| shellcheck | ok | 2 | 2 (2) | 100% | 0 | 0 | 0 |
| trivy | ok | 9 | 9 (8) | 100% | 0 | 0 | 7 |
| vacuum | ok | 5 | 5 (5) | 100% | 0 | 0 | 0 |
| zizmor | ok | 4 | 4 (4) | 100% | 0 | 0 | 0 |

## Problems

- juice-shop: 1 files have an absolute path of 260 or more characters; Opengrep skips them without a warning (`run init` records them)
- juice-shop: 2 dependency manifests without a lockfile (`package.json`, `frontend/package.json`): SCA checked only their 6 exact pins (15 records); version ranges and transitive dependencies are not checked
- juice-shop: opengrep analyzed 31 files only partially (parse errors); skipped: 2 files larger than 1.0 MB; 1 files with an absolute path of 260 or more characters (not reported by Opengrep)
- vulnapp: 3 dependency manifests without a lockfile (`csharp/VulnApp.csproj`, `php/composer.json`, `ruby/Gemfile`): SCA checked only their 6 exact pins (0 records); version ranges and transitive dependencies are not checked
