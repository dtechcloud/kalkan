# Third-party components

## Vendored upstream content

kalkan keeps verbatim copies of selected upstream files under `third_party/`. `third_party/MANIFEST.json` pins the commits and lists the copy rules. Each component folder has `UPSTREAM.md` (provenance) and `FILES.sha256` (content hashes). Run `python scripts/vendor_third_party.py --check` to verify the copies.

| Component | Upstream | Pinned commit | License | kalkan uses it for |
|---|---|---|---|---|
| security-audit-skill | https://github.com/cloudflare/security-audit-skill | `c1c8a8c` | MIT | Phase model, coverage ledger, finding schema, validators, domain packs |
| sast-skills | https://github.com/utkusen/sast-skills | `db52227` | MIT | Vulnerability class knowledge, batching pattern, report structure |
| codecrucible | https://github.com/block/codecrucible | `b5c8086` | Apache-2.0 | Quote verifier, verdict policy, finding identity, CWE families, language packs |
| deepsec | https://github.com/vercel-labs/deepsec | `4fa6722` | Apache-2.0 (+ NOTICE) | Regex matchers, regex safety checks, hunter hints, revalidation idea |
| open-code-review | https://github.com/alibaba/open-code-review | `11ac6d4` | Apache-2.0 | Security sections of the language rule documents, conservative review filter |
| gitlab-sast-rules | https://gitlab.com/gitlab-org/security-products/sast-rules | `53bf5cf` (v2.10.1, 2026-09-21) | MIT (243 files) and LGPL-3.0-only (152 files of `rules/lgpl`), by the license header of each file | Opengrep rule pack (C#, Java, JavaScript, Python, Scala, Kotlin, Swift) |
| 0xdea-semgrep-rules | https://github.com/0xdea/semgrep-rules | `dae50da` (2026-09-25) | MIT | Opengrep rule pack (C and C++) |
| trailofbits-semgrep-rules | https://github.com/trailofbits/semgrep-rules | `31390b3` (2025-11-12) | AGPL-3.0-only | Opengrep rule pack (Go, Python, Ruby, JavaScript, HCL, Ansible, generic) |
| atlassian-sast-ruleset | https://github.com/atlassian-labs/atlassian-sast-ruleset | `800d288` (2026-09-25) | LGPL-2.1-only | Opengrep rule pack (Java: FreeMarker, Jackson, Java I/O, JMX, JNDI, Soy, Spring, XStream; ADR-0007) |
| elttam-semgrep-rules | https://github.com/elttam/semgrep-rules | `2442685` (2026-08-03) | MIT | Opengrep rule pack (Java, Go, C#, JavaScript, Python, PHP; ADR-0007) |
| njsscan-rules | https://github.com/ajinabraham/njsscan | `b1a0797` (2026-10-23) | LGPL-3.0-or-later | Opengrep rule pack (Node.js, Electron; ADR-0007) |
| mobsfscan-rules | https://github.com/MobSF/mobsfscan | `175978c` (2026-10-23) | LGPL-3.0-or-later | Opengrep rule pack (Android Java and Kotlin, iOS Swift; ADR-0007) |
| mindedsecurity-android-rules | https://github.com/mindedsecurity/semgrep-rules-android-security | `8133aa8` (2026-06-05) | GPL-3.0-only | Opengrep rule pack (Android, by OWASP MASTG test; ADR-0007) |
| aikido-opengrep-rules | https://github.com/AikidoSec/opengrep-rules | `7ac79af` (2026-06-04) | MIT | Opengrep rule pack (GitHub Actions, npm publishing; ADR-0007) |
| semgrep-codeql-rules | https://github.com/andrew/semgrep-codeql | `84a03f3` (2025-12-21) | MIT (converted from github/codeql, MIT) | Opengrep rule pack, a measured subset (Python, JavaScript, Go, Java, Ruby, C#; ADR-0007) |

The rule packs (ADR-0005 K.8 and its license policy of 2026-10-25; ADR-0007 for the packs of 2026-11-07):

- The copies hold only rule files, no test sources. GitLab: only the files with the header `MIT (c) GitLab Inc.` or `GNU Lesser General Public License v3.0`; not copied are `rules/lgpl-cc` (Commons Clause), `rules/gitlab` (GitLab Enterprise Edition license), `c` (GPL-2.0) and `go` (Apache-2.0). ADR-0005 names the GitLab license "LGPL-2.1"; the files say LGPL-3.0.
- License texts: each folder keeps the upstream license files. The LGPL-3.0 adds permissions to the GPL-3.0 (https://www.gnu.org/licenses/gpl-3.0.txt); the upstream repository does not ship that text.
- AGPL-3.0 (Trail of Bits): the rule files stay unmodified in `third_party/` with the license, and the changed bundles in `rules/opengrep-packs/trailofbits/` stay under AGPL-3.0 with their source in this repository. AGPL-3.0 allows commercial use. kalkan is not offered as a network service.
- `KALKAN_RULE_PACKS=osi` turns the AGPL pack off (docs/ENGINE-SPEC.md, section 13).
- Removed on 2026-11-06: the opengrep-rules pack (`f1d2b56`, LGPL-2.1 with the Commons Clause License Condition v1.0). The Commons Clause forbids selling a product or service whose value derives from the rules, consulting and support services included, and the license is not OSI-approved. `KALKAN_RULE_PACKS` ignores the old pack name.
- Added on 2026-11-07 (ADR-0007), to replace the removed pack with free licenses: atlassian, elttam, njsscan, mobsfscan, mindedsecurity, aikido and semgrep-codeql. Each LICENSE was read again at the pinned commit; none carries the Commons Clause. The copyleft packs (LGPL-2.1, LGPL-3.0, GPL-3.0) stay in their own folders with their license texts, and their changed bundles in `rules/opengrep-packs/<pack>/` keep the license of the pack. LGPL and GPL allow commercial use, paid consulting included. All seven are in the license group `osi`.
- Left out of njsscan and mobsfscan: the 14 rule files whose header names Semgrep's semgrep-rules repository (no license before 2020-10-29, the Commons Clause after) or the GPL-3.0 mindedsecurity rules as their source (`third_party/MANIFEST.json`, the `exclude` lists).
- semgrep-codeql is an LLM conversion of the CodeQL queries of https://github.com/github/codeql (MIT, Copyright (c) 2006-2025 GitHub, Inc.; the root NOTICE repeats it) without upstream tests. kalkan keeps only the 28 rules that it measured on `tests/fixtures/vulnapp` (`keep_only` in `curation.json`, drop kind `unmeasured`).
- Not taken (2026-11-07 survey): patched-codes/semgrep-rules (GitLab content relabeled as MIT), Decurity/semgrep-smart-contracts (CC BY-NC-SA 4.0, non-commercial), amplify-security/opengrep-rules (Commons Clause), repositories without a license file, and the Semgrep Registry copies in brave/security-action.

Rules for ported code:

- A ported file keeps the upstream license in its SPDX header and names its source: `Ported from <repo>@<commit>: <path>`.
- A ported Apache-2.0 file states that it was changed (Apache-2.0 section 4(b)).
- The root `NOTICE` file repeats the upstream NOTICE texts (Apache-2.0 section 4(d)).
- kalkan does not use the trademarks of the upstream projects.

## Derived content in this repository

| Path | Derived from | License | How |
|---|---|---|---|
| `rules/matchers/*.json` (198 of the 204 specs; the 6 kalkan rules with `source: null` are MIT) | deepsec `packages/scanner/src/matchers/*.ts` | Apache-2.0 (Vercel, Inc.; see NOTICE) | Generated by `scripts/port_deepsec_matchers.py` (reads the vendored copy as text); each spec names its source file and commit; approximations are explained in its `notes` |
| `src/kalkan/matchers/` | deepsec `declarative-matcher.ts`, `utils.ts` | Apache-2.0 | Ported to Python; files keep the Apache-2.0 header |
| `src/kalkan/findings/fingerprint.py`, `quote_verify.py` | codecrucible `identity.go`, `scan_audit_v2.go` | Apache-2.0 (Block, Inc.) | Ported to Python |
| `src/kalkan/findings/validate.py`, `ledger.py`, `src/kalkan/util/safe_io.py` | security-audit-skill `validate-findings.cjs`, `validate-coverage-ledger.cjs` | MIT (Cloudflare, Inc.) | Ported to Python |
| `src/kalkan/sca/retirejs.py` | retire.js `node/lib/retire.js` (release 6.1.0) | Apache-2.0 (Erlend Oftedal; see NOTICE) | The matching functions ported to Python; the file keeps the Apache-2.0 header |
| `knowledge/**/*.md` | all five upstream projects | MIT and Apache-2.0 | Condensed and rewritten; each file lists its sources |
| `rules/opengrep-packs/<pack>/**/rules.yaml` (55 bundles, 733 rules) | the ten rule packs above | the license of each pack: MIT and LGPL-3.0-only, AGPL-3.0-only, MIT, LGPL-2.1-only, LGPL-3.0-or-later, GPL-3.0-only | Generated by `scripts/build_opengrep_packs.py`: the kept rules of the files of one pack folder joined into one file and re-indented, the rule text unchanged; each bundle names the pack, the license, the change (2026-10-25) and its source files. The unmodified files stay in `third_party/`. |
| `rules/opengrep-packs/index.json`, `curation.json` | the ten rule packs above | MIT (kalkan) | The kept rules with class and license, the dropped rules with their reason, the curation |

## External tools (installed at setup time, not part of this repository)

The bootstrap scripts download these tools in pinned versions and verify them. kalkan runs each tool as a separate process.

| Tool | Version | License | Note |
|---|---|---|---|
| Trivy | v0.75.0 | Apache-2.0 | Telemetry off. Versions 0.69.4 to 0.69.6 are blocked (CVE-2026-33634). |
| Checkov | 3.3.22 | Apache-2.0 | Installed with pip into the tool venv |
| Hadolint | v2.15.1 | GPL-3.0 | Unmodified binary, run as a subprocess only |
| Gitleaks | v8.30.1 | MIT | CLI only (the GitHub Action has a separate EULA) |
| Opengrep | 1.30.1 | LGPL-2.1 | Used with kalkan's own rule pack and the vendored rule packs (`rules/opengrep-packs`) |
| Bandit | 1.9.4 | Apache-2.0 | `bandit[sarif]` |
| Go toolchain | 1.26.9 | BSD-3-Clause | Official archive from https://go.dev/dl/, extracted unmodified into `.tools/go/1.26.9/go`. The archive SHA-256 comes from go.dev. kalkan also checks the SHA-256 of the extracted tree. Runs gosec and govulncheck and builds govulncheck and poutine. |
| gosec | v2.29.0 | Apache-2.0 | Runs with the Go toolchain above. |
| OSV-Scanner | v2.6.0 | Apache-2.0 | Queries osv.dev unless the offline database is used |
| Syft | v1.54.0 | Apache-2.0 | SBOM (CycloneDX) |
| Grype | v0.119.0 | Apache-2.0 | Downloads its vulnerability database |
| govulncheck | v1.8.0 | BSD-3-Clause | Built from source with `go install` and the Go toolchain above. The Go checksum database verifies the module. |
| zizmor | 1.30.1 | MIT | The PyPI wheels (SHA-256 from PyPI); kalkan extracts only the executable. Runs with `--offline`. |
| actionlint | v1.7.12 | MIT | Runs without shellcheck and pyflakes of the system. |
| poutine | v1.1.6 | Apache-2.0 | Built from source with `go install` and the Go toolchain above (no Windows release binary). Runs with `--disable-version-check`. |
| OpenSSF Scorecard | v5.5.0 | Apache-2.0 | `--local` mode with the checks that need no network. |
| Kingfisher | v2.11.1 | Apache-2.0 | Second secrets engine (working tree and git history). Validation and update check off; values redacted. kalkan extracts only the executable; the NOTICE and third-party notices stay in the `notices/` folder of the release archive. |
| ShellCheck | v0.11.0 | GPL-3.0 | Unmodified binary, run as a subprocess only. Windows on Arm uses the x86_64 build. |
| flawfinder | 2.0.20 | GPL-2.0-or-later | Installed with pip into the tool venv, run unmodified as a subprocess only |
| gixy (`gixy-ng`) | 0.2.55 | MPL-2.0 | Installed with pip into the tool venv without the `deep` extra; kalkan imports its Python API from a launcher in that venv and changes no gixy file. Dependencies: ngxparse (Apache-2.0), Jinja2 and MarkupSafe (BSD-3-Clause), ConfigArgParse (MIT). The release binaries are not used: they bundle redoctor (Business Source License 1.1, not OSI-approved). |
| helm | v4.3.0 | Apache-2.0 | Official binary from get.helm.sh (SHA-256 from the `.sha256sum` file of each asset; the PGP signatures were checked at pin time). kalkan runs only `helm template`: offline, without dependency commands. |
| vacuum | v0.33.0 | MIT | Runs `spectral-report` with `--remote=false`, `--no-update-check` and a kalkan ruleset (the built-in OWASP rules of vacuum). |

Docker image (`WITH_GO=true`, the default): the same Go toolchain 1.26.9 (BSD-3-Clause) in `/opt/go`, checked by the same SHA-256 values, for gosec, govulncheck and poutine. Hadolint, ShellCheck and flawfinder have their own GPL layer (`WITH_GPL`; `WITH_HADOLINT=false` also leaves them out).

## Data downloaded at setup time (not part of this repository)

| Data | Source | License | Note |
|---|---|---|---|
| RetireJS library repository | `repository/jsrepository-v5.json` of https://github.com/RetireJS/retire.js (branch `master`, the file of the retire 6.1.0 command line) | Apache-2.0 | `kalkan sca update-db` stores it in `.tools/vulndb/retire/` with its SHA-256. kalkan reads it as data for the vendored JavaScript check; no RetireJS code runs. `tests/fixtures/sca/retire/jsrepository-v5.json` is a small hand-written file in the same format. |

Not used: Semgrep registry rules (license forbids redistribution), CodeQL (proprietary terms), TruffleHog (Kingfisher and Gitleaks cover the same area), the GitLab rules under the GitLab Enterprise Edition license (`rules/gitlab`), the opengrep-rules pack and the GitLab `rules/lgpl-cc` (Commons Clause).
