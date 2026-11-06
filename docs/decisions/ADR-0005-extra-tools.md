# ADR-0005: Extra scanners and rules
English | [Türkçe](ADR-0005-extra-tools.tr.md)

- Status: accepted (proposed 2026-10-19, accepted 2026-10-25)
- Replaces: ADR-0001, the "Extra scanners" row

## Context

ADR-0001 limited the extra scanners to Trivy, Checkov, Hadolint, Gitleaks, Opengrep, Bandit and gosec. The same row left out zizmor, TruffleHog, Semgrep rules and CodeQL. The reason for Semgrep rules and CodeQL was the license. No reason was written for zizmor. For TruffleHog, an AGPL policy was requested first.

A tool survey on 2026-10-19 and the first test audits showed these gaps:

- Weak coverage in GitHub Actions and other CI files. Checkov does only 8 checks for GitHub Actions.
- Checkov does not scan Helm charts, because kalkan does not install the `helm` binary.
- Copied JS libraries are not visible to SCA.
- Known malicious packages (`MAL-`) in the local OSV database are handled as ordinary CVEs.
- The version query does not use the same network restriction as the scans.
- Secret scanning has only one engine. There is no tool for shell scripts, C/C++ and repository security posture. No SBOM is delivered.

On 2026-10-25, the project owner asked for the widest possible coverage of the security ecosystem: one person must audit their software end to end with 1-2 commands. The owner gave permission to research and integrate tools without a wait for approval. This ADR was accepted on that date.

## Decision

### Rules for each new tool

1. The pin day is at least 14 days after the release date.
2. The SHA-256 comes from the upstream checksum file. If there is no such file, it comes from the GitHub asset digest and is compared with the downloaded file.
3. The configuration and ignore files of the target do not load. By default, the tools ignore the suppression comments in the target (ADR-0003). A source that cannot be turned off goes into the status file.
4. Every network feature is turned off: validation, update check, telemetry. The table of promise 3 in `docs/SECURITY.md` gets a row. The proxy trap test covers the tool and requires zero connections.
5. The tool does not change, run or compile the target code.
6. Windows, Linux and macOS are supported. If there is no binary for a platform, the tool installs from source with the managed Go (`go-install`) or with pip.
7. The license rule is in the "License policy" section below. GPL and AGPL tools run unmodified as separate processes (as Hadolint does).
8. Before a tool enters, we compare it with the current tools on a corpus (at least the `vulnapp` fixture of kalkan and its safe twins).

### Added in 1.5.0 (2026-10-25 and 2026-10-26)

| Area | Tool or data | License | Installation | Plan |
|---|---|---|---|---|
| GitHub Actions security | zizmor | MIT | only the executable from the PyPI wheel | K.5 |
| Workflow audit | actionlint | MIT | binary | new |
| Multi-CI supply chain (GitHub Actions, GitLab CI, Azure Pipelines, Tekton) | poutine | Apache-2.0 | `go-install` | K.10 |
| Repository security posture | OpenSSF Scorecard (`--local`) | Apache-2.0 | binary | new |
| Secrets, second engine (git history included) | Kingfisher | Apache-2.0 | binary | new (meets the goal of K.6) |
| Shell scripts | ShellCheck | GPL-3.0 | binary, separate process | new |
| C/C++ | flawfinder | GPL-2.0 | pip, separate process | new |
| nginx configuration | gixy-ng | MPL-2.0 | pip | K.11 |
| Copied JavaScript libraries | retire.js `jsrepository-v5.json` (data) | Apache-2.0 | `kalkan sca update-db` | K.7 |
| SBOM delivery | Syft output + pins + copied libraries (CycloneDX 1.6, SPDX 2.3) | — | existing | new |
| One command | `kalkan audit`, `kalkan-audit`, `scripts/install.*` | — | — | new |
| Helm charts | helm (only `helm template`, no dependency update) + Checkov (`helm-checkov`) | Apache-2.0 | binary | K.3 |
| OpenAPI security | vacuum (OWASP rule set, `--remote=false`) | MIT | binary | K.9 |
| Extra Opengrep rule packs (`opengrep-packs`) | GitLab sast-rules (MIT and LGPL-3.0), 0xdea (MIT), Trail of Bits (AGPL-3.0), opengrep-rules (LGPL-2.1 + Commons Clause); 966 rules | the license of each pack | `third_party/` + `rules/opengrep-packs/` | K.8 |
| Malicious packages | OSV `MAL-` and Grype malicious code records → the `malicious-dependency` class, critical | — | existing databases | K.2 |
| New matcher rules | Namespace without a PSA label, `FROM` without a digest, lockfile registry address and `integrity`, http package index, committed binary files | — | `rules/matchers/` | K.4, K.12 |
| Safe version queries | `probe_env`: minimal environment, empty working folder, update check off | — | — | K.1 |

### Planned

- K.6 Betterleaks: Kingfisher was added. Betterleaks enters only if a measurement shows a meaningful difference from Gitleaks and Kingfisher.
  - Measurement on 2026-10-29: no meaningful difference, Betterleaks was not added.
- Slither (Solidity) and DevSkim rules: the next wave.

### Left out

| Tool | Reason |
|---|---|
| CodeQL | Proprietary license. Closed-source code needs a paid license. |
| Semgrep rule repository | The Semgrep Rules License v1.0 forbids distribution (the ADR-0001 decision applies). |
| TruffleHog | AGPL is no longer a blocker, but Kingfisher and Gitleaks cover the same area. A third secrets engine adds noise. |
| KICS | The 2.x versions publish no binaries (only Docker). Checkov covers most of the same IaC frameworks. On request, it can install from source only for Docker Compose. |
| Kubescape | The measurement showed a small difference and a network leak (measured before this decision). |
| Slither | It needs a solc compiler for each contract (AGPL is no longer a blocker). The next wave. |
| DevSkim | It needs the .NET runtime. Its rules can move to matchers later. |
| DAST tools (ZAP, Nuclei) | They need a running application. kalkan does not run the target (ADR-0004). |
| Container image scanning | An image pull uses the network and tells the registry service which images are in use. |
| License compliance | The ADR-0001 decision applies. In a source repository, the dependency licenses are mostly unknown offline. |

## License policy (decision 2026-10-25)

On 2026-10-25, the project owner said that kalkan will make no money and allowed every component that obeys its license. With this decision, the open question of 19 October (K.13) closed.

1. OSI-approved licenses (MIT, Apache-2.0, BSD, MPL, LGPL, GPL) are allowed.
2. AGPL-3.0 is allowed. The tools run unmodified as separate processes. The rule files stay unmodified under `third_party/`, with the license text and the source commit. kalkan is not offered as a network service. Thus, the network clause of the AGPL creates no obligation.
3. Licenses that forbid only sale (Commons Clause) are allowed in non-commercial use. These components stay in a separate folder, and a switch can turn them off.
4. Licenses that forbid sharing the rules with others or offering them as a service (Semgrep Rules License v1.0) and proprietary licenses (CodeQL) stay out.
5. If kalkan is shared or used commercially later, the components of items 2 and 3 get a new review. `THIRD_PARTY.md` shows the license of each component. Update (2026-11-06): kalkan is now public. Item 3 no longer applies, because the only Commons Clause pack was removed (see the note at the end).

Added with this policy: Trail of Bits semgrep-rules (AGPL-3.0) and opengrep-rules (LGPL-2.1 + Commons Clause). They pass the same quality filter as the K.8 rule packs.

## Consequences

- The tool count in doctor increases. The first setup takes longer, and the disk use increases.
- The deterministic phase takes longer. Each tool runs with its own time limit and is skipped when the target has no related file.
- Tool results enter the report as "unverified tool results". The agents use these results as hints. The verification budget goes to the results with the highest severity.
- `kalkan tools install --all`, bootstrap, the plugin setup, `kalkan doctor` and the Docker image read the tools from the manifest.
- ADR-0001 does not change. For the extra scanners, ADR-0005 replaces it.

## Implementation notes (2026-10-25)

The decision stayed the same. These details became clear during the integration:

- **gixy:** installed with pip (`gixy-ng==0.2.55`, MPL-2.0). The release binaries include redoctor with the Business Source License 1.1. This license is not OSI-approved.
- **zizmor:** kalkan extracts only the executable from the PyPI wheel files. Windows on Arm runs the x64 build with emulation.
- **poutine:** installs with `go-install` on every platform. The version check (`--disable-version-check`) is off. Upstream bug: on Windows, it does not read GitHub workflows (the path matching uses `/`). The report writes this gap as `platform_gap`.
- **OpenSSF Scorecard:** in local mode, only the six checks that use no network run (Binary-Artifacts, Dangerous-Workflow, Dependency-Update-Tool, License, Security-Policy, Token-Permissions). Pinned-Dependencies is out, because it connects to Docker Hub. On Windows, the workflow checks give no result because of the same path bug.
- **Kingfisher:** validation and the update check are off, and the values are redacted. If the adapter sees a value that is not redacted, it stops the run.
- **ShellCheck:** the inline `# shellcheck disable=` directives cannot be turned off in 0.11.0. The status file records this.
- **Checkov:** the `helm` and `kustomize` frameworks are off, because they open a network connection. Checkov runs with an empty home folder, so it cannot read a platform key file.
- **Docker:** the tool lists come from the manifest (`docker/manifest_tools.py`). The GPL tools (Hadolint, ShellCheck, flawfinder) are in the `WITH_GPL` layer.
- **Rule 1 (14 days):** on 2026-10-25, four tools broke this rule: zizmor 1.31.1 (release 2026-10-15), Kingfisher 2.14.0 (2026-10-20), OpenSSF Scorecard 5.6.0 (2026-10-12) and gixy-ng 0.2.58 (2026-10-25). Each one moved to the newest stable version released on or before 2026-10-11: zizmor 1.30.1, Kingfisher 2.11.1, Scorecard 5.5.0, gixy-ng 0.2.55. Every manifest entry now carries the `released_at` and `pinned_at` fields. A unit test fails when the pin day is not 14 days after the release day. Go 1.26.9 (release 2026-10-08) was pinned on 2026-10-16. On 2026-10-25, six archives were downloaded again, and all values matched. `pinned_at` shows this day.
- **gixy 0.2.55:** its Python API has no `load_default_vars` option. This version already does not read the variable folders of the machine. The launcher gives the option only when `Config` knows it.
- **Version queries (K.1):** `kalkan doctor` and `resolve` run the version command of each tool with the same minimal environment as the scanners and in an empty working folder. The manifest carries the flags (`version_args`) and the variables (`version_env`) that turn off the update check. Before the change, `checkov --version` connected to pypi.org and `govulncheck -version` connected to vuln.go.dev. After it, the proxy trap saw zero connections.
- **Trivy:** 0.75.0 downloads remote `$ref` files in `values.schema.json` when it processes Helm charts, and it has no option that turns this off. In local mode, the Trivy `helm` misconfig scanner is off. `helm-checkov` scans the charts.
- **vacuum:** 0.33.0 reads local `$ref` files outside the target also with `--remote=false` (on Windows, a UNC path can open an SMB connection). kalkan checks each reference first and does not scan a document that goes outside the target.
- **helm:** 4.3.0 runs with `--skip-schema-validation`. Without this flag, it downloads a remote schema. A chart with a missing dependency becomes a scan gap.
- **GitLab sast-rules:** the files have the LGPL-3.0-only license (together with MIT files), not LGPL-2.1. `rules/lgpl-cc` (Commons Clause), `rules/gitlab` (proprietary) and the flawfinder and gosec ports were not copied.
- **Rule packs:** the copies under `third_party/` did not change. The `rules/opengrep-packs/` files for the runs are re-indented combinations of these rules. The header of each file and `NOTICE` state this change. `KALKAN_RULE_PACKS=osi` turns off the AGPL and Commons Clause packs.
- **14-day rule:** zizmor 1.30.1, Kingfisher 2.11.1, Scorecard 5.5.0 and gixy-ng 0.2.55 were the versions after the downgrade. Every tool entry carries `released_at` and `pinned_at`. A unit test checks the rule in every entry.

## Update (2026-11-06)

The opengrep-rules pack was removed, because its Commons Clause forbids paid consulting and support services. kalkan looks for permissively licensed replacement rules.
