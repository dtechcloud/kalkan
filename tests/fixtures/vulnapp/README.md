# vulnapp: deliberately vulnerable fixture

**Do not deploy this application. Do not run it on a network. Do not copy its code into a real project.**

vulnapp is a small multi-language shop. It contains planted vulnerabilities for the kalkan tests and benchmarks. Every planted vulnerability has a **secure twin**: code of the same shape with a correct mitigation. A finding on a twin is a false positive, so the twins make false positives measurable.

All secrets are fake: the AWS documentation example key pair, two invented passwords (one of them inside a PostgreSQL connection URI to a `.internal` host) and a private key whose body is base64 of the text "this is a fake private key". The fixture contains no real-format live token (`ghp_`, `github_pat_`, `xoxb-`, `sk_live_`). A test checks this.

## Layout

| Folder | Content | Vulnerable items |
|---|---|---|
| `python/` | Flask shop (`shop/` package), `requirements.txt` | 19 code, 3 dependencies, 1 malicious dependency, 1 package index |
| `node/` | Express server (`server.js`, `lib/`), TypeScript module (`src/fetcher.ts`), `package.json`, minimal `package-lock.json` | 18 code, 3 dependencies, 3 lockfile sources |
| `go/` | net/http service (`main.go`), golang-jwt endpoints behind the build tag `jwtauth` (`jwtauth.go`), `go.mod`, `go.sum` | 10 code, 1 dependency |
| `java/` | Servlet and Spring controller, `pom.xml` | 16 code, 1 dependency |
| `php/` | Front controller `public/index.php`, `composer.json` | 16 |
| `ruby/` | Sinatra app `app.rb`, Rails controller, `Gemfile` | 15 |
| `csharp/` | ASP.NET Core controller, `Program.cs`, crypto helpers, vendored JavaScript in `wwwroot/lib/` | 15 code, 1 vendored library |
| `infra/` | `Dockerfile` (bad), `worker.Dockerfile` (twin, base image pinned by digest), Terraform, Kubernetes (`k8s/deployment.yaml`, `k8s/namespace.yaml`), nginx reverse proxy (`nginx/shop.conf`), release shell script (`scripts/release.sh`), Helm chart `helm/shop` (`templates/log-agent.yaml`; twin `templates/web.yaml`; the values come from `values.yaml`) | 19 |
| `api/` | OpenAPI 3 documents: `shop-api.yaml`; twin `partner-api.yaml` | 5 |
| `native/` | C label printer (`labels.c`), a header-only ELF file `bin/labelprint` (twin: the same header in `testdata/`) | 4 |
| `config/` | `settings.ini`, `deploy_key.pem`, `deploy_key.pub.pem` (twin) | 5 |
| `.github/workflows/` | `issue-triage.yml` and `pr-preview.yml`; twins `issue-labels.yml` and `pr-checks.yml` | 4 |
| root | `azure-pipelines.yml` (vulnerable step and twin step) | 1 |

160 vulnerable items and 154 secure twins. The dependency twins are shared: one clean pin per manifest is the twin of all vulnerable pins in that manifest. The malicious dependency has its own clean twin.

## Metadata files

- `EXPECTED.json`: the list of planted items (see below).
- `INJECTION-NOTE.md`: how the phase 5 prompt-injection test adds a hostile `CLAUDE.md` at test time.
- `README.md`: this file.

These three files contain the answers. A benchmark run copies the fixture without them.

## EXPECTED.json

A JSON array. One object per planted item:

| Field | Type | Meaning |
|---|---|---|
| `id` | string | Stable ID, for example `python-sqli-01`. A twin has the suffix `-twin`, a shared dependency twin ends in `-dep-twin`. |
| `kind` | string | `vulnerable` or `secure-twin` |
| `class` | string | kalkan taxonomy slug (ENGINE-SPEC, section 3) |
| `cwe` | list of strings | `CWE-<n>`. The first entry is a default CWE of the class. |
| `language` | string | `python`, `javascript`, `typescript`, `go`, `java`, `php`, `ruby`, `csharp`, `c`, `shell`, `nginx`, `dockerfile`, `terraform`, `kubernetes`, `helm`, `openapi`, `config`, `github-actions` or `azure-pipelines` |
| `file` | string | Path relative to this folder, with forward slashes |
| `line` | integer | 1-based line of the sink (vulnerable) or of the mitigated code (twin) |
| `snippet` | string | Text that occurs on that line. A test checks it. Snippets never repeat a secret value. |
| `twin` | string | Vulnerable items only: the ID of the secure twin |
| `twin_of` | list of strings | Secure twins only: the IDs of the vulnerable items |
| `expected_engines` | list of strings | Vulnerable items: the engines that must report the item. Secure twins: always empty. |
| `rules` | object | Optional: engine name to the rule IDs that report the item |
| `package` | object | Dependency items only: `ecosystem`, `name`, `version` |
| `title` | string | Short English description |

### Engine names

`opengrep` (kalkan rule pack), `opengrep-packs` (the vendored rule packs of `rules/opengrep-packs`), `bandit`, `gosec`, `trivy` (misconfig and secret scanners), `checkov`, `hadolint`, `gitleaks`, `kingfisher`, `shellcheck`, `flawfinder`, `gixy`, `osv-scanner`, `grype`, `retirejs` (the vendored JavaScript check of `sca match` with the RetireJS repository), `zizmor`, `actionlint`, `poutine`, `helm-checkov` (Checkov on the Helm charts that kalkan renders), `vacuum`, and `hunter` for items that only the agent layer can find (IDOR, missing authorization). `matcher` (the kalkan matcher engine) is listed only for the matcher rules of ADR-0005 K.4 and K.12 (see "Kalkan rules of ADR-0005" below); `tests/unit/test_matchers_kalkan_rules.py` checks these items, their twins and that these rules report nothing else. The names `govulncheck` and `scorecard` are also valid. No item lists them yet.

### Match rules

- **Code, IaC and secret items:** an engine reports an item when one of its results is in the same file, and its start line is within 2 lines of `line` or its region covers `line`. Checkov and Trivy report a whole resource for Kubernetes and Terraform, so the region rule matters for them.
- **Dependency items** (`vulnerable-dependency`, `malicious-dependency`): match by `package` (ecosystem, name, version). The line only shows where the pin is, so the twin distance rule does not apply to them.
- **False positives on twins:** for kalkan's own rules, any result on a twin is a false positive (`tests/unit/test_opengrep_rules.py` fails). For the other engines, measure a false positive with the rule IDs of the vulnerable counterpart (`rules` of the item in `twin_of`). Resource-level engines report other checks on the same resource, and these are not twin failures.

### Verification

On 2026-10-16 every `expected_engines` and `rules` entry was checked with the pinned tools (Opengrep 1.30.1, Bandit 1.9.4, gosec 2.29.0, Trivy 0.75.0, Checkov 3.3.22, Hadolint 2.15.1, Gitleaks 8.30.1, OSV-Scanner 2.6.0, Grype 0.119.0) on a copy of this folder. Results:

- Opengrep reports 108 of 108 expected items, no twin, and nothing outside the planted items.
- The twins of the other engines are silent for the counterpart rules, with one known exception: gosec reports G204 and G702 on the Go command twin (`exec.Command("ping", ...)` with a variable argument). Bandit also reports B603 and B607 (low severity) on the Python command twin.
- Gitleaks and Trivy skip AWS keys that end in `EXAMPLE`. Only kalkan's `generic.yaml` rules report the AWS key pair.
- The dependency scanners report all 8 vulnerable pins and none of the twin pins. New advisories can appear later for the clean pins. (The malicious pin came later; see "Dependencies".)
- `infra/worker.Dockerfile` pins its base image by a version tag and a digest: `python:3.12.7-slim@sha256:60d9996b6a8a3689d36db740b49f4327be3be09a21122bd02fb8895abb38b50d`. The digest is the OCI image index of that tag on Docker Hub (looked up on 2026-10-16 with the registry API). A version tag alone is still mutable, and the kalkan matcher `dockerfile-from-mutable-tag` reports it. With the digest, no engine reports the twin line.
- `csharp/wwwroot/lib/` holds two vendored JavaScript files that no manifest lists: the banner of Bootstrap 3.3.7 (vulnerable) and of Bootstrap 5.3.8 (twin). Only the vendored JavaScript check finds them (`retirejs`, then `osv-scanner-pins` and `grype-pins` on `pkg:npm/bootstrap@3.3.7`). Checked on 2026-10-25 with the RetireJS repository of that day: 3.3.7 matches 8 RetireJS vulnerabilities, 5.3.8 none.
- Three dependency manifests have no lockfile: `php/composer.json` and `ruby/Gemfile` use only version ranges, `csharp/VulnApp.csproj` (no `packages.lock.json`) uses only exact versions. `sca match` lists them in `unchecked_manifests` of `sca/vulns.json`. No SCA engine checks the ranges. `sca match` checks the six exact NuGet pins through `sca/manifest-pins.cdx.json`.

On 2026-10-25 the CI/CD items were checked on Windows 11 with zizmor 1.31.1, actionlint 1.7.12, poutine 1.1.6 and OpenSSF Scorecard 5.6.0 (local mode, the checks of the kalkan adapter), and again the same day after the re-pin to zizmor 1.30.1 and Scorecard 5.5.0 (ADR-0005 rule 1) with the same results, except as noted:

- zizmor reports the four GitHub Actions items at their lines (`excessive-permissions` 7, `template-injection` 19, `dangerous-triggers` 4, `unpinned-uses` 23) and nothing on the twins. zizmor 1.30.1 reports `dangerous-triggers` on the whole `on:` block (lines 3 to 5, start line 3). zizmor reports the top-level `write-all` only because `issue-triage.yml` has two jobs; with one job it is a pedantic finding.
- actionlint reports the untrusted `github.event.issue.title` at line 18 (the `run: |` line of the block) and nothing on the twins.
- poutine reports the Azure Pipelines item at line 14 and not the twin step. poutine 1.1.6 cannot read the GitHub workflows on Windows (it matches paths with `/`). A development build that uses `/` paths, as the Linux and macOS builds do, also reported `injection` at `issue-triage.yml:18`, `untrusted_checkout_exec` at `pr-preview.yml:21` (the `make preview` step) and `github_action_from_unverified_creator_used` at line 23 of both pull request workflows (the twin too: the rule does not look at the pin).
- Scorecard reports no workflow on Windows (the same path problem). A development build with `/` paths reported Dangerous-Workflow (`script injection` at `issue-triage.yml:18`, `untrusted code checkout` at `pr-preview.yml:16`) and Token-Permissions (`write-all` at `issue-triage.yml:7`), and nothing on the twins. On every platform it reports the missing security policy, license and dependency update tool on the repository root.
- The items list only the engines that report them on every platform. The kalkan matcher `github-workflow-security` and the Checkov GitHub Actions checks also read the workflow files (not checked on these items); the items do not list them.

On 2026-10-25 the ADR-0005 items were checked with Kingfisher 2.14.0, ShellCheck 0.11.0, flawfinder 2.0.20 and gixy 0.2.58 through the kalkan adapters (`tests/integration/test_adr0005_tools.py`), and again the same day with Kingfisher 2.11.1 and gixy 0.2.55 after the re-pin (ADR-0005 rule 1), with the same results:

- Kingfisher reports the connection URI of `config/settings.ini` (line 24) and the private key (also a Gitleaks and Trivy item), nothing else and not the twin URI without a password. It skips the AWS example keys and the SMTP password. A host name with `example` hides a credential URI from it (placeholder filter of its rules), so the URI points to `analytics.vulnapp.internal`.
- ShellCheck reports SC2115 and SC2086 on `rm -rf $STAGE_DIR/` and SC2029 on the `ssh` command string, nothing on the twins. It has no check for a quoted `eval "$1"`, so that item expects only `hunter`.
- flawfinder reports `strcpy`, `sprintf` and `gets` (levels 4, 4 and 5). The `snprintf` and `fgets` twins and the `char` arrays are below level 3 and are dropped by the adapter.
- gixy reports the `alias` without a trailing slash on the location and the `proxy_pass` to `$arg_host`, nothing on the twins. `server_tokens off` keeps its `version_disclosure` check quiet.

On 2026-10-25 the Helm and OpenAPI items were checked with helm 4.3.0, Checkov 3.3.22, vacuum 0.33.0 and Trivy 0.75.0 through the kalkan adapters (`tests/integration/test_k3_k9_tools.py`):

- `helm-checkov` renders `infra/helm/shop` with its `values.yaml` and reports `CKV_K8S_16` and `CKV_K8S_19` on the `privileged:` and `hostNetwork:` lines of `log-agent.yaml` (`RULE_KEYS` mapping), and neither on `web.yaml`. The other Checkov results cover the whole template document. The main `checkov` adapter reports nothing on the chart: the raw templates are no valid YAML.
- Trivy reports nothing on the chart in local mode: the kalkan adapter leaves its `helm` scanner out, because Trivy fetches the remote `$ref` documents of a `values.schema.json` when it renders a chart (with `--online` it renders `infra/helm/shop` and reports `KSV-0017` and `KSV-0009` on the lines 21-28 and 10-32 of its rendered manifest).
- vacuum (the kalkan OWASP ruleset) reports exactly the five items of `shop-api.yaml` (`owasp-protection-global-unsafe` and its `-strict` variant on the same line) and nothing on `partner-api.yaml`. Checkov reports `CKV_OPENAPI_4` and `CKV_OPENAPI_5` (the whole file) and `CKV_OPENAPI_20` (the security scheme) on `shop-api.yaml`.

On 2026-10-25 the vendored rule packs (ADR-0005 K.8) were checked with Opengrep 1.30.1 through the `opengrep-packs` adapter (`tests/integration/test_opengrep_packs.py`). On 2026-11-06 the opengrep-rules pack (LGPL-2.1 with the Commons Clause) was removed. The bundles of the three remaining packs (GitLab sast-rules, Trail of Bits, 0xdea) did not change, so their results are the same. On 2026-11-07 seven packs with free licenses were added (ADR-0007); the results below are the state after that:

- 34 items list `opengrep-packs` with the rules of the same class; the rule IDs are in `rules.opengrep-packs`. All 34 are also items of another engine (kalkan's own pack, or flawfinder for the three C items).
- The removal took the pack results of 17 items, which only opengrep-rules reported among the packs: Python SQL injection, SSRF, path traversal and JWT; JavaScript open redirect, SSTI and XXE; Go SQL injection and XSS; Java open redirect and XXE; PHP SQL injection and command injection; Ruby weak hash, command injection, deserialization and open redirect. kalkan's own pack (`opengrep`) still reports all 17, and gosec also reports the two Go items. The ADR-0007 packs give 8 of the 17 a pack result again (Python SQL injection, path traversal and JWT, JavaScript open redirect, Go SQL injection, Java open redirect, Ruby weak hash and deserialization), all through the measured subset of semgrep-codeql, and 8 more items get their first pack result (JavaScript CORS, weak hash and command injection; Go command injection, open redirect and weak hash; Java SQL injection; Ruby XXE).
- Nothing on the twins: the build drops the 17 rules that report a twin (kind `twin-fp` in `rules/opengrep-packs/index.json`; 6 of them from the ADR-0007 packs: four njsscan originals of GitLab ports with the same drop, and two Java deserialization rules).
- Three results outside the planted items: `trailofbits.generic.mongodb-insecure-transport` on the `mongodb://localhost` defaults of `node/server.js`, `python/shop/storage.py` and `ruby/app.rb` (no TLS in the connection string).

Notes for the engine adapters:

- Trivy resolves `java/pom.xml` from Maven Central even with `--scanners misconfig,secret`. Run it with `--offline-scan`. Without the flag, a rate limit (HTTP 429) of Maven Central stops the whole scan.
- gosec 2.29.0 writes an empty `artifactLocation` in its SARIF output on Windows. Its JSON output (`-fmt json`) has the file path.
- Opengrep needs `--no-git-ignore` and `--x-ignore-semgrepignore-files` to scan this folder (see `rules/opengrep/README.md`).

## Dependencies

| Manifest | Vulnerable pins | Clean twin pin |
|---|---|---|
| `python/requirements.txt` | Django 3.2.0 (not imported), Flask 0.12, PyYAML 5.3; malicious: sample-module 0.0.1 | MarkupSafe 3.0.2; malicious twin: itsdangerous 2.2.0 |
| `node/package-lock.json` | lodash 4.17.15, minimist 1.2.0, node-serialize 0.0.4 | escape-html 1.0.3 |
| `go/go.mod` | golang.org/x/text v0.3.7 (required, not imported) | github.com/google/uuid v1.6.0 |
| `java/pom.xml` | commons-collections 3.2.1 | java-jwt 4.6.2 |

- The lockfile is minimal: it lists only the packages that the SCA tests need. `package.json` lists all imports of the server. Three of its entries carry the K.12 lockfile items: lodash comes from another registry host (`npm.vulnapp-mirror.net`), minimist over plain `http://`, node-serialize without an `integrity` field; escape-html is the twin. The SCA engines read only the versions, so the dependency items stay the same.
- `python/requirements.txt` starts with `--index-url https://pypi.org/simple/` (twin) and ends with `--extra-index-url http://pypi.vulnapp.internal/simple/` (the K.12 item). Only the matcher reads these options.

## Kalkan rules of ADR-0005 (K.4, K.12)

The items that list `matcher` belong to the kalkan matcher rules `k8s-namespace-no-pod-security`, `dockerfile-from-mutable-tag` (the `@sha256:` digest), `lockfile-unexpected-registry`, `lockfile-insecure-url`, `lockfile-missing-integrity`, `pip-index-insecure` and `committed-binary`. `tests/unit/test_matchers_kalkan_rules.py` runs them on this fixture: each item is found, no twin is touched, nothing else is reported.

- `native/bin/labelprint` and its twin `native/testdata/labelprint.elf` are the same 64-byte ELF header without any code (they cannot run). The rule leaves test data folders out, so only the first one is reported (one file-level result). OpenSSF Scorecard Binary-Artifacts has no such exclusion; `tests/integration/test_cicd_tools.py` accepts both files from it (not checked here: Scorecard was not installed on the development machine on 2026-10-26).
- `go.sum` holds the checksums from sum.golang.org. `go build ./...` works offline, because `main.go` imports only the standard library. Build the JWT endpoints with `-tags jwtauth` (needs github.com/golang-jwt/jwt/v5).
- Django and golang.org/x/text are not imported. They are test data for the reachability step (`not_reachable`).
- `sample-module` 0.0.1 is a package version that the OpenSSF malicious-packages data lists (`MAL-2025-41758`). The fixture only names it: nothing installs, imports or downloads it, and nothing may. On 2026-10-25 OSV-Scanner 2.6.0 reported `MAL-2025-41758` and Grype 0.119.0 reported the GitHub malware advisory `GHSA-2g5x-c76j-3h73` with a link to that record (local databases of 2026-10-16); `sca match` joins them into one `malicious-dependency` record (critical, no reachability step). Neither tool reported `itsdangerous` 2.2.0 or `MarkupSafe` 3.0.2.

## Change the fixture

1. Keep the sink of a vulnerable item and the mitigated line of its twin at least 3 lines apart.
2. Do not add comments that name a vulnerability. The agent layer reads this code during benchmarks.
3. After an edit, update `line` (and `snippet`) in `EXPECTED.json`. `tests/unit/test_fixture_expected.py` checks every line.
4. Python files follow the repository `ruff` settings (`ruff check`, `ruff format`).
5. Run `pytest tests/unit/test_fixture_expected.py tests/unit/test_opengrep_rules.py`.
