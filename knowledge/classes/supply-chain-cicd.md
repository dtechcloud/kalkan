---
slug: supply-chain-cicd
title_en: Supply chain / CI-CD
title_tr: Tedarik zinciri / CI-CD
cwe: CWE-829, CWE-494, CWE-1357
owasp: A08:2021
sources: security-audit-skill, deepsec, open-code-review
---

## Summary

Untrusted code or input enters a trusted build, CI job, release or update path. Find workflows that run contributor code with secrets or write tokens, event fields that reach a shell, mutable third-party inputs, and artifacts or updates without an integrity binding. CI configuration is authorization code: who triggers it, whose code runs, and what it can publish.

## What it is

- **Untrusted code in a privileged workflow.** `pull_request_target`, `workflow_run` or `issue_comment` jobs check out and run pull request code with secrets, a write token, an OIDC cloud role or a self-hosted runner.
- **Expression injection.** Attacker-controlled fields (titles, bodies, branch names, commit messages, comments) go into `run:` or `github-script` through `${{ }}`, or into Jenkins Groovy strings. Such data written to `GITHUB_ENV` or `GITHUB_OUTPUT` sets variables for later steps.
- **Mutable build inputs (CWE-494).** Third-party actions pinned to a tag or branch, images without a digest, Terraform modules without a commit ref, `curl | sh` without a checksum, remote CI includes.
- **Dependency source confusion.** A private package name can resolve from a public registry: pip `--extra-index-url` (pip takes the highest version from all indexes), npm scopes without a registry mapping. Also typosquatted names.
- **Cache and artifact poisoning.** A low-trust job writes a cache or artifact that a trusted job later restores, runs or releases.
- **Over-broad automation identity.** `permissions: write-all`, secrets or `id-token: write` together with an untrusted trigger. Broad permissions without an untrusted path are hardening only.
- **Build-context leaks.** No `.dockerignore` or `files` allowlist, so `.env`, `.git` or keys ship in an image or package.
- **Release and update integrity.** Build, test, sign and publish steps refer to mutable names, not one digest. An updater does not check signatures, versions or rollback.

## What it is not

- A known-vulnerable package version → `vulnerable-dependency`.
- A resolved version that a malware database lists (OSV `MAL-`, GitHub malware advisory) → `malicious-dependency`. The source confusion or typosquat that let it in stays here.
- A literal secret in a workflow or a config file → `hardcoded-secrets`.
- Runtime settings of containers, Kubernetes or cloud resources (root user, privileged pods, open ports, IAM wildcards) → `iac-cloud-container`.
- A cloud role trust policy in IaC that accepts tokens from any repository or branch → `iac-cloud-container`. The workflow side (an untrusted trigger with `id-token: write`) stays here.
- Command injection in application code → `os-command-injection`.

## Where to look

For each workflow, note the trigger, the checkout ref, the code that runs, the secrets and token scopes, and what the job can publish. Mark every place where data or files cross from an untrusted job into a trusted one.

### GitHub Actions
- Workflows and composite actions (`.github/actions/*/action.yml`).
- Triggers: `pull_request_target`, `workflow_run`, `issue_comment`, `issues`, `discussion`. Fork `pull_request` runs get no secrets and a read-only token, unless a private-repository setting sends them.
- `actions/checkout` with `ref: ${{ github.event.pull_request.head.sha }}` or `head.ref`, followed by installs, builds, tests or local actions (`uses: ./...`). All of these run the fork's code.
- `${{ }}` in `run:` and `script:` with `github.event.issue.title` or `.body`, `pull_request.title`, `.body`, `.head.ref`, `.head.label`, `comment.body`, `review.body`, `head_commit.message`, `head_commit.author.*`, `github.head_ref`.
- `permissions:`, `secrets: inherit`, `id-token: write`, `persist-credentials` (the default leaves the token in `.git/config`).
- `uses:` refs that are not full 40-character commit SHAs, and `docker://` images with tags.
- `actions/cache` keys, artifacts shared across workflows, `runs-on: self-hosted` in public repositories.

### GitLab CI, Jenkins and other CI
- GitLab: `include: remote` URLs, `include: project` without `ref`, `image: x:latest`, variables such as `CI_MERGE_REQUEST_TITLE` or `CI_COMMIT_MESSAGE` passed to `eval` or unquoted.
- Jenkins: Groovy interpolation in `sh "..."` with `params` or `env.CHANGE_*`, `@Library` without a version.

### Dockerfile (build inputs)
- `FROM image:tag` without `@sha256:` in release images. `ADD https://...` without `--checksum`. `RUN curl ... | sh` without a checksum or signature check.
- Secrets in `ARG` or `ENV` (they stay in the image), `COPY . .` without a `.dockerignore`.

### Package manifests and registries
- `.npmrc` scopes and registries, `pip.conf`, `--extra-index-url`, `--trusted-host`, plain HTTP indexes.
- `"latest"`, `"*"` or git URLs without a commit in `package.json`, git dependencies without `rev` in `Cargo.toml`, `replace` directives in `go.mod`, snapshot versions in Maven and Gradle, `minimum-stability: dev` in Composer.
- Missing lockfiles, `npm install` instead of `npm ci` in CI, project `postinstall` scripts that download code.

### Terraform modules
- `module` sources from git or GitHub without a commit SHA, registry modules without `version`, providers without version constraints.

### Release and update code
- Updaters without a signature check over metadata and payload, a pinned key, or rollback protection. Releases from mutable tags. Signing keys that pull request jobs can reach.

## Safe patterns

- Use `pull_request` for untrusted code. In `pull_request_target` and `workflow_run` jobs, never check out or run pull request code. Treat downloaded artifacts as data.
- Pass event fields through `env:` and quote them in the shell (`"$TITLE"`). In Jenkins, use single-quoted `sh '...'` strings, so that the shell reads the variables.
- Set `permissions: contents: read` (or `{}`) at the top, and grant more per job only when needed. Set `persist-credentials: false`.
- Pin third-party actions to a full commit SHA with a version comment. Let Dependabot or Renovate update the pins.
- Pin release images by digest. Check downloads against a checksum or a signature from a separate trusted source.
- Commit lockfiles. Install with `npm ci`, `pip install --require-hashes` or `--frozen-lockfile`. Map private scopes to the private registry.
- Keep caches of untrusted jobs apart from release jobs. Sign releases, and check signature, version and channel in the updater.

## Weak mitigations

- Gates on `github.actor`, for example `dependabot[bot]`. The actor is whoever triggered the last event, not the author of the code.
- A label gate that does not pin the reviewed commit. The attacker pushes new code after the label.
- Tag pins such as `@v4` for third-party actions, and "verified creator" badges.
- A checksum downloaded from the same host as the file.
- Secret masking in logs. Encoded or split secrets pass the mask.
- Branch protection or fork-approval settings that the repository does not show.
- `npm audit` in CI. It does not find malicious packages.

## Verification checklist

- **attacker_control:** Name the lower-trust actor: fork author, issue commenter, upstream owner of an unpinned action, image or module, public registry publisher. Quote the trigger and the line where their code or data enters (checkout ref, `${{ }}` expression, `uses:` ref, `FROM`, `curl`).
- **privilege_boundary:** Name what the trusted context holds: secrets, token scopes, an OIDC role, publish rights, a self-hosted runner. Quote `permissions:`, `secrets.*` or `id-token: write`. A job with a read-only token and no secrets refutes it, unless its cache or artifact reaches a privileged job.
- **unmitigated:** Quote the missing control: no SHA pin, no `env:` indirection, no approval or environment gate, no checksum.
- Check that the trigger really runs on fork input. A fork `pull_request` run is not privileged.
- Repository and organization settings (default token permissions, fork approvals, environment reviewers, branch protection) are not in the repository. If the claim depends on them, the result is `needs_validation`.
- Severity guide: fork code with secrets or a write token, high or critical. Expression injection in a privileged trigger, high. An unpinned third-party action in a job with secrets, medium. Broad permissions alone, low.

## Examples

### GitHub Actions
```yaml
# Vulnerable: fork code runs with a write token, and the title reaches the shell
on: pull_request_target
permissions: write-all
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm install && npm test
      - run: echo "PR: ${{ github.event.pull_request.title }}"
```

```yaml
# Secure: untrusted trigger, read-only token, pinned action, title through env
on: pull_request
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<full-commit-sha> # v4
        with:
          persist-credentials: false
      - run: npm ci && npm test
      - env:
          TITLE: ${{ github.event.pull_request.title }}
        run: echo "PR: $TITLE"
```

### GitLab CI, Jenkins and other CI
```groovy
// Vulnerable: Groovy puts the branch name into the shell line
sh "git checkout ${env.CHANGE_BRANCH}"

// Secure: single quotes, so the shell reads the variable
sh 'git checkout "$CHANGE_BRANCH"'
```

### Dockerfile (build inputs)
```dockerfile
# Vulnerable: a mutable base and an unchecked installer
FROM node:20
RUN curl -fsSL https://get.example.com/install.sh | sh

# Secure: a digest pin and a checked download
FROM node:20@sha256:<digest-of-the-reviewed-image>
ADD --checksum=sha256:<expected-sha256> https://get.example.com/tool-1.2.3.tar.gz /tmp/tool.tgz
```

## Dynamic test hints

- Do not trigger real workflows, open real pull requests, push tags or publish packages.
- Expression injection: GitHub replaces `${{ }}` with text before the shell runs. Build the `run:` line with a harmless value such as `a"; echo KALKAN_MARKER; "` and run it with `bash` in the sandbox. The marker shows the injection.
- Dependency confusion: read the registry configuration only. Never publish a package to a public registry.

## False positive traps

- A `pull_request_target` job that only labels or comments and never checks out or runs pull request code.
- `${{ }}` values that an attacker cannot set: `github.sha`, `github.run_id`, `github.event.pull_request.number`, static `matrix` values, `workflow_dispatch` inputs (only writers can dispatch).
- Expressions in `with:` inputs instead of a shell. They are safe unless the action itself passes them to a shell.
- First-party `actions/*` pinned to a major tag, when the organization policy accepts it.
- Secrets in a workflow that never runs for fork input.
- A missing `permissions:` block when the default token may be read-only. The default is a repository setting, so the answer is `unknown`, at most hardening.

## Sources

Condensed and rewritten from the local copies under `third_party/`.

- `cloudflare/security-audit-skill@c1c8a8c: skills/security-audit/SUPPLY-CHAIN-AND-RELEASE.md` (MIT, Cloudflare): dependency, CI, cache, release and update classes, validation rules.
- `vercel-labs/deepsec@4fa6722: packages/scanner/src/matchers/github-workflow-security.ts`, `dockerfile-curl-pipe-unverified.ts`, `dockerfile-from-mutable-tag.ts`, `tf-module-unpinned.ts` (Apache-2.0, Vercel): risky triggers, expressions, unpinned refs, unchecked downloads.
- `alibaba/open-code-review@11ac6d4: internal/config/rules/rule_docs/github_workflows.md`, `terraform.md`, `package_json.md`, `cargo_toml.md`, `composer_json.md`, `pom_xml.md`, `build_gradle.md` (Apache-2.0, alibaba/open-code-review contributors): workflow security rules, version pinning, manifest hygiene.
- Dangerous GitHub contexts, `GITHUB_ENV` injection, Jenkins quoting, pip index behavior and `ADD --checksum` come from general knowledge.
