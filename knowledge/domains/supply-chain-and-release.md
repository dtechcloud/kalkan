---
name: supply-chain-and-release
title: Supply chain, CI, and release
classes: supply-chain-cicd, vulnerable-dependency
when_to_use: The target resolves dependencies, builds untrusted contributions, runs CI, creates, signs, or promotes release artifacts, loads plugins, or ships updates.
sources: third_party/security-audit-skill/skills/security-audit/SUPPLY-CHAIN-AND-RELEASE.md, third_party/open-code-review/rules/rule_docs/github_workflows.md
---

# Supply chain, CI, and release

This pack covers the trust hand-offs from source and dependencies to the artifact that a user runs. Split a large target into dependency resolution, CI isolation, artifact provenance, release authorization, and updater or plugin trust. Related packs: `memory-safety-and-binary` (flaws inside a local loader) and `cloud-and-deployment` (runtime workload authority).

## Core discipline

- A mutable or known-vulnerable dependency is not a finding by itself. Show who can influence resolution, which build uses it, and which execution or release boundary follows. For a known CVE, show that the vulnerable code is reachable or report the reachability as unknown.
- Follow integrity across every hand-off: source identity, resolved inputs, build worker, artifact identity, test result, signature or attestation, promotion, and the update consumer.
- CI configuration is authorization code. Establish which event triggers a workflow, whose code runs, which secrets and tokens exist, and what the job may publish or change.
- A checksum fetched from the same untrusted place as the artifact does not prove independent integrity. Name the trusted root and the failure behavior.
- Use `needs_validation` for branch protection, hosted-runner, registry, signing-service, and production-promotion facts that the repository does not show.

## Attack classes

### Dependency source and namespace confusion

- **Check:** resolver configuration that can select an unintended public or private namespace, fallback registry, mirror, repository, or source URL. Review package names, source priority, lockfile and checksum use, alternate build files, platform-specific resolution, and first install versus update.
- **Not a finding:** a scoped private namespace with a single pinned registry.

### Mutable and unbound build inputs

- **Check:** builds that use branches, tags, unverified submodules, downloaded tools (`curl | sh`), generated assets, remote includes, floating CI actions (`uses: org/action@main`), or container tags whose content can change without review. Name a lower-trust writer and a path into trusted build output.
- **Not a finding:** reproducibility gaps alone. A mutable reference that only the owner can move is a hardening note.

### Generated-source and codegen provenance gaps

- **Check:** schemas, vendored archives, generated clients, localization files, documentation examples, or binary blobs that produce shipped or executable content without the review and integrity gate that source gets. Compare local regeneration with the committed output and find who controls the input and the generator.
- **Not a finding:** generated code that the build regenerates from reviewed inputs.

### Build-context inclusion

- **Check:** secrets, local configuration, repository metadata, test fixtures, or developer artifacts that enter a package or image because the build context and ignore rules are wider than the intended release inputs.
- **Not a finding:** included files that hold no real credential, private data, or privileged configuration.

### Untrusted code in a privileged workflow

- **Check:** pull requests, issue comments, forks, dependency updates, or external events that run contributor-controlled code with protected secrets, write tokens, deployment authority, or a trusted runner. Classic shape: `pull_request_target` or `workflow_run` that checks out and builds the head commit. Compare the trigger type, checkout ref, approval gate, environment protection, and `permissions:` block.
- **Not a finding:** a `pull_request` workflow from forks with read-only tokens and no secrets. Do not assume host defaults that the repository does not show.

### Workflow command and expression injection

- **Check:** attacker-controlled branch names, commit messages, issue and pull-request titles or bodies, artifact names, matrix values, or step outputs that reach shell commands, `${{ }}` expressions inside `run:` blocks, paths, or privileged workflow inputs without canonical validation.
- **Not a finding:** values passed through an environment variable and quoted in the shell.

### Cache, artifact, and workspace trust mixing

- **Check:** a lower-trust job that can fill a cache, artifact, shared workspace, or output that a higher-trust job later restores and runs or releases. Review cache keys and scopes, artifact producer identity, digest binding, retention, and whether promotion resolves a mutable name again.
- **Not a finding:** caches scoped to the protected branch, or artifacts checked by digest.

### Automation identity overreach

- **Check:** CI jobs with permissions beyond the operation, repository, environment, or duration they need, where untrusted job input can select the affected resource.
- **Not a finding:** missing least privilege alone. Name a reachable privileged action.

### Build-to-promotion substitution

- **Check:** tests, review, signatures, and publication that refer to mutable tags, file names, channels, or artifact IDs instead of one immutable digest. Check every copy, repack, architecture merge, and provenance step between build and release.
- **Not a finding:** a pipeline that carries one digest from build to publication.

### Release authorization and signing-policy gaps

- **Check:** releases or signatures accepted from the wrong workflow, repository, branch, environment, key role, or threshold. Check the identity claims inside attestations and that the consumer validates them, not only that a signature is valid. Rotation, expiry, and revocation must fail closed where policy requires it.
- **Not a finding:** a verifier that pins the signer identity and the issuer.

### Update metadata and rollback confusion

- **Check:** an updater that authenticates payload bytes but not the version, product, platform, channel, target path, expiry, or rollback state, or that accepts metadata and payload from different authorized releases. Check atomic installation and recovery.
- **Not a finding:** an update framework that binds metadata to the payload and rejects rollbacks.

### Plugin and extension trust expansion

- **Check:** an extension package that gains host authority beyond its declared scope, a lower-trust publisher that can replace another publisher's identity, or install and update hooks that run before authenticity and capability checks.
- **Not a finding:** a user who installs an arbitrary plugin into the user's own environment by design.

### Vulnerable dependency reachability

- **Check:** for a dependency with a known advisory (CVE, GHSA, OSV), whether the target imports the affected package, calls the vulnerable function or feature, and passes attacker-influenced input to it. Check the resolved version in the lockfile, not only the manifest range.
- **Not a finding:** an advisory for a feature that the target never imports or configures. Report it as `not_reachable` with quotes, not as a separate vulnerability.

## Universal moves

- Walk back from a released digest or installed update to every source, generated input, credential, worker, cache, test result, and authorization decision.
- Compare untrusted and protected workflow events side by side. Mark each persisted channel between them and require an immutable identity plus producer trust.
- Review revoked keys, failed downloads, missing attestations, partial platform releases, rollbacks, and registry outages. The failure policy is part of release integrity.

## Validation rules

1. Name the lower-trust actor, the controllable source, cache, artifact, or metadata, the trusted job or updater that consumes it, and the unauthorized publication, code inclusion, secret disclosure, or privileged execution.
2. Prove artifact identity across the broken hand-off. A different mutable name or an unbound digest must reach a real consumer.
3. Check the package-manager, repository-host, registry, and signing defaults for the pinned version. Unknown hosted controls require `needs_validation`.
4. A local check uses a harmless fixture repository, a dummy credential marker, and a local registry or configuration. Never publish or change a real release.
5. A confirmed claim needs a complete source-visible hand-off and a meaningful result. Otherwise report `needs_validation` with the exact branch, runner, registry, signing, or deployment fact.

## Sources

- `third_party/security-audit-skill/skills/security-audit/SUPPLY-CHAIN-AND-RELEASE.md`, from cloudflare/security-audit-skill at commit `c1c8a8c` (MIT License, Copyright (c) 2025-2026 Cloudflare, Inc.).
- `third_party/open-code-review/rules/rule_docs/github_workflows.md`, from alibaba/open-code-review at commit `11ac6d4` (Apache-2.0, Copyright 2026 alibaba/open-code-review contributors).
- kalkan condensed and rewrote the text, adapted it to the kalkan verdict model, added the reachability class, and removed the agent-orchestration instructions.
