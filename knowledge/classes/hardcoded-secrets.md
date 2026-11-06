---
slug: hardcoded-secrets
title_en: Hardcoded secrets
title_tr: Gömülü sırlar (hardcoded secrets)
cwe: CWE-798
owasp: A07:2021
sources: sast-skills, codecrucible, deepsec, security-audit-skill, open-code-review
---

## Summary

A real credential is a literal in source, committed config, a build artifact or git history. Examples: API keys, passwords, private keys, signing secrets, tokens, connection strings with passwords. Rate it by two facts. First: who can read the literal (anyone through a client bundle or app binary, or only people with repository access). Second: what the credential unlocks.

## What it is

- **Literals in code or committed config.** `API_KEY = "..."`, database URLs with a password, Django `SECRET_KEY`, Flask `secret_key`, Rails `secret_key_base`. Also JWT signing secrets, keystore and LDAP passwords, PEM private keys, cloud access keys, service-account JSON.
- **Hardcoded fallbacks.** `process.env.JWT_SECRET || "dev-secret"`, `os.getenv("SECRET", "changeme")`, Spring `${JWT_SECRET:default}`. The fallback runs when the variable is unset.
- **Secrets that ship to clients.** Browser bundles, `NEXT_PUBLIC_*`, `VITE_*` and `REACT_APP_*` values, Angular `environment.ts`, mobile apps (APK, IPA, React Native, Flutter), Electron archives, HTML templates, source maps.
- **Committed secret files.** `.env`, `*.pem`, `*.key`, `id_rsa`, `credentials.json`, `*.tfvars`, `terraform.tfstate`, `.npmrc`, `.pypirc`, Rails `master.key`, keystores with their passwords.
- **History.** A secret removed from HEAD stays in git history and in every clone.
- **Shared defaults.** A seeded admin password, a default API token, or one encryption or HMAC key (CWE-321) in every installation of a product.

## What it is not

- Secrets that the running app writes to logs, errors, responses or traces → `sensitive-data-exposure`.
- Weak key size, weak algorithm, predictable key generation → `crypto`.
- CI behavior that leaks secrets (`echo` of a secret, untrusted pull-request jobs with secrets) → `supply-chain-cicd`. A literal value in a workflow, Dockerfile, Helm chart or Terraform file stays here.
- Credentials stored in plaintext in a database or browser storage at runtime → `sensitive-data-exposure`.
- JWT verification flaws → `jwt`. A literal JWT or session signing secret stays here.
- An endpoint that needs no credential at all → `authn` or `missing-authz`.
- Public identifiers: publishable keys, OAuth client IDs, the Firebase web config → no finding.

## Where to look

### Python

- `settings.py` (`SECRET_KEY`, `DATABASES`), Flask `app.secret_key`, `os.environ.get("X", "literal")`.
- `boto3.client(aws_access_key_id=...)` with literals. Notebook outputs with tokens.

### JavaScript/TypeScript

- Client code: files with `"use client"`, `src/` in Vite, CRA and Angular apps, and every module that a client entry point imports.
- `NEXT_PUBLIC_*`, `VITE_*`, `REACT_APP_*` names that hold credentials. The `env` block in `next.config.js` inlines values into the bundle.
- `process.env.X || "literal"` and `?? "literal"`. Expo `app.json` `extra`. Built `dist/` or `build/` folders in the repository.

### Java/Kotlin

- `application.properties`/`application.yml` (`spring.datasource.password`) and `${VAR:default}` defaults.
- Android `strings.xml`, `buildConfigField` in `build.gradle`, committed `local.properties` and `gradle.properties`.

### Go

- `const` tokens and keys, `os.Getenv` with a literal fallback, files in `//go:embed` that hold keys.

### PHP

- `config/*.php`, `wp-config.php` (`DB_PASSWORD`, auth keys and salts), a committed Laravel `.env`, `auth.json` with tokens.

### Ruby

- `config/secrets.yml`, `config/database.yml`, initializers with keys, a literal `secret_key_base`, a committed `master.key`.

### C#/.NET

- `appsettings*.json` and `web.config` connection strings with `Password=`, literal `machineKey` values, MAUI and Xamarin apps.

### Config, IaC and CI files

- `docker-compose*.yml` `environment:`, Dockerfile `ENV`/`ARG`, Kubernetes `Secret` manifests (Base64 is not encryption), Helm `values.yaml`.
- Terraform variable defaults and `*.tfvars`, GitHub workflow files with literal tokens, `.netrc`, `.git-credentials`.

## Safe patterns

- Read secrets at runtime from the environment or a secret manager (Vault, AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, SOPS, Rails credentials with the key outside the repository).
- Fail closed: stop at startup when a required secret is missing. No default value.
- Commit templates only (`.env.example` with placeholders). Let `.gitignore` cover `.env*`, keys and state files.
- Client apps hold no secret. Proxy the call through the backend, or give the client a short-lived scoped credential (presigned URL, STS token, OAuth with PKCE).
- Generate keys per installation instead of one vendor-wide default.
- Rotate every secret that was ever committed. Deleting it from HEAD or rewriting history does not revoke it.

## Weak mitigations

- A later commit that deletes the secret. History and clones keep it.
- Base64, hex, XOR or string splitting such as `"AKIA" + "..."`. Scanners and attackers decode it.
- Minification, ProGuard or R8, or native code storage in mobile apps. Extraction tools still read the value.
- A private repository. Every developer, CI system and leaked clone holds the secret.
- An environment override that exists, while the literal fallback still runs where the variable is unset.
- A secret encrypted with a key that is in the same repository.

## Verification checklist

- **attacker_control:** Name who can read the literal: anyone (client bundle, mobile app, public repository or image, source map), people with repository or artifact access, or nobody outside the build. For frontend code, trace the import chain from a client entry point.
- **privilege_boundary:** Name what the credential unlocks beyond the reader's access: a production database, a cloud account, a payment or email API, a key that forges sessions for any user. A local test container, a test-mode key or a public identifier refutes this question.
- **unmitigated:** Show that the value is real (entropy or a known issuer format, not a placeholder) and that production uses it (no environment override that always wins). If rotation is unknown, use `needs_validation` and name the owner check.
- Quote the variable name and the start of the assignment, not the full secret. That text is enough for the quote check.
- Rate client or public exposure of a production credential high or critical. Rate repository-only exposure lower, by who has access.

## Examples

### JavaScript/TypeScript (browser bundle)

Vulnerable: every browser that loads the bundle gets the cloud key.

```ts
const s3 = new S3Client({
  region: "eu-west-1",
  credentials: {
    accessKeyId: "AKIAIOSFODNN7EXAMPLE",
    secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  },
});
```

Secure: the backend gives the browser a short-lived presigned URL.

```ts
const { url } = await fetch("/api/uploads/presign", { method: "POST" }).then((r) => r.json());
await fetch(url, { method: "PUT", body: file });
```

### Python (Django settings)

Vulnerable: the literal fallback runs when the variable is missing.

```python
SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "example-not-a-secret")
```

Secure: no default, so startup fails without the secret.

```python
SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]
```

### Java/Kotlin (Spring Boot properties)

Vulnerable: a literal password and a literal default for the signing key.

```properties
spring.datasource.password=example-not-a-secret
jwt.secret=${JWT_SECRET:example-not-a-secret}
```

Secure: values come from the environment or a secret store, without defaults.

```properties
spring.datasource.password=${DB_PASSWORD}
jwt.secret=${JWT_SECRET}
```

## Dynamic test hints

- Never use, test or validate a found secret against the real service. Do not call any API with it.
- Show exposure only: grep the shipped artifact in the repository (`dist/`, `build/`, an APK) for the variable name or the key prefix. Build the bundle only when the build works offline in the sandbox.
- Fallbacks: start the config loader in a unit test with the variable unset. Print whether the fallback is used, plus its length, never the value.
- Signing secrets: sign a dummy token with the literal and pass it to the app's own verify function locally. This proves forgery without a real system.
- Redact values in all output: keep the first 4 characters and the length.

## False positive traps

- Placeholders: `changeme`, `your-api-key-here`, `xxx`, `TODO`, `<token>`, `dummy`, `example`, empty strings. Documentation keys such as `AKIAIOSFODNN7EXAMPLE`.
- Environment reads without a fallback (`process.env.X`, `os.environ["X"]`, `System.getenv`).
- Public by design: Stripe publishable keys, the Firebase web `apiKey`, referrer-restricted Maps keys, public OAuth client IDs, Sentry DSNs, search-only keys, reCAPTCHA site keys. A Supabase anon key is public too. Check its row-level security as `missing-authz`.
- Test fixtures for in-memory fakes or local containers, in files that do not ship. A live production key in a test file is still a finding.
- Public keys, certificates without private keys, hashes, checksums, commit IDs, lockfile integrity values, UUIDs used as IDs.
- Type definitions and interfaces without values. Server-only literals are not public exposure, but they are still findings at lower severity.
- One secret in many files is one finding. Report it at the most exposed location.

## Sources

Condensed and rewritten by kalkan. Vendored copies and pinned commits: `third_party/MANIFEST.json`.

- utkusen/sast-skills@db52227 (MIT, Utku Sen): `sast-files/.claude/skills/sast-hardcodedsecrets/SKILL.md` (public versus backend code, framework client rules, false positives).
- block/codecrucible@b5c8086 (Apache-2.0, Block): `cwe_deep_analysis.yaml` CWE-798 in `prompts/default/`, `prompts/carlini-curated/` and `prompts/exploit-proof-web-*/`, `prompts/default/analysis_sections.yaml` (key handling, configuration), `prompts/core/audit_families.yaml` (secrets), `prompts/carlini-curated/security_analysis_base.yaml` (do-not-report list).
- vercel-labs/deepsec@4fa6722 (Apache-2.0, Vercel): `packages/scanner/src/matchers/secrets-exposure.ts`, `secret-in-fallback.ts`, `secret-env-var.ts`, `env-exposure.ts`, `packages/processor/src/prompt/slug-notes.ts`.
- cloudflare/security-audit-skill@c1c8a8c (MIT, Cloudflare): `skills/security-audit/ATTACK-CLASSES.md` (obvious things), `WEB-PROTOCOL-AND-AUTH.md` (API-key exposure), `CLOUD-AND-DEPLOYMENT.md` (secret references).
- alibaba/open-code-review@11ac6d4 (Apache-2.0, alibaba/open-code-review contributors): `internal/config/rules/rule_docs/terraform.md`, `github_workflows.md`, `properties.md`.
- Added by kalkan from general knowledge: Angular, Expo, Android and .NET file locations, Rails `master.key`, the signing-secret test idea.
