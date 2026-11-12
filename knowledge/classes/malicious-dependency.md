---
slug: malicious-dependency
title_en: Malicious dependency
title_tr: Zararlı bağımlılık
cwe: CWE-506, CWE-1357
owasp: A06:2021, A08:2021
sources: security-audit-skill
---

## Summary

The project resolves a package version that a malware database lists as malicious: an OSV `MAL-` record (OpenSSF malicious-packages) or a GitHub malware advisory ("Malicious code in <package>"). Such a package does harm when it is installed or first imported, not through a bug that an attacker must reach. Treat every machine that installed it as exposed. Reachability does not change this, so kalkan creates no `sca_reach` task and never lowers the severity.

## What it is

- **Typosquat or look-alike name.** A package name close to a popular one (`reqeusts`, `fake-usragent`) that steals data or opens a shell.
- **Dependency confusion.** A public package with the name of a private one, pulled because an index or registry setting allows both.
- **Hijacked release.** A legitimate package whose maintainer account or build was taken over, so one or more versions carry malware.
- **Protestware and test uploads.** A version that wipes files or calls home, or a "test" package that runs commands on install.

**How kalkan handles this class.**

- `sca match` marks a record malicious when one of its IDs is an OSV `MAL-` ID. For Grype it also reads the advisory links: a link to `github.com/ossf/malicious-packages/.../MAL-<year>-<n>.json` adds that `MAL-` ID, and the title "Malicious code in <package> (<ecosystem>)" marks the record.
- A malicious record gets this class, severity `critical`, no `sca_reach` task and no reachability downgrade. A `MAL-` ID is the primary ID of the record.
- The report shows malicious records in a separate box before the ordinary SCA table and on the executive page. `summary.json` counts them (`counts.sca_malicious`), and SARIF gives them level `error`.

## What it is not

- A known vulnerability (CVE, GHSA) in a legitimate package → `vulnerable-dependency`.
- An unpinned version, a missing lockfile, a lockfile entry from an unexpected registry or without an `integrity` field → `supply-chain-cicd`. These make a malicious version possible, but they are not one.
- Malicious-looking code in the project's own files (a backdoor, an obfuscated loader) → the class of the sink, such as `code-injection` or `os-command-injection`.
- A withdrawn malware record (the database says the report was a mistake) → no finding; note it.

## Where to look

Start from the record in `sca/vulns.json`: package, version, the `MAL-` or GHSA ID, and `locations`. You have no network access. The local record, the lockfile and the git history of the target are your evidence.

### All ecosystems
- The lockfile or manifest line that resolves the exact version. A malware record often names single versions, not a range.
- The lockfile history: the commit that added the version, and the CI runs after it.
- Install hooks that run code: npm `preinstall`, `install` and `postinstall`, Python `setup.py` and build backends, RubyGems extensions, NuGet `install.ps1` and MSBuild targets, Cargo `build.rs`.
- Every place that installs dependencies: developer machines, CI runners, Docker builds, deployment hosts.

### JavaScript/TypeScript (npm, yarn, pnpm)
- `package-lock.json` (`"node_modules/<name>"`), `yarn.lock`, `pnpm-lock.yaml`. Check the `resolved` URL and the `integrity` hash of the entry.
- A dependency that only a transitive package pulls in: `npm ls <name>` lists the path on a machine with the tree installed.

### Python (pip, Poetry, uv)
- `requirements*.txt`, `poetry.lock`, `uv.lock`, `Pipfile.lock`, and `--index-url` or `--extra-index-url` lines that add another index.

### Ruby, .NET, Rust, Go
- `Gemfile.lock`, `packages.lock.json` or `PackageReference` items, `Cargo.lock`, `go.sum`.

## Safe patterns

- Remove the package, or pin a version that the record does not list and that the maintainer confirms is clean. Regenerate the lockfile.
- Treat every machine that installed the version as exposed: rebuild CI runners and build images, and check developer machines.
- Rotate every secret that the install could read: CI secrets and tokens, cloud credentials, registry tokens, SSH keys, `.env` files on the build machines.
- Check the lockfile history for the time window, and the logs of those machines for outbound connections.
- Use one trusted index or registry (`--index-url` only, npm scope mappings), lockfiles with `integrity` hashes, and `npm ci` or `pip install --require-hashes`.

## Weak mitigations

- An upgrade alone. Malware runs at install time, so the exposure already happened.
- "We never import it." The install hook runs without an import.
- Deleting the package from `node_modules` or the virtual environment without a rebuild and secret rotation.
- A scanner allowlist entry for the record.

## Verification checklist

- **Version quote:** the lockfile or manifest line that resolves the exact version of the record.
- **Record match:** the package name and version match the `MAL-` record or the GitHub malware advisory, in the same ecosystem. A name in another ecosystem is not a match.
- **Install path:** a lockfile, a Dockerfile `RUN pip install`, `npm ci` or a CI step shows that the version gets installed.
- **attacker_control:** The malware author controls the package code, by definition.
- **privilege_boundary:** The install runs with the rights of the developer, the CI job or the build. The secrets of that context are exposed.
- **unmitigated:** Only proof that the version never got installed (it was added and removed in the same unbuilt commit) limits the impact. Reachability does not.
- A record that the database withdrew, or a version outside the listed versions, is not a finding.

## Examples

### JavaScript/TypeScript (npm, yarn, pnpm)
```jsonc
// Malicious: the lockfile resolves a version that a MAL- record lists
"node_modules/some-typosquat": {
  "version": "1.0.3",
  "resolved": "https://registry.npmjs.org/some-typosquat/-/some-typosquat-1.0.3.tgz"
}

// Fixed: the package is gone from package.json and package-lock.json, the lockfile was
// regenerated, and the CI secrets were rotated
```

### Python (pip, Poetry, uv)
```text
# Malicious: an exact pin of a version that a MAL- record lists
sample-module==0.0.1

# Fixed: the pin is removed, one index is configured, and the hashes are required
--index-url https://pypi.org/simple/
--require-hashes
```

## Dynamic test hints

- Do not install, import or run the package, not even in the sandbox. The evidence is static: the record and the lockfile line.
- Never download the package to look at it. kalkan has no network access during an audit.

## False positive traps

- The record was withdrawn. Check the `withdrawn` field of the OSV record when it is available.
- The name matches a package in another ecosystem (an npm name in a PyPI lockfile).
- The record lists other versions, and the lockfile resolves a clean one.
- The manifest names the package, but a lockfile or a constraints file resolves another version.

## Sources

- kalkan `docs/ENGINE-SPEC.md` sections 3, 16 and 17, ADR-0005 (K.2).
- OpenSSF malicious-packages (`github.com/ossf/malicious-packages`, Apache-2.0): the `MAL-` OSV records that OSV-Scanner reads offline.
- GitHub Advisory Database malware advisories, as the Grype database carries them: GHSA records titled "Malicious code in <package> (<ecosystem>)" with a link to the `MAL-` record.
- `cloudflare/security-audit-skill@c1c8a8c: skills/security-audit/SUPPLY-CHAIN-AND-RELEASE.md` (MIT, Cloudflare): install-time code, lockfile checks and dependency source confusion.
- The response steps (remove, rebuild, rotate, check the lockfile history) come from general incident-response practice.
