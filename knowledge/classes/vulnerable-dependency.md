---
slug: vulnerable-dependency
title_en: Vulnerable dependency (SCA)
title_tr: Zafiyetli bağımlılık (SCA)
cwe: CWE-1395, CWE-937, CWE-1104
owasp: A06:2021
sources: codecrucible, security-audit-skill, open-code-review
---

## Summary

The project resolves a third-party package version that a published advisory (CVE, GHSA, OSV) covers. A version match is only a candidate. The finding is real when the application imports the package and reaches the vulnerable function or feature with input that an attacker can influence. Decide reachability with quotes: `reachable`, `not_reachable` or `unknown`.

## What it is

- **Reachable vulnerable version.** A lockfile or a vendored copy resolves a version inside the affected range, and first-party code reaches the vulnerable function, class or feature.
- **Transitive reach.** The vulnerable package is a transitive dependency, and the app reaches the vulnerable code through a direct dependency (for example a body parser that calls a vulnerable query-string parser).
- **Copied or vendored code (CWE-1104).** A copied `jquery-1.x.min.js`, a vendored C library or a forked package with a known advisory and no fixes.
- **End-of-life components (CWE-1104).** A runtime or framework line without security fixes, when an advisory affects the used feature.

**How kalkan handles this class.**

- `sca sbom` builds a CycloneDX software bill of materials (SBOM) of the target tree with Syft. Trivy is the fallback.
- `sca match` runs OSV-Scanner on the source and Grype on the SBOM. It merges records with the same ecosystem, package and version and an overlapping ID set into `sca/vulns.json`. Each record carries `vuln_id`, `aliases`, `summary`, `severity`, `cvss_score`, `fixed_versions` and `locations`, and becomes one candidate of this class.
- `sca reach` runs govulncheck for Go modules when Go is installed. A vulnerable symbol that the code calls marks the record `reachable`.
- For other ecosystems, the engine creates `sca_reach` tasks for `critical` and `high` records within the budget. The agent returns `reachability`, `reason`, `evidence[{file, line, quote}]` and `searched[]`.
- The engine checks each quote against the cited line (plus or minus 2 lines). It lowers the severity of a `not_reachable` record by one level. It never deletes a record.
- kalkan scans the source tree, not built images. OS packages of a base image are out of scope unless the SBOM lists them.

## What it is not

- A bug in the project's own code that looks like a CVE → its own class.
- A version that a malware database lists (an OSV `MAL-` record, a GitHub malware advisory) → `malicious-dependency`. It harms at install time, so reachability does not apply.
- Unpinned versions, missing lockfiles, dependency confusion, typosquats, install scripts, mutable images or actions → `supply-chain-cicd`.
- Unsafe use of a fixed library version (for example `yaml.load` with an unsafe loader) → the sink class, such as `deserialization`.
- A deprecated API without an advisory → `code-quality`.
- Container base-image settings → `iac-cloud-container`.

## Where to look

Start from the record in `sca/vulns.json`: package, resolved version, advisory summary, aliases and fixed versions. You have no network access, so the summary and the source tree are your evidence. Find the vulnerable symbol or feature in the summary, then search the code for it.

### All ecosystems
- The lockfile line that resolves the version. A manifest range (`^1.2.0`, `>=2`) is not a version.
- Import sites of the package and its submodules. Wrappers and re-exports in first-party code.
- Call sites of the named function, or the configuration that turns on the vulnerable feature.
- Framework auto-use: frameworks call parsers, loggers and template engines without an import in your code.
- Test, example, docs and tool folders with their own lockfiles.

### JavaScript/TypeScript (npm, yarn, pnpm)
- `package-lock.json` (`"node_modules/<name>": { "version": ... }`), `yarn.lock`, `pnpm-lock.yaml`. Nested copies can resolve another version for each importer.
- `require("x")`, `import ... from "x"`, subpath imports (`lodash/merge`), bundler aliases. `dependencies` against `devDependencies`. `overrides` and `resolutions`.
- Browser bundle or server code: the impact differs.

### Python (pip, Poetry, uv)
- `requirements*.txt` pins, `poetry.lock`, `uv.lock`, `Pipfile.lock`.
- The import name can differ from the package name: PyYAML is `yaml`, Pillow is `PIL`, beautifulsoup4 is `bs4`, pycryptodome is `Crypto`.

### Go
- `go.mod` and `go.sum`. govulncheck results already show call paths. Without them, search for the import path and the symbol.
- Standard-library advisories depend on the Go toolchain that builds the binary (the `go` and `toolchain` lines).

### Java (Maven, Gradle)
- `pom.xml` with parent BOMs (Spring Boot sets many versions), Gradle lockfiles. Without a lockfile, the resolved version can be `unknown`.
- Advisories often name a class, for example `StringSubstitutor` in Apache Commons Text. Search for that class and its configuration.

### Ruby, PHP, Rust, .NET
- `Gemfile.lock`, `composer.lock`, `Cargo.lock`, `packages.lock.json` or `PackageReference` items. RustSec advisories often list the affected functions.

### Vendored and copied code
- `vendor/`, `third_party/`, version banners in `*.min.js` files, C libraries copied into the tree.

## Safe patterns

- Upgrade to the lowest fixed version in `fixed_versions` on the same major line, then regenerate the lockfile.
- Pin a transitive fix with `overrides`, `resolutions`, a constraints file or `dependencyManagement`.
- If no fix exists, remove or replace the package, or turn off the vulnerable feature with a configuration line. Record that change as a compensating control.
- Commit lockfiles and run SCA in CI.

## Weak mitigations

- A manifest range that allows the fixed version while the lockfile still resolves the old one.
- A pinned direct dependency while a vulnerable transitive copy stays elsewhere in the tree.
- A WAF rule for a library bug.
- "We never call that function" without a search of wrappers, re-exports and framework auto-use.
- A mitigation flag that the advisory later called incomplete.

## Verification checklist

Reachability needs three quotes. The engine checks each quote against the cited line.

- **Version quote:** the lockfile line, or the vendored banner, that shows the resolved affected version.
- **Import quote:** the import of the package in first-party code, or the direct dependency that pulls it in.
- **Call-site quote:** the call of the vulnerable function, or the configuration that enables the vulnerable feature. Name the symbol from the advisory.
- **attacker_control:** Show that input from an entry point reaches that call, or that the vulnerable feature handles attacker data (for example every log message).
- **privilege_boundary:** The advisory impact crosses the app's boundary: code execution in a server, XSS in a page, denial of service of a shared service. A build tool that reads only trusted input refutes it.
- **unmitigated:** No control on the path removes the trigger: an input check, a disabled feature, a safe option. Quote the control if it exists.
- `reachable`: the version, import and call-site quotes exist, and an input path reaches the call.
- `not_reachable`: needs positive evidence. Quote the proof: the only import is in a test file, the package is a `devDependency` that only the build uses, or the feature is off. List every search in `searched[]`.
- `unknown`: dynamic imports, reflection, plugins, framework auto-use that you cannot trace, or an advisory without a symbol. A missing call is not proof when the advisory names no symbol.

## Examples

### JavaScript/TypeScript (npm, yarn, pnpm)
```js
// Reachable: lodash below 4.17.11 (CVE-2018-16487, prototype pollution in merge)
// package-lock.json: "node_modules/lodash": { "version": "4.17.10" }
const _ = require("lodash");
app.post("/prefs", (req, res) => { _.merge(userPrefs, req.body); res.sendStatus(204); });

// Fixed: lodash 4.17.21 in the lockfile, and only known keys are copied
const { theme, lang } = req.body;
Object.assign(userPrefs, { theme: String(theme), lang: String(lang) });
```

```jsonc
// Not reachable: the only import is scripts/build.js, which the build runs and the app never loads
"devDependencies": { "minimist": "1.2.0" }
```

### Python (pip, Poetry, uv)
```python
# Reachable: PyYAML below 5.4 runs code through FullLoader (CVE-2020-14343)
# requirements.txt: PyYAML==5.3.1
import yaml
config = yaml.load(request.data, Loader=yaml.FullLoader)

# Fixed: PyYAML 6.0.1 in the lockfile, and safe_load
config = yaml.safe_load(request.data)
```

### Go
```go
// Reachable shape: govulncheck reports that the code calls parser.Parse
// go.mod: example.com/parser v1.2.0 (affected below v1.2.5)
doc, err := parser.Parse(r.Body)
```

## Dynamic test hints

- Static reachability is the main evidence. A PoC is optional.
- The unit sandbox has no network, and `run init` does not copy `node_modules` or virtual environments. A PoC needs a prepared environment with the dependency installed. Otherwise keep the result static.
- Write a minimal local trigger against the app's own function. For prototype pollution, send `{"__proto__": {"kalkanMarker": 1}}` and check `({}).kalkanMarker`.
- Never run public exploit code from advisories, and never contact a deployed service.

## False positive traps

- The lockfile already resolves a fixed version, and the tool read the manifest range.
- The advisory needs another platform, OS or option (a Windows-only path bug on a Linux service, a non-default flag).
- The app imports a submodule that does not contain the vulnerable code.
- The record comes from an example, docs or tool folder with its own lockfile.
- One vulnerability under several IDs (CVE, GHSA, PYSEC). The engine merges aliases. Do not count it twice.
- The advisory is withdrawn or disputed.
- The CVSS base score is generic. Reachability and context decide the real impact.

## Sources

- kalkan `docs/ENGINE-SPEC.md` sections 6.3, 17 and 18: SBOM, matching, reachability tasks, quote checks, severity rules.
- `block/codecrucible@b5c8086: prompts/default/analysis_sections.yaml`, `prompts/core/analysis_sections.yaml` (known-vulnerable pins, CWE-1395) (Apache-2.0, Block): a present package is noise, a reachable vulnerable path is a finding.
- `cloudflare/security-audit-skill@c1c8a8c: skills/security-audit/SUPPLY-CHAIN-AND-RELEASE.md`, `ATTACK-CLASSES.md` (MIT, Cloudflare): a known-vulnerable dependency is not a finding by itself, lockfile checks.
- `alibaba/open-code-review@11ac6d4: internal/config/rules/rule_docs/composer_json.md`, `package_json.md`, `cargo_toml.md` (Apache-2.0, alibaba/open-code-review contributors): report a known vulnerability only with advisory evidence for the resolved version.
- Import-name mappings, lockfile formats and the CVE examples come from general knowledge.
