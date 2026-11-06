# kalkan Opengrep rule pack

kalkan's own Opengrep rules (Semgrep-compatible YAML). kalkan wrote every rule. The pack contains no rule from `semgrep-rules` or `opengrep-rules`. The vendored third-party packs are in `rules/opengrep-packs` with their own licenses. License: MIT (`# SPDX-License-Identifier: MIT` in every file).

The pack targets Opengrep 1.30.1, the version that `src/kalkan/tools/manifest.json` pins.

## Layout

| File | Rules | Content |
|---|---|---|
| `python.yaml` | 16 | Flask, Django, FastAPI, standard library |
| `javascript.yaml` | 17 | JavaScript and TypeScript: Node.js, Express, Koa |
| `go.yaml` | 10 | net/http, gin, echo, standard library |
| `java.yaml` | 15 | Servlet API, Spring MVC, JDK |
| `php.yaml` | 16 | plain PHP, Laravel, Symfony, Twig |
| `ruby.yaml` | 15 | Rails, Sinatra, standard library |
| `csharp.yaml` | 15 | ASP.NET Core, .NET base class library |
| `generic.yaml` | 2 | regex rules for any file (hardcoded AWS keys) |

106 rules in total. 68 rules use taint mode.

## Coverage

Number of rules per class and language:

| Class | python | javascript | go | java | php | ruby | csharp | generic |
|---|---|---|---|---|---|---|---|---|
| `code-injection` | 1 | 1 | - | 1 | 2 | 1 | 1 | - |
| `cors` | 1 | 1 | 1 | 1 | 1 | 1 | 1 | - |
| `crypto` | 2 | 2 | 1 | 2 | 2 | 2 | 2 | - |
| `deserialization` | 2 | 1 | - | 1 | 1 | 1 | 1 | - |
| `hardcoded-secrets` | - | - | - | - | - | - | - | 2 |
| `jwt` | 1 | 1 | 1 | 1 | 1 | 1 | 1 | - |
| `nosqli` | 1 | 1 | - | 1 | 1 | 1 | 1 | - |
| `open-redirect` | 1 | 1 | 1 | 1 | 1 | 1 | 1 | - |
| `os-command-injection` | 1 | 1 | 1 | 1 | 1 | 1 | 1 | - |
| `path-traversal` | 1 | 1 | 1 | 1 | 1 | 1 | 1 | - |
| `prototype-pollution` | - | 2 | - | - | - | - | - | - |
| `sqli` | 1 | 1 | 1 | 1 | 1 | 1 | 1 | - |
| `ssrf` | 1 | 1 | 1 | 1 | 1 | 1 | 1 | - |
| `ssti` | 1 | 1 | 1 | 1 | 1 | 1 | 1 | - |
| `xss` | 1 | 1 | 1 | 1 | 1 | 1 | 1 | - |
| `xxe` | 1 | 1 | - | 1 | 1 | 1 | 1 | - |

Go has no common eval, XXE, NoSQL or deserialization sink in the standard library, so the Go file has no rule for these classes.

## Rule format

- **ID:** `kalkan.<language>.<class>.<name>`. `<class>` is a slug of the kalkan taxonomy (`docs/ENGINE-SPEC.md`, section 3).
- **Fields:** `message` (what is wrong and how to fix it), `severity` (`ERROR`, `WARNING` or `INFO`), `languages`.
- **Metadata:**
  - `cwe`: a list in the form `"CWE-89: Improper Neutralization ..."`. Opengrep sorts the SARIF tags alphabetically, and `kalkan.sarif.ingest` takes the class of the first CWE tag. So the alphabetically first entry must map to the class through `kalkan.findings.taxonomy.class_for_cwe()`. A test checks this.
  - `kalkan_class`: the taxonomy slug. It is equal to the class part of the ID.
  - `confidence`, `likelihood`, `impact`: `HIGH`, `MEDIUM` or `LOW`.
  - `owasp`: OWASP Top 10 2021 entries. They match `taxonomy.owasp_for_class()`.
  - `references`: URLs (CWE entry and a fix guide).
  - `category: security` and `technology`.

Opengrep writes the CWE and OWASP entries into the SARIF rule `properties.tags` (`"CWE-89: ..."`, `"OWASP-A03:2021 - Injection"`). `kalkan.sarif.ingest` reads the class from the first CWE tag. `kalkan_class` is not in the SARIF output. The SARIF `level` follows `severity`: `ERROR` gives `error` (high), `WARNING` gives `warning` (medium).

## Run the pack

```
opengrep scan --config rules/opengrep --sarif-output=<out.sarif> \
  --no-rewrite-rule-ids --no-git-ignore --x-ignore-semgrepignore-files <target>
```

- `--no-rewrite-rule-ids`: without it, Opengrep adds the config path to every rule ID (`rules.opengrep.kalkan...`).
- `--no-git-ignore`: kalkan scans the copy under `runs/<run-id>/target/`. `runs/` is in `.gitignore`, so without this flag Opengrep skips every file of the copy.
- `--x-ignore-semgrepignore-files`: without a `.semgrepignore` file, Opengrep applies a default ignore list that skips `test/`, `tests/`, `vendor/`, `build/`, `dist/`, `node_modules/` and `*_test.go`. The vulnapp fixture lies under `tests/`. For a real audit, decide if test folders are in scope.
- The URIs in the SARIF output are relative to the working folder and use backslashes on Windows.
- `opengrep validate` downloads lint rules from semgrep.dev. It needs the network and uses rules under the Semgrep Rules License. kalkan does not run it in tests. The offline test checks the rule load through `scan`: an invalid rule gives a non-zero exit code and an error in the SARIF invocation.

## Design notes

- **Taint mode** for the injection classes. Sources are the request objects of each framework (`flask.request`, Django `request.GET`, Express `req.query`, typed `*http.Request` in Go, `HttpServletRequest` and Spring `@RequestParam` parameters in Java, `$_GET` and friends in PHP, `params` in Ruby, `[FromQuery]` parameters in C#). A sink is the dangerous argument, selected with `focus-metavariable`.
- **Pattern rules** for configuration problems that are dangerous with any data source: unsafe YAML loaders, XXE parser options, JWT checks turned off, weak hashes and ciphers, CORS with credentials.
- **Allowlist lookups are sanitizers.** In Python, JavaScript, Java and Ruby, a lookup in a constant map with an ALL_CAPS name (`FEEDS.get(name)`, `RETURN_PAGES[key]`) cleans the value. In Go, PHP and C#, the rules use `taint_assume_safe_indexes: true` instead.
- **Typed languages** use `taint_assume_safe_numbers` and `taint_assume_safe_booleans`, so a parsed integer does not carry taint.
- **Name-based sanitizers** (for example `escapeHtml`, `is_allowed_url`) are heuristics. A call with a matching name cleans the value. Check such calls in a review.
- **Known limits:** taint analysis is intra-procedural (per function). A guard such as `if not allowed(url): abort()` does not clean a value, except where a rule declares a `by-side-effect` sanitizer. Second-order data (from a database or a file) is not a source.

## Opengrep 1.30.1 behavior that the rules depend on

- `metavariable-regex` matches only identifiers and string literals. On a dotted name (`yaml.Loader`), a PHP variable or a concatenation it never matches. The rules use `metavariable-pattern` with `pattern-regex` or explicit patterns for such values.
- `opengrep validate` rejects YAML anchors and aliases, although `scan` accepts them. The rule files do not use anchors.
- A plain YAML value that contains `: ` breaks the file. Such patterns are in single quotes.
- Typed metavariables: Go uses `($X : *http.Request)`. Java and C# use cast syntax `(HttpServletRequest $X)`.
- JavaScript: `require("child_process")` aliases resolve, `require("node:child_process")` does not. The command injection rule has an extra branch for it.

## Tests

- `tests/unit/test_opengrep_rules.py`: static checks of the rule files (IDs, fields, metadata, coverage). The tests marked `tools` run Opengrep on `tests/fixtures/vulnapp` and check that:
  - every planted vulnerable item that expects `opengrep` is reported by a rule of the same class (start line within 2 lines),
  - no rule fires on a secure twin,
  - every result belongs to a planted vulnerable item,
  - every rule fires at least once on the fixture,
  - `kalkan.sarif.ingest` gives each result the class of its rule.
- `tests/fixtures/vulnapp/EXPECTED.json` lists the planted items. See `tests/fixtures/vulnapp/README.md`.

## Add a rule

1. Write the rule in the file of its language. Use the ID scheme and all metadata fields.
2. Add a vulnerable example and a secure twin to the fixture.
3. Add both items to `EXPECTED.json` with the exact line and a snippet of that line.
4. Run `pytest tests/unit/test_opengrep_rules.py tests/unit/test_fixture_expected.py`.
