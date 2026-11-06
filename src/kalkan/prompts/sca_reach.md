## Task: dependency reachability

Decide whether the target's own code reaches the vulnerable part of one dependency. The engine verifies your quotes. A `not_reachable` answer lowers the severity of the vulnerability record by one level, so it needs a thorough, documented search.

The target copy is at `{{TARGET_DIR}}`.

### Input

The input holds the vulnerability record: ecosystem, package, installed version, vulnerability IDs, summary, affected functions or modules when the database names them, fixed versions, and the manifest or lockfile locations.

A record with `vendored` entries comes from a JavaScript library file that the target copied into its own tree (no package manager). Its locations are those files. Find the pages, templates and scripts that load the file (`<script src=...>`, a bundler import of the local path; `import_patterns` holds the file names), then the uses of the vulnerable function or option.

```json
{{INPUT_JSON}}
```

### Source around the manifest entries

{{SOURCE_EXCERPTS}}

### Knowledge

{{KNOWLEDGE}}

### Method

1. Read the vulnerability summary and decide which functions, classes, options or input formats of the package carry the weakness. When the record names them, use those names. When it does not, derive them from the summary; say so in `reason`.
2. Find where the target imports the package: Grep for the import forms of the ecosystem (`import x`, `from x import`, `require("x")`, `import ... from "x"`, `"github.com/org/x"`, `use x::`, `<artifactId>x</artifactId>` plus the Java package name, `using X;`, `require 'x'`).
3. Find calls to the vulnerable functions or uses of the vulnerable feature from the target's own code. Follow wrappers inside the target.
4. Decide:
   - `reachable`: the target's code calls the vulnerable function or feature. Quote the import line and the call line. Say in `reason` whether attacker-controlled data reaches the call, when you can see it.
   - `not_reachable`: the package is imported but the vulnerable part is never used, or the package is only a build, test or development dependency. List every pattern and path you searched in `searched`. Quote the import or the manifest line that shows the usage scope.
   - `unknown`: the package is used only through another dependency, the vulnerable part cannot be identified from the record, or dynamic loading hides the use. Explain in `reason`.
5. Never claim `not_reachable` without a search list. When in doubt, answer `unknown`.

### Result fields

- `vuln_ref`: copy it from the input.
- `reachability`, `reason`, `evidence` (quotes), `searched` (patterns and paths you checked).

