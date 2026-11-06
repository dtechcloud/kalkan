---
slug: dos-redos
title_en: ReDoS / resource exhaustion
title_tr: DoS / ReDoS
cwe: CWE-400, CWE-1333
owasp: A04:2021
sources: security-audit-skill, codecrucible, deepsec
---

## Summary

A lower-trust caller controls the size or shape of input that the server processes without a bound, so one request or a few requests consume CPU, memory, disk or a shared quota far beyond their cost. Typical root causes are a regular expression with super-linear backtracking applied to caller input, a missing size or count limit on a parser, and work multiplied by a caller-chosen factor. Report it only when the code path is reachable by the caller and no bound sits before the expensive work.

## What it is

- A regular expression whose structure allows catastrophic backtracking (a quantified group that contains another quantifier over overlapping characters, or alternatives that match the same text), run by a backtracking engine on caller-controlled text without a length limit.
- A regular expression built from caller input (`new RegExp(userValue)`, `re.compile(user_value)`), which gives the caller control of the pattern itself.
- Unbounded reads: request bodies, uploads, multipart parts, archive members or decompressed data read into memory with no size limit.
- Parsers without limits: JSON, XML or YAML depth and size, GraphQL query depth and complexity, image dimensions, PDF page counts.
- Work amplification: a caller-chosen count, page size, batch size, loop bound, recursion depth or fan-out that the server multiplies into queries, outbound requests or model calls.
- Shared-resource exhaustion: one tenant or user filling a shared queue, disk, connection pool or paid quota with no per-caller limit.

## What it is not

- Missing login throttling or credential guessing → `rate-limit-bruteforce`.
- Exponential entity expansion in XML caused by enabled DTD processing → `xxe`.
- A crash from a memory-safety defect → `memory-safety`.
- Two concurrent requests that break an invariant → `race-condition`.
- GraphQL depth, complexity and alias batching when the issue is specific to the schema → `graphql`.
- Volumetric traffic, network floods and infrastructure capacity: out of scope for source review; not a finding.
- A slow endpoint that only an administrator can call by design, with no impact on other users: hardening note at most.

## Where to look

### Python

- `re.match`, `re.search`, `re.fullmatch`, `re.compile` on request data; `re.compile` with a pattern from the request.
- `request.get_data()`, `request.files`, `await request.body()` without a size check; Django `DATA_UPLOAD_MAX_MEMORY_SIZE` raised or disabled; FastAPI handlers reading `UploadFile` fully.
- `zipfile`, `tarfile`, `gzip`, `zlib.decompress` without a member count or output size bound; `yaml.load` with large documents; `json.loads` on unbounded bodies.

### JavaScript/TypeScript

- `new RegExp(input)`, `str.match(/.../)`, `.replace` and `.split` with complex patterns on request fields; validation libraries with custom regex options.
- `express.json({ limit })` or `bodyParser` with a very large or missing limit; `multer` without `limits`; reading a stream into a string with no cap.
- Loops over `req.query.count`, `limit` or `pageSize` values without a maximum; `Promise.all` over caller-sized arrays.

### Java/Kotlin

- `Pattern.compile` on request data or with a request-supplied pattern; `String.matches`, `replaceAll`, `split` with nested quantifiers.
- Spring `spring.servlet.multipart.max-file-size` and `max-request-size` raised or unlimited; Jackson without stream read constraints for very deep or long input.
- `ZipInputStream` loops without entry count and total size bounds.

### Go

- Go's `regexp` package uses RE2 and runs in linear time; a backtracking risk exists only with third-party engines such as `regexp2`. Look instead for `io.ReadAll(r.Body)` without `http.MaxBytesReader`, missing `ReadTimeout`/`ReadHeaderTimeout` on `http.Server`, and `archive/zip` loops without bounds.

### PHP

- `preg_match`, `preg_replace` on request data with nested quantifiers; patterns concatenated from input; `pcre.backtrack_limit` raised.
- `file_get_contents('php://input')` with raised `post_max_size`; `ZipArchive` extraction without limits.

### Ruby

- `=~`, `match`, `scan`, `gsub` with nested quantifiers on params (Ruby 3.2+ adds `Regexp.timeout`; check whether it is set); `Regexp.new(params[...])`.
- Rack and Rails body size settings; `Zlib::Inflate` without a bound.

### C#/.NET

- `Regex` without a `matchTimeout` on request data; `new Regex(userInput)`; `RegexOptions.NonBacktracking` is the safe alternative on .NET 7+.
- Kestrel `MaxRequestBodySize` set to null or very large; `[DisableRequestSizeLimit]`; `[RequestSizeLimit]` with huge values.

## Safe patterns

- A linear-time regex engine for caller input (Go `regexp`, RE2 bindings such as `google-re2`, .NET `RegexOptions.NonBacktracking`), or simple patterns without nested or overlapping quantifiers, anchored, with a length check before the match.
- A regex timeout where the platform offers one (.NET `matchTimeout`, Ruby `Regexp.timeout`) as a second layer.
- Never compile a pattern from caller input; when search needs patterns, escape the input (`re.escape`, `Regex.Escape`) or use plain substring search.
- Explicit limits before work: body size, upload size, part count, archive member count and total decompressed size, parser depth, page size maximum, batch size maximum.
- Per-caller quotas for expensive operations (exports, report generation, model calls), enforced on the server.
- Timeouts on server reads and on outbound calls; bounded worker pools and queues.

## Weak mitigations

- A client-side length check (the attacker skips it).
- A length limit applied after the regex runs, or applied to a different field than the one matched.
- A global request timeout at the proxy only: the worker keeps burning CPU after the client is gone.
- Catching the exception of a timeout but retrying the same work.
- Limits that a caller can raise through a parameter (`?limit=` with no server maximum).

## Verification checklist

- **attacker_control:** quote the entry point that passes caller text, size or count to the expensive operation (route handler, parser call, regex call). Configuration-only values and constants refute it.
- **privilege_boundary:** state who calls the path and who suffers: one user degrading service for other users or tenants, or an anonymous caller consuming shared resources, crosses a boundary. A caller slowing only its own session does not.
- **unmitigated:** quote the expensive line and show that no bound sits before it: no length check, no size limit, no linear-time engine, no timeout. Quote the bound when it exists; a bound that the caller controls does not refute.
- For a regex, name the structural reason for super-linear behavior (nested quantifier, overlapping alternation) and the engine (backtracking or linear-time).
- For unbounded reads and parsers, quote the configuration that sets or removes the limit, or state that the framework default applies and what it is.
- Severity: availability impact is usually medium; high only when one low-trust request can stop a shared service for everyone and the path needs no authentication.

## Examples

### Python

Vulnerable: a backtracking pattern with a nested quantifier on request text, and no length check.

```python
import re

TAG_LIST = re.compile(r"^(\w+\s?)*$")

def save_tags(request):
    tags = request.form["tags"]
    if not TAG_LIST.match(tags):
        abort(400)
```

Secure: a simple pattern, a length limit first, and no nested quantifier.

```python
import re

TAG = re.compile(r"[A-Za-z0-9_]{1,32}")

def save_tags(request):
    tags = request.form["tags"]
    if len(tags) > 512:
        abort(413)
    items = tags.split()
    if len(items) > 20 or not all(TAG.fullmatch(t) for t in items):
        abort(400)
```

### JavaScript/TypeScript (Express)

Vulnerable: a pattern compiled from the query string and a body read without a limit.

```javascript
app.get("/search", (req, res) => {
  const pattern = new RegExp(req.query.q);
  res.json(items.filter((item) => pattern.test(item.name)));
});
```

Secure: escaped input with a plain substring search, and an explicit body limit.

```javascript
app.use(express.json({ limit: "100kb" }));
app.get("/search", (req, res) => {
  const q = String(req.query.q ?? "").slice(0, 100).toLowerCase();
  res.json(items.filter((item) => item.name.toLowerCase().includes(q)));
});
```

### C#/.NET

Vulnerable: a backtracking regex with no timeout on request data.

```csharp
var ok = Regex.IsMatch(input, @"^([a-z0-9]+\.)*[a-z0-9]+$");
```

Secure: the non-backtracking engine and a length check.

```csharp
if (input.Length > 253) return BadRequest();
var ok = Regex.IsMatch(input, @"^([a-z0-9]+\.)*[a-z0-9]+$",
    RegexOptions.NonBacktracking);
```

## Dynamic test hints

- Never load-test, flood or stress any system, and never send repeated or oversized requests to a running service. Availability claims are settled from source and bounded local analysis.
- Check a suspicious regex with a static ReDoS analyzer (for example `recheck`, `safe-regex` or `regexploit`) on the pattern text alone, or reason about its structure: nested quantifiers and overlapping alternatives on a backtracking engine.
- For unbounded reads, confirm the limit in code and configuration and the framework default for the pinned version; no request is needed.
- A local unit test may call the function once with a short input and a strict timeout inside the sandbox to show that a fixed version stays fast; it must not try to exhaust resources.

## False positive traps

- Go `regexp`, RE2 and `RegexOptions.NonBacktracking` run in linear time; nested quantifiers there are not ReDoS.
- A pattern applied only to constants, configuration or values the server generated.
- A length check before the match that bounds the input to a small size (backtracking on a few dozen characters is harmless).
- Framework defaults that already bound bodies and uploads (check the pinned version before you claim a missing limit).
- Admin-only or offline batch tools whose cost falls only on the operator.
- A theoretical amplification with no caller-controlled factor.

## Sources

- cloudflare/security-audit-skill@c1c8a8c: skills/security-audit/RESOURCE-EXHAUSTION-AND-AVAILABILITY.md and ATTACK-CLASSES.md (resource exhaustion, validation rules). MIT, Cloudflare, Inc.
- block/codecrucible@b5c8086: prompts/default/cwe_deep_analysis.yaml (CWE-400, CWE-1333), prompts/core/audit_families.yaml (resources family), prompts/exploit-proof-web-js and exploit-proof-web-go. Apache-2.0, Block, Inc.
- vercel-labs/deepsec@4fa6722: packages/scanner/src/matchers (regex and body-size matchers), packages/processor/src/prompt/slug-notes.ts. Apache-2.0, Vercel, Inc.
- General knowledge, condensed and rewritten for kalkan: engine behavior of RE2, .NET `NonBacktracking`, Ruby `Regexp.timeout`, framework body-size settings. Confirm them against the pinned framework version.
