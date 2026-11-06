---
slug: code-quality
title_en: Non-security code quality
title_tr: Kod kalitesi (güvenlik dışı)
cwe:
owasp:
sources: codecrucible, deepsec, security-audit-skill, open-code-review
---

## Summary

`code-quality` holds real defects and hardening notes that have no attacker path across a trust boundary. The engine keeps this class out of the security findings in the report body. Its severity is never above `low`. If a lower-trust principal can trigger the defect and gain something, use the matching security class instead.

## What it is

- **A bug without an attacker path.** Data loss or corruption, a crash, a resource leak or a wrong result. Normal use or operator input triggers it, but no attacker controls it.
- **Security-adjacent weak spots that are not exploitable today.** Auth or crypto decisions copied into many handlers. An exception swallowed on a security path that still fails closed. `unsafe` code whose invariant holds now but has no written contract. A debug or bypass helper that no production build reaches.
- **Reliability gaps.** Missing timeouts, retries without backoff, unawaited promises, ignored errors, tasks that outlive their owner.
- **Hardening notes.** A missing defense-in-depth layer with no affected principal or resource today.

Where each item goes:

- A concrete defect with a fix and a location → a candidate with class `code-quality`.
- A pure hardening idea → the hunter's `hardening` list (`title`, `file`, `line`, `note`), not a candidate.
- Style, naming, formatting, typos, comments, complexity, dead code and test coverage → not reported at all.

## What it is not

- A crash, panic, leak or loop that an attacker can trigger in a shared service → `dos-redos`.
- A C or C++ memory error that input reaches → `memory-safety`.
- A race that gives a lower-trust user money, items or access → `race-condition` or `business-logic`.
- Secrets or personal data in logs or errors → `sensitive-data-exposure`.
- A security check behind a flag that is off by default, or that a client can switch → the class of that check (`authn`, `missing-authz`, `csrf`).
- A debug endpoint that production serves → `security-misconfig`.
- A missing rate limit on login or codes → `rate-limit-bruteforce`.

## Where to look

Most items come from other classes: a candidate that turns out to have no attacker path. Note these shapes while you review security units. Do not run a separate quality review.

### All stacks
- Error paths that swallow errors and continue with a default, especially around token checks, permission checks and payments.
- Security decisions copied into many handlers instead of one helper.
- Debug, test and bypass helpers, and the guard that keeps them out of production.
- Outbound calls without timeouts, retry loops without limits.

### JavaScript/TypeScript (Express, Next.js, NestJS)
- Promises without `await` around locks, transactions and writes. `.catch(() => {})`.

### Python (Django, Flask, FastAPI)
- `except Exception: pass`, broad `except` blocks that hide failures, mutable default arguments.

### Go
- `_ =` and `x, _ :=` on errors, `defer` inside loops, goroutines without cancellation.

### Rust
- `unwrap()`, `expect()` and `panic!` on operator input in library or service code, `let _ =` on a `Result`, `unsafe` without a `# Safety` note.

### C and C++
- Leaks on error paths, missing `free` or RAII, unchecked return values without an attacker trigger.

### Swift and Kotlin
- `!`, `try!`, `as!` and `!!` on runtime values, `try?` that hides a required failure, `GlobalScope.launch`.

## Safe patterns

- Propagate errors with context. Fail closed on security paths.
- Put each auth and crypto decision in one helper, and call it everywhere.
- Use RAII, `defer`, `use` or `with` blocks for resources.
- Use structured concurrency, cancellation and timeouts.
- Write a `# Safety` contract for each `unsafe` block.
- Remove debug and bypass helpers from production builds with a build flag, not with a comment.

## Weak mitigations

- An error that the code logs and then replaces with a default value.
- `|| true` in scripts, `try?`, `let _ =` and empty `catch` blocks.
- A comment such as "do not call in prod" as the only guard.
- A retry without a limit or backoff as the fix for a failure.

## Verification checklist

For this class, the three questions keep their keys but ask about a defect, not an attack.

- **attacker_control:** Name the trigger: a normal user action, an operator input or a runtime condition. Quote the path to the defect. If a lower-trust principal controls the trigger and gains something, move the candidate to the security class.
- **privilege_boundary:** Name the observable effect beyond the intended behavior: lost or corrupted data, a crash, a leak, a wrong result. If the effect crosses a security boundary, move the candidate to the security class.
- **unmitigated:** Quote the missing handling: no error check, no timeout, no cleanup, no lock. A handler at a higher layer (middleware, supervisor, framework) that handles the failure refutes it.
- Set the overall severity to `info` for hardening and minor defects, and to `low` for a defect with user-visible impact (data loss, crash). Never use `medium` or higher.
- Keep the description factual. Do not call the defect a vulnerability.

## Examples

### JavaScript/TypeScript (Express, Next.js, NestJS)
```ts
// Defect: the write is not awaited, so its error is lost and the response comes first
app.post("/settings", async (req, res) => {
  saveAuditEntry(req.user.id, req.body);
  res.sendStatus(204);
});

// Fixed
app.post("/settings", async (req, res) => {
  await saveAuditEntry(req.user.id, req.body);
  res.sendStatus(204);
});
```

### Python (Django, Flask, FastAPI)
```python
# Defect: a failed invoice mail is invisible
try:
    send_invoice_email(order)
except Exception:
    pass

# Fixed: log with context and queue a retry
try:
    send_invoice_email(order)
except MailError:
    log.exception("invoice mail failed", extra={"order": order.id})
    retry_queue.put(order.id)
```

### Rust
```rust
// Defect: a bad operator config file crashes the service at startup
let cfg: Config = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();

// Fixed: return an error with context
let text = std::fs::read_to_string(path).with_context(|| format!("read {path}"))?;
let cfg: Config = serde_json::from_str(&text).context("parse config")?;
```

## Dynamic test hints

- A PoC is optional for this class. If you write one, use a unit test with dummy data.
- Run the existing test suite in the sandbox. Use `go test -race` for races and LeakSanitizer for leaks.
- Simulate the failure with a stub that throws or times out, and check the visible effect.
- No load tests and no stress tests.

## False positive traps

- The behavior is intended and documented: best-effort telemetry, fire-and-forget metrics.
- A higher layer handles the failure: framework error middleware, a supervisor restart, a transaction rollback.
- The code is test, example or tooling code.
- A language or framework guarantee covers it: `defer` order, `Drop`, context managers.
- The reverse trap: do not hide a security bug here. If a lower-trust principal triggers it with a gain, use the security class.

## Sources

Condensed and rewritten from the local copies under `third_party/`.

- `block/codecrucible@b5c8086: prompts/default/analysis_sections.yaml` (`code_quality` section) (Apache-2.0, Block): security-adjacent quality items and the list of things not to report.
- `vercel-labs/deepsec@4fa6722: packages/processor/src/prompt/core.ts`, `packages/scanner/src/matchers/missing-await.ts`, `security-behind-flag.ts` (Apache-2.0, Vercel): non-security bug labels, unawaited calls, checks behind flags.
- `cloudflare/security-audit-skill@c1c8a8c: skills/security-audit/HUNTING.md`, `VALIDATION-AND-REPORTING.md` (MIT, Cloudflare): a missing best practice without an affected principal is hardening, separate hardening notes.
- `alibaba/open-code-review@11ac6d4: internal/config/rules/rule_docs/default.md`, `rust.md`, `swift.md`, `kotlin.md`, `c.md`, `cpp.md` (Apache-2.0, alibaba/open-code-review contributors): error handling, null safety, leaks, concurrency.
- kalkan `docs/ENGINE-SPEC.md` sections 7 and 18: the severity scale and the hunter `hardening` list.
