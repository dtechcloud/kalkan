---
slug: race-condition
title_en: Race condition / TOCTOU
title_tr: Race condition / TOCTOU
cwe: CWE-362, CWE-367
owasp: A04:2021
sources: codecrucible, security-audit-skill, deepsec, open-code-review
---

## Summary

Two requests, threads or processes run between a check and the action that the check guards. The attacker gets a result that no serial run gives, such as a double spend, a reused single-use token or another user's data. Report it only when concurrent access is reachable and the gain is concrete.

## What it is

- **Check-then-act on shared data.** A read and a dependent write are two operations without an atomic guard. Typical targets: balances, coupons, tokens, stock counters, "is this name free?" checks, quotas.
- **Single-use resources.** "Is it used?" and "mark it used" are two queries, so all parallel requests pass the check.
- **File-system TOCTOU (CWE-367).** Code checks a path (`exists`, `access`, `stat`, `lstat`, a realpath prefix check) and then opens the same path by name. Another local user swaps the file or plants a symlink in the window.
- **Unsynchronized shared memory.** Request data lives in a singleton field, a module global or a package variable. Concurrent requests read each other's data or corrupt a map or a counter.
- **Broken lock scope.** The lock or transaction does not cover both the check and the use. Causes: a missing `await`, an in-process mutex with several instances, an unused transaction object.

Use the narrowest CWE: CWE-367 for files, CWE-362 for shared data, CWE-366 for threads, CWE-820 or CWE-821 for missing or wrong synchronization.

## What it is not

- A flaw that needs no concurrency (skipped step, negative quantity, coupon stacking) → `business-logic`.
- Replay of a signed webhook or message, or broker redelivery without deduplication → `webhook-replay`.
- No rate limit at all → `rate-limit-bruteforce`. A limiter that parallel requests exceed because its counter is not atomic stays here.
- Use-after-free or double free in C, C++ or unsafe Rust → `memory-safety`. Reentrancy in contracts → `smart-contract`.
- A deadlock that attacker input triggers → `dos-redos`. A data race that crashes the process (Go "concurrent map writes") stays here.
- Symlink following or `../` without a check/use window → `path-traversal`.
- Application caches shared across tenants → `multi-tenant`. Web cache poisoning → `request-smuggling-crlf-cache`.

## Where to look

### Python

- Django `get()` and then `save()` with a computed value, without `select_for_update()` in `transaction.atomic()` or an `F()` update.
- SQLAlchemy queries and changes without `with_for_update()` or a conditional `update()`.
- asyncio: each `await` between the check and the write lets other tasks run, also on one thread.
- Module-level dicts and caches in threaded servers. `os.path.exists` or `os.access` before `open()`. `tempfile.mktemp()`.

### JavaScript/TypeScript

- Prisma, TypeORM, Sequelize, Mongoose: `findUnique`, `findOne` or `findById`, then `update`, `save` or `delete`.
- Inside `prisma.$transaction(async (tx) => ...)`, calls on `prisma.` instead of `tx.` run outside the transaction.
- Redis `GET` and then `SET` or `DEL` without `MULTI`/`WATCH`, a Lua script or one atomic command.
- Lock or transaction helpers called without `await`. Requests interleave at every `await`, and module variables are shared.

### Java/Kotlin

- Spring beans are singletons. A field with per-request data in a `@Controller` or `@Service` leaks across users.
- JPA `findById` and then `save` without `@Version`, `@Lock(PESSIMISTIC_WRITE)` or a conditional `@Modifying` query.
- `@Transactional` on a private method, or a call from the same class, starts no transaction.
- `HashMap` or `SimpleDateFormat` shared between threads. Double-checked locking without `volatile`.

### Go

- Maps written from handlers without `sync.Mutex`, `sync.RWMutex` or `sync.Map`. Concurrent writes crash the process.
- Counters with `x++` instead of `sync/atomic`. Loop variables captured by goroutines before Go 1.22.
- `db.Begin()` and a plain `SELECT` before the `UPDATE`, without `FOR UPDATE`.

### PHP

- PHP shares no memory between requests, but the database, cache and files are shared.
- Laravel `find()` and then `save()` without `DB::transaction()` plus `lockForUpdate()`. `file_exists()` before `fopen()`.

### Ruby

- Rails `find` and then `update` without `lock!`, `with_lock` or `lock_version`.
- `validates :x, uniqueness: true` without a database unique index. Two inserts pass the validation together.
- Puma runs threads, so class variables and globals are shared.

### C#/.NET

- EF Core read-modify-write without a concurrency token (`[ConcurrencyCheck]`, `rowversion`).
- Singleton services with mutable fields, or `Dictionary` instead of `ConcurrentDictionary`.

### SQL databases and stores

- READ COMMITTED (default in PostgreSQL, SQL Server, Oracle) loses updates in `SELECT` then `UPDATE`. A MySQL InnoDB plain `SELECT` reads a snapshot without a lock.
- One Redis command is atomic, a sequence is not. A MongoDB update is atomic when the guard is in the filter.

## Safe patterns

- One conditional statement and a row-count check: `UPDATE accounts SET balance = balance - :amt WHERE id = :id AND balance >= :amt`, then require one affected row. Burn tokens with `... AND used_at IS NULL`.
- A unique constraint on the consumption record, for example `(coupon_id, user_id)`, with the side effect after the insert.
- A row lock in a transaction: `SELECT ... FOR UPDATE` (`select_for_update()`, `with_lock`, `lockForUpdate()`, JPA `PESSIMISTIC_WRITE`).
- A version column that the `UPDATE` checks (JPA `@Version`, Rails `lock_version`, EF Core `rowversion`). SERIALIZABLE with a retry for multi-row invariants.
- Atomic store commands: Redis `INCR`, `SET key value NX EX`, `GETDEL`, Lua scripts. MongoDB `findOneAndUpdate` with the guard in the filter.
- In-process state: `sync.Mutex`, `sync/atomic`, `ConcurrentHashMap.compute`, `threading.Lock`. These protect one process only.
- Files: `O_CREAT | O_EXCL` (plus `O_NOFOLLOW` on POSIX), `fstat` on the open descriptor, atomic rename, `mkstemp` in a private directory.
- An idempotency key with a unique constraint, stored before the side effect.

## Weak mitigations

- A transaction at the default READ COMMITTED level around a plain `SELECT` and an `UPDATE`.
- A transaction that the code opens but does not use: Spring self-invocation, `prisma.` calls inside a `tx` callback, a second session.
- A mutex or an in-memory lock when several workers, pods or serverless instances run the code.
- An "exists?" check or a uniqueness validation without a database unique index. A disabled button, a debounce or a `sleep`.
- A Redis lock without expiry, with too short an expiry, or released without an owner check.
- A realpath or `lstat` check, then `open()` on the original path name.

## Verification checklist

- **attacker_control:** Name the entry point. Show that the attacker can send two or more requests that reach the check before the first write commits, with one account or with colluding accounts.
- **privilege_boundary:** Name the gain that a serial run does not give. Examples: extra credit, a second redemption, a limit overrun, another user's data, a file write outside the attacker's reach. No gain or an idempotent result refutes this question.
- **unmitigated:** Quote the check line and the use line. Show that no atomic statement, row lock, version check, unique constraint or effective isolation level covers both.
- Count the statements and `await` points between check and use. Name the database, its isolation level and the driver model (pooled async, threads, one connection).
- If the number of instances decides the result and the repository does not show it, use `needs_validation`.

## Examples

### Python (Django)

Vulnerable: the check and the debit are two statements.

```python
wallet = Wallet.objects.get(user=request.user)
if wallet.balance >= amount:
    wallet.balance -= amount
    wallet.save()
    send_payout(request.user, amount)
```

Secure: one conditional update and a row-count check.

```python
with transaction.atomic():
    changed = Wallet.objects.filter(user=request.user, balance__gte=amount).update(
        balance=F("balance") - amount)
    if changed != 1:
        raise InsufficientFunds()
    send_payout(request.user, amount)
```

### JavaScript/TypeScript (Prisma)

Vulnerable: all parallel requests see `used === false`.

```ts
const c = await prisma.coupon.findUnique({ where: { code } });
if (!c || c.used) throw new Error("invalid coupon");
await prisma.coupon.update({ where: { code }, data: { used: true } });
await addCredit(prisma, userId, c.value);
```

Secure: the guard is part of the write, and every call uses `tx`.

```ts
await prisma.$transaction(async (tx) => {
  const r = await tx.coupon.updateMany({ where: { code, used: false }, data: { used: true } });
  if (r.count !== 1) throw new Error("invalid coupon");
  const c = await tx.coupon.findUniqueOrThrow({ where: { code } });
  await addCredit(tx, userId, c.value);
});
```

### Java/Kotlin (Spring)

Vulnerable: the controller is a singleton, so all requests share the field.

```java
@RestController
class InvoiceController {
    private Account current;

    @GetMapping("/invoices")
    List<Invoice> list(Principal p) {
        current = accounts.byName(p.getName());
        return invoices.forAccount(current.getId()); // another request can change it
    }
}
```

Secure: keep request data in local variables.

```java
@GetMapping("/invoices")
List<Invoice> list(Principal p) {
    Account current = accounts.byName(p.getName());
    return invoices.forAccount(current.getId());
}
```

## Dynamic test hints

- Start 10 to 50 workers behind a barrier (`threading.Barrier`, `Promise.all`, a closed Go channel). Each worker calls one handler with one dummy account.
- Check the invariant (no negative balance, one redemption per coupon) after each of 20 rounds. Report the number of broken rounds.
- Use the production database engine when the target compose file supplies it. SQLite can hide the race.
- To show the window without luck, add a pause hook in a test double between the read and the write. Say that the hook widened the window.
- In Go, run the harness with `go test -race`. In Java, use an `ExecutorService` and a `CountDownLatch`.
- Use local fixtures only. Never send parallel traffic to a shared or live system.

## False positive traps

- The check and the write are one atomic statement, and the code checks the affected row count.
- A unique constraint makes the losing request fail before any side effect.
- The operation is idempotent: two runs give the same state as one run.
- No interleaving window exists: synchronous code without `await` in one Node process, or one synchronous SQLite connection in one process.
- Only the attacker's own data changes and the race gives no gain.
- The data is read-only or local to one request, or the code runs only at startup or in a test.
- A scanner signal such as "read, then write without a transaction" is a lead. Read the code between the two calls.

## Sources

Condensed and rewritten by kalkan. Vendored copies and pinned commits: `third_party/MANIFEST.json`.

- block/codecrucible@b5c8086 (Apache-2.0, Block): `cwe_deep_analysis.yaml` CWE-362 in `prompts/default/`, `prompts/carlini-curated/` and `prompts/exploit-proof-web-go/`, `prompts/default/analysis_sections.yaml` (concurrency_state), `prompts/core/audit_families.yaml` (concurrency).
- cloudflare/security-audit-skill@c1c8a8c (MIT, Cloudflare): `skills/security-audit/ATTACK-CLASSES.md` (races, file TOCTOU), `PROTOCOLS-RPC-AND-MESSAGING.md` (idempotency).
- vercel-labs/deepsec@4fa6722 (Apache-2.0, Vercel): `packages/scanner/src/matchers/non-atomic-operation.ts`, `non-atomic-read-delete.ts`, `missing-await.ts`, `packages/processor/src/prompt/slug-notes.ts`.
- alibaba/open-code-review@11ac6d4 (Apache-2.0, alibaba/open-code-review contributors): `internal/config/rules/rule_docs/java.md`, `go.md`, `python.md`, `php.md` (concurrency sections).
- Added by kalkan from general knowledge: isolation levels, Spring proxy, Rails uniqueness, Prisma `tx`, file TOCTOU APIs.
