---
name: resource-exhaustion-and-availability
title: Resource exhaustion and availability
classes: dos-redos, rate-limit-bruteforce
when_to_use: Untrusted requests, messages, files, tenant state, or agent work can consume shared CPU, memory, disk, connections, workers, queues, quotas, or paid APIs, or can crash or deadlock a shared service.
sources: third_party/security-audit-skill/skills/security-audit/RESOURCE-EXHAUSTION-AND-AVAILABILITY.md
---

# Resource exhaustion and availability

This pack separates a source-reviewable availability vulnerability from a general performance issue. Never validate by stressing a shared or live service. A reachable fatal error belongs here because of its shared impact, even when another pack covers the parser. Related packs: `memory-safety-and-binary` (memory integrity) and `protocols-rpc-and-messaging` (broker delivery logic).

## Core discipline

- Require an input-to-cost path, a missing effective bound, and impact on another user, a shared service, a safety function, or operator-owned spend. Self-limiting work inside the requester's own process is not a service vulnerability.
- A missing rate limit is not enough. Check body, message, and file caps, concurrency limits, queues, deadlines, database constraints, upstream gateways, and per-tenant quotas before you call a path unbounded.
- Never run stress, saturation, or production tests. Use complexity analysis, small boundary fixtures, mocked paid calls, strict local resource limits, and deterministic cancellation tests.
- State the attacker's cost, the service's work, persistence, scope, and recovery. One bounded input with a superlinear or persistent shared effect differs a lot from sustained volume.
- Use `needs_validation` when upstream caps, deployed topology, autoscaling, paid quotas, or recovery behavior outside the repository decides the claim.

## Attack classes

### Superlinear parsing, matching, or evaluation

- **Check:** small accepted input that drives catastrophic regex backtracking (nested quantifiers over overlapping alternatives, for example `^(a+)+$`), nested parsing, recursive validation, symbolic evaluation, graph traversal, template expansion, or adversarial sort and hash behavior. Derive the accepted depth and cardinality and the resulting complexity.
- **Not a finding:** a linear-time engine (RE2, Go `regexp`, Rust `regex`) or input that code caps to a small length first.

### Decompression and representation amplification

- **Check:** compressed, sparse, nested, aliased, or encoded input that expands far beyond the checked transfer or file size. Limits must apply after every expansion and across parser stages: archives, images, fonts, structured documents, XML entities, and protocol compression tables.
- **Not a finding:** expansion bounded by an explicit output limit.

### Database and downstream query amplification

- **Check:** a small request that creates broad scans, pathological joins, fan-out, unbounded sorts or aggregations, or many downstream calls because query depth, filter cardinality, pagination, or expansion fields have no bound. GraphQL depth, aliases, and batching belong here.
- **Not a finding:** a scope that authorization grants on purpose, with a page-size cap.

### Unbounded buffering and cardinality

- **Check:** bodies, out-of-order streams, uploads, sessions, unique cache keys, metric labels, log fields, subscriptions, or pending jobs that grow without per-item and aggregate limits. Find cleanup and expiry on disconnect, timeout, cancellation, and partial parse.
- **Not a finding:** growth bounded by an enforced per-tenant quota.

### Descriptor, handle, and temporary-resource leaks

- **Check:** malformed or canceled work that skips cleanup and keeps sockets, files, cursors, timers, subprocesses, temporary files, or object references. Confirm that the leak repeats per request and drains a shared pool.
- **Not a finding:** a one-time leak at startup or exit.

### Detached work after cancellation

- **Check:** a client timeout, disconnect, canceled job, or failed authorization that returns control but leaves database, model, network, or worker work running. Trace cancellation and deadline propagation through every layer.
- **Not a finding:** short work that ends on its own within the request deadline.

### Pre-authentication work imbalance

- **Check:** expensive parsing, key lookups, cryptography (password hashing on unauthenticated endpoints), decompression, or external requests that run before authentication and before the first size or rate gate. Compare the requester's effort with the shared cost.
- **Not a finding:** cheap pre-authentication work behind an upstream limit that the repository shows.

### Quota-accounting scope and reset gaps

- **Check:** accounting keyed on an attacker-influenced IP header, route, tenant, key prefix, or task ID, so that one principal escapes its budget or spends another principal's allocation. Review integer overflow, distributed races, retries, reconnects, and account switching. Login, password reset, OTP, and invite endpoints without effective attempt limits belong to `rate-limit-bruteforce`.
- **Not a finding:** a missing limit on a cheap, idempotent, public read.

### Worker, pool, and priority starvation

- **Check:** low-priority or attacker-controlled jobs that hold shared locks, workers, database pools, event-loop turns, or scheduler priority that unrelated users need. Show a path that bypasses queue fairness or keeps a slot past its deadline.
- **Not a finding:** fair scheduling with per-tenant concurrency caps.

### Reachable fatal error or deadlock

- **Check:** untrusted input that reaches a panic, abort, fatal assertion, unhandled exception, process exit, lock cycle, or infinite loop in a shared process. Confirm the supervisor scope: one worker or the whole service.
- **Not a finding:** an error that the framework turns into a 4xx or 5xx response for one request. A restarted, isolated worker lowers impact but does not erase a defect that repeats on demand.

### Retry storms and fail-open amplification

- **Check:** timeouts, dependency errors, partial processing, or health-check failures that trigger synchronized or unbounded retries without jitter, ceilings, circuit breaking, or deduplication.
- **Not a finding:** bounded retries with backoff.

### Poison records and head-of-line blocking

- **Check:** one malformed record or message that fails again and again at the front of a shared queue, partition, startup scan, migration, or recovery loop. Review skip and quarantine policy, offsets, and whether other tenants share the blocked unit.
- **Not a finding:** a consumer that moves failed records to a dead-letter queue after a bounded number of attempts.

### Unsafe recovery and capacity rollback

- **Check:** restart, restore, fallback, or cleanup paths that rebuild unbounded state, ignore current quotas, or restore the input that repeats the failure at once.
- **Not a finding:** recovery that applies current limits.

## Universal moves

- Build an input-to-resource table: earliest accepted size and cardinality, work before authentication, downstream fan-out, persistence, shared pool, limit and cleanup owner, and recovery.
- Compare aggregate limits with per-object limits. Ten thousand valid one-byte items can pass a per-message cap and still exhaust tenant-wide or process-wide state.
- A PoC runs only in an isolated fixture with strict CPU, memory, and time limits and a few small growth points. Mock external and paid calls. Stop once the missing bound or cancellation is observable.

## Validation rules

1. Name the untrusted input, the requester's work, the service amplification or retained resource, the shared blast radius, and the recovery. Missing limits without a concrete shared impact are hardening notes.
2. Confirm that no source-visible upstream, parser, queue, tenant, or framework bound stops the path. Unknown deployed controls require `needs_validation`.
3. For superlinear behavior, establish the accepted complexity and a bounded growth curve. For leaks, show repeatable retention after cleanup should run. For fatal paths, name the process or supervisor isolation.
4. Rank by low requester effort, unauthenticated reach, cross-tenant scope, persistence, and poor recovery. Never validate by causing an outage.
5. A confirmed claim needs a safe proof and a meaningful shared effect. Otherwise report `needs_validation` with the exact upstream limit, topology, quota, or recovery fact.

## Sources

- `third_party/security-audit-skill/skills/security-audit/RESOURCE-EXHAUSTION-AND-AVAILABILITY.md`, from cloudflare/security-audit-skill at commit `c1c8a8c` (MIT License, Copyright (c) 2025-2026 Cloudflare, Inc.).
- kalkan condensed and rewrote the text, adapted it to the kalkan verdict model and taxonomy, and removed the agent-orchestration instructions.
