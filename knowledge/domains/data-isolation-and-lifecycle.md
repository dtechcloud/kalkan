---
name: data-isolation-and-lifecycle
title: Data isolation and data lifecycle
classes: multi-tenant, idor, sensitive-data-exposure
when_to_use: The target stores multi-tenant or access-controlled data, keeps derived copies (cache, search, analytics, exports, backups), or promises deletion, revocation, or retention.
sources: third_party/security-audit-skill/skills/security-audit/DATA-ISOLATION-AND-LIFECYCLE.md
---

# Data isolation and data lifecycle

Use this pack when the target stores multi-tenant or access-controlled data, builds search, index, cache, or analytics copies, issues object links, exports or restores records, migrates schemas, or promises deletion, revocation, and retention. Follow one data item through every copy and every state change. Split a large target by primary storage, cache and search, object storage, analytics and logs, export and backup, deletion and revocation, and migration. Related packs: `cloud-and-deployment` (provider storage policy) and the `idor` and `multi-tenant` class packs (endpoint-level checks).

## Core discipline

- A tenant or owner field on a record is not isolation. Find the query, key, path, policy, or row-level control that enforces it on each read and write path.
- Trace derived copies. Safe primary data can become unsafe in search, cache, analytics, exports, previews, logs, replicas, and backups, which often have other ACL and retention rules.
- Deletion and revocation are lifecycle promises. Check current, historical, cached, indexed, exported, restored, and queued copies within the product's stated boundary.
- A privacy or retention preference is not automatically a vulnerability. Require an explicit access boundary or a deletion or revocation promise, plus an unauthorized reader or a later operation.
- Use `needs_validation` when external storage policy, retention settings, CDN behavior, replica lag, or backup access decides the claim.

## Attack classes

### Missing tenant or owner enforcement

- **Check:** read, update, delete, list, count, and bulk queries that select an object without binding it to the authenticated tenant or owner, or that take that identity from body fields. Compare direct lookups, nested relationships, background jobs, admin tools, imports, and legacy paths.
- **Not a finding:** a lookup that a row-level policy, default scope, or ownership join already restricts, when that control is visible on this path.

### Composite-key and namespace collision

- **Check:** cache keys, object paths, unique constraints, search document IDs, temporary files, and deduplication keys that omit the tenant or environment. Two principals can then overwrite or read the same logical key, even though the records have separate owners.
- **Not a finding:** keys that include a server-derived tenant or a random component that no other principal can produce.

### Policy and query disagreement

- **Check:** row-level policies, ORM default scopes, authorization filters, and raw or bypass clients that apply different predicates. Check joins, aggregates, aliases, views, transactions, `unscoped` or service clients, and error paths where the request context is missing.
- **Not a finding:** a bypass client that only trusted maintenance code uses, with no request-controlled selector.

### Blob and signed-reference overreach

- **Check:** object keys, attachment IDs, version IDs, share links, or signed URLs that allow operations or namespaces beyond the issuing principal's access, or that stay valid after the underlying ACL changes. A signed reference must bind the operation, the exact object and version, the audience, the expiry, and the tenant.
- **Not a finding:** an intentionally public link to public content.

### Search, cache, and index ACL drift

- **Check:** ACL or lifecycle changes on a primary record that do not invalidate a searchable, cached, embedded, thumbnail, feed, preview, or index copy. Check filtering at retrieval time as well as at ingestion and invalidation.
- **Not a finding:** a derived copy that the read path filters with the current ACL.

### Analytics, logs, traces, and diagnostics as alternate readers

- **Check:** private content or credentials sent to systems with broader access, longer retention, or tenant mixing. Confirm the data class and a realistic reader.
- **Not a finding:** field names, public identifiers, or operator-only content under the intended policy.

### Enumeration and aggregate oracles

- **Check:** counts, filters, sort order, errors, unique constraints, timing, notifications, or existence checks that disclose protected object or account state. Name one confidential predicate and the observable difference.
- **Not a finding:** general response variance, or existence of a public account.

### Export and backup scope expansion

- **Check:** exports, snapshots, portability packages, reports, or backups that include other tenants, hidden fields, soft-deleted data, secret values, or history above the requester's access. Check per-item authorization after selection, and authorization to download the final artifact.
- **Not a finding:** an export that applies the same per-item authorization as the read API.

### Import and restore authority expansion

- **Check:** restore or import paths that skip owner, schema, ACL, uniqueness, or validation rules, overwrite existing resources, or create records in a tenant that the requester cannot write. Treat archive contents as untrusted and authorize the resulting operation.
- **Not a finding:** an import that runs each record through the normal create path.

### Migration default and ownership confusion

- **Check:** old records without tenant, ACL, or lifecycle fields, colliding legacy IDs, and partial rollouts where new and old readers apply different defaults. Review backfill, dual read and write, compatibility, rollback, and resumed migrations.
- **Not a finding:** a migration that sets a safe default (deny or owner-only) for missing fields.

### Backup and replication boundary drift

- **Check:** encryption keys, storage accounts, cross-region replicas, restore environments, or support snapshots with broader identity or tenant scope than the primary data.
- **Not a finding:** a claim that only hosted access settings can decide. Source confirms in-repo policy only, so the rest is `needs_validation`.

### Soft-delete and tombstone bypass

- **Check:** direct lookups, search, relation traversal, object links, background processors, or restores that ignore the lifecycle predicate and return or act on deleted or revoked records. Check whether a deleted identifier can be registered again while references still exist.
- **Not a finding:** a soft-deleted record that only administrators can see by design.

### Stale authorization in derived state

- **Check:** membership removal, ACL updates, consent withdrawal, secret revocation, or role downgrades that do not invalidate sessions, caches, subscriptions, jobs, or materialized data that keep authorizing later operations.
- **Not a finding:** a short, documented cache lifetime that the product accepts, without a concrete later unauthorized operation.

### Retention and queued-work overrun

- **Check:** deletion that completes in primary storage while queued processors, retries, exports, analytics, or generated artifacts recreate or keep the data beyond the promised boundary. Look for idempotent deletion and tombstone propagation.
- **Not a finding:** retention that the product documents and promises.

### Restore reintroduces invalid state

- **Check:** backup, undo, undelete, or replica recovery that restores data, credentials, memberships, or permissions that current policy no longer allows. Restored state must be authorized again, and changes made after the snapshot must apply again.
- **Not a finding:** a restore that re-applies current authorization.

## Universal moves

- Pick one protected record. Draw its primary write, query, cache, index, event, export, backup, deletion, and restore paths. Mark the principal and the tenant at every edge.
- Compare two dummy tenants through the same service methods. Repeat after an ACL change, a deletion, an account switch, and a restore.
- Start at bypass clients, background jobs, migrations, global unique constraints, and cache keys. These paths often lack the request-scoped identity that interactive endpoints carry.

## Validation rules

1. Name the lower-trust principal, the protected data or state, the affected owner or tenant, the alternate copy or operation, and the unauthorized disclosure or change.
2. Cite both the intended source-of-truth policy and the path that omits it or disagrees with it. Confirm that no other layer enforces the same tenant or lifecycle condition.
3. A local check uses two dummy tenants and non-sensitive fixtures and stops at the first record or operation that crosses scope. Never use real user data.
4. When external cache, object storage, replica, analytics, backup, or retention policy decides the claim, report `needs_validation` with the owner-observed check.
5. A confirmed claim needs complete lineage and a concrete boundary impact. Otherwise name the unresolved storage, ACL, invalidation, retention, or restore fact.

## Sources

- `third_party/security-audit-skill/skills/security-audit/DATA-ISOLATION-AND-LIFECYCLE.md`, from cloudflare/security-audit-skill at commit `c1c8a8c` (MIT License, Copyright (c) 2025-2026 Cloudflare, Inc.).
- kalkan condensed and rewrote the text, adapted it to the kalkan verdict model, and removed the agent-orchestration instructions.
