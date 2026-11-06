---
slug: multi-tenant
title_en: Multi-tenant isolation
title_tr: Kiracı izolasyonu (multi-tenant isolation)
cwe: CWE-284
owasp: A01:2021
sources: security-audit-skill, sast-skills, codecrucible, deepsec, open-code-review
---

## Summary

Data or actions of one tenant (organization, workspace, account, team) reach a principal of another tenant. The tenant boundary is missing in a query, a key, a cache, a job, a policy or a derived copy. A tenant field on a record is not isolation. Isolation is the query, key, path or policy that enforces the field on every read and write.

## What it is

- **Tenant from the request.** `X-Tenant-Id`, `orgId` in the body or query, or the subdomain selects the tenant, and the code does not check membership against the session.
- **Missing tenant predicate.** A lookup, list, count, search, report, bulk update or bulk delete without `tenant_id = <session tenant>`.
- **Bypass clients.** Raw SQL, `unscoped`, `withoutGlobalScopes()`, `IgnoreQueryFilters()`, a Supabase `service_role` key in a user route, or a Salesforce `without sharing` class.
- **Row-level security gaps.** PostgreSQL RLS with a `USING (true)` policy, or an app role that bypasses RLS: the table owner without `FORCE ROW LEVEL SECURITY`, a `BYPASSRLS` role or a superuser.
- **Tenant context leaks.** A tenant session variable set with `SET` on a pooled connection, or a schema switch that the next request inherits.
- **Shared keys and namespaces.** Cache keys, object storage paths, search document IDs, queue names, temp files or unique constraints without the tenant ID.
- **Background work.** Jobs, webhooks, consumers and schedulers that lose the tenant context or trust a tenant ID from the payload.
- **Derived copies.** Search indexes, analytics, exports, backups, previews and embeddings that keep old ACLs or mix tenants.
- **Lifecycle.** Removed members keep access through sessions, API keys or caches. Invites that are not bound to the invited identity. Restore or import into another tenant.
- **Real-time channels.** Socket rooms or broadcasts that are not scoped to the tenant of the subscriber.

## What it is not

- Two users of the same tenant, owner check missing → `idor`. A role inside the tenant → `missing-authz`.
- A `tenant_id` field written through request binding → `mass-assignment`.
- Bucket, IAM or network policy of the cloud provider → `iac-cloud-container`.
- Unkeyed request headers that poison a shared cache → `request-smuggling-crlf-cache`.
- OIDC issuer checks for a multi-tenant IdP (for example Entra ID `common`) → `oauth-oidc-saml`.
- Personal data in logs without a cross-tenant reader → `sensitive-data-exposure`.

## Where to look

Find how a request gets its tenant: a session claim, a membership table, the subdomain. Find the enforcement layer: an ORM scope, RLS, a repository wrapper. Then list every path that skips that layer: raw queries, admin and service clients, jobs, caches, search, exports and migrations.

### Python (Django, Flask, FastAPI)
- DRF `get_queryset()` without `request.user.org` filtering. Custom managers (`objects` and `all_objects`). Celery tasks that take `org_id` from the payload.
- django-tenants: queries against the public schema, and code that sets the schema from request data.

### JavaScript/TypeScript (Express, Next.js, NestJS)
- Prisma extensions or middleware that add `tenantId`, and `$queryRaw` calls that skip them. Supabase RLS policies and the `service_role` key in server routes.
- Next.js `unstable_cache` keys without the tenant. tRPC or NestJS context that reads `orgId` from input. Socket.IO room names.

### Java (Spring)
- A `CurrentTenantIdentifierResolver` that reads a header. Hibernate `@Filter` does not apply to `find()` or `get()` by primary key.

### Go
- Repository functions that take an `orgID` argument from the request. Middleware that puts a header value in the context as the tenant.

### PHP (Laravel)
- Eloquent global scopes and `withoutGlobalScopes()`. `DB::table()` queries skip Eloquent scopes. Tenant packages that identify the tenant from a header or domain.

### Ruby (Rails)
- acts_as_tenant: `ActsAsTenant.without_tenant` and `unscoped`. Apartment: schema switches that leak across threads or requests.

### C#/.NET (ASP.NET Core)
- EF Core `HasQueryFilter` with `IgnoreQueryFilters()` call sites. Tenant resolvers that trust a host or header without a membership check.

## Safe patterns

- Derive the tenant from the authenticated session and the membership table. Check membership before any tenant switch.
- Enforce isolation in one layer that every path uses: RLS with `FORCE ROW LEVEL SECURITY`, an ORM global scope, or a repository that requires a tenant argument.
- Fail closed when the tenant context is missing.
- Put the tenant ID in every composite key: cache keys, object paths, search document IDs, unique constraints, queue routing.
- Set tenant variables per transaction (`SET LOCAL`), not per pooled connection.
- Pass the tenant to jobs from server-side state, and check membership again in the consumer.
- Revoke sessions, API keys and cache entries when a member leaves.

## Weak mitigations

- A tenant column without query enforcement.
- Hiding other tenants in the UI, or a tenant picker that only lists own tenants.
- A subdomain or host that selects the tenant without a membership check.
- An ORM scope that raw queries, admin clients or `unscoped` calls skip.
- RLS enabled while the app connects as the table owner or as a `BYPASSRLS` role.
- A cache key with the user ID but no tenant ID, when one user belongs to several tenants.

## Verification checklist

- **attacker_control:** Name the tenant of the attacker and the input or path that reaches another tenant: header, object ID, cache key, job payload. Quote where it enters.
- **privilege_boundary:** Name the data or action of the other tenant. Cross-tenant access is a boundary crossing, even when both principals are authenticated.
- **unmitigated:** Quote the intended enforcement (scope, RLS policy, filter) and the path that skips it or disagrees with it. Confirm that no other layer applies the same predicate.
- Check the database role and the RLS settings before you accept RLS as a control.
- If storage, CDN, replica or backup policy is outside the repository, answer `unknown`.

## Examples

### JavaScript/TypeScript (Express, Next.js, NestJS)
```js
// Vulnerable: the tenant comes from a header
const projects = await prisma.project.findMany({ where: { orgId: req.get("x-org-id") } });
```

```js
// Secure: the tenant comes from a checked membership
const m = await prisma.membership.findFirst({ where: { userId: req.user.id, orgId: req.params.orgId } });
if (!m) return res.sendStatus(404);
const projects = await prisma.project.findMany({ where: { orgId: m.orgId } });
```

### Python (Django, Flask, FastAPI)
```python
# Vulnerable: no tenant filter in the viewset
def get_queryset(self):
    return Invoice.objects.all()
```

```python
# Secure
def get_queryset(self):
    return Invoice.objects.filter(org=self.request.user.active_org)
```

### C#/.NET (ASP.NET Core)
```csharp
// Vulnerable: the global tenant filter is turned off on a user path
var docs = await _db.Documents.IgnoreQueryFilters().Where(d => d.Id == id).ToListAsync();
```

```csharp
// Secure: the HasQueryFilter tenant filter stays on
var doc = await _db.Documents.FirstOrDefaultAsync(d => d.Id == id);
```

## Dynamic test hints

- Use a local build with two dummy tenants, `T1` and `T2`, and users `alice@T1` and `bob@T2`. Never use real tenant data.
- Header and ID swap: bob sends `GET /api/projects` with `X-Org-Id: T1`, and `GET /api/projects/<T1 project id>`. Expect 403 or 404.
- Host switch: bob calls `http://t1.localhost:<port>/api/projects` with his own session. Expect a rejection.
- Cache: alice loads a cached dashboard, then bob loads the same route. Bob must see only T2 data.
- Jobs: bob starts an export with `{"org_id": "T1"}`. Expect a rejection, and no T1 rows in the file.
- Lifecycle: remove alice from T1, then replay her saved cookie and API key. Expect 403.
- Unit level: call the repository with a T2 context and a T1 object ID.

## False positive traps

- RLS with `FORCE ROW LEVEL SECURITY`, or a global scope, applies to this exact path. Quote it.
- The tenant comes from a verified session claim, not from the header that the first pass saw.
- The data is shared reference data by design, for example a global catalog.
- The app has only one tenant. Then owner checks belong to `idor`.
- Platform operators have cross-tenant access through a checked operator role.

## Sources

Condensed and rewritten from the local copies under `third_party/`.

- `cloudflare/security-audit-skill@c1c8a8c: skills/security-audit/DATA-ISOLATION-AND-LIFECYCLE.md` (MIT, Cloudflare): tenant enforcement, composite keys, policy and query disagreement, derived copies, lifecycle, dummy-tenant tests.
- `utkusen/sast-skills@db52227: sast-files/.claude/skills/sast-idor/SKILL.md` (MIT, Utku Sen): tenant scoping as a prevention pattern.
- `block/codecrucible@b5c8086: prompts/default/cwe_deep_analysis.yaml` (CWE-639, CWE-862) (Apache-2.0, Block): database-level isolation as a refutation.
- `vercel-labs/deepsec@4fa6722: packages/processor/src/prompt/core.ts`, `slug-notes.ts`, `highlights.ts` (Apache-2.0, Vercel): cross-tenant IDs, tenant cache keys, socket rooms, `without sharing`.
- `alibaba/open-code-review@11ac6d4: internal/config/rules/rule_docs/prisma.md` (Apache-2.0, alibaba/open-code-review contributors): tenant relations and constraints.
- PostgreSQL RLS bypass rules, pooled-connection leaks and Hibernate filter limits come from general knowledge.
