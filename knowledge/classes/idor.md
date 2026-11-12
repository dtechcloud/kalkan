---
slug: idor
title_en: IDOR / BOLA
title_tr: IDOR / BOLA
cwe: CWE-639, CWE-566
owasp: A01:2021
sources: sast-skills, security-audit-skill, codecrucible, deepsec, open-code-review
---

## Summary

The server uses a client-supplied identifier to read or change an object, but it does not check that the caller may use that object. User A changes an ID and reaches the data of user B. APIs call this Broken Object Level Authorization (BOLA). The ID can be in the path, the query, the body, a header or a GraphQL argument.

## What it is

- **Lookup without an owner predicate.** `findById(req.params.id)`, `Order.objects.get(id=...)`, `findUnique({ where: { id } })`, `SELECT ... WHERE id = ?`.
- **Existence check used as an access check.** A 404 for a missing row is not an ownership check.
- **Write side open.** Reads check the owner, but update, delete or restore do not.
- **Nested resources.** The code checks the parent, but not that the child belongs to it: `/projects/1/files/999`, where file 999 is in project 2.
- **ID in two places.** The check uses the path ID, and the query uses a body ID, a duplicate parameter or a header.
- **Bulk and batch.** The code checks only the first ID, or the batch as a whole.
- **Indirect objects.** Downloads by file ID, attachment IDs, export job IDs, GraphQL `node(id:)`, WebSocket channels of another user.
- **Foreign references in writes.** A new object points to an object of another user. Examples: a comment on a private document, an item moved into a foreign folder, a foreign `payment_method_id`.
- **Acting user from the body.** `user_id` comes from the request instead of the session.

## What it is not

- Attacker and victim are in different tenants and the tenant predicate is missing → `multi-tenant`.
- No login at all → `authn`. A normal user reaches an admin function → `missing-authz`.
- Objects that are public by design are not findings.
- Tampering with `role`, `price` or `owner_id` fields → `mass-assignment` or `business-logic`.
- `?id=1 OR 1=1` → `sqli`. A file path in the ID → `path-traversal`.
- Sequential IDs alone are not a finding. They raise the severity of a real IDOR.

## Where to look

Find every handler that takes an object ID. For each resource type, write down the ownership predicate: `owner_id`, `created_by`, or membership through a join table. Then check that the predicate is part of the query, or that a check runs between the fetch and the use.

### Python (Django, Flask, FastAPI)
- Django: `Model.objects.get(pk=...)` and `get_object_or_404(Model, pk=...)` without a user filter. DRF: `get_queryset()` that returns `.all()`.
- DRF runs `has_object_permission` only when the view calls `get_object()`. A custom view that fetches the row itself skips it.
- SQLAlchemy: `session.get(Model, id)` and `query.get(id)` without an owner filter.

### JavaScript/TypeScript (Express, Next.js, NestJS)
- Mongoose `findById`, `findByIdAndUpdate`, `findByIdAndDelete`. Prisma `findUnique`, `update` and `delete` with `where: { id }` only. Sequelize `findByPk`. TypeORM `findOneBy({ id })`.
- Next.js `page.tsx` server components and route handlers that load an object from `params.id`. GraphQL resolvers for `node(id:)`.

### Java (Spring)
- Spring Data `findById`, `getReferenceById`, `deleteById` with a path variable. No `@PostAuthorize` or ownership check in the service.

### Go
- GORM `db.First(&order, id)`, or SQL `WHERE id = $1` without `AND owner_id = $2`.

### PHP (Laravel)
- Route model binding (`show(Order $order)`) loads any ID. Authorize it with a policy or `can:` middleware. `scopeBindings()` scopes a child to its parent only, not to the user.

### Ruby (Rails)
- `Model.find(params[:id])` instead of `current_user.models.find(params[:id])`. Pundit without `policy_scope` on index actions.

### C#/.NET (ASP.NET Core)
- `_db.Orders.FindAsync(id)` without resource-based `AuthorizeAsync(User, order, policy)`.

## Safe patterns

- Scope the query to the caller: `WHERE id = ? AND owner_id = ?`, `current_user.orders.find(id)`, `findFirst({ where: { id, userId } })`.
- Or fetch the object and call a policy before any use or response.
- Apply the same check to read, update, delete and export, and to each item of a bulk request.
- Check that IDs in the body that reference other objects belong to the caller.
- Take the acting user ID from the session, never from the request.
- Return 404 for both "missing" and "not yours".

## Weak mitigations

- UUIDs, hashids or other hard-to-guess IDs without a check. IDs leak in URLs, logs, emails and other responses.
- Filtering in the frontend.
- A check on the parent but not on the child, or on the list endpoint but not on the detail endpoint.
- A rate limit on the endpoint.

## Verification checklist

- **attacker_control:** Quote where the ID enters and the fetch that uses it. Show how the attacker gets a victim ID: sequential values, IDs in other responses, shared links. Hard-to-guess IDs lower the severity but do not refute.
- **privilege_boundary:** Name the gain: read of private data, update, delete, or a low-impact action like a comment on a record the attacker cannot read.
- **unmitigated:** Quote the fetch and the use. Between them, quote the owner comparison or the scoped query, or state that none exists. Check default scopes, row-level security and policy middleware.
- If the same gap appears on one resource type through several verbs, report one finding and list the routes.
- If authorization can run in a service layer that you cannot see, answer `unknown`.

## Examples

### JavaScript/TypeScript (Express, Next.js, NestJS)
```js
// Vulnerable: any logged-in user reads any invoice
const inv = await prisma.invoice.findUnique({ where: { id: req.params.id } });
```

```js
// Secure: the query includes the owner
const inv = await prisma.invoice.findFirst({ where: { id: req.params.id, userId: req.user.id } });
if (!inv) return res.sendStatus(404);
```

### Python (Django, Flask, FastAPI)
```python
# Vulnerable
order = get_object_or_404(Order, pk=order_id)
```

```python
# Secure
order = get_object_or_404(Order, pk=order_id, user=request.user)
```

### PHP (Laravel)
```php
// Vulnerable: route model binding loads any order
public function show(Order $order) { return $order; }
```

```php
// Secure: policy check before use
public function show(Order $order) { Gate::authorize('view', $order); return $order; }
```

### Ruby (Rails)
```ruby
# Vulnerable
@doc = Document.find(params[:id])
```

```ruby
# Secure
@doc = current_user.documents.find(params[:id])
```

## Dynamic test hints

- Use a local build with two dummy accounts, `alice` and `bob`. Never use real users or data.
- Basic shape: alice sends `POST /api/orders` and gets `{"id": 101}`. Bob sends `GET /api/orders/101` with his own cookie. Expect 404 or 403.
- Repeat with `PATCH /api/orders/101` and `DELETE /api/orders/101` as bob. Check that the order of alice is unchanged.
- Body reference: bob sends `POST /api/comments {"doc_id": <private doc of alice>}`. Expect a rejection.
- Bulk: bob sends `POST /api/orders/bulk-delete {"ids": [<bob order>, 101]}`. Order 101 must survive.
- Unit level: call the service function with the context of bob and the object ID of alice.

## False positive traps

- The query goes through a scoped relation (`current_user.orders`), a default scope or row-level security.
- The object is public or shared with all users by design.
- The handler uses only the ID of the caller, for example `/api/me`.
- A policy middleware or a decorator on the class performs the check.
- The route is admin-only, and the guard requires the admin role.

## Sources

Condensed and rewritten from the local copies under `third_party/`.

- `utkusen/sast-skills@db52227: sast-files/.claude/skills/sast-idor/SKILL.md` (MIT, Utku Sen): IDOR IS / IS NOT lists, prevention patterns, stack examples, edge cases.
- `cloudflare/security-audit-skill@c1c8a8c: skills/security-audit/ATTACK-CLASSES.md`, `DATA-ISOLATION-AND-LIFECYCLE.md` (MIT, Cloudflare): bulk and export checks, alternate access paths, signed references.
- `block/codecrucible@b5c8086: prompts/default/analysis_sections.yaml` (access control audit), `prompts/default/cwe_deep_analysis.yaml` (CWE-639, CWE-862), `prompts/carlini-curated/cwe_deep_analysis.yaml` (CWE-639) (Apache-2.0, Block): existence-check trap, duplicate rule, severity factors.
- `vercel-labs/deepsec@4fa6722: packages/processor/src/prompt/slug-notes.ts`, `core.ts` (Apache-2.0, Vercel): user-supplied IDs in lookups, route parameter manipulation.
- `alibaba/open-code-review@11ac6d4: internal/config/rules/rule_docs/prisma.md` (Apache-2.0, alibaba/open-code-review contributors): owner relations and constraints in the schema.
