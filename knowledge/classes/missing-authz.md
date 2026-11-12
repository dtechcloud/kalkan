---
slug: missing-authz
title_en: Missing authorization
title_tr: Eksik yetkilendirme (missing authorization)
cwe: CWE-862, CWE-285, CWE-863, CWE-269, CWE-425
owasp: A01:2021
sources: sast-skills, security-audit-skill, codecrucible, deepsec, open-code-review
---

## Summary

An authenticated caller runs a function that needs a higher role or a specific permission, because the server does not check that permission. This is vertical privilege escalation: a normal user calls an admin, owner or operator function. Look for login-only checks, checks on some paths but not on others, and roles that come from the request.

## What it is

- **Login-only gate on a privileged function.** User and role management, settings, feature flags, impersonation, data exports for all users, billing for all accounts, job triggers, cache purges.
- **Inconsistent checks.** The role check exists on `GET` but not on `POST`, `PUT` or `DELETE`. It exists on the REST route but not on the GraphQL mutation, RPC method, WebSocket event, Server Action, bulk endpoint or older API version.
- **Wrong check (CWE-863).** An inverted condition, `||` instead of `&&`, or the wrong role or permission name. Also a check after the side effect, or an async check without `await`. A pending promise is always truthy.
- **Role from the request.** `req.body.role`, an `X-Role` header, `?admin=true`, or an unsigned cookie field like `role=admin`.
- **Self-escalation (CWE-269).** A member changes roles, sends invites with the owner role, or approves an elevated request, and the code checks only membership.
- **Fail-open policy.** The helper returns `true` on an error or an unknown action. A feature flag turns the check off. An OPA/Rego policy has no `default allow := false`.

## What it is not

- No authentication at all on a function that needs a user → `authn` (CWE-306).
- One user reaches the object of another user → `idor`. Data of another tenant → `multi-tenant`.
- A role field written through request binding on an ordinary update → `mass-assignment`.
- A forged or unverified token → `jwt`. A violated business rule (limits, workflow order) → `business-logic`.
- Framework diagnostic endpoints (actuator, pprof, profiler) open by config → `security-misconfig`.
- Solidity `onlyOwner` or role modifiers → `smart-contract`. Cloud IAM policies → `iac-cloud-container`. Exported mobile components and local IPC → `mobile-desktop-ipc`.

## Where to look

Build the authorization model first: the roles, the permission names, the policy layer, and where each check runs. Then list the privileged functions: paths like `/admin`, `/internal`, `/manage`, and operations on other users, settings, money or all records. For each function, find the check on every HTTP method and every transport.

### Python (Django, Flask, FastAPI)
- Django: `@permission_required`, `@user_passes_test`, `PermissionRequiredMixin`, `is_staff` checks. DRF: `IsAuthenticated` where `IsAdminUser` or a custom permission is needed, `@action` methods that override `permission_classes`.
- Flask: custom `admin_required` decorators and their order. FastAPI: role dependencies, router-level `dependencies=[...]`.

### JavaScript/TypeScript (Express, Next.js, NestJS)
- Express: role middleware on the router, and routes mounted outside it. Next.js: Server Actions and route handlers need a role check inside the function.
- NestJS: a typical `RolesGuard` returns `true` when the handler has no `@Roles()` metadata. tRPC: `protectedProcedure` where `adminProcedure` is needed. GraphQL: resolvers and field directives.

### Java (Spring)
- `@PreAuthorize` does nothing without `@EnableMethodSecurity` (older: `@EnableGlobalMethodSecurity(prePostEnabled = true)`). `@Secured` also needs `securedEnabled = true`. Method security does not apply to self-invocation or private methods.
- `requestMatchers(...)` order: the first match wins, so an earlier broad rule shadows `hasRole("ADMIN")`.

### Go
- Handlers mounted on the user group instead of the admin group. A Casbin or policy `Enforce` result that the code ignores.

### PHP (Laravel)
- Missing `can:` middleware, `Gate::authorize` or `$this->authorize`. A `Gate::before` callback that returns `true` too often. Symfony: `#[IsGranted]` and `access_control` order.
- WordPress: `is_admin()` only tells that an admin page loads. It is not a capability check. Use `current_user_can()`.

### Ruby (Rails)
- `before_action :require_admin, only: [...]` lists that omit actions. Pundit without `after_action :verify_authorized`. CanCanCan `authorize!` missing in custom actions.

### C#/.NET (ASP.NET Core)
- `[Authorize]` without `Roles` or `Policy` on admin actions. `[AllowAnonymous]` overrides. Policy handlers that call `context.Succeed` on every path.

## Safe patterns

- Deny by default. A global policy requires a named permission for each route. Public and login-only routes opt out explicitly.
- Attach role checks to the route group or controller class, before any side effect.
- One authorization service serves every transport: REST, GraphQL, RPC, jobs, Server Actions.
- Load roles and permissions from the server-side user record, never from the request.
- Tests call each privileged route as a normal user and expect 403.

## Weak mitigations

- Hidden admin links, disabled buttons, role checks in the SPA only.
- A check that `req.user` exists, used as an admin check.
- A path-prefix string compare in middleware. Case, trailing slashes, encoded characters and `/api/v2/admin` bypass it.
- A role check on the page loader, but not on the action or API that the page calls.
- An obscure URL or an "internal" flag in the request.

## Verification checklist

- **attacker_control:** Name the lowest role that can reach the function (any user, member, viewer) and the request that it sends. Quote the route and its guards.
- **privilege_boundary:** Name the privileged capability gained. Quote the guard if the route already requires exactly that role, because that refutes the finding.
- **unmitigated:** Quote where the role check must be and what is there instead. Check class-level annotations, router groups, global policies, method security setup and the service layer.
- Compare sibling handlers. A check that exists on siblings but not on this handler is a strong signal.
- Report a missing role model for one function family once, and list the routes as evidence.
- If the check can live in a service layer or gateway that you cannot see, answer `unknown`.

## Examples

### JavaScript/TypeScript (Express, Next.js, NestJS)
```js
// Vulnerable: login check only
router.delete("/admin/users/:id", auth, async (req, res) => {
  await User.deleteOne({ _id: req.params.id });
  res.sendStatus(204);
});
```

```js
// Secure: role from the server-side user record
const requireAdmin = (req, res, next) => (req.user.role === "admin" ? next() : res.sendStatus(403));
router.delete("/admin/users/:id", auth, requireAdmin, deleteUser);
```

### Python (Django, Flask, FastAPI)
```python
# Vulnerable: any logged-in user can change roles
class RoleView(APIView):
    permission_classes = [IsAuthenticated]
```

```python
# Secure
class RoleView(APIView):
    permission_classes = [IsAuthenticated, IsAdminUser]
```

### Java (Spring)
```java
// Vulnerable: any authenticated user
@Secured("ROLE_USER")
@PostMapping("/api/admin/flags")
public void setFlag(@RequestBody Flag f) { flags.save(f); }
```

```java
// Secure (method security enabled with @EnableMethodSecurity)
@PreAuthorize("hasRole('ADMIN')")
@PostMapping("/api/admin/flags")
public void setFlag(@RequestBody Flag f) { flags.save(f); }
```

## Dynamic test hints

- Use a local build. Create two dummy accounts: `alice` (normal user) and `admin1` (admin). Never test real systems.
- Call each privileged route with the session of alice. Expect 403. Repeat for every method, the GraphQL mutation, the RPC method and each API version.
- Add client role hints: `X-Role: admin`, `?admin=true`, `"role": "admin"` in the body. The result must not change.
- Request shape: `DELETE /admin/users/<admin1 id>` with the cookie of alice. A 204 confirms the finding.
- Unit level: call the handler with a request context for a normal user and assert a 403 or an exception.

## False positive traps

- The check sits on the controller class, the router group or a global policy.
- The function is open to all authenticated users by design, for example shared workspace settings.
- The service method that the handler calls performs the role check.
- A gateway enforces the role, and the repository config shows it.
- The route is an admin route used only by admins, and the guard requires that role.

## Sources

Condensed and rewritten from the local copies under `third_party/`.

- `utkusen/sast-skills@db52227: sast-files/.claude/skills/sast-missingauth/SKILL.md` (MIT, Utku Sen): broken function-level authorization, prevention patterns, per-method checks, examples.
- `cloudflare/security-audit-skill@c1c8a8c: skills/security-audit/ATTACK-CLASSES.md` (MIT, Cloudflare): access control questions, weaker parallel paths, bulk and export checks.
- `block/codecrucible@b5c8086: prompts/default/analysis_sections.yaml` (authorization model), `prompts/default/cwe_deep_analysis.yaml` (CWE-862), `prompts/core/audit_families.yaml` (authorization family, privilege_boundary refutation) (Apache-2.0, Block).
- `vercel-labs/deepsec@4fa6722: packages/processor/src/prompt/core.ts`, `slug-notes.ts`, `highlights.ts` (Apache-2.0, Vercel): negated checks, framework guards, Server Actions, GraphQL resolvers, tRPC.
- `alibaba/open-code-review@11ac6d4: internal/config/rules/rule_docs/rego.md`, `php.md`, `solidity.md` (Apache-2.0, alibaba/open-code-review contributors): default-deny policy, client-side-only authorization, routing to the smart-contract class.
