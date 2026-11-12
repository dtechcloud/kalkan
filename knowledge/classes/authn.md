---
slug: authn
title_en: Authentication flaws
title_tr: Kimlik doğrulama hataları (authentication)
cwe: CWE-287, CWE-306, CWE-288, CWE-290, CWE-384, CWE-613, CWE-620, CWE-640, CWE-1390
owasp: A07:2021
sources: sast-skills, security-audit-skill, codecrucible, deepsec, open-code-review
---

## Summary

The server treats a request as a known user, or runs a non-public function, without valid proof of identity. Look for a missing or bypassable authentication gate, a broken session lifecycle and weak account recovery. The usual impact is account takeover or anonymous use of private functions.

## What it is

- **Missing authentication (CWE-306).** An anonymous request reaches a function that needs a user: private data, a state change, an admin action.
- **Alternate path (CWE-288).** A second door skips the gate: an old API version, an internal port, a debug or test route, an `x-test-*` header, or `if (env === "dev") return adminUser`.
- **Spoofed identity (CWE-290).** The server reads identity from client data: `X-User-Id`, an unsigned `uid` cookie, `X-Forwarded-For` in an IP allowlist, a client-certificate header from any peer.
- **Fail-open gate.** An error, a timeout or a missing setting leaves the user unset, but the handler still runs. A missing `await` on an async check has the same effect.
- **Broken credential check.** An empty password passes, PHP loose comparison makes `"0e1" == "0e2"` true, or the code compares the wrong field.
- **Session lifecycle.** The session ID stays the same across login and a fixation vector exists (CWE-384). Sessions or refresh tokens stay valid after logout, password change or account disable (CWE-613).
- **Recovery and account changes (CWE-640, CWE-620).** A reset token without user binding, expiry or single use. A token in the response body. A reset link built from the `Host` header. A password or email change without the current password.
- **MFA and step-up (CWE-1390).** A client calls the post-MFA step directly. A user enrolls or replaces a factor without fresh authentication. A challenge upgrades the wrong session.
- **API keys.** A prefix-only match, a key from another environment, or a revoked key that a cache still accepts.
- **Account enumeration (CWE-204).** Login, reset or signup responses differ for known and unknown accounts, and account existence is private. Alone, this is low severity.

## What it is not

- JWT signature, algorithm, key or claim checks → `jwt`.
- OAuth, OIDC or SAML flows (state, redirect_uri, ID token, assertion) → `oauth-oidc-saml`.
- An authenticated user calls an admin function → `missing-authz`. Another user's object → `idor`. Another tenant's data → `multi-tenant`.
- No rate limit or lockout on login, OTP or reset → `rate-limit-bruteforce`.
- A hardcoded password, API key or session signing secret → `hardcoded-secrets`.
- Weak password hashing, a non-crypto PRNG for tokens, a timing-unsafe compare → `crypto`.
- Missing cookie flags alone → `security-misconfig`. Credentials in logs, URLs or responses → `sensitive-data-exposure`.
- Cross-site use of the victim's cookie → `csrf`. Webhook signatures → `webhook-replay`.

## Where to look

First find the gate: app-wide middleware, a router-level mount, a route decorator, or a check in each handler. Then list every route outside the scope of the gate and every second door to the same function.

### Python (Django, Flask, FastAPI)
- Django: views without `@login_required` or `LoginRequiredMixin`. DRF `DEFAULT_PERMISSION_CLASSES` is `AllowAny` when the settings do not set it.
- Flask: `@login_required` written above `@app.route`. The route then registers the unwrapped view. Also `before_request` hooks with path exceptions.
- FastAPI: routes without an auth dependency. `OAuth2PasswordBearer` only extracts the token. Another dependency must verify it.

### JavaScript/TypeScript (Express, Next.js, NestJS)
- Express: routes registered before `app.use(auth)`. Auth middleware that calls `next()` in its `catch` block.
- Next.js: auth only in `middleware.ts` (matcher gaps, CVE-2025-29927 `x-middleware-subrequest`). Each `'use server'` export and each `route.ts` handler is a public endpoint and needs its own session check.
- NestJS: controllers without `@UseGuards`, or `@Public()` opt-outs from a global guard. tRPC: a `publicProcedure` that reads `ctx.session`.
- express-session: login without `req.session.regenerate()`.

### Java (Spring)
- `SecurityFilterChain`: wide `permitAll()` patterns, no `anyRequest().authenticated()`, path-matching gaps between the security matcher and the MVC router.
- `sessionFixation().none()`. A custom filter that builds the `Authentication` from a header.

### Go
- Routes on the root router or engine instead of the protected group. Handlers that read the user ID from a header.

### PHP (Laravel)
- Routes outside `Route::middleware('auth')`, or with `->withoutMiddleware(...)`.
- Plain PHP: login without `session_regenerate_id(true)`. `==` or `strcmp` on secrets instead of `hash_equals` or `password_verify`.

### Ruby (Rails)
- `skip_before_action :authenticate_user!`, wide `only:` or `except:` lists. A server-side session store without `reset_session` at login.

### C#/.NET (ASP.NET Core)
- `[AllowAnonymous]` on sensitive actions. Minimal API maps without `.RequireAuthorization()`. No `FallbackPolicy`.

## Safe patterns

- One gate runs before every handler. A short, explicit list names the public routes.
- Identity comes only from a verified session or token, never from headers or body fields.
- The gate fails closed: any error returns 401.
- Rotate the session ID at login, at MFA completion and at privilege change. Destroy the server session at logout.
- Reset tokens: 128 bits or more from a CSPRNG, stored hashed, bound to one user, short expiry, single use. Revoke all sessions after the reset. Build links from a configured base URL.
- A password or email change requires the current password or fresh authentication.

## Weak mitigations

- Auth only at the edge (Next.js middleware, proxy or WAF rules). A route that escapes the matcher has no gate.
- Hidden URLs, client-side route guards, a fixed "secret" header from the frontend.
- An IP allowlist that reads `X-Forwarded-For` without a trusted-proxy setting.
- Logout that only clears the client cookie.
- Session rotation on the password login path only, not on SSO, MFA or "remember me" paths.

## Verification checklist

- **attacker_control:** Name the entry point and the request that an anonymous or low-trust client sends. Quote the route registration and the gate mount, or the flawed check.
- **privilege_boundary:** Name the gain: acting as another user, or using a non-public function without credentials. A route that is public by design refutes it.
- **unmitigated:** Quote where the gate must be and what is there instead. Check router mounts, class decorators, global guards and framework defaults first.
- Session fixation needs a vector: a session ID from the URL, or a cookie that a sibling domain can set. Without a vector, report hardening only.
- Check the framework default before you claim a missing rotation. Django `login()`, Spring Security and Laravel `Auth::login` rotate the ID. express-session and plain PHP sessions do not.
- If the gate can be outside the given source (gateway, mesh, IaC), answer `unknown`, not `refuted`.

## Examples

### JavaScript/TypeScript (Express, Next.js, NestJS)
```js
// Vulnerable: identity comes from a client header
app.use((req, res, next) => { req.userId = req.get("x-user-id"); next(); });
```

```js
// Secure: identity comes from the server session, and the gate fails closed
app.use((req, res, next) => {
  if (!req.session.userId) return res.sendStatus(401);
  req.userId = req.session.userId;
  next();
});
```

### Python (Django, Flask, FastAPI)
```python
# Vulnerable: the reset token never expires and stays valid after use
user = User.objects.get(reset_token=token)
user.set_password(new_password)
user.save()
```

```python
# Secure: hashed, single-use, short-lived token
rec = ResetToken.objects.get(token_hash=sha256_hex(token), used=False, expires_at__gt=now())
rec.user.set_password(new_password)
rec.user.save()
rec.used = True
rec.save()  # then revoke the other sessions of the user
```

### PHP (Laravel)
```php
// Vulnerable (plain PHP): the session ID stays the same across login
if (password_verify($pw, $row['hash'])) { $_SESSION['uid'] = $row['id']; }
```

```php
// Secure
if (password_verify($pw, $row['hash'])) {
    session_regenerate_id(true);
    $_SESSION['uid'] = $row['id'];
}
```

## Dynamic test hints

- Use a local build only. Create two dummy accounts: `alice` (user) and `admin1` (admin). Never use real hosts, accounts or data.
- Missing gate: send the request with no cookie and no token. A 200 with private data or a state change confirms it.
- Spoofing: send `X-User-Id: <admin1 id>` or `X-Forwarded-For: 127.0.0.1` without credentials.
- Fixation: get an anonymous session ID, log in as alice with that cookie, and compare the ID before and after.
- Logout: save the cookie of alice, log out, then replay a request with the saved cookie. It must fail.
- Reset: use one token twice. Use an old token after a new one. Submit the token of alice with the email of `admin1`.
- Unit level: call the middleware with a fake request and a verifier that throws. The handler must not run.

## False positive traps

- A router-level or app-level gate covers the route, and the first pass missed it.
- The route is public by design: login, register, reset request, health, public catalog. Confirm that it returns no private data.
- A second mechanism authenticates the request, for example an API key checked in the handler.
- The framework rotates the session ID by default, or the session is a signed cookie with no server-side ID.
- "User not found" and "wrong password" differ only for public account names. This alone is not a finding.
- The code is test-only, or a build flag excludes it from production.

## Sources

Condensed and rewritten from the local copies under `third_party/`.

- `utkusen/sast-skills@db52227: sast-files/.claude/skills/sast-missingauth/SKILL.md` (MIT, Utku Sen): the unauthenticated-endpoint class, middleware order, route groups.
- `cloudflare/security-audit-skill@c1c8a8c: skills/security-audit/WEB-PROTOCOL-AND-AUTH.md` (MIT, Cloudflare): session fixation and invalidation, MFA, step-up, recovery, API keys, mTLS identity.
- `block/codecrucible@b5c8086: prompts/default/analysis_sections.yaml`, `prompts/default/cwe_deep_analysis.yaml` (CWE-287, CWE-306, CWE-384, CWE-640), `prompts/core/audit_families.yaml` (Apache-2.0, Block): framework defaults, validation checks, false positive indicators.
- `vercel-labs/deepsec@4fa6722: packages/processor/src/prompt/core.ts`, `slug-notes.ts`, `highlights.ts` (Apache-2.0, Vercel): auth bypass patterns, dev and test bypasses, framework gate notes.
- `alibaba/open-code-review@11ac6d4: internal/config/rules/rule_docs/php.md` (Apache-2.0, alibaba/open-code-review contributors): PHP comparison and secret-handling rules.
