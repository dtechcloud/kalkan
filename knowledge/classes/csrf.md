---
slug: csrf
title_en: CSRF
title_tr: CSRF
cwe: CWE-352, CWE-1385
owasp: A01:2021
sources: security-audit-skill, codecrucible, deepsec, open-code-review, sast-skills
---

## Summary

A browser attaches ambient credentials (session cookie, HTTP basic auth, client certificate) to a request that another site starts. If a state-changing endpoint has no effective anti-CSRF control, the attacker changes state as the victim. Cross-site WebSocket hijacking is the same flaw on a WebSocket upgrade.

## What it is

- **Unprotected state change.** A cookie-authenticated `POST`, `PUT`, `PATCH` or `DELETE` without a CSRF token, an Origin check or an effective SameSite cookie.
- **State change on GET.** `GET /account/delete` or `GET /transfer?to=...`. SameSite=Lax still sends the cookie on a top-level GET navigation.
- **Protection turned off.** `@csrf_exempt`, `csrf.exempt`, `VerifyCsrfToken::$except`, `skip_forgery_protection`, `csrf().disable()` with session cookies, `[IgnoreAntiforgeryToken]`.
- **Token flaws.** The token is not bound to the session, the server checks it only when present, or one token serves all users. A double-submit cookie is unsigned, and a sibling subdomain can set it.
- **Content-type gaps.** A JSON route also parses `text/plain`, form or multipart bodies. A browser sends these as simple requests without a preflight.
- **Method override.** A form field like `_method=DELETE` turns a cross-site POST into a protected verb.
- **Same-site attackers.** A request from `evil.example.com` to `app.example.com` is same-site. SameSite does not stop it when an attacker controls any subdomain.
- **Login CSRF.** The attacker logs the victim into the account of the attacker. Report it only when it has impact, for example saved payment data or uploads.
- **Cross-site WebSocket hijacking (CWE-1385).** The upgrade accepts the session cookie without an Origin check or a channel token.

## What it is not

- Requests that authenticate only with a bearer token in the `Authorization` header. The attacker page cannot set it.
- A CORS policy that lets another origin read credentialed responses → `cors`.
- A missing OAuth `state` → `oauth-oidc-saml`. Missing frame protection (clickjacking) → `security-misconfig`.
- Same-origin requests issued by injected script → `xss`. Webhooks without signatures → `webhook-replay`.
- CSRF on a GET logout is a nuisance. Do not report it.

## Where to look

List every cookie-authenticated state change, including form, JSON, multipart, method-override and legacy routes. Read the session cookie settings where the cookie is set. Then read the CSRF middleware, its route coverage and its exemptions.

### Python (Django, Flask, FastAPI)
- Django: `CsrfViewMiddleware` is on by default. Look for `@csrf_exempt`, wide `CSRF_TRUSTED_ORIGINS`, `SESSION_COOKIE_SAMESITE = None`. DRF enforces CSRF only inside `SessionAuthentication`. A custom class that reads the session cookie skips it.
- Flask and FastAPI have no CSRF protection by default. Look for Flask-WTF `CSRFProtect` and `@csrf.exempt`, and cookie-based auth in FastAPI.

### JavaScript/TypeScript (Express, Next.js, NestJS)
- Express and NestJS have no CSRF protection by default, and `csurf` is deprecated. Look for `express.text()` or `urlencoded()` parsers on JSON routes.
- Next.js Server Actions compare `Origin` with `Host`. Check `serverActions.allowedOrigins`. Route handlers (`route.ts`) have no CSRF check.
- WebSockets: `ws` or Socket.IO servers without an Origin check in `verifyClient` or `allowRequest`.

### Java (Spring)
- Spring Security enables CSRF by default. `csrf().disable()` or `ignoringRequestMatchers(...)` with a session cookie is a finding. WebSocket `setAllowedOrigins("*")`.

### Go
- No default protection. Look for gorilla/csrf, nosurf, or `http.CrossOriginProtection` (Go 1.25). gorilla/websocket `CheckOrigin` that returns `true`.

### PHP (Laravel)
- `VerifyCsrfToken` covers the `web` group. Check `$except` or `validateCsrfTokens(except: ...)`. Routes in `api.php` that use the session guard. WordPress: `admin_post_*` and `wp_ajax_*` handlers without `check_admin_referer` or `wp_verify_nonce`.

### Ruby (Rails)
- `ActionController::Base` protects by default. `ActionController::API` has no protection, so cookie auth there is a finding. Also `skip_forgery_protection` and `match ... via: :all`.

### C#/.NET (ASP.NET Core)
- Razor Pages validate antiforgery tokens by default. MVC controllers need `[ValidateAntiForgeryToken]` or a global `AutoValidateAntiforgeryTokenAttribute`. Also `[IgnoreAntiforgeryToken]` and `DisableAntiforgery()`.

## Safe patterns

- A synchronizer token per session, or a signed double-submit token bound to the session. The server checks it on every state change, for every content type.
- An exact Origin allowlist or a `Sec-Fetch-Site` check on state-changing requests.
- Session cookies with `SameSite=Lax` or `Strict`, and the `__Host-` prefix.
- No state change on GET or HEAD.
- WebSocket upgrades with an exact Origin allowlist and a channel token.

## Weak mitigations

- A Referer check that accepts a missing Referer. An Origin check with `includes` or `startsWith`.
- A JSON content type that only the client sends, while the server parses any body.
- A token in HTML forms, but no check on AJAX or JSON routes.
- A missing SameSite attribute. Browser defaults differ, and some browsers allow a top-level POST shortly after the cookie is set.
- CORS as a CSRF defense. CORS controls reads. It does not stop simple requests.
- A custom-header check, when the CORS policy allows that header from any origin with credentials.

## Verification checklist

- **attacker_control:** Name the ambient credential, the route and the cross-site request shape that carries the cookie. Shapes: a form POST, a top-level GET, a `no-cors` fetch with a `text/plain` body.
- **privilege_boundary:** Name the state change done as the victim: password or email change, payment, membership, deletion. Logout and cosmetic preferences are below the reporting floor.
- **unmitigated:** Quote the session cookie settings, the CSRF middleware and its exemptions, and the route. Name the missing check.
- `SameSite=Strict`, or `Lax` on a non-GET route, refutes the finding for modern browsers. The exception is a same-site attacker origin.
- Bearer-only authentication refutes the finding.
- If a proxy or deployment config sets the cookie attributes and you cannot see it, answer `unknown`.

## Examples

### Python (Django, Flask, FastAPI)
```python
# Vulnerable: CSRF check removed on a cookie-authenticated state change
@csrf_exempt
@login_required
def change_email(request):
    request.user.email = request.POST["email"]
    request.user.save()
```

```python
# Secure: keep the default middleware check, accept POST only
@require_POST
@login_required
def change_email(request): ...
```

### JavaScript/TypeScript (Express, Next.js, NestJS)
```js
// Vulnerable: GET changes state, cookie session, no token
app.get("/account/delete", requireSession, deleteAccount);
```

```js
// Secure: POST with a session-bound token and an Origin check
app.post("/account/delete", requireSession, checkOrigin(["https://app.example.test"]), csrfCheck, deleteAccount);
```

### Java (Spring)
```java
// Vulnerable: session-cookie app with CSRF turned off
http.csrf(csrf -> csrf.disable()).formLogin(Customizer.withDefaults());
```

```java
// Secure: default CSRF, cookie repository for an SPA
http.csrf(csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()));
```

## Dynamic test hints

- Run the app at `http://localhost:3000` and an attacker page at `http://127.0.0.1:4000`. These are different sites. Use dummy accounts `alice` (victim) and `mallory` (attacker) and local hosts only.
- Log in as `alice`. Open the attacker page in the same browser. The page auto-submits `<form method="POST" action="http://localhost:3000/account/email">` with `email=mallory@example.test`. Check whether the email changed.
- JSON route: `fetch(url, { method: "POST", mode: "no-cors", credentials: "include", headers: { "Content-Type": "text/plain" }, body: '{"email":"m@example.test"}' })`.
- GET route: `<img src="http://localhost:3000/account/delete">`.
- WebSocket: `new WebSocket("ws://localhost:3000/ws")` from the attacker page. Check whether the server accepts the cookie of alice.
- Without a browser: send the request through the framework test client with the session cookie of alice, no token and `Origin: http://evil.test`. Expect 403.

## False positive traps

- The route authenticates only with a bearer token or an API key header.
- The session cookie is `SameSite=Lax` or `Strict`, and the route is not GET.
- The framework protection is on by default, and the route has no exemption.
- The route is read-only, or the change is a logout or a preference.
- The route requires a custom header, and CORS does not allow it cross-origin with credentials.
- A login CSRF without impact on data or actions.

## Sources

Condensed and rewritten from the local copies under `third_party/`.

- `cloudflare/security-audit-skill@c1c8a8c: skills/security-audit/WEB-PROTOCOL-AND-AUTH.md` (ordinary CSRF, CSRF validation rule), `CLIENT-SIDE.md` (cross-site WebSocket) (MIT, Cloudflare).
- `block/codecrucible@b5c8086: prompts/default/analysis_sections.yaml` (CSRF decision tree), `prompts/default/cwe_deep_analysis.yaml` and `prompts/carlini-curated/cwe_deep_analysis.yaml` (CWE-352), `prompts/carlini-curated/security_analysis_base.yaml` (GET logout rule) (Apache-2.0, Block).
- `vercel-labs/deepsec@4fa6722: packages/processor/src/prompt/highlights.ts`, `slug-notes.ts` (Apache-2.0, Vercel): Django `@csrf_exempt`, Laravel `$except`, Razor Pages, SvelteKit and Clojure anti-forgery notes.
- `alibaba/open-code-review@11ac6d4: internal/config/rules/rule_docs/php.md` (Apache-2.0, alibaba/open-code-review contributors): ambient credentials as the CSRF condition.
- `utkusen/sast-skills@db52227: sast-files/.claude/skills/sast-jwt/SKILL.md` (MIT, Utku Sen): JWT cookies without SameSite routed to CSRF.
