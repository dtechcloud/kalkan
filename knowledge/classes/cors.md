---
slug: cors
title_en: CORS misconfiguration
title_tr: CORS yapılandırması
cwe: CWE-942, CWE-346
owasp: A01:2021, A05:2021
sources: codecrucible, deepsec, security-audit-skill
---

## Summary

The server tells browsers that another origin may read its responses with the credentials of the user. A malicious page then reads private data, tokens or CSRF tokens from the session of the victim. The dangerous shape is a reflected or weakly matched `Origin` together with `Access-Control-Allow-Credentials: true` on a sensitive, cookie-authenticated response.

## What it is

- **Origin reflection with credentials.** The response copies the request `Origin` into `Access-Control-Allow-Origin` (ACAO) and sends `Access-Control-Allow-Credentials: true`. Common forms:
  - Express `cors({ origin: true, credentials: true })`, or an `origin` callback that always allows.
  - Spring `allowedOriginPatterns("*")` with `allowCredentials(true)`.
  - ASP.NET Core `SetIsOriginAllowed(_ => true).AllowCredentials()`.
  - nginx `add_header Access-Control-Allow-Origin $http_origin`, and Go code that copies the header.
- **"All origins" settings that reflect.** Some libraries echo the origin when all origins and credentials are on. Examples: Starlette or FastAPI `allow_origins=["*"]` with `allow_credentials=True`, and django-cors-headers `CORS_ALLOW_ALL_ORIGINS` with `CORS_ALLOW_CREDENTIALS`. Laravel `allowed_origins => ['*']` with `supports_credentials => true` behaves the same. Confirm the behavior of the installed version.
- **Weak origin matching.** `endsWith("example.com")` passes `evilexample.com`. `startsWith("https://example.com")` passes `https://example.com.evil.test`. Also `includes`, unanchored regexes and unescaped dots.
- **The `null` origin.** Sandboxed iframes and `data:` documents send `Origin: null`. Allowing it with credentials lets any page read.
- **Over-trusted origins.** A wildcard subdomain rule with credentials, while users can host script on a subdomain. Credentialed trust for `http://` origins, which a network attacker can inject into.
- **Network-gated data.** `ACAO: *` on an intranet or localhost service whose only protection is its network position. Any page in the browser of an employee can read it.

## What it is not

- A literal `ACAO: *` with credentials. Browsers reject this combination, so it is not exploitable. Do not report it, unless the library turns it into reflection.
- `ACAO: *` without credentials on public data, or on an API that uses bearer tokens.
- Cross-site requests that change state → `csrf`. CORS controls reads. It does not stop simple requests.
- WebSocket Origin checks → `csrf`. `postMessage` without an origin check → `xss` when the data reaches a DOM sink.
- A reflected ACAO without `Vary: Origin` that poisons a shared cache → `request-smuggling-crlf-cache`.
- Bucket CORS rules in IaC → `iac-cloud-container`. Other security headers → `security-misconfig`.

## Where to look

Find every place that sets ACAO: CORS middleware, manual headers, reverse proxy and gateway config, serverless config. Read the credential setting and the matching logic. Then check what the responses contain and whether they authenticate with cookies.

### Python (Django, Flask, FastAPI)
- django-cors-headers: `CORS_ALLOW_ALL_ORIGINS`, `CORS_ALLOWED_ORIGIN_REGEXES`, `CORS_ALLOW_CREDENTIALS`.
- Starlette or FastAPI `CORSMiddleware(allow_origins=..., allow_origin_regex=..., allow_credentials=...)`. Flask-CORS `supports_credentials=True` with wide `origins`.

### JavaScript/TypeScript (Express, Next.js, NestJS)
- `cors()` options: `origin: true`, callbacks, regexes. NestJS `app.enableCors(...)`. Next.js `headers()` in `next.config.js` and middleware that sets ACAO. Socket.IO and Apollo `cors` options.

### Java (Spring)
- `CorsConfiguration.setAllowedOriginPatterns`, `@CrossOrigin(originPatterns = ...)`, `addCorsMappings`, Spring Cloud Gateway `globalcors`.

### Go
- rs/cors or gin-contrib/cors `AllowOriginFunc` that returns `true`. Handlers that set ACAO from `r.Header.Get("Origin")`.

### PHP (Laravel)
- `config/cors.php`: `allowed_origins`, `allowed_origins_patterns`, `supports_credentials`. Plain PHP that echoes `$_SERVER['HTTP_ORIGIN']`.

### Ruby (Rails)
- rack-cors raises an error for `origins '*'` with `credentials: true`. Look for `origins` with a regex like `/.*/` or a block that returns `true`.

### C#/.NET (ASP.NET Core)
- `AddCors` policies with `SetIsOriginAllowed` or `SetIsOriginAllowedToAllowWildcardSubdomains`. `AllowAnyOrigin()` with `AllowCredentials()` is rejected by the framework.

## Safe patterns

- An exact allowlist of full origins (scheme, host, port), compared with string equality.
- Credentials only for the origins that need them. Send `Vary: Origin` when ACAO varies.
- No `null`, no `http://` origins and no user-content subdomains on credentialed endpoints.
- Bearer tokens for cross-origin APIs where possible.

## Weak mitigations

- `endsWith`, `startsWith`, `includes`, an unanchored regex, or a regex with unescaped dots.
- A denylist of known bad origins.
- An origin check in the preflight handler only. Simple GET requests still get the header.
- An allowlist that contains a development origin like `http://localhost:3000` in production.

## Verification checklist

- **attacker_control:** Quote the config or code that sets ACAO. Give the exact attacker origin that passes, for example `https://example.com.evil.test` or `null`.
- **privilege_boundary:** Name the private response data that the attacker page reads with the credentials of the victim: profile data, tokens, API keys, a CSRF token. Public data gives no boundary crossing.
- **unmitigated:** Show three facts: credentials are allowed, the endpoint authenticates with a cookie, and the browser sends that cookie cross-site (`SameSite=None`). Quote each one.
- A session cookie with `SameSite=Lax` or `Strict` is not sent on a cross-site fetch. Then only same-site attacker origins remain, for example a user-content subdomain.
- If a proxy, gateway or CDN sets the headers and you cannot see its config, answer `unknown`.

## Examples

### JavaScript/TypeScript (Express, Next.js, NestJS)
```js
// Vulnerable: reflects any origin with credentials
app.use(cors({ origin: true, credentials: true }));

// Vulnerable: unanchored regex, "https://app.example.test.evil.test" passes
app.use(cors({ origin: /https:\/\/app\.example\.test/, credentials: true }));
```

```js
// Secure: exact allowlist
const allowed = new Set(["https://app.example.test"]);
app.use(cors({ origin: (o, cb) => cb(null, allowed.has(o)), credentials: true }));
```

### Python (Django, Flask, FastAPI)
```python
# Vulnerable: Starlette echoes the origin for cookie requests in this setting
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)
```

```python
# Secure
app.add_middleware(CORSMiddleware, allow_origins=["https://app.example.test"], allow_credentials=True)
```

### Java (Spring)
```java
// Vulnerable
config.setAllowedOriginPatterns(List.of("*"));
config.setAllowCredentials(true);
```

```java
// Secure
config.setAllowedOrigins(List.of("https://app.example.test"));
config.setAllowCredentials(true);
```

## Dynamic test hints

- Use a local build and a dummy account `alice`. Never send requests to real systems.
- Header check: send `GET /api/me` with the session cookie of alice and `Origin: https://evil.test`. A response with `Access-Control-Allow-Origin: https://evil.test` and `Access-Control-Allow-Credentials: true` confirms the policy flaw.
- Try more origins: `null`, `https://app.localhost.evil.test`, `https://evilapp.localhost`, `http://app.localhost`.
- Browser check (optional): an attacker page at `http://127.0.0.1:4000` runs `fetch("http://localhost:3000/api/me", { credentials: "include" })` and reads the body. This works only when the cookie is sent cross-site.
- Unit level: call the origin callback or the middleware with each origin and assert the header value.

## False positive traps

- A literal `*` with credentials. The browser rejects it.
- The response holds public data, or the API authenticates with a bearer token only.
- The session cookie is `SameSite=Lax` or `Strict`, and no same-site attacker origin exists.
- An exact allowlist applies, and the first pass misread it.
- The permissive config is development-only, and the production config overrides it. Quote both.

## Sources

Condensed and rewritten from the local copies under `third_party/`.

- `block/codecrucible@b5c8086: prompts/default/analysis_sections.yaml` (configuration: CORS, CWE-942), `prompts/carlini-curated/security_analysis_base.yaml` (do-not-report rule for `*` with credentials), `prompts/carlini-curated/cwe_deep_analysis.yaml` (CWE-352 CORS notes) (Apache-2.0, Block).
- `vercel-labs/deepsec@4fa6722: packages/processor/src/prompt/slug-notes.ts`, `highlights.ts`, `packages/scanner/src/matchers/cors-wildcard.ts` (Apache-2.0, Vercel): `origin: true` with credentials, nginx reflection, Spring `@CrossOrigin`.
- `cloudflare/security-audit-skill@c1c8a8c: skills/security-audit/CLIENT-SIDE.md` (credentialed CORS trust), `ATTACK-CLASSES.md` (obvious-things list) (MIT, Cloudflare).
- Library behavior for "all origins" with credentials (Starlette, django-cors-headers, Laravel, rack-cors, ASP.NET Core) and the SameSite interaction come from general knowledge. Confirm them against the installed version.
