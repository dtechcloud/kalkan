---
slug: request-smuggling-crlf-cache
title_en: Request smuggling / CRLF / cache poisoning
title_tr: Request smuggling / CRLF / cache poisoning
cwe: CWE-444, CWE-113
owasp: A03:2021, A04:2021
sources: security-audit-skill, codecrucible, deepsec, open-code-review
---

## Summary

Two HTTP components read the same bytes, header or cache key in different ways. A front end and a back end disagree about request boundaries. User text with CR or LF reaches a header or a log line. A shared cache stores a response under a key that misses an input. A finding names both components and the value that each side sees differently.

## What it is

- **Request framing disagreement (CWE-444).** A proxy, gateway or custom HTTP parser in the repository and the back end treat `Content-Length`, `Transfer-Encoding` or header normalization differently. Typical places: hand-written HTTP servers, custom reverse proxies, protocol downgrade layers, Lua or OpenResty code.
- **Header injection (CWE-113, CWE-93).** User text goes into `Location`, `Set-Cookie`, `Content-Disposition` or a custom header through an API that does not reject CR and LF. Mail headers built from user text have the same shape.
- **Log forging (CWE-117).** User text with line breaks goes into a plain-text log line and creates fake entries for readers or parsers.
- **Web cache poisoning.** A request input changes a cacheable response but is not part of the cache key. Common inputs: `X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Original-URL`, a query parameter that the cache ignores, `Host` used for absolute URLs.
- **Private responses in a shared cache.** An authenticated response gets a public `Cache-Control`, or a CDN rule caches by file extension while the app ignores the extension. Another user can then read the stored private page.
- **Path normalization differences.** A proxy checks a path rule, and the app normalizes the path differently (encoded slashes, `;` path parameters, `..` segments), so the rule does not apply.

## What it is not

- A user-controlled redirect target without CR or LF → `open-redirect`. A header value reflected into HTML → `xss`.
- `Host` header trusted for password reset links that no cache stores → `authn`.
- Application data caches (Redis, memory) keyed without user or tenant → `multi-tenant`.
- CORS origin reflection → `cors`. Missing security headers → `security-misconfig`.
- Sensitive data written to logs → `sensitive-data-exposure`. Only the line-break forging stays here.
- A server version with a known framing CVE → `vulnerable-dependency`.
- Outbound requests to attacker-chosen hosts → `ssrf`.

## Where to look

### Python

- Raw WSGI `start_response` headers and custom `http.server` handlers. Django raises `BadHeaderError` on line breaks.
- Flask-Caching `@cache.cached()` keys on the path only unless `query_string=True`. Django `cache_page` without the right `vary_on_headers`.
- `logging` with plain format strings that include user text.

### JavaScript/TypeScript

- Node `http` rejects CR and LF in header values. Check raw `socket.write` responses and custom proxies (`http-proxy`, `http-proxy-middleware`).
- `Cache-Control: public` or `s-maxage` on personalized routes, Next.js `headers()` rules, Workers `caches.default` keyed by the full URL.
- `console.log` of user text into plain-text log pipelines.

### Java/Kotlin

- `response.setHeader` or `addHeader` with user text on older containers. Spring Cloud Gateway or Zuul filters that copy or rewrite headers.
- Log patterns with `%m` and no CRLF encoding (Log4j2 `%enc{%m}{CRLF}`, Logback `%replace`).
- A replaced Spring Security `StrictHttpFirewall`. Tomcat `;` path parameters behind a proxy with path rules.

### Go

- `net/http` sanitizes line breaks in response header values. Check custom TCP servers and custom `httputil.ReverseProxy` directors that copy headers or set `Host`.
- `log.Printf("%s", userText)` in plain-text logs.

### PHP

- `header()` refuses line breaks in modern PHP. `mail()` additional headers built from user input do not.
- `error_log()` with user text. Session pages served through a shared cache.

### Ruby

- Header handling differs between Rack versions. Check the pinned version before you claim CR/LF injection.
- `expires_in ..., public: true` on authenticated actions. `Rails.logger` plain format with user text.

### C#/.NET

- Kestrel rejects control characters in response headers. Classic ASP.NET relies on `enableHeaderChecking`.
- `[ResponseCache(Location = ResponseCacheLocation.Any)]` on authenticated endpoints. YARP header transforms.

### Nginx, proxies and CDN config

- `proxy_cache` on locations with session content, `proxy_ignore_headers Cache-Control Set-Cookie`, cache rules by file extension.
- `proxy_cache_key` that misses `$host` or `$scheme` when the app varies on them. The default key uses `$proxy_host`, the upstream name, not the client `Host`.
- `proxy_set_header X-Forwarded-Host $http_x_forwarded_host` passes the client value through. `ignore_invalid_headers off`, `underscores_in_headers on`.
- Varnish `vcl_hash` without `Host` or cookie handling. Lua `ngx.shared` keys from `ngx.var.host` or `request_uri`.

## Safe patterns

- One standard HTTP stack end to end. No custom HTTP parsers. The edge rejects requests with both `Content-Length` and `Transfer-Encoding`, or with duplicate lengths, and forwards a normalized request.
- Framework header setters that reject CR and LF, plus encoding of user values (`encodeURIComponent` for redirect paths, RFC 6266 encoding for file names).
- Structured logs (JSON) or escaped line breaks for user text in log lines.
- Cache keys that include every input that changes the response, or an app that ignores unkeyed headers. Read `X-Forwarded-*` only when a trusted proxy overwrites it.
- `Cache-Control: private, no-store` on authenticated and personalized responses, including errors and redirects. Static assets from a dedicated path or domain. Unknown path suffixes return 404.
- `Vary` for each request header that changes the response.
- The proxy strips client copies of `X-Forwarded-*`, `X-Original-URL` and `X-Rewrite-URL`, then sets its own.

## Weak mitigations

- Removing `\n` but not `\r`, or filtering before a later URL-decoding step.
- `Cache-Control: private` on the main response only, while error and redirect responses stay cacheable.
- Cache rules by file extension.
- `Vary: User-Agent` to "fix" poisoning. It fragments the cache, but the unkeyed input stays.
- Trust in `X-Forwarded-Host` because "the proxy sets it", when the proxy appends instead of overwriting.

## Verification checklist

- **attacker_control:** Name the attacker-controlled part: a header, a path suffix, a query parameter or a body field. Show that it reaches the front end (proxy, CDN, cache) and the back end (app, parser, log reader) unchanged.
- **privilege_boundary:** Name the effect on other users: a poisoned cached response, a stored private response that the attacker can read, a bypassed front-end rule, or forged audit lines. An effect on the attacker's own requests only refutes this question.
- **unmitigated:** Quote both sides: the front-end parse or cache key (proxy config, cache rule, CDN rule in the repository) and the different back-end handling. Show that the runtime does not reject CR and LF for the pinned version. If the proxy or CDN config is not in the repository, use `needs_validation` and name the exact setting.
- For cache findings, show that the response is cacheable (status, `Cache-Control`, cache rule) and list the inputs that the key misses.

## Examples

### Python (Flask-Caching)

Vulnerable: the cache key ignores the query string, but the page depends on it.

```python
@app.get("/products")
@cache.cached(timeout=300)
def products():
    lang = request.args.get("lang", "en")
    return render_template("products.html", lang=lang)
```

Secure: the query string is part of the key, and only known values are accepted.

```python
@app.get("/products")
@cache.cached(timeout=300, query_string=True)
def products():
    lang = request.args.get("lang", "en")
    if lang not in {"en", "tr", "de"}:
        lang = "en"
    return render_template("products.html", lang=lang)
```

### JavaScript/TypeScript (Express behind a CDN)

Vulnerable: a personal response is marked as public for shared caches.

```ts
app.get("/api/me", requireUser, (req, res) => {
  res.set("Cache-Control", "public, max-age=600");
  res.json(profileOf(req.user));
});
```

Secure: shared caches must not store it.

```ts
app.get("/api/me", requireUser, (req, res) => {
  res.set("Cache-Control", "private, no-store");
  res.json(profileOf(req.user));
});
```

### Go (log forging)

Vulnerable: line breaks in the user name create extra log lines.

```go
log.Printf("login failed for %s", r.FormValue("user"))
```

Secure: a structured logger escapes the value.

```go
slog.Warn("login failed", "user", r.FormValue("user"))
```

### PHP (mail headers)

Vulnerable: the sender address goes into the headers without a check.

```php
mail($to, $subject, $body, "From: " . $_POST["email"]);
```

Secure: accept one valid address without line breaks.

```php
$from = filter_var($_POST["email"] ?? "", FILTER_VALIDATE_EMAIL);
if ($from === false || preg_match("/[\r\n]/", $from)) {
    http_response_code(400);
    exit;
}
mail($to, $subject, $body, ["Reply-To" => $from]);
```

## Dynamic test hints

- Header setters: in a unit test with the framework test client, set a header from a value that contains a line break. Record whether the framework raises an error or sends one header.
- Logs: write logs to a temporary file in the test, log a dummy value with a line break, and count the lines.
- Cache keys: prove them from configuration and code. If the compose file of the target contains the cache or proxy, compare two responses on the internal sandbox network for two dummy users.
- Framing disagreements: prove them statically by naming both parsers, their versions and their settings. Do not send crafted framing requests. If proof needs the real proxy chain, use `needs_validation`.
- Never test against deployed systems, shared caches or CDNs.

## False positive traps

- Runtimes that reject or clean CR and LF in header values: Node.js `http`, Go `net/http`, Kestrel, modern servlet containers, PHP `header()`, Django. Quote the version.
- User values that the code URL-encodes before the header set.
- JSON logs that escape line breaks.
- Responses that no shared cache stores: `private`, `no-store`, responses with `Set-Cookie` under default CDN rules, POST responses.
- An "unkeyed" header that is in the key, or that the app never reads.
- A single server with no proxy or cache in the repository. A framing claim needs two parsers.
- Reflected `X-Forwarded-Host` in an uncached response is not cache poisoning.

## Sources

Condensed and rewritten by kalkan. Vendored copies and pinned commits: `third_party/MANIFEST.json`.

- cloudflare/security-audit-skill@c1c8a8c (MIT, Cloudflare): `skills/security-audit/WEB-PROTOCOL-AND-AUTH.md` (request framing, cache poisoning, cache deception, forwarded headers, response-header injection, validation rules), `CLIENT-SIDE.md` (service-worker cache identity), `DATA-ISOLATION-AND-LIFECYCLE.md` (cache ACL drift).
- block/codecrucible@b5c8086 (Apache-2.0, Block): `prompts/default/cwe_deep_analysis.yaml` (CWE-113, CWE-117), `prompts/default/analysis_sections.yaml` (cross_site header injection, data_exposure log injection), `prompts/core/audit_families.yaml` (output), `prompts/exploit-proof-web-java/cwe_deep_analysis.yaml` (CWE-117).
- vercel-labs/deepsec@4fa6722 (Apache-2.0, Vercel): `packages/scanner/src/matchers/cache-key-poisoning.ts`, `cache-key-scope.ts`, `lua-shared-dict-poisoning.ts`, `packages/processor/src/prompt/slug-notes.ts`, `highlights.ts` (Workers cache keys).
- alibaba/open-code-review@11ac6d4 (Apache-2.0, alibaba/open-code-review contributors): `internal/config/rules/rule_docs/php.md`, `go.md` (header and redirect boundaries).
- Added by kalkan from general knowledge: runtime header validation behavior, Flask-Caching key default, Nginx `proxy_cache_key` default, PHP `mail()` header note.
