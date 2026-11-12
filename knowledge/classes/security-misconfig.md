---
slug: security-misconfig
title_en: Security misconfiguration
title_tr: Güvenlik yapılandırma hataları (misconfiguration)
cwe: CWE-16
owasp: A05:2021
sources: codecrucible, security-audit-skill, deepsec, open-code-review
---

## Summary

An application, framework or web server setting weakens a security control on a reachable production path. Examples: debug mode on, an open debug or admin surface, an insecure default, a security check behind a flag that fails open, missing cookie or header protection. A missing header or flag alone is hardening. It becomes a finding when you can name the attack it enables and the asset at risk.

## What it is

- **Debug mode in production.** Django `DEBUG = True`, Flask `debug=True` (the Werkzeug console runs code), Laravel `APP_DEBUG=true`, Symfony `APP_ENV=dev`, ASP.NET `UseDeveloperExceptionPage()` outside Development, Rails `consider_all_requests_local = true`, PHP `display_errors = On`.
- **Open debug and admin surfaces.** Spring Boot Actuator (`/actuator/env`, `/heapdump`, `/jolokia`), Go `net/http/pprof` and `expvar` on the public mux, the H2 console, Django debug toolbar, admin consoles without authentication.
- **Fail-open switches.** A security check behind a feature flag that defaults off. `if (process.env.SKIP_AUTH)` treats the string `"false"` as true. Bypass headers such as `x-test-user` honored in production code. A check that the code skips when a config value is missing.
- **Insecure defaults.** Django `ALLOWED_HOSTS = ["*"]`, Express `trust proxy` set to `true` for every hop, static file serving from the project root (it serves `.env` and `.git`), world-writable files (CWE-732).
- **Session cookie flags (CWE-614, CWE-1004).** No `Secure` on a session cookie, no `HttpOnly` where XSS can steal it, `SameSite=None` without a need.
- **Missing protection headers (CWE-693, CWE-1021).** No `frame-ancestors` or `X-Frame-Options` on a page with a one-click sensitive action. No HSTS on a site with credentials.
- **Web server rules.** Nginx and Apache settings that drop security headers, serve hidden files or expose status pages.

## What it is not

- IaC, cloud, Kubernetes, container and Terraform settings → `iac-cloud-container`. CI workflow settings → `supply-chain-cicd`.
- CORS → `cors`. TLS versions, ciphers and certificate checks → `crypto`. XML parser features → `xxe`.
- GraphQL introspection, playground, depth and batching limits → `graphql`.
- Missing body size limits and timeouts → `dos-redos`. Cache rules and cache keys → `request-smuggling-crlf-cache`.
- Literal default passwords or keys → `hardcoded-secrets`.
- Data that code writes to responses or logs → `sensitive-data-exposure`. Directory listing (CWE-548) also goes there.
- A route without authentication in code → `authn` or `missing-authz`. Disabled CSRF protection → `csrf`.
- An Nginx `alias` path traversal → `path-traversal`. Missing rate limits → `rate-limit-bruteforce`.

## Where to look

### Python

- `settings/production.py` and settings modules: `DEBUG`, `ALLOWED_HOSTS`, `SECURE_*`, `SESSION_COOKIE_SECURE`, `CSRF_COOKIE_SECURE`, `X_FRAME_OPTIONS`.
- Flask `app.run(debug=True, host="0.0.0.0")`, `app.config["DEBUG"]`, `FLASK_DEBUG` in deploy files.

### JavaScript/TypeScript

- `NODE_ENV` handling, `helmet()` presence and options, `express-session` cookie options, `app.set("trust proxy", true)`, `express.static(__dirname)`.
- Environment flags read as truthy strings. Next.js `headers()` in `next.config.js`.

### Java/Kotlin

- Spring Security `permitAll()` on `/actuator/**`, `headers().frameOptions().disable()`, Tomcat manager apps, `web.xml` security constraints.

### Go

- `import _ "net/http/pprof"` registers handlers on `http.DefaultServeMux`. A public server with a `nil` handler then serves `/debug/pprof/`.
- `expvar` on the public mux. Cookies with `Secure: false` or `HttpOnly: false`.

### PHP

- `php.ini`: `display_errors`, `expose_php`, `session.cookie_secure`, `session.cookie_httponly`, `session.use_strict_mode`.
- `.env` `APP_DEBUG` and `APP_ENV`, WordPress `WP_DEBUG_DISPLAY`, `.htaccess` rules.

### Ruby

- `config/environments/production.rb`: `consider_all_requests_local`, `force_ssl`, `config.hosts`, session store options.

### C#/.NET

- `Program.cs` environment checks around `UseDeveloperExceptionPage`, `UseHsts` and `UseHttpsRedirection`. Cookie `SecurePolicy`, `HttpOnly`, `SameSite`.
- `web.config`: `customErrors mode="Off"`, `compilation debug="true"`, `httpCookies requireSSL`.

### Spring Boot properties

- `management.endpoints.web.exposure.include=*`, `management.endpoint.env.show-values=ALWAYS`, `management.server.port` on a public interface.
- `spring.h2.console.enabled=true` with `spring.h2.console.settings.web-allow-others=true`.
- `server.error.include-stacktrace=always`, `server.error.include-message=always`, `server.servlet.session.cookie.secure=false`, `debug=true`.

### Nginx

- An `add_header` line in a `location` drops every `add_header` inherited from the `server` block. Check the headers per location.
- No `location ~ /\.` deny rule (serves `.git` and `.env`). `real_ip_header X-Forwarded-For` with `set_real_ip_from 0.0.0.0/0` makes client IPs spoofable.
- `server_tokens on` is a banner only.

### Apache

- `<Location /server-status>` without `Require local` leaks URLs with tokens and client addresses.
- `AllowOverride All` in upload folders. `ServerSignature On` and `TraceEnable On` are hardening notes.

## Safe patterns

- Per-environment settings with secure defaults. Debug stays off unless an explicit dev flag is on. Startup fails when a required security setting is missing.
- Actuator: expose `health` (and `info`) only, protect `/actuator/**`, or bind the management port to an internal interface.
- pprof and expvar on a separate internal listener, not on the public mux.
- Session cookies with `Secure`, `HttpOnly`, `SameSite=Lax` or `Strict`, the `__Host-` prefix and a narrow `Domain` and `Path`.
- One middleware for all responses: CSP with `frame-ancestors`, HSTS, `X-Content-Type-Options: nosniff`, `Referrer-Policy` (helmet, Django `SecurityMiddleware`, Spring Security headers).
- Nginx: repeat the security headers in each location that adds headers (for example with an `include` snippet). Deny hidden files.
- Trust forwarded headers only from known proxy addresses or a fixed hop count.
- Parse boolean flags explicitly (`=== "true"`). Keep bypass code out of production builds.

## Weak mitigations

- A hidden or unlinked debug URL, or a menu item removed from the UI.
- "The deploy sets `NODE_ENV`" when the repository shows no such setting. Use `needs_validation`, do not refute.
- `X-XSS-Protection` as an XSS defense. Browsers ignore it.
- A WAF or edge rule as the only control in front of Actuator or pprof.
- IP allowlists that read `X-Forwarded-For` from any client.
- A CSP with `unsafe-inline`, `unsafe-eval` or wildcard sources.

## Verification checklist

- **attacker_control:** Show that the attacker reaches the surface on the production path. Evidence: the route is in the production build, the port is public in the deploy config, or the setting is active for the production profile. If only the deployment can tell, use `needs_validation` and name the setting.
- **privilege_boundary:** Name the attack and the asset: code execution (Werkzeug console, H2 console, Jolokia), secrets from `/actuator/env` or a heap dump, session theft over HTTP, clickjacking of a named action. No sensitive asset or action refutes this question.
- **unmitigated:** Quote the setting. Show that no later override removes it on the production path (environment file, environment variable, security filter, localhost binding).
- Resolve the final config for the production profile: base file, profile file, then environment variables.
- Check framework defaults for the pinned version. For example, Spring Boot 2.5 and later expose only `health` over HTTP.

## Examples

### Python (Django settings)

Vulnerable: the production settings turn on debug pages and accept any Host.

```python
DEBUG = True
ALLOWED_HOSTS = ["*"]
```

Secure: secure values unless the environment asks for debug.

```python
DEBUG = os.environ.get("DJANGO_DEBUG") == "1"
ALLOWED_HOSTS = os.environ["DJANGO_ALLOWED_HOSTS"].split(",")
```

### Spring Boot properties

Vulnerable: all Actuator endpoints are on the public port.

```properties
management.endpoints.web.exposure.include=*
```

Secure: only health, on an internal port.

```properties
management.endpoints.web.exposure.include=health
management.server.port=9091
management.server.address=127.0.0.1
```

### Go

Vulnerable: the blank import puts pprof on the public default mux.

```go
import _ "net/http/pprof"

func main() { log.Fatal(http.ListenAndServe(":8080", nil)) }
```

Secure: the public server uses its own mux, and pprof listens on localhost.

```go
import _ "net/http/pprof"

func main() {
	go func() { log.Println(http.ListenAndServe("127.0.0.1:6060", nil)) }()
	log.Fatal(http.ListenAndServe(":8080", appMux))
}
```

### Nginx

Vulnerable: the `add_header` in the location drops the server-level headers.

```nginx
server {
    add_header Content-Security-Policy "frame-ancestors 'none'" always;
    location /account/ {
        add_header Cache-Control "no-store";
        proxy_pass http://app;
    }
}
```

Secure: the location includes the shared header set again.

```nginx
location /account/ {
    include snippets/security-headers.conf;
    add_header Cache-Control "no-store";
    proxy_pass http://app;
}
```

## Dynamic test hints

- Load the settings module with the production environment from the repository deploy files (dummy values). Print the effective values, such as `DEBUG` and the exposed endpoints.
- App level (compose): start the service with the production profile on the internal network. Request `/actuator/env`, `/debug/pprof/` or a missing page, and record the status and a short body marker.
- Flags: a unit test with `SKIP_AUTH="false"` shows whether the bypass branch runs.
- Nginx and Apache are not in the sandbox image list. Prove their findings statically with the exact blocks.
- Never scan or probe deployed hosts.

## False positive traps

- Development-only files (`settings/dev.py`, `docker-compose.override.yml`, `.env.example`, `application-dev.properties`) that the production config does not load.
- Debug flags behind an environment check that the production config sets (quote it).
- Missing frame or CSP headers on JSON APIs, or on public pages without a sensitive action: hardening.
- `Server` and `X-Powered-By` banners: informational at most.
- A cookie without `HttpOnly` that JavaScript must read by design and that holds no session, such as a double-submit CSRF cookie.
- Actuator with `health` and `info` only, or a management port bound to localhost.

## Sources

Condensed and rewritten by kalkan. Vendored copies and pinned commits: `third_party/MANIFEST.json`.

- block/codecrucible@b5c8086 (Apache-2.0, Block): `prompts/default/analysis_sections.yaml` (configuration, cross_site), `prompts/core/audit_families.yaml` (exposure), `prompts/default/cwe_deep_analysis.yaml` (CWE-1021, CWE-209), `prompts/carlini-curated/security_analysis_base.yaml` (do-not-report list).
- cloudflare/security-audit-skill@c1c8a8c (MIT, Cloudflare): `skills/security-audit/ATTACK-CLASSES.md` (obvious things), `WEB-PROTOCOL-AND-AUTH.md` (cookie scope, host trust), `CLIENT-SIDE.md` (clickjacking), `CLOUD-AND-DEPLOYMENT.md` (development values in production).
- vercel-labs/deepsec@4fa6722 (Apache-2.0, Vercel): `packages/scanner/src/matchers/debug-endpoint.ts`, `session-cookie-config.ts`, `security-behind-flag.ts`, `env-var-as-bool.ts`, `test-header-bypass.ts`, `response-header-leak.ts`, `packages/processor/src/prompt/slug-notes.ts`, `highlights.ts`.
- alibaba/open-code-review@11ac6d4 (Apache-2.0, alibaba/open-code-review contributors): `internal/config/rules/rule_docs/php.md`, `properties.md`, `default.md`.
- Added by kalkan from general knowledge: Spring Boot properties and defaults, Nginx `add_header` inheritance, Apache `server-status`, Go `DefaultServeMux`, the H2 console.
