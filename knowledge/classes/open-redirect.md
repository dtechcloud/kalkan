---
slug: open-redirect
title_en: Open redirect
title_tr: Open redirect
cwe: CWE-601
owasp: A01:2021
sources: codecrucible, deepsec, security-audit-skill, open-code-review
---

## Summary

The application sends the browser to a destination that the request controls, and it does not check the destination. Attackers use the trusted domain for phishing, for token or code theft through the redirect, and for filter bypass in other allowlists. A plain open redirect is usually low or medium severity. Chains raise it.

## What it is

- **Server-side redirects.** `res.redirect(req.query.next)`, `redirect(request.GET["next"])`, `"redirect:" + url` in Spring MVC, `http.Redirect(w, r, next, 302)`, `redirect($request->input('url'))`, `redirect_to params[:return_to]`, `Redirect(returnUrl)`.
- **Header sources.** The `Location` value comes from `Referer`, `Host` or `X-Forwarded-Host`.
- **Client-side navigation.** `window.location = params.get("next")`, `location.assign(hash)`, `router.push(callbackUrl)`, a meta refresh with a query value.
- **Weak validators.** The code checks the value, but a crafted value passes:
  - `startsWith("/")` passes `//evil.test` and `/\evil.test`.
  - `startsWith("https://app.test")` passes `https://app.test.evil.test` and `https://app.test@evil.test`.
  - `includes("app.test")` and `endsWith("app.test")` pass `evilapp.test` and `app.test.evil.test`.
  - An unanchored regex, or a regex with an unescaped dot.
  - A check on the decoded value, then a redirect with a value that the server decodes again.
  - A different parser on the server and in the browser. Browsers treat `\` like `/` and drop tabs and newlines.
- **Typical places.** Post-login `next`, post-logout `returnTo`, SSO relay state, link shorteners, "leave this site" pages without an interstitial.

## What it is not

- `redirect_uri` checks at an OAuth authorization server → `oauth-oidc-saml`.
- A server-side HTTP client that follows redirects → `ssrf`. An open redirect on an allowlisted host can be a link in an SSRF chain.
- CR or LF in the `Location` header → `request-smuggling-crlf-cache`.
- A `javascript:` or `data:` destination that executes → `xss`.
- A fixed, server-side host with a user-controlled path is not an open redirect.

## Where to look

Search for redirect sinks and for parameter names: `next`, `url`, `redirect`, `return`, `returnTo`, `return_url`, `continue`, `goto`, `dest`, `target`, `callback`, `back`. Trace each value to the sink and read the validator.

### Python (Django, Flask, FastAPI)
- Django `redirect()` and `HttpResponseRedirect` with request data. The safe helper is `url_has_allowed_host_and_scheme(url, allowed_hosts=..., require_https=...)`.
- Flask `redirect(request.args.get("next"))`. FastAPI `RedirectResponse(url)`.

### JavaScript/TypeScript (Express, Next.js, NestJS)
- Express `res.redirect()` and `res.location()` with request data.
- Next.js `redirect()` and `NextResponse.redirect(new URL(param, req.url))`. `new URL()` ignores the base when the parameter is an absolute URL.
- Client code: `router.push`, `window.location`, `location.href` with query or hash values. Auth.js `callbackUrl` with a custom `redirect` callback.

### Java (Spring)
- `"redirect:" + param`, `response.sendRedirect(param)`, `RedirectView`. A success handler with `setTargetUrlParameter(...)`.

### Go
- `http.Redirect` with `r.URL.Query().Get(...)`. Gin `c.Redirect(302, c.Query("url"))`. Echo `c.Redirect`.

### PHP (Laravel)
- `redirect($url)`, `redirect()->to(...)` and `redirect()->away(...)` with request data. `header("Location: " . $_GET["url"])`. WordPress `wp_redirect` instead of `wp_safe_redirect`.

### Ruby (Rails)
- `redirect_to params[...]`. Rails 7 defaults raise on external hosts (`raise_on_open_redirects`). `allow_other_host: true` turns that off.

### C#/.NET (ASP.NET Core)
- `Redirect(returnUrl)` without `Url.IsLocalUrl(returnUrl)`. `LocalRedirect` is the safe form.

## Safe patterns

- Redirect to a named route or an ID from an allowlist, not to a raw URL.
- Or parse the value with a standard URL parser and accept only:
  - a relative path that starts with one `/`, not `//` or `/\`, with no backslash and no control character, or
  - an absolute URL whose scheme, host and port exactly match an allowlist.
- Use the framework helper: `url_has_allowed_host_and_scheme`, `LocalRedirect` or `Url.IsLocalUrl`, `wp_safe_redirect`, Rails `url_from`.
- Show an interstitial page before external links.

## Weak mitigations

- Prefix, suffix and substring checks on the raw string.
- A denylist of `http://` and `https://`. Scheme-relative URLs and other schemes pass.
- A host check without a scheme check, so `javascript:` passes.
- A check of the parsed host with a parser that differs from the browser parser.

## Verification checklist

- **attacker_control:** Quote the redirect call and the request value that reaches it. Show that the value can travel in a link that a victim opens, such as a GET parameter or a hash.
- **privilege_boundary:** Name the gain: a trusted-domain jump to an attacker site, a leaked code or token, or a bypass of another allowlist. Without a chain, keep the severity low.
- **unmitigated:** Quote the validator, or state that none exists. Give the concrete bypass value, for example `//evil.test` or `https://app.test@evil.test`.
- A fixed host with a user path, or an exact origin allowlist, refutes the finding.
- If the value is POST-only, explain how a victim submits it. This lowers the severity.

## Examples

### JavaScript/TypeScript (Express, Next.js, NestJS)
```js
// Vulnerable: "//evil.test" starts with "/"
const next = String(req.query.next || "/");
if (next.startsWith("/")) return res.redirect(next);
```

```js
// Secure: one leading slash, no backslash, same origin after parsing
const next = String(req.query.next || "/");
const u = new URL(next, "https://app.example.test"); // the parser also drops tabs and newlines
if (/^\/(?![\/\\])/.test(next) && !next.includes("\\") && u.origin === "https://app.example.test") {
  return res.redirect(u.pathname + u.search);
}
return res.redirect("/");
```

### Python (Django, Flask, FastAPI)
```python
# Vulnerable
return redirect(request.GET.get("next", "/"))
```

```python
# Secure
nxt = request.GET.get("next", "/")
if not url_has_allowed_host_and_scheme(nxt, allowed_hosts={request.get_host()}, require_https=True):
    nxt = "/"
return redirect(nxt)
```

### C#/.NET (ASP.NET Core)
```csharp
// Vulnerable
return Redirect(returnUrl);
```

```csharp
// Secure: throws for non-local URLs
return LocalRedirect(returnUrl);
```

## Dynamic test hints

- Use a local build and a dummy account `alice`. Use the reserved `.test` domain for the attacker host so that nothing resolves. Never follow redirects to real external sites.
- Send `GET /login?next=<value>`, logged in as alice when the flow needs it. Read only the `Location` header or the client navigation target.
- Values to try: `//evil.test`, `/\evil.test`, `https:evil.test`, `https://app.localhost@evil.test`, `https://app.localhost.evil.test`, `%2F%2Fevil.test`, `/%09/evil.test`, `javascript:alert(1)`.
- A `Location` header that points to `evil.test` confirms the finding.
- Unit level: call the validator directly with the same list and assert a rejection.

## False positive traps

- A server-side literal fixes the host, and the user controls only the path.
- An exact allowlist of origins applies, and it rejects `//`, `\`, `javascript:` and `data:`.
- The target comes from server-side session state, for example the URL that the framework saved before login.
- The value is a signed parameter, and the server checks the signature.
- Client routing accepts only internal route names.

## Sources

Condensed and rewritten from the local copies under `third_party/`.

- `block/codecrucible@b5c8086: prompts/default/analysis_sections.yaml` (open redirect), `prompts/default/cwe_deep_analysis.yaml` (CWE-601), `prompts/core/audit_families.yaml` (network family) (Apache-2.0, Block): validation checks, bypass values, false positive indicators.
- `vercel-labs/deepsec@4fa6722: packages/processor/src/prompt/slug-notes.ts`, `highlights.ts`, `packages/scanner/src/matchers/open-redirect.ts`, `unsafe-redirect.ts`, `url-regex-validation.ts` (Apache-2.0, Vercel): `//` paths, encoding bypasses, framework redirect sinks.
- `cloudflare/security-audit-skill@c1c8a8c: skills/security-audit/CLIENT-SIDE.md` (client-side navigation), `ATTACK-CLASSES.md` (obvious-things list) (MIT, Cloudflare).
- `alibaba/open-code-review@11ac6d4: internal/config/rules/rule_docs/php.md` (Apache-2.0, alibaba/open-code-review contributors): redirects built from untrusted data.
- Framework helper names (Django, ASP.NET Core, WordPress, Rails 7 defaults) come from general knowledge.
