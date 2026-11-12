---
name: web-protocol-and-auth
title: HTTP protocol, sessions, and authentication
classes: authn, jwt, oauth-oidc-saml, csrf, request-smuggling-crlf-cache
when_to_use: The target speaks HTTP at a parsing, caching, browser-session, or identity boundary, or implements sessions, JWT, OAuth, OIDC, SAML, MFA, passkeys, account recovery, API keys, or mTLS.
sources: third_party/security-audit-skill/skills/security-audit/WEB-PROTOCOL-AND-AUTH.md
---

# HTTP protocol, sessions, and authentication

Access-control review asks whether a principal may perform an operation. This pack asks whether the HTTP or identity layer can confuse which principal, request, assurance level, or token an operation belongs to. Related pack: `client-side` (browser-side CORS and messaging).

## Core discipline

- Framing and cache findings need two interpretations of the same request, response, or key. Name both components and the exact normalized value on each side.
- For every credential, find the signature or secret check and every binding its role needs: issuer, audience, origin, relying party, client, session, principal, resource, assurance, expiry, and one-time state.
- `Host`, `Forwarded`, `X-Forwarded-*`, `Origin`, `Referer`, redirect targets, callback state, and request-derived URLs are trust decisions. Trace each one to the affected identity or response.
- A missing header, cookie attribute, MFA prompt, or rate limit is not a finding alone. Require an accepted invalid request, a cross-principal impact, an assurance downgrade, or a credential disclosure.
- Use `needs_validation` when a proxy, IdP, browser, certificate, secret, or deployed configuration decides the claim and the repository does not show it.

## Attack classes

### Request framing and desynchronization

- **Check:** front and back ends that disagree on request length or header normalization: several `Content-Length` values, `Transfer-Encoding`, HTTP/2 downgrade, header-name normalization, and CR/LF handling. Confirm which bytes each component assigns to which request.
- **Not a finding:** a single standard server with no custom parser and no visible proxy chain. A proxy or a custom parser gives much more surface.

### Web cache poisoning and cache deception

- **Check:** request values that change cached content or security headers but are absent from the cache key (forwarded host, cookies, query normalization, authorization state). Check cache rules that treat a private dynamic path as a static asset through suffix or path-parameter tricks.
- **Not a finding:** a cache that keys on every varying input or never stores personalized responses.

### Host and forwarded-header trust

- **Check:** untrusted host or proxy metadata that builds absolute URLs, tenant routing, callbacks, reset links, cache keys, or the client address that authorization or rate limiting uses. Confirm whether trusted ingress removes client copies.
- **Not a finding:** a host value checked against an allowlist before use.

### Response-header injection

- **Check:** untrusted data in `Location`, `Set-Cookie`, CSP, or another response header with CR/LF or unsafe normalization, and a security-relevant change to the response.
- **Not a finding:** a framework that rejects control characters in header values. Check the framework version first.

### Ordinary CSRF

- **Check:** a state-changing endpoint that the browser calls with ambient credentials and that accepts a cross-site request without an effective anti-CSRF token, SameSite binding, or strict `Origin` check. Inventory every cookie-authenticated mutation, including multipart, method-override, and legacy routes.
- **Not a finding:** read-only actions, and routes that need a non-ambient bearer token.

### Session fixation and invalidation

- **Check:** session IDs not rotated on login, MFA completion, impersonation, or other privilege changes, and sessions that stay valid after logout, password change, revocation, or account disable. Check refresh tokens, signed cookies, WebSocket state, and caches too.
- **Not a finding:** a short-lived stateless token whose expiry the product accepts, when no revocation promise exists.

### Cookie scope and transport

- **Check:** a sensitive cookie with a broad `Domain` or `Path`, a cookie that can cross plain HTTP, or a sibling cookie that another component reads instead.
- **Not a finding:** a missing flag alone. It is a hardening note unless a less trusted origin, network position, or browser path can steal or replace the credential.

### JWT verification and claim binding

- **Check:** signature verification with a server-pinned algorithm and key source, then `exp`, `nbf`, `aud`, and `iss`. Treat `kid`, `jku`, and `x5u` as untrusted key selectors. Look for `alg: none`, HS256 and RS256 confusion, and decode-without-verify paths. A valid token for another service is invalid here.
- **Not a finding:** a library call that pins the algorithm and validates the standard claims.

### OAuth and OIDC request and callback binding

- **Check:** first establish the role. For an authorization server, check exact `redirect_uri` matching. For a client, check a session-bound `state`, PKCE and code binding, ID-token issuer, audience, signature, and `nonce`, and the selected-IdP binding in multi-provider flows. Compare the first callback with retry, deep-link, and account-link routes.
- **Not a finding:** an authorization-server control in a relying-party codebase.

### SAML signed-object and assertion binding

- **Check:** that the element whose signature code validates is the element that code uses as identity. Review unsigned or fallback paths, XML parser hardening, canonicalization differences, validity windows, audience and recipient, request correlation, and replay state.
- **Not a finding:** a maintained library that checks signature wrapping, with the expected audience configured.

### MFA enrollment, step-up, and assurance downgrade

- **Check:** enrollment, replacement, disablement, recovery-code generation, trusted-device creation, and fallback login without the intended prior assurance. A challenge must upgrade only its own principal, session, operation, and expiry, once. Compare UI, API, and resumed flows for a route that skips the check.
- **Not a finding:** a missing MFA prompt where the product does not promise MFA for that action.

### WebAuthn and passkey verification

- **Check:** at registration, binding of challenge, RP ID, origin, credential, user handle, algorithm, and required user verification to the initiating session. At authentication, verification of challenge, RP ID, origin, credential membership, signature, and user presence. Check account discovery for user-handle confusion.
- **Not a finding:** signature-counter handling, unless the product treats a counter regression as a clone signal.

### Account linking, password reset, and recovery

- **Check:** adding an IdP, passkey, email, phone, or device without a current session, proof of the new identity, required step-up, and callback state bound to the initiating account. For reset and recovery (tokens, backup codes, support recovery, email change), check token randomness, user and action binding, expiry, one-time use, attempt limits, delivery URL trust (the `Host` header), and invalidation of older tokens and sessions.
- **Not a finding:** different responses that only reveal public account existence.

### API-key scope, binding, and exposure

- **Check:** keys that reach broader tenants, resources, actions, or environments than their server-side record grants, or request parameters that override those bindings. Review prefix versus full-secret checks, publishable versus secret key confusion, and revocation caches. Check keys in client bundles, URLs, logs, and errors that a lower-trust principal can read.
- **Not a finding:** a public identifier that the vendor calls a key.

### mTLS identity and certificate fallback

- **Check:** processes that trust client-certificate identity headers from any peer, map attacker-influenced subject text to an account, or accept certificates for the wrong trust domain, usage, or validity. Check fail-open paths after expiry, revocation, or renewal failure.
- **Not a finding:** a trusted proxy that terminates mTLS, strips incoming identity headers, and is the only peer that can connect. Missing revocation data in deployment makes the claim `needs_validation`.

## Universal moves

- Walk issue, store, transmit, consume, refresh, and revoke for every credential and challenge. Compare normal, error, retry, migration, legacy, and account-switch paths.
- List every door to the same identity and every route to the same sensitive operation. The effective policy is the weakest parallel path.
- Compare parser, proxy, router, cache, and application normalization side by side. A PoC feeds the same bounded request fixture to each local component, never to a live deployment.

## Validation rules

1. Apply the source-visibility gate. Proxy chains, edge cache keys, IdP policy, certificate trust, cookie behavior, secrets, and deployed auth modes can be outside the repository. Record a precise `needs_validation` candidate instead of guessing.
2. For framing and cache findings, name both components and the divergent parse or key, and the cross-request, cross-user, or private-response impact.
3. For token, MFA, passkey, linking, recovery, API-key, and mTLS findings, cite the verification line and the missing binding. Show that the server accepts the invalid transition or credential.
4. For CSRF, name the ambient credential, the state-changing route, the accepted cross-site request shape, the cookie policy, and the missing check.
5. Check framework and library defaults. If the version or configuration is unknown, use `needs_validation`. Do not turn an unverified critical claim into a lower-severity confirmed finding.

## Sources

- `third_party/security-audit-skill/skills/security-audit/WEB-PROTOCOL-AND-AUTH.md`, from cloudflare/security-audit-skill at commit `c1c8a8c` (MIT License, Copyright (c) 2025-2026 Cloudflare, Inc.).
- kalkan condensed and rewrote the text, adapted it to the kalkan verdict model, and removed the agent-orchestration instructions.
