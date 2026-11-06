---
slug: jwt
title_en: JWT / token handling
title_tr: JWT / token doğrulama
cwe: CWE-347
owasp: A02:2021, A07:2021
sources: sast-skills, security-audit-skill, codecrucible, deepsec, open-code-review
---

## Summary

The server trusts the claims of a JSON Web Token (JWT) before it fully verifies the token. Typical gaps: no signature check, an algorithm or key that the token chooses, a wrong token purpose, or unchecked binding claims (`exp`, `aud`, `iss`). A forged, altered or foreign token then gives the attacker any identity or role.

## What it is

- **Decode without verify.** The code reads claims from an unverified token: `jwt.decode()` in jsonwebtoken, `options={"verify_signature": False}` in PyJWT, `JWT.decode()` in auth0 java-jwt. Also `ParseUnverified` in Go, `JWT.decode(t, nil, false)` in ruby-jwt, `decodeJwt` in jose, or a manual base64 decode.
- **Algorithm from the token.** The verify call has no algorithm allowlist, and the library default accepts `alg: none` or an algorithm that the attacker chooses.
- **Algorithm confusion.** The server uses RS256 or ES256, the public key is known, and the verify call also accepts HS256 with the same key. The attacker signs with HMAC and uses the public key as the secret.
- **Key from the token.** The code trusts an embedded `jwk`, fetches `jku` or `x5u` without an exact allowlist, or maps `kid` to an attacker-writable key record.
- **Errors ignored.** The code catches the verify error and uses the decoded payload, or it does not await an async verify.
- **Token purpose confusion.** A refresh, ID, email-verification or reset token works as an access token. All token types use one key, and the code does not check `typ` or a purpose claim.
- **Missing binding claims.** No `exp` check, or no `aud` and `iss` check where several services or issuers share a key or a JWKS. A token for service A then works at service B.
- **Weak HMAC secret.** A short or guessable secret lets an attacker crack a captured token offline and sign new ones.
- **No revocation.** Long-lived tokens stay valid after logout, password change or account disable, and the product promises that these events end access.

## What it is not

- A signing secret or private key in source code, or an env fallback like `JWT_SECRET || "secret"` → `hardcoded-secrets`.
- `kid` into a SQL query → `sqli`. `kid` into a file path → `path-traversal`. A `jku` fetch that reaches internal hosts → `ssrf`.
- ID token checks at an OIDC login callback (`nonce`, `aud` = client ID) and SAML assertions → `oauth-oidc-saml`.
- A valid token whose `sub` fetches another user's object → `idor`. A valid token without a role check → `missing-authz`.
- A token in `localStorage` that XSS can read → `xss`. A token in URLs or logs → `sensitive-data-exposure`.
- A JWT cookie used cross-site → `csrf`. Server session lifecycle (non-JWT) → `authn`. Webhook HMAC → `webhook-replay`.

## Where to look

Map every issue site (`sign`, `encode`) and every consume site (`verify`, `decode`, `parse`). Note the library and its version from the lockfile, the algorithm list, the key source and the claim options. Then find routes that read the `Authorization` header without the shared verify middleware.

### Python (Django, Flask, FastAPI)
- PyJWT 2 requires `algorithms` for verification. Look for `verify_signature: False`, `verify_exp: False`, and keys chosen from `get_unverified_header`.
- Authlib `jwt.decode()` checks the signature only. The code must call `claims.validate()` for `exp`, `iss` and `aud`.

### JavaScript/TypeScript (Express, Next.js, NestJS)
- jsonwebtoken before v9: a missing `algorithms` option can allow `none` or HMAC/RSA confusion (CVE-2022-23540, CVE-2022-23541).
- NestJS `JwtService.decode()` does not verify. Check `verifyOptions` in `JwtModule.register`. passport-jwt: check `algorithms` and `secretOrKey`.
- jose: `jwtVerify(token, key, { issuer, audience })` is correct. `decodeJwt` is decode only.

### Java (Spring)
- jjwt: `parseClaimsJws` or `parseSignedClaims` requires a signature. `parseClaimsJwt`, and `parse` in old versions, can return unsigned claims.
- Spring resource server checks `exp` and `nbf`. It checks `iss` and `aud` only when you configure them.

### Go
- golang-jwt rejects `none` unless the key function returns `jwt.UnsafeAllowNoneSignatureType`. A key function without a `token.Method` check is a bug if it can return a key that another algorithm family accepts.
- `dgrijalva/jwt-go` is unmaintained (CVE-2020-26160, audience bypass). lestrrat-go/jwx: `jwt.ParseInsecure` or `jwt.WithVerify(false)`.

### PHP (Laravel)
- firebase/php-jwt before v6 with a `kid` key array allows algorithm confusion (CVE-2021-46743). lcobucci/jwt: `parse()` without `validate()` or `assert()` with `SignedWith`.

### Ruby (Rails)
- ruby-jwt: `JWT.decode(token, key, true, { algorithm: "HS256" })` verifies. A third argument of `false` skips verification.

### C#/.NET (ASP.NET Core)
- `TokenValidationParameters` with `ValidateIssuer`, `ValidateAudience` or `ValidateLifetime` set to `false`, `RequireSignedTokens = false`, or a `SignatureValidator` that returns `new JwtSecurityToken(token)`. `ReadJwtToken` is decode only.

## Safe patterns

- Verify with a server-pinned list of one algorithm family and a key from server config or a pinned JWKS URL. Never take the key or the algorithm from the token.
- Require `exp`. Check `iss` and `aud` when more than one issuer or audience can exist.
- Use a separate key, or a checked `typ` or purpose claim, for each token type.
- Use a random HMAC key of 256 bits or more from a secret store, or an asymmetric key pair.
- Keep access tokens short-lived. Rotate refresh tokens. Keep a server-side revocation check (deny list or token version) when logout or disable must end access.
- Verify in one shared middleware. Handlers read only its output.

## Weak mitigations

- A string check `alg !== "none"`. Case variants and other algorithms pass.
- An allowlist that mixes HMAC and RSA algorithms for one key object.
- A `jku` or `x5u` check with `startsWith` or `includes`.
- A manual `exp` check after `decode`, with no signature check.
- `try { verify(t) } catch { claims = decode(t) }`.
- A deny list held in the memory of one instance.

## Verification checklist

- **attacker_control:** Name what the attacker changes (header `alg`, header key, payload claim, token type) and quote the decode or verify call that accepts it. For a weak secret, name the endpoint that accepts tokens signed with it.
- **privilege_boundary:** Name the identity or role that the forged or foreign token gives (any user, an admin, another service).
- **unmitigated:** Quote the verify call and its options. Name the missing element: signature, algorithm pin, trusted key source, `exp`, `aud`, `iss` or purpose. Check the default of the exact library version.
- Algorithm confusion needs all three: an asymmetric setup, a known public key, and a verify call that accepts HMAC with that key.
- Do not report a missing `exp`, `aud`, `iss` or `nbf` alone. Report it only with a concrete acceptance path, for example a second service that shares the key.
- If the library version or the gateway config is not visible, answer `unknown`.

## Examples

### JavaScript/TypeScript (Express, Next.js, NestJS)
```js
// Vulnerable: decode does not verify the signature
const claims = jwt.decode(req.headers.authorization.slice(7));
```

```js
// Secure: pinned algorithm, issuer and audience
const claims = jwt.verify(token, process.env.JWT_KEY, {
  algorithms: ["HS256"], issuer: "https://auth.example.test", audience: "api",
});
```

### Python (Django, Flask, FastAPI)
```python
# Vulnerable: signature check disabled
claims = jwt.decode(token, options={"verify_signature": False})
```

```python
# Secure
claims = jwt.decode(token, key, algorithms=["RS256"], audience="api",
                    issuer="https://auth.example.test", options={"require": ["exp"]})
```

### Go
```go
// Vulnerable: the error is ignored. Parse returns the claims even when the signature is bad.
tok, _ := jwt.Parse(s, func(t *jwt.Token) (any, error) { return hmacKey, nil })
uid := tok.Claims.(jwt.MapClaims)["sub"]
```

```go
// Secure: one allowed method, the error and Valid are checked
tok, err := jwt.Parse(s, func(t *jwt.Token) (any, error) { return hmacKey, nil },
	jwt.WithValidMethods([]string{"HS256"}), jwt.WithAudience("api"))
if err != nil || !tok.Valid {
	return errUnauthorized
}
```

## Dynamic test hints

- Use a local build and test keys only. Create two dummy accounts, `alice` and `bob`. Get the token of alice from the local login.
- Unsigned token: set the header to `{"alg":"none"}`, set `sub` to the ID of bob, and send `<header>.<payload>.` with an empty signature. Expect 401.
- Tampered payload: change `role` to `admin` and keep the old signature. Expect 401.
- Confusion: sign an HS256 token with the public key PEM of the local server as the secret. Expect 401.
- Header keys: embed a new `jwk`, or point `jku` at a file server inside the test network. Expect 401.
- Purpose: send the refresh or reset token of alice as the bearer token. Expect 401.
- Unit level: call the verify helper directly with these crafted tokens. No network is needed.
- Never crack or replay tokens from a real system.

## False positive traps

- `decode` runs only for logging or routing, and a full verify runs on the same request path.
- The library default already blocks the attack (jsonwebtoken 9 and later, PyJWT 2, golang-jwt `none` handling).
- A gateway verifies the token, and the repository config shows it.
- A missing `aud` in a single service with its own key is hardening, not a finding.
- The secret comes from the environment with no fallback. No weak value exists in the repository.
- A client decodes an ID token only to display the user name.

## Sources

Condensed and rewritten from the local copies under `third_party/`.

- `utkusen/sast-skills@db52227: sast-files/.claude/skills/sast-jwt/SKILL.md` (MIT, Utku Sen): JWT flaw list, prevention patterns, library examples.
- `cloudflare/security-audit-skill@c1c8a8c: skills/security-audit/WEB-PROTOCOL-AND-AUTH.md` (MIT, Cloudflare): verification and claim binding, `kid`/`jku`/`x5u` as untrusted key selectors.
- `block/codecrucible@b5c8086: prompts/default/analysis_sections.yaml` (token verification), `prompts/carlini-curated/security_analysis_base.yaml` (do-not-report rule for claim warnings) (Apache-2.0, Block).
- `vercel-labs/deepsec@4fa6722: packages/processor/src/prompt/slug-notes.ts`, `core.ts`, `packages/scanner/src/matchers/algorithm-confusion.ts` (Apache-2.0, Vercel): algorithm pinning and dev-branch verify skips.
- `alibaba/open-code-review@11ac6d4: internal/config/rules/rule_docs/rego.md` (Apache-2.0, alibaba/open-code-review contributors): claims used for authorization need upstream verification.
