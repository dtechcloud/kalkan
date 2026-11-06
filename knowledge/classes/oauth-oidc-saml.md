---
slug: oauth-oidc-saml
title_en: OAuth / OIDC / SAML
title_tr: OAuth / OIDC / SAML
cwe: CWE-287, CWE-347
owasp: A02:2021, A07:2021
sources: sast-skills, security-audit-skill, codecrucible, deepsec
---

## Summary

A federated login trusts an artifact that is not bound to the right party, request or session. The artifact is an authorization code, an access token, an ID token or a SAML response. The attacker then logs in as the victim, links a foreign identity to the account of the victim, or steals codes and tokens.

## What it is

First decide the role of the component: OAuth client or relying party (RP), authorization server (AS) or identity provider (IdP), or SAML service provider (SP). Each role owns different checks.

- **Client / RP: missing request binding.** No `state`, a `state` that the code does not compare, or a `state` that is not bound to the browser session. Result: login CSRF, or the identity of the attacker is linked to the account of the victim.
- **Client / RP: PKCE.** A public client (SPA, mobile) without PKCE, or a `code_verifier` that is not bound to the session.
- **Client / RP: ID token.** No check of the signature, `iss`, `aud` (the client ID), `exp` or `nonce`. Keys must come from the configured issuer.
- **Client / RP: wrong identity key.** The code maps the external identity to an account by email, or by an unverified email (`email_verified` missing or false). In a multi-IdP setup, it uses `sub` without `iss`. An access token issued to another client works as login proof.
- **Client / RP: IdP mix-up.** The callback does not check that the response comes from the IdP that the user selected.
- **AS / IdP.** `redirect_uri` matched by prefix, substring, regex or wildcard. Codes that are reusable, long-lived or not bound to the client and the `redirect_uri`. PKCE `plain`, or a verifier that the token endpoint does not check. Refresh tokens not bound to the client. Scope growth at refresh. Error redirects to an unchecked `redirect_uri`.
- **SAML SP: signature wrapping.** The code verifies one element and reads the identity from another one.
- **SAML SP: weak signature policy.** Unsigned assertions pass, or the code only checks that a `Signature` element exists. The verification key comes from the `KeyInfo` of the message instead of the configured IdP certificate.
- **SAML SP: missing conditions.** No check of `Audience`, `Recipient`, `Destination`, `Issuer`, `NotBefore`, `NotOnOrAfter` or `InResponseTo`. No replay cache for assertion IDs. NameID text extraction that stops at an XML comment.

## What it is not

- An API that verifies a JWT access token → `jwt`.
- XXE or entity expansion in the SAML parser → `xxe`.
- A post-login `next` or `returnTo` redirect → `open-redirect`.
- A client secret in a public client bundle → `hardcoded-secrets`.
- Discovery, `jku` or `request_uri` fetches that reach internal hosts → `ssrf`.
- Session fixation or logout after the federated login completes → `authn`. CSRF on ordinary forms → `csrf`.

## Where to look

Find the login start and the callback or assertion consumer service (ACS). Also find the account-link flow and the code that maps the external identity to a local user. Read the library options first. Defaults often enforce `state`, `nonce` and PKCE, and the bug is the option that turns them off.

### Python (Django, Flask, FastAPI)
- django-allauth auto-connect by email settings. python-social-auth pipelines that associate users by email.
- python3-saml with `strict: false`, or `wantAssertionsSigned` off. signxml: the code must use the element that `verify()` returns, not the original tree.

### JavaScript/TypeScript (Express, Next.js, NestJS)
- Auth.js (NextAuth) `allowDangerousEmailAccountLinking: true`, or `checks` without `state` or `pkce`. openid-client: the callback must pass the saved `state`, `nonce` and `code_verifier`.
- Passport OAuth strategies without `state: true` or `pkce: true`. @node-saml: `wantAssertionsSigned`, `audience`, `validateInResponseTo`, the IdP certificate option.

### Java (Spring)
- Spring Security OAuth2 Client and SAML2 enforce most checks by default. Look for custom OpenSAML code that validates a signature and then reads another element.

### Go
- golang.org/x/oauth2: the callback must compare `state` with the session value. go-oidc: `SkipClientIDCheck`, `SkipIssuerCheck`, `SkipExpiryCheck` or `InsecureSkipSignatureCheck` set to `true`. Old crewjam/saml versions (CVE-2020-27846).

### PHP (Laravel)
- Laravel Socialite `->stateless()` turns off the `state` check. league/oauth2-client needs a manual `state` compare. onelogin/php-saml with `strict` off.

### Ruby (Rails)
- OmniAuth: the request phase must be POST with CSRF protection (`omniauth-rails_csrf_protection`). Users matched by `auth.info.email`. Old ruby-saml (CVE-2024-45409, CVE-2025-25291, CVE-2025-25292).

### C#/.NET (ASP.NET Core)
- `AddOpenIdConnect` with `ValidateIssuer = false` on a multi-tenant (`common`) authority, without an own tenant or issuer check.

## Safe patterns

- Use the maintained library flow. Do not parse callbacks or assertions by hand.
- `state`: random, bound to the browser session, compared once, then deleted. Add the selected IdP to it.
- PKCE with S256 for every client. `nonce` for OIDC, checked in the ID token.
- Validate the ID token: signature with keys of the configured issuer, `iss`, `aud`, `exp`, `nonce`, and `azp` when present.
- The account key is the pair (`iss`, `sub`). Link by email only when `email_verified` is true and the user proves control of the existing account.
- AS: exact match against registered redirect URIs. Single-use, short-lived codes bound to the client, the `redirect_uri` and the PKCE verifier.
- SAML: verify with the configured IdP certificate. Read identity only from the signed element. Require signed assertions. Check audience, recipient, destination, issuer, time window and `InResponseTo`. Cache assertion IDs until they expire.

## Weak mitigations

- A `state` compared with a value that the attacker can also set, for example a query parameter or a cookie outside the session.
- A `redirect_uri` check with `startsWith`, `includes` or an unanchored regex.
- An email-domain allowlist on an unverified email claim.
- XPath `//Assertion` or `getElementsByTagName("NameID")[0]` after a signature check.
- `strict: false`, `SkipClientIDCheck` or a test IdP setting copied from development config.
- PKCE `plain`, or PKCE only on the mobile client.

## Verification checklist

- **attacker_control:** Name the artifact that the attacker controls, forges or replays (callback query, code, ID token, SAML response, `redirect_uri`). Quote the line that consumes it.
- **privilege_boundary:** Name the result: a session as the victim, or a foreign identity on the account of the victim. Other results: a stolen code or token, or login as any user.
- **unmitigated:** Quote the validation step and name the missing binding: session, client, issuer, audience, nonce, signed element, time window or replay state. Quote the option that turns off a library default.
- Assign the check to the right role. A client does not own the redirect URI allowlist of the IdP.
- IdP settings (registered redirect URIs, signing policy) are often outside the repository. Then answer `unknown`.

## Examples

### JavaScript/TypeScript (Express, Next.js, NestJS)
```js
// Vulnerable: state is never compared
app.get("/cb", async (req, res) => {
  const tokens = await exchangeCode(req.query.code);
  req.session.user = await userFromIdToken(tokens.id_token);
});
```

```js
// Secure: state bound to the session, single use
app.get("/cb", async (req, res) => {
  const expected = req.session.oauthState;
  delete req.session.oauthState;
  if (!expected || req.query.state !== expected) return res.sendStatus(400);
  const tokens = await exchangeCode(req.query.code, req.session.pkceVerifier);
  req.session.user = await userFromIdToken(tokens.id_token, req.session.nonce);
});
```

### Python (Django, Flask, FastAPI)
```python
# Vulnerable: verifies the signature, then reads the unverified document
XMLVerifier().verify(doc, x509_cert=idp_cert)
name_id = doc.find(".//{*}NameID").text
```

```python
# Secure: read only from the element that verify() returns
signed = XMLVerifier().verify(doc, x509_cert=idp_cert).signed_xml
name_id = signed.find(".//{*}NameID").text
```

### PHP (Laravel)
```php
// Vulnerable: state check turned off
$gh = Socialite::driver('github')->stateless()->user();
```

```php
// Secure: default flow with the state check
$gh = Socialite::driver('github')->user();
$user = User::firstWhere(['provider' => 'github', 'provider_id' => $gh->getId()]);
```

## Dynamic test hints

- Use a local mock IdP or AS in the test network. Create dummy users `alice` and `mallory`. Never use a real IdP, tenant or account.
- Login CSRF: start a login as `mallory`, stop before the callback, and open the callback URL in the session of `alice`. Alice must not end up logged in as or linked to `mallory`.
- Replay: send one authorization code twice. The second exchange must fail.
- AS redirect: register `https://app.example.test/cb` and request `https://app.example.test.evil.test/cb` or an extra path. Expect a rejection without a redirect.
- ID token: use a token for another client ID, an expired token, or a wrong `nonce`. Expect a rejection.
- SAML (local test certificates): replay an assertion, change `Audience`, or wrap a signed assertion and add an unsigned one for `alice`. Expect a rejection.
- Unit level: feed saved callback and assertion fixtures to the handler.

## False positive traps

- The library enforces `state`, `nonce` and PKCE by default, and the code does not turn them off.
- The component is a client. The redirect URI allowlist lives in the IdP config.
- The SAML library validates the whole response and reads identity from the verified tree.
- Email linking runs only after the user authenticates to the existing account.
- An implicit-flow client exists only in tests or examples that do not ship.

## Sources

Condensed and rewritten from the local copies under `third_party/`.

- `cloudflare/security-audit-skill@c1c8a8c: skills/security-audit/WEB-PROTOCOL-AND-AUTH.md` (MIT, Cloudflare): component role first, OAuth/OIDC request and callback binding, SAML signed-object binding, account linking.
- `cloudflare/security-audit-skill@c1c8a8c: skills/security-audit/ATTACK-CLASSES.md` (MIT, Cloudflare): scope and capability growth across delegation and refresh.
- `utkusen/sast-skills@db52227: sast-files/.claude/skills/sast-jwt/SKILL.md` (MIT, Utku Sen): untrusted key material in headers, applied to ID tokens and SAML `KeyInfo`.
- `block/codecrucible@b5c8086: prompts/default/cwe_deep_analysis.yaml` (CWE-287, CWE-601) and `prompts/core/audit_families.yaml` (Apache-2.0, Block): `redirect_uri` code leakage, authentication family checks.
- `vercel-labs/deepsec@4fa6722: packages/processor/src/prompt/core.ts`, `packages/scanner/src/matchers/oauth-flow.ts` (Apache-2.0, Vercel): OAuth callback manipulation patterns.
- Library option names, CVE references and the SAML wrapping examples come from general knowledge. Verify them against the library version in the lockfile.
