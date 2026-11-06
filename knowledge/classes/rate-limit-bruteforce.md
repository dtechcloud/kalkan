---
slug: rate-limit-bruteforce
title_en: Rate limiting / brute force
title_tr: Rate limiting / brute force
cwe: CWE-307, CWE-799
owasp: A07:2021
sources: security-audit-skill, codecrucible, deepsec, sast-skills
---

## Summary

An attacker repeats a guess or a costly action, and no effective limit stops the repetition. The usual targets are passwords, one-time codes, reset and invite tokens, and endpoints that call paid services. Report a finding only when the repetition gives a concrete gain: account takeover, a multi-factor authentication (MFA) bypass, a valid code, or spend that the operator pays.

## What it is

- **Online password guessing (CWE-307).** A login, token or PIN endpoint accepts unlimited failed attempts for one account. No per-account counter, lockout, delay or challenge exists.
- **Credential stuffing.** Only a per-IP limit exists, so a distributed attacker tries leaked passwords on many accounts.
- **Short codes without an attempt cap.** A 6-digit one-time password (OTP), SMS or email code has one million values. Without a cap per challenge, the attacker guesses it inside the validity window. Backup codes, PINs and short reset, invite or coupon codes have the same risk.
- **Limit bypass (CWE-799).** The limiter key comes from attacker input: `X-Forwarded-For` without a trusted-proxy setting, a username in other case, a new session cookie. Route aliases, GraphQL aliases and batched requests escape a per-request count.
- **Fail-open limiter.** When the counter store (Redis, database) fails, every request passes.
- **Costly side effects.** "Send code", invite, email and SMS routes, and routes that call paid APIs (LLM, payment), have no per-user or per-recipient quota. The result is toll fraud, message bombing or operator spend.

## What it is not

- A missing or broken authentication gate, or a user-existence oracle in login and reset responses → `authn`.
- Offline cracking of a weak JWT secret → `jwt`. Of a weak password hash → `crypto`. A token with too few random bits or a non-CSPRNG source → `crypto`.
- A limiter counter that parallel requests exceed because its update is not atomic → `race-condition`.
- One request that exhausts CPU or memory → `dos-redos`. One request that starts an unbounded agent loop → `llm-ai`.
- A coupon redeemed twice by parallel requests → `race-condition`. A rule that the code never enforces → `business-logic`.
- GraphQL depth and complexity limits → `graphql`.
- A missing CAPTCHA on a form with no secret to guess and no costly side effect → not a finding.

## Where to look

Find every endpoint that checks a guessable secret or starts a costly side effect. Then find its limiter and read the key, the store and the scope.

### All stacks
- Login, token exchange, MFA and OTP verify, reset confirm, email or phone verification, invite accept, coupon redeem, PIN unlock, API key checks.
- "Send code", "resend" and invite routes. Routes that call LLM, SMS, email or payment APIs.
- The limiter key (account, source IP, or both) and how the code gets the client IP.
- The counter store: per-process memory gives each replica or serverless instance its own count.
- Gateway, WAF or proxy limits (nginx `limit_req`, API gateway throttling) are often outside the repository.

### JavaScript/TypeScript (Express, Next.js, NestJS)
- `express-rate-limit` (default store: per-process memory), `rate-limiter-flexible`, `@nestjs/throttler`, `@upstash/ratelimit`.
- `app.set("trust proxy", true)` makes `req.ip` the left-most `X-Forwarded-For` value, which the client sets. A `keyGenerator` that reads a header has the same problem.
- Next.js: every `route.ts` handler and `'use server'` export needs its own limit. A limit in `middleware.ts` misses routes outside its matcher.

### Python (Django, Flask, FastAPI)
- DRF has no throttles by default. `AnonRateThrottle` keys on the raw `X-Forwarded-For` value when `NUM_PROXIES` is not set, so a client can pick a new bucket per request.
- `django-axes` needs both its middleware and its backend. `django-ratelimit` with `block=False` only marks the request.
- Flask-Limiter `get_remote_address` reads `request.remote_addr`. Behind a proxy, `ProxyFix(x_for=N)` must match the real proxy count. FastAPI has no built-in limiter (search for `slowapi`).

### Java (Spring)
- Spring Security has no built-in lockout. Search for Bucket4j filters or failure-event listeners. A Resilience4j `RateLimiter` is one global bucket: it protects the service, not an account.

### Go
- `golang.org/x/time/rate` limiters are often global, or kept per IP in a map. Check the key source: `X-Real-IP`, `X-Forwarded-For`, or `r.RemoteAddr` behind a proxy.

### PHP (Laravel)
- `throttle:` middleware and `RateLimiter::for('login')`. Starter kits key on the lower-case email plus the IP. A trusted proxy setting of `'*'` trusts every proxy header.

### Ruby (Rails)
- `rack-attack` throttles, the Rails 7.2 `rate_limit to:, within:` call. Devise `:lockable` works only when the model lists it.

### C#/.NET (ASP.NET Core)
- Identity counts failures only with `PasswordSignInAsync(..., lockoutOnFailure: true)`. The scaffolded login page passes `false`.
- `AddRateLimiter`: check the partition key and the `ForwardedHeaders` options (`KnownProxies`, `KnownNetworks`).

## Safe patterns

- Count failures per account (normalized identifier) and per source in a shared store with atomic updates (`INCR` with `EXPIRE`, or one conditional `UPDATE`).
- After N failures, add a growing delay or a challenge, or lock the account for a short time. Add a global limit against credential stuffing.
- Cap the attempts per OTP challenge (for example 5), then invalidate the code. Keep a short expiry and single use. A resend does not reset the counter.
- Get the client IP only through a fixed trusted-proxy hop count or a list of known proxies.
- Mount the limiter at a layer that every route alias passes. Count GraphQL operations and aliases, not HTTP requests.
- On authentication routes, fail closed when the counter store is down.
- Set per-user quotas and spend caps on paid APIs, and per-recipient limits on SMS and email.

## Weak mitigations

- A per-IP limit only. Attackers rotate IPv4 and IPv6 addresses.
- A per-process counter with several replicas, or a counter in a cookie that the attacker drops.
- A limit on the web route, but none on the API or mobile alias.
- A source counter that resets after any successful login. The attacker logs in to their own account after every few guesses.
- A CAPTCHA that the server does not check, or checks only on the first step.
- A UI delay, a generic error message, a hidden endpoint, or one global bucket for the whole service.
- An OTP that stays valid after the app sends a new code.

## Verification checklist

- **attacker_control:** Name the endpoint and the guessed value or the repeated action. Quote the route registration and the line that checks the secret. Show that an anonymous or low-trust client can call it many times.
- **privilege_boundary:** Name the gain: another account, an MFA bypass, a valid code or key, or operator spend. A repeated action that affects only the attacker refutes it.
- **unmitigated:** Quote the limiter mount and its key, or list the searches that found none. A limiter keyed on a client header, mounted on another alias, or kept per process does not refute. If a gateway or WAF can hold the limit, answer `unknown`.
- Do the arithmetic: secret space, attempts per window, validity window. One million codes, 10 minutes, no cap: feasible. 5 attempts, then a new code: not feasible.
- Check the framework default and version before you claim a gap (DRF throttles, Identity `lockoutOnFailure`, Devise lockable).
- Severity guide: a missing login limit alone is usually `medium`. A short code without an attempt cap that gives account takeover is usually `high`.

## Examples

### JavaScript/TypeScript (Express, Next.js, NestJS)
```js
// Vulnerable: the client sets X-Forwarded-For, and one alias has no limit
app.set("trust proxy", true);
const limiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10 });
app.post("/login", limiter, login);
app.post("/api/v1/login", login);

// Secure: one known proxy hop, a shared store, and the key includes the account
app.set("trust proxy", 1);
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, limit: 10, store: redisStore,
  keyGenerator: (req) => `${req.ip}|${String(req.body.email).toLowerCase()}`,
});
app.post(["/login", "/api/v1/login"], express.json(), limiter, login);
```

### Python (Django, Flask, FastAPI)
```python
# Vulnerable: no attempt cap, and the code stays valid for 10 minutes
@app.post("/mfa/verify")
def verify(code: str, user=Depends(pending_user)):
    if code == user.otp_code:
        return issue_session(user)
    raise HTTPException(401)

# Secure: 5 attempts per challenge, then the code is dead
@app.post("/mfa/verify")
def verify(code: str, user=Depends(pending_user)):
    ch = consume_attempt(user.id)  # one atomic UPDATE ... SET attempts = attempts + 1 RETURNING *
    if ch is None or ch.expired or ch.attempts > 5:
        invalidate_challenge(user.id)
        raise HTTPException(429)
    if not hmac.compare_digest(code, ch.code):
        raise HTTPException(401)
    invalidate_challenge(user.id)
    return issue_session(user)
```

## Dynamic test hints

- Use a local build, dummy accounts and local stubs for the SMS, email, payment and LLM providers. Never use real hosts, phone numbers, mailboxes or paid APIs.
- Send N + 5 failed logins for one dummy account (N is the configured limit). Expect `429` or a lock after N attempts. Keep the total to a few dozen requests.
- Repeat with a new `X-Forwarded-For` value per request, another username case, each route alias, and one GraphQL request with many aliases. The count must not reset.
- OTP: send wrong codes past the cap, then the right code. It must fail. A resend must keep the counter and make the old code invalid.
- Unit level: call the key function with forged headers. Start two app instances on one test store and check that they share the count.

## False positive traps

- A global middleware, gateway, WAF or proxy config holds the limit, and the first pass missed it. If the limit can be outside the repository, the answer is `unknown`.
- The secret has 128 or more random bits (API keys, session tokens). Guessing is not feasible, with or without a limit.
- An external identity provider (OIDC, SAML, Cognito, Auth0) checks the password, so the app has no password endpoint.
- The auth library enforces a lockout: Devise lockable in the model, Identity with `lockoutOnFailure: true`, django-axes fully installed.
- The endpoint is internal-only or needs an admin role.
- A public read endpoint with no secret and no cost. A missing limit there is not this class.

## Sources

Condensed and rewritten from the local copies under `third_party/`.

- `cloudflare/security-audit-skill@c1c8a8c: skills/security-audit/WEB-PROTOCOL-AND-AUTH.md`, `RESOURCE-EXHAUSTION-AND-AVAILABILITY.md`, `ATTACK-CLASSES.md` (MIT, Cloudflare): MFA and recovery attempt controls, attacker-influenced quota keys.
- `block/codecrucible@b5c8086: prompts/default/analysis_sections.yaml`, `prompts/carlini-curated/cwe_deep_analysis.yaml`, `prompts/core/audit_families.yaml` (Apache-2.0, Block): lockout, backup codes, the TOTP window.
- `vercel-labs/deepsec@4fa6722: packages/scanner/src/matchers/rate-limit-bypass.ts`, `expensive-api-abuse.ts`, `packages/processor/src/prompt/core.ts`, `slug-notes.ts`, `highlights.ts` (Apache-2.0, Vercel): sensitive endpoints, paid-API abuse.
- `utkusen/sast-skills@db52227: sast-files/.claude/skills/sast-businesslogic/SKILL.md` (MIT, Utku Sen): generic brute force is not a business logic flaw.
- Framework details (Express `trust proxy`, DRF `NUM_PROXIES`, Identity `lockoutOnFailure`, Rails `rate_limit`, Laravel starter kits) come from general knowledge.
