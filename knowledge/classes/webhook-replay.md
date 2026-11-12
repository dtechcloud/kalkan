---
slug: webhook-replay
title_en: Webhook signature / replay
title_tr: Webhook imzası / replay
cwe: CWE-345, CWE-294
owasp: A07:2021, A08:2021
sources: deepsec, security-audit-skill, codecrucible, open-code-review
---

## Summary

An endpoint or consumer accepts a message that claims to come from a trusted producer (payment provider, Git host, chat platform, internal service, queue) without proof. The signature check is missing, can be skipped, covers the wrong bytes, or compares in a timing-unsafe way. Or the handler accepts an old valid message again. The attacker forges an event such as "payment succeeded", or repeats the side effect of one valid event.

## What it is

- **No verification (CWE-345).** The webhook route acts on the body without checking the provider signature header (`Stripe-Signature`, `X-Hub-Signature-256`, `X-Slack-Signature`, `X-Shopify-Hmac-Sha256`, `X-Twilio-Signature`, Standard Webhooks `webhook-signature`).
- **Skippable verification.** The check runs only when the header is present (`if (sig) verify(...)`). A missing secret disables it. A dev flag or a test header bypasses it. A caught verification error lets the handler continue.
- **Wrong bytes.** The HMAC covers re-serialized parsed JSON instead of the raw body, or the code verifies one part and acts on another (query parameters, a second body field).
- **Secret check against an unset variable.** A comparison with `` `Bearer ${process.env.CRON_SECRET}` `` matches the literal text `Bearer undefined` when the variable is missing. An HMAC with an empty key is computable by anyone.
- **Weak comparison.** `==` on the signature, a prefix compare, or a request header that selects the algorithm.
- **Replay (CWE-294).** No timestamp tolerance, a timestamp outside the signed content, no deduplication by event ID, or deduplication after the side effect.
- **Trusted payload.** The handler trusts `amount`, `status` or `plan` from the body instead of the provider object it can fetch by ID.
- **Untrusted producers on internal buses.** A queue consumer acts on `type`, `role` or `tenant` fields from any producer that can publish, without producer authentication or a signed envelope.

## What it is not

- JWT verification flaws → `jwt`. SAML and OIDC assertions → `oauth-oidc-saml`.
- Outgoing webhooks to user-registered URLs, and SNS `SubscribeURL` fetches → `ssrf`.
- A deduplication check that exists but is not atomic (check, then insert the event ID) → `race-condition`.
- A wrong state machine for valid events → `business-logic`.
- A hardcoded webhook secret → `hardcoded-secrets`. A weak MAC algorithm in general → `crypto`.
- Missing authentication on normal user endpoints → `authn` or `missing-authz`.
- CSRF exemption of a verified webhook route is correct, not a finding.

## Where to look

### Python

- Flask or Django views with `@csrf_exempt` that read `request.json` or `request.body`. `stripe.Webhook.construct_event(payload, sig_header, secret)` needs the raw `request.data` or `request.body`.
- Manual `hmac.new(...)` checks: look for `hmac.compare_digest` and the `sha256=` prefix handling. Slack `SignatureVerifier`. Celery or queue consumers.

### JavaScript/TypeScript

- Routes after `express.json()` lose the raw body, so code re-serializes with `JSON.stringify(req.body)` or skips the check. Look for `express.raw()` or a `verify` callback that keeps the raw body.
- Next.js handlers need `await req.text()` before parsing. SDK verifiers: `stripe.webhooks.constructEvent`, `@octokit/webhooks` `verify`, `svix` `Webhook.verify`.
- Slack Bolt receivers verify with `signingSecret`. Custom receivers and raw routes need their own check.
- `crypto.timingSafeEqual` versus `===`. Handling of an unset `process.env` secret.

### Java/Kotlin

- Spring `@PostMapping("/webhook")` with `@RequestBody Map` (parsed) instead of `String` or `byte[]`. Stripe Java `Webhook.constructEvent`. `MessageDigest.isEqual` for the compare.

### Go

- `io.ReadAll(r.Body)` and then `hmac.Equal`. `webhook.ConstructEvent` (stripe-go), `github.ValidatePayload` (go-github). A check for an empty secret before use.

### PHP

- Laravel `VerifyCsrfToken::$except` entries need a signature check. `file_get_contents("php://input")` for the raw body, `hash_hmac` with `hash_equals`.
- Laravel Cashier applies its signature middleware only when `cashier.webhook.secret` is set. An unset secret means no verification.

### Ruby

- `skip_before_action :verify_authenticity_token` routes: check for a signature check on `request.raw_post`. `Stripe::Webhook.construct_event`, `ActiveSupport::SecurityUtils.secure_compare`.

### C#/.NET

- Actions that bind `[FromBody]` models instead of reading the raw body. Stripe.net `EventUtility.ConstructEvent`. `CryptographicOperations.FixedTimeEquals`.

### Routes, cron and queues

- Paths such as `/webhook`, `/webhooks/*`, `/hooks/*`, `/callback`, `/notify`, `/ipn`, `/slack/events`, `/api/cron/*`.
- Queue consumers (`@KafkaListener`, `@RabbitListener`, SQS handlers, BullMQ processors, Celery tasks) that a lower-trust component can feed.

## Safe patterns

- Verify before parsing or acting, preferably with the provider SDK. The HMAC covers the exact raw body bytes (plus the timestamp or ID). Compare in constant time. Reject a missing header, a missing secret or a mismatch.
- Replay protection: a timestamp inside the signed content with a tolerance (for example 5 minutes), and an event ID stored with a unique constraint before the side effect.
- Idempotent handlers: state transitions keyed on the provider object ID (`UPDATE orders SET status = 'paid' WHERE id = ? AND status = 'pending'`).
- Fetch critical state from the provider API by ID instead of trusting body fields, where the provider supports it.
- Per-endpoint secrets from a secret store, with startup failure when missing and two active secrets during rotation.
- Accept only expected event types. Ignore the rest.
- Internal buses: authenticated producers (broker ACLs, mTLS, signed envelopes), and consumers that re-check authorization for the named resource.

## Weak mitigations

- An IP allowlist alone. Provider ranges are shared, and `X-Forwarded-For` is spoofable.
- A secret token in the URL path or query. It leaks into logs and never expires, and a captured URL still works.
- HMAC over `JSON.stringify(req.body)`. Key order and whitespace differ, and teams then disable the check.
- A timestamp check when the timestamp is not part of the signed content.
- Event ID deduplication in memory only (lost on restart, not shared between instances), or after the side effect.
- Verification for some event types only.

## Verification checklist

- **attacker_control:** Show that an external attacker reaches the endpoint (public route, no network restriction in the repository) and controls body and headers. For replay, name a realistic source of a valid signed message, such as logs, a shared proxy or the provider's own retries.
- **privilege_boundary:** Name the forged or repeated effect: an order marked paid, credit added, an account upgraded, a deployment triggered, an admin event processed. A handler that only logs, or only starts an authenticated re-fetch, refutes or lowers this.
- **unmitigated:** Quote the path from the route to the side effect. Show the missing verification, or the bypass branch (missing secret, missing header, caught error), or the missing timestamp and ID checks. If middleware verifies, quote its wiring and configuration.
- Name the signed bytes and the processed bytes. Check what happens when the secret variable is unset (read the config defaults).
- Provider retries also cause duplicates without an attacker. Rate the security impact by who can cause the duplicate.

## Examples

### JavaScript/TypeScript (Express and Stripe)

Vulnerable: no signature check, and the body decides the order state.

```ts
app.post("/webhooks/stripe", express.json(), async (req, res) => {
  if (req.body.type === "checkout.session.completed") {
    await markPaid(req.body.data.object.metadata.orderId);
  }
  res.sendStatus(200);
});
```

Secure: verify the raw body, then deduplicate by event ID.

```ts
app.post("/webhooks/stripe", express.raw({ type: "application/json" }), async (req, res) => {
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, req.get("stripe-signature") ?? "", WEBHOOK_SECRET);
  } catch {
    return res.sendStatus(400);
  }
  if (!(await recordEventOnce(event.id))) return res.sendStatus(200);
  if (event.type === "checkout.session.completed") await markPaid(event.data.object.metadata.orderId);
  res.sendStatus(200);
});
```

### Python (Flask, generic HMAC)

Vulnerable: a missing header skips the check, and old messages stay valid.

```python
@app.post("/hooks/partner")
def partner_hook():
    sig = request.headers.get("X-Signature")
    if sig and sig != hmac.new(SECRET, request.data, "sha256").hexdigest():
        abort(401)
    apply_event(request.json)
    return "", 204
```

Secure: required header, signed timestamp, constant-time compare, durable deduplication.

```python
@app.post("/hooks/partner")
def partner_hook():
    sig = request.headers.get("X-Signature", "")
    ts = request.headers.get("X-Timestamp", "")
    if not SECRET or not ts.isdigit() or abs(time.time() - int(ts)) > 300:
        abort(401)
    want = hmac.new(SECRET, ts.encode() + b"." + request.get_data(), "sha256").hexdigest()
    if not hmac.compare_digest(sig, want):
        abort(401)
    event = request.get_json()
    if not store_event_id_once(event["id"]):  # unique constraint
        return "", 204
    apply_event(event)
    return "", 204
```

## Dynamic test hints

- Forgery: in a unit test with the framework test client, send a dummy event without a signature, or with a wrong one. Check whether the side effect runs (a dummy order marked paid in an in-memory database).
- Replay: sign a dummy event with a test secret from the test environment and send it twice. Then send one with a timestamp one hour old. Record which ones the handler accepts.
- Fail-open: unset the secret variable in the test and send an unsigned dummy event.
- Use test secrets and fixtures only. Never send events to real provider endpoints, and never use real secrets.

## False positive traps

- An SDK or framework verifies before the handler (Slack Bolt receivers, `@octokit/webhooks` middleware, Cashier with a configured secret, Svix). Quote the wiring.
- The webhook only triggers an authenticated re-fetch from the provider by ID, and the handler acts on the fetched state.
- The endpoint is internal only, as the repository shows. Otherwise use `needs_validation`.
- Provider retries meet an idempotent state transition.
- A timing-unsafe compare alone is a weak finding. Rate it low.
- Example or test handlers that the production router does not register.

## Sources

Condensed and rewritten by kalkan. Vendored copies and pinned commits: `third_party/MANIFEST.json`.

- vercel-labs/deepsec@4fa6722 (Apache-2.0, Vercel): `packages/scanner/src/matchers/webhook-handler.ts`, `slack-signing-verification.ts`, `cron-secret-check.ts`, `insecure-crypto.ts` (timing-unsafe compare), `packages/processor/src/prompt/core.ts`, `slug-notes.ts` (webhook-handler).
- cloudflare/security-audit-skill@c1c8a8c (MIT, Cloudflare): `skills/security-audit/PROTOCOLS-RPC-AND-MESSAGING.md` (untrusted producer as control plane, duplicate delivery, stale messages, callback correlation), `ATTACK-CLASSES.md` (missing HMAC verification).
- block/codecrucible@b5c8086 (Apache-2.0, Block): `prompts/default/analysis_sections.yaml` (protocol_logic: replay and signed-data coverage, concurrency_state: non-idempotent replay), `prompts/core/audit_families.yaml` (authentication: CWE-294).
- alibaba/open-code-review@11ac6d4 (Apache-2.0, alibaba/open-code-review contributors): `internal/config/rules/rule_docs/php.md` (non-constant-time secret comparison).
- Added by kalkan from general knowledge: provider header names and SDK verifiers, raw-body handling per framework, the Laravel Cashier note, the examples.
