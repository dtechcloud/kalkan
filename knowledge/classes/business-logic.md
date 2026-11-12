---
slug: business-logic
title_en: Business logic flaws
title_tr: İş mantığı hataları (business logic)
cwe: CWE-840, CWE-841, CWE-1284
owasp: A04:2021
sources: sast-skills, security-audit-skill, codecrucible, deepsec, open-code-review
---

## Summary

The code does what it says, but not what the business rule requires. A request is valid, authenticated and authorized, but it breaks a rule that the server never enforces. Typical rules cover price, quantity, limits, workflow order, one-time use, entitlements and time windows. Pattern matching rarely finds these flaws. Read the domain, name the rule, then find its enforcement point.

## What it is

- **Parameter trust.** The client sends the price, total, discount, fee, currency or exchange rate, and the server uses it instead of its own data. The item ID changes between the price lookup and the charge.
- **Numeric range (CWE-1284).** Negative quantities or amounts turn a charge into a credit or reverse a transfer. Zero, huge and fractional values also break rules.
  - `-1` skips a guard like `if limit > 0 { check }`.
  - `0` means "unlimited" by mistake.
  - A negative duration sets an expiry in the past or disables it.
- **Money arithmetic.** Floating-point currency, rounding per line that favors the attacker, overflow in `quantity * price`, split payments with a loose tolerance.
- **Workflow bypass (CWE-841).** A client calls step 3 without steps 1 and 2 (payment, email check, KYC, approval). A `PATCH` sets `status=approved` directly. A completion token works twice. A failed step leaves earlier effects in place.
- **One-time use and limits.** Coupon reuse or stacking, invite and referral reuse, self-referral, trial farming, per-user caps that the client sends, quota counters that some paths skip.
- **Entitlements.** The plan is checked at purchase time only, or a cached entitlement survives a downgrade. Premium features stay reachable through the API.
- **Refunds.** A refund after consumption or download, partial refunds above the total, a refund to a different payment method.
- **Fulfillment on the wrong signal.** The order ships when the client reaches the success URL, not when the verified payment event arrives.
- **Time.** Client-supplied timestamps, timezone shifts, `<` instead of `<=` at a boundary, grace periods that renew forever.
- **Fail-open defaults.** Missing config, a disabled feature flag or a failed dependency turns a rule off.
- **Separation of duties.** A user with the approver role approves a request that the same user created.

## What it is not

- Two parallel requests pass the same check-then-act (double spend, coupon race) → `race-condition`.
- No rate limit or brute-force protection → `rate-limit-bruteforce`.
- A price or role field written through automatic request binding → `mass-assignment`.
- Missing login, role, owner or tenant checks → `authn`, `missing-authz`, `idor`, `multi-tenant`.
- Huge page sizes or expensive queries → `dos-redos`. On-chain economics → `smart-contract`.
- Unsigned or replayed payment webhooks → `webhook-replay`. Reuse of password reset tokens → `authn`.

## Where to look

Map the domain first:

- Money: orders, payments, wallets, refunds, payouts.
- Limits: quotas, ratings, seats.
- Workflows: checkout, KYC, approvals, bookings.
- Promotions: coupons, referrals, trials.
- Entitlements: plans, feature flags.

Search for field names: `price`, `amount`, `total`, `discount`, `qty`, `balance`, `credit`, `fee`, `limit`, `quota`, `status`, `step`, `expires`, `coupon`, `referral`, `plan`. For each rule, find the server-side enforcement point. Then check every path: UI API, mobile API, batch, import, admin and legacy routes.

### Python (Django, Flask, FastAPI)
- Serializers and Pydantic models without range checks (`gt=0`, `le=...`). `IntegerField` where `PositiveIntegerField` fits. No `CheckConstraint`. `float` for money instead of `Decimal`.
- Views that set `status` directly instead of a state-machine transition.

### JavaScript/TypeScript (Express, Next.js, NestJS)
- Zod or Joi `number()` without `.int()`, `.positive()` or `.max()`. Money in floats. Checkout code that sends a client `amount` or `price` to the payment provider.
- Fulfillment in the success-page handler instead of the verified webhook. Server Actions that accept totals.

### Java (Spring)
- Missing `@Positive`, `@Min` or `@Max` on input DTOs. `double` for money instead of `BigDecimal`. Status enums changed through a generic `PATCH`.

### Go
- Integer conversion and overflow in money math. Handlers that copy `req.Status` into the record.

### PHP (Laravel)
- Missing `min:`, `max:` or `integer` validation rules. Loose `==` comparisons on amounts, codes or statuses. Floats for money.

### Ruby (Rails)
- Missing `numericality` validations. `update(status: params[:status])`. AASM or state-machine transitions bypassed with `update_column`.

### C#/.NET (ASP.NET Core)
- Missing `[Range]` attributes. `double` for money instead of `decimal`. Multi-step writes without a transaction.

## Safe patterns

- Re-derive prices, totals, discounts and fees on the server. Ignore the arithmetic of the client.
- Validate ranges on the server: sign, integer type, upper bounds, allowed enum values.
- Use decimal types or integer minor units for money, with one rounding rule.
- Model workflows as server-side state machines. Each transition checks the current state and the actor.
- Mark one-time items as used in the same transaction as the benefit. Add a unique constraint per user and code.
- Check entitlements at the point of use, from current server data.
- Fulfill orders from the verified payment event.
- Use server time and clear boundary rules. Fail closed when config, flags or dependencies are missing.
- Add database constraints (`CHECK`, `UNIQUE`) as a second layer.

## Weak mitigations

- Client-side checks: HTML `min` and `max`, disabled buttons, hidden fields.
- Validation on create but not on update, import or a second API.
- A check of the cart total but not of each line item.
- A "used" flag in the client session or cookie.
- API documentation that says "must be positive".
- A state flag set after the external side effect, for example after the charge.

## Verification checklist

- **attacker_control:** Name the request that the attacker sends (field, value, step order) and quote where the server accepts it. A normal user account is usually enough.
- **privilege_boundary:** Name the rule and the business impact: free or cheaper goods, moved money, exceeded limits, a skipped step, a reused benefit. Quote where the product defines the rule. Without a defined rule, it is not a finding.
- **unmitigated:** Quote where the rule must be enforced (handler, service, database constraint, state machine) and show the gap. Check database constraints, ORM validators and later checks, for example at payment capture.
- If the only gap is concurrency, route the finding to `race-condition`.
- If the rule lives in an external system that you cannot see (payment provider config), answer `unknown`.

## Examples

### JavaScript/TypeScript (Express, Next.js, NestJS)
```js
// Vulnerable: the client decides the price
const total = req.body.items.reduce((s, i) => s + i.price * i.qty, 0);
await payments.charge(req.user.id, total);
```

```js
// Secure: server prices, integer cents, positive integer quantities
let total = 0;
for (const { id, qty } of req.body.items) {
  if (!Number.isInteger(qty) || qty < 1 || qty > 100) return res.sendStatus(400);
  total += (await catalog.priceCents(id)) * qty;
}
await payments.charge(req.user.id, total);
```

### Python (Django, Flask, FastAPI)
```python
# Vulnerable: a negative amount moves money from the recipient
def transfer(sender, recipient, amount):
    sender.balance -= amount
    recipient.balance += amount
```

```python
# Secure: positive amount, enough funds, one transaction with row locks
def transfer(sender_id, recipient_id, amount: Decimal):
    if amount <= 0:
        raise ValidationError("amount")
    with transaction.atomic():
        s = Account.objects.select_for_update().get(pk=sender_id)
        if s.balance < amount:
            raise ValidationError("funds")
        ...
```

### Ruby (Rails)
```ruby
# Vulnerable: the requester sets any status
@request.update(status: params[:status])
```

```ruby
# Secure: a server-side transition with a state and actor check
@request.approve!(by: current_user) # raises unless pending and approver != requester
```

## Dynamic test hints

- Use a local build with dummy users `alice` and `bob` and a mocked payment provider in test mode. Never use real money or real accounts.
- Price: `POST /api/checkout {"items": [{"id": 1, "qty": 1, "price": 0.01}]}`. The stored total must equal the catalog price.
- Sign and range: `{"qty": -3}`, a transfer of `{"amount": -100}` from alice to bob, `{"rating": 9999}`, `{"max_views": -1}`, `{"expires_in": -3600}`. Expect rejections and unchanged balances.
- Workflow: create an order, skip `/pay`, call `POST /api/orders/<id>/confirm`. Send `PATCH /api/requests/<id> {"status": "approved"}` as the requester. Expect rejections.
- One-time use: apply one coupon twice, one after the other. Reuse the invite code of alice for bob.
- Entitlement: downgrade alice to the free plan, then call a premium API. Expect 403.
- Fulfillment: open the success URL without a payment. Nothing must ship.
- Unit level: call the service functions with boundary values.

## False positive traps

- A database constraint, an ORM validator or a later step enforces the rule. Quote it.
- The client owns the value by design, for example a tip or a donation, within a checked range.
- An operator endpoint exists to override prices, behind an operator role.
- No product rule exists. Do not invent rules that the code and documentation do not state.
- The only gap is a race between parallel requests. That is `race-condition`.

## Sources

Condensed and rewritten from the local copies under `third_party/`.

- `utkusen/sast-skills@db52227: sast-files/.claude/skills/sast-businesslogic/SKILL.md` (MIT, Utku Sen): IS / IS NOT lists, attack categories, server-side enforcement checks.
- `cloudflare/security-audit-skill@c1c8a8c: skills/security-audit/ATTACK-CLASSES.md` (MIT, Cloudflare): business logic, feature abuse, chained trust and default or fallback behavior.
- `block/codecrucible@b5c8086: prompts/default/analysis_sections.yaml` (Apache-2.0, Block): the business logic section (parameter trust, semantic range, workflow, reuse, rounding, time) and the protocol logic section (state machine, arithmetic).
- `vercel-labs/deepsec@4fa6722: packages/processor/src/prompt/slug-notes.ts` (`non-atomic-operation`) and `packages/scanner/src/matchers/security-behind-flag.ts` (Apache-2.0, Vercel): check-then-act notes, fail-open flags.
- `alibaba/open-code-review@11ac6d4: internal/config/rules/rule_docs/default.md`, `php.md` (Apache-2.0, alibaba/open-code-review contributors): boundary conditions, loose comparison, transactions.
- Payment fulfillment and separation-of-duties notes come from general knowledge.
