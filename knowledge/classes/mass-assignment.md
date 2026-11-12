---
slug: mass-assignment
title_en: Mass assignment
title_tr: Mass assignment
cwe: CWE-915
owasp: A08:2021
sources: codecrucible, deepsec, sast-skills, open-code-review
---

## Summary

The server copies client fields into a model or a database write without an allowlist. The attacker adds fields that the form never shows: role, admin flag, owner, tenant, balance, price or verification status. The result is privilege escalation, ownership takeover or financial abuse.

## What it is

- **Wholesale binding on create or update.** `User.create(req.body)`, `findByIdAndUpdate(id, req.body)`, `prisma.user.update({ data: req.body })`, `Model::create($request->all())`, `user.update(params[:user].permit!)`.
- **Entity binding.** Spring `@RequestBody User user` then `repo.save(user)`. ASP.NET Core `[FromBody] User user` then `_db.Update(user)`. Go `c.Bind(&user)` then `db.Save(&user)`.
- **Spread order.** `{ role: "user", ...req.body }` lets the body win. `{ ...req.body, role: "user" }` is the safe order.
- **Schemas that keep unknown keys.** Zod `.passthrough()`, Joi `.unknown(true)`, JSON Schema without `additionalProperties: false`, NestJS `ValidationPipe` without `whitelist: true`.
- **Nested writes.** Rails `accepts_nested_attributes_for` that permits privileged nested fields like `role` or `org_id`. Prisma nested `connect` in `data`. GraphQL input types mapped straight to models. JSON Patch on any path, for example `/role`.
- **Wide framework config.** Laravel `$guarded = []`, or `$fillable` with privileged fields. Django `ModelForm` with `fields = "__all__"`. DRF serializers without `read_only_fields`. Rails `permit!`.
- **Fields to look for.** `role`, `is_admin`, `permissions`, `owner_id`, `user_id`, `tenant_id`, `org_id`, `balance`, `credits`, `price`, `discount`, `status`, `plan`, `quota`, `email_verified`, `kyc_passed`, `password_hash`.

## What it is not

- `__proto__` or `constructor` keys in a deep merge → `prototype-pollution`.
- A handler that reads `req.body.price` on purpose and trusts it → `business-logic`.
- A changed object ID in the path → `idor`. A reassigned `owner_id` through binding stays in this class.
- A dedicated role-change endpoint without a role check → `missing-authz`.
- Private fields in responses, for example `password_hash` → `sensitive-data-exposure`.
- Query operators in the body, for example `{"$ne": null}` → `nosqli`.

## Where to look

Find every create, update and upsert that takes request data. List the fields of the model and mark the privileged ones. Then find the allowlist: a DTO, `permit`, `$fillable`, serializer fields or a strict schema.

### Python (Django, Flask, FastAPI)
- `ModelForm` with `fields = "__all__"` or `exclude`. DRF serializers with `fields = "__all__"` and no `read_only_fields`, also on `partial=True` updates.
- `Model.objects.create(**request.data)`, `setattr(obj, key, value)` loops over request JSON, Pydantic input models that mirror the full table.

### JavaScript/TypeScript (Express, Next.js, NestJS)
- Mongoose `new Model(req.body)`, `Object.assign(doc, req.body)`. Prisma `data: req.body`. Sequelize `create(req.body)` without `fields`. TypeORM `repo.merge(entity, req.body)`. Drizzle `.values({ ...body })` or `.set(body)`.
- Zod `.passthrough()`, NestJS `ValidationPipe` options, and spread order in object literals.

### Java (Spring)
- `@RequestBody` or `@ModelAttribute` bound to a JPA entity. Missing `@JsonProperty(access = READ_ONLY)` or `@JsonIgnore` on privileged fields. `BeanUtils.copyProperties(input, entity)`. No `@InitBinder` allowlist.

### Go
- `ShouldBindJSON` or `json.Decode` into the GORM model. `db.Save(&u)` writes every field. `Updates(map)` built from the request body.

### PHP (Laravel)
- `$guarded = []`, `$fillable` with `role` or `is_admin`, `fill($request->all())`, `forceFill`. The safe forms are `$request->validated()` and `$request->only([...])`.

### Ruby (Rails)
- `permit!`, `permit(:role)`, nested attributes that permit `:role`, `:user_id` or `:org_id`.

### C#/.NET (ASP.NET Core)
- Entities as action parameters. `TryUpdateModelAsync(entity)` without an include list. `JsonPatchDocument<User>` applied to the entity. AutoMapper profiles that map privileged members.

## Safe patterns

- Bind input to a DTO or form object that holds only the editable fields. Map them to the entity explicitly.
- Use an allowlist: `permit(:name, :email)`, `$request->only([...])`, serializer `fields = [...]` with `read_only_fields`, `pick(body, [...])`.
- Reject unknown keys in the schema: `additionalProperties: false`, Zod `.strict()`, `whitelist` with `forbidNonWhitelisted`.
- Set server-owned fields after the copy. The owner comes from the session, the role from server defaults.
- Change roles, plans and statuses only through separate endpoints with a role check.

## Weak mitigations

- Denylists: `exclude`, `$guarded = ['id']`, `delete body.role`. They miss new fields, aliases like `isAdmin`, and nested paths.
- A frontend form that omits the field.
- `@JsonIgnoreProperties(ignoreUnknown = true)`. It ignores unknown fields but still binds known ones.
- A default role set before the spread of the body.
- Type validation only. The types match, but the field is privileged.

## Verification checklist

- **attacker_control:** Quote the create or update call and show that request fields reach it without an allowlist. Name the privileged field that the attacker adds.
- **privilege_boundary:** Name the gain: an admin role, ownership of another object, membership in another tenant, free credit, a verified status. A model without sensitive fields refutes the finding.
- **unmitigated:** Quote the missing allowlist, or state that no DTO, strong parameters, `$fillable` limit or strict schema exists. Check that no later line overwrites the field.
- Confirm that the field exists on the model and that the write persists it.
- An admin-only endpoint that sets roles on purpose is not a finding.

## Examples

### JavaScript/TypeScript (Express, Next.js, NestJS)
```js
// Vulnerable: the body can set role or isAdmin
await User.findByIdAndUpdate(req.user.id, req.body);
```

```js
// Secure: explicit allowlist
const { name, bio } = req.body;
await User.findByIdAndUpdate(req.user.id, { name, bio });
```

### PHP (Laravel)
```php
// Vulnerable: protected $guarded = []; on the model
$user->update($request->all());
```

```php
// Secure
$user->update($request->validate(['name' => 'required|string', 'bio' => 'nullable|string']));
```

### Ruby (Rails)
```ruby
# Vulnerable
@user.update(params.require(:user).permit!)
```

```ruby
# Secure
@user.update(params.require(:user).permit(:name, :bio))
```

### C#/.NET (ASP.NET Core)
```csharp
// Vulnerable: the entity is the input model
public async Task<IActionResult> Edit([FromBody] User user) { _db.Update(user); await _db.SaveChangesAsync(); return Ok(); }
```

```csharp
// Secure: a DTO with editable fields only
public async Task<IActionResult> Edit([FromBody] ProfileDto dto) {
    var user = await _db.Users.FindAsync(User.FindFirstValue(ClaimTypes.NameIdentifier));
    user.Name = dto.Name;
    await _db.SaveChangesAsync();
    return Ok();
}
```

## Dynamic test hints

- Use a local build with dummy accounts `alice` and `bob`. Never test real systems.
- Privilege: alice sends `PATCH /api/users/me {"name": "A", "role": "admin", "isAdmin": true, "email_verified": true}`. Then she reads `GET /api/users/me` and calls an admin-only route. Expect no change and a 403.
- Ownership: alice sends `POST /api/projects {"name": "p", "ownerId": "<bob id>", "orgId": "<other tenant>"}`. Check the stored row.
- Money: `POST /api/orders {"itemId": 1, "price": 0}` when the price must come from the server.
- Nested: `{"user": {"memberships_attributes": [{"org_id": "<other org id>", "role": "owner"}]}}`. Check that no membership row appears.
- Unit level: call the service with a body that holds extra fields and assert the saved values.

## False positive traps

- A DTO, `permit` list, `$fillable` limit, serializer field list or strict schema applies.
- The model has no privileged fields. Every column is data that the user may set.
- The code overwrites the field after the copy, for example `user.role = "user"`.
- The field is not on the model or table, so the ORM drops it.
- The endpoint is admin-only and sets these fields on purpose.

## Sources

Condensed and rewritten from the local copies under `third_party/`.

- `block/codecrucible@b5c8086: prompts/default/cwe_deep_analysis.yaml` (CWE-915), `prompts/default/analysis_sections.yaml` (privilege assignment), `prompts/core/audit_families.yaml` (authorization family: allowlist as refutation) (Apache-2.0, Block).
- `vercel-labs/deepsec@4fa6722: packages/processor/src/prompt/slug-notes.ts` (spread order), `highlights.ts` (Django, DRF, Laravel, Rails, Echo notes), `packages/scanner/src/matchers/drizzle-mass-assignment.ts`, `zod-passthrough-mass-assignment.ts` (Apache-2.0, Vercel).
- `utkusen/sast-skills@db52227: sast-files/.claude/skills/sast-idor/SKILL.md`, `sast-businesslogic/SKILL.md` (MIT, Utku Sen): routing of `role=admin` and price tampering.
- `alibaba/open-code-review@11ac6d4: internal/config/rules/rule_docs/php.md` (Apache-2.0, alibaba/open-code-review contributors): mass assignment only when fillable or guarded config does not constrain the fields.
