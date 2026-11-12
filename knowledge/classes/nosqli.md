---
slug: nosqli
title_en: NoSQL injection
title_tr: NoSQL injection
cwe: CWE-943
owasp: A03:2021
sources: codecrucible, deepsec, sast-skills, security-audit-skill
---

## Summary

The application passes an attacker-controlled object, or an attacker string, into a NoSQL query where it expects a plain value. The attacker then smuggles query operators (`$ne`, `$gt`, `$where`, `$regex`) to bypass a login, read other documents, or run server-side code. MongoDB is the common target. The core shape is an untyped request value that reaches a query builder.

## What it is

- **Operator smuggling.** The code passes a whole request object into a query: `User.find(req.body)` or `findOne({ email: req.body.email })`. The attacker sends `{"$ne": null}` or `{"$gt": ""}` in a field where the code expected a string.
- **Login bypass.** `find({ user: input.user, pass: input.pass })` with `pass = {"$ne": null}` matches a document without the password.
- **`$where` with user text.** `$where` runs a JavaScript expression inside the database. Built from an f-string or concatenation, it is server-side code execution, not only a query change.
- **Raw JSON into a query.** `find(JSON.parse(req.body.filter))` or `json.loads(request.json["filter"])` lets the client set any operator key.
- **`$regex` from input.** A user-controlled regular expression causes a slow match (ReDoS) and lets the attacker probe values.
- **Redis / other stores.** `EVAL` with a Lua script built from user text. A DynamoDB filter expression from user input.

## What it is not

- Injection into a SQL query string → `sqli`.
- A ReDoS from a regex with no database query involved → `dos-redos`.
- Passing a whole body into a model create/update to set privileged fields → `mass-assignment`.
- Reaching another user's document with a correct query by changing an ID → `idor`.
- `$where` is also code execution, but it stays in this class when the injection is into the query object.

## Where to look

Find the query call first. Then check whether each field value is a coerced primitive or a raw request value.

### Python (PyMongo, Motor, mongoengine)
- `coll.find({"$where": f"..."})`, `coll.find({...})` where a value is `request.json[...]` without a type cast.
- `coll.find({"name": {"$regex": request.args.get("q")}})`, `re.compile(request...)`.
- `json.loads(request.json["filter"])` passed into a query.
- `Model.objects(__raw__={...})` built from user input.

### JavaScript/TypeScript (Mongoose, MongoDB driver)
- `Model.find(req.body)`, `findOne({ email: req.body.email })` with no coercion.
- `find({ $where: "..." + x })`, `$where: function() {...}`, `aggregate([{ $match: { $where: ... } }])`.
- `new RegExp(req.query.q)` used in a query.
- `find(JSON.parse(req.body.filter))`.

### PHP
- MongoDB queries built from `$_GET` / `$_POST` arrays. PHP parses `field[$ne]=` in the query string into a nested array.

## Safe patterns

- Build the query field by field from validated primitive values. Cast each value to a string or number before it reaches the query.
- A schema layer (Zod, Joi, Pydantic, class-validator, a Mongoose schema with typed paths) that rejects an object where a scalar is expected.
- Reject keys that start with `$` or contain a dot in a request object before use.
- Never put user text inside `$where` or a Lua `EVAL` script. Use a normal query.
- `express-mongo-sanitize` or an equivalent middleware that strips operator keys.

## Weak mitigations

- A blocklist of a few operator names. The set of operators is large.
- A check for `$` only at the top level. An attacker nests the operator one level deeper.
- Escaping quotes. It does not stop an object value from carrying operator keys.
- Trusting the client `Content-Type`. The body shape, not the header, carries the attack.

## Verification checklist

- **attacker_control:** Name the entry point and the field. Quote the query call that takes the raw request value with no coercion.
- **privilege_boundary:** State the gain: a login bypass, reading other documents, or code execution through `$where`.
- **unmitigated:** Confirm no schema or cast turns the value into a primitive before the query. Quote the cast or the schema to refute.
- `$where` and Lua `EVAL` with user text are code execution. Rate them higher than an operator-smuggling read.

## Examples

### JavaScript/TypeScript (Mongoose)
```javascript
// Vulnerable: untyped body value lets {"$ne": null} bypass the password check
const user = await User.findOne({ email: req.body.email, pass: req.body.pass });

// Secure: coerce each value to a string first
const email = String(req.body.email);
const pass = String(req.body.pass);
const user = await User.findOne({ email, pass });
```

### Python (PyMongo)
```python
# Vulnerable: $where built from an f-string runs JS in the database
coll.find({"$where": f"this.age > {request.args['age']}"})

# Secure: a normal typed comparison, no $where
coll.find({"age": {"$gt": int(request.args["age"])}})
```

## Dynamic test hints

- Use a local build and a local database only. Never test a real system.
- Login bypass: send the password field as an object, for example JSON `{"email":"a@b.c","pass":{"$ne":null}}`. A success without the right password confirms it.
- Query string form: `?user[$ne]=&pass[$ne]=` against a local Express or PHP app.
- `$regex`: send `{"email":{"$regex":"^a"}}` and compare which accounts match to confirm value probing.
- `$where`: on a local database only, send `{"$where":"sleep(3000)||true"}` and compare the response time.

## False positive traps

- A DTO or schema (Zod, Joi, Pydantic, class-validator) coerces each field to a primitive before the query.
- The value is cast with `String(...)`, `int(...)` or similar before it reaches the query.
- `express-mongo-sanitize` or an equivalent strips operator keys on the request.
- The query uses a server constant, not a request value.
- The driver method takes a typed argument that cannot hold an operator object.

## Sources

Condensed and rewritten from the local copies under `third_party/`.

- `block/codecrucible@b5c8086: prompts/default/analysis_sections.yaml` (INJECTION, NOSQL), `prompts/exploit-proof-web-js/cwe_deep_analysis.yaml` (CWE-943), `prompts/core/audit_families.yaml` (injection family) (Apache-2.0, Block): the operator-smuggling shape, `$where` code execution, DTO refute.
- `vercel-labs/deepsec@4fa6722: packages/scanner/src/matchers/js-nosql-injection.ts`, `py-nosql-injection.ts`, `processor/src/prompt/slug-notes.ts` (Apache-2.0, Vercel): per-language sinks, `$regex` ReDoS, `JSON.parse(req...)` note.
- `utkusen/sast-skills@db52227: sast-files/.claude/skills/sast-sqli/SKILL.md` (MIT, Utku Sen): the "NoSQL is a distinct class" boundary and the parameterized-ORM-is-safe rule.
- `cloudflare/security-audit-skill@c1c8a8c: skills/security-audit/ATTACK-CLASSES.md` (MIT, Cloudflare): the field/key/metadata injection reminder.
