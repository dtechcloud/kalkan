---
slug: prototype-pollution
title_en: Prototype pollution
title_tr: Prototype pollution
cwe: CWE-1321
owasp: A08:2021
sources: codecrucible, security-audit-skill, deepsec, open-code-review
---

## Summary

Attacker-controlled keys such as `__proto__`, `constructor` or `prototype` reach a recursive merge, clone or path assignment. The write lands on `Object.prototype` or another shared prototype, so every object inherits the attacker's property. The impact needs a gadget: code that later reads the polluted property and changes authorization, rendering, process options or control flow. Find both the write and the gadget. Pollution without a gadget is a latent bug: lower the severity, do not dismiss it.

## What it is

- **Unsafe recursive merge, clone or extend.** Hand-written `deepMerge` helpers, older versions of `lodash.merge`, `mergeWith`, `defaultsDeep`, `set`, `setWith` and `zipObjectDeep`, `jQuery.extend(true, ...)`, `hoek`, `deep-extend`, `merge`, `mixin-deep`, `set-value`, `dot-prop`, `object-path`, `flat` (unflatten).
- **Path assignment from user input.** `obj[a][b] = value`, `_.set(target, req.body.path, req.body.value)`, reduce-based setters for dotted paths.
- **Nested input sources.** JSON bodies keep `__proto__` as an own key, and a later merge copies it onto a real prototype. Query parsers that build nested objects, WebSocket messages, uploaded config files, `postMessage` data.
- **Client-side pollution.** Browser query or hash parsers merge `__proto__[x]=y` from `location`. Script gadgets in loaded libraries then reach DOM XSS.
- **Python class pollution.** A recursive merge with `setattr` or `__dict__` on objects reaches `__class__`, `__init__.__globals__` and module globals. `pydash.set_` with user paths had the same shape.
- **Ruby class pollution.** A recursive merge into objects with `instance_variable_set` or `public_send("#{key}=")` changes class-level state.

Typical server gadgets: authorization flags read without an own-property check (`user.isAdmin`, `options.role`), template engine options (EJS, Pug, Handlebars), `child_process` options (`shell`, `env`, `NODE_OPTIONS`), sanitizer or HTTP client options. Polluting `toString` or `valueOf` with a non-function crashes the process (shared denial of service).

## What it is not

- Request keys that set fields on a model or DTO (`role`, `isAdmin`) without touching a prototype → `mass-assignment`. A trailing object spread of request data is also mass assignment.
- Java, Go, PHP and .NET have no prototype chain. Request keys that set object fields → `mass-assignment`.
- `node-serialize`, `funcster` and other code-running deserializers → `deserialization`. `eval` of user input → `code-injection`.
- DOM XSS without a pollution step → `xss`. Operator objects in database queries (`{"$gt": ""}`) → `nosqli`.
- A vulnerable lodash version in the lockfile without a reachable merge of attacker keys → `vulnerable-dependency`.

## Where to look

### JavaScript/TypeScript

- Merge, clone, extend and set helpers in `utils/` and `lib/`. Calls that pass `req.body`, `req.query`, `ctx.request.body` or parsed JSON as the source.
- Config loaders that merge user JSON or YAML into defaults. Options objects built by merging user input.
- Body parsers: Express `express.json()` keeps `__proto__` as an own key. Fastify rejects `__proto__` and `constructor` keys by default (`onProtoPoisoning`, `onConstructorPoisoning`). Check the options of other parsers, such as `koa-bodyparser`.
- `Object.assign(target, parsed)` with a parsed `__proto__` key. This changes the prototype of `target` only, not of all objects.
- The lockfile versions of the merge libraries above, for the function that the code calls.

### Browser (client-side JavaScript)

- URL parsers (`deparam`-style helpers, custom `parseQuery`) that build nested objects from `location.search` or `location.hash`.
- `postMessage` handlers and `localStorage` state that merge data into configuration objects.

### Python

- Recursive merge functions that use `setattr`, `getattr` or `__dict__` on objects, not only on dicts.
- `pydash.set_` or `update_` with user-controlled paths. Paths with `__class__`, `__globals__` or `__init__` segments.

### Ruby

- Recursive merges that call `instance_variable_set`, `send` or `public_send` with keys from `params` or parsed JSON.

## Safe patterns

- Skip `__proto__`, `constructor` and `prototype` keys at every level of a recursive merge or path set. Recurse only into own properties (`Object.hasOwn(src, key)`).
- Create user-keyed containers with `Object.create(null)`, or use `Map`.
- Validate input with a schema that strips unknown keys before any merge: Zod `z.object` (strips by default), Joi `stripUnknown`, Ajv `additionalProperties: false` with `removeAdditional`.
- Parse JSON with a parser that rejects prototype keys (`secure-json-parse`, the Fastify default).
- Patched library versions. No `_.set` or `_.setWith` with user paths, or an allowlist of paths.
- Harden gadgets: read options with own-property checks and build option objects with a null prototype.
- Node `--disable-proto=delete` removes the `__proto__` accessor. `Object.freeze(Object.prototype)` at startup blocks writes, but can break libraries.

## Weak mitigations

- A filter for `__proto__` only. `constructor.prototype` reaches the same object.
- A key check at the top level only, not inside the recursion.
- A string check on the joined path while the setter splits it differently (`a.__proto__.x`, `a[__proto__][x]`, arrays of segments).
- A `JSON.parse(JSON.stringify(x))` round trip. The `__proto__` own key survives.
- `Object.freeze` on the target object. `Object.prototype` stays writable.
- Zod `.passthrough()` or Joi `unknown(true)` before the merge. Both keep unknown keys.
- `--disable-proto` alone. The `constructor.prototype` path stays open.

## Verification checklist

- **attacker_control:** Show that attacker-controlled keys, not only values, reach the merge or setter. Show that the key survives parsing: JSON keeps `__proto__`, modern `qs` drops it, Fastify rejects it.
- **privilege_boundary:** Name the gadget and its effect: an authorization flag, a template or process option toward code execution, a sanitizer option toward XSS, or a crash of a shared process. Without a gadget, keep the candidate at low severity or `needs_validation`, and say so.
- **unmitigated:** Quote the recursive write. Show that no key filter, null-prototype target, stripping schema, safe parser or patched version stops it. For a library, give the version from the lockfile.
- State the scope: global (`Object.prototype`, all requests in the process) or local (one object after `Object.assign`).
- On the client, name how a victim receives the polluting URL or message.

## Examples

### JavaScript/TypeScript (recursive merge)

Vulnerable: `{"__proto__": {"isAdmin": true}}` in a JSON body pollutes every object.

```js
function deepMerge(target, src) {
  for (const key in src) {
    if (typeof src[key] === "object" && src[key] !== null) {
      target[key] = deepMerge(target[key] ?? {}, src[key]);
    } else {
      target[key] = src[key];
    }
  }
  return target;
}
const settings = deepMerge(defaults(), req.body);
```

Secure: skip prototype keys and walk own properties only.

```js
const BLOCKED = new Set(["__proto__", "constructor", "prototype"]);
function deepMerge(target, src) {
  for (const key of Object.keys(src)) {
    if (BLOCKED.has(key)) continue;
    const value = src[key];
    target[key] = value && typeof value === "object" ? deepMerge(Object.hasOwn(target, key) ? target[key] : {}, value) : value;
  }
  return target;
}
```

### JavaScript/TypeScript (path setter)

Vulnerable: the client chooses the path, for example `constructor.prototype.isAdmin`.

```js
function setPath(obj, path, value) {
  const keys = path.split(".");
  let cur = obj;
  for (const k of keys.slice(0, -1)) cur = cur[k] ??= {};
  cur[keys.at(-1)] = value;
}
setPath(profile, req.body.path, req.body.value);
```

Secure: only listed paths are allowed.

```js
const ALLOWED = new Set(["display.theme", "display.language", "notify.email"]);
if (!ALLOWED.has(req.body.path)) return res.status(400).end();
setPath(profile, req.body.path, String(req.body.value));
```

### Python (class pollution)

Vulnerable: `{"__class__": {"__init__": {"__globals__": {"ADMIN_MODE": true}}}}` changes a module global.

```python
def merge(src, dst):
    for k, v in src.items():
        if isinstance(dst, dict):
            if isinstance(v, dict) and k in dst:
                merge(v, dst[k])
            else:
                dst[k] = v
        elif hasattr(dst, k) and isinstance(v, dict):
            merge(v, getattr(dst, k))
        else:
            setattr(dst, k, v)
```

Secure: reject dunder keys and merge into plain dicts only.

```python
def merge(src: dict, dst: dict) -> dict:
    for k, v in src.items():
        if not isinstance(k, str) or k.startswith("__"):
            raise ValueError("bad key")
        if isinstance(v, dict):
            v = merge(v, dst[k] if isinstance(dst.get(k), dict) else {})
        dst[k] = v
    return dst
```

## Dynamic test hints

- Run each test in a fresh process, because pollution is global and persists.
- Call the merge with `JSON.parse('{"__proto__":{"kalkanPolluted":"yes"}}')`, then check `({}).kalkanPolluted === "yes"`. Repeat with `{"constructor":{"prototype":{"kalkanPolluted":"yes"}}}`.
- Show the gadget in the same harness with a harmless marker: a dummy user's authorization result changes, or the effective options object shows the polluted value.
- Stop at the changed value. Do not build a code execution chain.
- Python: after the merge, print the changed dummy global. Ruby: print the changed class attribute.

## False positive traps

- `JSON.parse` alone, object spread `{...input}`, `structuredClone`: they create own properties only.
- `Object.assign({}, input)` changes the prototype of the new object only. No global pollution.
- A merge with an explicit key filter (quote it), or targets made with `Object.create(null)` or `Map`.
- Keys from server constants, or from a schema that strips unknown keys.
- A patched library version for the exact function that the code calls.
- Modern `qs` drops prototype keys by default (`allowPrototypes: false`). JSON bodies still need a check.
- A polluted property without a reachable gadget: lower the severity and keep the candidate.

## Sources

Condensed and rewritten by kalkan. Vendored copies and pinned commits: `third_party/MANIFEST.json`.

- block/codecrucible@b5c8086 (Apache-2.0, Block): `prompts/default/cwe_deep_analysis.yaml` (CWE-1321), `prompts/exploit-proof-web-js/cwe_deep_analysis.yaml` (CWE-1321), `prompts/default/analysis_sections.yaml` (dependencies), `prompts/core/audit_families.yaml` (parsing).
- cloudflare/security-audit-skill@c1c8a8c (MIT, Cloudflare): `skills/security-audit/CLIENT-SIDE.md` (prototype pollution and gadget chain, validation rule 2).
- vercel-labs/deepsec@4fa6722 (Apache-2.0, Vercel): `packages/scanner/src/matchers/object-injection.ts`, `spread-operator-injection.ts`, `zod-passthrough-mass-assignment.ts`, `packages/processor/src/prompt/slug-notes.ts`, `highlights.ts` (Koa body parser).
- alibaba/open-code-review@11ac6d4 (Apache-2.0, alibaba/open-code-review contributors): `internal/config/rules/rule_docs/ts_js_tsx_jsx.md` (prototype chain safety).
- Added by kalkan from general knowledge: Python and Ruby class pollution, Fastify and `qs` defaults, Node `--disable-proto`, `Object.assign` scope, the gadget list.
