---
name: javascript
title: JavaScript and TypeScript (Node.js, browsers, React, Next.js)
tech: node, next, express, react, vue, angular, nestjs, fastify, koa, hono
sources: third_party/codecrucible/prompts/exploit-proof-web-js/analysis_sections.yaml, third_party/codecrucible/prompts/exploit-proof-web-js/cwe_deep_analysis.yaml, third_party/open-code-review/rules/rule_docs/ts_js_tsx_jsx.md, third_party/deepsec/processor/prompt/highlights.ts, third_party/deepsec/processor/prompt/slug-notes.ts, third_party/sast-skills/skills/sast-rce/SKILL.md
---

# JavaScript and TypeScript (Node.js, browsers, React, Next.js)

Node.js servers, serverless and edge handlers, and browser code. On the server, trace request data into eval-like APIs, shells, queries, templates, files, and outbound requests. In the browser, trace browser-only sources into DOM sinks. See the `client-side` domain pack for browser trust boundaries.

## Sources of attacker input

- **Node servers:** Express `req.query`, `req.params`, `req.body`, `req.headers`, `req.cookies`, and `req.files`, Koa `ctx.query`, `ctx.params`, and `ctx.request.body`, Fastify `request.query`, `request.params`, and `request.body`, Hono `c.req.query()`, `c.req.param()`, and `c.req.json()`, and NestJS `@Body()`, `@Query()`, `@Param()`, and `@Headers()`.
- **Next.js:** route handler `Request` objects, `params` and `searchParams` in pages, layouts, and middleware, Server Action arguments and form data, `getServerSideProps` context, and `pages/api` routes.
- **Realtime and jobs:** WebSocket and Socket.IO messages, `socket.handshake` fields, GraphQL arguments, and queue job data (BullMQ `job.data`).
- **Browser:** `location.hash`, `location.search`, `document.referrer`, `window.name`, `postMessage` `event.data`, storage, router params (`useParams`, `useSearchParams`), and server data that other users wrote.

## Dangerous sinks

### code-injection

- `eval`, `new Function`, `setTimeout` and `setInterval` with a string, the `vm` functions (`vm` is not a sandbox), `require(user)`, and `import(user)`.

### os-command-injection

- `child_process.exec` and `execSync` (always a shell), `spawn` and `execFile` with `shell: true`, template strings such as `` exec(`convert ${f} out.png`) ``, and `shelljs.exec`. Argument injection still applies without a shell.

### sqli

- Template literals or concatenation in `pg`, `mysql2`, or `sqlite3` queries, `knex.raw(user)`, `sequelize.query` without replacements, `sequelize.literal(user)`, TypeORM `query()` and string `where()`, and Prisma `$queryRawUnsafe` and `$executeRawUnsafe`. Identifiers and `ORDER BY` from input need an allowlist.

### nosqli

- `User.find(req.body)` or `findOne({ email, password })` with values that can be objects with `$ne`, `$gt`, or `$regex`. `$where` and `$function` with input run JavaScript in the database.

### prototype-pollution

- `_.merge`, `_.defaultsDeep`, `_.set`, `_.setWith`, `deepmerge`, and hand-written recursive merges with attacker keys (`__proto__`, `constructor`, `prototype`), plus a gadget that reads the polluted property. Query parsers such as `qs` build nested objects from `a[b][c]=x`.

### xss

- DOM: `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, jQuery `.html()` and `$(html)`, and `href` or `src` with a `javascript:` URL.
- Frameworks: React `dangerouslySetInnerHTML`, Vue `v-html`, and Angular `[innerHTML]` after `bypassSecurityTrustHtml`.
- Server templates: EJS `<%- %>`, Handlebars `{{{ }}}`, Pug `!{}` and `!=`, Nunjucks `|safe` or `autoescape: false`, and `` res.send(`<div>${x}</div>`) ``.
- JSON inside `<script>` that does not escape `</`.

### ssti

- `pug.compile(user)`, `ejs.render(user)`, `Handlebars.compile(user)`, `nunjucks.renderString(user)`, and `_.template(user)`, where the template source comes from input.

### path-traversal

- `fs.readFile`, `fs.createReadStream`, `fs.writeFile`, and `res.sendFile` with input, `path.join(base, user)` without a resolve-and-prefix check, `express.static` with a user-influenced root, multer `destination` and `filename` callbacks, and archive extraction (`adm-zip`, `unzipper`, `tar`) without entry checks.

### ssrf

- `fetch`, `axios`, `got`, `node-fetch`, `undici`, and `http.request` with a URL from input. Most clients follow redirects by default. A hostname check before the request does not stop DNS rebinding.

### open-redirect

- `res.redirect(req.query.next)`, Next.js `redirect(user)`, `router.push(user)`, and `window.location = user`. A leading-slash check must also reject `//host` and `/\host`.

### deserialization

- `node-serialize` `unserialize`, `funcster`, `cryo`, and `js-yaml` 3.x `load` (js-yaml 4 `load` is safe).

### jwt

- `jsonwebtoken` `verify` without an `algorithms` list, `jwt.decode` used as verification, one key for both HMAC and RSA algorithms, and weak or hardcoded secrets.

### csrf

- Cookie-authenticated routes that change state without a CSRF token, an origin check, or `SameSite`, and GET routes that change state. Next.js Server Actions compare `Origin` with `Host`. Custom route handlers do not.

### cors

- `cors({ origin: true, credentials: true })`, reflected `req.headers.origin`, unanchored regex origins, and the `null` origin with credentials.

### mass-assignment

- `Model.create(req.body)`, `Object.assign(user, req.body)`, `prisma.user.update({ data: req.body })`, Sequelize `update(req.body)` without `fields`, Mongoose `strict: false`, and NestJS `ValidationPipe` without `whitelist: true`.

### crypto

- `Math.random()` for tokens, `crypto.createCipher` (no IV, removed in Node.js 22), ECB modes, MD5 or SHA-1 for passwords, `===` on secrets, `rejectUnauthorized: false`, and `NODE_TLS_REJECT_UNAUTHORIZED=0`.

### hardcoded-secrets

- Secrets in `NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`, or `PUBLIC_` variables (they ship to the browser), `process.env.KEY || "fallback-secret"`, and keys in client bundles or source maps.

### missing-authz

- Express routes registered before `app.use(auth)`, Next.js route handlers and Server Actions without an auth call, and NestJS controllers without `@UseGuards`.

### idor

- `findById(req.params.id)`, `findUnique({ where: { id } })`, and similar lookups without an owner or tenant condition.

### dos-redos

- Regexes with nested quantifiers on input (V8 backtracks), no body size limit, synchronous CPU or file work (`pbkdf2Sync`, `readFileSync`) on request paths, and unbounded GraphQL depth.

### sensitive-data-exposure

- Error handlers that send `err.stack` or `err.message`, and responses that return whole database rows.

## Framework notes

### Express

- Middleware order is the auth model. A route defined before `app.use(authMiddleware)` is public.
- `req.query` values can be arrays (`?a=1&a=2`). With the extended parser (the Express 4 default) they can also be objects (`?a[b]=1`). Type confusion breaks string checks.
- `res.sendFile` with the `root` option rejects traversal. A joined absolute path does not.

### Next.js

- `middleware.ts` alone is not authentication. Its matcher can miss routes. Check the handler or the data function itself.
- Every Server Action and route handler is a public endpoint. Each needs its own authentication and authorization.
- `unstable_cache` and `revalidateTag` with user-controlled keys can share data across users.
- `images.remotePatterns` with wildcard hosts lets the image optimizer fetch from any host.

### React

- JSX escapes text. The escape hatches are `dangerouslySetInnerHTML`, `ref.current.innerHTML`, and URL attributes with `javascript:`.
- Server-rendered state in `<script>` tags must escape `</`.

### Vue and Angular

- Vue escapes `{{ }}`. `v-html` does not.
- Angular sanitizes `[innerHTML]`. `bypassSecurityTrust*` turns the sanitizer off.

### NestJS

- Guards (`@UseGuards`) are the auth layer. Check `@Public()` decorators that opt out of a global guard.
- A DTO without `class-validator` rules, or a `ValidationPipe` without `whitelist`, passes extra fields to services.

### Fastify, Koa, and Hono

- Register hooks (`onRequest`, `preHandler`) and middleware before the routes they protect. Fastify plugins keep their hooks inside their own scope.
- Hono often runs at the edge. Check whether it calls a separate backend without the user identity.

### Node.js runtime

- `vm` is not a security boundary, and `child_process.exec` always uses a shell.
- `Buffer.allocUnsafe` returns uninitialized memory. Never send it before a full write.

## Safe idioms

- Parameterized queries (`pool.query("... WHERE id = $1", [id])`), query builders with bound values, and Prisma tagged templates.
- `execFile` or `spawn` with an argument array, no shell, and `--` before user values.
- `textContent`, framework escaping, and DOMPurify with a strict configuration for required HTML.
- `path.resolve(base, name)`, then a check that the result starts with `base + path.sep`.
- `crypto.randomBytes`, `crypto.randomUUID`, `crypto.timingSafeEqual`, and `bcrypt`, `argon2`, or `scrypt` for passwords.
- Schema validation (Zod, Joi, class-validator with `whitelist`) that builds new objects from known fields.
- `jose` `jwtVerify`, or `jsonwebtoken` `verify` with an explicit `algorithms` list.
- `Object.create(null)` or `Map` for dictionaries keyed by input.

## Common false positives

- Prisma `$queryRaw` tagged templates, and knex or Sequelize calls with bindings.
- `exec` or `spawn` with only literal arguments.
- `dangerouslySetInnerHTML` with a constant string or with DOMPurify output.
- `Object.assign({}, obj)` and object spread. A shallow copy does not pollute `Object.prototype`.
- `JSON.parse` of input without a later recursive merge into a shared object.
- `cors()` with `*` on a public API that uses no cookies.
- `Math.random()` for UI effects, sampling, or test data.
- Secrets from `process.env` in server-only files that client components do not import.
- Files under `dist/`, `build/`, `.next/`, or `node_modules/`. Review the source, not the build output.

## Sources

- `third_party/codecrucible/prompts/exploit-proof-web-js/analysis_sections.yaml` and `cwe_deep_analysis.yaml`, from block/codecrucible at commit `b5c8086` (Apache-2.0, Copyright 2026 Block, Inc.).
- `third_party/open-code-review/rules/rule_docs/ts_js_tsx_jsx.md`, from alibaba/open-code-review at commit `11ac6d4` (Apache-2.0, Copyright 2026 alibaba/open-code-review contributors).
- `third_party/deepsec/processor/prompt/highlights.ts` (Next.js, React, Express, Fastify, NestJS, Hono, Koa, GraphQL, Socket.IO, and BullMQ entries) and `slug-notes.ts`, from vercel-labs/deepsec at commit `4fa6722` (Apache-2.0, Copyright 2026 Vercel, Inc. and contributors).
- `third_party/sast-skills/skills/sast-rce/SKILL.md` (Node.js sink lists), from utkusen/sast-skills at commit `db52227` (MIT License, Copyright (c) 2026 Utku Sen).
- kalkan condensed and rewrote the material, regrouped it by kalkan class slug, and added version notes.
