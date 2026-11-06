---
slug: graphql
title_en: GraphQL-specific issues
title_tr: GraphQL
cwe:
owasp: A05:2021
sources: sast-skills, security-audit-skill, deepsec, open-code-review, codecrucible
---

## Summary

A GraphQL endpoint makes every field, mutation and subscription its own entry point. This class covers the GraphQL-specific bugs. User strings build operation documents. Authorization depends on the query path. Depth, cost, aliases or batching have no limits. Introspection or IDEs are open on an untrusted production surface. A resolver bug with its own class (SQL injection, IDOR, SSRF) keeps that class.

## What it is

- **Operation document injection.** User text goes into the document (query, mutation or subscription text) instead of the `variables` map. The server builds a new document from strings and runs or forwards it. The attacker adds fields, aliases, fragments or directives. Suggested CWE: CWE-74.
- **Path-dependent authorization.** A sensitive type or field is protected on one path but reachable through another: nested relations, interfaces and unions, `node(id:)` lookups by global ID, federation `_entities`. Suggested CWE: CWE-863.
- **Field-level exposure.** The parent object is allowed, but fields such as `email`, `role`, `passwordHash` or `apiKey` have no check of their own.
- **Missing cost controls.** No limit on depth, complexity, aliases, root fields, tokens, batch size or page size. Recursive types (`user { friends { friends ... } }`) multiply the work. Suggested CWE: CWE-770.
- **Batching past rate limits.** One HTTP request carries hundreds of aliased `login` or `verifyOtp` mutations, or a JSON array of operations. A per-request limiter counts one. Suggested CWE: CWE-307 or CWE-799.
- **Per-request state errors.** A DataLoader or cache created at module level shares results across users. A subscription authorized once at connect keeps sending events after the role changes.
- **Introspection, field suggestions and IDEs** (GraphiQL, Playground) on an untrusted production endpoint. Usually low severity. Suggested CWE: CWE-200.

## What it is not

- SQL or NoSQL injection in resolver code → `sqli` or `nosqli`. SSRF from a resolver → `ssrf`.
- One resolver that loads an object by an attacker-supplied ID without an owner check → `idor`.
- A mutation without the role check that its REST twin has → `missing-authz`. Cross-tenant reads → `multi-tenant`.
- Mutations over GET or form-encoded requests with cookie authentication → `csrf`.
- Stack traces in GraphQL error responses → `sensitive-data-exposure`.
- Body size limits and server timeouts in general → `dos-redos`.
- A client that sends its own document with a static query and bound variables → no finding.

## Where to look

### JavaScript/TypeScript

- Apollo Server: `introspection` (on unless `NODE_ENV` is `production`), `validationRules`, `allowBatchedHttpRequests`, `csrfPrevention`, `includeStacktraceInErrorResponses`.
- Limit packages: `graphql-depth-limit`, `graphql-query-complexity`, `graphql-validation-complexity`, `@escape.tech/graphql-armor`. GraphQL Yoga plugins, Mercurius `queryDepth` and `allowBatchedQueries`.
- Auth wiring: NestJS guards with `GqlExecutionContext`, type-graphql `@Authorized`, Pothos or Nexus `authorize`, graphql-shield (`fallbackRule: allow` fails open).
- `new DataLoader(...)` outside the per-request context factory.
- Document building: template literals with `${...}` in `gql`, `graphql({ source })` or in a fetch body `query` field.

### Python

- Graphene `GraphQLView(graphiql=True)`, `DjangoObjectType` with `fields = "__all__"`, auth middleware.
- Strawberry `permission_classes`, extensions `QueryDepthLimiter`, `MaxAliasesLimiter`, `MaxTokensLimiter`, `DisableIntrospection`. Ariadne `introspection` and `debug`.
- `graphql_sync(schema, f"...")` with user text.

### Java/Kotlin

- graphql-java `MaxQueryDepthInstrumentation`, `MaxQueryComplexityInstrumentation`, `NoIntrospectionGraphqlFieldVisibility`.
- Spring for GraphQL `spring.graphql.schema.introspection.enabled`, `spring.graphql.graphiql.enabled`, `@PreAuthorize` on `@QueryMapping` and `@SchemaMapping`. Netflix DGS data fetchers.

### Go

- gqlgen `handler.NewDefaultServer` adds introspection and has no complexity limit. Look for `extension.FixedComplexityLimit` and `@hasRole` directive code.
- graph-gophers/graphql-go `MaxDepth`, `MaxParallelism`, `DisableIntrospection`.

### PHP

- webonyx/graphql-php `DocumentValidator::addRule` with `QueryDepth`, `QueryComplexity`, `DisableIntrospection`.
- Lighthouse `config/lighthouse.php` security keys, `@guard` and `@can` directives.

### Ruby

- graphql-ruby `max_depth`, `max_complexity`, `disable_introspection_entry_points`, `authorized?` on types and fields.

### C#/.NET

- Hot Chocolate `AddMaxExecutionDepthRule`, cost options, `[Authorize]` on fields, introspection settings. GraphQL.NET complexity settings.

### Schema files

- `*.graphql` and `*.graphqls`: list fields without `first` or `limit`, recursive types, sensitive fields without an auth directive, `node`/`nodes` fields, federation `@key` types.

## Safe patterns

- Static documents with variables. A persisted query allowlist (registered at build time) for first-party clients.
- Authorization in the business layer or per field, so that every path runs it. Deny by default (graphql-shield `fallbackRule: deny`). The `node(id:)` resolver checks the permission of the resolved type.
- A new DataLoader per request, created in the context factory.
- Limits: depth (for example 10 to 15) and a cost budget with list multipliers. Also caps on aliases, root fields, tokens, batch size and page size, and a timeout.
- Rate limits that count operations and aliases, not HTTP requests.
- Introspection, suggestions and IDEs off on the public production endpoint, or staff only.
- Masked errors in production. POST with `application/json` only, or a required custom header (Apollo CSRF prevention).
- Subscriptions: authenticate the connection and filter each event per subscriber.

## Weak mitigations

- Introspection off as the only control. Field suggestions, client bundles and schema-guessing tools still reveal the schema.
- Automatic persisted queries (APQ) treated as an allowlist. Any client can register a new hash.
- A depth limit without cost or alias limits. Wide queries, aliases and fragments still multiply the work.
- Per-request rate limits on login, OTP or coupon mutations.
- Authorization on the top-level field only, or in the client UI only.
- Escaping quotes in user text before string concatenation into a document.
- Authorization at the gateway only while the subgraphs accept direct requests.

## Verification checklist

- **attacker_control:** Show that the attacker reaches the endpoint, anonymous or with a normal account. Show the decisive part that the attacker controls: document text, query shape (depth, aliases, batch), a global ID, or subscription arguments.
- **privilege_boundary:** Name the gain: forbidden fields or objects, a forbidden mutation, brute force past a per-request limit, or work far beyond one normal request on a shared service. Introspection alone gives the schema only. Rate it low unless the schema is confidential.
- **unmitigated:** Quote the server setup (missing rules or plugins, introspection setting) or the path that skips the check. Show that no gateway, persisted query allowlist or global guard covers it.
- List every path to the sensitive type: root fields, nested relations, `node`, `_entities`, interfaces and unions.
- Check the defaults of the pinned server version and the scope of each DataLoader.

## Examples

### JavaScript/TypeScript (document injection)

Vulnerable: user text becomes part of the forwarded document.

```ts
app.post("/proxy", async (req, res) => {
  const query = `query { me { ${req.body.fields} } }`;
  res.json(await internalGraphql({ query }));
});
```

Secure: a fixed document. User data goes into variables only.

```ts
const ME = `query Me($withEmail: Boolean!) { me { id name email @include(if: $withEmail) } }`;
app.post("/proxy", async (req, res) => {
  res.json(await internalGraphql({ query: ME, variables: { withEmail: req.body.withEmail === true } }));
});
```

### JavaScript/TypeScript (Apollo Server limits)

Vulnerable: no depth or cost rules.

```ts
const server = new ApolloServer({ typeDefs, resolvers, introspection: true });
```

Secure: validation rules limit depth and cost. Introspection follows the environment.

```ts
const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: process.env.NODE_ENV !== "production",
  validationRules: [depthLimit(10), createComplexityLimitRule(1000)],
});
```

### Python (Strawberry field permission)

Vulnerable: `invoices` is reachable through `team { members { invoices } }` for any viewer.

```python
@strawberry.type
class User:
    name: str

    @strawberry.field
    def invoices(self) -> list[Invoice]:
        return invoices_for(self.id)
```

Secure: the field checks the viewer on every path.

```python
class IsSelf(BasePermission):
    message = "forbidden"

    def has_permission(self, source, info, **kwargs) -> bool:
        return info.context.user.id == source.id

@strawberry.type
class User:
    name: str

    @strawberry.field(permission_classes=[IsSelf])
    def invoices(self) -> list[Invoice]:
        return invoices_for(self.id)
```

## Dynamic test hints

- Run the schema in-process (`graphql(...)`, `schema.execute_sync(...)`, the server test client) with mocked data sources and a dummy viewer.
- Injection: call the vulnerable function with `fields` set to `id } adminStats { total`. Show that the result has the extra root field.
- Batching: send one request with 50 aliased `login` mutations and dummy credentials. Count the resolver calls.
- Depth: run a nested query of depth 20 on a small fixture. Count resolver calls and stop early. Do not measure capacity.
- Paths: query the sensitive field through a second path (`node(id:)`, a nested relation) as another dummy user.
- Introspection: run `{ __schema { types { name } } }` with the production config.

## False positive traps

- A server that parses and runs the client's own document is not injection. Only a new document built from user strings on the server is.
- A static document with variables, even when the variables come from the user.
- Introspection on an internal or development endpoint, or a schema that the product publishes.
- Limits at the gateway or router (for example Apollo Router limits). Quote the config, or use `needs_validation`.
- A global guard or schema directive that wraps every field (quote the wiring).
- Lists that the data model bounds, or pagination with a server-side cap.
- Batching that the server version disables by default (Apollo Server 4 `allowBatchedHttpRequests`).

## Sources

Condensed and rewritten by kalkan. Vendored copies and pinned commits: `third_party/MANIFEST.json`.

- utkusen/sast-skills@db52227 (MIT, Utku Sen): `sast-files/.claude/skills/sast-graphql/SKILL.md` (what injection is and is not, prevention patterns, examples).
- cloudflare/security-audit-skill@c1c8a8c (MIT, Cloudflare): `skills/security-audit/PROTOCOLS-RPC-AND-MESSAGING.md` (interceptor gaps, per-item and streaming authorization), `RESOURCE-EXHAUSTION-AND-AVAILABILITY.md` (query amplification).
- vercel-labs/deepsec@4fa6722 (Apache-2.0, Vercel): `packages/processor/src/prompt/highlights.ts` (GraphQL), `slug-notes.ts` (js-graphql-resolver), `packages/scanner/src/matchers/js-graphql-resolver.ts`.
- alibaba/open-code-review@11ac6d4 (Apache-2.0, alibaba/open-code-review contributors): `internal/config/rules/rule_docs/graphql.md` (security and resource limits).
- block/codecrucible@b5c8086 (Apache-2.0, Block): `prompts/default/analysis_sections.yaml` (configuration: introspection and playground).
- Added by kalkan from general knowledge: library and setting names, APQ and DataLoader notes, alias batching, `node` and `_entities` paths, the examples.
