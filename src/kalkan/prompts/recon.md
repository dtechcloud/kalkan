## Task: reconnaissance

Map one aspect of the target so that later hunters know where lower-trust input enters, which boundaries protect what, and which vulnerability classes matter. You return source facts, not findings.

The target copy is at `{{TARGET_DIR}}`. The input below gives your `kind`, the detected technologies, the file inventory and the deterministic tool results so far.

### Input

```json
{{INPUT_JSON}}
```

### Method knowledge

{{KNOWLEDGE}}

### What to map for your `kind`

Do only the part for the `kind` in the input. Other recon tasks cover the other parts.

- **product:** product type, users and operators, the trust-sensitive actions a normal user can take; languages, frameworks, build system, runtimes and deployment models visible in the repository; main entry points and subsystem boundaries; a comparable well-known product when the source makes the comparison clear (otherwise say none).
- **principals:** each lower-trust principal (anonymous client, user, user of another tenant, operator, upstream service, message producer, local user, CI contributor, model or tool caller) and the actions it has by design; how each entry surface authenticates; where per-resource authorization and tenant or owner scoping happen; privilege changes, confirmation, revocation, account recovery and fallback paths; which controls are visible in source and which depend on deployment.
- **surfaces:** every place where external or lower-trust input enters: HTTP and browser routes, RPC and GraphQL, queues and webhooks, file uploads and parsers, archives and documents, CLI arguments, environment and configuration, plugins, CI workflows, cloud events, LLM context and tool arguments, mobile deep links and web views, local IPC. For each surface, follow the main transformations to the security-relevant sinks (database, shell, file system, outbound HTTP, template, deserializer, crypto, auth decision). Record parallel paths to the same effect (legacy routes, batch jobs, admin variants).
- **execution:** tests, fixtures and small harnesses that could later reproduce a finding with dummy data; compose files and Dockerfiles that start the application; build and test commands (do not run them); commands that would fetch dependencies or touch shared systems (mark them as prohibited); deployment facts that source cannot show but that decide security (reverse proxy, WAF, IAM, feature flags).

### Method

1. Start with the file inventory and manifests in the input. Use Glob to find route files, controllers, handlers, middleware, configuration and infrastructure files. Use Grep for framework markers (route decorators, `router.`, `@app.`, `@RequestMapping`, `http.HandleFunc`, `Route::`, `resources :`).
2. Read the files that define structure: entry points, routers, middleware chains, auth setup, data access layers, configuration loaders.
3. Every fact needs evidence: a file, a line and a quote. A fact you cannot quote goes to `uncertainties`.
4. Stay broad, not deep. Do not hunt for bugs. When you notice a likely weakness, record the surface and add the class to `classes_of_interest`; the hunters will check it.
5. Stop when your part is mapped. A large repository needs a representative map, not every file.

### Result fields

- `kind`: the kind from the input.
- `summary_md`: Markdown, at most 400 words, about your part only. The engine joins the four summaries into the architecture summary that every hunter reads, so make it dense and factual: name files, principals, boundaries and controls.
- `facts`: important statements, each with one or more quotes.
- `surfaces`: entry surfaces you found. `id` is short and unique within your result (for example `http-users-get`). `auth` is the weakest authentication the surface requires: `none`, `user`, `privileged` (admin or operator), `service` (machine credentials) or `unknown`. `trust_boundary` names who crosses into what (for example "internet to API", "tenant A to shared database"). `subsystem` is the component or package. Kinds `product`, `principals` and `execution` list only surfaces they notice on the way; `surfaces` lists all of them.
- `classes_of_interest`: taxonomy slugs that the code makes relevant (for example `sqli` when raw SQL is built, `ssrf` when the server fetches user-supplied URLs, `idor` when routes take object IDs). Include a class only for a source-visible reason.
- `sensitive_data`: kinds of sensitive data the system stores or moves (credentials, tokens, personal data, payment data, secrets).
- `uncertainties`: decisive facts you could not settle from source.

