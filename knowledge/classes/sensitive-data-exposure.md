---
slug: sensitive-data-exposure
title_en: Sensitive data exposure / PII in logs
title_tr: Hassas veri ifşası
cwe: CWE-200, CWE-532
owasp: A01:2021, A09:2021
sources: codecrucible, security-audit-skill, deepsec, open-code-review
---

## Summary

Sensitive data reaches a reader who must not have it. The data can be credentials, tokens, personal or financial data, or internals that enable a named next attack. The channel can be an API response, an error, a log, a trace, an analytics event, an export, a URL or client storage. Name what leaks, through which channel, to which audience. "Information disclosure" alone is a category, not a finding.

## What it is

- **Over-serialization (CWE-213).** `res.json(user)` returns `password_hash`, `reset_token`, `mfa_secret`, `api_key` or internal flags. DRF `fields = "__all__"`, FastAPI routes without `response_model`, entities returned without a DTO.
- **Error details to clients (CWE-209).** Stack traces, SQL errors with query text, absolute paths and internal host names in responses. Driver messages in `err.message` often carry SQL and values.
- **Secrets and personal data in logs (CWE-532).** Logged request bodies, `Authorization` headers, cookies, passwords of failed logins, tokens, card numbers. Logging the whole request object does all of this at once.
- **Traces and error trackers.** Sentry, Datadog or OpenTelemetry attributes with request bodies, headers or user records.
- **Secrets in URLs (CWE-598).** Tokens, passwords or session IDs in query strings reach proxy logs, browser history and the `Referer` header.
- **Debug information from code (CWE-215, CWE-497).** A handler that returns `process.env`, `phpinfo()` output, configuration dumps or heap data.
- **Directory listing (CWE-548)** and files served from the web root: `.git/`, backups, dumps, source maps with secrets.
- **Cleartext storage (CWE-312, CWE-522).** Plaintext or reversibly encrypted passwords (CWE-256, CWE-257). Sensitive fields stored in clear where a lower-trust reader exists.
- **Derived copies.** Exports, backups, analytics, search indexes or dead-letter queues that hold data above the reader's access.
- **Existence oracles** that reveal a confidential fact, such as a private record or a hidden account. Public account existence alone is not enough.

## What it is not

- A literal secret in source or git history → `hardcoded-secrets`.
- Another user's object returned because the ownership check is missing → `idor`. Cross-tenant reads → `multi-tenant`. This class covers extra fields for a permitted reader, and side channels such as logs.
- A setting that turns on debug output (`DEBUG = True`, `display_errors`, `include-stacktrace=always`, open Actuator) → `security-misconfig`.
- CR/LF injection into log lines → `request-smuggling-crlf-cache`. Private responses stored by a shared cache → `request-smuggling-crlf-cache`.
- Cleartext transport over `http://` and weak encryption → `crypto`. CORS origin reflection → `cors`.
- System prompt or model output leaks in LLM features → `llm-ai`.
- Version banners and framework names alone → no finding (hardening at most).

## Where to look

### Python

- DRF `ModelSerializer` with `fields = "__all__"`, FastAPI routes without `response_model`, `JsonResponse({"error": str(e)})`, `traceback.format_exc()` in responses.
- `logger.info(f"... {password}")`, `logger.debug(request.headers)`, `print(request.json)`.
- Sentry `send_default_pii=True` without a `before_send` scrubber.

### JavaScript/TypeScript

- `res.json(user)`, `res.status(500).json({ error: err.message, stack: err.stack })`, `res.send(err)`.
- `console.log(req.body)`, `logger.info({ req })`, pino or winston without `redact`.
- Next.js `getServerSideProps` returning full records. The props go into the HTML (`__NEXT_DATA__`).
- GraphQL types with `passwordHash` fields. Prisma queries without `select`. Tokens in `localStorage` with a realistic lower-trust reader.

### Java/Kotlin

- Controllers that return JPA entities without a DTO or `@JsonIgnore` on secret fields.
- `e.printStackTrace(response.getWriter())`, `log.info("login {} {}", user, password)`.

### Go

- `http.Error(w, err.Error(), 500)` with database errors. `json.NewEncoder(w).Encode(user)` without `json:"-"` on secret fields.
- `log.Printf("%+v", r)` and `fmt.Errorf` with tokens.

### PHP

- `var_dump`, `print_r` or `json_encode($user)` of full records in responses. `$e->getMessage()` from PDO in responses.
- `error_log(print_r($_POST, true))`. Laravel models without `$hidden` for secret attributes.

### Ruby

- `render json: @user` with all attributes. `rescue => e` then `render json: { error: e.message }`.
- `Rails.logger.info(params.inspect)` and `filter_parameters` that misses custom names such as `:token` or `:ssn`.

### C#/.NET

- Controllers that return EF entities. `ex.ToString()` in responses. `LogInformation("{@Request}", request)` that logs full objects.

### Logging and observability

- Request logging middleware with headers (morgan `:req[authorization]`, Nginx `log_format` with `$http_authorization` or cookies).
- APM agents that capture bodies (`captureBody: "all"`), OpenTelemetry HTTP instrumentation with header capture, analytics events with emails.

## Safe patterns

- Response allowlists: explicit serializer fields, `response_model`, DTOs, `@JsonIgnore`, `[JsonIgnore]`, `json:"-"`, Laravel `$hidden`, Prisma `select`.
- One global error handler that returns a generic message and a correlation ID. Details go to server logs only.
- Redaction at the logger: pino `redact`, structlog processors, Logback or Log4j2 masking, Serilog destructuring policies, Rails `filter_parameters`, Django `sensitive_variables` and `sensitive_post_parameters`.
- Never log whole request objects, headers or bodies on authentication paths.
- Tokens in headers or POST bodies, not in URLs. `Referrer-Policy: no-referrer` on pages with tokens in the URL.
- Error trackers with `send_default_pii=False` and a `beforeSend` scrubber.
- Store hashes of tokens, adaptive hashes of passwords, and encrypted sensitive fields with keys outside the database.
- Per-item authorization in exports. No public source maps.

## Weak mitigations

- Fields hidden in the frontend while the API still returns them.
- A deny list of field names that misses variants (`passwd`, `pwd`, `secretKey`, nested objects, header case).
- No `stack` in the response, but `err.message` from the database driver.
- Masking in the log viewer while the raw logs go to a third party.
- An environment guard for verbose errors when the production config does not set the variable.
- A truncated card number in one log line while another line logs the raw request.

## Verification checklist

- **attacker_control:** Name who can trigger and read the leak: an anonymous caller, any user, a same-tenant user, an operator with log access, or a third party through `Referer` or analytics. Show the request that reaches the path, such as malformed input that raises the verbose error.
- **privilege_boundary:** Name the exact data and why the reader may not have it: other users' personal data, credentials or tokens, password hashes, or internals for a named next attack. Public data, the reader's own data, or an admin-only diagnostic for admins refutes this question.
- **unmitigated:** Quote the line that writes the data to the channel. Show that no serializer allowlist, error wrapper, redaction filter or environment guard removes it on the production path.
- Use the narrowest CWE: 209, 213, 215, 312, 532, 548 or 598.
- For logs, name the destination and its readers (durable, shared, third party). For environment guards, quote the production config.

## Examples

### JavaScript/TypeScript (Express)

Vulnerable: database errors and stack traces go to any caller.

```ts
app.use((err, req, res, next) => {
  res.status(500).json({ error: err.message, stack: err.stack });
});
```

Secure: a generic answer for the client, details in the server log.

```ts
app.use((err, req, res, next) => {
  const id = crypto.randomUUID();
  logger.error({ id, err }, "unhandled error");
  res.status(500).json({ error: "internal error", id });
});
```

### Python (FastAPI)

Vulnerable: the ORM object goes out with its secret columns.

```python
@app.get("/users/{user_id}")
def get_user(user_id: int, db: Session = Depends(get_db)):
    return db.get(User, user_id)  # includes password_hash and reset_token
```

Secure: a response model limits the fields.

```python
class UserOut(BaseModel):
    id: int
    name: str

@app.get("/users/{user_id}", response_model=UserOut)
def get_user(user_id: int, db: Session = Depends(get_db)):
    return db.get(User, user_id)
```

### Java/Kotlin (logging)

Vulnerable: the password of a failed login goes to the log.

```java
log.warn("login failed user={} password={}", form.getUser(), form.getPassword());
```

Secure: log the event and a non-secret identifier only.

```java
log.warn("login failed user={}", form.getUser());
```

## Dynamic test hints

- Errors: send a malformed dummy request through the framework test client. Check the response for a stack frame, SQL text or a file path.
- Serialization: create a fixture user with `password_hash = "DUMMY-HASH-MARKER"`. Call the endpoint and search the response for the marker.
- Logs: point the logger to a temporary file, log in with the password `DUMMY-PASSWORD-MARKER`, and search the file for the marker.
- Use dummy data only. Never read real logs, real user data or production telemetry.

## False positive traps

- Public data by design: catalog items, published content, public profile fields.
- The reader's own data, or admin-only diagnostics for admins.
- Version strings, framework names and build IDs: fingerprinting only.
- Generic user-facing errors such as "Invalid email format".
- Verbose errors behind a dev-only guard that the production config sets (quote the config).
- Logs with user IDs, request IDs, or hashed or truncated values.
- A field name in an error message without its value. Check that the field holds sensitive data.
- A token in `localStorage` without a realistic lower-trust reader.

## Sources

Condensed and rewritten by kalkan. Vendored copies and pinned commits: `third_party/MANIFEST.json`.

- block/codecrucible@b5c8086 (Apache-2.0, Block): `prompts/default/cwe_deep_analysis.yaml` (CWE-200, CWE-209, CWE-522), `prompts/carlini-curated/cwe_deep_analysis.yaml` (CWE-200), `prompts/default/analysis_sections.yaml` (data_exposure), `prompts/core/audit_families.yaml` (exposure), `prompts/carlini-curated/security_analysis_base.yaml` (do-not-report list).
- cloudflare/security-audit-skill@c1c8a8c (MIT, Cloudflare): `skills/security-audit/DATA-ISOLATION-AND-LIFECYCLE.md` (derived copies, logs, exports, oracles), `ATTACK-CLASSES.md` (feature abuse, obvious things), `CLIENT-SIDE.md` (browser storage).
- vercel-labs/deepsec@4fa6722 (Apache-2.0, Vercel): `packages/scanner/src/matchers/error-message-leak.ts`, `secret-in-log.ts`, `secrets-plaintext-exposure.ts`, `sensitive-data-in-traces.ts`, `response-header-leak.ts`, `packages/processor/src/prompt/highlights.ts`.
- alibaba/open-code-review@11ac6d4 (Apache-2.0, alibaba/open-code-review contributors): `internal/config/rules/rule_docs/python.md`, `go.md`, `php.md` (security sections).
- Added by kalkan from general knowledge: Next.js props in HTML, Laravel `$hidden`, Rails `filter_parameters`, logging middleware and APM notes, the marker test idea.
