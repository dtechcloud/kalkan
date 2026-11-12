---
name: go
title: Go (net/http, Gin, Echo, Fiber, Chi, gRPC)
tech: go
sources: third_party/codecrucible/prompts/exploit-proof-web-go/analysis_sections.yaml, third_party/codecrucible/prompts/exploit-proof-web-go/cwe_deep_analysis.yaml, third_party/open-code-review/rules/rule_docs/go.md, third_party/deepsec/processor/prompt/highlights.ts
---

# Go (net/http, Gin, Echo, Fiber, Chi, gRPC)

Go web services, gRPC servers, workers, and CLIs. Trace request data into SQL strings, commands, file paths, templates, and outbound requests. Check middleware scope for every route group, ownership on every lookup, and concurrency on shared state.

## Sources of attacker input

- **net/http:** `r.URL.Query()`, `r.FormValue`, `r.PostFormValue`, `r.PathValue` (Go 1.22 patterns), `r.Body`, `r.Header`, `r.Cookie`, and `r.MultipartForm`.
- **Routers:** Gin `c.Param`, `c.Query`, `c.PostForm`, and `c.ShouldBind*`, Echo `c.Param`, `c.QueryParam`, and `c.Bind`, Fiber `c.Params`, `c.Query`, and `c.BodyParser`, Chi `chi.URLParam`, and gorilla/mux `mux.Vars`.
- **RPC and messages:** gRPC request messages and stream items, NATS, Kafka, and SQS payloads, and webhook bodies.
- **CLIs and tools:** `os.Args`, Cobra flags, environment variables, and parsed files (archives, YAML, JSON).

## Dangerous sinks

### sqli

- `db.Query`, `db.Exec`, and `db.QueryRow` with `fmt.Sprintf` or `+`, sqlx with built strings, and GORM `Where`, `Raw`, `Exec`, `Order`, `Select`, and `Group` with formatted strings or raw input.
- Identifiers (columns, tables, `ORDER BY`, `LIMIT`) from input need an allowlist.

### os-command-injection

- `exec.Command("sh", "-c", s)`, `exec.Command(userBinary, ...)`, user arguments that start with `-` (for example `-oProxyCommand=` for `ssh`), and `syscall.Exec`.

### path-traversal

- `os.Open(filepath.Join(base, user))` without a containment check. `filepath.Clean` does not stop a path from climbing above `base`.
- `http.ServeFile(w, r, userPath)` and `http.FileServer(http.Dir(root))` with a user-influenced root.
- `archive/zip` and `archive/tar` extraction that joins entry names without `filepath.IsLocal` or a containment check.

### ssrf

- `http.Get`, `http.Post`, `http.NewRequest`, and `net.Dial` with a URL or address from input. The default client follows up to 10 redirects. A check of the host name before the request does not stop DNS rebinding.

### xss

- `text/template` for HTML output (it does not escape), `template.HTML`, `template.JS`, `template.URL`, and `template.HTMLAttr` conversions of input, and `fmt.Fprintf(w, "<p>%s</p>", v)`. Without an explicit `Content-Type`, `net/http` sniffs the body and can serve it as HTML.

### ssti

- `template.New(...).Parse(user)` with `text/template` or `html/template`. A template from input can call exported methods of the data passed to it.

### deserialization

- `encoding/gob` from untrusted peers (not designed for hostile input, memory exhaustion), YAML into `interface{}` without size limits, and custom `UnmarshalJSON` methods that act on payload values. `encoding/xml` does not resolve external entities.

### crypto

- `math/rand` and `math/rand/v2` for tokens, keys, nonces, or reset codes, `bytes.Equal` or `==` on secrets, MD5 or SHA-1 for passwords, `tls.Config{InsecureSkipVerify: true}`, and `MinVersion` below TLS 1.2.

### jwt

- golang-jwt `jwt.Parse` with a key function that does not check `token.Method`, `ParseUnverified` used for decisions, and parsers without `jwt.WithValidMethods`, expiry, and audience checks.

### dos-redos

- `io.ReadAll(r.Body)` without `http.MaxBytesReader`, an `http.Server` without `ReadHeaderTimeout` and the other timeouts (slowloris), unbounded goroutine fan-out per request, `gzip.NewReader` piped into `io.Copy` without a limit, and backtracking engines such as `regexp2`. The standard `regexp` package runs in linear time.

### race-condition

- Concurrent map writes (the runtime aborts the whole process), shared struct fields without a mutex, check-then-act on database rows without a transaction or `SELECT ... FOR UPDATE`, and goroutines that capture a loop variable in modules with a `go` directive below 1.22.

### missing-authz

- Routes registered outside the authenticated group, Echo or Gin `Use` calls after route registration, and gRPC services without an interceptor (unary and stream interceptors are separate).

### idor

- `db.First(&order, id)` and `WHERE id = ?` lookups without an owner or tenant condition.

### mass-assignment

- `json.Unmarshal(body, &user)` into a model with fields such as `IsAdmin` or `Role`, and GORM `Updates(body)`, `Save(&user)`, or `Updates(map)` built from request keys.

### csrf

- Cookie-authenticated handlers that change state without `gorilla/csrf`, `http.CrossOriginProtection` (Go 1.25), or another origin or token check.

### open-redirect

- `http.Redirect(w, r, r.URL.Query().Get("next"), 302)` and `c.Redirect(302, user)` without an allowlist. A leading-slash check must also reject `//host` and `/\host`.

### sensitive-data-exposure

- `err.Error()` text returned to clients, `render.JSON` of whole database rows, and logs of tokens, headers, or Cobra credential flags.

### hardcoded-secrets

- JWT signing keys, API keys, and DSNs with passwords as string constants.

## Framework notes

### net/http

- Go 1.22 `ServeMux` patterns support methods and wildcards. A handler without a method pattern accepts every verb.
- `net/http` replaces CR and LF in header values with spaces when it writes the response, so header injection through `w.Header().Set` is rare. Raw connection writes bypass that protection.
- `http.Server{}` has no timeouts by default.

### Gin, Echo, and Fiber

- Middleware applies only to routes registered after `Use` in the same group. Check sensitive routes that live on the root engine.
- `c.Bind` and `c.ShouldBind` fill any matching exported field. Bind into a request struct, not into a model.
- Fiber reuses request buffers. Values from `c` must not escape the handler without a copy.

### Chi and gorilla/mux

- Middleware applies to the router or group where `Use` runs and to the routes below it. For each sensitive route, find its router and confirm that the auth middleware is on it or on a parent.
- `chi.URLParam` and `mux.Vars` are raw input.

### gRPC

- Register both unary and stream interceptors. A stream checked only when it opens keeps its authority after revocation.
- grpc-go limits a received message to 4 MB by default. A raised `MaxRecvMsgSize` and long-lived streams need their own limits.

### GORM and database/sql

- `Where("name = ?", v)` binds values. `Where("name = " + v)` and `Where(fmt.Sprintf(...))` do not.
- After a `rows.Next()` loop, check `rows.Err()`, and close `rows` on every path.

### Errors, nil, and context

- A typed nil pointer stored in an `error` interface is not `nil`, so `if err != nil` can take the wrong branch.
- Ignored errors from authorization or verification calls fail open.
- A request handler that starts work with `context.Background()` ignores client cancellation.

## Safe idioms

- `db.QueryContext(ctx, "SELECT ... WHERE id = $1", id)` and GORM placeholders.
- `exec.CommandContext(ctx, "/usr/bin/convert", "--", path)` with a fixed program.
- `os.OpenRoot(dir)` and `root.Open(name)` (Go 1.24), or `filepath.IsLocal(name)` before a join.
- `html/template` for HTML, and `json.NewEncoder(w)` with a JSON content type.
- `crypto/rand`, `crypto/subtle.ConstantTimeCompare`, `bcrypt` or `argon2id`, and `tls.Config` with `MinVersion: tls.VersionTLS12`.
- `http.MaxBytesReader`, `ReadHeaderTimeout`, and `json.Decoder.DisallowUnknownFields` with a size cap.
- A custom `net.Dialer.Control` function that rejects private and loopback addresses at connect time.

## Common false positives

- `fmt.Sprintf` SQL whose values are constants or parsed integers.
- `exec.Command` with literal arguments.
- `text/template` that renders plain text, YAML, or code, not HTML.
- `math/rand` for jitter, load balancing, sampling, or tests.
- Maps used from one goroutine only, or guarded by one mutex on every access.
- A missing `http.MaxBytesReader` behind a proxy that the repository shows with a body limit.
- `regexp` patterns from the standard library on input. They cannot backtrack catastrophically.
- Files that end in `_test.go`, and code under `testdata/`.

## Sources

- `third_party/codecrucible/prompts/exploit-proof-web-go/analysis_sections.yaml` and `cwe_deep_analysis.yaml`, from block/codecrucible at commit `b5c8086` (Apache-2.0, Copyright 2026 Block, Inc.).
- `third_party/open-code-review/rules/rule_docs/go.md`, from alibaba/open-code-review at commit `11ac6d4` (Apache-2.0, Copyright 2026 alibaba/open-code-review contributors).
- `third_party/deepsec/processor/prompt/highlights.ts` (Gin, Echo, Fiber, Chi, gorilla/mux, and Cobra entries), from vercel-labs/deepsec at commit `4fa6722` (Apache-2.0, Copyright 2026 Vercel, Inc. and contributors).
- kalkan condensed and rewrote the material, regrouped it by kalkan class slug, corrected the `encoding/gob` risk to resource exhaustion, and added version notes.
