---
name: rust
title: Rust (Actix, Axum, Rocket, Tonic, unsafe and FFI)
tech: rust
sources: third_party/codecrucible/prompts/exploit-proof-rust/analysis_sections.yaml, third_party/codecrucible/prompts/exploit-proof-rust/cwe_deep_analysis.yaml, third_party/open-code-review/rules/rule_docs/rust.md, third_party/deepsec/processor/prompt/highlights.ts
---

# Rust (Actix, Axum, Rocket, Tonic, unsafe and FFI)

Rust services, CLIs, libraries, and FFI layers. Safe Rust removes most memory bugs, so the hunt focuses on `unsafe` blocks and FFI boundaries, panics and allocation on untrusted input, integer casts, and the usual web sinks. See the `memory-safety-and-binary` domain pack for native boundaries.

## Sources of attacker input

- **Web frameworks:** Actix `web::Query`, `web::Json`, `web::Path`, `web::Form`, and `HttpRequest` headers, Axum `Query`, `Json`, `Path`, `Form`, `HeaderMap`, and `TypedHeader` extractors, Rocket `FromForm`, `Json`, and route parameters, and Warp filters.
- **RPC and messages:** Tonic `Request<T>` messages and `Streaming<T>` items, and queue payloads.
- **Bytes and files:** network reads, files, and archives parsed with `serde`, `bincode`, `nom`, or hand-written parsers.
- **FFI and CLIs:** pointers and lengths from C callers, `std::env::args`, and environment variables.
- Extractors check structure, not content. A `Json<T>` value is still attacker data.

## Dangerous sinks

### memory-safety

- Raw pointer dereferences, `slice::from_raw_parts` and `from_raw_parts_mut` with an untrusted length, `ptr::copy` and `copy_nonoverlapping`, `get_unchecked`, `set_len`, `mem::transmute`, `MaybeUninit::assume_init` before full initialization, `Box::from_raw` on a pointer that someone else still uses, `CStr::from_ptr` without a NUL guarantee, and `static mut`.
- `unsafe impl Send` or `Sync` for types with interior mutability, and lifetimes extended to `'static` with `transmute`.
- FFI: C code that writes through a pointer and length, Rust callbacks that panic across `extern "C"` (undefined behavior before Rust 1.81, an abort since then), and Rust values freed while C still holds a pointer.

### dos-redos

- `unwrap`, `expect`, `panic!`, `unreachable!`, slice indexing, and `RefCell::borrow_mut` on paths that input controls. A panic aborts the process when the profile sets `panic = "abort"`.
- `Vec::with_capacity(len)` and `vec![0; len]` with an untrusted length, `bincode` decoding without a size limit, recursion without a depth limit (`serde_json` keeps a limit of 128 unless code disables it), and missing body limits (Axum's `DefaultBodyLimit` is 2 MB, Warp needs `content_length_limit`).
- Backtracking regex crates such as `fancy-regex` on input. The `regex` crate runs in linear time.

### sqli

- `sqlx::query(&format!(...))`, `diesel::sql_query(format!(...))`, `rusqlite` `execute(&format!(...))`, and SeaORM `Statement::from_string` with formatted input.

### os-command-injection

- `Command::new(user_program)`, `Command::new("sh").arg("-c").arg(input)`, and `.arg(input)` where the value can start with `-`. On Windows, `.bat` and `.cmd` arguments needed Rust 1.77.2 for safe escaping.

### path-traversal

- `Path::join(input)` (an absolute `input` replaces the base), `std::fs` and `tokio::fs` calls with input, archive extraction that joins `entry.path()` itself, and `canonicalize` checks done on a different path than the one opened.

### ssrf

- `reqwest::get(input)`, `reqwest::Client` requests, and `hyper` clients with a URL from input. `reqwest` follows up to 10 redirects by default.

### xss

- `format!` HTML into an `HttpResponse` body with an HTML content type, Askama `|safe`, Tera with autoescape turned off, and Maud `PreEscaped(input)`.

### deserialization

- `rkyv` on untrusted bytes without validation (undefined behavior), and length-prefixed formats that allocate before a bound check. `serde` does not run code during decoding, so the risk is allocation and logic, not gadget chains.

### crypto

- `SmallRng`, or a `StdRng` seeded from time, for tokens, `==` on secrets (use `subtle` or `constant_time_eq`), `md-5` or `sha1` for passwords, `danger_accept_invalid_certs(true)`, and rustls dangerous configuration.

### jwt

- `jsonwebtoken` `Validation` with `insecure_disable_signature_validation()`, `validate_exp = false`, or several algorithms for one key.

### race-condition

- A `std::sync::Mutex` guard held across `.await`, atomics with `Relaxed` ordering used to publish data, and check-then-act on files or rows.

### missing-authz

- Handlers without an auth extractor or guard, Axum routes added after `.layer(auth)` (layers wrap only routes that exist at that point), Actix scopes without `.wrap(auth)`, and Rocket routes without a request guard.

### idor

- Lookups by an id from `Path<T>` without an owner or tenant condition.

### mass-assignment

- Request bodies deserialized straight into database models that have role or owner fields.

## Framework notes

### Actix-web

- `App::wrap` applies to the whole app, `web::scope().wrap()` to one scope. A middleware that calls the next service before its check is a bypass.
- `web::Json` and `web::Payload` have default size limits. Look for `JsonConfig` or `PayloadConfig` calls that raise them.

### Axum and Tower

- `.layer()` wraps only the routes added before it. `.route_layer()` applies only to matched routes. Check the order of `.route`, `.layer`, `.merge`, and `.nest`.
- `State` and `Extension` carry shared data. An `Extension<User>` exists only if a middleware inserts it.

### Rocket and Warp

- Rocket request guards are the auth gate. A handler without a guard is public. Fairings that run before the guard are the wrong place for security checks.
- Warp filter order matters. The auth filter must run before the body filter.

### Tonic (gRPC)

- Interceptors check authentication per request. For streams, check authority on each message when scope can change.
- Use `Status::unauthenticated` and `Status::permission_denied`, not generic errors, so that callers cannot misread failures.

### unsafe code and FFI

- Each `unsafe` block needs a `// SAFETY:` comment that states the invariant, and each call site must satisfy it. A missing comment is a hint, not a finding.
- Wrap Rust code that C calls with `catch_unwind`, and convert errors at the boundary.

## Safe idioms

- `sqlx::query!` and `query_as!` with bind parameters, Diesel's query builder, and `rusqlite` `params![]`.
- `Command::new("/usr/bin/convert").arg("--").arg(path)` with a fixed program.
- `checked_add`, `checked_mul`, and `try_into()` for untrusted lengths and casts.
- `?` and `match` instead of `unwrap` on request paths.
- `bincode` options with a byte limit, and `rkyv` with validation (`check_bytes`).
- `rand::rngs::OsRng` or `rand::rng()` for secrets, `subtle::ConstantTimeEq`, and the `argon2` or `bcrypt` crates.
- `canonicalize` on the joined path, then `starts_with(base)`, and the `zip` crate's `enclosed_name()`.

## Common false positives

- `unsafe` blocks with a sound, documented invariant that every caller satisfies.
- `unwrap` on values that the code validated just before, on constants, or in tests and build scripts.
- `as` casts on values bounded by an earlier check.
- `format!` SQL with only constant fragments.
- `rand::random` and `rand::thread_rng` for tokens. They are cryptographically secure since `rand` 0.8.
- `serde` structs without `deny_unknown_fields`. Unknown fields are ignored, which is usually safe.
- Panics in an Axum or Actix handler that the runtime turns into a 500 response for one request only.

## Sources

- `third_party/codecrucible/prompts/exploit-proof-rust/analysis_sections.yaml` and `cwe_deep_analysis.yaml`, from block/codecrucible at commit `b5c8086` (Apache-2.0, Copyright 2026 Block, Inc.).
- `third_party/open-code-review/rules/rule_docs/rust.md`, from alibaba/open-code-review at commit `11ac6d4` (Apache-2.0, Copyright 2026 alibaba/open-code-review contributors).
- `third_party/deepsec/processor/prompt/highlights.ts` (Actix-web, Axum, Rocket, Warp, and Tonic entries), from vercel-labs/deepsec at commit `4fa6722` (Apache-2.0, Copyright 2026 Vercel, Inc. and contributors).
- kalkan condensed and rewrote the material, regrouped it by kalkan class slug, and added version notes.
