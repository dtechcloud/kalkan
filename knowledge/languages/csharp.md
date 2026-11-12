---
name: csharp
title: C# and .NET (ASP.NET Core, Entity Framework, Blazor)
tech: dotnet
sources: third_party/deepsec/processor/prompt/highlights.ts, third_party/open-code-review/rules/rule_docs/default.md, third_party/sast-skills/skills/sast-rce/SKILL.md, third_party/sast-skills/skills/sast-sqli/SKILL.md, third_party/sast-skills/skills/sast-xss/SKILL.md, third_party/sast-skills/skills/sast-xxe/SKILL.md, third_party/sast-skills/skills/sast-ssti/SKILL.md, third_party/sast-skills/skills/sast-pathtraversal/SKILL.md, third_party/sast-skills/skills/sast-ssrf/SKILL.md, third_party/sast-skills/skills/sast-fileupload/SKILL.md
---

# C# and .NET (ASP.NET Core, Entity Framework, Blazor)

ASP.NET Core MVC, Razor Pages, minimal APIs, Blazor, SignalR, gRPC, Azure Functions, and legacy ASP.NET. Trace model-bound input into SQL, processes, deserializers, XML readers, Razor output, files, and outbound requests. Check the authorization attributes, policies, and fallback policy for every endpoint. Read the target framework in the `.csproj` file, because many defaults differ between .NET Framework and modern .NET.

## Sources of attacker input

- **Model binding:** `[FromQuery]`, `[FromRoute]`, `[FromBody]`, `[FromForm]`, and `[FromHeader]` parameters, complex types bound from any source, and minimal API handler parameters.
- **HttpContext:** `Request.Query`, `Request.Form`, `Request.Headers`, `Request.Cookies`, `Request.Body`, `Request.Path`, and `IFormFile` (including `FileName`).
- **Realtime and RPC:** SignalR hub method arguments, gRPC messages and streams, and WCF operations.
- **Functions and jobs:** Azure Functions HTTP triggers, queue, Service Bus, and blob trigger payloads, and hosted-service messages.
- **Blazor:** component parameters, query-string parameters (`[SupplyParameterFromQuery]`), and JavaScript interop callbacks.

## Dangerous sinks

### sqli

- `SqlCommand` or `DbCommand` text built with `+` or interpolation, EF Core `FromSqlRaw` and `ExecuteSqlRaw` with interpolated input, Dapper `Query` with a concatenated SQL string, and dynamic LINQ strings (`System.Linq.Dynamic.Core`) from input. `FromSqlInterpolated`, `FromSql` (EF Core 7+), and Dapper parameter objects bind values.

### os-command-injection

- `Process.Start(fileName, arguments)` with input, `ProcessStartInfo.Arguments` built from strings, `cmd.exe /c` or `bash -c` wrappers, and `UseShellExecute = true` with a file name from input.

### code-injection

- Roslyn `CSharpScript.EvaluateAsync(input)`, dynamic compilation, `Type.GetType(input)` with `Activator.CreateInstance`, and `Assembly.Load` of uploaded bytes.

### deserialization

- `BinaryFormatter` (obsolete, and removed in .NET 9), `SoapFormatter`, `NetDataContractSerializer`, `LosFormatter`, `ObjectStateFormatter`, `JavaScriptSerializer` with a `SimpleTypeResolver`, Json.NET with `TypeNameHandling` other than `None` and no `SerializationBinder`, `DataContractSerializer` with known types taken from input, and ViewState without MAC validation or with a leaked `machineKey`.

### xss

- `@Html.Raw(x)`, `new HtmlString(x)`, `MvcHtmlString.Create(x)`, Blazor `(MarkupString)x`, values written into inline `<script>` blocks without JavaScript encoding, and `Response.Write` in Web Forms.

### ssti

- Templates parsed from input with Scriban `Template.Parse`, `Handlebars.Compile`, DotLiquid `Template.Parse`, Fluid `FluidParser.TryParse`, or RazorEngine-style runtime compilation.

### xxe

- `XmlDocument`, `XmlTextReader`, and `XmlReader` with `DtdProcessing.Parse` and an `XmlUrlResolver`. Before .NET Framework 4.5.2, `XmlDocument` and `XmlTextReader` resolve external entities by default. Modern .NET defaults are safe unless code changes them.

### path-traversal

- `File.ReadAllText`, `File.OpenRead`, `new FileStream`, `PhysicalFile`, and `File.Delete` with input. `Path.Combine(base, input)` returns `input` when it is an absolute path. `IFormFile.FileName` used as a storage path, and archive loops that write `entry.FullName` without a check.

### ssrf

- `HttpClient.GetAsync`, `SendAsync`, `WebRequest.Create` (which also handles `file://`), `WebClient`, and RestSharp with a URL from input. `HttpClientHandler` follows redirects by default.

### open-redirect

- `Redirect(returnUrl)` and `Results.Redirect(returnUrl)` without `Url.IsLocalUrl`. `LocalRedirect` rejects external URLs.

### missing-authz

- Controllers or actions without `[Authorize]`, `[AllowAnonymous]` on sensitive actions, minimal API endpoints without `RequireAuthorization()`, no `FallbackPolicy`, and role checks without resource-based checks.

### idor

- `_db.Orders.Find(id)` and `FirstOrDefault(o => o.Id == id)` without an owner condition or an `IAuthorizationService.AuthorizeAsync` resource check.

### csrf

- MVC POST actions without `[ValidateAntiForgeryToken]` or a global `AutoValidateAntiforgeryTokenAttribute`, `[IgnoreAntiforgeryToken]` on state-changing endpoints, and cookie-authenticated minimal API form endpoints with antiforgery turned off. Razor Pages validate the token by default.

### cors

- `SetIsOriginAllowed(_ => true)` with `AllowCredentials()`, and middleware that copies the `Origin` header. ASP.NET Core rejects `AllowAnyOrigin` together with `AllowCredentials`.

### mass-assignment

- Entity types bound directly from the request (over-posting), `TryUpdateModelAsync` without a property list, and `[Bind]` lists that include role or owner fields.

### crypto

- `System.Random` for tokens, MD5 or SHA-1 for passwords, `==` on secrets, `ServerCertificateCustomValidationCallback` that returns `true`, and `ServicePointManager.ServerCertificateValidationCallback` overrides.

### jwt

- `TokenValidationParameters` with `ValidateIssuer`, `ValidateAudience`, `ValidateLifetime`, or `ValidateIssuerSigningKey` set to `false`, `RequireSignedTokens = false`, and a custom `SignatureValidator` that skips the check.

### sensitive-data-exposure

- `UseDeveloperExceptionPage` or detailed errors in production, logs of request bodies or tokens, and entities with password hashes returned from APIs.

### dos-redos

- `Regex` without a match timeout on input (use `RegexOptions.NonBacktracking` in .NET 7+ or a timeout), `[DisableRequestSizeLimit]`, and large form or multipart limits.

### race-condition

- Check-then-act updates without a transaction, a concurrency token, or a row lock.

## Framework notes

### ASP.NET Core MVC and Razor Pages

- Razor `@x` HTML-encodes. `@Html.Raw` and `HtmlString` do not.
- `[ApiController]` returns 400 on invalid model state. Without it, the action must check `ModelState.IsValid`.
- Global filters and the `FallbackPolicy` decide what unannotated endpoints get. Check `Program.cs` or `Startup.cs`.

### Minimal APIs

- Each `MapGet` or `MapPost` chain needs `RequireAuthorization()` unless a group or the fallback policy covers it.
- Form-bound endpoints need the antiforgery middleware (.NET 8).

### Authentication and authorization setup

- `UseAuthentication()` and `UseAuthorization()` run between routing and the endpoints. Middleware that answers before them (static files, custom handlers, `Map` branches) gets no authorization.
- Cookie authentication options decide `SameSite`, `Secure`, and `HttpOnly`. Check `Cookie.SecurePolicy` and `SameSite` settings.

### Entity Framework Core, Dapper, and ADO.NET

- LINQ queries bind values. `FromSqlRaw` and `ExecuteSqlRaw` with interpolation do not, while `FromSqlInterpolated` and `FromSql` do.
- Dapper binds values only through parameter objects (`new { id }`).

### Blazor and SignalR

- Blazor Server runs component code on the server. An authorization check in the UI alone does not protect a hub or a service method.
- SignalR hubs need `[Authorize]` on the hub or on each method. Group names from input can leak messages across tenants.

### Azure Functions

- `AuthorizationLevel.Anonymous` makes an HTTP trigger public. A function key identifies the calling app, not a user.
- Queue and blob triggers carry attacker data when any web path can write to the queue or container.

### Legacy ASP.NET (Web Forms, MVC 5)

- `ValidateRequest` and request validation are weak XSS filters, not encoding.
- ViewState without `EnableViewStateMac`, or with a known `machineKey`, allows deserialization attacks.

## Safe idioms

- `SqlParameter` and `cmd.Parameters.Add`, EF Core LINQ, `FromSqlInterpolated`, and Dapper parameter objects.
- `ProcessStartInfo` with a fixed `FileName`, `ArgumentList` instead of an argument string, and `UseShellExecute = false`.
- `System.Text.Json` without polymorphic type handling, or Json.NET with `TypeNameHandling.None`.
- `XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null }`.
- `Path.GetFullPath(Path.Combine(base, name))` followed by a `StartsWith(base)` check, and generated storage names for uploads.
- `RandomNumberGenerator`, `CryptographicOperations.FixedTimeEquals`, ASP.NET Core Identity `PasswordHasher`, and AES-GCM.
- Request DTOs, `[Authorize(Policy = ...)]`, resource-based authorization, and `LocalRedirect`.

## Common false positives

- Interpolated strings passed to `FromSqlInterpolated`, `FromSql`, or `ExecuteSqlInterpolated`. EF Core turns them into parameters.
- `@Html.Raw` with a constant string or with output from a sanitizer such as HtmlSanitizer.
- `Process.Start` with literal arguments.
- `BinaryFormatter` on data that only the application writes and reads locally (still a hardening note for removal).
- `[AllowAnonymous]` on login, registration, and public pages.
- `[IgnoreAntiforgeryToken]` on API endpoints that use bearer tokens only.
- MD5 or SHA-1 for checksums, ETags, or cache keys.

## Sources

- `third_party/deepsec/processor/prompt/highlights.ts` (.NET / ASP.NET Core and Azure Functions entries), from vercel-labs/deepsec at commit `4fa6722` (Apache-2.0, Copyright 2026 Vercel, Inc. and contributors).
- `third_party/open-code-review/rules/rule_docs/default.md`, from alibaba/open-code-review at commit `11ac6d4` (Apache-2.0, Copyright 2026 alibaba/open-code-review contributors). open-code-review has no C# rule document, and its default document only lists general review questions.
- `third_party/sast-skills/skills/` (C# and .NET sink lists in `sast-rce`, `sast-sqli`, `sast-xss`, `sast-xxe`, `sast-ssti`, `sast-pathtraversal`, `sast-ssrf`, and `sast-fileupload`), from utkusen/sast-skills at commit `db52227` (MIT License, Copyright (c) 2026 Utku Sen).
- codecrucible has no .NET prompt set. kalkan condensed and rewrote the material above, regrouped it by kalkan class slug, and added framework and version notes.
