---
name: java
title: Java and Kotlin (Spring, Jakarta EE, Ktor, Android)
tech: java, spring
sources: third_party/codecrucible/prompts/exploit-proof-web-java/analysis_sections.yaml, third_party/codecrucible/prompts/exploit-proof-web-java/cwe_deep_analysis.yaml, third_party/open-code-review/rules/rule_docs/java.md, third_party/open-code-review/rules/rule_docs/kotlin.md, third_party/deepsec/processor/prompt/highlights.ts
---

# Java and Kotlin (Spring, Jakarta EE, Ktor, Android)

JVM web services, workers, and Android apps. Trace request data into JDBC and JPA queries, deserializers, XML parsers, expression languages, templates, files, and outbound requests. Check the Spring Security filter chain and method security for every sensitive route.

## Sources of attacker input

- **Spring MVC and WebFlux:** `@PathVariable`, `@RequestParam`, `@RequestBody`, `@RequestHeader`, `@CookieValue`, `@ModelAttribute`, `@RequestPart` and `MultipartFile`, and `@MessageMapping` (WebSocket and STOMP).
- **Jakarta EE and servlets:** `@PathParam`, `@QueryParam`, `@FormParam`, `@HeaderParam`, and `HttpServletRequest` `getParameter`, `getHeader`, `getCookies`, and `getInputStream`.
- **Ktor and Micronaut:** `call.parameters`, `call.receive<T>()`, `call.request.queryParameters`, `@Body`, and `@QueryValue`.
- **Messaging and jobs:** Kafka, JMS, and RabbitMQ listeners, scheduled jobs that read user data, and RMI or remoting endpoints.
- **Android:** intent extras, deep-link URIs, exported components, content-provider queries, and WebView JavaScript bridges.

## Dangerous sinks

### sqli

- `Statement.executeQuery("..." + v)`, `JdbcTemplate` queries built with `+` or `String.format`, `entityManager.createQuery("..." + v)` (JPQL and HQL injection), `createNativeQuery("..." + v)`, MyBatis `${param}`, and jOOQ plain-SQL strings with concatenation.
- `ORDER BY` columns and directions from input. Bound parameters cannot cover identifiers.

### os-command-injection

- `Runtime.getRuntime().exec(String)`, `new ProcessBuilder("sh", "-c", cmd)`, and `ProcessBuilder` lists where a user value starts with `-`.

### code-injection

- SpEL `parseExpression(user).getValue(...)` with a `StandardEvaluationContext`, OGNL (Struts 2), MVEL, `GroovyShell.evaluate`, `ScriptEngine.eval`, JNDI `InitialContext.lookup(user)`, and Hibernate Validator `buildConstraintViolationWithTemplate(user)` (EL injection).

### ssti

- FreeMarker templates built from input (the `?new` built-in reaches Java classes), Velocity `evaluate(user)`, Pebble templates from input, and Thymeleaf view names or fragment expressions built from input (for example `return "user/" + name`), which Thymeleaf preprocesses with SpEL.

### deserialization

- `ObjectInputStream.readObject()` without an `ObjectInputFilter`, `XMLDecoder`, XStream without an allowlist, Jackson `enableDefaultTyping()`, `activateDefaultTyping` with a permissive validator, or `@JsonTypeInfo(use = Id.CLASS)` on untrusted input, Kryo or Hessian without class registration, and SnakeYAML `new Yaml().load(...)` before 2.0.

### xxe

- `DocumentBuilderFactory`, `SAXParserFactory`, `XMLInputFactory`, `TransformerFactory`, `SchemaFactory`, `XMLReader`, DOM4J `SAXReader`, and JDOM `SAXBuilder` without `disallow-doctype-decl` or disabled external entities.

### xss

- Thymeleaf `th:utext`, JSP `<%= %>` and unescaped EL without `<c:out>` or `fn:escapeXml`, FreeMarker without auto-escaping, and `response.getWriter().print(user)` with an HTML content type.

### path-traversal

- `new File(base, user)`, `Paths.get(base, user)`, `Files.newInputStream`, and `Files.write` with input, a canonical-path check placed after the access or missing, zip slip in `ZipInputStream` or commons-compress loops, and Spring `ResourceLoader.getResource(user)` (which accepts `file:` and `classpath:` prefixes).

### ssrf

- `RestTemplate`, `WebClient`, `HttpClient`, OkHttp, Feign, and `new URL(user).openConnection()` (which also handles `file:` and `jar:`) with a URL from input.

### open-redirect

- `"redirect:" + user` view names and `response.sendRedirect(user)` without an allowlist.

### missing-authz

- `permitAll()` on sensitive paths, `anyRequest().permitAll()`, request matchers in the wrong order, `@PreAuthorize` without `@EnableMethodSecurity` (Spring then ignores the annotation), and JAX-RS resources without `@RolesAllowed`.

### idor

- `repository.findById(id)` and `entityManager.find(Order.class, id)` without an owner or tenant condition.

### csrf

- `http.csrf().disable()` or `csrf(AbstractHttpConfigurer::disable)` on an app that uses session cookies.

### cors

- `allowedOriginPatterns("*")` with `allowCredentials(true)`, and filters that copy the `Origin` header into the response.

### mass-assignment

- `@ModelAttribute` or `@RequestBody` bound straight to an entity with role or owner fields, and `@InitBinder` without `setAllowedFields`.

### crypto

- `MessageDigest` MD5 or SHA-1 for passwords, `Cipher.getInstance("AES")` (ECB by default in most providers), DES, static IVs, `java.util.Random` for tokens, `TrustManager` implementations that accept every certificate, and `HostnameVerifier` that returns `true`.

### jwt

- jjwt `parseClaimsJwt` or `parse` on tokens that may be unsigned, auth0 `JWT.decode` without `verify`, and verifiers without algorithm, issuer, and audience checks.

### request-smuggling-crlf-cache

- Log4j 2 below 2.17.1 that logs user data (Log4Shell JNDI lookups), and CR/LF from input in log lines or response headers.

### dos-redos

- `Pattern` regexes with nested quantifiers on input (Java regex backtracks), unbounded multipart or JSON bodies, and XML entity expansion.

### race-condition

- Check-then-act on balances or stock without locking. `@Transactional` on a private method or a self-invoked method gives no transaction, because Spring applies it through a proxy.

### sensitive-data-exposure

- Entities with password hashes returned as JSON, Actuator endpoints such as `/actuator/env` and `/actuator/heapdump` exposed, and `server.error.include-stacktrace=always`.

## Framework notes

### Spring Security

- `SecurityFilterChain` with `authorizeHttpRequests` is the route gate. Matchers apply in order, and the first match wins.
- Method annotations (`@PreAuthorize`, `@Secured`) work only with `@EnableMethodSecurity` (or the older `@EnableGlobalMethodSecurity`) and only on calls through the Spring proxy.
- A custom filter that catches an exception and continues the chain can skip authentication.

### Spring Boot configuration

- Check `management.endpoints.web.exposure.include`, the H2 console, `spring.devtools`, and profile-specific files that production loads.
- `@Value` and `application.yml` secrets committed to the repository are hardcoded secrets.

### Spring Data, JPA, Hibernate, and MyBatis

- Derived query methods, the Criteria API, and `@Query` with `:name` or `?1` parameters bind values.
- MyBatis `#{}` binds values. `${}` pastes text into the SQL.

### Jakarta EE and JAX-RS

- `@RolesAllowed`, `@PermitAll`, and `@DenyAll` gate resources. A resource without them relies on `web.xml` constraints, which you must check.
- Servlet filters that match by URL pattern can miss path-parameter and encoded variants.

### Templates

- Thymeleaf `th:text`, JSP `<c:out>`, and FreeMarker with `output_format` HTML escape output. `th:utext`, raw `<%= %>`, and `?no_esc` do not.

### Kotlin and Ktor

- `authenticate("name") { }` blocks gate routes. A route outside the block is public.
- `call.receive<T>()` validates structure, not ownership. The `!!` operator on input-derived values throws on null and can end the request.

### Android

- `android:exported="true"` and intent filters expose components to other apps. Before API 31, an intent filter alone exports a component.
- `WebView` with `setJavaScriptEnabled(true)` and `addJavascriptInterface` lets loaded pages call Java methods.

## Safe idioms

- `PreparedStatement` with `?` placeholders, `JdbcTemplate` with argument arrays, JPA `setParameter`, and MyBatis `#{}`.
- `ProcessBuilder` with a fixed program, a validated argument list, and `--` before user values.
- `ObjectInputFilter` allowlists, Jackson without default typing, and SnakeYAML `SafeConstructor`.
- A shared XML factory helper that sets `disallow-doctype-decl` and `FEATURE_SECURE_PROCESSING`.
- `Path.normalize()` and `toRealPath()` before `startsWith(base)`, and generated file names for uploads.
- `SecureRandom`, `MessageDigest.isEqual` for secrets, `BCryptPasswordEncoder` or Argon2, and AES-GCM with a random IV.
- Request DTOs with only public fields and explicit copies into entities.

## Common false positives

- `JdbcTemplate.query("... WHERE id = ?", mapper, id)` and JPQL with named parameters.
- Concatenated SQL whose values are constants or parsed integers.
- `Runtime.exec(new String[]{...})` with literal arguments.
- `ObjectInputStream` on data that the server signed and verified before the read, or on files that only the application writes.
- XML parsing of bundled configuration files that no user can change.
- `csrf().disable()` on a stateless API that uses bearer tokens only.
- MD5 or SHA-1 for checksums, ETags, or cache keys.
- SLF4J parameterized logging (`log.info("user={}", user)`) with Logback, which has no JNDI lookups.

## Sources

- `third_party/codecrucible/prompts/exploit-proof-web-java/analysis_sections.yaml` and `cwe_deep_analysis.yaml`, from block/codecrucible at commit `b5c8086` (Apache-2.0, Copyright 2026 Block, Inc.).
- `third_party/open-code-review/rules/rule_docs/java.md` and `kotlin.md`, from alibaba/open-code-review at commit `11ac6d4` (Apache-2.0, Copyright 2026 alibaba/open-code-review contributors).
- `third_party/deepsec/processor/prompt/highlights.ts` (Spring, Ktor, Micronaut, JAX-RS, and Android entries), from vercel-labs/deepsec at commit `4fa6722` (Apache-2.0, Copyright 2026 Vercel, Inc. and contributors).
- kalkan condensed and rewrote the material, regrouped it by kalkan class slug, and added version notes.
