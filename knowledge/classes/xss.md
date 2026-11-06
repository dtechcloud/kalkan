---
slug: xss
title_en: Cross-site scripting
title_tr: Cross-site scripting (XSS)
cwe: CWE-79, CWE-80, CWE-83, CWE-116
owasp: A03:2021
sources: sast-skills, codecrucible, deepsec, security-audit-skill, open-code-review
---

## Summary

The application writes attacker text into a page as HTML, into JavaScript, or into the DOM without encoding for that context. A script then runs in the victim's browser: session theft, credential theft, actions as the victim. The sink is the render, not the input. Find the render site and name the output context.

## What it is

- **Reflected.** User input is echoed into the response on the same request.
- **Stored.** User input is saved, then rendered to other users later.
- **DOM-based.** Client JavaScript reads a browser source and writes to a DOM sink with no server step.
- **Server template bypass.** The unescaped marker is used: Jinja `|safe`, `mark_safe`, `Markup`, `{% autoescape off %}`; EJS `<%- %>`; Handlebars `{{{ }}}`; Pug `!{}`, `!=`; Thymeleaf `th:utext`; Twig `|raw`; Blade `{!! !!}`; Rails `raw`, `html_safe`, `<%== %>`; JSP `<%= %>`, `${}` with no `c:out`; Razor `@Html.Raw`; Go `template.HTML/JS/URL` or `text/template` for HTML.
- **HTML string building.** `res.send("<p>"+x+"</p>")`, `f"<h1>{x}</h1>"`, `echo $x`.
- **DOM sinks.** `innerHTML`, `outerHTML`, `document.write`, `insertAdjacentHTML`, `$(el).html(x)`, React `dangerouslySetInnerHTML`, Vue `v-html`, Angular `[innerHTML]` and `bypassSecurityTrust*`.
- **JavaScript execution sinks.** `eval`, `setTimeout`/`setInterval` with a string, `new Function`, `location.href = "javascript:"+x`, `el.setAttribute("onclick", x)`.
- **Context mismatch (CWE-116).** HTML-escaped data placed in a `<script>` string, an `on*` attribute, or a `javascript:` URL. HTML escaping does not protect those grammars.

## What it is not

- User input as the template source → `ssti`.
- CR/LF into a response header → `request-smuggling-crlf-cache`.
- A redirect to a user URL → `open-redirect`.
- A page framed for a click → `security-misconfig` (clickjacking) / `csrf`.
- `textContent` and `innerText` write plain text with no HTML parsing. Not a sink.
- Prototype pollution and DOM clobbering are browser classes but route to `prototype-pollution`.

## Where to look

Find the render site. Name the output context (HTML body, attribute, script string, URL). Then trace the value to a user source.

### Python (Django, Flask, Jinja2)
- `|safe`, `mark_safe(x)`, `Markup(x)`, `format_html` with raw args, `{% autoescape off %}`, `HTMLResponse(x)`, `render_template_string(f"...{x}...")`.
- Inline script: `<script>const x = {{ v }}</script>` needs `|json_script`, not HTML escaping.

### JavaScript/TypeScript (React, Vue, Angular, Express)
- `dangerouslySetInnerHTML`, `v-html`, `[innerHTML]`, `bypassSecurityTrustHtml`, `el.innerHTML = x`, `document.write(x)`, `$(el).html(x)`.
- SSR: `res.send(`<div>${x}</div>`)`. JSON in a script tag must escape `</` (serialize-javascript).
- DOM sources: `location.search`, `location.hash`, `document.referrer`, `window.name`, `postMessage` `event.data`.

### Java/Kotlin
- JSP `<%= x %>`, `${x}` without `<c:out>`; Thymeleaf `th:utext`; Freemarker `${x}` in a non-escaping mode; `response.getWriter().print(x)` to `text/html`.

### Go
- `text/template` for HTML output (no auto-escape); `template.HTML(x)`, `template.JS(x)`, `template.URL(x)` casts; `fmt.Fprintf(w, "<div>%s</div>", x)`.

### PHP
- `echo $x`, `print $x`, `<?= $x ?>` with no `htmlspecialchars`. Laravel Blade `{!! $x !!}`. Symfony Twig `|raw`.

### Ruby
- `raw(x)`, `x.html_safe`, `<%= raw x %>`. Note: bare `<%= x %>` auto-escapes in Rails and is safe.

### C#/.NET
- `@Html.Raw(x)`, `MvcHtmlString.Create(x)`. Bare `@x` HTML-encodes and is safe.

## Safe patterns

- Context-aware auto-escaping left on: Jinja2/Django `{{ x }}`, EJS `<%= %>`, Handlebars `{{ }}`, Razor `@x`, Go `html/template`, React JSX `{x}`, Angular and Vue `{{ }}`.
- Explicit encoding for the exact context before output: `htmlspecialchars`, `escape-html`, `c:out`, `fn:escapeXml`.
- `textContent` / `innerText` for a text node.
- A sanitizer with a strict allowlist (DOMPurify, sanitize-html with no tags and no attributes) before an `innerHTML` write.
- `|json_script` or a `</`-escaping serializer for data embedded in an inline script.

## Weak mitigations

- A Content-Security-Policy. It reduces impact but does not fix the injection. `unsafe-inline` or `unsafe-eval` in `script-src` removes most of its value.
- Custom escaping or a regex that strips `<script>`. Bypassable. Keep the finding.
- A WAF or input validation that is not a strict format allowlist.
- HTML escaping for a value placed in a script, an event handler, or a URL. Wrong context.

## Verification checklist

- **attacker_control:** Name the render site and the user source. Quote the unescaped marker or the DOM/JS sink, and the source feeding it.
- **privilege_boundary:** State the gain against a victim: session or credential theft, actions as the victim. Stored XSS shown to an admin counts.
- **unmitigated:** Confirm no context-correct encoding and no strict sanitizer on this path. Name the output context. Quote the encoder or sanitizer to refute.
- For stored XSS, confirm both legs: the write path takes user input, and the read path renders it unescaped.
- A response of `application/json` or `text/plain` that no page embeds as HTML is not XSS.

## Examples

### JavaScript/TypeScript (DOM, React)
```javascript
// Vulnerable: URL fragment written as HTML
el.innerHTML = "Hello, " + location.hash.slice(1);

// Secure: text node, no HTML parsing
el.textContent = "Hello, " + location.hash.slice(1);
```
```jsx
// Vulnerable: dangerouslySetInnerHTML with user content
<div dangerouslySetInnerHTML={{ __html: comment }} />
// Secure: render as text (React auto-escapes)
<div>{comment}</div>
```

### Python (Django / Jinja2)
```python
# Vulnerable: mark_safe bypasses auto-escaping
return render(request, "bio.html", {"bio": mark_safe(request.GET["bio"])})

# Secure: pass the raw string; the template escapes {{ bio }}
return render(request, "bio.html", {"bio": request.GET["bio"]})
```

### PHP
```php
// Vulnerable: echo with no encoding
echo "<p>Welcome, " . $_GET["name"] . "</p>";

// Secure: context-correct encoding
echo "<p>Welcome, " . htmlspecialchars($_GET["name"], ENT_QUOTES, "UTF-8") . "</p>";
```

## Dynamic test hints

- Use a local build only. Never test a real system.
- Reflected: send `q=<script>alert(1)</script>` or `q="><img src=x onerror=alert(1)>` and view the source to see whether it renders unescaped.
- DOM: open a local page with `#<img src=x onerror=alert(1)>` and watch for the alert.
- Context probe: if the value sits in an attribute, try `" onmouseover=alert(1) x="`. If in a script string, try `</script><script>alert(1)</script>`.
- Stored: submit the payload through the write form, then open the page that renders it.
- Keep the payload to a harmless `alert(1)` on a local instance.

## False positive traps

- The template uses the auto-escaped form and the output context is HTML body text.
- The value is not attacker-influenced: a server literal, an admin-only field, or a number/enum with no string bytes.
- A strict sanitizer (DOMPurify with a restrictive config) processes the value before the sink.
- The sink is `textContent`, `innerText`, or `setAttribute` on a non-event, non-URL attribute. No HTML parse.
- The response is `application/json` or `text/plain` and no HTML page embeds it.
- Rails bare `<%= x %>`, Razor bare `@x`, Go `html/template` with a plain string: auto-escaped. Flag only the explicit unescape forms.

## Sources

Condensed and rewritten from the local copies under `third_party/`.

- `utkusen/sast-skills@db52227: sast-files/.claude/skills/sast-xss/SKILL.md` (MIT, Utku Sen): the reflected/stored/DOM types, per-engine unescaped markers, DOM sinks and sources, per-stack examples, stored-XSS two-leg rule.
- `block/codecrucible@b5c8086: prompts/default/cwe_deep_analysis.yaml` (CWE-79), `prompts/default/analysis_sections.yaml` (BROWSER-MEDIATED), `prompts/core/audit_families.yaml` (output family), `prompts/exploit-proof-web-*` (Apache-2.0, Block): the render-site focus, context mismatch, CSP caveat, false positive indicators.
- `vercel-labs/deepsec@4fa6722: packages/scanner/src/matchers/xss.ts`, `dangerous-html.ts`, `js-react-unsafe-json-in-html.ts`, `processor/src/prompt/highlights.ts`, `slug-notes.ts` (Apache-2.0, Vercel): DOM sinks, JSON-in-script `</`-escape, framework render notes.
- `cloudflare/security-audit-skill@c1c8a8c: skills/security-audit/CLIENT-SIDE.md` (MIT, Cloudflare): DOM-based XSS source-to-sink method and the self-injection exclusion.
- `alibaba/open-code-review@11ac6d4: internal/config/rules/rule_docs/ts_js_tsx_jsx.md`, `jinja.md`, `freemarker.md`, `pug.md`, `handlebars_mustache.md` (Apache-2.0, alibaba/open-code-review contributors): per-template escaping boundaries, `innerHTML` rule.
