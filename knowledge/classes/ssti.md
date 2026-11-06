---
slug: ssti
title_en: Server-side template injection
title_tr: Server-side template injection (SSTI)
cwe: CWE-1336
owasp: A03:2021
sources: sast-skills, codecrucible, deepsec, open-code-review
---

## Summary

The application uses attacker text as the template source, not as template data. A template engine then runs the attacker's template syntax. With a code-capable engine (Jinja2, Twig, Freemarker, Velocity, ERB, EJS), this reaches arbitrary code and full server compromise. The whole finding is the difference between template source and template data.

## What it is

- **User input as the template string.** `render_template_string(user_input)`, `Template(user_input).render()`, `env.from_string(user_input)`, `ejs.render(user_input)`, `Handlebars.compile(user_input)`, `nunjucks.renderString(user_input)`, `pug.compile(user_input)`, `Velocity.evaluate(ctx, w, tag, user_input)`, `new Template(name, new StringReader(user_input), cfg)`, `ERB.new(user_input).result`, `Twig createTemplate(user_input)`, `template.New("x").Parse(user_input)`.
- **Dynamic template name.** The template file name comes from user input and the engine resolves an arbitrary template: `render_template(user_name)`, `res.render(req.query.template)`, a Spring controller returning `"user/" + lang + "/view"`.
- **Second-order.** A "custom template" feature stores user template syntax in the database. A later render runs it without a sandbox.

## What it is not

- User input passed as a context variable to a fixed template that auto-escapes → not a finding (or `xss` if the output is unescaped).
- `eval`-style evaluation outside a template engine → `code-injection`.
- A command through a shell → `os-command-injection`.
- A user path that selects an arbitrary file to read, with no template render → `path-traversal`.
- A logic-less engine (Mustache, strict Handlebars with no helpers) with a user template: no code primitive exists, so rate it lower and check only data leakage.

## Where to look

Flag any render, compile or evaluate call whose template argument is a variable, a concatenation or any non-literal. Then trace whether user input reaches that argument.

### Python (Jinja2, Mako, Django)
- `render_template_string(x)`, `Environment().from_string(x)`, `jinja2.Template(x).render()`, `mako.template.Template(x)`.
- Safe shape: `render_template("page.html", name=x)` — `x` is data.

### JavaScript/TypeScript (EJS, Nunjucks, Handlebars, Pug, Lodash)
- `ejs.render(x)`, `nunjucks.renderString(x)`, `Handlebars.compile(x)`, `pug.compile(x)`, `pug.render(x)`, `_.template(x)`.
- Express: `pug.compile(req.body...)`, `res.render(req.query.template)`.

### Java/Kotlin (Freemarker, Velocity, Thymeleaf, StringTemplate, Pebble)
- Freemarker `new Template(name, new StringReader(x), cfg)`, `cfg.getTemplate(x)` with a user name.
- Velocity `evaluate(ctx, w, tag, x)`. Thymeleaf controller returning a view name built from user input. `new ST(x)`.

### Go (text/template, html/template)
- `template.New("x").Parse(x)`, `t.Parse(x)`, `t.ParseFiles(x)` with a user name.
- Note: even `html/template` runs attacker template syntax if user input reaches `.Parse`.

### PHP (Twig, Smarty, Blade)
- `$twig->createTemplate($x)->render()`, `$smarty->fetch("string:".$x)`, `Blade::render($x)`, `View::make($x)` with a user name.

### Ruby (ERB, Liquid)
- `ERB.new(x).result(binding)`, `Liquid::Template.parse(x).render()`.

### Framework note: dynamic template name
- A controller that builds a view name from user input can hit path traversal and, for Thymeleaf, Spring EL in the path. Validate the name against an allowlist.

## Safe patterns

- Keep the template a fixed file or a constant string. Pass user data only as a context variable to that template.
- Validate a dynamic template name against a hardcoded allowlist of template names.
- For a user-authored template requirement, use a logic-less engine (Mustache, Liquid with safe config) and treat it as a product decision, not a safe default.

## Weak mitigations

- A blocklist that strips `{{`, `}}`, `{%`, `%}`. Encoding and alternate syntax get past it. Keep the finding.
- A sandbox mode (Jinja2 `SandboxedEnvironment`, a Twig sandbox). These have an escape history. Note it, do not fully credit it.
- Escaping the output. SSTI runs before output, so output escaping does not help.

## Verification checklist

- **attacker_control:** Name the entry point and the value. Quote the render/compile call and show user input is the template STRING, not a context variable.
- **privilege_boundary:** State the gain: with a code-capable engine, arbitrary code and full server compromise.
- **unmitigated:** Confirm no allowlist (for a dynamic name) and no confirmed sandbox. A blocklist of template characters does not refute. Quote a fixed template source to refute.
- Name the engine and its risk level. A logic-less engine (Mustache) with a user template is lower severity; still check data leakage.

## Examples

### Python (Jinja2 / Flask)
```python
# Vulnerable: user input is the template source
name = request.args.get("name", "")
return render_template_string(f"<h1>Hello {name}</h1>")
# payload: name={{7*7}} -> 49 ; then RCE via object traversal

# Secure: user input is data for a fixed template
return render_template("greet.html", name=request.args.get("name", ""))
```

### JavaScript/TypeScript (EJS / Pug)
```javascript
// Vulnerable: user input compiled as a template
res.send(ejs.render(req.query.template, { user: req.user }));

// Secure: fixed view, user input as data
res.render("report", { content: req.query.content });
```

### Java/Kotlin (Freemarker)
```java
// Vulnerable: user text becomes the template body
Template t = new Template("p", new StringReader(req.getParameter("tmpl")), cfg);

// Secure: load a fixed template, pass data in the model
model.addAttribute("user", userService.findById(id));
return "report"; // resolves to a fixed template file
```

## Dynamic test hints

- Use a local build only. Never run a payload against a real system.
- Probe with a math expression first: send `name={{7*7}}` (Jinja2/Twig/Nunjucks), `name=<%= 7*7 %>` (ERB/EJS), or `name=#{7*7}` and look for `49`.
- A `49` in the response confirms template evaluation. Then stop at the proof; do not run a destructive payload.
- For a dynamic template name, send a known other template name and check whether it renders.
- Keep payloads to the math probe on a local instance.

## False positive traps

- User input is template DATA passed as a context variable to a fixed template. This may be `xss` if unescaped, but it is not SSTI.
- The engine is logic-less (Mustache, Handlebars with no custom helpers). No code primitive exists in the language.
- The template string is a server-side literal. The user value the first pass saw is the render context, not the source.
- A dynamic template name is checked against a strict allowlist before resolution.
- Do not mark "Not Vulnerable" only because a blocklist strips template characters. Blocklists are bypassable.

## Sources

Condensed and rewritten from the local copies under `third_party/`.

- `utkusen/sast-skills@db52227: sast-files/.claude/skills/sast-ssti/SKILL.md` (MIT, Utku Sen): the source-vs-data distinction, the engine list per language, engine risk levels, per-stack examples, the Thymeleaf view-name note.
- `block/codecrucible@b5c8086: prompts/default/cwe_deep_analysis.yaml` (CWE-1336), `prompts/default/analysis_sections.yaml` (TEMPLATE), `prompts/exploit-proof-web-js/cwe_deep_analysis.yaml` (CWE-1336), `prompts/core/audit_families.yaml` (injection family) (Apache-2.0, Block): the source-vs-data validation checks, sandbox caveats, false positive indicators.
- `vercel-labs/deepsec@4fa6722: packages/processor/src/prompt/slug-notes.ts` (Apache-2.0, Vercel): the Express `pug.compile(user)` = SSTI note.
- `alibaba/open-code-review@11ac6d4: internal/config/rules/rule_docs/jinja.md`, `freemarker.md`, `pug.md`, `handlebars_mustache.md` (Apache-2.0, alibaba/open-code-review contributors): per-engine template-injection and sandbox notes, logic-less vs code-capable distinction.
