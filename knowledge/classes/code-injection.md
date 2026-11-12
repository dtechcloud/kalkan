---
slug: code-injection
title_en: Code injection / eval
title_tr: Code injection / eval
cwe: CWE-94, CWE-95, CWE-917, CWE-74, CWE-470
owasp: A03:2021
sources: sast-skills, codecrucible, deepsec, open-code-review
---

## Summary

The application passes attacker text to a function that evaluates it as code in the application language. The attacker then runs arbitrary code in the process. This class covers `eval`, the `Function` constructor, dynamic `import`/`require`, expression-language evaluation (SpEL, OGNL, MVEL) and unsafe reflection. The core shape is attacker bytes reaching a code-evaluation sink.

## What it is

- **Eval-style sinks.** `eval`, `exec`, `compile` (Python); `eval`, `new Function`, `setTimeout`/`setInterval` with a string, `vm.runInNewContext` (JavaScript); `eval`, `assert`, `create_function`, `preg_replace` with the `/e` modifier (PHP); `eval`, `instance_eval`, `class_eval` (Ruby).
- **Expression-language injection (CWE-917).** Spring SpEL `parseExpression(x).getValue(...)`, Struts OGNL, MVEL, a template that reaches EL. User text becomes an expression that runs code.
- **Dynamic module load.** `importlib.import_module(x)`, `__import__(x)`, `require(x)`, `import(x)` with a user path. PHP `include`/`require` with a user path that points to attacker content.
- **Unsafe reflection (CWE-470).** The attacker selects the class or method that the code instantiates or calls.
- **Partial injection.** User text sits inside a larger static code string and breaks out of its quoting context.
- **Second-order.** A stored user value is later evaluated by a job or a build step.

## What it is not

- An OS command through a shell → `os-command-injection`.
- Template source from user input → `ssti` (it is CWE-94 wearing a template hat, but it stays in `ssti`).
- Deserializing attacker bytes that trigger a gadget chain → `deserialization`.
- A SQL or NoSQL query change → `sqli` or `nosqli`.
- `JSON.parse`, `ast.literal_eval` and `yaml.safe_load` have no code semantics. They are not this class.
- `vm.runInNewContext` is not a real sandbox. Treat an escape as code injection, not a safe control.

## Where to look

Find the evaluation sink first. Then trace the argument bytes: fully user-controlled, partly (embedded in a larger string), or fully static.

### Python
- `eval(x)`, `exec(x)`, `compile(x, ...)` then `exec`, `importlib.import_module(x)`, `__import__(x)`.
- Safe lookalike: `ast.literal_eval(x)` parses literals only.

### JavaScript/TypeScript
- `eval(x)`, `new Function(body)`, `setTimeout(string, ...)`, `setInterval(string, ...)`, `vm.runInNewContext(x)`, `require(x)`, dynamic `import(x)`.
- Safe lookalike: `JSON.parse(x)` has no code semantics.

### Java/Kotlin
- SpEL `new SpelExpressionParser().parseExpression(x).getValue(ctx)`, `@Value("#{...}")` with user data, OGNL in Struts, MVEL template engines, Thymeleaf `th:utext` that reaches EL, `ScriptEngine.eval(x)`.
- Reflection: `Class.forName(x).newInstance()` with a user class name.

### Go
- `text/template` and `html/template` can call methods on the data, but Go has no general `eval`. Reflection that selects a function from user input is the risk. Plugins loaded from a user path.

### PHP
- `eval($x)`, `assert($x)`, `create_function('', $x)`, `preg_replace('/.../e', ...)`, `call_user_func($x)`, dynamic `include`/`require` with a user path.

### Ruby
- `eval(x)`, `instance_eval(x)`, `class_eval(x)`, `send(x, ...)` with a user method name, `Object.const_get(x)`.

### C#/.NET
- `CSharpScript.EvaluateAsync(x)`, `DataTable.Compute`, dynamic `Assembly.Load` plus `CreateInstance` with user input.

## Safe patterns

- Do not evaluate user input as code. Choose a data format or a safe parser: `ast.literal_eval`, `JSON.parse`, a math-expression library (mathjs, a safe calculator).
- For a dynamic choice, map a user key to a fixed function with a dictionary or a switch. The user key is a lookup key, not code.
- Keep every expression (SpEL, OGNL) a compile-time constant. Bind user data only as a named context variable.
- Load a module or class from a fixed allowlist, never from a user path.

## Weak mitigations

- A blocklist of keywords such as `import` or `__`. An attacker finds another path to the same object.
- `vm.runInNewContext` or a "sandbox" claim. These have an escape history. Note it, do not credit it.
- A regex that tries to allow only "math". It rarely holds against a determined input.
- Stripping quotes for a partial-injection case. The attacker changes the structure another way.

## Verification checklist

- **attacker_control:** Name the entry point and the value. Quote the evaluation sink and show the argument is user-controlled, in full or embedded.
- **privilege_boundary:** State the gain: run arbitrary code in the process, which usually means full compromise.
- **unmitigated:** Confirm the sink is a real code-evaluation primitive, not a safe lookalike (`JSON.parse`, `ast.literal_eval`). For a partial injection, confirm the user value can break its quoting context. Quote the safe parser or the allowlist to refute.
- For an embedded value, check whether a safe serialization (for example `JSON.stringify` into a string literal) escapes every metacharacter.

## Examples

### Python
```python
# Vulnerable: eval runs attacker code
result = eval(request.args["expr"])  # __import__('os').system('id')

# Secure: literal_eval parses data only
from ast import literal_eval
result = literal_eval(request.args["expr"])
```

### JavaScript/TypeScript
```javascript
// Vulnerable: new Function builds code from user input
const fn = new Function("x", `return ${req.body.formula}`);

// Secure: a math library, no code evaluation
const { evaluate } = require("mathjs");
const result = evaluate(req.body.formula);
```

### Java/Kotlin (SpEL)
```java
// Vulnerable: user text becomes a SpEL expression
Object v = new SpelExpressionParser().parseExpression(userExpr).getValue(ctx);

// Secure: fixed expression, user data bound as a variable
Expression e = parser.parseExpression("#input.length()");
ctx.setVariable("input", userValue);
Object v = e.getValue(ctx);
```

## Dynamic test hints

- Use a local build only. Never run a payload against a real system.
- Probe first with a harmless expression: send `expr=7*7` and look for `49` in the response.
- Then confirm code reach with a safe side effect on the local app, for example a short `sleep`, and compare the response time.
- For SpEL on a local Spring app, probe with `#{7*7}` and watch for `49`.
- Keep every payload harmless (`7*7`, a short sleep). Do not run destructive code.

## False positive traps

- The argument is a server-side literal. The user value flows to a different nearby call.
- The sink is a safe lookalike: `ast.literal_eval`, `JSON.parse`, `yaml.safe_load`.
- The user value is embedded through a mechanism that cannot break context, for example `JSON.stringify` into a quoted string literal.
- The expression is a constant and the user value is only a bound context variable.
- The sink runs only in a build-time or CLI path that never serves a request. Mark `unknown` if the caller is outside the source.

## Sources

Condensed and rewritten from the local copies under `third_party/`.

- `utkusen/sast-skills@db52227: sast-files/.claude/skills/sast-rce/SKILL.md` (MIT, Utku Sen): the eval-like sinks per language, the `ast.literal_eval`/`JSON.parse` safe lookalikes, per-stack examples.
- `block/codecrucible@b5c8086: prompts/default/cwe_deep_analysis.yaml` (CWE-94), `prompts/default/analysis_sections.yaml` (DYNAMIC EXECUTION), `prompts/exploit-proof-web-java/cwe_deep_analysis.yaml` (CWE-917), `prompts/core/audit_families.yaml` (injection family) (Apache-2.0, Block): the sink list, SpEL/OGNL, partial-injection and sandbox notes, false positive indicators.
- `vercel-labs/deepsec@4fa6722: packages/scanner/src/matchers/rce.ts` (Apache-2.0, Vercel): the `eval`, `new Function`, `vm.runIn*Context`, dynamic `require` sinks.
- `alibaba/open-code-review@11ac6d4: internal/config/rules/rule_docs/python.md`, `php.md` (Apache-2.0, alibaba/open-code-review contributors): the "eval/exec on untrusted input is arbitrary code execution" rule and PHP dynamic-include guidance.
