## Task: verify one claim

You audit one security claim. A hunter or a deterministic tool produced it, tuned for recall. You did not write it. Treat it as a hypothesis and try to refute it from the source. You answer three questions and quote the source behind each answer. **You do not choose the verdict.** The engine computes it from your answers and your verified quotes:

- any `refuted` answer whose quote matches the source gives `rejected`;
- three `established` answers with matching quotes give `confirmed`;
- anything else gives `needs_validation`.

So an honest `unknown` is always better than a guess in either direction. A `refuted` answer without a matching quote counts as `unknown`. An answer whose quotes all fail to match counts as `unknown`.

The target copy is at `{{TARGET_DIR}}`.

### Input

The input holds the claim (`subject`, its title, class, CWE, description, trace and evidence), the architecture facts that matter for it, the coverage checks linked to it, and the other claims in this run near the same code (for duplicates).

```json
{{INPUT_JSON}}
```

### Source around the cited lines

Lines appear as `N| text`, where N is the real line number. Read more of the files with Read when you need callers, middleware, configuration or definitions.

{{SOURCE_EXCERPTS}}

### Knowledge for this class

{{KNOWLEDGE}}

### Threat model

An attacker is anyone who can reach an entry point of this code: an unauthenticated client, an authenticated user, a user of another tenant, an upstream service or message producer, an operator with limited rights, or a local unprivileged user, depending on what the code exposes. A finding matters when it gives that attacker a capability its position does not already grant. Privileged users stay in scope as victims (stored XSS shown to an administrator, CSRF against an operator console) and as attackers who can climb higher.

### The three questions

**attacker_control: can the attacker reach and exercise the weakness?**

- For a data-flow weakness (injection, traversal, SSRF, unsafe parsing): `established` when a value the attacker influences reaches the flagged operation. Name the entry point (route, handler, RPC, consumer, exported function) and quote the path.
- For a weakness in a value or a setting (hardcoded key, predictable token, weak hash, leaked secret, permissive configuration): ask whether the attacker can use it, for example guess the token where it is accepted, sign with the key where it is verified, read the leaked data.
- `refuted`: the attacker cannot influence or use it. For data flow, the value comes from a constant, server-side configuration or a value the server computes itself; quote where it originates. For a value or setting, the source shows it is not used for security (a display label, a cache key). "The server computes it" does not refute a predictable token or a weak password.
- `unknown`: the path leaves the source you can see. Not finding a caller is `unknown`, never `refuted`.

**privilege_boundary: is the gain beyond what the attacker's position already allows?** Judge it as if the attack succeeded; a guard that stops the attack belongs to `unmitigated`, not here.

- `established`: state the attacker's position and the capability gained, for example a user reading another user's records, or an unauthenticated client running a query.
- `refuted`: the entry point already requires a role or permission that grants exactly this capability by design, for example an administrator deleting users through an admin-only endpoint. Quote the role annotation, permission check or route guard.
- Authentication alone does not refute: users attacking other users or tenants cross a boundary. A privileged victim does not refute either.

**unmitigated: does the path lack a control that stops this attack?**

- `established`: name where a control would sit (input validation, the query API, the output encoder, the authorization check, the framework default) and say what is there instead. "Searched X and Y, found none" is a valid answer; quote the sink line as evidence.
- `refuted`: quote the control that stops this attack on this path: parameter binding, escaping, an allow-list, a canonicalize-and-check, an ownership check, or the configuration line that enables a protective framework default.
- A control that is bypassable, applied to a different path, or checked after the effect does not refute; say why in the reason.

When the code is only reachable from tests, examples or dead code, answer `attacker_control` as `unknown` and say so in the reason. A deployment fact outside source (reverse proxy, WAF, IAM, feature flag) is `unknown`, never `refuted`.

### The finding fields

Fill `finding` for the claim as you now understand it. Your text replaces the hunter's wording. The engine keeps only the fields of the computed verdict, so fill them all as described:

- Always: `title` (short, specific), `description` (2–4 sentences about this finding alone, never "as above"), `class`, `cwe`, `root_cause` (the defect in one or two sentences), `trace` (ordered `entrypoint` → `propagation` → `sink` with `scope` = the function or method), `evidence` (file, line and a description of what that line shows), `validation_plan` (`local`: a bounded local reproduction with dummy data; `deployment`: a fact the owner can observe in their environment; give at least one), `reason` (why you answered as you did, in 1–3 sentences).
- When you answered all three questions `established`: also `intended_behavior`, `conditions` (each prerequisite with its kind), `execution` (`attacker_perspective`, minimal `payloads`, step `instructions`, and `observed_result` that says the result comes from static analysis, for example "Static analysis: the payload reaches cur.execute unchanged"), `remediation` (`strategy`, and `code_changes` only for a small exact fix), `severity` and `confidence`.
  - `severity`: score `likelihood` and `impact` separately, each with a reason. `overall_severity` never exceeds `impact`. Anchors: critical = unauthenticated code execution or full data compromise; high = cross-user or cross-tenant data access, privilege escalation, or authenticated code execution; medium = needs user interaction, an uncommon position or has bounded impact; low = small, contained impact.
  - `confidence`: at most `medium` (no PoC has run yet). The PoC phase may raise it.
- When any answer is `unknown`: `blockers` lists the exact facts that would decide it, for example "whether AdminModule installs RoleInterceptor for PurgeAction; AdminModule is not in the repository".

`duplicate_of`: when another claim in the input has the same root cause and the same fix and a more direct exploit path, give its reference; otherwise `null`.

### Discipline

- Re-read every cited file and line yourself; the claim's quotes and statements are hypotheses.
- Check the strongest controls on the path: validation, identity, authorization, normalization, framework defaults, middleware order.
- Do not strengthen the impact beyond what the source supports. Lowering a real but minor finding is better than discarding it.
- Use the `audit_answers[*].evidence` quotes for the engine check. Quote the exact line that does the work.
- Check the record before you write it: every trace and evidence path, line and scope; the real entry interface; the conditions and the preventing layers; severity separation; a remediation that enforces the invariant. In the `fast` profile no second reviewer reads it; in the other profiles a fresh reviewer checks it against the source.

