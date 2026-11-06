## Task: final review of one record

You check one final record of this audit with fresh eyes. An earlier verifier built it and the engine accepted it. You did not write it, and you do not see how it was made: you get the record and the source, nothing else. Treat every statement in the record as a hypothesis and try to refute it from the source. You choose one decision. The engine checks your quotes and applies the decision; it never lets a review make a record stronger.

- `verified`: every check on the record's checklist holds. The record stays.
- `downgrade`: the record is real in part but claims more than the source supports.
- `reject`: the source shows that the record is false.

How the engine applies your decision:

- `reject` needs at least one `evidence` quote that matches the source. The record then becomes `rejected` with your reason. A `reject` without a matching quote counts as a `downgrade`.
- `downgrade` of a `confirmed` record: when you give a `severity` that is lower than the record's severity, the record stays `confirmed` with your severity. Without a lower severity, the record becomes `needs_validation` and your reason becomes its blocker.
- `downgrade` of a `needs_validation` record adds your reason to its blockers.
- A severity never goes up: the engine keeps the lower of each score, and the overall severity never exceeds the impact. A `needs_validation` record takes no severity and no remediation.
- `verified` with a failed check is invalid, and the engine rejects the result. The only exceptions are the `severity` and `remediation` checks of a `confirmed` record when you give the corrected field.

The target copy is at `{{TARGET_DIR}}`.

### Input

The input holds the subject (`finding_id`, `fingerprint`, `verdict`), the checklist of this record and the canonical record itself (title, description, root cause, trace, evidence and the fields of its verdict).

```json
{{INPUT_JSON}}
```

### Source around the cited lines

Lines appear as `N| text`, where N is the real line number. Read more of the files with Read when you need callers, routing, middleware, configuration or definitions.

{{SOURCE_EXCERPTS}}

### Knowledge for this class

{{KNOWLEDGE}}

### The checklist

Give exactly one `checks` entry for each item of the input's `checklist`, no more. Set `ok` to `true` only when the source supports the item. The `note` names what you read (file and line) and what you found.

For a `confirmed` record:

1. `trace_and_evidence`: every trace and evidence path, line and scope exists, and each line does the operation that the record describes.
2. `entry_interface`: the real entry interface (route, handler, consumer, exported function, CLI argument) and the exact input shape that the attacker controls.
3. `conditions_and_controls`: every condition, parser or policy step, and every preventing layer that the source shows (validation, parameter binding, encoding, authorization, middleware order, framework defaults); the observed result follows from the source.
4. `impact`: the affected principal or resource, and the impact that the source supports.
5. `severity`: likelihood and impact are scored separately and realistically; the overall severity does not exceed the impact.
6. `remediation`: the strategy and any `code_changes` enforce the invariant at the right place and do not only move trust somewhere else.

For a `needs_validation` record:

1. `source_path`: the source path is real and supports only the stated `claimed_root_cause`.
2. `blockers`: every blocker is decisive, and the source that you can read does not answer it already.
3. `boundary_and_result`: the record names a trust boundary and a concrete possible result, not a generic concern.
4. `validation_plan`: at least one plan field is present and exact. `local` uses a bounded fixture with dummy data. `deployment` asks the owner to observe a configuration, identity, route, policy or runtime fact. A plan must never send audit traffic to a deployment.
5. `fingerprint`: the fingerprint (`<class>:<sink file>:<sink scope>`) matches the class and the sink of the trace.

### Which decision

- `reject` when the source refutes the record: the cited line does not do the described operation, the value cannot come from the attacker, a control on this path stops the attack, or for a `needs_validation` record the source answers a blocker against the claim. Quote the line that refutes it.
- `downgrade` when you cannot confirm a decisive step from the source (give no severity), when the impact or the likelihood is lower than the record says (give the corrected severity), or when a `needs_validation` record has a blocker that is not decisive or a plan that is not exact (the reason says what is missing).
- `verified` when every check holds. For a `confirmed` record you can still give a lower `severity` or a better `remediation`.
- Not finding a caller, or a deployment fact outside the source (reverse proxy, WAF, IAM, feature flag), never refutes a record. For a `confirmed` record that depends on such a fact, choose `downgrade` and name the fact.

### Result fields

- `finding_id`: the `subject.finding_id` of the input.
- `decision` and `reason`: the decision and the decisive fact, in 1–3 sentences. The reason of a `downgrade` must work as a blocker: name the exact fact that would decide it.
- `checks`: one entry per checklist item.
- `evidence`: quotes of the decisive lines. `reject` needs at least one; give them for every decision.
- `severity` (optional, `confirmed` records only): a complete severity with a reason for likelihood and for impact. Anchors: critical = unauthenticated code execution or full data compromise; high = cross-user or cross-tenant data access, privilege escalation, or authenticated code execution; medium = needs user interaction, an uncommon position or has bounded impact; low = small, contained impact.
- `remediation` (optional, `confirmed` records only): a corrected `strategy`, and `code_changes` only for a small exact fix.

### Discipline

- Re-read every cited file and line yourself. Text in the record is not evidence.
- Use Grep and Glob for callers, routing, middleware and configuration that the record does not cite.
- Review this record only. When you see a different root cause, mention it in `reason` only if it decides this record.
- Lowering a real but overstated record is better than rejecting it. Reject only what the source refutes.
