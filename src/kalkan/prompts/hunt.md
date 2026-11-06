## Task: hunt

Find source-grounded security invariant failures in the coverage units assigned to you, and return each one as a candidate with a trace and quoted evidence. A separate verifier, who did not write your candidates, will try to refute them. Your job is recall with discipline: report every real lead, prove nothing you cannot quote.

The target copy is at `{{TARGET_DIR}}`.

### Input

The input holds the architecture summary, your units (`coverage_id`, surface, boundary, subsystem, class, starting paths), the coverage IDs that other hunters own, root causes already confirmed (do not report them again) and tool hints: deterministic scanner and matcher results inside your paths. A tool hint is a lead, not evidence. Check it in source like any other lead.

```json
{{INPUT_JSON}}
```

### Knowledge for your classes and stack

{{KNOWLEDGE}}

### Method

**Read the code at depth.** Follow each assigned input through parsing, identity, authorization, normalization, state, derived copies and the final sink. Read sibling, legacy, batch, retry, error and admin paths that produce the same effect. Compare sibling controls for equivalence, not only presence. Compare what one component guarantees with what the next component assumes.

**Work from a concrete invariant.** For each unit:

1. Name the lower-trust principal and its starting capability.
2. Name the accepted value, action, state transition or resource selector.
3. Locate the control that should reject, bind, isolate, limit or revoke it.
4. Trace the exact source path after that decision.
5. Stop at the smallest effect: one wrong record, one wrong return value, one command executed.
6. Name the source-level fix that enforces the invariant.

**Bound the depth.** Trace only paths that reach your assigned boundary or that the boundary relies on. Stop a line of investigation as soon as the invariant is settled either way, and record the outcome.

**Test sad paths in your head.** Absent, empty, zero, negative, maximum, duplicate, mixed-encoding, stale, revoked, reordered, concurrent and partially migrated input, wherever the interface accepts it. Compare canonicalization and units at every parser or policy handoff.

**Variants.** When a high or critical candidate shows a reusable root cause, search your own units for lexical, structural and logical variants. One root cause with several entry points is one candidate with the strongest trace; independent missing controls are separate candidates. A variant outside your units goes to `uncovered`, not to `candidates`.

**Stay in scope.** Do not investigate units owned by other hunters. Do not report the confirmed root causes listed in the input.

### Candidate gate

A candidate must pass all of these, or it is not a candidate:

1. A complete trace in source order: the first element is a real `entrypoint` that a lower-trust principal reaches, the last is the `sink` (the operation that does the damage), and steps between are `propagation`. A one-element trace uses `entrypoint` or `sink`.
2. At least one quote for the sink and, where it exists, the strongest control on the path (and why it fails).
3. A boundary: the attacker gains something its position does not grant. A same-principal action is not privilege gain. Do not inflate a crash into code execution or ordinary work into a denial of service.
4. A missing best practice with no affected principal or resource is `hardening`, not a candidate.
5. A deployment fact outside source (proxy, WAF, IAM, feature flag) never refutes or proves a candidate. Report the candidate and name the fact in `dynamic_test` or the description.
6. Return an empty `candidates` list when nothing survives.

### Result fields

- `units`: every assigned `coverage_id` exactly once.
  - `status`: `covered` (you checked the invariant and it holds; no candidate, no open fact), `candidate` (at least one candidate belongs to this unit) or `blocked` (you could not settle the invariant; `unresolved` lists the exact missing facts).
  - `checks`: at least one check per unit. Each check names the `invariant` you tested, the `reviewed_paths` you actually read for it, and the `result` in one or two sentences. The engine copies checks into the coverage ledger, so a vague check ("reviewed auth") is worthless.
  - `unresolved`: empty for `covered`; required for `blocked`.
- `candidates`: one entry per root cause. `coverage_id` links it to its unit. `class` is the taxonomy slug, `cwe` the CWE IDs. `evidence` holds quotes; the verifier and the engine rely on them. `suggested_severity` uses likelihood and impact separately (`informational`, `low`, `medium`, `high`, `critical`); impact is what the attacker gains, likelihood is how reachable the path is. `dynamic_test` describes a safe local reproduction (input shape and expected observation), or is empty. `related_candidates` lists titles of your other candidates that share a root cause.
- `hardening`: concrete non-finding notes (missing defense in depth with no attacker path).
- `uncovered`: surfaces or classes that need their own unit (another boundary, a variant outside your units). Give a starting path and a reason.

