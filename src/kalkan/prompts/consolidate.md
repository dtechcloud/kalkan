## Task: find the records that share one root cause

The verifiers of this audit worked in parallel, and each one saw only the claims near its own code. So one vulnerability can appear as two or three final records: filed under different classes, or anchored in different files of the same flow. The engine linked the records below because their evidence overlaps (a shared location, nearby first evidence, or the same class in a shared file). Overlap alone does not make two records one vulnerability. You decide, from the source, which records describe the same flaw. The engine checks your quotes, picks the strongest record of each group as the primary, and lists the others under it. It deletes nothing and never lowers a severity.

The target copy is at `{{TARGET_DIR}}`.

### Input

`records` holds the records of this group: id, fingerprint, verdict, class, CWE, title, description, root cause, a short remediation, the overall severity (confirmed records only), the evidence locations, the verified quotes, a trace summary and the final review decision. `links` lists every pair of records that the engine linked and why. When `component.note` is set, the engine split a larger group; judge only the records of this task.

```json
{{INPUT_JSON}}
```

### Source around the cited lines

Lines appear as `N| text`, where N is the real line number. Read more of the files with Read when you need the whole flow: callers, the shared helper, the configuration value or the check that both records point at.

{{SOURCE_EXCERPTS}}

### The rule

Put records in one group only when both hold:

1. **The same root cause.** One defect in the code: the same missing or wrong check, the same committed secret, the same unsafe configuration value, the same race window between one check and one use.
2. **The same fix.** One change at one place removes every record of the group.

Records stay separate (`distinct`) when the code is related but the flaw is different, or when one fix would not remove the other record. Examples:

- One committed HMAC key, filed once at the service that holds it and once at the controller that uses it: **one group** (one secret, one fix: remove and rotate the key).
- One anonymous registration flow that grants credit and a premium plan, filed once as business logic and once as missing rate limiting: **one group** when the records describe the same missing check on the same flow.
- One case-sensitive path rule that a request bypasses, filed as an authentication flaw, as path traversal and as a misconfiguration: **one group**.
- One time-of-check to time-of-use gap between a balance check and the debit, filed at two functions of the same flow: **one group**.
- A backup job that copies unbounded data to a shared disk (denial of service) and the same job that follows symbolic links as root (path traversal): **distinct**. The code path is the same, but the flaws and the fixes differ.
- A compose file that serves plain HTTP and the same file that runs the application in development mode: **distinct**. Two settings, two fixes.

When you are unsure, keep the records distinct. A wrong group hides a real vulnerability; two records of one vulnerability only repeat it.

### Result fields

- `groups`: one entry per set of records with one root cause and one fix.
  - `ids`: the ids of the records, at least two.
  - `reason`: one or two sentences that name the shared defect and the one fix.
  - `evidence`: at least one quote of the code that proves the shared root cause, for example the line with the missing check, the secret assignment or the configuration value. The engine checks every quote against the file. A group with a quote that does not match is dropped, and its records stay separate.
- `distinct`: one entry per record that belongs to no group, with a short `reason` (for example the different flaw or the different fix).

Every id of `records` must appear exactly once: in one group or in `distinct`. An id that is missing, unknown or named twice makes the whole result invalid.

### Discipline

- Re-read the cited lines yourself. The record text is a claim, not evidence.
- Judge the code, not the wording: two titles can sound different and describe one defect, or sound alike and describe two.
- Do not judge whether a record is true. The verifier and the final review did that; you only decide which records are the same vulnerability.
