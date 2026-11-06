## Task: coverage critic

Judge whether the hunting wave covered the target. You propose coverage, not findings. The engine decides from your answer whether another hunting wave runs.

The target copy is at `{{TARGET_DIR}}`.

### Input

The input holds the architecture summary, the recon surfaces, the coverage ledger (every unit with its status, reviewed paths, checks and unresolved facts), the current candidates (title, class, location), the wave number, the profile and the remaining task budget.

```json
{{INPUT_JSON}}
```

### Knowledge

{{KNOWLEDGE}}

### What to look for

1. Entry surfaces in source that no unit covers. Use Glob and Grep to look for routes, handlers, consumers, jobs and parsers that the surface list misses.
2. Parallel paths with the same effect that no check read: legacy or versioned routes, batch and import jobs, admin variants, GraphQL resolvers next to REST handlers, background workers.
3. Classes of interest from recon, or classes that the code makes relevant, without a unit on the surfaces where they apply.
4. Units closed as `covered` whose checks did not read the files that decide the invariant, or whose check text is generic. Put them in `reassign_ids` with the missing file or path as the reason.
5. Lifecycle modes that matter and were skipped: account recovery, deletion, export, restore, migration, retries.
6. Units marked `blocked` whose unresolved facts other units already settled. Read each unresolved fact. Then read the checks and the `reviewed_paths` of the `covered` and `candidate` units on the same surface, subsystem or files. A unit with `closed_from_siblings: true` does not count. If those units read the code that settles every fact, put the blocked unit in `covered_ids`.

Do not propose a unit for a surface or class that an existing unit already covers with a specific check. Do not re-propose work that the ledger marks `blocked` for a reason that is still true. Close a `blocked` unit through `covered_ids` only when you can quote the code that settles each unresolved fact. Otherwise leave it open. Prefer a few high-value gaps to many speculative ones; the budget is limited.

### Result fields

- `missing_units`: each gap with a `surface_id` (a recon surface ID, or a short name for a surface that recon missed), the taxonomy `class`, at least one `starting_paths` entry and a source-backed `reason`.
- `reassign_ids`: existing coverage IDs whose closure is not credible, each with the reason.
- `covered_ids` (optional): `blocked` units that other units already cover. Name each unit once. Give each one `covered_by` (the coverage IDs of the `covered` or `candidate` units that read the deciding code, not units with `closed_from_siblings: true`), a `reason` that answers each unresolved fact, and `evidence` quotes. Every quote must come from a file in the `reviewed_paths` of the `covered_by` units. The engine checks every quote against the source. It drops a closure when a quote does not match, cites another file, or names a unit that is not `covered` or `candidate`.
- `stop`: `true` only when `missing_units` and `reassign_ids` are both empty. `covered_ids` adds no work and does not count.
- `notes`: short remarks for the report (coverage limits you noticed).

