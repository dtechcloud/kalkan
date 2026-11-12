# ADR-0006: The PoC verification sandbox is active
English | [Türkçe](ADR-0006-sandbox-active.tr.md)

- Status: accepted
- Date: 2026-10-29
- Related: ADR-0004 (this decision updates it). ADR-0008 (2026-11-11) replaces the app-level parts: the app level is active, and it uses the network only with the opt-in `--allow-build-network`.

## Context

ADR-0004 left the PoC sandbox out of the v1 scope. The `poc` stage always took the `poc:skip`
path, and code findings depended only on static evidence. On 2026-10-29, the project owner asked for the
sandbox in the main release: a small verification program from the target code runs in an
isolated container, shows that the finding is real and adds the evidence to the report.

## Decision

- The `kalkan.sandbox` module gives unit-level verification: `docker_available()` and
  `run_poc(ctx, task_id, harness)`.
- When Docker is available, the `poc` stage takes the `poc_build` agent tasks and the `poc:run` step. Without
  Docker, or with `--docker off`, it takes the `poc:skip` path as before. The default is `--docker auto`.
- Isolation profile (unit level): no network (`--network none`), a read-only root file system,
  a non-root user (65534), all capabilities dropped (`--cap-drop ALL`),
  `no-new-privileges`, limits for CPU, memory (512m) and PIDs, a wall-clock timeout. The target
  mounts read-only under `/target`. Only `/out` and `/tmp` are writable.
- The engine downloads no image during an audit. The base images are on an allow list
  (`src/kalkan/sandbox/images.json`), and `kalkan sandbox pull` downloads them by hand. The report shows a missing image
  as `blocked`. The engine does not download it.
- Evidence transfer: a safe copy moves the `/out` output of the container and the captured logs
  to `evidence/<finding-id>/` (it follows no links, takes only regular files, and limits the size and
  the count).
- This release does not run app-level (compose) PoCs: `blocked`, blocker
  `sandbox_app_deferred`. The structure is in place, and a later work completes it.

## Consequences

- A `needs_validation` code finding can become `confirmed` with a `passed` PoC, and its
  confidence becomes `high` (the rules of `kalkan.findings.merge` did not change).
- `poc.json` states: `passed`, `failed`, `blocked`. Blocker codes: `sandbox_timeout`,
  `sandbox_image_missing`, `sandbox_image_not_allowed`, `sandbox_app_deferred`,
  `sandbox_unavailable`, `sandbox_error`.
- The three security promises stay (docs/SECURITY.md). The container has no network, the target
  mounts read-only and the PoC uses fake data. Only `kalkan sandbox pull` downloads images to the machine
  (docs/SECURITY.md, "What leaves the machine").
- The ADR-0004 phrase "out of the v1 scope" now belongs to the past. The report text says "The PoC verification sandbox
  did not run in this audit" in place of "The PoC sandbox is not part of this release".
