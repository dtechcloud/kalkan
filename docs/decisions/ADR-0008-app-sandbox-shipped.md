# ADR-0008: The app-level PoC sandbox is active
English | [Türkçe](ADR-0008-app-sandbox-shipped.tr.md)

- Status: accepted
- Date: 2026-11-11
- Decided by: the project owner
- Related: ADR-0001, ADR-0004 and ADR-0006 (this decision replaces their "app level deferred" parts)

## Context

ADR-0006 made the PoC sandbox active at the unit level and deferred the app level (compose stacks). The app level is now in the engine: `kalkan.sandbox.app` (docs/ENGINE-SPEC.md, section 23). Some findings need the running application, for example an IDOR or a missing authorization check. A unit harness cannot show them.

## Decision

- The app level is active. When the `poc_build` result asks for it, the engine starts the target's compose stack and sends the harness requests from a client container.
- The engine checks the resolved compose configuration first. It refuses a privileged service, a host or shared namespace, an added capability, a device, the Docker socket, a bind mount outside the target copy, and an external volume or network (blocker `sandbox_app_unsafe`).
- The engine writes its own compose file. Every service is on one internal network without internet access. No port is published to the host. The services get a small capability set, `no-new-privileges`, and memory, CPU and PID limits. Binds inside the target copy are read-only.
- The app level uses the network only with the opt-in `--allow-build-network` (`kalkan audit --allow-build-network` or `kalkan run init --allow-build-network`). The flag is off by default. With it, `docker compose pull` and `docker compose build` get network access to pull and build the stack images. The running stack stays on the internal network and never gets internet.
- Without the flag, the engine pulls and builds no image. A finding that needs one is `blocked` with the blocker `sandbox_build_network_needed` or `sandbox_image_missing`.
- `docker compose down -v --remove-orphans --rmi local` always runs at the end.

## Consequences

- The report can show runtime evidence for findings that need the running application.
- docs/SECURITY.md lists `--allow-build-network` among the opt-in features that use the network.
- The blocker `sandbox_app_deferred` stays readable in the report, but the engine no longer writes it.
