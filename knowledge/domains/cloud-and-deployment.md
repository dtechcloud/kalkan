---
name: cloud-and-deployment
title: Cloud and deployment configuration
classes: iac-cloud-container, security-misconfig, hardcoded-secrets, ssrf
when_to_use: The repository defines cloud identity, IaC, containers, Kubernetes, serverless or edge functions, ingress, managed storage, or per-environment configuration.
sources: third_party/security-audit-skill/skills/security-audit/CLOUD-AND-DEPLOYMENT.md
---

# Cloud and deployment configuration

Use this pack when the repository defines cloud IAM, infrastructure as code, container images, Kubernetes objects, a service mesh, serverless or edge functions, ingress, object storage, managed services, or environment-specific settings. The question is whether each deployed component gets the intended identity, isolation, network reachability, secrets, and policy. Source often states intent, not live fact, so keep source-confirmed defects apart from facts that need owner validation. Related packs: `supply-chain-and-release` (build and promotion), `web-protocol-and-auth` (proxy semantics), `data-isolation-and-lifecycle` (tenant scope in stores).

## Core discipline

- A manifest alone does not prove a live exposure. Find the environment that uses it, the defaults and overlays that change it, and whether the path is active.
- Map each workload identity to concrete operations and resources. A broad policy is a finding only when lower-trust input can reach an unauthorized action through it.
- Ingress, proxies, a service mesh, metadata services, and admission policy are real boundaries. Count a control only when its configuration and its attachment are visible.
- A secret reference is not a secret disclosure. Name a lower-trust reader, an output, an artifact, a log path, or an unsafe fallback value.
- Use `needs_validation` for account policy, network attachment, runtime admission, hosted metadata settings, and drift that only the owner can observe.

## Attack classes

### Workload identity overreach

- **Check:** workload, pod, function, edge-worker, or node identities that can act on tenants, accounts, resources, or APIs beyond their role, where untrusted request or job input selects the target. Review policy conditions, resource patterns, service-account attachment, namespace mapping, and fallback credentials.
- **Not a finding:** a broad role that no lower-trust input can steer. Record it as a hardening note.

### Cross-account or cross-tenant role confusion

- **Check:** role assumption, external IDs, token exchange, workload federation (for example CI OIDC trust), and resource policies that accept identity claims not bound to the intended account, audience, repository, branch, namespace, or workload. Establish both the trust policy and the caller-controlled claim.
- **Not a finding:** a trust policy that pins the subject and audience claims.

### Application authorization delegated to cloud metadata

- **Check:** application code that trusts caller-supplied identity headers, tags, labels, account IDs, or resource metadata without proof that they came from the control plane or a trusted proxy. Cloud IAM and application authorization are separate checks.
- **Not a finding:** headers that a trusted proxy sets after it strips client copies, when the configuration shows both steps.

### Unexpected service or management-plane reachability

- **Check:** ingress rules, services, listeners, security groups, load-balancer annotations, port mappings, and bind addresses that expose admin, debug, metrics, node, control-plane, or internal APIs to a lower-trust network.
- **Not a finding:** missing network controls alone, which are `needs_validation`. A repository-defined public route to a sensitive handler can be confirmed.

### Trusted-proxy and mesh identity bypass

- **Check:** backends that accept forwarded identity, an mTLS subject, or authorization metadata from peers outside the intended ingress or sidecar. Look for alternate ports and health or legacy paths that skip the mesh. Check header stripping, peer reachability, and fail-open behavior when the proxy is absent.
- **Not a finding:** a backend that only the proxy can reach, when network policy in the repository shows it.

### Metadata and internal-service reachability

- **Check:** an untrusted URL, destination, or protocol choice that reaches instance or container metadata, control-plane sockets, or internal APIs with workload credentials. Trace URL parsing and redirects with the `ssrf` class. Here, establish the network path, the metadata version (for example IMDSv1, or IMDSv2 with its hop limit), and the identity.
- **Not a finding:** a fetch to a fixed host. Do not assume a reachable metadata service when the configuration is not visible.

### Host or control-plane capability exposure

- **Check:** workloads that can use privileged mode, added capabilities, host namespaces, host paths, device mounts, container runtime sockets, or service-account tokens that cross into node or control-plane authority. Check who can select these settings.
- **Not a finding:** a missing seccomp profile or a writable root filesystem without a reachable operation that crosses the boundary. That is hardening.

### Admission and policy path inconsistency

- **Check:** one deployment route that enforces image identity, namespace, resource, secret, or privilege policy while another controller, job, upgrade, restore, or compatibility path does not. Confirm the alternate route and the object that it deploys.
- **Not a finding:** a policy gap on a path that never deploys.

### Namespace and label trust confusion

- **Check:** network, admission, secret, or workload-identity policy that relies on labels, annotations, names, or namespaces that a less trusted principal can set. Compare who controls the selector with the authority that a match grants.
- **Not a finding:** selectors that only administrators can set.

### Security-control precedence drift

- **Check:** development values, chart defaults, environment variables, command-line flags, feature gates, sidecar injection, or regional overlays that turn off authentication, TLS, tenant scoping, or audit in a deployed environment. Render the final configuration for each maintained environment, not only the base file.
- **Not a finding:** an insecure value in a local-only or test profile that no deployed environment loads.

### Secret exposure across workload boundaries

- **Check:** secrets that reach logs, crash reports, process arguments, shared environment, broad volumes, build output, service discovery, or read APIs that another workload or tenant can reach. Check the secret type and the authority that it grants.
- **Not a finding:** a public endpoint, a key ID, or a publishable key.

### Credential renewal and outage fallback

- **Check:** a failure to mount, refresh, rotate, or revoke a credential that leaves stale credentials active or makes the app fall back to a weaker identity mode. Review startup, readiness, reconnect, and cached-client behavior.
- **Not a finding:** a failure that stops the service (fail closed).

### Object storage and signed-URL policy

- **Check:** bucket or container policies, object keys, CDN origins, and signed URLs that do not bind the principal, operation, object namespace, audience, or expiry. Review list, version, and write operations as well as reads.
- **Not a finding:** a public bucket that holds intentionally public assets.

### Event-source identity confusion

- **Check:** functions or workers that trust body fields as the event source without a check of the provider-signed envelope, subscription or topic, account, region, and replay state. Compare push, pull, retry, and dead-letter paths.
- **Not a finding:** events from a source that only the platform can write, when the binding is visible.

### Edge and runtime boundary mismatch

- **Check:** edge or serverless code that assumes a secret, API, filesystem, isolation, or tenant policy that differs from the origin runtime. Check whether a fallback to the origin changes authority or cache behavior.
- **Not a finding:** a difference that changes no authority and no cached content.

## Universal moves

- Render every maintained environment. Build a matrix of external ports, workload identities, network peers, mounted secrets, and cloud resources. Ask why each difference exists.
- Follow a lower-trust request, object, label, or event into cloud policy. Show which workload credential performs the final operation and which condition should scope it.
- Compare normal deploys with migration, restore, node maintenance, failover, and local or emulator paths. Check the behavior when the mesh, admission, identity, secret, or policy service is down.

## Validation rules

1. Establish the active source path and the effective deployed object. Otherwise use `needs_validation` and name the missing rendered manifest or owner-observed attachment.
2. Name the lower-trust caller or workload, the cloud or application identity, the controllable selector, the affected resource, and the unauthorized operation or disclosure.
3. Check the provider and orchestrator defaults at the pinned version. Do not assume a public IP, a reachable metadata service, a permissive firewall, or a missing admission controller.
4. A local check renders templates, evaluates policy, or inspects a fixture with dummy identities. Never probe live endpoints or change shared cloud resources.
5. A confirmed claim needs a complete active source trace and a concrete boundary result. Otherwise report `needs_validation` with the exact policy, identity attachment, overlay, network, or drift fact to check.

## Sources

- `third_party/security-audit-skill/skills/security-audit/CLOUD-AND-DEPLOYMENT.md`, from cloudflare/security-audit-skill at commit `c1c8a8c` (MIT License, Copyright (c) 2025-2026 Cloudflare, Inc.).
- kalkan condensed and rewrote the text, adapted it to the kalkan verdict model, and removed the agent-orchestration instructions.
