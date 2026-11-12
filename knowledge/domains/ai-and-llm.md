---
name: ai-and-llm
title: AI, LLM, and agent systems
classes: llm-ai
when_to_use: A language model reads untrusted content, calls tools, keeps memory, talks to MCP peers, or feeds its output to a sink.
sources: third_party/security-audit-skill/skills/security-audit/AI-AND-LLM.md
---

# AI, LLM, and agent systems

Follow the flow from untrusted content, through the model or its memory, to a capability, an authority, or a sink. The ordinary classes (access control, injection, rendering) still apply at every hop. Related pack: `client-side` (model output in a browser).

## Core discipline

- Prompt injection alone is not a finding. Show a code-level failure: the content reaches another principal's context, uses authority the requester lacks, discloses data the requester cannot read, or drives a sink the requester cannot reach directly.
- Treat model output, memory records, tool descriptions, and MCP responses as untrusted input. Point to the code that grants authority, trusts the output, writes durable state, or feeds a sink.
- A guardrail prompt is not a security control. Count only deterministic controls: resource-scoped authorization, isolation, binding, and narrowly scoped credentials.
- Name the attacker, the affected principal, the execution identity, the resource, the action, the authority used, and the result. A user who asks the model to use the user's own authority is not a delegation defect.
- Authorization and action binding are separate controls. When attacker content makes the system act under a victim's valid authority, and the victim did not request or approve that exact action, the binding failed.
- Use `needs_validation` when the decision depends on provider, model, renderer, deployment, or identity behavior that the repository does not show.

## Attack classes

### Indirect injection through retrieved or ingested content

- **Check:** who can write each source that enters a model context (RAG documents, indexed pages, files, email, issues, tool responses, metadata), how retrieval scopes it, whose session reads it, and which capability that session holds. Check isolation, resource authorization, and binding to the reader's intent as three separate controls.
- **Not a finding:** persuasive text by itself. The defect is the missing deterministic control.

### Cross-session or cross-tenant context bleed

- **Check:** the keys of conversation history, embeddings, retrieval results, and prompt caches. The tenant and ACL filter must be in the query itself and in every cache key. Look for alternate queries, shared caches, and batch paths that omit the filter.
- **Not a finding:** a tenant field that a record merely stores. Storage is not enforcement, so find the query that uses it.

### Persistent memory poisoning

- **Check:** who can create, update, merge, and delete memory, and the provenance and tenant scope of each record. Look for low-trust observations or model summaries that become durable instructions or facts for another task, user, or privileged session.
- **Not a finding:** memory that a user saved on purpose and that serves only that user's own allowed requests.

### Prompt role and provenance confusion

- **Check:** prompt assembly that lets untrusted text pose as a system message, an earlier turn, a tool result, a policy, or a memory record. Look for string concatenation, untyped history, caller-controlled role fields, and serialization round trips that lose source labels.
- **Not a finding:** a forged label that changes no deterministic trust decision and reaches no meaningful capability.

### Tool-argument injection into a downstream sink

- **Check:** each field of a model-produced tool call, from the decoded arguments to SQL, shell, file, URL-fetch, or privileged API sinks. Treat the tool schema as input parsing. A schema narrows the shape of a value but does not authorize it or make it safe for the sink.
- **Not a finding:** a field that the handler validates, scopes, and parameterizes before the sink. When the sink is ordinary, report the ordinary class (for example `sqli` or `ssrf`).

### Excessive agency and confused-deputy authority

- **Check:** the effective identity of each tool call. Look for service identities or broad credentials where the handler does not re-check the requesting principal's permission on the named resource. Confirm that the attacker cannot do the same operation through the normal product interface.
- **Not a finding:** a shared credential when the code enforces a per-user query scope.

### Action confirmation and approval binding

- **Check:** whether an approval binds the normalized tool name, the full argument object, the requester, the target, the amount, the expiry, and batch membership. Check retries and resumed sessions: one approval must not authorize a changed or duplicated side effect.
- **Not a finding:** an action that the principal requested on purpose and that the handler authorizes.

### Tool-schema and dispatcher disagreement

- **Check:** aliases, extra fields, duplicate keys, type coercion, nested free-form objects, and out-of-range values that the schema accepts but the dispatcher or handler reads differently. Validation must run again where a value becomes a resource selector or a security option.
- **Not a finding:** a difference that changes no resource, principal, or security option.

### Unbounded delegated action loops

- **Check:** a bounded request that can queue repeated spend, messages, mutations, or external API calls without a per-request budget, per-action authorization, cancellation, or idempotency key. Establish the effect on shared cost, quotas, other users, or durable state from code.
- **Not a finding:** heavy work that stays inside the requester's own budget. Never test by exhausting a service.

### Sub-agent and MCP trust inheritance

- **Check:** the principal, tenant, credentials, memory, and capabilities that pass into each delegated call. Look for a full-session hand-off where less authority would do. Check the credential audience and whether returned results stay untrusted.
- **Not a finding:** delegation that narrows capability to the task and treats returned data as untrusted.

### MCP server and tool identity confusion

- **Check:** routing of calls and results by names, request IDs, resource URIs, or model-selected aliases that an attacker can influence, instead of by the authenticated connection and the outstanding request. Check whether two servers can claim one tool, whether a reconnect changes the binding, and whether one server's response can satisfy another server's pending call.
- **Not a finding:** routing that is bound to the authenticated connection and to request correlation.

### MCP metadata and schema as policy

- **Check:** tool descriptions, resource metadata, prompts, completion hints, or schemas from an MCP peer that the code trusts as policy or authorization. Find the deterministic allowlist, server identity check, and handler authorization that stay in force when the metadata disagrees.
- **Not a finding:** metadata that only guides the model while deterministic checks decide.

### Insecure output rendering

- **Check:** model output that reaches an HTML, Markdown, template, URL, or command sink without the encoding and policy that the sink needs. For browser rendering, check auto-loaded resources (images, links) and CSP or sanitization.
- **Not a finding:** output that an escaping framework renders as text. Renderer behavior outside the repository makes the candidate `needs_validation`.

### Sensitive context extraction

- **Check:** prompt assembly and data fetches that put credentials, other users' data, private source, or access-granting policy values into a context whose output the user can influence.
- **Not a finding:** disclosure of generic instructions or system-prompt text that crosses no data boundary.

## Universal moves

- Draw four maps first: execution identities, capabilities, writable context and memory sources, and output destinations. Then connect the starting principal to the final authority.
- Start at side-effecting tools and walk back through the dispatcher, schema, confirmation, model context, retrieval, and ingestion. Start at durable memory reads and trace every writer.
- Compare direct, queued, retried, resumed, batched, and delegated paths for one action. The strongest gate must run after the arguments are final and before every side effect.

## Validation rules

1. Name the crossed boundary and the observable result: attacker, affected principal or shared resource, execution identity, target, and the unauthorized or unrequested action or disclosure.
2. For a confused-deputy claim, show that the tool lacks requester-and-resource authorization and that the attacker cannot do the same action normally. For an action-binding claim, show that attacker content caused an action under the victim's authority that the victim did not request or approve. Valid generic authorization does not prove intent.
3. For a memory or retrieval claim, cite both the attacker-controlled write and the later cross-principal read or privileged decision. A shared record without a reachable consumer is not enough.
4. For action binding, compare the approved object with the object that the handler uses. For schema disagreement, compare the validated object with the handler's object.
5. For MCP identity, check the authenticated connection, request correlation, tool namespace, and effective credential. Use `needs_validation` when external server identity or deployment routing decides the claim.
6. A confirmed claim needs a complete source trace and a meaningful result. Otherwise report `needs_validation` with the unresolved fact and a bounded check. A local check uses a mocked model and dummy tools, never a live provider.

## Sources

- `third_party/security-audit-skill/skills/security-audit/AI-AND-LLM.md`, from cloudflare/security-audit-skill at commit `c1c8a8c` (MIT License, Copyright (c) 2025-2026 Cloudflare, Inc.).
- kalkan condensed and rewrote the text, adapted it to the kalkan verdict model, and removed the agent-orchestration instructions.
