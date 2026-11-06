---
name: protocols-rpc-and-messaging
title: Protocols, RPC, and messaging
classes: webhook-replay, graphql
when_to_use: The target uses gRPC, GraphQL transports, Protobuf, Thrift, Cap'n Proto, custom binary protocols, streaming RPC, webhooks, brokers, queues, pub/sub, or event buses.
sources: third_party/security-audit-skill/skills/security-audit/PROTOCOLS-RPC-AND-MESSAGING.md, third_party/deepsec/processor/prompt/slug-notes.ts
---

# Protocols, RPC, and messaging

This pack covers peer identity, the meaning of decoded messages, routing, replay, ordering, and delivery semantics. Split a large system by producer and consumer pair, external and internal peer role, synchronous RPC, streaming, and asynchronous message paths. Related packs: `memory-safety-and-binary` (parser memory safety), `web-protocol-and-auth` (HTTP framing), `resource-exhaustion-and-availability` (availability impact).

## Core discipline

- "Internal" is not authentication. Name the peer identity at every hop and show how it becomes the application principal that authorization uses.
- Schema validation proves the message shape, not its origin, resource authority, order, or safe values. Follow decoded fields to policy decisions and side effects.
- Broker guarantees and application guarantees differ. Write down retry, ordering, acknowledgement, deduplication, and transaction behavior before you judge a state change.
- A parser disagreement needs two concrete consumers, schema versions, or wire forms, and one security-relevant value that differs between them.
- Use `needs_validation` when broker ACLs, service-mesh identity, topic attachment, or compatibility behavior outside the repository decides the claim.

## Attack classes

### Message boundary and canonicalization disagreement

- **Check:** components that disagree on length, compression, duplicate fields, unknown fields, encoding, numeric width, normalization, or which of envelope and body wins. Compare generated and custom parsers, gateways, language bindings, and version converters. Confirm which principal, resource, or operation differs after decoding.
- **Not a finding:** a divergence that one side rejects safely, or one that changes no security-relevant value.

### Union, enum, and default confusion

- **Check:** unknown variants, missing discriminators, zero values, default privileges, or compatibility mappings that reach code that assumes a validated case. Review exhaustive dispatch, default branches, and how old consumers read newly added fields.
- **Not a finding:** a default branch that rejects the message.

### Envelope and payload identity mismatch

- **Check:** authorization that uses routing or envelope metadata while the handler acts on a different tenant, account, subject, object, or sender in the body. Find the authoritative source and make sure clients cannot override it.
- **Not a finding:** a handler that takes identity only from the authenticated envelope.

### Interceptor and method-path inconsistency

- **Check:** authentication and authorization interceptors that cover unary methods but not streams, reflection, health checks, gateway-transcoded paths, compatibility services, or individual stream messages. Compare every registration and route to the same operation.
- **Not a finding:** a public health or reflection method that exposes nothing sensitive. Reflection on an internal admin service is still worth a note.

### Peer identity to application-principal confusion

- **Check:** mTLS, workload identity, bearer metadata, forwarded identity, or broker credentials that authenticate a channel while a caller-controlled field selects the user or tenant. Deterministic policy must bind the channel identity to the claimed principal.
- **Not a finding:** a service account that may act for any tenant by design, when the design documents it and the caller is trusted.

### Per-item and streaming authorization gaps

- **Check:** streams, subscriptions, batches, or bulk messages that code authorizes once, while later items name other resources or keep flowing after a role change, membership removal, or token revocation. Check where scope can change and bind subscriptions to their original principal.
- **Not a finding:** a stream whose items all inherit a fixed, authorized resource.

### Callback and reply-correlation confusion

- **Check:** predictable, reused, or cross-tenant correlation IDs that let a response, webhook, cancellation, or acknowledgement satisfy another caller's pending operation. Bind each outstanding request to the authenticated peer, tenant, operation, and lifecycle.
- **Not a finding:** random correlation IDs that code checks against the waiting peer.

### Webhook signature and replay

- **Check:** inbound webhooks that parse or act on the body before signature verification, verify against a re-serialized body instead of the raw bytes, compare signatures with a non-constant-time function, accept unsigned fallback paths, or skip timestamp and event-ID replay checks.
- **Not a finding:** a provider SDK verification call on the raw body before any processing, with a tolerance window and deduplication.

### Topic, routing-key, and subscription scope gaps

- **Check:** publishers or subscribers that can choose another tenant's topic, wildcard, consumer group, partition, reply queue, or dead-letter route. Check broker ACLs where visible and the application code that builds names. Tenant text inside a payload is not isolation.
- **Not a finding:** names built only from server-side identity.

### Dead-letter, retry, and diagnostic disclosure

- **Check:** messages routed to dead-letter queues, error topics, traces, or operator views that carry secrets or cross-tenant payloads to a lower-trust consumer. Review policy and redaction on the failure path, not only on normal delivery.
- **Not a finding:** failure queues that only the owning service can read.

### Untrusted producer treated as control plane

- **Check:** a message body that can declare itself an admin event, provider callback, replication record, or migration instruction without an independently authenticated producer and event type. Verify signatures and source, account, and audience binding before privileged handling.
- **Not a finding:** a privileged event type that only an authenticated internal producer can publish.

### Duplicate delivery and idempotency gaps

- **Check:** retries or redelivery that repeat a side effect because deduplication is absent, runs after the mutation, or uses a key that collides across tenants or operations. Confirm the delivery model and that the side effect is not naturally idempotent.
- **Not a finding:** an idempotent side effect, or a dedup key checked in the same transaction as the mutation.

### Out-of-order and stale message acceptance

- **Check:** older state, revoked membership, canceled work, or pre-step-up authorization that arrives after newer state and overwrites it. Review sequence and version checks, tombstones, partition changes, and replay workflows.
- **Not a finding:** a consumer that rejects messages older than the stored version.

### Acknowledgement, commit, and multi-consumer ordering

- **Check:** acknowledgement before a durable commit (lost security work), commit before an unreliable acknowledgement (duplicated mutation), and multi-consumer transitions that leave only part of an authorization change committed after a failure.
- **Not a finding:** a transactional outbox or inbox that covers the transition.

## Universal moves

- Draw producer, broker or transport, gateway, consumer, and storage for each message family. At each hop, record the authenticated peer, the authoritative tenant and resource fields, the validation, and the side effect.
- Feed the same small fixture to every in-repo schema version or language binding. Try duplicate, missing, unknown, boundary, replayed, and reordered messages without creating load.
- Compare normal, retry, dead-letter, replay, migration, reflection, stream, and gateway-transcoded routes. Security policy must survive transport changes.

## Validation rules

1. Name the realistic producer or peer, the accepted message, the authenticated channel identity, the affected principal or resource, and the unauthorized change or disclosure.
2. For a disagreement claim, cite both parsers or consumers and the decoded value that differs. A safe rejection on either side refutes confirmation.
3. For replay and ordering claims, establish the actual delivery guarantees. A PoC uses an in-memory transport and a bounded message sequence.
4. For authorization and isolation, check every interceptor, broker ACL, gateway, and consumer layer visible in source. External attachments make the candidate `needs_validation`.
5. A confirmed claim needs the complete message lifecycle and a meaningful result. Otherwise report `needs_validation` with the exact broker, service identity, route, or delivery fact.

## Sources

- `third_party/security-audit-skill/skills/security-audit/PROTOCOLS-RPC-AND-MESSAGING.md`, from cloudflare/security-audit-skill at commit `c1c8a8c` (MIT License, Copyright (c) 2025-2026 Cloudflare, Inc.).
- `third_party/deepsec/processor/prompt/slug-notes.ts` (webhook-handler note), from vercel-labs/deepsec at commit `4fa6722` (Apache-2.0, Copyright 2026 Vercel, Inc. and contributors).
- kalkan condensed and rewrote the text, adapted it to the kalkan verdict model, added the webhook class, and removed the agent-orchestration instructions.
