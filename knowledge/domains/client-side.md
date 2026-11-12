---
name: client-side
title: Client-side and browser code
classes: xss, prototype-pollution, cors, open-redirect, csrf
when_to_use: Trust decisions or untrusted rendering happen in a browser, an extension, a webview, or a service worker.
sources: third_party/security-audit-skill/skills/security-audit/CLIENT-SIDE.md
---

# Client-side and browser code

Use this pack for single-page apps, browser extensions, embedded webviews, service workers, offline apps, and any code that renders attacker-influenced content into the DOM, receives cross-window messages, or uses browser storage. Some sources here never reach the server: URL fragments, `window.name`, `postMessage` data, and cached content. Related packs: `web-protocol-and-auth` (server-side CSRF, sessions, callbacks) and `desktop-mobile-and-local-ipc` (the native side of a webview bridge).

## Core discipline

- A client-side candidate needs a controllable source and a sink that executes or discloses. Name both and show the data flow between them.
- The impact must reach a victim's session, another origin, or shared persistence. Self-injection and disclosure of the attacker's own data are not findings.
- Framework escaping, the same-origin policy, CSP, COOP and CORP, service-worker scope, and modern `noopener` defaults are real controls. Check them before you assign impact.
- Browser storage and caches are shared per origin and can outlive a login. For each record, find the writer, the reader, and the lifecycle event that clears it (logout, account switch, tenant change, worker update).
- Use `needs_validation` when the result depends on renderer behavior, extension permissions, deployed headers, or browser policy that the repository does not show.

## Attack classes

### DOM-based XSS

- **Check:** flows from `location` fields, `document.referrer`, `window.name`, message data, storage, and other browser state into `innerHTML`, `outerHTML`, `document.write`, string-evaluating APIs (`eval`, `setTimeout` with a string), executable URLs, jQuery HTML methods, or framework escape hatches (`dangerouslySetInnerHTML`, `v-html`, `bypassSecurityTrust*`).
- **Not a finding:** interpolation that the framework escapes.

### DOM clobbering

- **Check:** injected `id` or `name` attributes that shadow a global, a form property, a configuration object, or an initialization flag that code later trusts. Prove both a markup path that keeps the attribute (for example a sanitizer that allows `id`) and a security-relevant use of the shadowed value.
- **Not a finding:** clobberable markup without a security-relevant reader.

### Prototype pollution with a gadget

- **Check:** an attacker-controlled key (`__proto__`, `constructor.prototype`) that reaches a recursive write such as a deep merge or a path setter, and then a reachable gadget that reads the polluted property to change authorization, execution, navigation, or rendering.
- **Not a finding:** `JSON.parse` alone, a shallow copy, or pollution without a gadget.

### postMessage origin and source trust

- **Check:** message handlers that act on `event.data` without an exact origin allowlist and, when several frames share an origin, without a check of `event.source`. On the sending side, check sensitive data sent with the target origin `*`.
- **Not a finding:** a handler that only displays non-sensitive data. A substring, prefix, suffix, or unanchored-regex origin test is not an origin check and does not refute the claim.

### Cross-site WebSocket hijacking

- **Check:** a WebSocket upgrade that accepts ambient cookies from any origin without an `Origin` check or a channel token, plus a message handler that reads or changes data.
- **Not a finding:** a socket that authenticates with a non-ambient token in the first message.

### Credentialed CORS

- **Check:** a server that reflects or loosely matches `Origin`, allows credentials, and returns sensitive data or accepts a state change.
- **Not a finding:** a bare `*` together with credentials (browsers refuse it), or `*` on public data without credentials.

### Service-worker registration and scope takeover

- **Check:** whether attacker-influenced content can become the registered worker script, control a path that receives a broad `Service-Worker-Allowed` scope, or change imported scripts without integrity control. Check the final script URL, MIME type, origin, and scope.
- **Not a finding:** a same-origin worker with its intended scope.

### Service-worker cache and identity confusion

- **Check:** a worker that caches personalized responses without account, tenant, or authorization state in its key, and then serves them after logout or account switch. Review fetch routing, cache names, navigation fallbacks, cleanup, and offline error paths.
- **Not a finding:** caching of public, non-personalized assets.

### Browser-storage disclosure and stale authorization

- **Check:** tokens, private responses, drafts, or authorization decisions in `localStorage`, `sessionStorage`, IndexedDB, Cache Storage, extension storage, or client state that another account or a less trusted same-origin component can read, or that keep working after logout or revocation.
- **Not a finding:** a stored token alone. Name a realistic reader with less authority.

### Cross-context storage and broadcast confusion

- **Check:** `storage` events, `BroadcastChannel`, shared workers, or origin-wide caches that carry identity or commands between tabs without a binding to the current session. Check account switching, private windows, tenant changes, and stale tabs that overwrite newer auth state.
- **Not a finding:** a broadcast of non-sensitive UI state.

### XS-Leaks and cross-origin state oracles

- **Check:** an attacker page that can tell protected cross-origin state apart through load or error events, frame counts, redirects, timing, cache state, or response size while the browser sends the victim's credentials. Name one concrete secret predicate (for example "a private project with this name exists").
- **Not a finding:** generic timing variance or the availability of public resources.

### Window and opener state

- **Check:** cross-origin window metadata or navigation results that reveal protected state, and kept opener or named-window links that let an attacker page steer a privileged navigation. Check COOP, frame protection, and `noopener`.
- **Not a finding:** reverse tabnabbing in browsers that give links an implicit `noopener`, unless the code keeps `window.opener` on purpose.

### Clickjacking

- **Check:** a framed, state-changing action without an effective `frame-ancestors` directive, `X-Frame-Options` header, or equivalent isolation. Confirm that the action can complete in the framed state.
- **Not a finding:** a missing header on read-only content. Report it as a hardening note.

### Client-side navigation confusion

- **Check:** a client source that controls a redirect or navigation without a scheme and destination policy, including `javascript:` and `data:` destinations.
- **Not a finding:** navigation to a fixed or allowlisted destination.

## Universal moves

- Start from DOM, navigation, worker, message, and storage sinks. Trace back to browser-only and server-controlled sources. Record the browser policy that should stop each path.
- Walk through account switch, logout, worker update, offline fallback, and stale tabs in the source. A PoC uses a local test origin and dummy accounts, never production users or origins.
- For XS-Leaks, list only the predicates that source and local browser behavior prove. Then name the header or rendering change that removes the oracle.

## Validation rules

1. Cite the source, the sink, the browser policy, the affected origin or session, and the observable change or disclosure.
2. For prototype pollution, prove the recursive write and a security-relevant gadget. For DOM clobbering, prove that the markup survives and that code uses the shadowed value.
3. For service workers and storage, prove the lifecycle path: an attacker-controlled write or cache entry must reach another account, another tenant, or a later authorization state.
4. For messaging, CORS, WebSocket, and XS-Leaks, show the exact origin or source check and the protected state or action. Confirm that CSP, COOP, CORP, cookie attributes, and SameSite do not already block the attack.
5. A confirmed claim needs a complete client path. Otherwise report `needs_validation` with the exact deployed header, extension permission, browser version, or renderer behavior that an owner must check.

## Sources

- `third_party/security-audit-skill/skills/security-audit/CLIENT-SIDE.md`, from cloudflare/security-audit-skill at commit `c1c8a8c` (MIT License, Copyright (c) 2025-2026 Cloudflare, Inc.).
- kalkan condensed and rewrote the text, adapted it to the kalkan verdict model, and removed the agent-orchestration instructions.
