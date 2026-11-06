---
name: desktop-mobile-and-local-ipc
title: Desktop, mobile, and local IPC
classes: mobile-desktop-ipc
when_to_use: The target is a desktop or mobile app, a privileged helper, an updater, a local daemon, a webview host, a deep-link handler, or a local IPC client or server.
sources: third_party/security-audit-skill/skills/security-audit/DESKTOP-MOBILE-AND-LOCAL-IPC.md
---

# Desktop, mobile, and local IPC

The untrusted actor can be a downloaded document, remote web content, another local app, another OS user, a sandboxed process, or a lower-privilege account. State that starting capability instead of treating all local users as equal. Related packs: `client-side` (the browser side of a webview), `memory-safety-and-binary` (native memory and loaders), `supply-chain-and-release` (update authenticity).

## Core discipline

- Establish the realistic attacker: another app, another OS user, a sandboxed child, an untrusted document, or a remote origin. Harm to yourself within the same account and authority is not a boundary violation.
- Paths, process names, bundle or package IDs, and sender fields that a caller declares do not authenticate a peer. Use OS peer credentials, code identity, capability handles, or protected channel state.
- A native bridge or helper must authorize each operation and the final resource after parsing. A trusted UI or broker does not make attacker-influenced arguments trusted.
- OS sandboxes, code signing, entitlements, permissions, keychain ACLs, exported-component policy, and consent prompts are real controls when they are pinned and visible.
- Use `needs_validation` when signing, manifest merging, OS version, device policy, installer ACLs, or packaging decides the claim and the repository does not show it.

## Attack classes

### Custom-scheme and deep-link ambiguity

- **Check:** routes that another app or page can invoke to change state, import data, complete authentication, or select an account without a binding to the current session and a one-time callback value. Review URI normalization, duplicate query fields, scheme, host, and path matching, exported handler policy, and stale or replayed links.
- **Not a finding:** a deep link that only opens a read-only screen with public content.

### App and account hand-off confusion

- **Check:** OAuth, SSO, magic-link, invite, device-pairing, passwordless, or payment callbacks that return to the wrong installed app, profile, tenant, or pending transaction. State must bind to the initiating app identity, the current session, the account, the provider, the operation, and an expiry.
- **Not a finding:** a callback that verifies a session-bound state value before it acts.

### File-open and intent authority confusion

- **Check:** associated files, share intents, drag-and-drop items, clipboard records, notification actions, or open-file events that trigger a privileged operation without checks of content type, sender trust, current user intent, and the final target.
- **Not a finding:** an import that asks the user to confirm and runs with the user's own authority.

### Navigation-origin to bridge confusion

- **Check:** remote or attacker-controlled frames that can reach a JavaScript-to-native bridge meant only for packaged content. The origin check must run at call time and after every navigation, redirect, subframe creation, popup, and error page.
- **Not a finding:** a bridge that checks the exact origin at each call. A URL-prefix check or an initial-load check is not enough to refute the claim.

### Over-broad native bridge capabilities

- **Check:** a generic bridge that lets web content choose arbitrary files, commands, IPC methods, credentials, or system actions. Check method allowlists, normalized arguments, user and tenant authority, gesture or confirmation requirements, and what return values disclose.
- **Not a finding:** a narrow bridge method with fixed arguments.

### Webview file and universal access

- **Check:** settings that let remote content read app-local files, privileged custom schemes, or internal origins: file access, universal access from file URLs, mixed content, debug interfaces, and custom protocol handlers.
- **Not a finding:** a permissive setting without reachable protected content. Report it as a hardening note.

### IPC peer-authentication gaps

- **Check:** Unix sockets, named pipes, XPC, Binder, D-Bus, native messaging, RPC, shared memory, or loopback listeners that accept a lower-trust peer without checks of OS credentials, code identity, sandbox token, or channel ownership. A meaningful method or disclosure must sit behind the channel.
- **Not a finding:** a channel that only the same user can open and that grants nothing beyond that user's authority.

### Claimed principal versus channel identity

- **Check:** request fields that select another user, tenant, profile, or capability than the authenticated process or channel. Bind each method and resource to the peer credential, not to an identifier the caller declares.
- **Not a finding:** a field that the server checks against the peer credential.

### Exported service, activity, receiver, or provider overreach

- **Check:** mobile components or local automation endpoints that other apps can invoke and that perform operations meant for the app itself. Review the final merged manifest, intent filters, permission or signature level, path grants, and alternate aliases.
- **Not a finding:** a component protected by a signature-level permission. When the merged manifest is unknown, use `needs_validation`.

### IPC lifecycle and correlation confusion

- **Check:** predictable request IDs, reused handles, stale channels, inherited descriptors, world-writable socket paths, or restart behavior that lets one peer answer, cancel, or reuse another peer's operation. Review creation permissions and cleanup of socket files, locks, ports, and shared mappings.
- **Not a finding:** correlation IDs that are random and bound to the peer.

### Privileged helper as a confused deputy

- **Check:** a low-privilege caller that can choose a privileged command, file, service, user, or system setting without per-operation authorization. Review sudo, polkit, UAC, and XPC helper rules. The helper must validate normalized arguments itself.
- **Not a finding:** a helper that exposes one fixed operation with no caller-chosen target.

### Install, update, and repair path trust

- **Check:** a privileged installer or helper that reads manifests, scripts, packages, symlinks, working directories, or repair state that a lower-trust actor can write after authorization. Authorization must bind to immutable content and safe destination paths.
- **Not a finding:** inputs in directories that only administrators can write.

### Local file ownership and TOCTOU

- **Check:** code that checks a file or path and then follows a replacement, symlink, mount, or case or normalization change during a privileged read or write. Prefer descriptor-relative operations and a check of the final owner.
- **Not a finding:** paths whose every directory only the same privileged user can write.

### Credential-store and local-secret boundary mismatch

- **Check:** keychain or keystore items, token files, backups, logs, clipboard data, notification previews, or local configuration that another app, profile, or user with less authority can read. State the lower-trust reader and the power of the credential.
- **Not a finding:** plaintext that only the intended OS account can read.

### Account switch, logout, and device restore leakage

- **Check:** cached data, background tasks, widgets, notifications, local databases, webview storage, or biometric approvals that survive logout or an account change and appear under a later account. Review backup, restore, and multi-profile behavior.
- **Not a finding:** data that stays within one account across its own sessions.

### Pending-action and user-presence confusion

- **Check:** notifications, widgets, shortcuts, share sheets, biometric prompts, or deferred operations that authorize a different action than the one shown, run after expiry, or use another profile's pending state. Bind confirmation to the normalized action, the resource, the account, and the current foreground state.
- **Not a finding:** a prompt that shows and binds the exact action.

## Universal moves

- List every process, app component, local endpoint, URI scheme, file association, webview origin, and helper. Record the OS identity, the runtime privilege, the caller, and the callable operation.
- Read the final packaging inputs: merged manifests, entitlements, installer rules, native-messaging registrations, protocol handlers, and ACL creation. Later build steps can overwrite source declarations.
- A PoC uses dummy profiles and non-sensitive local fixtures on an isolated machine or emulator. Never touch other users' apps, credentials, or production services.

## Validation rules

1. Name the attacker's starting capability, the OS or app principal that is crossed, the entry channel, the accepted argument or state, and the unauthorized operation or disclosure.
2. Check the OS sandbox, peer credential, signing, entitlement, permission, consent, and installer controls that apply. Unknown packaging or runtime facts require `needs_validation`.
3. For a webview bridge, cite both the navigation or origin control and the privileged native sink. For IPC, cite peer authentication and per-resource authorization. For a helper, check the final normalized destination.
4. Keep local checks bounded and use dummy content and accounts. Stop after the boundary result and do not extend the proof into persistence or wider system changes.
5. A confirmed claim needs a complete source chain. Otherwise report `needs_validation` with the exact OS, manifest, signing, ACL, or device-lifecycle fact.

## Sources

- `third_party/security-audit-skill/skills/security-audit/DESKTOP-MOBILE-AND-LOCAL-IPC.md`, from cloudflare/security-audit-skill at commit `c1c8a8c` (MIT License, Copyright (c) 2025-2026 Cloudflare, Inc.).
- kalkan condensed and rewrote the text, adapted it to the kalkan verdict model, and removed the agent-orchestration instructions.
