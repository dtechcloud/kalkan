---
slug: mobile-desktop-ipc
title_en: Mobile / desktop / local IPC
title_tr: Mobil / masaüstü / yerel IPC
cwe: CWE-926, CWE-927, CWE-749, CWE-427
owasp: A01:2021
sources: security-audit-skill, deepsec, open-code-review
---

## Summary

A native app or a local process trusts a caller that it should not trust. The caller is another app, a web page in a webview, a link, another OS user or a lower-privilege process. Look at exported components, deep links, webview bridges, local inter-process communication (IPC) endpoints and privileged helpers. Always state the attacker's starting position and the OS or app boundary that the attack crosses.

## What it is

- **Exported components (CWE-926).** An Android activity, service, receiver or provider is exported without a permission and does work that only the app should do.
- **Intent redirection (CWE-927).** The app starts an intent that it read from another app's extras, or it gives out a mutable `PendingIntent` with an implicit intent.
- **Deep links and URL schemes.** A link changes state, imports data, completes a login or selects an account without a current session and a one-time binding. Another app can register the same custom scheme.
- **Webview bridges (CWE-749).** `addJavascriptInterface`, `WKScriptMessageHandler` or an Electron preload gives remote content native functions, files or tokens. The origin check runs only at the first load, or it compares a string prefix. File or universal access lets a remote page read app files.
- **Electron settings.** `nodeIntegration: true`, `contextIsolation: false` or `sandbox: false` on a window with remote content. `ipcMain` handlers without a sender check. `shell.openExternal` with an untrusted URL.
- **Local IPC without peer checks.** Unix sockets, named pipes, XPC, Binder, D-Bus, native messaging hosts and loopback HTTP or WebSocket servers accept any local peer. Or a request field, not the OS peer identity, selects the user.
- **Privileged helpers.** A setuid binary, Windows service, macOS helper tool or polkit action runs an operation that a low-privilege caller selects. Installers and updaters read scripts or follow symlinks in paths that a lower-trust user can write.
- **Library search order (CWE-427).** A privileged process loads a DLL, shared library or plugin from a directory that a lower-trust user can write.
- **Local secrets across a boundary.** Tokens in world-readable files, shared storage, broad keychain classes or shared app-group containers.

## What it is not

- API keys or secrets compiled into the app → `hardcoded-secrets`.
- Cleartext traffic, App Transport Security exceptions, disabled certificate checks → `crypto`.
- XSS in the app's own web content → `xss`, with the bridge as the impact. Remote origins that reach the bridge stay here.
- Memory corruption in a native parser → `memory-safety`. Unsigned updates or plugins → `supply-chain-cicd`.
- Server-side checks behind the app's API → `authn`, `missing-authz`, `idor`. OAuth redirects and PKCE → `oauth-oidc-saml`.
- Path traversal in an exported provider's `openFile` → `path-traversal`, with the export as the entry point.
- Missing root detection, obfuscation or certificate pinning on the user's own device → not a finding.

## Where to look

List every process, component, URL scheme, webview origin, local endpoint and helper. For each one, note its OS identity, who can call it and what it can do.

### Android
- The merged `AndroidManifest.xml` of each build variant: `android:exported`, intent filters, `android:permission` and its `protectionLevel`, `grantUriPermissions`, `FileProvider` paths (`<root-path>` is broad). With `targetSdkVersion` below 31, an intent filter exports a component by default.
- `getIntent()` extras passed to `startActivity`, `PendingIntent` flags, receivers registered with `RECEIVER_EXPORTED`.
- `WebView`: `setJavaScriptEnabled`, `addJavascriptInterface`, `setAllowFileAccess`, `setAllowUniversalAccessFromFileURLs`, host checks in `shouldOverrideUrlLoading`.

### iOS and macOS
- `CFBundleURLTypes`, `application(_:open:options:)`, `scene(_:openURLContexts:)`, universal links and `apple-app-site-association`.
- `WKWebView` message handlers: they must check `frameInfo.isMainFrame` and `securityOrigin`. `loadHTMLString(_:baseURL:)` with a file URL.
- Keychain `kSecAttrAccessible` values and access groups, app-group containers.
- `NSXPCListener` delegates: `shouldAcceptNewConnection` must check the peer's code signature (`setCodeSigningRequirement` or the audit token).

### Electron and Tauri
- `BrowserWindow` `webPreferences`, the `preload` script, `contextBridge.exposeInMainWorld`.
- `ipcMain.handle` and `ipcMain.on` handlers that read files, run commands or open URLs. Check `event.senderFrame`.
- `will-navigate`, `setWindowOpenHandler`, `protocol.handle` path joins, `shell.openExternal`.
- Tauri capabilities and scopes (`fs`, `shell`), and input checks in `#[tauri::command]` functions.

### Local daemons and IPC (Go, C, Rust, .NET)
- Unix sockets: the directory and mode, the umask, `SO_PEERCRED` or `getpeereid`. An abstract-namespace socket has no file permissions.
- Windows named pipes: the security descriptor (a NULL descriptor gives the default DACL), and how the server identifies the client.
- Loopback HTTP and WebSocket servers: an auth token, `Host` and `Origin` checks against DNS rebinding and cross-site requests.
- D-Bus services and polkit rules, native messaging manifests (`allowed_origins`), sudoers entries with wildcards.

## Safe patterns

- Android: `exported="false"` unless another app must call the component. Signature-level permissions for app-family IPC, explicit intents, `FLAG_IMMUTABLE`, narrow `FileProvider` paths.
- Webviews: load only bundled or allowlisted HTTPS origins (exact scheme and host), give remote content no bridge, turn off file access.
- iOS: check the URL parts, and ask the user before a state-changing deep link. Store tokens with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`.
- Electron: `contextIsolation: true`, `sandbox: true`, `nodeIntegration: false`. Expose narrow functions through `contextBridge`, check the sender in every IPC handler, and open only allowlisted `https:` URLs.
- Local IPC: identify the peer with OS credentials (peer UID, client token, audit token and code signature). Use mode 0600 sockets in a 0700 directory. Authorize each method against the peer.
- Loopback servers: a random per-session token, plus `Host` and `Origin` checks.
- Helpers: allowlist operations, use normalized absolute paths and `O_NOFOLLOW`, and load libraries only from protected directories.

## Weak mitigations

- A caller check on a package name, bundle ID, process name or path that the message carries.
- URL checks with `startsWith` or `contains`: `https://app.example.com.attacker.test` passes.
- An origin check at the first load only, not after redirects or navigation.
- A custom Android permission with `normal` protection level. Any app can request it.
- "Only localhost can connect." Every local user, and every web page through the browser, can reach a loopback port.
- A loopback token in a world-readable file.

## Verification checklist

- **attacker_control:** State the attacker's starting position: another installed app, a web page in the webview or the browser, a link that the victim opens, another local OS user, a sandboxed process. Quote the entry: the manifest element, URL handler, bridge registration or listener.
- **privilege_boundary:** Name the crossed boundary and the gained operation: app-private data, actions as the user, code in the app or the helper, root or SYSTEM. The same user acting on their own app or device refutes it.
- **unmitigated:** Quote the missing peer check, permission, origin check or confirmation, or the broad setting.
- Read the effective configuration: merged manifest, `targetSdkVersion`, entitlements, Electron version. Electron isolates the context by default since version 12, and sandboxes renderers since version 20.
- Signing, entitlements, OS version, installer ACLs and device policy are often outside the repository. Then the result is `needs_validation`.

## Examples

### Android
```kotlin
// Vulnerable: an exported deep-link activity loads any URL and gives it the session
val url = intent.data?.getQueryParameter("url") ?: return
webView.settings.javaScriptEnabled = true
webView.addJavascriptInterface(SessionBridge(session), "Native")
webView.loadUrl(url)

// Secure: exact host check, and no bridge for remote pages
val target = intent.data?.getQueryParameter("url")?.let(Uri::parse) ?: return
if (target.scheme == "https" && target.host == "app.example.com") {
    webView.loadUrl(target.toString())
}
```

### Electron and Tauri
```js
// Vulnerable: remote content with Node access, and any frame can run commands
const win = new BrowserWindow({ webPreferences: { nodeIntegration: true, contextIsolation: false } });
win.loadURL(remoteUrl);
ipcMain.handle("run", (_event, cmd) => execSync(cmd));

// Secure: isolated renderer, a narrow action, and a sender check
const win = new BrowserWindow({ webPreferences: { preload, contextIsolation: true, sandbox: true } });
ipcMain.handle("export-report", (event, id) => {
  const u = new URL(event.senderFrame.url);
  if (u.protocol !== "app:" || u.host !== "bundle") throw new Error("denied");
  return exportReport(String(id));
});
```

### Local daemons and IPC (Go, C, Rust, .NET)
```go
// Vulnerable: a world-writable directory and mode 0777, so any local user can call
l, _ := net.Listen("unix", "/tmp/agent.sock")
os.Chmod("/tmp/agent.sock", 0o777)

// Secure: a 0700 directory of the service user, and a SO_PEERCRED UID check per connection
l, _ := net.Listen("unix", "/run/agent/agent.sock")
```

## Dynamic test hints

- Use an emulator or a simulator with dummy accounts, never a real device with real data.
- Android: `adb shell am start -a android.intent.action.VIEW -d "myapp://open?url=https://example.test"`. Providers: `adb shell content query --uri content://<authority>/...`.
- iOS simulator: `xcrun simctl openurl booted "myapp://..."`.
- Electron: load a test page from a server on `127.0.0.1` and call the exposed API from it.
- Local IPC: connect as a second, unprivileged test user (or another UID in a container) and call one harmless method.
- Stop at the proof of the boundary. Do not install persistence or change system settings.

## False positive traps

- The merged manifest differs from the source: a library or build variant sets the flag, or `tools:node="remove"` drops the component. Debug-only manifests do not ship.
- The launcher activity must be exported. A component behind a signature permission, or one that does only harmless work, is not a finding.
- The deep link opens a page and changes nothing, or it needs a session and a confirmation.
- The webview loads only bundled assets and blocks navigation.
- The attacker is the same OS user without a sandbox, so that user can already read the same files. Or the attacker already has root or administrator rights.

## Sources

Condensed and rewritten from the local copies under `third_party/`.

- `cloudflare/security-audit-skill@c1c8a8c: skills/security-audit/DESKTOP-MOBILE-AND-LOCAL-IPC.md`, `CLIENT-SIDE.md`, `MEMORY-SAFETY-AND-BINARY.md` (MIT, Cloudflare): deep-link, webview, IPC, exported-component, helper and local-secret classes, library search order, validation rules.
- `vercel-labs/deepsec@4fa6722: packages/scanner/src/matchers/android-manifest-export.ts`, `ios-url-scheme.ts`, `unix-socket-listener.ts`, `packages/processor/src/prompt/highlights.ts`, `slug-notes.ts` (Apache-2.0, Vercel): Android and iOS entry points, socket listener risks.
- `alibaba/open-code-review@11ac6d4: internal/config/rules/rule_docs/swift.md` (Apache-2.0, alibaba/open-code-review contributors): web view, deep link and networking rules.
- Electron and Tauri settings, Android API 31 rules, XPC peer checks and named-pipe DACLs come from general knowledge.
