---
slug: ssrf
title_en: Server-side request forgery
title_tr: Server-side request forgery (SSRF)
cwe: CWE-918, CWE-441
owasp: A10:2021
sources: sast-skills, codecrucible, deepsec, security-audit-skill
---

## Summary

The attacker controls or influences the destination of a request the server makes. The server then reaches a target the attacker cannot reach directly: the cloud metadata endpoint, `localhost`, an internal service, or an internal network. The core shape is user input reaching the destination argument of an outbound call with no effective allowlist.

## What it is

- **Full URL control.** `requests.get(user_url)`, `fetch(req.body.url)`, `http.Get(target)`. The worst case.
- **Host or part control.** The user controls the host, the port, or the path under a fixed host.
- **Feature-driven fetch.** A webhook test, an import-from-URL, a link preview, an image proxy, a PDF or screenshot renderer that follows `<img src>`.
- **DNS / raw socket.** `socket.connect((host, port))`, `net.Dial("tcp", addr)`, a DNS lookup on a user hostname.
- **Shell-out.** `curl` or `wget` run with a user target.
- **Stored destination.** A webhook URL saved from user input with no allowlist, used later for a request.
- **Blind SSRF.** The response is not returned, but timing or a side effect confirms the request. Still a finding.

## What it is not

- A browser redirect (HTTP 302) to a user URL → `open-redirect`.
- A user URL rendered in an `<a>` without escaping → `xss`.
- An XML parser that resolves an external entity to an internal URL → `xxe` (SSRF via XXE stays in `xxe`).
- A user file path for a local read, with no network call → `path-traversal`.
- A fully hardcoded outbound URL with no user influence → not this class.

## Where to look

Flag an outbound call whose destination is dynamic. Then trace the destination to a user source and check for an allowlist.

### Python
- `requests.get/post`, `urllib.request.urlopen`, `httpx.get`, `aiohttp ClientSession().get`, `socket.connect`, `dns.resolver.resolve`.

### JavaScript/TypeScript
- `fetch(url)`, `axios.get(url)`, `http.get`/`https.request`, `got`, `superagent`, `node-fetch`, `net.createConnection`, `dns.lookup`.
- Watch redirect following: `axios` and `got` follow by default, so an allowed host can 30x to an internal one.

### Java/Kotlin
- `new URL(url).openConnection()`, `HttpURLConnection`, `RestTemplate.getForObject(url)`, `WebClient.get().uri(url)`, OkHttp, Apache HttpClient.

### Go
- `http.Get(url)`, `http.NewRequest(..., url, ...)`, `net.Dial`, `net.LookupHost`. The default client follows redirects; set `CheckRedirect` to re-validate.

### PHP
- `curl_setopt(CURLOPT_URL, $url)` then `curl_exec`, `file_get_contents($url)` with an http/https/ftp scheme, Guzzle `$client->request('GET', $url)`.

### Ruby
- `Net::HTTP.get(uri)`, `URI.open(url)`, `open(url)` (Kernel/OpenURI), `RestClient.get`, `Faraday`, `HTTParty`.

### C#/.NET
- `HttpClient.GetAsync(url)`, `WebRequest.Create(url)`, `WebClient.DownloadString(url)`.

### Shell-out (all stacks)
- `subprocess`/`exec`/`system` running `curl`, `wget`, `nc` with a user target.

## Safe patterns

- A strict allowlist of permitted hosts or URL prefixes, checked before the request.
- No user influence on the destination: a fixed URL, with user input only in a request body the target expects.
- Resolve the hostname once, check the resolved IP against private and link-local ranges, then connect to that same IP. This closes the DNS-rebinding window only when the request uses the pinned IP.
- Disable redirect following, or re-validate every hop against the allowlist.
- A dedicated egress proxy that enforces the destination policy.

## Weak mitigations

- An IP blocklist of private ranges and `169.254.169.254`. Bypassable with DNS rebinding, a decimal IP (`2130706433`), an IPv6-mapped address (`[::ffff:127.0.0.1]`), or a redirect chain. Keep the finding.
- A scheme-only check (allow `https://`). It still allows any external HTTPS host.
- A DNS-resolve-then-check that reconnects by hostname. The second lookup can return a different IP (TOCTOU).
- A substring check on the URL. `http://allowed.com@evil.com/` and similar parser tricks get past it.

## Verification checklist

- **attacker_control:** Name the entry point and the destination argument. Quote the outbound call and the destination construction. Note whether the user controls the full URL, the host, or only a path.
- **privilege_boundary:** State the gain: reach the cloud metadata endpoint, an internal service, or scan the internal network from the server's position.
- **unmitigated:** Confirm no strict allowlist on this path. A blocklist, a scheme-only check, or a resolve-then-recheck is not enough. Quote the host allowlist to refute.
- A stored destination is tainted if it was accepted without allowlist validation at write time. Trace the write.
- Blind SSRF (no response body) is still a finding. Note the out-of-band confirmation.

## Examples

### Python (requests)
```python
# Vulnerable: full URL from the user
url = request.args["url"]
return requests.get(url).text

# Secure: strict host allowlist
ALLOWED = {"api.example.com"}
url = request.args["url"]
if urlparse(url).hostname not in ALLOWED:
    abort(403)
return requests.get(url).text
```

### JavaScript/TypeScript (fetch)
```javascript
// Vulnerable: webhook URL from the body
const r = await fetch(req.body.url);

// Secure: allowlist and no redirect following
const ALLOWED = new Set(["hooks.example.com"]);
if (!ALLOWED.has(new URL(req.body.url).hostname)) return res.sendStatus(403);
const r = await fetch(req.body.url, { redirect: "manual" });
```

### Go (net/http)
```go
// Vulnerable: user URL passed to http.Get (follows redirects by default)
resp, err := http.Get(r.URL.Query().Get("url"))

// Secure: allowlist the host, reject redirects
u, _ := url.Parse(r.URL.Query().Get("url"))
if !allowedHosts[u.Hostname()] { http.Error(w, "forbidden", 403); return }
client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
resp, err := client.Get(u.String())
```

## Dynamic test hints

- Use a local build only. Point the destination at a local listener you control. Never test a real system or a real metadata endpoint.
- Internal reach: run a local HTTP listener, then send `?url=http://127.0.0.1:<port>/` and confirm the server connects.
- Blind test: point the URL at your local listener and watch for the inbound request even when the response is not returned.
- Blocklist bypass study on the local app: try a decimal IP for loopback, an IPv6-mapped form, and a redirect from an allowed local host to another local port.
- Do not target `169.254.169.254` or any real internal host.

## False positive traps

- The host is a fixed literal and the user controls only a path under it. That may be path traversal on an internal API, not SSRF.
- A strict allowlist of destination hosts is enforced, redirects do not follow, and the resolved IP is checked before connect.
- The outbound call is made by a client-side component (a browser `fetch`), not the server. That is a CORS or open-redirect concern.
- Egress is firewalled so the metadata endpoint and private ranges are unreachable, and the IaC confirms it. Lower the severity and note the assumption.
- The destination comes from trusted server config, not user input.

## Sources

Condensed and rewritten from the local copies under `third_party/`.

- `utkusen/sast-skills@db52227: sast-files/.claude/skills/sast-ssrf/SKILL.md` (MIT, Utku Sen): the outbound sinks per language, the allowlist patterns, the "blocklists are not mitigations" rule, partial-control and stored-destination notes, per-stack examples.
- `block/codecrucible@b5c8086: prompts/default/cwe_deep_analysis.yaml` (CWE-918), `prompts/default/analysis_sections.yaml` (TRUST BOUNDARIES / SSRF), `prompts/core/audit_families.yaml` (network family), `prompts/exploit-proof-web-*` (Apache-2.0, Block): the URL-component question, allowlist-vs-denylist, redirect and DNS-rebinding bypasses, blind SSRF, false positive indicators.
- `vercel-labs/deepsec@4fa6722: packages/scanner/src/matchers/ssrf.ts`, `untrusted-redirect-following.ts`, `go-ssrf.ts`, `git-provider-url-injection.ts`, `processor/src/prompt/slug-notes.ts` (Apache-2.0, Vercel): request-derived URL sinks, redirect-following bypass, partial-URL interpolation note.
- `cloudflare/security-audit-skill@c1c8a8c: skills/security-audit/ATTACK-CLASSES.md` (MIT, Cloudflare): webhook/notification-as-SSRF and the redirect and URL-parser-differential reminders.
