---
slug: path-traversal
title_en: Path traversal / file read-write
title_tr: Path traversal
cwe: CWE-22, CWE-23, CWE-36, CWE-59, CWE-73, CWE-552
owasp: A01:2021
sources: sast-skills, codecrucible, open-code-review, deepsec
---

## Summary

The application builds a filesystem path from attacker text and does not confine the resolved path to an intended base directory. The attacker uses `../` or an encoded variant to read or write files outside that directory: `/etc/passwd`, source code, keys, config. Archive extraction (zip slip) and symlink following are variants. The core shape is a user path component reaching a file operation without a canonicalize-and-check.

## What it is

- **Read outside the base.** A user filename joined to a base and read without a prefix check: `open(join(BASE, name))`, `send_file(name)`, `res.sendFile(name)`.
- **Write outside the base.** A user filename used as a write destination, which can overwrite config or plant a file.
- **Dynamic include.** PHP `include($_GET['page'].'.php')` reaches an attacker path.
- **Zip slip.** An archive entry name contains `../` and extraction writes outside the target directory.
- **Symlink follow (CWE-59).** A path resolves through an attacker-placed symlink to escape the base.
- **Encoded traversal.** `%2e%2e%2f`, double-encoded `%252e`, mixed separators. A string filter misses them; filesystem resolution handles them.
- **Second-order.** A filename stored from user input is later used in a file read elsewhere.

## What it is not

- Fetching a remote URL from user input → `ssrf`.
- Writing attacker content that the server then executes or an upload execution path → `file-upload` (or `code-injection` if the written file runs).
- A user path reaching a code `include`/`require` that executes it → `code-injection` is the primary class.
- Reading another user's object through a correct, confined path by changing an ID → `idor`.
- A fully hardcoded path with no user component → not this class.

## Where to look

Flag a file operation whose path has a dynamic component. Then trace the component to a user source and check for a confinement control.

### Python
- `open(x)`, `open(os.path.join(BASE, x))`, `Path(x).read_text()`, `send_file(x)`, `send_from_directory(base, x)`, `FileResponse(x)`.
- Note: `send_from_directory` calls `safe_join` and is safe unless the base itself is user-controlled.

### JavaScript/TypeScript
- `fs.readFile(x)`, `fs.createReadStream(x)`, `res.sendFile(x)`, `res.download(x)`, `path.join(base, x)`, `path.resolve(base, x)`.
- `express.static` with a user-controlled root. `res.sendFile` without the `root` option.

### Java/Kotlin
- `new File(base, x)`, `Paths.get(base).resolve(x)`, `Files.readAllBytes`, `new UrlResource(path.toUri())`, `ResourceLoader.getResource(x)`.
- Archive: `ZipEntry.getName()` used as an output path.

### Go
- `os.Open(filepath.Join(base, x))`, `os.ReadFile(x)`, `http.ServeFile(w, r, x)`.
- Note: `filepath.Clean` alone does not stop escape above a base. Use `filepath.Abs` then `filepath.Rel` and reject a `..` result.

### PHP
- `file_get_contents(x)`, `fopen(x)`, `readfile(x)`, `include(x)`, `require(x)`.
- Safe: `basename($x)` before the join; a `realpath` prefix check.

### Ruby
- `File.read(x)`, `File.open(x)`, `send_file(x)`, `render file: x`.
- Safe: `File.basename(params[:file])`.

### C#/.NET
- `File.ReadAllText(x)`, `new FileStream(x, ...)`, `File.Open(x, ...)`.

## Safe patterns

- Canonicalize, then check the prefix. Resolve to an absolute real path and verify it starts with the base plus a separator: `realpath(join(base, x)).startswith(base + sep)`.
- `basename` / `path.basename` to strip every directory component when only a filename is needed.
- An allowlist of permitted filenames.
- A lookup by ID that maps to a server-chosen path, so the user never supplies a path.
- Per-entry validation for archive extraction: resolve each entry under the target and reject any `..` escape.
- A framework helper that confines the path (Flask `send_from_directory`, `res.sendFile` with `root`).

## Weak mitigations

- `replace("../", "")`. Bypassable with `....//` or an encoding. Keep the finding.
- A check that the input does not start with `/`. It does not stop a relative `../` escape.
- `os.path.join` or `path.join` alone. `join("/base", "../etc/passwd")` resolves to `/etc/passwd`.
- A single URL-decode. The attacker double-encodes.
- An extension check with no prefix check. The path still escapes; the extension can be framed at the end.
- A prefix check with no trailing separator. `/safe` also matches `/safe-other`.

## Verification checklist

- **attacker_control:** Name the entry point and the path component. Quote the file operation and the path construction.
- **privilege_boundary:** State the gain: read files outside the base (config, keys, source) or write outside it. Name a target file.
- **unmitigated:** Confirm no canonicalize-and-check, no `basename`, no allowlist before the operation. Quote the confinement control to refute. A weak filter (`replace("../","")`) does not refute.
- Note encoded-variant handling. A string filter that does not resolve the path is weak.
- For archive extraction, confirm the check is per entry, not only on the archive path.

## Examples

### Python (Flask)
```python
# Vulnerable: user filename joined with no prefix check
return send_file(os.path.join("/var/www/files", request.args["file"]))

# Secure: resolve and verify the base prefix
base = os.path.realpath("/var/www/files")
p = os.path.realpath(os.path.join(base, request.args["file"]))
if not p.startswith(base + os.sep):
    abort(403)
return send_file(p)
```

### JavaScript/TypeScript (Express)
```javascript
// Vulnerable: req.query.file used directly
fs.readFile(path.join(__dirname, "uploads", req.query.file), cb);

// Secure: resolve and check the prefix
const base = path.resolve(__dirname, "uploads");
const p = path.resolve(base, req.query.file);
if (!p.startsWith(base + path.sep)) return res.sendStatus(403);
fs.readFile(p, cb);
```

### Archive extraction (zip slip)
```python
# Vulnerable: entry names may contain ../
with zipfile.ZipFile(user_zip) as zf:
    zf.extractall("/var/www/uploads")

# Secure: validate each entry under the base before extracting
base = os.path.realpath("/var/www/uploads")
with zipfile.ZipFile(user_zip) as zf:
    for m in zf.namelist():
        t = os.path.realpath(os.path.join(base, m))
        if not t.startswith(base + os.sep):
            raise ValueError("zip slip")
    zf.extractall(base)
```

## Dynamic test hints

- Use a local build only. Never test a real system.
- Read probe: `?file=../../../../etc/hostname` on a local app and look for the file content.
- Encoded probe: `?file=%2e%2e%2f%2e%2e%2fetc%2fhostname` and the double-encoded `%252e%252e%252f` form.
- Mixed separator on Windows: `?file=..\..\windows\win.ini` against a local Windows build.
- Zip slip: build a local archive with an entry named `../evil.txt` and extract it into a temporary directory to confirm the escape.
- Keep every target a harmless local file.

## False positive traps

- The filename is a server-generated identifier (a database key, a UUID, a content hash) with no user bytes in the path.
- A canonical path is computed and verified to start with the base (with a trailing separator) before the operation.
- A framework static handler owns the path and confines it by design.
- `basename` or `secure_filename` strips the directory component before the join.
- Flask `send_from_directory` is safe by itself; flag it only when the base directory is user-controlled.

## Sources

Condensed and rewritten from the local copies under `third_party/`.

- `utkusen/sast-skills@db52227: sast-files/.claude/skills/sast-pathtraversal/SKILL.md` (MIT, Utku Sen): the file sinks per language, the realpath/basename/allowlist patterns, encoded-variant and zip-slip notes, per-stack examples.
- `block/codecrucible@b5c8086: prompts/default/cwe_deep_analysis.yaml` (CWE-22), `prompts/default/analysis_sections.yaml` (PATH), `prompts/core/audit_families.yaml` (files family), `prompts/exploit-proof-web-*` (Apache-2.0, Block): the canonicalize-and-check method, framework decode behavior, false positive indicators.
- `alibaba/open-code-review@11ac6d4: internal/config/rules/rule_docs/go.md`, `python.md`, `php.md` (Apache-2.0, alibaba/open-code-review contributors): the Go `filepath.Clean` caveat and the "normalize and enforce the boundary" rule.
- `vercel-labs/deepsec@4fa6722: packages/scanner/src/matchers/path-traversal.ts`, `fs-write-symlink-boundary.ts` (Apache-2.0, Vercel): the read and write path sinks and the symlink-boundary note.
