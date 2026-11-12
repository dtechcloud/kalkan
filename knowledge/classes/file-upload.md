---
slug: file-upload
title_en: Unsafe file upload
title_tr: Güvensiz dosya yükleme (file upload)
cwe: CWE-434
owasp: A04:2021
sources: sast-skills, codecrucible, open-code-review
---

## Summary

The application accepts a user file without a strong check on type, name and storage, and the stored file is reachable or executable. The worst outcome is a web shell: the attacker uploads a `.php` (or `.jsp`, `.aspx`) file and the server runs it on request. The finding depends on three facts: the validation on upload, the storage location, and how the file is served.

## What it is

- **No validation.** Any file type is accepted and saved.
- **Content-Type only.** The check reads the request `Content-Type` header, which the client sets freely. `shell.php` with `Content-Type: image/png` passes.
- **Blocklist with gaps.** `.php` is blocked but `.php3`, `.php5`, `.phtml`, `.phar`, `.shtml` are not. For Java: `.jsp`, `.jspx`. For ASP.NET: `.asp`, `.aspx`, `.ashx`, `.asmx`, `.cer`.
- **Case bypass.** `.php` is blocked but `.PHP` or `.pHp` is not, because the compare does not lowercase.
- **Double extension.** `shell.php.jpg` passes a last-segment check but a server with a wrong handler mapping runs it as PHP.
- **Path traversal in the name.** The original filename is used in the storage path unsanitized: `../../webroot/shell.php`.
- **Execution directory.** Even a correct extension check is weak if the file lands in a web-executable directory.

## What it is not

- The filename used as a read path elsewhere → `path-traversal`.
- A `../` in the archive entry name on extraction (zip slip) → `path-traversal`.
- An SVG with `<script>` reflected back → `xss`.
- An XML or SVG that triggers an outbound request → `xxe` / `ssrf`.
- A missing file size limit → `dos-redos`.
- Reading another user's uploaded file without authorization → `idor`.

## Where to look

Find the upload receive and the save. Then evaluate the three facts: validation, storage location, serving.

### Python (Flask, Django)
- Flask `request.files[...]`, `file.save(...)`. Django `request.FILES`, `default_storage.save`, a `FileField` with no validator.
- Safe: `secure_filename`, an extension allowlist, `magic` byte check, storage outside the web root, a UUID name.

### JavaScript/TypeScript (Multer, Express)
- `multer({ dest })` with no `fileFilter`, or a MIME-only `fileFilter`. `req.files` from `express-fileupload`. `fs.writeFile` with a request stream.
- Safe: `multer.diskStorage` with a UUID filename, an extension allowlist, a non-served destination.

### Java/Kotlin (Spring)
- `MultipartFile` saved with `file.getOriginalFilename()` into a served path. A `Content-Type`-only check.
- Safe: `FilenameUtils.getExtension` against an allowlist, a UUID name, a path outside the web root.

### Go
- `r.FormFile`, `io.Copy(dst, file)` with `header.Filename` in the path.
- Safe: `filepath.Ext` against an allowlist, a UUID name, a non-served directory.

### PHP
- `move_uploaded_file($_FILES['file']['tmp_name'], 'uploads/'.$_FILES['file']['name'])`, a `['type']`-only check, a blocklist missing `phtml`/`phar`.
- Safe: `pathinfo(..., PATHINFO_EXTENSION)` against an allowlist, a random name, a non-executable directory.

### Ruby (Rails)
- `File.open(... original_filename ...)`, ActiveStorage/CarrierWave/Shrine without a content-type and extension allowlist.

### C#/.NET
- `IFormFile.CopyToAsync` to `wwwroot/uploads` with `file.FileName`.
- Safe: `Path.GetExtension` against an allowlist, a GUID name, a path outside the web root.

## Safe patterns

- An extension allowlist of safe types, compared case-insensitively. An allowlist beats a blocklist.
- A server-generated name (UUID or random). The user never sets the stored name or extension.
- Storage outside the web root, or in object storage with no execution, served through a controlled endpoint.
- Serving with a fixed `Content-Type` (for example `application/octet-stream`), `Content-Disposition: attachment`, and `X-Content-Type-Options: nosniff`.
- A magic-byte check as defense in depth, in addition to the allowlist.
- `secure_filename` / `basename` on the name before any path use.

## Weak mitigations

- A blocklist of dangerous extensions. It is almost always incomplete. Mark at least likely vulnerable.
- A `Content-Type` header check. The client controls the header.
- A case-sensitive extension compare. `.PHP` gets past it.
- A magic-byte check alone, with the extension and the execution directory unchanged. A polyglot file passes.
- An allowlist with the file still stored in an executable directory. One validation gap then becomes code execution.

## Verification checklist

- **attacker_control:** Name the upload endpoint and the field. Quote the save call and the validation (or its absence).
- **privilege_boundary:** State the gain: upload an executable file that the server runs (web shell, full compromise), or place a file in an unintended directory.
- **unmitigated:** Confirm the validation is bypassable (none, Content-Type only, blocklist, case-sensitive) and the storage is reachable or executable. Quote a strict allowlist plus a non-served path plus a server name to refute.
- Note the storage location and the serving behavior in every finding. They decide the impact.

## Examples

### Python (Flask)
```python
# Vulnerable: no check, saved to a served directory under the user name
f = request.files["file"]
f.save(os.path.join("static/uploads", f.filename))

# Secure: allowlist, random name, stored outside the web root
ALLOWED = {"png", "jpg", "jpeg", "gif"}
f = request.files["file"]
ext = secure_filename(f.filename).rsplit(".", 1)[-1].lower()
if ext not in ALLOWED:
    abort(400)
f.save(os.path.join("/var/uploads", f"{uuid.uuid4()}.{ext}"))
```

### JavaScript/TypeScript (Multer)
```javascript
// Vulnerable: no filter, served directory, user name kept
const upload = multer({ dest: "public/uploads/" });

// Secure: extension allowlist, UUID name, non-served destination
const ALLOWED = [".jpg", ".jpeg", ".png", ".gif"];
const upload = multer({
  storage: multer.diskStorage({
    destination: "/var/uploads",
    filename: (req, file, cb) => cb(null, `${uuidv4()}${path.extname(file.originalname).toLowerCase()}`),
  }),
  fileFilter: (req, file, cb) => cb(null, ALLOWED.includes(path.extname(file.originalname).toLowerCase())),
});
```

### PHP
```php
// Vulnerable: Content-Type header check only, user name kept
if ($_FILES["file"]["type"] !== "image/jpeg") die("bad");
move_uploaded_file($_FILES["file"]["tmp_name"], "uploads/".$_FILES["file"]["name"]);

// Secure: extension allowlist, random name, non-executable directory
$allowed = ["jpg","jpeg","png","gif"];
$ext = strtolower(pathinfo($_FILES["file"]["name"], PATHINFO_EXTENSION));
if (!in_array($ext, $allowed)) die("bad");
move_uploaded_file($_FILES["file"]["tmp_name"], "/var/uploads/".bin2hex(random_bytes(16)).".".$ext);
```

## Dynamic test hints

- Use a local build only. Never test a real system.
- No check: upload a harmless `.txt`, then a `.php` that prints a fixed string, and request the stored URL on the local app.
- Content-Type bypass: `curl -F "file=@shell.php;type=image/png"` against the local endpoint, then request the stored path.
- Blocklist bypass: try `.phtml`, `.phar`, `.php5` (PHP) or `.PHP` for the case bypass.
- Double extension: upload `shell.php.jpg` and check whether the server runs it.
- Keep the uploaded script harmless (print a constant) and local.

## False positive traps

- A strict extension allowlist, compared case-insensitively, with a UUID rename and storage outside the web root.
- Storage in object storage with no execution, served from a domain that shares no cookies with the app.
- The upload is restricted to an admin role whose compromise is already game over; the upload grants nothing more. Note this as a severity reducer.
- A controlled download endpoint forces `Content-Disposition: attachment` and a safe `Content-Type`.
- `secure_filename` / `basename` strips the path and only a server name reaches the storage path.

## Sources

Condensed and rewritten from the local copies under `third_party/`.

- `utkusen/sast-skills@db52227: sast-files/.claude/skills/sast-fileupload/SKILL.md` (MIT, Utku Sen): the bypass vectors (Content-Type, blocklist gaps, case, double extension, path traversal), the allowlist/UUID/non-served patterns, per-stack examples, server-specific dangerous extensions.
- `block/codecrucible@b5c8086: prompts/default/cwe_deep_analysis.yaml` (CWE-434), `prompts/core/audit_families.yaml` (files family), `prompts/exploit-proof-web-python/cwe_deep_analysis.yaml` (CWE-434) (Apache-2.0, Block): the "upload is delivery, the sink is what happens next" framing, storage and serving checks, the magic-byte-vs-extension note, false positive indicators.
- `alibaba/open-code-review@11ac6d4: internal/config/rules/rule_docs/php.md` (Apache-2.0, alibaba/open-code-review contributors): the server-side type check, generated storage name, and executable-file handling rule.
