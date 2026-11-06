---
slug: crypto
title_en: Cryptographic misuse
title_tr: Kriptografi hataları
cwe: CWE-327
owasp: A02:2021
sources: codecrucible, security-audit-skill, deepsec, open-code-review
---

## Summary

A security decision rests on a weak, misused or unauthenticated cryptographic primitive. Examples: a broken hash or cipher, a predictable random token, a reused nonce, a timing-unsafe secret comparison, disabled certificate checks, a fast password hash. Name the primitive and its purpose first. MD5 in a cache key is harmless, MD5 in a signature is a finding.

## What it is

- **Broken algorithm or mode (CWE-327, CWE-328).** DES, 3DES, RC4, Blowfish, ECB mode, RSA keys below 2048 bits (CWE-326), MD5 or SHA-1 for signatures, certificates or integrity of attacker-influenced data.
- **Weak password hashing (CWE-916, CWE-759, CWE-760).** Raw or salted MD5, SHA-1 or SHA-256, one iteration, no salt or one global salt.
- **Weak randomness (CWE-330, CWE-338).** A non-cryptographic generator makes session IDs, reset tokens, API keys, OTPs, CSRF tokens, salts or IVs.
- **IV and nonce misuse (CWE-329, CWE-323).** A static or zero IV for CBC, a reused nonce with GCM, CTR or ChaCha20, an IV generated once at startup.
- **Unauthenticated encryption.** CBC or CTR without a MAC, or decryption before the MAC check. Distinguishable padding errors give a padding oracle.
- **Timing-unsafe comparison (CWE-208).** `==`, `equals` or `bytes.Equal` on HMACs, API keys or tokens.
- **Disabled TLS validation (CWE-295).** The client accepts any certificate or host name, or allows TLS below 1.2.
- **Cleartext transport of secrets (CWE-319).** Credentials or tokens over `http://` or unencrypted links on untrusted networks.
- **Fail-open or downgradable crypto.** A verify error leads to acceptance, or input selects a weak algorithm. XOR, Base64 or a custom cipher used as encryption.

## What it is not

- Hardcoded keys, IVs, passwords or tokens in source or git history → `hardcoded-secrets`.
- JWT `alg` confusion, missing signature checks, claim checks → `jwt`. SAML and OIDC signatures → `oauth-oidc-saml`.
- Missing, bypassable or replayable webhook signature checks, also a timing-unsafe compare inside them → `webhook-replay`.
- Passwords stored in plaintext or in a reversible form (CWE-256, CWE-257) → `sensitive-data-exposure`.
- Cookie `Secure` flag, HSTS, security headers → `security-misconfig`. TLS policies of load balancers in IaC → `iac-cloud-container`.
- A crypto library version with a CVE → `vulnerable-dependency`.
- Guessable IDs with working authorization → no finding. Without authorization → `idor`.
- OTP brute force without throttling → `rate-limit-bruteforce`. An OTP from `Math.random` stays here.

## Where to look

### Python

- `hashlib.md5`/`sha1`/`sha256` on passwords. Django `PASSWORD_HASHERS` with `MD5PasswordHasher` or unsalted hashers.
- `random.random`, `randint`, `choice` for tokens instead of `secrets`.
- PyCryptodome `AES.MODE_ECB`, `DES`, `ARC4`, fixed `iv=`. `cryptography` `modes.ECB()` or `CBC` without HMAC.
- `requests(..., verify=False)`, `ssl._create_unverified_context()`, `CERT_NONE`. `==` on digests instead of `hmac.compare_digest`.

### JavaScript/TypeScript

- `Math.random()` near `token`, `secret`, `otp`, `nonce`, `password`. Use `crypto.randomBytes` or `crypto.randomUUID`.
- `createHash('md5'|'sha1')` on passwords. `createCipher` (deprecated, removed in Node 22). `aes-*-ecb`. `Buffer.alloc(16)` as IV.
- CryptoJS `AES.encrypt(msg, "passphrase")` derives the key with one MD5 round.
- `===` on `signature`, `hmac` or `digest` instead of `crypto.timingSafeEqual`.
- `rejectUnauthorized: false`, `NODE_TLS_REJECT_UNAUTHORIZED = "0"`, an `https.Agent` without checks.

### Java/Kotlin

- `Cipher.getInstance("AES")` uses ECB by default. Also `"DES"`, `"DESede"`, `"RC4"`, `"AES/ECB/..."`.
- `new IvParameterSpec(new byte[16])`, `new Random()` or `Math.random()` for tokens instead of `SecureRandom`.
- `MessageDigest.getInstance("MD5")` for passwords. Spring `NoOpPasswordEncoder`, `StandardPasswordEncoder`, low PBKDF2 iterations.
- An empty `checkServerTrusted`, a `HostnameVerifier` that returns `true`, `SSLContext.getInstance("TLSv1")`.
- `Arrays.equals` or `String.equals` on MACs instead of `MessageDigest.isEqual`. `KeyPairGenerator.initialize(1024)`.

### Go

- `math/rand` for tokens instead of `crypto/rand`. `crypto/md5` or `crypto/sha1` for passwords. `crypto/des`, `crypto/rc4`.
- A fixed IV in `cipher.NewCBCEncrypter`, a fixed or resetting nonce with `cipher.NewGCM`.
- `bytes.Equal` or `==` on MACs instead of `hmac.Equal`. `tls.Config{InsecureSkipVerify: true}`, `MinVersion` below `tls.VersionTLS12`.

### PHP

- `md5($password)`, `sha1()` or `crypt()` with a weak salt instead of `password_hash()`.
- `rand()`, `mt_rand()`, `uniqid()`, `str_shuffle()` for tokens instead of `random_bytes()` or `random_int()`.
- `openssl_encrypt` with `-ecb` or a static IV. `CURLOPT_SSL_VERIFYPEER => false`, `verify_peer => false`.
- `==` on hashes. Strings like `"0e123..."` compare as numbers. Use `hash_equals`.

### Ruby

- `Digest::MD5` or `SHA1` for passwords instead of `bcrypt` or `has_secure_password`. `rand` for tokens instead of `SecureRandom`.
- `OpenSSL::Cipher.new("aes-256-ecb")` or a fixed `iv`. `VERIFY_NONE`. `==` on HMACs instead of `secure_compare`.

### C#/.NET

- `MD5.Create()` or `SHA1.Create()` for passwords. `new Random()` for tokens instead of `RandomNumberGenerator`.
- `DES`, `TripleDES`, `RC2`, `CipherMode.ECB`, a static `IV`. Old `Rfc2898DeriveBytes` defaults (SHA-1, 1000 rounds).
- `ServerCertificateCustomValidationCallback = (...) => true`. `SslProtocols.Tls`. `==` on MACs instead of `CryptographicOperations.FixedTimeEquals`.

## Safe patterns

- Passwords: argon2id, scrypt, bcrypt (cost 10 or more), or PBKDF2-HMAC-SHA256 with a high iteration count. Framework helpers: Django hashers, `password_hash()`, `has_secure_password`, ASP.NET Core `PasswordHasher`, Spring `DelegatingPasswordEncoder`.
- Random values from a CSPRNG (`secrets`, `crypto.randomBytes`, `SecureRandom`, `crypto/rand`, `random_bytes()`, `RandomNumberGenerator`), at least 128 bits.
- Encryption: an AEAD (AES-GCM, ChaCha20-Poly1305) with a unique random nonce per message, or a high-level API (libsodium, Fernet, Tink).
- Constant-time comparison: `hmac.compare_digest`, `crypto.timingSafeEqual`, `MessageDigest.isEqual`, `hmac.Equal`, `hash_equals`, `secure_compare`, `FixedTimeEquals`.
- TLS: default verification, TLS 1.2 or later, a custom CA bundle instead of disabled checks.
- Signatures: RSA 2048 or more, ECDSA P-256, Ed25519, HMAC-SHA256 with a random 256-bit key. Separate keys per purpose.
- Fail closed: a decrypt or verify error stops the request.

## Weak mitigations

- A salt on a fast hash, or nested fast hashes such as `md5(md5($p))`. Both stay cheap to brute force on a GPU.
- Base64, hex or XOR as "encryption".
- `Math.random` seeded with time or hashed with SHA-256, UUIDv1 or time-based IDs as secrets. The values stay predictable.
- A random IV created once at startup and reused for every message.
- CBC with a random IV but no MAC. The padding oracle remains when errors differ.
- A "dev only" flag that disables TLS checks and defaults to on when the variable is missing.

## Verification checklist

- **attacker_control:** Show how the attacker uses the weakness: a guessed token, observed ciphertexts, chosen ciphertext for a decrypt endpoint, a network position for TLS, or a stolen password hash. Name the input or the position.
- **privilege_boundary:** Name the gain: account takeover by a predicted reset token, a forged session or signature, decrypted personal data, captured credentials. A non-security use (cache key, ETag, deduplication, sharding) refutes this question.
- **unmitigated:** Quote the primitive and the line that uses its output for the security decision. Show that no stronger layer protects it, such as an HMAC with a server key, a KDF wrapper or a library default. The live path must reach it, not only a dead compatibility branch.
- State algorithm, mode, key size and purpose. Give the entropy of random values in bits (`Math.random()*1e6` gives about 20 bits), the nonce source, and the password hash parameters.

## Examples

### Python

Vulnerable: a fast hash for passwords and a predictable reset token.

```python
user.password_hash = hashlib.sha256((salt + password).encode()).hexdigest()
reset_token = "".join(random.choice(string.ascii_letters) for _ in range(20))
```

Secure: an adaptive password hash and a CSPRNG token.

```python
from argon2 import PasswordHasher
user.password_hash = PasswordHasher().hash(password)
reset_token = secrets.token_urlsafe(32)
```

### JavaScript/TypeScript (Node.js)

Vulnerable: `Math.random` token and a timing-unsafe HMAC check.

```ts
const apiKey = Math.random().toString(36).slice(2);
if (req.get("x-signature") === hmac(secret, rawBody)) grantAccess();
```

Secure: random bytes and a constant-time compare.

```ts
const apiKey = crypto.randomBytes(32).toString("base64url");
const got = Buffer.from(req.get("x-signature") ?? "", "hex");
const want = Buffer.from(hmac(secret, rawBody), "hex");
if (got.length === want.length && crypto.timingSafeEqual(got, want)) grantAccess();
```

### Java/Kotlin

Vulnerable: the default transformation is AES in ECB mode.

```java
Cipher c = Cipher.getInstance("AES");
c.init(Cipher.ENCRYPT_MODE, key);
byte[] out = c.doFinal(plain);
```

Secure: AES-GCM with a fresh 96-bit nonce.

```java
byte[] nonce = new byte[12];
new SecureRandom().nextBytes(nonce);
Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce));
byte[] out = c.doFinal(plain); // store nonce + out
```

## Dynamic test hints

- ECB: encrypt two equal 16-byte blocks with the target function. Equal ciphertext blocks prove ECB.
- Static IV or nonce: encrypt the same plaintext twice. Identical output proves reuse.
- Weak password hash: hash a dummy password with the target function and compare it with plain `sha256` output.
- `java.util.Random`: recover the seed from two outputs in a unit test and predict the next token.
- TLS: start a local server with a self-signed certificate on loopback. Show that the client connects.
- Padding oracle: change one ciphertext byte and call the local decrypt function. Stop when two different error types show.
- Never measure timing over a network or test real services. A quoted `==` on a secret is the evidence.

## False positive traps

- MD5 or SHA-1 for cache keys, ETags, deduplication, content addressing or non-security checksums.
- `random` or `Math.random` for UI, jitter, backoff, sampling or test data.
- HMAC-MD5 or HMAC-SHA1 with a strong key: the security rests on the key. Report it as hardening at most.
- A weak algorithm in a branch that the current configuration cannot reach, or a legacy hash that the code upgrades at login.
- A fast hash such as SHA-256 over a random 256-bit API token. A slow hash protects low-entropy passwords only.
- UUIDv4 from a CSPRNG (`uuid4`, `UUID.randomUUID`, `crypto.randomUUID`) gives 122 random bits.
- `verify=False` only in tests or tools that do not ship.
- A timing-unsafe compare is hard to exploit over a network. Rate it low.

## Sources

Condensed and rewritten by kalkan. Vendored copies and pinned commits: `third_party/MANIFEST.json`.

- block/codecrucible@b5c8086 (Apache-2.0, Block): `cwe_deep_analysis.yaml` (CWE-327, CWE-338) in `prompts/default/`, `prompts/carlini-curated/` and `prompts/exploit-proof-web-*/`, `prompts/default/analysis_sections.yaml` (cryptography), `prompts/core/audit_families.yaml` (secrets).
- cloudflare/security-audit-skill@c1c8a8c (MIT, Cloudflare): `skills/security-audit/ATTACK-CLASSES.md` (cryptography and secrets).
- vercel-labs/deepsec@4fa6722 (Apache-2.0, Vercel): `packages/scanner/src/matchers/insecure-crypto.ts`, `crypto-usage.ts`, `lua-crypto-weakness.ts`.
- alibaba/open-code-review@11ac6d4 (Apache-2.0, alibaba/open-code-review contributors): `internal/config/rules/rule_docs/python.md`, `go.md`, `php.md` (security sections).
- Added by kalkan from general knowledge: Java `Cipher` default, CryptoJS KDF, PHP magic hashes, .NET and Ruby APIs, test ideas.
