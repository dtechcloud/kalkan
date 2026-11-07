# CodeQL to Semgrep Rule Conversion

This project converts security rules from [GitHub's CodeQL repository](https://github.com/github/codeql) to [Semgrep](https://github.com/semgrep/semgrep) format. The translation was done automatically using [Claude Code](https://claude.ai/claude-code).

Semgrep's runner is open source, but their rules are not. CodeQL's rules are open source, but the CodeQL engine is not. This project bridges that gap by converting CodeQL's open source security rules to run on Semgrep's open source engine.

## Source

Rules are converted from the official CodeQL repository, which contains security queries organized by CWE (Common Weakness Enumeration) categories.

## Structure

```
rules/
├── python/security/     # Python security rules (89 rules)
├── javascript/security/ # JavaScript/TypeScript security rules (42 rules)
├── go/security/         # Go security rules (31 rules)
├── java/security/       # Java security rules (30 rules)
├── ruby/security/       # Ruby security rules (29 rules)
├── cpp/security/        # C/C++ security rules (22 rules)
├── csharp/security/     # C# security rules (15 rules)
├── swift/security/      # Swift/iOS security rules (13 rules)
├── actions/security/    # GitHub Actions security rules (10 rules)
└── generic/security/    # Language-agnostic rules (6 rules)
```

## Conversion Status

| Language | Rules |
|----------|-------|
| [Python](rules/python/security/) | 89 |
| [JavaScript/TypeScript](rules/javascript/security/) | 42 |
| [Go](rules/go/security/) | 31 |
| [Java](rules/java/security/) | 30 |
| [Ruby](rules/ruby/security/) | 29 |
| [C/C++](rules/cpp/security/) | 22 |
| [C#](rules/csharp/security/) | 15 |
| [Swift](rules/swift/security/) | 13 |
| [GitHub Actions](rules/actions/security/) | 10 |
| [Generic](rules/generic/security/) | 6 |
| **Total** | **287** |

## Conversion Notes

CodeQL uses sophisticated dataflow analysis that Semgrep cannot fully replicate. This conversion focuses on:

1. Pattern-based detections (direct API usage, configuration issues)
2. Simple taint tracking where Semgrep's pattern matching suffices
3. Hardcoded secrets and credentials
4. Insecure cryptographic configurations
5. Dangerous function calls
6. Framework-specific security patterns

Some CodeQL rules that rely heavily on cross-function dataflow analysis may have reduced precision when converted to Semgrep patterns.

## Usage

Run all rules against your codebase:

```bash
semgrep --config rules/ /path/to/your/code
```

Run rules for a specific language:

```bash
semgrep --config rules/python/security/ /path/to/python/code
```

## Validation

All rules are validated using `semgrep --validate` before inclusion.

## Rules by Language

**Python (89 rules):** SQL injection, command injection, XSS, path traversal, XXE, SSRF, unsafe deserialization, broken cryptography, hardcoded credentials, insecure cookies, TLS certificate validation, weak crypto keys, LDAP injection, template injection, regex DoS, file permissions, URL redirects, NoSQL injection, XML bombs, log injection, header injection, XPath injection, stack trace exposure, bind all interfaces, JWT security, timing attacks, archive security (tar/zip slip), decompression bombs, Django security (debug mode, CSRF, raw SQL, mark_safe), weak token generation, weak password hashing

**JavaScript (42 rules):** SQL injection, command injection, XSS, path traversal, unsafe deserialization, hardcoded credentials, TLS certificate validation, XXE, broken cryptography, insecure randomness, open redirect, SSRF, NoSQL injection, prototype pollution, regex injection, cookie security, CORS misconfiguration, log injection, template injection, XPath injection, bind all interfaces, JWT security, Electron security (nodeIntegration, contextIsolation, webSecurity), Express security (Helmet, CORS, body parser limits, session cookies), environment variable injection

**Go (31 rules):** SQL injection, command injection, path traversal, SSRF, XSS, XXE, broken cryptography, hardcoded credentials, insecure TLS, disabled certificate checks, insecure host keys, insecure randomness, cookie security, insufficient key size, open redirect, JWT signature verification, OAuth2 state validation, XPath injection, log injection, bind all interfaces, CORS misconfiguration, database N+1 queries, GORM error handling

**Java (30 rules):** SQL injection, command injection, XSS, path traversal, unsafe deserialization, XXE, broken cryptography, insecure randomness, hardcoded credentials, LDAP injection, SSRF, open redirect, log injection, cookie security, XPath injection, bind all interfaces, zip slip, Android WebView security (JavaScript, file access, content access, sensitive logging), Spring security (CSRF, SpEL injection, redirects, actuator exposure)

**Ruby (29 rules):** SQL injection, command injection, XSS, unsafe deserialization, path traversal, hardcoded credentials, open redirect, SSRF, broken cryptography, XXE, insecure randomness, NoSQL injection, log injection, cookie security, template injection, XPath injection, bind all interfaces, Rails security (mass assignment, html_safe, render, send/public_send, constantize)

**C/C++ (22 rules):** Dangerous functions (gets, sprintf, strcpy, strcat, gmtime, localtime), broken cryptography (MD5, SHA1, DES, RC4), command injection, format string vulnerabilities, insecure randomness, hardcoded credentials, memory safety (memset deleted, use-after-free), file permissions, goto usage, assert side effects, malloc null checks, division by zero

**C# (15 rules):** SQL injection, command injection, XSS, path traversal, unsafe deserialization (BinaryFormatter, XmlSerializer, JavaScriptSerializer), XXE, hardcoded credentials, cookie security, LDAP injection, open redirect

**Swift (13 rules):** SQL injection, command injection, path traversal, broken cryptography (MD5, SHA1, ECB mode), hardcoded credentials, cleartext storage (UserDefaults, logging), insecure TLS, constant salt

**GitHub Actions (10 rules):** Unpinned actions, script injection (title, body, head_ref), dangerous triggers (pull_request_target), checkout PR head, missing permissions, excessive permissions, secrets exposure

**Generic (6 rules):** Private key detection (RSA, DSA, EC, OPENSSH, PGP), AWS access keys, GitHub tokens, Slack tokens, insecure HTTP URLs, insecure FTP URLs

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Attribution

These rules are derived from and inspired by the [GitHub CodeQL repository](https://github.com/github/codeql), which is maintained by GitHub and its contributors. The original CodeQL queries provided the foundation for these Semgrep conversions. Thank you to the CodeQL team and all contributors for their work on security analysis tooling.
