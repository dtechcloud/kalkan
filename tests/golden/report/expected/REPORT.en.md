# Security audit report: shop

| Field | Value |
|---|---|
| Run ID | `20261015T120000Z-shop-a1b2` |
| Target | `C:/projects/shop` |
| Target kind | Local folder |
| Git commit | — |
| Profile | standard |
| Run language | tr |
| Started | 2026-10-15 09:30 UTC |
| Last update | 2026-10-15 12:00 UTC |
| Report date | 2026-10-15 12:30 UTC |
| Phase | Report |
| Status | Complete |
| Technologies | `docker`, `flask`, `python` |

## 1. Executive summary

Confirmed findings: 2. Highest severity: High. Findings that need validation: 1. Candidate findings that the verifier rejected: 1. Unverified tool results: 2. Warning: known malicious package versions in the dependencies: 1. These packages run code when they are installed. Do the steps of section 8.1 now. Vulnerable dependencies (SCA): 5. Reachable records: 1.

> **Partial pass.** This report may not cover the whole target. Section 2 gives the reasons.

| Metric | Count |
|---|---|
| Confirmed findings | 2 |
| Severity: Critical | 0 |
| Severity: High | 1 |
| Severity: Medium | 1 |
| Severity: Low | 0 |
| Severity: Info | 0 |
| Need validation | 1 |
| Rejected | 1 |
| Unverified tool results | 2 |
| SCA records | 5 |
| Malicious dependencies | 1 |

*The severity counts cover confirmed findings only.*

### 1.1 Finding list

| ID | Title | Severity | Verdict | Location |
|---|---|---|---|---|
| `KF-CF0FB1E8E50E80FC` | SQL injection in user lookup | High | Confirmed | `app/db.py:8` |
| `KF-760073988BED4CB8` | Görsel proxy'sinde SSRF | Medium | Confirmed | `app/routes.py:19` |
| `KF-32409FEA7A491CFA` | Dosya okumada path traversal | — | Needs validation | `app/routes.py:25` |
| `KF-C4BCAA828C227419` | Router \`admin\` \| &lt;script&gt;alert('x')&lt;/script&gt; yetki atlatma | — | Rejected | `app/routes.py:31` |

## 2. Scope

> **Partial pass.** This report may not cover the whole target. Reasons:
>
> - Open coverage units (planned, in_progress, deferred or blocked): 1.
> - Dependency manifests without a lockfile: 1. SCA did not check their version ranges or transitive dependencies.

### 2.1 Profile and budget

Profile: standard. Agent task budget: 13 / 150 used.

### 2.2 Phases

| Phase | Status | Started | Finished |
|---|---|---|---|
| Preparation | Done | 2026-10-15 12:00 UTC | 2026-10-15 12:00 UTC |
| Deterministic scan | Done | 2026-10-15 12:00 UTC | 2026-10-15 12:00 UTC |
| SCA | Done | 2026-10-15 12:00 UTC | 2026-10-15 12:00 UTC |
| Reconnaissance | Done | 2026-10-15 12:00 UTC | 2026-10-15 12:00 UTC |
| Plan | Done | 2026-10-15 12:00 UTC | 2026-10-15 12:00 UTC |
| Hunt | Done | 2026-10-15 12:00 UTC | 2026-10-15 12:00 UTC |
| Validation | Done | 2026-10-15 12:00 UTC | 2026-10-15 12:00 UTC |
| PoC | Done | 2026-10-15 12:00 UTC | 2026-10-15 12:00 UTC |
| Merge | Done | 2026-10-15 12:00 UTC | 2026-10-15 12:00 UTC |
| Report | Running | 2026-10-15 12:00 UTC | — |

### 2.3 Scanners

| Engine | Group | Status | Version | Duration | Note |
|---|---|---|---|---|---|
| `bandit` | Scan | Ran | `1.9.4` | 3.0 s | — |
| `gitleaks` | Scan | Ran | `8.30.1` | 1.2 s | — |
| `opengrep` | Scan | Ran | `1.30.1` | 12.4 s | — |
| `trivy` | Scan | Skipped | — | 0.0 s | tool not installed: trivy |
| `grype` | SCA | Skipped | — | 0.0 s | offline: no vulnerability database |
| `osv-scanner` | SCA | Ran | `2.6.0` | 4.5 s | — |
| `retirejs` | SCA | Ran | `jsrepository-v5 2026-10-15 sha256:c213444cbf88` | 0.4 s | JavaScript files checked: 1; vendored library versions: 1 (files: 1) |
| `syft` | SCA | Ran | `1.54.0` | 3.2 s | — |

### 2.4 Coverage ledger

| Unit status | Count |
|---|---|
| Candidate found | 2 |
| Covered | 1 |
| Deferred | 1 |
| Not applicable | 1 |
| **Total** | **5** |

**Final review.** 2 records passed a second, independent review: 1 verified, 1 downgraded, 0 rejected. Confirmed or needs-validation records without a review: 1.

### 2.5 Missing inputs

All inputs were read.

### 2.6 Scan gaps

The tools could not scan these files completely. A file without results here is not necessarily clean.

These manifests have no lockfile next to them. The SCA tools read the package versions and the transitive dependencies from a lockfile. kalkan checked the exact versions (exact pins) of these manifests separately.

| File | Ecosystem | Exact pins checked | Ranges not checked | Reason |
|---|---|---|---|---|
| `web/package.json` | npm | 1 | 2 | Version ranges without a lockfile |

`opengrep`: files analyzed only partially (parse errors or internal tool errors): 1.

- `app/helpers.py`

`opengrep`: files skipped: 1.

Reasons:

- files larger than 1.0 MB: 1

Files:

- `static/bundle.min.js`

Files with an absolute path of 260 or more characters: 1. Opengrep may skip them without a warning. Cause: the Opengrep core program is not long-path aware. LongPathsEnabled=1 does not lift this limit. LongPathsEnabled on this host: on. Fix: set `KALKAN_RUNS_DIR` to a short folder (for example `C:/kr`). Then start a new run.

## 3. Confirmed findings

The engine confirms a finding in one of two ways: the three questions are established with quotes that the engine found in the source, or a sandbox PoC demonstrates the vulnerability. The findings are ordered by severity.

*kalkan translates the title, the description and the remediation of each finding. Other fields keep the language of the run.*

### 3.1 High · SQL injection in user lookup

| Field | Value |
|---|---|
| ID | `KF-CF0FB1E8E50E80FC` |
| Severity | High (likelihood: High, impact: High) |
| Confidence | Medium |
| Class | SQL injection (`sqli`) |
| CWE | CWE-89 |
| OWASP | A03:2021 |
| Location | `app/db.py:8` |
| Engines | `hunter`, `verifier`, `opengrep`, `reviewer` |
| Final review | Verified: Kayıttaki her yol ve satır kaynakla uyuşuyor; f-string, id değerini SQL metnine koyuyor. |
| Linked candidates | `CAND-7FB0BF0A3BDA3C13` |
| PoC | No PoC record |
| Runtime validation | Not performed |

**Description.** GET /users puts the id parameter straight into a SQL query.

**Root cause.** find\_user, SQL metnini f-string ile kuruyor.

**Intended behavior.** Sorgu, user\_id değerini parametre olarak bağlamalı.

**Trace**

| # | Kind | Location | Scope | Description |
|---|---|---|---|---|
| 1 | Entrypoint | `app/routes.py:12` | `get_user` | id değerini query string'den okuyor. |
| 2 | Sink | `app/db.py:8` | `find_user` | Biçimlenmiş SQL metnini çalıştırıyor. |

**Evidence**

- `app/db.py:8`: f-string, user\_id değerini SQL metnine koyuyor.

**Three questions**

| Question | Answer | Reason | Quotes |
|---|---|---|---|
| Does the attacker control the input? | Established | id değeri HTTP isteğinin query string'inden geliyor. | `app/routes.py:12` `user_id = request.args.get("id")` |
| Does the flow cross a privilege boundary? | Established | Oturum açmış her kullanıcı başka kullanıcıların satırlarını okuyabilir. | `app/routes.py:10` `@login_required` |
| Is an effective mitigation missing? | Established | Değer bağlama veya doğrulama olmadan SQL metnine giriyor. | `app/db.py:8` `cur.execute(f"SELECT * FROM users WHERE id = {user_id}")` |

**Conditions**

- Authentication level: Saldırganın normal bir kullanıcı hesabı olmalı.

**Attack scenario**

**Attacker.** Normal hesabı olan, oturum açmış bir kullanıcı.

Steps:

1. Normal kullanıcı olarak oturum aç.
2. GET /users?id=1%20OR%201=1 isteğini gönder.

Payload:

```text
1 OR 1=1
```

**Observed result.** Yalnızca statik analiz: payload cur.execute çağrısına değişmeden ulaşıyor.

**Remediation.** Use a bound parameter.

Code change: `app/db.py`

```text
cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
```

### 3.2 Medium · Görsel proxy'sinde SSRF (not translated)

| Field | Value |
|---|---|
| ID | `KF-760073988BED4CB8` |
| Severity | Medium (likelihood: High, impact: Medium) |
| Confidence | High |
| Class | Server-side request forgery (`ssrf`) |
| CWE | CWE-918 |
| OWASP | A10:2021 |
| Location | `app/routes.py:19` |
| Engines | `hunter`, `verifier`, `poc-builder` |
| Final review | Not reviewed |
| PoC | Passed · unit |
| Runtime validation | Reproduced: the PoC showed the effect in the sandbox |

**Description.** GET /fetch, kullanıcının verdiği adrese sunucudan istek atıyor. *(not translated)*

**Root cause.** fetch, url değerini doğrulamadan http\_get'e veriyor.

**Intended behavior.** Sunucu yalnızca izin listesindeki adreslere istek atmalı.

**Trace**

| # | Kind | Location | Scope | Description |
|---|---|---|---|---|
| 1 | Entrypoint | `app/routes.py:18` | `fetch` | url değerini query string'den okuyor. |
| 2 | Sink | `app/routes.py:19` | `fetch` | Sunucu, kullanıcının verdiği adrese istek atıyor. |

**Evidence**

- `app/routes.py:19`: http\_get, doğrulanmamış url değerini kullanıyor.

**Three questions**

| Question | Answer | Reason | Quotes |
|---|---|---|---|
| Does the attacker control the input? | Established | url değeri query string'den geliyor. | `app/routes.py:18` `url = request.args.get("url")` |
| Does the flow cross a privilege boundary? | Unknown | unverified\_evidence | — |
| Is an effective mitigation missing? | Established | Adres doğrulaması yok. | `app/routes.py:19` `return http_get(url)` |

**Attack scenario**

**Attacker.** Kimliği doğrulanmamış uzak bir saldırgan.

Steps:

1. GET /fetch?url=http://169.254.169.254/latest/meta-data/ gönder.

Payload:

```text
http://169.254.169.254/latest/meta-data/
```

**Observed result.** Harness, 169.254.169.254 adresine giden isteği yakaladı.

**PoC result (Passed · unit).** Harness, 169.254.169.254 adresine giden isteği yakaladı.

PoC files: `poc/KF-760073988BED4CB8/out/stdout.txt`

**Remediation.** Hedef adresi bir allowlist ile sınırla. *(not translated)*

## 4. Findings that need validation

The evidence for these findings is incomplete. They have no severity. Read the blockers and the validation plan.

### 4.1 Dosya okumada path traversal (not translated)

| Field | Value |
|---|---|
| ID | `KF-32409FEA7A491CFA` |
| Class | Path traversal / file read-write (`path-traversal`) |
| CWE | CWE-22 |
| Location | `app/routes.py:25` |
| Engines | `hunter`, `verifier` |
| Final review | Downgraded: Uygulama dosya adını hiç normalize etmiyor; tek açık soru, önündeki reverse proxy'nin ../ dizilerini engelleyip engellemediği. |
| PoC | Not run · unit |
| Runtime validation | Not performed |

**Description.** GET /files, name parametresini dosya yoluna ekliyor. *(not translated)*

**Claimed root cause.** read\_file, name değerini normalleştirmeden yola ekliyor.

**Blockers**

- Bir reverse proxy ../ dizilerini engelliyor olabilir.
- Uygulama dosya adını hiç normalize etmiyor; tek açık soru, önündeki reverse proxy'nin ../ dizilerini engelleyip engellemediği.
- `sandbox_unavailable`: The PoC verification sandbox did not run (Docker was off or not available).

**Validation plan**

- Local: Uygulamayı çalıştır ve name=../../etc/passwd gönder.
- Deployment: Onaylı test ortamında proxy davranışını kontrol et.

**Trace**

| # | Kind | Location | Scope | Description |
|---|---|---|---|---|
| 1 | Entrypoint | `app/routes.py:24` | `read_file` | name değerini query string'den okuyor. |
| 2 | Sink | `app/routes.py:25` | `read_file` | Birleştirilmiş yolu açıyor. |

**Evidence**

- `app/routes.py:25`: open çağrısı birleştirilmiş yolu kullanıyor.

**PoC result (Not run · unit).** Çalışmadı: Docker sandbox yok.

## 5. Rejected findings

The verifier or the final review rejected these candidates. The records stay for the audit trail.

| ID | Title | Class | Location | Reason |
|---|---|---|---|---|
| `KF-C4BCAA828C227419` | Router \`admin\` \| &lt;script&gt;alert('x')&lt;/script&gt; yetki atlatma (not translated) | `missing-authz` | `app/routes.py:31` | require\_authorization, settings\_update çağrısından önce çalışıyor. |

## 6. Hardening notes

These notes are not vulnerabilities. They are improvements that raise security.

| Title | Location | Note |
|---|---|---|
| Konteyner root olarak çalışıyor | `Dockerfile` | Dockerfile'a bir USER satırı ekle. |
| Hata ayıklama \| &lt;b&gt;modu&lt;/b&gt; | `app/routes.py:6` | \`app.debug\` üretimde kapalı olmalı. |

## 7. Tool results (unverified)

> Deterministic tools produced these results. No agent verified them. They can contain false positives.

### 7.1 bandit (1)

Medium 1

| Severity | Rule | Title | Location | Class |
|---|---|---|---|---|
| Medium | `B506` | Hostile \| title with \`back\`ticks\`\` and &lt;script&gt;alert(1)&lt;/script&gt; | `app/config.py:7` | `deserialization` |

### 7.2 gitleaks (1)

High 1

| Severity | Rule | Title | Location | Class |
|---|---|---|---|---|
| High | `generic-api-key` | Generic API key | `app/config.py:3` | `hardcoded-secrets` |

## 8. Vulnerable dependencies (SCA)

> Manifests without a lockfile: 1. SCA checked only their exact pins. Section 2.6 lists them.

### 8.1 Malicious dependency

> [!CAUTION]
> **Package versions that match a known malicious package record (OSV `MAL-`, GitHub malware advisory): 1. The malicious code runs when the package is installed. Thus the reachability result does not matter, and the severity stays Critical.**
>
> Do these steps:
>
> 1. Remove the package and this version. Regenerate the lockfile.
> 2. Treat every machine that installed the package as exposed: developer machines, CI runners and build images.
> 3. Rotate the secrets that the install could read: CI secrets, tokens, cloud credentials and SSH keys.
> 4. Find the commit that added this version in the lockfile history. Check the builds after it.

| Package | Version | Ecosystem | Record IDs | Severity | Location |
|---|---|---|---|---|---|
| `sample-module` | `0.0.1` | PyPI | `MAL-2025-41758`, `GHSA-2g5x-c76j-3h73` | Critical | `requirements.txt` |

### 8.2 Known vulnerabilities

These records show known vulnerable dependencies. The reachability result can lower the severity.

Records from an exact pin in a manifest without a lockfile: 1. The table marks them with `manifest`.

Records from JavaScript files that the project copied into its tree (vendored): 1. No package manager lists these files. The table marks the records with `vendored`. Files:

- `web/static/js/jquery.min.js` (`jquery 1.12.4`)

| Package | Version | Ecosystem | Vulnerability ID | Severity | Fixed version | Reachability |
|---|---|---|---|---|---|---|
| `pyyaml` | `5.3` | PyPI | `GHSA-8q59-q68h-6hv4`, `CVE-2020-14343` | Critical | `5.4` | Reachable |
| `lodash` | `4.17.15` (manifest) | npm | `GHSA-p6mc-m468-83gw`, `CVE-2020-8203` | High | `4.17.19` | Unknown |
| `jquery` | `1.12.4` (vendored) | npm | `GHSA-jpcq-cgw6-v4j6`, `CVE-2020-11023` | Medium | `3.5.0` | Unknown |
| `requests` | `2.19.0` | PyPI | `GHSA-x84v-xcm2-53pg`, `CVE-2018-18074` | Low | `2.20.0` | Not reachable |

SBOM: `report/sbom.cdx.json` (CycloneDX 1.6), `report/sbom.spdx.json` (SPDX 2.3). Components: 5 (Syft 3, manifest pin 1, vendored JavaScript 1).

## Appendix A. Method and sources

### A.1 Method

- For each candidate finding, kalkan asks three questions: does the attacker control the input, does the flow cross a privilege boundary, is an effective mitigation missing.
- The verifier agent supports each answer with a quote from the source code.
- The engine looks for each quote in the source: the cited line and two lines before and after it. A quote that is not in the source does not count.
- The engine, not the agent, gives the verdict. Three established answers confirm the finding. One answer refuted with a quote rejects it. Otherwise the finding needs validation.
- Without a PoC run, a confirmed finding rests on static evidence. A passed PoC raises the confidence. When the verifier supplied the required fields, a passed PoC also confirms a finding that needs validation.
- Tool results and SCA records come from deterministic engines. They do not become findings without agent verification.

### A.2 Tool versions

| Tool | Version | Install kind |
|---|---|---|
| `bandit` | `1.9.4` | pip |
| `gitleaks` | `8.30.1` | binary |
| `opengrep` | `1.30.1` | binary |
| `osv-scanner` | `2.6.0` | binary |

### A.3 Run

| Field | Value |
|---|---|
| Run ID | `20261015T120000Z-shop-a1b2` |
| kalkan version | `0.0.0-golden` |
| Report date | 2026-10-15 12:30 UTC |
| Report files | `REPORT.md`, `REPORT.html`, `REPORT.en.md`, `REPORT.en.html`, `EXECUTIVE.html`, `EXECUTIVE.en.html`, `findings.sarif`, `findings.json`, `sbom.cdx.json`, `sbom.spdx.json`, `summary.json` |

### A.4 Warnings

- Files with an absolute path of 260 or more characters: 1. Opengrep may skip them without a warning: its core program is not long-path aware, also with LongPathsEnabled=1. Set KALKAN\_RUNS\_DIR to a short folder (for example C:/kr) and start a new run.

---

The Turkish version of this report is `REPORT.md`.
