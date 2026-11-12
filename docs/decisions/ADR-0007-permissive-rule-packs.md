# ADR-0007: Rule packs with free licenses replace the opengrep-rules pack
English | [Türkçe](ADR-0007-permissive-rule-packs.tr.md)

- Status: accepted
- Date: 2026-11-07
- Decided by: the project owner
- Related: ADR-0005 (rule packs, K.8, and its license policy; this decision extends it)

## Context

On 2026-11-06, kalkan removed the opengrep-rules pack (461 kept rules). Its license is LGPL-2.1 with the Commons Clause, and the Commons Clause forbids paid consulting and support services that take their value from the rules. On the vulnapp fixture, 17 planted items lost their only pack result. kalkan's own rules still found all 17.

The project owner asked for replacement rules with a free license: redistribution in an MIT repository and commercial use, paid consulting included, must be allowed. A survey on 2026-11-07 read the LICENSE of every candidate at its repository. No single free pack covers as many languages as the removed pack.

## Decision

1. kalkan vendors seven more packs, each as a separate component in `third_party/` with its license files:

   | Pack | Upstream | License | Kept rules |
   |---|---|---|---|
   | `atlassian` | atlassian-labs/atlassian-sast-ruleset | LGPL-2.1-only | 31 |
   | `elttam` | elttam/semgrep-rules | MIT | 28 |
   | `njsscan` | ajinabraham/njsscan | LGPL-3.0-or-later | 41 |
   | `mobsfscan` | MobSF/mobsfscan | LGPL-3.0-or-later | 73 |
   | `mindedsecurity` | mindedsecurity/semgrep-rules-android-security | GPL-3.0-only | 25 |
   | `aikido` | AikidoSec/opengrep-rules | MIT | 2 |
   | `semgrep-codeql` | andrew/semgrep-codeql | MIT (converted from github/codeql, MIT) | 28 |

2. All seven packs are in the license group `osi`. LGPL and GPL are OSI-approved and allow commercial use. `KALKAN_RULE_PACKS=osi` still turns off only the AGPL pack.
3. The copyleft packs stay in their own folders with their license texts. Their changed bundles in `rules/opengrep-packs/<pack>/` keep the license of the pack, and their source is in this repository.
4. Rule files whose header names another source are left out: Semgrep's semgrep-rules repository (no license before 2020-10-29, the Commons Clause after) and the GPL-3.0 mindedsecurity rules inside mobsfscan. That is 14 files of njsscan and mobsfscan.
5. Each pin is at least 14 days old on the pin day 2026-11-07 (ADR-0005, rule 1). For njsscan and mobsfscan, kalkan pins the last commit before 2026-10-24.
6. The curation keeps only security rules with a clear class. It drops hardening advice and good-control markers (kind `best-practice`), review markers without data flow (`audit`), Kubernetes and GitHub Actions rules that Trivy, Checkov, zizmor and actionlint already check (`covered`), code quality rules (`non-security`), noisy rules (`noisy`), the join-mode rule that Opengrep 1.30.1 rejects (`parse`), and rules that report a secure twin of vulnapp (`twin-fp`). The automatic duplicate check drops 57 rules that repeat a GitLab port, and the drop kind `duplicate` names 6 more whose pattern changed after the port.
7. The rules of semgrep-codeql came from an LLM conversion and have no tests upstream. The new curation key `keep_only` keeps only the 28 rules that found a planted vulnapp item without touching a secure twin or other code. The other 259 rules are dropped with the kind `unmeasured`. The GitHub Actions, secret and C rules of that pack are left out too, because zizmor, Gitleaks, Kingfisher, flawfinder and the 0xdea pack cover them.
8. The root `NOTICE` names each new component and repeats the GitHub copyright notice of the CodeQL queries.

## Consequences

- The packs hold 733 kept rules in 55 bundles (505 before). With kalkan's own 106 rules, Opengrep runs 839 rules.
- On vulnapp, 34 planted items have a pack result (18 before). 8 of the 17 items that the removal lost have a pack result again, all through semgrep-codeql. Nothing touches a secure twin, and the results outside the planted items stay the same 3. The adapter run takes 17.6 s (the three earlier packs alone: 14.7 s).
- The semgrep-codeql subset is chosen on vulnapp, so its result on vulnapp is no independent measurement. A benchmark on other targets must confirm its value.
- Gaps that stay open: Python SSRF, JavaScript SSTI and XXE, Go XSS, Java XXE, PHP SQL injection and command injection, Ruby command injection and open redirect, and Solidity (no free Solidity pack was found).
- `curation.json` and `scripts/build_opengrep_packs.py` gain `keep_only` and the drop kind `unmeasured`.
