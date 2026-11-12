# benchmarks

Benchmarks of the deterministic kalkan pipeline (phase 8, task 8.3): OWASP Juice Shop, DVWA and the fixture repository `tests/fixtures/vulnapp`. The latest numbers are in `results/SUMMARY.md`.

## Run

```
python benchmarks/run_benchmark.py                    # all targets
python benchmarks/run_benchmark.py --target vulnapp   # one target: juice-shop, dvwa or vulnapp
python benchmarks/run_benchmark.py --offline          # cached databases, existing clones only
```

The script uses the standard library only. It starts every kalkan command through the repository `.venv` (`python -m kalkan ... --json`). Set up the venv and the pinned scanners first (`scripts/bootstrap.ps1` or `scripts/bootstrap.sh`).

## What it measures

The benchmark covers the deterministic part only. No LLM runs, and no target code runs. For each target the script does these steps and measures the wall time of each step:

1. Prepare the source folder (see "Targets").
2. `kalkan run init <source>`
3. `kalkan scan all`
4. `kalkan sca sbom`
5. `kalkan sca match`
6. `kalkan merge`
7. `kalkan report`

The network is used only for the git fetch. The scan and SCA steps run in local mode, the kalkan default (`docs/SECURITY.md`, promise 3): they read the local vulnerability databases of `kalkan sca update-db` and use no network. With `--offline`, the script uses existing clones only and passes `--offline` to the scan and SCA steps (kalkan accepts the flag, and it changes nothing).

## Isolation

Every kalkan command runs with `KALKAN_RUNS_DIR=<repo>/.bench-runs`. The default `runs/` folder and its `LATEST` pointer stay untouched, so a live audit can run at the same time. The `.bench-runs/` folder holds:

- `<run-id>/`: the kalkan runs of the benchmark.
- `_src/<target>/`: the source folders (git clones and the fixture copy).
- `_logs/<target>/<step>.stdout.txt` and `.stderr.txt`: the output of each step.

The folder name is short on purpose. On Windows, Opengrep skips files whose absolute path has 260 or more characters, without a message (ENGINE-SPEC section 10). `run init` records such files in `long_paths`, and the Opengrep status file lists them in `skipped_files`.

## Targets

`targets.json` pins every target. A git target is fetched at the pinned commit with its full history (`git init`, then `git fetch <url> <commit>`), and `kalkan run init` gets the local folder. `run init <url> --ref <commit>` can pin a ref too, but it clones again on every run; the local folder is reused. The history scan (`gitleaks-history`) thus covers the history of the pinned commit only. The clone sets `core.symlinks=false`, `core.longpaths=true` and `core.autocrlf=false`. A clone at the pinned commit is reused on the next run.

The fixture target is copied without its answer files (`README.md`, `EXPECTED.json`, `INJECTION-NOTE.md`).

The source folders are below the kalkan repository. Thus the script renames the agent instruction files and folders of each source folder (`CLAUDE.md`, `AGENTS.md`, `.claude/`, `.cursor/` and the other names of ENGINE-SPEC section 10) with the suffix `.kalkan-neutralized`, as `kalkan run init` does in its copy. Without this step, an agent session in the repository could load them, and `tests/test_repo_hygiene.py` fails. The result file lists the renamed paths in `prepare.neutralized`.

To move a pin, resolve the new commit with `git ls-remote <url>` (for an annotated tag, use the peeled `^{}` line) and update `targets.json`.

## Result files

`results/<target>.json` holds:

| Field | Content |
|---|---|
| `kalkan`, `tools`, `host` | kalkan version and commit, pinned tool versions from `.tools/installed.json`, platform |
| `target_ref` | URL, tag, commit, and the `git_ref` that `run init` recorded |
| `steps` | command, exit code and wall time of each step |
| `files`, `excluded`, `tech`, `long_paths` | from `target-manifest.json` |
| `engines` | status, duration, exit code, tool version and candidate count of each engine (`scans/*.status.json`, `sca/*.status.json`); for Opengrep also the files scanned, partially analyzed and skipped with the skip reasons (`files_scanned`, `partial_files`, `skipped_files` of its status file; an older run falls back to the stderr summary) |
| `candidates` | candidates by engine, class and severity (`candidates.json`) |
| `sca` | SBOM components, raw records per matcher (also `osv-scanner-pins` and `grype-pins`), merged records by severity, engine set and ecosystem (`sca/vulns.json`); `manifest_pins` and `pin_records`: the exact pins of manifests without a lockfile and the merged records found through them (`pin_source: manifest`) |
| `merge`, `report` | the merge summary and the sizes of the report files |
| `dependency_manifests` | manifests without a lockfile, from `unchecked_manifests` of `sca/vulns.json` (`kalkan.sca.manifests`; an older run falls back to a folder walk). SCA checks only their exact pins, not their version ranges or transitive dependencies |
| `fixture` | fixture targets only: recall per engine and false positives on the secure twins |

`results/SUMMARY.md` is a short table across all result files. The script writes it again after each run.

## Fixture scoring

The scoring uses `EXPECTED.json` and the match rules of the fixture README.

- **Found.** A candidate of the engine is in the same file, and its start line is within 2 lines of the item line. The `found` count also accepts a candidate region that covers the line (Checkov and Trivy report whole resources). The `found_pm2` count uses the 2-line rule only.
- **Dependency items.** They match by ecosystem, package and version in `sca/vulns.json`, for each SCA engine separately.
- **Agent-only items.** Items whose only expected engine is `hunter` are not scored.
- **Twin false positive (`twin_fp`).** For kalkan's own rules (`opengrep`, `matcher`), any result near a secure twin counts. For the other engines, only a result with a rule ID of the vulnerable counterpart counts. A dependency twin counts when its package has a vulnerability record.
- **`twin_hits_any_rule`.** Twins with any result of the engine within 2 lines, whatever the rule.
- **`unplanned_results`.** Results that are not near any planted item or twin.

## Known limits

- gosec and govulncheck need a Go toolchain. `kalkan tools install --all` installs the pinned Go (the manifest tool `go`). Without it, both engines are skipped, and their expected items count as missed for that engine.
- SCA numbers change when the vulnerability databases change. Compare SCA counts only between runs of the same day.
- A manifest without a lockfile (Juice Shop sets `package-lock=false` in `.npmrc`) gives SCA records only for its exact pins. Its version ranges and transitive dependencies stay unchecked; `SUMMARY.md` lists such manifests under "Problems".
- Wall times depend on the host, the disk and the cache state of the tools.
