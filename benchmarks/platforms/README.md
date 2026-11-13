# Platform checks

Each folder here is the result of `scripts/platform_check.sh` on one machine: does every kalkan tool work on that operating system and processor? The check audits no project of the person who runs it. It uses the planted test targets of this repository only.

## Run the check (macOS or Linux)

You need git, curl, Python 3.11 or later and about 8 GB of free disk. Docker is optional: when it runs, the check pulls the two sandbox base images (`python:3.12-slim` and `mcr.microsoft.com/dotnet/sdk:10.0`, about 1 GB) and tests the PoC sandbox. For `--pr`, you also need the GitHub CLI (`gh`), signed in.

1. Clone the repository. A ZIP download does not work: the check needs git.

   ```sh
   git clone https://github.com/dtechcloud/kalkan.git
   cd kalkan
   ```

2. Run the check and open a pull request with the result:

   ```sh
   sh scripts/platform_check.sh --pr
   ```

   Without `--pr`, the result stays on your machine in `platform-check/<os>-<arch>-<date>/`. Send the `.tar.gz` next to that folder to the maintainers.

The check takes about 1 hour. Most of the time goes to the downloads (the 22 pinned tools and about 3.7 GB of vulnerability databases) and to the tool tests. A second run with `--skip-bootstrap` uses the installed tools.

macOS: clone the repository outside Desktop and Documents, for example into `~/kalkan`. On one Mac, the files of `.venv` below `~/Desktop` were hidden, Python 3.13 skipped the hidden `.pth` file of the install, and kalkan could not be imported. `scripts/bootstrap.sh` now stops with this explanation.

macOS: the first start of a downloaded tool can show a Gatekeeper dialog. If a tool fails with "cannot be opened", write that in the pull request.

## What the check does

| Step | Command | Shows |
|---|---|---|
| bootstrap | `scripts/bootstrap.sh` | every pinned tool installs, with its SHA-256 check |
| doctor | `kalkan doctor --json` | the tool versions, the databases, git, Docker and Claude Code |
| tool-tests | `pytest -m tools` | every tool finds the planted items of the test fixtures |
| docker-pull | `kalkan sandbox pull` | the base images of the sandbox (only when Docker runs) |
| docker-tests | `pytest -m docker` | the PoC sandbox (only when Docker runs) |
| benchmark | `benchmarks/run_benchmark.py --target vulnapp` | the full deterministic pipeline: scan, SBOM, SCA, merge, report |

`scripts/platform_report.py` then writes `SUMMARY.md`:

- **PASS**: every step ended with exit code 0, no tool test failed or was skipped, and every engine has the status `ok` on the vulnapp fixture.
- **INCOMPLETE**: nothing failed, but a tool test was skipped (a missing tool, database or git), a step did not run, or Docker runs but the sandbox tests were skipped (a base image could not be pulled).
- **FAIL**: a step, a doctor check, a tool test or an engine failed.

The summary compares the engine results with the committed Windows 11 result (`benchmarks/results/vulnapp.json`).

## Privacy

The result holds no project of yours and no audit report. Before the summary, the script replaces your home folder with `~`, your host name with `[host]` and your user name in a path (for example `pytest-of-<you>`) with `[user]` in every result file. Read `SUMMARY.md` before you open the pull request if you want to make sure.

## Pull request contents

`--pr` makes a branch `platform-check/<name>` and commits `benchmarks/platforms/<name>/` with `SUMMARY.md`, `doctor.json`, the JUnit files of the tests, `benchmark-vulnapp.json` and the last 300 lines of the log of each failed step. When you cannot push to the repository, the GitHub CLI makes a fork first. The CI of a pull request from a fork waits for a maintainer's approval.
