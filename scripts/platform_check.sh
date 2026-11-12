#!/bin/sh
# SPDX-License-Identifier: MIT
#
# Platform check: does every kalkan tool work on this machine? (macOS and Linux)
#
#   git clone https://github.com/dtechcloud/kalkan.git
#   cd kalkan
#   sh scripts/platform_check.sh          # check only; the result stays on this machine
#   sh scripts/platform_check.sh --pr     # check, then open a pull request with the result
#
# The check audits no project of yours. It uses the test targets of the repository only:
#   1. bootstrap      scripts/bootstrap.sh: .venv, the 22 pinned tools, the vulnerability
#                     databases (about 3.7 GB), kalkan doctor
#   2. doctor         kalkan doctor --json
#   3. dev-install    pip install -e ".[dev]" (pytest)
#   4. tool-tests     pytest -m tools: every tool on the planted test fixtures
#   5. docker-tests   pytest -m docker: the PoC sandbox (only when Docker runs)
#   6. benchmark      the deterministic pipeline on the vulnapp fixture (scan, SCA, merge, report)
#   7. report         scripts/platform_report.py: SUMMARY.md, verdict PASS, INCOMPLETE or FAIL
#
# Time: about 1 hour, mostly the downloads of step 1 and the tests of step 4. Disk: about 8 GB.
# The result folder is platform-check/<os>-<arch>-<date>/ with a .tar.gz next to it. Personal
# data is removed from it: the home folder becomes ~ and the host name becomes [host].
#
# Options:
#   --pr               open a pull request on dtechcloud/kalkan with the result (needs the
#                      GitHub CLI "gh", signed in; a fork is made when you cannot push)
#   --skip-bootstrap   use the existing .venv and tools (a second run)
#   --no-docker        skip the Docker tests even when Docker runs
#   -h, --help         show this text
#
# Exit code: 0 PASS, 1 FAIL or INCOMPLETE, 2 a precondition is missing.

set -u

UPSTREAM=dtechcloud/kalkan
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(dirname -- "$script_dir")
cd "$repo_root" || exit 2

open_pr=0
skip_bootstrap=0
use_docker=1
for arg in "$@"; do
    case "$arg" in
        --pr) open_pr=1 ;;
        --skip-bootstrap) skip_bootstrap=1 ;;
        --no-docker) use_docker=0 ;;
        -h | --help)
            sed -n '3,33p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            printf 'platform_check: unknown option: %s (see --help)\n' "$arg" >&2
            exit 2
            ;;
    esac
done

say() {
    printf '\n==> %s\n' "$*"
}

stop() {
    printf 'platform_check: %s\n' "$*" >&2
    exit 2
}

# --- preconditions ----------------------------------------------------------------------------

[ -d .git ] || stop "run this in a git clone of the repository (git clone https://github.com/$UPSTREAM.git), not in a ZIP download."
command -v git >/dev/null 2>&1 || stop "git was not found. On macOS: xcode-select --install"
command -v curl >/dev/null 2>&1 || stop "curl was not found."
base_python=""
for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1 &&
        "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null; then
        base_python=$candidate
        break
    fi
done
[ -n "$base_python" ] || [ -x .venv/bin/python ] ||
    stop "Python 3.11 or later was not found. On macOS: brew install python@3.13 (or python.org)."
free_kb=$(df -Pk . | awk 'NR == 2 {print $4}')
if [ -n "$free_kb" ] && [ "$free_kb" -lt 8000000 ]; then
    stop "less than 8 GB free on this disk ($((free_kb / 1024 / 1024)) GB). The tools and databases need about 6 GB."
fi
if [ "$open_pr" -eq 1 ]; then
    command -v gh >/dev/null 2>&1 || stop "--pr needs the GitHub CLI: brew install gh, then gh auth login"
    gh auth status >/dev/null 2>&1 || stop "--pr needs a signed-in GitHub CLI: gh auth login"
    git config user.email >/dev/null 2>&1 || stop "--pr needs a git identity: git config --global user.email <you@example.com>"
    if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
        stop "--pr needs a clean working tree (git status shows changes)."
    fi
fi

os_name=$(uname -s | tr '[:upper:]' '[:lower:]')
[ "$os_name" = darwin ] && os_name=macos
arch=$(uname -m)
stamp=$(date -u +%Y%m%d-%H%M)
name="$os_name-$arch-$stamp"
out="$repo_root/platform-check/$name"
mkdir -p "$out/logs" "$out/benchmark" || stop "cannot create $out"
: >"$out/steps.tsv"
py="$repo_root/.venv/bin/python"

# run_step NAME COMMAND...: run a command, keep its log and its exit code.
run_step() {
    step=$1
    shift
    say "$step: $*"
    started=$(date +%s)
    "$@" >"$out/logs/$step.log" 2>&1
    code=$?
    seconds=$(($(date +%s) - started))
    printf '%s\t%s\t%s\n' "$step" "$code" "$seconds" >>"$out/steps.tsv"
    if [ "$code" -eq 0 ]; then
        printf '    ok (%s s)\n' "$seconds"
    else
        printf '    exit code %s (%s s); the last lines of logs/%s.log:\n' "$code" "$seconds" "$step"
        tail -n 15 "$out/logs/$step.log" | sed 's/^/    | /'
    fi
    return "$code"
}

printf 'kalkan platform check -> %s\n' "$out"

# --- steps ------------------------------------------------------------------------------------

if [ "$skip_bootstrap" -eq 1 ] && [ -x "$py" ]; then
    printf 'bootstrap\t0\t0\n' >>"$out/steps.tsv"
    say "bootstrap: skipped (--skip-bootstrap)"
else
    run_step bootstrap sh scripts/bootstrap.sh
fi
[ -x "$py" ] || stop "the bootstrap made no .venv; read $out/logs/bootstrap.log"

say "doctor: kalkan doctor --json"
started=$(date +%s)
"$py" -m kalkan doctor --json >"$out/doctor.json" 2>"$out/logs/doctor.log"
code=$?
printf 'doctor\t%s\t%s\n' "$code" "$(($(date +%s) - started))" >>"$out/steps.tsv"
printf '    exit code %s\n' "$code"

run_step dev-install "$py" -m pip install --disable-pip-version-check -q -e ".[dev]"

run_step tool-tests "$py" -m pytest -m tools -p no:cacheprovider -rfEs \
    --junitxml="$out/tools-junit.xml" tests

if [ "$use_docker" -eq 1 ] && command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    run_step docker-tests "$py" -m pytest -m docker -p no:cacheprovider -rfEs \
        --junitxml="$out/docker-junit.xml" tests
else
    say "docker-tests: skipped (Docker is not running, or --no-docker)"
fi

git show HEAD:benchmarks/results/vulnapp.json >"$out/reference-vulnapp.json" 2>/dev/null
run_step benchmark "$py" benchmarks/run_benchmark.py --target vulnapp
cp benchmarks/results/vulnapp.json "$out/benchmark/vulnapp.json" 2>/dev/null
cp benchmarks/results/SUMMARY.md "$out/benchmark/SUMMARY.md" 2>/dev/null
# The benchmark writes into the tracked results folder: put the committed files back.
git checkout -- benchmarks/results 2>/dev/null

say "report"
"$py" scripts/platform_report.py "$out"
verdict_code=$?
verdict=$(sed -n '1s/.*: //p' "$out/SUMMARY.md")
tar -czf "$out.tar.gz" -C "$repo_root/platform-check" "$name"
printf '\nResult: %s\n  %s/SUMMARY.md\n  %s.tar.gz (send this file if you do not open a pull request)\n' \
    "$verdict" "$out" "$out"

# --- pull request -----------------------------------------------------------------------------

if [ "$open_pr" -eq 1 ]; then
    say "pull request"
    branch="platform-check/$name"
    dest="benchmarks/platforms/$name"
    start_ref=$(git rev-parse --abbrev-ref HEAD)
    git switch -q -c "$branch" || stop "cannot create the branch $branch"
    mkdir -p "$dest"
    for file in SUMMARY.md doctor.json tools-junit.xml docker-junit.xml; do
        [ -f "$out/$file" ] && cp "$out/$file" "$dest/$file"
    done
    [ -f "$out/benchmark/vulnapp.json" ] && cp "$out/benchmark/vulnapp.json" "$dest/benchmark-vulnapp.json"
    # The log of each failed step, last 300 lines (already redacted).
    while IFS="$(printf '\t')" read -r step code seconds; do
        if [ "$code" != 0 ] && [ -f "$out/logs/$step.log" ]; then
            tail -n 300 "$out/logs/$step.log" >"$dest/$step.log"
        fi
    done <"$out/steps.tsv"
    title="Platform check: $(sed -n '1s/^# Platform check: //p' "$out/SUMMARY.md")"
    git add "$dest"
    git commit -q -m "$title" -m "Result of scripts/platform_check.sh. Details: $dest/SUMMARY.md." ||
        stop "git commit failed"

    permission=$(gh repo view "$UPSTREAM" --json viewerPermission --jq .viewerPermission 2>/dev/null)
    case "$permission" in
        ADMIN | MAINTAIN | WRITE)
            remote=origin
            head="$branch"
            ;;
        *)
            gh repo fork "$UPSTREAM" --remote --remote-name fork >/dev/null 2>&1 ||
                git remote get-url fork >/dev/null 2>&1 ||
                stop "cannot fork $UPSTREAM; the result is committed on the local branch $branch"
            remote=fork
            head="$(gh api user --jq .login):$branch"
            ;;
    esac
    git push -q -u "$remote" "$branch" || stop "git push to $remote failed; the result is on the local branch $branch"
    gh pr create --repo "$UPSTREAM" --base main --head "$head" --title "$title" \
        --body-file "$out/SUMMARY.md" || stop "gh pr create failed; the branch $branch is pushed to $remote"
    git switch -q "$start_ref"
fi

exit "$verdict_code"
