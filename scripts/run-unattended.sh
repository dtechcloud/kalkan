#!/bin/sh
# SPDX-License-Identifier: MIT
#
# Run or resume a kalkan audit unattended (headless) on Linux and macOS (Git Bash on Windows
# also works). The script calls <repository root>/.venv/bin/kalkan unattended with all its
# arguments and passes the exit code through. kalkan unattended starts Claude Code headless in
# rounds from the repository root, waits through usage-limit resets, and stops when the audit
# is done (exit code 0), incomplete (exit code 1) or after --max-hours (exit code 1).
# A relative target path is relative to your current folder.
#
# Usage: sh scripts/run-unattended.sh <target | devam [RUN_ID]> [options]

set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(dirname -- "$script_dir")

usage() {
    cat <<'EOF'
Usage: scripts/run-unattended.sh <target | devam [RUN_ID]> [options]

Run or resume a kalkan audit headless. The script waits through usage-limit resets.

  <target>               local folder or git URL to audit (creates a new run)
  devam RUN_ID           resume this run
  devam                  resume the run in runs/LATEST
  --run RUN_ID           with devam: the run to resume
  --profile NAME         fast, standard (default) or deep
  --no-latest            new run only: keep runs/LATEST unchanged
  --max-hours N          stop after N hours in total (default: 24)
  --round-hours N        stop one host round after N hours (default: 6)
  --host NAME            claude (default) or codex
  --log-dir DIR          folder of the log file (default: runs)
  --dry-run              print the command lines and start nothing
  --json                 print the result as JSON
  -h, --help             show this text

All options: .venv/bin/kalkan unattended --help
EOF
}

if [ "$#" -eq 0 ]; then
    usage >&2
    exit 2
fi
for arg in "$@"; do
    case "$arg" in
        -h | --help)
            usage
            exit 0
            ;;
    esac
done

if [ -x "$repo_root/.venv/bin/kalkan" ]; then
    kalkan="$repo_root/.venv/bin/kalkan"
elif [ -f "$repo_root/.venv/Scripts/kalkan.exe" ]; then
    kalkan="$repo_root/.venv/Scripts/kalkan.exe"
else
    printf 'run-unattended: error: %s was not found. Set up kalkan first: sh scripts/bootstrap.sh\n' \
        "$repo_root/.venv/bin/kalkan" >&2
    exit 1
fi

exec "$kalkan" unattended "$@"
