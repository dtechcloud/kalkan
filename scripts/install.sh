#!/bin/sh
# SPDX-License-Identifier: MIT
#
# Install or update kalkan as a Claude Code plugin with one command, on Linux and macOS (Git
# Bash on Windows also works; PowerShell uses scripts/install.ps1). Run it again at any time:
# every step checks what is there first.
#
#   1. Check git, Python 3.11 or later and the Claude Code CLI (signed in), and that git can
#      read the repository.
#   2. Add the kalkan marketplace (claude plugin marketplace add dtechcloud/kalkan#stable), or
#      update it when it is there (claude plugin marketplace update kalkan).
#   3. Install the plugin for your user (claude plugin install kalkan@kalkan --scope user), or
#      update it (claude plugin update kalkan@kalkan).
#   4. Run the plugin setup kalkan-setup: the engine venv, the pinned scanners, the local
#      vulnerability databases and kalkan doctor (5 to 15 minutes the first time).
#   5. Print the command that audits a project.
#
# Usage: sh scripts/install.sh [--dry-run] [--source SOURCE] [--skip-setup]
#
# Without a checkout:
#   curl -fsSL https://raw.githubusercontent.com/dtechcloud/kalkan/stable/scripts/install.sh | sh
# Options through the pipe: ... | sh -s -- --dry-run
#
# Exit codes: 0 done, 1 a check or a step failed (the message names the fix), 2 usage.

set -eu

REPO=dtechcloud/kalkan
MARKETPLACE=kalkan
PLUGIN=kalkan@kalkan
DATA_ID=kalkan-kalkan

source=$REPO#stable # the tested releases; main holds the newest changes
dry_run=no
skip_setup=no

usage() {
    cat <<'EOF'
Usage: sh scripts/install.sh [--dry-run] [--source SOURCE] [--skip-setup]

Install or update kalkan as a Claude Code plugin: the marketplace, the plugin (user scope),
the pinned scanners and the vulnerability databases. Run it again to update.

  --dry-run          run only the checks; print every command that would change something
  --source SOURCE    marketplace source (default: dtechcloud/kalkan#stable; also a local path
                     or another GitHub source that Claude Code accepts)
  --skip-setup       leave out kalkan-setup (the next /kalkan in Claude Code runs it)
  -h, --help         show this text
EOF
}

say() {
    printf '==> %s\n' "$*"
}

note() {
    printf '    %s\n' "$*"
}

warn() {
    printf 'kalkan install: warning: %s\n' "$*" >&2
}

fail() {
    printf 'kalkan install: error: %s\n' "$*" >&2
    exit 1
}

while [ "$#" -gt 0 ]; do
    case $1 in
        --dry-run) dry_run=yes ;;
        --skip-setup) skip_setup=yes ;;
        --source)
            if [ "$#" -lt 2 ]; then
                usage >&2
                exit 2
            fi
            source=$2
            shift
            ;;
        --source=*) source=${1#--source=} ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            printf 'kalkan install: error: unknown option: %s\n' "$1" >&2
            usage >&2
            exit 2
            ;;
    esac
    shift
done

# Run a command that changes something. A dry run prints it instead.
change() {
    if [ "$dry_run" = yes ]; then
        printf 'dry run: would run:'
        printf ' %s' "$@"
        printf '\n'
        return 0
    fi
    "$@"
}

# ---------------------------------------------------------------------------------------------
# 1. Checks

say "Check git"
command -v git >/dev/null 2>&1 ||
    fail "git is not installed. Install it (https://git-scm.com/downloads), then run this installer again."
note "$(git --version 2>&1)"

say "Check Python 3.11 or later"
version_check='import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)'
find_python() {
    for candidate in python3 python; do
        if command -v "$candidate" >/dev/null 2>&1 &&
            "$candidate" -c "$version_check" >/dev/null 2>&1; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    if command -v py >/dev/null 2>&1 && py -3 -c "$version_check" >/dev/null 2>&1; then
        printf '%s\n' "py -3"
        return 0
    fi
    return 1
}
py=$(find_python) ||
    fail "Python 3.11 or later was not found. Install it (https://www.python.org/downloads/), then run this installer again."
# $py is "py -3" or one command name: word splitting is intended here.
# shellcheck disable=SC2086
note "$($py --version 2>&1)"

# The JSON answers of the Claude Code CLI, read with Python (no jq needed).
JSON_HELPER='import json, sys
query = sys.argv[1]
wanted = sys.argv[2] if len(sys.argv) > 2 else ""
try:
    data = json.loads(sys.stdin.read() or "null")
except ValueError:
    data = None
items = [item for item in data if isinstance(item, dict)] if isinstance(data, list) else []
if query == "logged-in":
    value = data.get("loggedIn") if isinstance(data, dict) else None
    print("yes" if value is True else "no" if value is False else "unknown")
elif query == "config-dir":
    value = data.get("configDirectory") if isinstance(data, dict) else None
    print(value.replace("\\", "/") if isinstance(value, str) else "")
elif query == "has-marketplace":
    print("yes" if any(item.get("name") == wanted for item in items) else "no")
elif query == "has-plugin":
    print("yes" if any(item.get("id") == wanted for item in items) else "no")
elif query == "install-path":
    found = [item for item in items if item.get("id") == wanted]
    found.sort(key=lambda item: item.get("scope") != "user")
    paths = [item.get("installPath") for item in found]
    print(next((p.replace("\\", "/") for p in paths if isinstance(p, str) and p), ""))
'
json_query() {
    # shellcheck disable=SC2086
    $py -c "$JSON_HELPER" "$@"
}

say "Check the Claude Code CLI"
command -v claude >/dev/null 2>&1 ||
    fail "the Claude Code CLI (claude) is not on PATH. Install Claude Code, sign in with: claude auth login, then run this installer again."
note "$(claude --version 2>&1 | head -n 1)"
auth=$(claude auth status --json 2>/dev/null) || true
case $(printf '%s' "$auth" | json_query logged-in) in
    yes) note "signed in" ;;
    no) fail "Claude Code is not signed in. Run: claude auth login. Then run this installer again." ;;
    *) warn "cannot read the login state (claude auth status). If Claude Code asks you to sign in later, run: claude auth login" ;;
esac
config=$(printf '%s' "$auth" | json_query config-dir)
[ -n "$config" ] || config=${CLAUDE_CONFIG_DIR:-$HOME/.claude}
# CLAUDE_CODE_PLUGIN_CACHE_DIR moves the plugins root (cache, marketplaces and data) of Claude Code.
plugins_root=${CLAUDE_CODE_PLUGIN_CACHE_DIR:-$config/plugins}
data=$plugins_root/data/$DATA_ID

github_repo=
case $source in
    *://* | /* | ./* | ../* | "~"* | [A-Za-z]:*) ;; # a URL or a local path
    */*) github_repo=${source%%[#@]*} ;;
esac
if [ -n "$github_repo" ] && [ -e "$source" ]; then
    github_repo= # a local folder that looks like owner/repo
fi
if [ -n "$github_repo" ]; then
    say "Check that git can read the kalkan repository"
    if GIT_TERMINAL_PROMPT=0 git ls-remote --exit-code "https://github.com/$github_repo.git" HEAD >/dev/null 2>&1; then
        note "git can read https://github.com/$github_repo"
    elif GIT_TERMINAL_PROMPT=0 GIT_SSH_COMMAND="ssh -o BatchMode=yes" git ls-remote --exit-code "git@github.com:$github_repo.git" HEAD >/dev/null 2>&1; then
        note "git can read git@github.com:$github_repo"
    else
        fail "git cannot read https://github.com/$github_repo.git. When the repository needs a GitHub login, run: gh auth login, then gh auth setup-git. Then run this installer again."
    fi
fi

# ---------------------------------------------------------------------------------------------
# 2. Marketplace and plugin

say "Add or update the kalkan marketplace"
markets=$(claude plugin marketplace list --json 2>/dev/null) || markets="[]"
if [ "$(printf '%s' "$markets" | json_query has-marketplace "$MARKETPLACE")" = yes ]; then
    change claude plugin marketplace update "$MARKETPLACE" ||
        fail "claude plugin marketplace update $MARKETPLACE failed (see above). Run this installer again."
else
    change claude plugin marketplace add "$source" ||
        fail "claude plugin marketplace add $source failed (see above). When the repository needs a GitHub login, run: gh auth setup-git. Then run this installer again."
fi

say "Install or update the kalkan plugin (user scope)"
plugins=$(claude plugin list --json 2>/dev/null) || plugins="[]"
if [ "$(printf '%s' "$plugins" | json_query has-plugin "$PLUGIN")" = yes ]; then
    change claude plugin update "$PLUGIN" ||
        fail "claude plugin update $PLUGIN failed (see above). Run this installer again."
else
    change claude plugin install "$PLUGIN" --scope user ||
        fail "claude plugin install $PLUGIN failed (see above). Run this installer again."
fi

# ---------------------------------------------------------------------------------------------
# 3. Setup: engine, scanners, databases, doctor

say "Set up the engine, the pinned scanners and the vulnerability databases (kalkan-setup)"
plugins=$(claude plugin list --json 2>/dev/null) || plugins="[]"
root=$(printf '%s' "$plugins" | json_query install-path "$PLUGIN")
if [ "$skip_setup" = yes ]; then
    note "skipped (--skip-setup): the next /kalkan in Claude Code runs it"
elif [ -z "$root" ]; then
    if [ "$dry_run" = yes ]; then
        change sh "<plugin folder>/bin/kalkan-setup" "$data"
    else
        fail "cannot find the installed kalkan plugin (claude plugin list --json). Run this installer again."
    fi
elif [ ! -f "$root/bin/kalkan-setup" ] && [ "$dry_run" = no ]; then
    fail "the plugin folder $root has no bin/kalkan-setup. Update the plugin: claude plugin update $PLUGIN"
else
    note "this takes 5 to 15 minutes the first time and about 2 seconds later"
    change sh "$root/bin/kalkan-setup" "$data" ||
        fail "kalkan-setup failed (see above). Run this installer again; installed tools are kept."
fi

# ---------------------------------------------------------------------------------------------
# 4. The audit command

say "Done. Audit a project with one command:"
note "sh \"$data/bin/kalkan-audit\" <folder or git URL>"
case $data in
    [A-Za-z]:*) note "PowerShell: & \"$data/bin/kalkan-audit.cmd\" <folder or git URL>" ;;
esac
note "Options: --profile fast|standard|deep, --tools-only (no Claude Code), --open, --yes"
note "Resume a stopped audit: sh \"$data/bin/kalkan-audit\" devam <run-id>"
note "Reports: ~/kalkan-runs/<run-id>/report/. Restart Claude Code to use /kalkan in a session."
