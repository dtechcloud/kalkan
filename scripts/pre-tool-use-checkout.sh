#!/bin/sh
# SPDX-License-Identifier: MIT
#
# PreToolUse hook launcher of a kalkan checkout (.claude/settings.json, docs/SECURITY.md). It
# runs `python -I -m kalkan.plugin_hook` in the .venv of the checkout with KALKAN_HOOK_CHECKOUT
# set, so the hook decides only for the kalkan subagents (project agents kalkan-<role>): reads
# stay in the target/ and tasks/ folders of their run, the only write is the result file of the
# bound task, and .env files are never read. The orchestrator and every other session follow
# the normal permission flow. Before, checkout mode had no hook, and a prompt-injected subagent
# could read any operator file and write the result of any task (self-audit of 2026-11-13).
#
# The launcher prints nothing and exits 0 (the normal permission flow decides) when the event
# comes from no kalkan subagent. When the checkout has no .venv yet, a kalkan subagent call is
# denied: the subagents never run without their confinement.

root=${CLAUDE_PROJECT_DIR:-}
[ -n "$root" ] || exit 0

input=$(cat)
case $input in
    *'"agent_type"'*'"kalkan-'*) ;;
    *) exit 0 ;;
esac

python=""
for candidate in "$root/.venv/Scripts/python.exe" "$root/.venv/bin/python"; do
    if [ -f "$candidate" ]; then
        python=$candidate
        break
    fi
done
if [ -z "$python" ]; then
    printf '%s\n' '{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": "kalkan subagent: the checkout has no .venv, so the permission check cannot run; run the bootstrap script first"}}'
    exit 0
fi

printf '%s' "$input" | KALKAN_HOOK_CHECKOUT=$root "$python" -I -m kalkan.plugin_hook
exit 0
