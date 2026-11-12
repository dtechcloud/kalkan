#!/bin/sh
# SPDX-License-Identifier: MIT
#
# PreToolUse hook launcher of the kalkan Claude Code plugin (hooks/hooks.json, docs/PLUGIN.md,
# docs/SECURITY.md). It runs `python -I -m kalkan.plugin_hook` in the engine venv that
# kalkan-setup created in CLAUDE_PLUGIN_DATA. The hook allows the kalkan engine commands, the
# subagent result files and reads in the kalkan folders, confines the kalkan subagents to their
# run, and denies network tools in a session while it runs a kalkan audit.
#
# Arguments are ignored: hooks.json gives each handler its own tag, so that Claude Code never
# merges two handlers with different "if" filters.
#
# The launcher prints nothing and exits 0 (the normal permission flow decides) when:
# - the engine venv does not exist yet (before kalkan-setup there is nothing to allow);
# - the event does not mention kalkan and no session runs a kalkan audit (no marker in
#   $data/hook/sessions). This quick filter uses shell built-ins only, so other sessions stay
#   fast.

data=${CLAUDE_PLUGIN_DATA:-}
[ -n "$data" ] || exit 0

python=""
for candidate in "$data/venv/Scripts/python.exe" "$data/venv/bin/python"; do
    if [ -f "$candidate" ]; then
        python=$candidate
        break
    fi
done
[ -n "$python" ] || exit 0

active=""
set -- "$data"/hook/sessions/*.json
[ -e "$1" ] && active=1

input=$(cat)
case $input in
    *kalkan*) ;;
    *) [ -n "$active" ] || exit 0 ;;
esac

printf '%s' "$input" | "$python" -I -m kalkan.plugin_hook
exit 0
