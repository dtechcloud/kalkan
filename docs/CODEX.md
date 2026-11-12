# Running an audit with OpenAI Codex

kalkan runs under Claude Code and under the OpenAI Codex CLI. The engine (`kalkan`) is the same for both hosts. This document covers the Codex host: setup, interactive audits, headless rounds with `codex exec` and resume after a usage limit.

## Files for Codex

| File | Purpose | Source |
|---|---|---|
| `AGENTS.md` | Audit runbook. Codex loads it at the start of a session. | Generated from `CLAUDE.md` |
| `.agents/skills/kalkan/SKILL.md` | The `$kalkan` orchestrator skill | Generated from `.claude/skills/kalkan/SKILL.md` |
| `.agents/skills/kalkan/agents/openai.yaml` | `allow_implicit_invocation: false`: Codex starts the skill only on an explicit `$kalkan` | Generated from `disable-model-invocation` of the Claude skill |
| `.codex/agents/kalkan-*.toml` | The ten kalkan subagents (Codex custom agents) | Generated from `.claude/agents/kalkan-*.md` |
| `.codex/config.toml` | Project config: sandbox, approval policy, network, web search, thread limit | Written by hand |
| `.codex/rules/kalkan.rules` | Execpolicy rules: two engine commands run outside the sandbox, `curl`, `wget` and `git push` are forbidden | Written by hand, checked against `.claude/settings.json` |

Do not edit a generated file. Edit the Claude Code file, then run `python scripts/sync_host_files.py`. The test `tests/unit/test_host_sync.py` runs the same script with `--check` and fails when a Codex file is out of date. When a Claude edit breaks a host-specific replacement, the script names the replacement. Then update the replacement table in `scripts/sync_host_files.py`.

## Requirements

- A current Codex CLI release with skills in `.agents/skills` and custom agents in `.codex/agents`. Codex turns on subagents by default since March 2026.
- A Codex login. `codex login status` exits with code 0 when you are logged in.
- The kalkan bootstrap: `scripts/bootstrap.ps1` (Windows) or `scripts/bootstrap.sh` (Linux, macOS).
- A git checkout of kalkan. `codex exec` stops outside a git repository unless you add `--skip-git-repo-check`.

## One-time setup: trust the kalkan folder

Codex loads the project `.codex/` layer only for a trusted project. Without trust, Codex ignores `.codex/config.toml`, `.codex/rules/kalkan.rules` and the kalkan subagents. The `$kalkan` skill then stops and tells you to trust the folder.

Do one of these:

1. Start `codex` in the kalkan folder and accept the trust prompt.
2. Add the folder to your user config `~/.codex/config.toml` (Windows: `%USERPROFILE%\.codex\config.toml`). Use the absolute path of your kalkan folder:

   ```toml
   [projects.'C:\Users\you\kalkan']
   trust_level = "trusted"
   ```

**Windows sandbox.** Codex runs commands on Windows in its native sandbox. The `mxc` and `elevated` modes block the network with process isolation or firewall rules. The `unelevated` mode has weaker network isolation. For an audit, use `mxc` or `elevated` (`windows.sandbox` in the user config).

## Interactive audit

1. Open a terminal in the kalkan folder.
2. Run `codex`.
3. Type `$kalkan <target folder> [fast|standard|deep]`, for example `$kalkan C:\code\shop standard`.
4. To resume after a break or a usage limit, start `codex` in the kalkan folder again and type `$kalkan devam <run-id>`. The start message names the run ID. `$kalkan devam` alone resumes the newest run.

The engine keeps all run state under `runs/<run-id>/`. A new Codex session continues the run. It does not need the old conversation. The skill writes `--run <run-id>` in every engine command, so audits in parallel sessions never touch each other's run (docs/PLUGIN.md, "Parallel audits").

**Git URL targets.** Under Codex, `run init` runs inside the sandbox without network, so it cannot clone a git URL. Clone the repository first, then give the local folder to `$kalkan`. Under Claude Code the engine runs outside a sandbox and clones the URL itself.

## Headless round with `codex exec`

One `codex exec` call runs one round of the `$kalkan` skill without a chat. Run it from the kalkan folder.

First round:

```sh
codex exec --sandbox workspace-write -c 'approval_policy="never"' -c 'sandbox_workspace_write.network_access=false' -c 'web_search="disabled"' --json '$kalkan C:\code\shop standard --headless'
```

Each later round (the first round prints the run ID):

```sh
codex exec --sandbox workspace-write -c 'approval_policy="never"' -c 'sandbox_workspace_write.network_access=false' -c 'web_search="disabled"' --json '$kalkan devam 20261016T151915Z-shop-5fc6 --headless'
```

The same lines work in PowerShell and in bash.

- Put the prompt in single quotes. In double quotes, PowerShell and bash expand `$kalkan` as a variable.
- Codex parses the value of `-c key=value` as TOML. When a shell drops the inner double quotes, Codex reads the bare word as a string, so the value stays the same.
- The flags repeat `.codex/config.toml`, so the sandbox holds even when a user config sets other values. `codex exec` uses the approval policy `never` by default. The flag makes it explicit.
- `--headless` tells the skill that nobody can answer. The skill prints no progress lines and answers the English-report question with `no`.
- `--json` writes JSON Lines events to stdout. Without it, Codex writes progress to stderr and only the final message to stdout. `-o <file>` also writes the final message to a file.
- When stdin is not a terminal, `codex exec` reads stdin to the end and adds it to the prompt. In a script, connect stdin to an empty input, for example `< /dev/null` in bash or `stdin=subprocess.DEVNULL` in Python.
- A round ends when the skill reaches `done` or `incomplete`, or when Codex stops, for example at a usage limit. `codex exec` exits with code 1 after a failed or interrupted turn. Do not trust the exit code alone. Read `kalkan run status --run <run-id> --json` after each round.

### Resume the same Codex session

A new round with `$kalkan devam <run-id> --headless` is the preferred way to continue. The engine state is on disk, and a new session starts with a clean context.

To continue the previous Codex conversation instead, use `codex exec resume`. Put the options before `resume`:

```sh
codex exec --sandbox workspace-write -c 'approval_policy="never"' -c 'sandbox_workspace_write.network_access=false' -c 'web_search="disabled"' --json resume --last '$kalkan devam 20261016T151915Z-shop-5fc6 --headless'
```

- `--last` picks the newest session that started in the current folder. That can be an interactive session of your own.
- `codex exec resume <SESSION_ID>` picks one session. The `thread.started` event of the `--json` output gives the ID in `thread_id`.
- `--ephemeral` stores no session files. A session started with it cannot be resumed.

## Usage limits

When Codex reaches a usage limit, the round stops. The run state stays on disk.

1. Read the reset time in the Codex message.
2. After that time, type `$kalkan devam <run-id>` (interactive) or start the next headless round.
3. Tasks that the stopped round leased go back to the queue when their lease expires (45 minutes). Until then `run next` returns `wait`.

How Codex reports a usage limit (Codex source: `codex-rs/protocol/src/error.rs`, `codex-rs/exec/src/exec_events.rs`):

- The message starts with `You’ve hit your usage limit.` and ends with `Try again at 3:45 PM.` The time is in the local time zone of the machine, without a zone name. For a reset on another day the end is `Try again at Oct 17th, 2026 9:05 AM.` When Codex does not know the reset time, the end is `Try again later.`
- Some plans can end with `… or try again at <time>.` after a purchase hint.
- Workspace plans can report depleted credits or a spend cap instead, for example `Your workspace is out of credits. …` or `You hit your spend cap …`. These messages have no reset time, and waiting does not help.
- With `--json`, the message is in an `error` event, `{"type":"error","message":"…"}`, and in the `turn.failed` event, `{"type":"turn.failed","error":{"message":"…"}}`. The JSON stream of `codex exec` has no separate rate-limit event.

## Differences from Claude Code

| Topic | Claude Code | Codex |
|---|---|---|
| Entry point | `/kalkan` | `$kalkan` |
| Subagent limits | A tool list per agent (`Read, Grep, Glob, Write`) and `maxTurns` | No tool list. The subagent gets a shell and `apply_patch` in the sandbox of the parent session. The agent file states the Claude limits as rules. Codex has no turn limit per agent. |
| Writes | `.claude/settings.json` allows writes only to task result files | The `workspace-write` sandbox allows writes anywhere in the repository. Only the instructions limit a subagent to its result file. |
| Network | Deny rules for `WebFetch`, `WebSearch`, `curl`, `wget` | Sandbox without network, web search turned off |
| Engine commands | Run outside a sandbox (allow rule) | `run step` and `task complete` run outside the sandbox (`.codex/rules/kalkan.rules`). The other commands, `run init` included, run inside it: no git clone. |
| `.env` files | Deny rules for `Read` | The agent instructions forbid them. No technical block. |
| Parallel tasks | One message with several Agent calls | Spawn all subagents, wait, then close them. `.codex/config.toml` allows 6 open threads. Raise `max_concurrent_threads_per_session` when you use `run init --max-parallel` above 6. |

## Execpolicy rules

`.codex/rules/kalkan.rules` holds Codex execpolicy rules. Codex loads them only for a trusted project.

- A `prefix_rule` with `decision = "allow"` runs a matching command outside the sandbox without a prompt. The file allows `kalkan run step` and `kalkan task complete`. They run the scanners, update the vulnerability databases and start the Docker PoC sandbox.
- `run init` stays in the sandbox on purpose. An allowed `run init` could clone any URL, and a manipulated agent could use that URL to send data out.
- `curl`, `wget` and `git push` are forbidden.
- The rules apply to the subagents as well. The subagent instructions forbid every engine command.
- Codex compares the first token exactly, so the rules list the engine path spellings `.venv/Scripts/kalkan.exe`, `./.venv/Scripts/kalkan.exe`, `.venv\Scripts\kalkan.exe`, `.\.venv\Scripts\kalkan.exe`, `.venv/bin/kalkan` and `./.venv/bin/kalkan`.
- **Untested:** Codex runs Windows commands through PowerShell. Whether these rules match a PowerShell command line is not tested. If a rule does not match, the engine step runs inside the sandbox: scanner results and database updates can then be missing.

To test a rule without a session: `codex execpolicy check --pretty --rules .codex/rules/kalkan.rules -- .venv/Scripts/kalkan.exe run step --json`. The test `tests/unit/test_host_sync.py` reads the file, runs the `match` and `not_match` examples of each rule, and compares the rules with `.claude/settings.json`.

## Unattended runs

`kalkan unattended --host codex` runs the headless rounds above in a loop and waits through usage-limit resets. The Python loop is the same for both hosts (`src/kalkan/unattended/`, `CodexHost` in `hosts.py`).

```sh
kalkan unattended C:\code\shop --profile standard --host codex
kalkan unattended devam 20261016T151915Z-shop-5fc6 --host codex
kalkan unattended devam --host codex
```

`scripts/run-unattended.ps1` and `scripts/run-unattended.sh` take the same arguments. Add `--dry-run` to print the command lines and start nothing.

- **Command.** `[codex, "exec", "--sandbox", "workspace-write", "-c", "approval_policy=never", "-c", "sandbox_workspace_write.network_access=false", "-c", "web_search=disabled", "--json", prompt]`, without a shell, from the repository root, with an empty stdin. The values have no inner quotes: a `codex.cmd` shim passes the arguments through `cmd.exe`, and Codex reads a bare word as a string.
- **Run.** For a target, `kalkan unattended` first runs `kalkan run init <target> --profile <profile> --json` itself and binds to the new run ID. `devam <run-id>` binds to that run. `devam` alone binds to the run in `runs/LATEST` once, at the start.
- **Prompt.** `$kalkan devam <run-id> --headless` in every round. With Claude Code the prompts start with `/kalkan`.
- **Git URL targets.** `--host codex` refuses a git URL, like `$kalkan` in a Codex session (there `run init` cannot clone in the sandbox). Clone the repository first.
- **Windows shim.** For `codex.cmd`, a prompt with `%`, `!`, `^`, `&`, `|`, `<`, `>`, `(` or `)` is refused. The `$` of `$kalkan` is safe in `cmd.exe`.
- **Limit detection.** The loop reads the `message` of `error` events, the `error.message` of `turn.failed` events and plain text lines. It skips every `item.*` event (`agent_message`, `reasoning`, `command_execution` and the others), because items can quote the audit target.
  - `Try again at 3:45 PM.` and `Try again at Oct 17th, 2026 9:05 AM.` resolve in the local time zone. The loop sleeps until that time plus 2 minutes.
  - `Try again later.` has no time. The loop backs off: 5, 10, 20, 40, 60, then 60 minutes.
  - A depleted-credits or spend-cap message stops the loop with exit code 1, unless the same round also reports a reset time. Add credits or raise the cap, then run `kalkan unattended devam <run-id> --host codex` (the stop message names it).
- **Exit code.** The loop logs the exit code of `codex exec` but does not trust it. After each round it reads `kalkan run status --run <run-id> --json`.
- **Doctor.** `kalkan doctor` shows `unattended:codex`: whether `codex` is on PATH, and its version. The check is information only.

## Sources

The developers.openai.com links redirect to the same pages on learn.chatgpt.com.

- Codex subagents and custom agents: https://developers.openai.com/codex/subagents
- Codex skills: https://developers.openai.com/codex/skills
- AGENTS.md discovery: https://developers.openai.com/codex/guides/agents-md
- Config basics and precedence: https://developers.openai.com/codex/config-basic
- Config reference: https://developers.openai.com/codex/config-reference
- Non-interactive mode (`codex exec`): https://developers.openai.com/codex/noninteractive
- CLI reference: https://developers.openai.com/codex/cli/reference
- Execpolicy rules: https://developers.openai.com/codex/rules
- Windows sandbox: https://developers.openai.com/codex/windows
- Codex source: https://github.com/openai/codex (`codex-rs/exec`, `codex-rs/agent-roles`, `codex-rs/protocol/src/error.rs`)
