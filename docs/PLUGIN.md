# kalkan as a Claude Code plugin

The plugin lets you run a kalkan audit from any folder, in the Claude Code CLI or in the VS Code extension, without a checkout of this repository. You install it once. The first `/kalkan` sets up the engine and the pinned scanners by itself.

## Requirements

- Claude Code 2.1 or later (2.1.217 or later for `--max-usd`, tested with 2.1.301), signed in.
- Python 3.11 or later (`py -3`, `python3` or `python` on `PATH`).
- git. On Windows: Git for Windows. The skill runs the engine through the Bash tool (Git Bash), and the permission hook runs in Git Bash.
- Network for the first setup: the pinned scanners and the local vulnerability databases (about 290 MB of OSV databases and the Grype database, 3.67 GB on disk on 2026-10-29, measured once on one Windows 11 machine). On Windows the release archives of the scanners hold about 530 MB (the sizes in `src/kalkan/tools/manifest.json`). pip gets Checkov, Bandit, flawfinder and gixy from PyPI, and Go gets the modules of govulncheck and poutine. The setup checks the 15 downloaded programs and the Go toolchain against a pinned SHA-256. pip installs the 4 Python tools by exact version, without a hash check. The Go checksum database checks the 2 tools that `go install` builds (docs/SECURITY.md). After the setup, an audit uses no network except your Claude session, the clone of a git URL target and the opt-in `--allow-build-network` (docs/SECURITY.md).
- Optional: Docker (the PoC verification sandbox). You do not need Go: the setup installs Go 1.26.9.

## Install

### One command (recommended)

The installer does every step of this section and the setup below, and prints the audit command. It needs git, Python 3.11 or later and a signed-in Claude Code:

```sh
curl -fsSL https://raw.githubusercontent.com/dtechcloud/kalkan/stable/scripts/install.sh | sh
```

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/dtechcloud/kalkan/stable/scripts/install.ps1)))
```

1. It checks git, Python, `claude --version` and `claude auth status --json` (signed in), and that git can read the repository (`git ls-remote` over https, then ssh). Each failure names its fix, for example `claude auth login`, or `gh auth setup-git` when your git needs a GitHub login.
2. It runs `claude plugin marketplace add dtechcloud/kalkan#stable`, or `claude plugin marketplace update kalkan` when the marketplace exists.
3. It runs `claude plugin install kalkan@kalkan --scope user`, or `claude plugin update kalkan@kalkan` when the plugin exists.
4. It runs the setup `sh <plugin folder>/bin/kalkan-setup <plugin data folder>`: the engine, the pinned scanners, the vulnerability databases and `kalkan doctor`. On Windows it finds `sh.exe` of Git for Windows.
5. It prints the `kalkan-audit` command ([One-command audit](#one-command-audit)).

Every step checks first, so the same line updates kalkan later. Options:

- `--dry-run` (PowerShell: `-DryRun`) runs only the checks and prints the commands that would change something.
- `--source <marketplace source>` (`-Source`) adds another source, for example a local checkout.
- `--skip-setup` (`-SkipSetup`) leaves the setup to the next `/kalkan`.

Pass options through the pipe with `... | sh -s -- --dry-run`, or after the last parenthesis in PowerShell. The PowerShell one-line form returns its exit code in `$LASTEXITCODE` and never closes the window. A clone works too: `git clone https://github.com/dtechcloud/kalkan.git`, then `sh kalkan/scripts/install.sh` (Windows: `powershell -ExecutionPolicy Bypass -File kalkan\scripts\install.ps1`).

### Claude Code CLI

From a terminal:

```sh
claude plugin marketplace add dtechcloud/kalkan#stable
claude plugin install kalkan@kalkan --scope user
```

Or inside a Claude Code session:

```text
/plugin marketplace add dtechcloud/kalkan#stable
/plugin install kalkan@kalkan
```

Restart Claude Code after the install.

**Release channel.** `#stable` follows the `stable` branch: the tested releases. Pull requests go to `main`, and a release moves `stable` forward. To try the newest changes, add `dtechcloud/kalkan#main` in place of `#stable` (remove the marketplace first: `claude plugin marketplace remove kalkan`).

Use the user scope (the default). A user-scope plugin works in every folder, also in a folder that Claude Code does not trust yet and under `claude -p`. A project-scope plugin loads only in a trusted folder.

### VS Code extension

1. Make sure that the workspace is trusted. The extension does not work in Restricted Mode.
2. Type `/plugins` in the Claude Code prompt box.
3. Open the **Marketplaces** tab. Add `dtechcloud/kalkan#stable`.
4. Open the **Plugins** tab. Select `kalkan`, then **Install for you**.


## Run an audit

Open Claude Code in any folder and type:

```text
/kalkan https://github.com/org/repo deep
```

- Arguments: `<path or git URL> [fast|standard|deep] [--no-latest]` (default `standard`). A relative path counts from the current folder.
- Resume after a break or a usage limit: `/kalkan devam <run-id>`. The start message names the run ID. `/kalkan devam` alone resumes the newest run and says which one.
- `/kalkan:kalkan` is the full name. Use it in a folder that has its own `/kalkan` command, for example a kalkan checkout: there the bare `/kalkan` starts the checkout's skill.
- Headless, from any folder: `claude -p "/kalkan <target> fast --headless" --permission-mode dontAsk`. A run that waits through usage-limit resets: [Unattended runs](#unattended-runs).

The first `/kalkan` runs the setup (step 1 below). The skill tells you so, because the scanner downloads take minutes (5 to 15 minutes; the Checkov install alone took about 10 minutes on the test machine). Later starts take about 2 seconds.

1. `kalkan-setup` creates a venv in the plugin data folder and installs the engine wheel that the plugin carries (no network). It copies the launchers (`kalkan-audit`, `kalkan-unattended` and their `.cmd` files) to `bin/` in the plugin data folder.
2. It installs the pinned scanners (`kalkan tools install --all`).
3. It downloads the local vulnerability databases (`kalkan sca update-db`: OSV, Grype, the Go database of govulncheck and the RetireJS repository). These requests send only ecosystem names and the archive requests. A failure only warns: `sca match` then records a database gap and never asks an online service.
4. It runs `kalkan doctor`.
5. It records the wheel hash. After a plugin update the next `/kalkan` installs the new engine.

When the setup fails, the skill shows the error and the command. You can run the same command in a terminal (the path of an install from GitHub; `<version>` is the plugin version, for example `1.0.0`):

```sh
sh ~/.claude/plugins/cache/kalkan/kalkan/<version>/bin/kalkan-setup ~/.claude/plugins/data/kalkan-kalkan
```

Add `--force` to repeat every step.

## One-command audit

`kalkan-audit` audits a folder or a git URL from a terminal and prints the report files at the end. It runs `kalkan audit` of the plugin venv (docs/ENGINE-SPEC.md section 25).

| Terminal | Command |
|---|---|
| Git Bash, Linux, macOS | `sh ~/.claude/plugins/data/kalkan-kalkan/bin/kalkan-audit <target>` |
| PowerShell | `& "$HOME\.claude\plugins\data\kalkan-kalkan\bin\kalkan-audit.cmd" <target>` |
| cmd | `"%USERPROFILE%\.claude\plugins\data\kalkan-kalkan\bin\kalkan-audit.cmd" <target>` |

- **Options:** `--profile fast|standard|deep` (default `standard`), `--tools-only`, `--open`, `--yes`, `--no-latest`, `--lang en|tr` (default `en`), `--allow-build-network`, `--live PATH`, `--not-live PATH` (both repeatable), `--max-hours N` (default 24), `--max-usd N`, `--json`. `kalkan audit --help` explains each one. `devam [<run-id>]` in place of the target resumes a run (`devam` alone: the newest run). The run keeps its mode and profile.
- **Setup check.** The command runs the doctor checks that the audit needs: every pinned tool, the vulnerability databases, and in agent mode the Claude Code CLI and its login. A missing tool or database is installed only with `--yes`, or after you answer `y` in a terminal (`kalkan tools install --all`, `kalkan sca update-db`). Otherwise the command prints the two fix commands with the engine path and stops with exit code 5. A missing or signed-out Claude Code also stops agent mode with exit code 5 and names `--tools-only` as the way without agents.
- **Run.** The command creates the run itself (`~/kalkan-runs/<run-id>`) and prints its ID. Then it runs the scanners and SCA in its own process, one line per step, so no Claude Code round spends time or usage on them.
- **Agents.** Then the unattended runner takes over, bound to the run ID: the rounds `claude -p "/kalkan:kalkan devam <run-id> --headless"` run in `~/kalkan-runs` as described under [Unattended runs](#unattended-runs). A watcher prints the phase changes and the task counts. A usage limit prints its reset time. The log goes to `~/kalkan-runs/unattended-<UTC time>.log`.
- **Tools-only.** `--tools-only` needs no Claude Code: the engine skips the agent phases (recon, plan, hunt, validate, poc) with the reason "tools-only mode: no agent validation; all results are unverified tool results", and the report shows that reason and an unknown overall risk.
- **End.** The command prints a short summary (overall risk, counts by severity, the top 3 findings or tool results, vulnerable dependencies) and the deliverables: `EXECUTIVE.html`, `REPORT.html`, `REPORT.md`, `findings.sarif`, `findings.json`, `summary.json` and the SBOM files. `--open` opens `EXECUTIVE.html` in the default browser.
- **Exit codes:** 0 done, 1 incomplete (the partial report exists), stopped (`--max-hours`, Ctrl+C) or failed, 2 usage, 5 setup needed. A stop message names `kalkan-audit devam <run-id>`.
- **Parallel audits:** one terminal per audit, as for `kalkan-unattended`. Add `--no-latest` to a side audit.

## Unattended runs

`kalkan-unattended` runs an audit without a chat. It starts `claude -p` round after round, waits through usage-limit resets and stops when the audit is done. A run can take hours, so start it in a terminal.

1. Type `/kalkan unattended <target> [fast|standard|deep]` in Claude Code once. The skill runs the setup and prints the `kalkan-audit` command for your terminal ([One-command audit](#one-command-audit)). It starts no run.
2. Run that command in a terminal. To run only the agent rounds, use `kalkan-unattended` instead. With a marketplace install it is:

   | Terminal | Command |
   |---|---|
   | Git Bash, Linux, macOS | `sh ~/.claude/plugins/data/kalkan-kalkan/bin/kalkan-unattended <target> --profile standard` |
   | PowerShell | `& "$HOME\.claude\plugins\data\kalkan-kalkan\bin\kalkan-unattended.cmd" <target> --profile standard` |
   | cmd | `"%USERPROFILE%\.claude\plugins\data\kalkan-kalkan\bin\kalkan-unattended.cmd" <target> --profile standard` |

3. Resume after a stop: write `devam <run-id>` in place of the target and the profile. The stop message names this command. `devam` alone resumes the newest run.

- **Stable path.** The plugin folder has the version in its path (`.../cache/kalkan/kalkan/<version>/`). So the setup copies `bin/kalkan-unattended` and `bin/kalkan-audit` (sh) and their `.cmd` files (Windows) to `bin/` in the plugin data folder, and refreshes the copies at every `/kalkan`. Each copy finds the venv in its parent folder. The copy in the plugin folder uses `CLAUDE_PLUGIN_DATA` instead.
- **Options.** The launcher passes all arguments to `kalkan unattended`: `--run RUN_ID` (with `devam`, the same as `devam RUN_ID`), `--profile`, `--no-latest`, `--lang en|tr`, `--max-hours N` (default 24), `--max-usd N`, `--round-hours N` (default 6), `--host claude|codex`, `--log-dir DIR`, `--dry-run`, `--json`. `--dry-run` prints the `run init` command and the `claude -p` command line and starts nothing. A relative target path counts from the current folder of the terminal. `--host codex` needs a checkout (docs/CODEX.md).
- **Run.** For a new target the launcher first creates the run itself: `kalkan run init <target> --profile <profile> --json` in the plugin venv (with `--no-latest` when you give it). It prints `run <run-id> created` and binds to that run. `devam <run-id>` binds to that run. `devam` alone binds to the run in `~/kalkan-runs/LATEST` once, at the start. A later change of `LATEST` never moves the launcher to another run.
- **Rounds.** Every round runs `claude -p "/kalkan:kalkan devam <run-id> --headless" --permission-mode dontAsk --output-format stream-json --verbose`. The full skill name never starts another `/kalkan` command. After each round the launcher reads `kalkan run status --run <run-id> --json`.
- **Working folder.** The rounds run in the runs folder `~/kalkan-runs` (or `KALKAN_RUNS_DIR`). A user-scope plugin works in any folder. The runs folder holds no `CLAUDE.md` or `.claude/settings.json` of a target, and every resume finds the same folder. A runs folder inside a `.claude` folder is refused, because Claude Code never lets a subagent write there.
- **Trust.** The launcher checks no folder trust: the plugin hook allows the engine commands and the result files also in an untrusted folder (see the test results below). A checkout still needs a trusted folder.
- **Output.** The log goes to `~/kalkan-runs/unattended-<UTC time>.log`, the report to `~/kalkan-runs/<run-id>/report/`. Exit codes: 0 done. 1 incomplete, stopped (the message names the resume command with the run ID), `run init` failed, or the run folder is gone. 2 usage error. 5 `claude` not on PATH.
- **Errors.** Without the plugin data folder or the engine, the launcher stops with exit code 1 and tells you to type `/kalkan unattended` in Claude Code once.
- **cmd.exe.** cmd.exe interprets `&`, `|`, `<`, `>`, `^` and `%` in an argument without double quotes. Quote a target path with such a character, or use Git Bash.
- **Test state.** The launchers, the setup copy and the plugin mode of `kalkan unattended` are tested with fake engines and with a dry run in a real plugin venv (Windows 11, Git Bash, PowerShell 7, cmd). A live unattended run through `kalkan-unattended` is not measured yet. `kalkan-audit` hands a run to the same loop: on 2026-10-31 `kalkan-audit devam` drove a live agent audit to `done`. The rounds use the same `claude -p ... --permission-mode dontAsk` call as the headless test runs below.

## Parallel audits

You can audit several projects at the same time: one Claude Code session or one terminal per audit. Each orchestrator binds to one run ID and writes `--run <run-id>` in every engine command. `~/kalkan-runs/LATEST` names only the newest run. It is the default of a plain `devam`, and nothing else reads it. `kalkan-audit` works like the terminal column below: `kalkan-audit C:/code/shop --profile deep` in one terminal and `kalkan-audit C:/code/billing --profile fast --no-latest` in another.

| Step | Claude Code (one session per audit) | Terminal (one per audit) |
|---|---|---|
| Start audit 1 | `/kalkan C:/code/shop deep` | `sh ~/.claude/plugins/data/kalkan-kalkan/bin/kalkan-unattended C:/code/shop --profile deep` |
| Start audit 2 | `/kalkan C:/code/billing fast` | `sh ~/.claude/plugins/data/kalkan-kalkan/bin/kalkan-unattended C:/code/billing --profile fast` |
| Resume one run | `/kalkan devam 20261016T151915Z-shop-5fc6` | `sh ~/.claude/plugins/data/kalkan-kalkan/bin/kalkan-unattended devam 20261016T151915Z-shop-5fc6` |
| Resume the newest run | `/kalkan devam` | `sh ~/.claude/plugins/data/kalkan-kalkan/bin/kalkan-unattended devam` |

- The start message of `/kalkan`, the line `run <run-id> created` of `kalkan-unattended` and its stop message name the run ID. The run IDs are also the folder names in `~/kalkan-runs`.
- `devam --run <run-id>` is the same as `devam <run-id>`.
- A new run becomes the newest run (`LATEST`). Add `--no-latest` to keep `LATEST` unchanged, for example for a short side audit: `/kalkan C:/code/tool fast --no-latest` or `kalkan-unattended C:/code/tool --profile fast --no-latest`. Then resume it only with its run ID.
- In PowerShell, use `& "$HOME\.claude\plugins\data\kalkan-kalkan\bin\kalkan-unattended.cmd"` with the same arguments.
- Engine commands by hand: `kalkan run init <target> --no-latest --json` creates a run without touching `LATEST`. Every later command takes `--run <run-id>` (`run status`, `run next`, `run step`, `run wait`, `run resume`, `task complete`, `report`, ...).

## Where the data lives

| What | Folder | On uninstall |
|---|---|---|
| Plugin files (skill, agents, hook, engine wheel) | `~/.claude/plugins/cache/kalkan/kalkan/<version>/` | marked `.orphaned_at`, removed later by Claude Code |
| Engine venv, scanners (`.tools/`), vulnerability databases (`.tools/vulndb/`), caches (`.tools/cache/`: the unpacked runtime of opengrep), hook state (`hook/`), setup stamp, launchers `kalkan-audit` and `kalkan-unattended` (`bin/`) | `~/.claude/plugins/data/kalkan-kalkan/` | removed, unless `--keep-data` |
| Runs and reports | `~/kalkan-runs/<run-id>/` (report in `report/`) | kept |

- `KALKAN_RUNS_DIR` moves the runs (set it in the environment that starts Claude Code). On Windows a short folder such as `C:\kr` also avoids the Opengrep long-path limit.
- The runs are not in the plugin data folder on purpose: Claude Code never lets a tool write below a `.claude` folder without a prompt, and the subagents must write their result files (see the test results below).
- `~/.claude/plugins/data/kalkan-kalkan/venv/kalkan-home.json` tells the engine where its home and its runs are.
- No scanner writes outside these folders: their logs, temporary files, caches and Go settings stay in the data folder or in the run (docs/SECURITY.md, "What kalkan writes where").

## Permissions

A plugin cannot ship permission rules, so the plugin uses two other ways:

- The skill's `allowed-tools` pre-approves the engine and setup commands, Read, Grep and Glob for the turn that runs `/kalkan`.
- A `PreToolUse` hook gives the other decisions (docs/SECURITY.md, promise 2):
  - **kalkan subagents** get `allow` or `deny` for every call. They may read only in the `target/` and `tasks/` folders of their run (and a saved output of a tool call of the same session, which Claude Code writes to its `tool-results` folder for a large result), and write only the `result.json` of their own task (the first prompt file that an agent reads binds it to its task). Every other tool is denied: Bash, Edit, WebFetch, WebSearch, MCP tools and the rest.
  - **Your session** may run one engine command at a time (no `&&`, `;`, pipes, redirection, `$` or backticks) and the setup command, and may read in the plugin data folder and the runs folder. `.env` files there are denied.
  - **While your session runs an audit**, the hook denies its network tools: WebFetch, WebSearch, MCP tools, and Bash or PowerShell commands with a network program, a URL or a git transfer. This ends when the run is done, or 6 hours after the last engine command. Other sessions are never denied anything.
  - Every other tool call follows your normal permission settings, and your deny rules still win.

So `/kalkan` also works in `dontAsk` mode and in a folder that you never trusted.

**Speed.** Each hook call starts Git Bash (about 0.2 s on Windows; about 0.4 to 0.6 s when Python decides, measured once on 2026-10-16 on one Windows 11 machine). The hook starts only for Read, Grep, Glob, Write, NotebookEdit, WebFetch, WebSearch and MCP tools, for Bash commands that mention kalkan or a network word, and for PowerShell commands that mention a network word. The launcher then exits without Python unless the call mentions kalkan or a session runs an audit.

## Update and uninstall

- Update: run the installer line again ([Install](#one-command-recommended)). By hand: `claude plugin marketplace update kalkan`, then `claude plugin update kalkan@kalkan`, then restart Claude Code. The next `/kalkan` (or `kalkan-setup`) installs the new engine. It keeps every vulnerability database that is younger than 7 days (`kalkan sca update-db --max-age 168`), so an update within a week downloads no database. Never update while an audit runs.
- Disk usage: `kalkan clean` prints the size of the engine, the tools, the databases, the caches and the runs. In the plugin, run the engine of the venv: `~/.claude/plugins/data/kalkan-kalkan/venv/Scripts/kalkan.exe clean` on Windows, `~/.claude/plugins/data/kalkan-kalkan/venv/bin/kalkan clean` elsewhere. Measured once on 2026-10-29 on one Windows 11 machine: tools 1.53 GB in 34,272 files, databases 3.67 GB in 4,744 files. `kalkan doctor` shows the same sizes in its `footprint` row.
- After an audit: `kalkan run clean <run-id>` deletes the target copy, the history copy and the work folders of a finished run and keeps its report (`--dry-run` shows the size first).
- Free more space: `kalkan clean --runs` (with `--keep-reports` each `report/` stays), `--caches`, `--databases`, `--tools`. The command lists what goes and asks first; `--dry-run` only lists, `-y` skips the question. `kalkan tools install --all` and `kalkan sca update-db` bring deleted tools and databases back (`kalkan doctor` and `kalkan audit` name them); the next scan fills the caches again.
- Uninstall:
  1. `kalkan clean --all` deletes the runs, the caches, the databases and the tools. It keeps the engine that runs it and prints the next step.
  2. `claude plugin uninstall kalkan@kalkan` removes the plugin and the data folder `~/.claude/plugins/data/kalkan-kalkan/` with the engine venv (add `--keep-data` to keep that folder). Claude Code keeps its copy of the plugin in `~/.claude/plugins/cache/kalkan/` with an `.orphaned_at` marker until it removes it itself.
  3. `claude plugin marketplace remove kalkan`.
  4. The runs folder `~/kalkan-runs` is outside the plugin folders and stays; after `kalkan clean --all` it holds no run. Delete it by hand.

## Test results of the open points

Measured on 2026-10-16 with Claude Code 2.1.301 on Windows 11 (user name with `ü`), model `claude-haiku`, `claude -p ... --permission-mode dontAsk` in an untrusted temporary folder.

| Question | Result |
|---|---|
| Does `claude plugin validate` accept the files? | Yes. `claude plugin validate .` (marketplace) and `claude plugin validate plugins/kalkan` pass without a warning. |
| Install from a marketplace | `claude plugin marketplace add <local path>` and `claude plugin install kalkan@kalkan --scope user` worked. Claude Code copied the plugin to `~/.claude/plugins/cache/kalkan/kalkan/0.0.1/` (engine wheel included). `claude plugin uninstall` and `claude plugin marketplace remove` removed it again. |
| Bare `/kalkan` or `/kalkan:kalkan`? | Both start the plugin skill, also from a folder that Claude Code does not trust. The session lists only `kalkan:kalkan`; the bare name works because the skill sets `name: kalkan` and no other command owns it. |
| Subagent type of a plugin agent | `kalkan:kalkan-<role>`. The session lists all of them (ten since the polish step added `kalkan-polisher`); `kalkan:kalkan-recon`, `-hunter`, `-critic` and `-verifier` ran in the live audit. |
| `agent_type` in the hook input of a subagent call | `kalkan:kalkan-recon` (with the plugin prefix), and `agent_id` is set. Calls of the main session have neither. |
| `${CLAUDE_PLUGIN_DATA}` on Windows | `C:/Users/DevKüçük/.claude/plugins/data/kalkan-kalkan` (marketplace install) or `.../kalkan-inline` (`--plugin-dir`): forward slashes, the `ü` kept. The skill text and the hook environment hold the same string. `${CLAUDE_PLUGIN_ROOT}` is the plugin folder in the same form. |
| Can a hook `allow` a subagent write below `~/.claude`? | No. The hook answered `allow` for all four recon result files in `${CLAUDE_PLUGIN_DATA}/runs`, and Claude Code still denied every write in `dontAsk` mode. Claude Code protects `.claude` folders. This is why the runs moved to `~/kalkan-runs`. |
| Does the hook let a subagent write its result in `dontAsk` mode, in an untrusted folder? | Yes, with the runs in `~/kalkan-runs`. A full `fast` audit of a one-file Flask app ran to the end: 12 subagents (4 recon, 4 hunter, 1 critic, 3 verifier), 12 result files accepted, 54 engine commands, 2 confirmed findings, all reports written, 0.12 USD with Haiku. |
| The final plugin files (Bash hook with `if`) | `/kalkan devam --headless` resumed the run that had failed without hooks and finished it: 15 subagents, 16 result files, 37 engine commands, 0 denied calls, 3 confirmed findings. |
| Is the hook needed? (`disableAllHooks`) | Yes. In one run the model quoted the setup path, the `allowed-tools` rule did not match the quoted command, and `dontAsk` denied it. In a second run (unquoted paths) the engine commands ran, the subagents could read (the skill's `allowed-tools` grant also covered their Read and Glob calls), but all four result writes were denied. Without a skill, Read and Glob outside the current folder are denied in `dontAsk` mode. |
| Does `if` limit the hook? | Yes. With `"if": "Bash(*kalkan*)"` the launcher started for the engine command and not for `echo hello`. The plugin uses `if` filters for Bash (kalkan and network words) and PowerShell (network words), so other sessions pay nothing for their other commands. Write, Read, Grep and Glob calls start the launcher, which exits after about 0.4 s when the event does not mention kalkan (0.6 s for a kalkan call, measured in Git Bash on a busy machine). |
| First setup on Windows | About 15 minutes (8 binaries, then Checkov and Bandit with pip, which took about 10 minutes). A repeated setup with every tool present: 2.5 to 3.5 minutes (hash checks and `kalkan doctor`). A current engine: 1.6 s. |
| Git Bash and `/kalkan` | Git Bash rewrites the argument `/kalkan ...` of `claude -p` into `C:/Program Files/Git/kalkan ...`. Set `MSYS_NO_PATHCONV=1`, or start `claude -p` from PowerShell. |

## Licenses

kalkan's own code is MIT (`plugins/kalkan/LICENSE`). The engine wheel also carries the curated Opengrep rule packs (`kalkan/_data/rules/opengrep-packs/`). They keep their own licenses: MIT (0xdea, elttam, aikido, semgrep-codeql and the MIT part of gitlab), LGPL-3.0-only (the `rules/lgpl` part of gitlab), LGPL-2.1-only (atlassian), LGPL-3.0-or-later (njsscan, mobsfscan), GPL-3.0-only (mindedsecurity) and AGPL-3.0-only (trailofbits). The wheel carries each license text in its `.dist-info/licenses/third_party/` folder. `KALKAN_RULE_PACKS=osi` turns the AGPL pack off. THIRD_PARTY.md lists every component.

## Development

- `python scripts/sync_host_files.py` writes the plugin skill and agents from `.claude/`. `python scripts/build_plugin.py` writes the manifests, the license copies and the engine wheel. Both have `--check`. The tests run it. CI runs it too.
- Try the working tree for one session without an install: `claude --plugin-dir plugins/kalkan`. The data folder is then `~/.claude/plugins/data/kalkan-inline/`. In Git Bash, set `MSYS_NO_PATHCONV=1` before `claude -p "/kalkan ..."`: Git Bash rewrites an argument that starts with `/` into a Windows path.
- `claude plugin validate .` checks the marketplace and `claude plugin validate plugins/kalkan` the plugin.
- `KALKAN_HOOK_LOG=<file>` in the environment of Claude Code makes the hook log each event and its decision.
- docs/ENGINE-SPEC.md section 24 holds the contracts.
