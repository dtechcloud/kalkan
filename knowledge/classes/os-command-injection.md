---
slug: os-command-injection
title_en: OS command injection
title_tr: Command injection
cwe: CWE-78, CWE-77, CWE-88
owasp: A03:2021
sources: sast-skills, codecrucible, deepsec, open-code-review
---

## Summary

The application runs an OS command built from attacker text. When a shell parses the command, metacharacters (`;`, `|`, `&`, `` ` ``, `$()`) run extra commands. Without a shell, attacker text can still become its own flag (argument injection) or choose the binary. The usual impact is full server compromise.

## What it is

- **Shell with user text.** A command string that includes user input runs through a shell: `shell=True`, `/bin/sh -c`, `cmd /c`, `child_process.exec`, backticks, `os.system`, `shell_exec`.
- **User-chosen binary.** The attacker controls the program name, not only an argument.
- **Argument injection (CWE-88).** No shell, but a user value starts with `-` and becomes a flag, for example `--output=/etc/passwd` or `ssh -oProxyCommand=...`.
- **Shell-out to a network tool.** `curl`, `wget`, `nc` invoked with a user-controlled target.
- **Environment influence.** The request sets `PATH`, `LD_PRELOAD` or `PYTHONPATH` for the child process.
- **Second-order.** A stored user value is later used to build a command in a job or a cron task.

## What it is not

- `eval`-style evaluation of attacker code in the application language → `code-injection`.
- Template source from user input → `ssti`.
- Deserializing attacker bytes that trigger a gadget chain → `deserialization`.
- A SQL injection that reaches `xp_cmdshell` → `sqli` is the primary class.
- A user-controlled URL for a server HTTP request, with no shell → `ssrf`.
- A user-controlled file path for a read or write, with no command → `path-traversal`.

## Where to look

Find the exec sink first. Then check whether a shell parses the string and whether user text reaches the command or an argument.

### Python
- `os.system(x)`, `os.popen(x)`, `subprocess.run(x, shell=True)`, `Popen(x, shell=True)`, `subprocess.run(f"cmd {x}")` as a string.
- Safe shape: `subprocess.run(["cmd", x])` as a list with no `shell=True`.

### JavaScript/TypeScript
- `child_process.exec(x)`, `execSync(x)` always use a shell; `spawn`/`execFile` with `shell: true`.
- Template-literal commands: `` exec(`convert ${x} out.png`) ``. `Bun.$`...`` template.
- Safe shape: `execFile("cmd", [x])` or `spawn("cmd", [x])` with `shell` off.

### Java/Kotlin
- `Runtime.getRuntime().exec(x)` with a single string the JVM splits naively; `new ProcessBuilder("sh","-c",x)`.
- Safe shape: `ProcessBuilder` with a fixed command and validated args. Argument injection still possible.

### Go
- `exec.Command("sh","-c",x)`, `exec.Command(x)` with a user binary, `syscall.Exec`.
- Safe shape: `exec.Command("bin", arg1, arg2)` with discrete validated args and no `sh -c`.

### PHP
- `exec`, `system`, `passthru`, `shell_exec`, `popen`, `proc_open`, the backtick operator, all with a variable.
- `escapeshellarg`/`escapeshellcmd` reduce risk but have a bypass history. Prefer a direct process API.

### Ruby
- `system(x)` as a string, `exec(x)`, `IO.popen(x)`, backticks, `%x{...#{x}...}`.
- Safe shape: `system("cmd", arg1, arg2)` with separate args.

### C#/.NET
- `Process.Start(x)`, `ProcessStartInfo { FileName = x, Arguments = x }` with user input.

## Safe patterns

- No shell: pass an argument array to the process API. A shell never parses the string.
- Put user values before a `--` separator, or validate that they do not start with `-`.
- A strict allowlist of known-safe values for any part the user controls.
- A fixed command name. The user never chooses the binary.
- A sandbox (container with no shell, seccomp, nsjail) when a command must run.

## Weak mitigations

- `escapeshellarg` / `shlex.quote` alone. They are context-specific and have a bypass history. Keep the finding but note the control.
- A blocklist of metacharacters. An attacker finds another character or an encoding.
- An argument array that still lets a user value become a flag. Argument injection remains.
- A quoting routine written by hand.

## Verification checklist

- **attacker_control:** Name the entry point and the value. Quote the exec call and show the shell (`shell=True`, `exec`, `sh -c`) or the argv slot the value fills.
- **privilege_boundary:** State the gain: run arbitrary commands as the service user, read protected files, or open a reverse shell.
- **unmitigated:** With a shell, confirm the user bytes reach the command string with no context-correct quoting. Without a shell, check for argument injection. Quote the allowlist or the argv array to refute.
- A list-form call with no shell closes metacharacter injection. It does not close argument injection or a user-chosen binary.

## Examples

### Python
```python
# Vulnerable: shell parses the user host
subprocess.run(f"ping -c 1 {request.args['host']}", shell=True)
# payload: host=127.0.0.1;id

# Secure: list form, no shell
subprocess.run(["ping", "-c", "1", request.args["host"]], timeout=5)
```

### JavaScript/TypeScript
```javascript
// Vulnerable: exec always uses a shell
exec(`grep -r "${req.query.q}" /var/log/app/`);

// Secure: execFile with an argument array, no shell
execFile("grep", ["-r", req.query.q, "/var/log/app/"]);
```

### Go
```go
// Vulnerable: sh -c parses the user value
exec.Command("sh", "-c", "ping -c 1 "+r.URL.Query().Get("host")).Run()

// Secure: discrete args, no shell
exec.Command("ping", "-c", "1", r.URL.Query().Get("host")).Run()
```

## Dynamic test hints

- Use a local build only. Never run a payload against a real system.
- Shell test: send `host=127.0.0.1;id` or `host=127.0.0.1%3Bid` and look for the `id` output.
- Blind test: send `host=127.0.0.1;sleep 3` and compare the response time on the local app.
- Argument injection test with no shell: send a value that starts with `-`, for example `file=--help`, and check whether the tool treats it as a flag.
- Keep the payloads to harmless commands (`id`, `sleep`) on a local instance.

## False positive traps

- No shell and the arguments are an array, and user values sit after `--` or the target binary takes no flags.
- The command string is fully static. The user value flows to a different call nearby.
- The user value is checked against a closed allowlist of safe literals before the exec.
- The process runs in a sandbox with no shell, which makes the exec uninteresting even if reached.
- A list-form `subprocess.run([...])` with no `shell=True` is not metacharacter injection. Check for argument injection instead.

## Sources

Condensed and rewritten from the local copies under `third_party/`.

- `utkusen/sast-skills@db52227: sast-files/.claude/skills/sast-rce/SKILL.md` (MIT, Utku Sen): the OS command sinks per language, the list-form safe pattern, the allowlist pattern, per-stack examples.
- `block/codecrucible@b5c8086: prompts/default/cwe_deep_analysis.yaml` (CWE-78), `prompts/default/analysis_sections.yaml` (COMMAND), `prompts/core/audit_families.yaml` (injection family), `prompts/exploit-proof-web-*` (Apache-2.0, Block): the shell check, argument injection, `--` separator, environment influence, false positive indicators.
- `vercel-labs/deepsec@4fa6722: packages/scanner/src/matchers/rce.ts`, `go-command-injection.ts`, `processor/src/prompt/slug-notes.ts` (Apache-2.0, Vercel): per-language exec sinks and the dynamic-vs-static command note.
- `alibaba/open-code-review@11ac6d4: internal/config/rules/rule_docs/python.md`, `php.md`, `go.md` (Apache-2.0, alibaba/open-code-review contributors): the "pass an argument list, avoid the shell" rule and PHP process-API guidance.
