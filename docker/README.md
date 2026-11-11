# kalkan container image

`docker/Dockerfile` builds an image with the kalkan engine and the pinned scanners.

**Status: not built for the current tool set.** The last image build that this page records is from 2026-10-16. kalkan added several scanners after that day, and nobody built and tested an image with the current tool set. CI builds the image, but that job does not gate a merge. The sizes and results below are from 2026-10-16. Use it to run the deterministic engine (`kalkan audit --tools-only`, or `run init`, `scan`, `sca`, `report` one by one) on a machine without a local install, or in CI. The image does not contain Claude Code. See [Claude Code and /kalkan](#claude-code-and-kalkan).

One command audits a folder without agents (Linux and macOS, PowerShell below):

```sh
mkdir -p kalkan-runs kalkan-vulndb
docker run --rm --user "$(id -u):$(id -g)" \
  -v "/path/to/src:/src:ro" -v "$PWD/kalkan-runs:/work/runs" \
  -v "$PWD/kalkan-vulndb:/opt/kalkan/.tools/vulndb" \
  kalkan:local audit /src --tools-only --yes
```

Windows (PowerShell, Docker Desktop):

```powershell
New-Item -ItemType Directory -Force kalkan-runs, kalkan-vulndb | Out-Null
docker run --rm -v "C:\src\myapp:/src:ro" -v "${PWD}\kalkan-runs:/work/runs" -v "${PWD}\kalkan-vulndb:/opt/kalkan/.tools/vulndb" kalkan:local audit /src --tools-only --yes
```

With `--yes`, the first run downloads the vulnerability databases into `kalkan-vulndb` (3.67 GB on disk on 2026-10-29, measured once on one Windows 11 machine). Later runs use them and need no network. The report is in `kalkan-runs/<run-id>/report/`, and the last lines of the output name the files. Leave out `--yes` in CI to fail with exit code 5 instead of a download when the databases are missing.

The PoC verification sandbox (ADR-0006) uses the allowlisted base images of `src/kalkan/sandbox/images.json`, which `kalkan sandbox pull` downloads. This document is about `docker/Dockerfile` only.

## Contents

| Path | Content |
|---|---|
| `/opt/kalkan` | Copy of the repository. `KALKAN_HOME` points here. |
| `/opt/kalkan/.venv` | Engine venv with an editable install of kalkan. `kalkan` is on `PATH`. |
| `/opt/kalkan/.tools` | Scanners from `kalkan tools install`, with SHA-256 checks and `installed.json`. |
| `/opt/kalkan/.tools/vulndb` | Local vulnerability databases. The folder is empty in the image and belongs to the `kalkan` user. Mount a host folder or a volume here. |
| `/opt/go` | Go toolchain 1.26.9 (the default). Empty when the build sets `WITH_GO=false`. |
| `/work/runs` | Runs folder (`KALKAN_RUNS_DIR`). Mount a host folder or a volume here. |
| `/usr/local/bin/kalkan-entrypoint` | Entry point. It runs `kalkan <arguments>`. |

- Base image: `python:3.12.15-slim-trixie` (Debian 13), pinned by digest. The Dockerfile adds two Debian packages, `git` and `ca-certificates`, with their dependencies. It adds no compilers.
- User: `kalkan`, uid 10001, gid 10001. The container runs as this user by default, not as root.
- The `.dockerignore` file in the repository root keeps `.git`, `.venv`, `.tools`, `runs` and `tests` out of the build context. The build context must be the repository root.

The image installs every tool of `src/kalkan/tools/manifest.json`, the source of the versions and the SHA-256 values. The Dockerfile has no tool list: each install layer asks `docker/manifest_tools.py` for its tools, so a tool that the manifest gains arrives in the next build without a Dockerfile change.

| Layer | Tools (`docker/manifest_tools.py`) | Build argument |
|---|---|---|
| core | every tool without a GPL license that needs no Go (on 2026-10-25: Trivy, Gitleaks, Opengrep, OSV-Scanner, Syft, Grype, Checkov, Bandit, zizmor, actionlint, OpenSSF Scorecard, Kingfisher, gixy, helm and vacuum). The pip tools live in `.tools/pyenv`. | always |
| GPL | every tool with a GPL or AGPL license (an LGPL license, as Opengrep has, stays in core), for example Hadolint, ShellCheck and flawfinder | `WITH_GPL` |
| Go | every tool that needs Go to build or to run (`requires_go`, or kind `go-install`), for example gosec, govulncheck and poutine | `WITH_GO` (a GPL Go tool also needs `WITH_GPL`) |
| go stage | the Go toolchain itself (`/opt/go`) | `WITH_GO` |

`docker run --rm kalkan:local tools list` prints the tools of an image with their versions. A tool without a build for the platform is skipped, and `kalkan doctor` names it.

## Build

Run the command in the repository root. The same command works in PowerShell, bash and zsh:

```sh
docker build -f docker/Dockerfile -t kalkan:local .
```

Without the GPL tools (Hadolint and the others of the GPL layer):

```sh
docker build -f docker/Dockerfile --build-arg WITH_GPL=false -t kalkan:local .
```

Without the Go toolchain and the tools that need Go (`kalkan doctor` then reports these tools as `fail`):

```sh
docker build -f docker/Dockerfile --build-arg WITH_GO=false -t kalkan:local .
```

The build downloads the scanners from their GitHub releases, the pip tools from PyPI and, with `WITH_GO=true` (the default), Go from go.dev. A build took about 9 minutes on a Windows 11 machine with Docker Desktop, and about 5 minutes with `WITH_GO=false` (measured on 2026-10-16 with the tools of that day). The tool layers come after the repository copy, so a change in the repository downloads the tools again. A change of `WITH_GPL` or `WITH_GO` alone keeps the cached core scanner layer.

### Build arguments

| Argument | Default | Effect |
|---|---|---|
| `WITH_GPL` | `true` | `false` leaves out the GPL layer (and the GPL tools of the Go layer). See [GPL tools license note](#gpl-tools-license-note). |
| `WITH_HADOLINT` | `true` | The older name of the GPL switch: `false` also leaves out every GPL tool. |
| `WITH_GO` | `true` | Go 1.26.9 and the tools that need Go. `false` leaves them out. |
| `GO_VERSION` | `1.26.9` | Go release. Change it only together with the two checksums and the `go` entry of `src/kalkan/tools/manifest.json` (a unit test compares them). |
| `GO_SHA256_AMD64`, `GO_SHA256_ARM64` | pinned | SHA-256 of `go<version>.linux-<arch>.tar.gz` from https://go.dev/dl/. |
| `PYTHON_IMAGE` | `pinned-python` | Base image. The default is the stage `pinned-python`: `python:3.12.15-slim-trixie` with a pinned digest (Dependabot updates the tag and the digest together). Another value replaces it, for example an image from your own registry. |

Any value other than `true` or `false` for `WITH_GPL`, `WITH_HADOLINT` or `WITH_GO` stops the build.

The manifest has `linux-arm64` assets for every binary tool, so `docker buildx build --platform linux/arm64` can work. Only `linux/amd64` was built and tested. The tools that kalkan added after 2026-10-16 never ran in a tested image.

## Run

Every `docker run` starts a new container. The run state stays in the mounted runs folder (`runs/LATEST` names the newest run), so the next command continues the same run.

Linux and macOS:

```sh
mkdir -p runs
docker run --rm --user "$(id -u):$(id -g)" \
  -v "/path/to/target:/target:ro" -v "$PWD/runs:/work/runs" \
  kalkan:local run init /target
docker run --rm --user "$(id -u):$(id -g)" \
  -v "/path/to/target:/target:ro" -v "$PWD/runs:/work/runs" \
  kalkan:local scan all
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD/runs:/work/runs" kalkan:local run status
```

Windows (PowerShell):

```powershell
New-Item -ItemType Directory -Force runs | Out-Null
docker run --rm -v "C:\src\myapp:/target:ro" -v "${PWD}\runs:/work/runs" kalkan:local run init /target
docker run --rm -v "C:\src\myapp:/target:ro" -v "${PWD}\runs:/work/runs" kalkan:local scan all
docker run --rm -v "${PWD}\runs:/work/runs" kalkan:local run status
```

Other commands:

```sh
docker run --rm kalkan:local --version
docker run --rm kalkan:local doctor --json
docker run --rm kalkan:local tools list
docker run --rm -it --entrypoint sh kalkan:local
```

Notes:

- On Linux, `--user "$(id -u):$(id -g)"` lets the container write to your runs folder. Docker Desktop on Windows and macOS does not need it. When the runs folder is not writable, the entry point prints a warning.
- The target mount is read-only (`:ro`). `run init` copies the target into the run folder.
- A git URL target (`run init <url>`) and `kalkan sca update-db` need the network. The scanners and the SCA steps use none (local mode, docs/SECURITY.md): they read the databases in `/opt/kalkan/.tools/vulndb`. The image ships no database. Run `update-db` (or `audit --yes`) once with a host folder or a volume at `/opt/kalkan/.tools/vulndb` to keep them. The folder belongs to the `kalkan` user in the image, so a new named volume there is writable for uid 10001. With `--user`, mount a host folder that you own instead. Without a database, `sca match` records a database gap, and `kalkan audit` stops with exit code 5 unless `--yes` is given. Add `--network none` to a command that must not use the network.
- opengrep unpacks its runtime into `/opt/kalkan/.tools/cache`, not below `HOME` (docs/SECURITY.md, "What kalkan writes where"). When `HOME` is not writable (for example with `--user` or `--read-only`), the entry point moves `HOME` to a new folder in `/tmp`.
- The root file system can be read-only: add `--read-only --tmpfs /tmp`.
- `kalkan doctor` reports Docker, Node.js and Claude Code as missing. These results are warnings. The PoC sandbox needs Docker and is not available in the container. A `needs_validation` finding then keeps its verdict and gets the blocker `sandbox_unavailable`.
- `kalkan doctor` reports every manifest tool that the image leaves out as `fail`: the GPL tools with `WITH_GPL=false`, and Go and the tools that need it with `WITH_GO=false`. The engine skips these scanners, and `kalkan audit` stops with exit code 5 (setup needed) in such an image: use the default build for `kalkan audit`.
- git refuses a repository that belongs to another user ("dubious ownership"). The image does not set `safe.directory`, because a target repository is untrusted data. For a history scan of a mounted repository, run the container with the uid of the owner, or use a git URL target.

## GPL tools license note

- Hadolint is GPL-3.0, and other GPL or AGPL tools of the manifest join it in the GPL layer. kalkan is MIT. kalkan runs each unmodified binary as a separate process and does not link to it.
- The Dockerfile installs these tools in their own layer. `--build-arg WITH_GPL=false` (or the older `WITH_HADOLINT=false`) builds an image without them. kalkan then skips their scanners, and `kalkan doctor` reports them as `fail`.
- If you distribute an image with a GPL tool, the GPL terms apply to that binary. For example, the recipients must be able to get the corresponding source of Hadolint: https://github.com/hadolint/hadolint/tree/v2.15.1.
- Other components have their own terms. Opengrep is LGPL-2.1. The Debian packages of the base image (for example git) carry their own licenses. `THIRD_PARTY.md` lists all scanners.

## Go tools

With `WITH_GO=true` (the default), the `go` stage downloads Go 1.26.9 from go.dev and checks its SHA-256. The version and the two SHA-256 values are the ones of the `go` entry in `src/kalkan/tools/manifest.json`, so a native install and the image run the same Go. kalkan accepts `/opt/go` as a system Go (version 1.26 or later) and does not install a second copy in `.tools/go`. `kalkan doctor` shows `tool:go` as `ok` with the source `path`. The final stage then installs gosec (release binary, SHA-256 from the manifest) and builds govulncheck and poutine with `go install` and `/opt/go`. The Go checksum database verifies their modules. The layer removes the build folders `.tools/go-build`. `GOTOOLCHAIN=local` stops Go from downloading another toolchain at run time.

With `WITH_GO=false`, the image has no Go. `kalkan doctor` reports Go, gosec, govulncheck and poutine as `fail`, and the engine skips gosec, govulncheck and poutine.

## Claude Code and /kalkan

The image does not contain Claude Code. Use one of these two ways:

1. **Host.** Install kalkan on the host with `scripts/bootstrap.ps1` (Windows) or `scripts/bootstrap.sh` (Linux, macOS). Then run `/kalkan` in a Claude Code session in the repository. The skill calls the engine in the host `.venv`. A host session cannot use the image as its engine: the engine gives the agents file paths in its runs folder, and the container paths are not valid on the host.
2. **Container.** Build a second image with Claude Code on top of `kalkan:local`. Claude Code 2.1.280 needs Node.js 22 or later, and the Debian package is older, so the example copies Node.js from the official image:

   ```dockerfile
   FROM node:22.23.3-trixie-slim@sha256:154ba2f4d6fec323d28e4f4bb86bba4677f1223391a1979cf521304e03a98dfa AS node

   FROM kalkan:local
   USER root
   COPY --from=node /usr/local/bin/node /usr/local/bin/node
   COPY --from=node /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/npm
   RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
       && npm install -g --no-audit --no-fund @anthropic-ai/claude-code@2.1.280 \
       && npm cache clean --force
   USER 10001:10001
   WORKDIR /opt/kalkan
   # An empty value moves the runs folder back to /opt/kalkan/runs, where the
   # permission rules of .claude/settings.json allow the agents to write.
   ENV KALKAN_RUNS_DIR=
   ENTRYPOINT ["claude"]
   CMD []
   ```

   Save the example as `Dockerfile.claude`. Build and start it (PowerShell: replace `$PWD/target` with the target folder):

   ```sh
   docker build -f Dockerfile.claude -t kalkan-claude:local .
   docker run -it --rm -v "$PWD/target:/target:ro" \
     -v kalkan-runs:/opt/kalkan/runs -v kalkan-home:/home/kalkan \
     kalkan-claude:local
   ```

   Log in to Claude Code in the session, then type `/kalkan /target`. The `kalkan-home` volume keeps the login. The skill works unchanged: the repository root is `/opt/kalkan`, and the engine is at `.venv/bin/kalkan`.

   On 2026-10-16 this example built on top of the default image (2.01 GB). `claude --version` gave 2.1.280, and `kalkan doctor` found Claude Code and a writable `/opt/kalkan/runs`. A full `/kalkan` run in the container was not tested.

## Image size

Measured once on 2026-10-16 with Docker Desktop 28.3.2 (linux/amd64), with the tools of that day and the older build argument `WITH_HADOLINT` (now `WITH_GPL`):

| Build | Size on disk (`docker image ls`) | Compressed content |
|---|---|---|
| `WITH_HADOLINT=true`, `WITH_GO=false` | 1.47 GB | 366 MB |
| `WITH_HADOLINT=false` | 1.40 GB | 354 MB |
| `WITH_HADOLINT=true`, `WITH_GO=true` (now the default) | 1.94 GB | 470 MB |

The `WITH_HADOLINT=false` row has no Go. The first two rows were measured when a missing tool was a doctor warning. `kalkan doctor` now reports it as `fail`, so only a build with every tool gives exit code 0. The default build (now `WITH_GO=true`) was built again on 2026-10-16 after that change: 1.94 GB, `kalkan doctor` exit code 0, `tool:go` `ok` with `/opt/go/bin/go` (Go 1.26.9), and govulncheck built with it.

The core scanners take most of the space: the Checkov venv about 295 MB, Trivy 165 MB, Grype 87 MB, Syft 84 MB. Hadolint adds about 56 MB.
