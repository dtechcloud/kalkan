## Task: build a proof of concept

Write a small, safe proof of concept (PoC) for one finding. The engine runs it in a locked Docker sandbox and decides from the output whether the finding is proven. You only write files into your result; you never run anything.

The target copy is at `{{TARGET_DIR}}`.

### Input

The input holds the finding (title, class, trace, evidence, conditions, execution payloads), the detected technologies, the allowed base images (`base_images`), the unit-level limits (`limits`) and the compose files of the target (`compose_files`, empty when it has none).

```json
{{INPUT_JSON}}
```

### Source around the finding

{{SOURCE_EXCERPTS}}

### Knowledge for this class

{{KNOWLEDGE}}

### The sandbox

- **Unit level** (`level: "unit"`): the engine runs `command` in the chosen `base_image` with no network at all, the target mounted read-only at `/target`, your files read-only at `/poc`, a writable `/out` and `/tmp`, user `nobody`, one CPU, 512 MB memory, a short wall-clock limit. The image holds only the language runtime and its standard library: **no third-party packages and no way to install them.**
- **App level** (`level: "app"`, only when `compose_files` is not empty): the engine resolves `app.compose_file` and refuses a stack with privileged services, host or shared namespaces, added capabilities, devices, the Docker socket, bind mounts outside the target or external volumes. It starts the services on one internal network without internet access and without published ports, waits up to 120 seconds for `app.port` on `app.service`, sends your `app.requests` as plain HTTP to `http://<service>:<port><path>` from a client container, and matches `success_regex` against the printed lines (`REQUEST <n> <METHOD> <path> -> <status>`, then up to 8 KB of the body). A stack that builds or pulls images runs only when the user allowed the build network; otherwise it is blocked. Use the app level only when a unit harness cannot reach the vulnerable code (for example an authorization check in the request pipeline), and keep `files` empty.

### How to write a unit harness

1. Import or load the real target code from `/target`, so that the PoC proves the target's behavior, not a copy of it. Copying the vulnerable logic into the harness proves nothing; do not do it.
2. When the target module imports a framework that the image lacks (Flask, Django, Express, Spring), insert minimal stubs before the import: for Python, register fake modules in `sys.modules`; for Node, a small shim folder under `/poc` on `NODE_PATH`. For Go, write a `main` package with a `go.mod` whose `replace` directive points at `/target`; the command copies `/poc` to `/tmp/poc` and runs it there with `GOCACHE`, `GOPATH` and `GOFLAGS=-mod=mod` under `/tmp`. This works only when the code under test needs no third-party module that is missing from the target. For Java, use the single-file source launcher (`java /poc/Harness.java`) against JDK-only code. For C#, use `mcr.microsoft.com/dotnet/sdk:10.0`: write `poc.csproj` (`Microsoft.NET.Sdk`, `net10.0`, no `PackageReference`) with a `<Compile Include="/target/..." />` item for each target file under test, and a `Program.cs`; the command is `["sh", "-c", "cp -r /poc /tmp/poc && dotnet run --project /tmp/poc/poc.csproj -p:UseAppHost=false"]` (`/tmp` cannot run native programs, so the DLL runs through `dotnet`). ASP.NET Core is available offline: add `<FrameworkReference Include="Microsoft.AspNetCore.App" />` when the target files use `Microsoft.AspNetCore.*` types (for example `DefaultHttpContext` to call a handler or a middleware). NuGet packages are not available: include only target files that compile without them, stub a package type with a minimal class of the same namespace and name, or report `feasible: false`. Keep stubs minimal and name them in `expected_observation`.
3. Feed the payload from the finding with dummy data only. Use an in-memory or `/tmp` database (for example `sqlite3` in Python), dummy users, dummy secrets such as `example-not-a-secret`.
4. Observe the vulnerable effect directly (rows returned across a boundary, a command marker executed inside the sandbox, a file read outside the allowed folder, an unescaped payload in the output), then print one line `KALKAN_POC_OK <short observation>`. Print `KALKAN_POC_FAIL <reason>` when the effect does not happen. Set `success_regex` to `KALKAN_POC_OK`.
5. Stop at the minimum effect. No persistence, no destructive action, no denial of service, no outbound connection, no real credential.

### When a PoC is not feasible

When the sandbox cannot exercise the real code (missing dependencies that stubs cannot replace, a native build step, an external service the finding needs, no compose file for an app-level path), do not write a weak harness. Return `feasible: false` with the exact `reason`. The finding then keeps its verdict with the blocker `sandbox_infeasible`.

### Result fields

- `finding_id`: copy it from the input.
- `feasible`: `true` with the fields below, or `false` with only `reason`.
- `level`, `base_image` (one of the allowed images; match the target language).
- `files`: the harness files, with paths relative to `/poc` (for example `poc.py`, `stubs/flask/__init__.py`).
- `command`: the argument list to run, for example `["python", "/poc/poc.py"]`.
- `success_regex`, `expected_observation` (what a passing run shows and why it proves the finding).
- `app`: `null` for unit level; for app level the compose file, service, port and the HTTP requests (method, path starting with `/`, headers as name and value pairs, body).

