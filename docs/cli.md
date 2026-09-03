# lithos-sandbox CLI

The `sandbox-driver-cli` crate builds the `lithos-sandbox` executable. The CLI
is a thin application over the provider traits. It does not add resources or
operations to the core library.

## Command structure

Use a built-in provider name or a configured profile with `--provider`:

```text
lithos-sandbox [--provider PROFILE] [--output table|json|id] COMMAND
```

Provider commands check configuration and capabilities:

```sh
lithos-sandbox provider list
lithos-sandbox --provider docker provider health
lithos-sandbox --provider docker provider capabilities
```

Sandbox commands manage persistent provider resources:

```sh
id=$(lithos-sandbox --provider docker --output id sandbox create \
  --image ubuntu:24.04 --name example)

lithos-sandbox --provider docker sandbox inspect "$id"
lithos-sandbox --provider docker sandbox exec "$id" -- bash -lc 'uname -a'
lithos-sandbox --provider docker sandbox stop "$id" --wait
lithos-sandbox --provider docker sandbox start "$id" --wait
lithos-sandbox --provider docker sandbox delete "$id"
```

The CLI also provides `pause`, `resume`, `archive`, `recover`,
`refresh-activity`, and `undelete`. It checks the selected provider's
capabilities before it calls an optional operation.

Upload and download one file with the filesystem facet:

```sh
lithos-sandbox --provider docker sandbox fs upload \
  "$id" ./input.txt /workspace/input.txt
lithos-sandbox --provider docker sandbox fs download \
  "$id" /workspace/result.txt ./result.txt
```

Open an interactive shell when the sandbox provides either a local shell
command or a PTY:

```sh
lithos-sandbox --provider docker sandbox shell "$id"
```

## One-shot runs

`sandbox run` creates a sandbox, activates it, runs one command, and deletes
it. It deletes the sandbox after command failure too.

```sh
lithos-sandbox --provider docker sandbox run --image ubuntu:24.04 -- \
  bash -lc 'printf "hello\n"'
```

Use `--keep` with a persistent provider to preserve the sandbox. The CLI
writes its ID to stderr so command stdout stays unchanged.

The Host provider stores its handles in process memory. Therefore, Host
handles cannot be used by a later CLI invocation. Use Host only with
`sandbox run`. `--workspace PATH` designates a caller-owned directory. Host
cleanup releases the handle and does not delete that directory.

```sh
lithos-sandbox --provider host sandbox run --workspace "$PWD" -- \
  bash -lc 'cargo test'
```

## Creation input

Common creation fields have command-line options:

```sh
lithos-sandbox --provider docker sandbox create \
  --image ubuntu:24.04 \
  --name example \
  --kind container \
  --cpu 2 \
  --memory-mb 4096 \
  --env RUST_BACKTRACE=1 \
  --label project=example \
  --network allow-all
```

Use `--spec FILE` for the complete serialized `SandboxSpec`. The file is JSON.
Convenience options override the corresponding fields from the file. Use
`--spec -` to read JSON from stdin.

```sh
lithos-sandbox --provider daytona sandbox create --spec sandbox.json
```

Provider-specific creation options can stay in the JSON specification or be
passed as a JSON value:

```sh
lithos-sandbox --provider docker sandbox create \
  --image ubuntu:24.04 \
  --provider-config '{"auto_pull":true}'
```

## Configuration

The CLI reads the first applicable configuration source:

1. `--config PATH`
2. `SANDBOX_DRIVER_CONFIG`
3. `$XDG_CONFIG_HOME/sandbox-driver/config.toml`
4. `$HOME/.config/sandbox-driver/config.toml`

Without configuration, the built-in profile names are `host`, `docker`, and
`daytona`. The default provider is `host`.

```toml
default-provider = "local-docker"

[providers.local-docker]
type = "docker"

[providers.daytona]
type = "daytona"
api-key-env = "DAYTONA_API_KEY"
api-url = "https://app.daytona.io/api"
target = "us"
```

An unconfigured built-in Daytona profile reads the standard Daytona
environment variables. A configured profile can name different environment
variables. The configuration stores environment variable names, not secret
values.

Configure an external JSON-RPC plugin as follows:

```toml
[providers.e2b]
type = "plugin"
kind = "e2b"
path = "/usr/local/bin/lithos-sandbox-e2b"
sha256 = "0123456789abcdef..."
inherit-env = ["PATH", "E2B_API_KEY"]
```

The CLI verifies the checksum before it starts the plugin. Set `dev = true`
only for local plugin development when no checksum is available. Plugin
processes receive only configured `env` values and variables named by
`inherit-env`.

## Output and exit behavior

Resource commands default to tables. Use `--output json` for structured data
or `--output id` when a script only needs resource IDs.

Lifecycle progress goes to stderr. Select `--events json` for newline-delimited
JSON events or `--events off` to hide progress.

`sandbox exec` and `sandbox run` reserve stdout and stderr for the sandbox
command. They require the default `--output table` mode. The CLI returns the
sandbox command's exit code when it fits in the platform exit-code range. It
returns 124 for a timeout, 130 for cancellation, and 125 when a command ended
without a usable exit code. CLI and provider errors return 1.
