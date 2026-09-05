# sandbox-driver

A Rust library for driving sandboxes across providers: manage sandboxes,
snapshots, and volumes behind one capability-discoverable interface.

| Crate | Purpose |
| --- | --- |
| `sandbox-driver` | Core traits, types, exec-derived facets, wait/probe helpers |
| `sandbox-driver-host` | Host (local) provider — directories, no isolation |
| `sandbox-driver-docker` | Docker provider — containers with a workspace volume, one-shot containers, sidecars, image pulls |
| `sandbox-driver-docker-config` | The Docker provider's `provider_config` as plain Serde types, for hosts on the wire |
| `sandbox-driver-daytona` | Daytona provider — cloud VMs, nested Docker, snapshots, volumes |
| `sandbox-driver-daytona-config` | Typed Daytona and nested Docker configuration for plugin clients |
| `sandbox-driver-protocol` | JSON-RPC plugin protocol (version 2, with per-operation data channels): serve any provider, adapt any plugin |
| `sandbox-driver-conformance` | Black-box conformance suite every provider must pass |
| `sandbox-driver-{host,docker,daytona}-plugin` | The three providers as plugin executables: `sandbox-driver-host`, `sandbox-driver-docker`, `sandbox-driver-daytona` |
| `sandbox-driver-cli` | `lithos-sandbox` command for provider diagnostics and sandbox operations |

Host and Docker pass conformance locally (Docker needs a daemon), in
process and served over the plugin wire; the Daytona suite runs live with
`DAYTONA_API_KEY` set.

See `docs/design.md` for the interface design
and `docs/protocol.md` for the normative plugin wire protocol.

## Nested Docker on Daytona

Daytona can own a nested job container, sidecars, and one-shot action containers.
Use `DaytonaProviderConfig` from `sandbox-driver-daytona-config`. The runner
snapshot must include `start-docker` and Python 3. Container traffic crosses a
private authenticated preview. VM stop and delete own the full resource fence.
See [the design](docs/design.md#nested-docker-on-daytona) for configuration and
restart behavior.

The transport has deterministic local tests. The hosted integration remains an
explicit live gate:

```sh
# Set DAYTONA_API_KEY and SANDBOX_DRIVER_DAYTONA_DIND_SNAPSHOT first.
cargo nextest run --locked -p sandbox-driver-daytona --test nested_docker --run-ignored only
```

## CLI

Build the `lithos-sandbox` command and inspect the available operations:

```sh
cargo build --locked -p sandbox-driver-cli
target/debug/lithos-sandbox --help
```

Host plugins can recover across restarts on Linux and macOS. Set
`SANDBOX_DRIVER_HOST_REGISTRY` to a caller-owned directory, or use
`HostProvider::with_registry` in Rust. Stop fences sandbox process groups;
recovery never signals saved process ids. Named workspaces remain designated
unless `workspace_ownership: Managed` explicitly transfers their creation and
deletion to the provider. Managed workspaces are deleted only after work stops.

Run a command in a temporary Host sandbox:

```sh
lithos-sandbox --provider host sandbox run --workspace "$PWD" -- \
  bash -lc 'cargo test'
```

Use Docker for persistent sandbox operations:

```sh
id=$(lithos-sandbox --provider docker --output id sandbox create \
  --image ubuntu:24.04)
lithos-sandbox --provider docker sandbox exec "$id" -- uname -a
lithos-sandbox --provider docker sandbox delete "$id"
```

See [docs/cli.md](docs/cli.md) for provider profiles, plugin configuration,
creation specifications, output formats, and exit behavior.

## Diagnostics

The library crates emit `tracing` spans and events. Applications choose
the subscriber and output destination. Operation fields include provider
kinds, resource IDs, states, attempts, counts, and durations. They do not
include commands, environment values, tokens, URLs, file paths, request
bodies, or command output.

The plugin executables configure a stderr subscriber. They use `RUST_LOG`
when set and default to `info`. Protocol messages remain on stdout.

## Setup

Install the locked tools and prepare the repository:

```sh
mise trust
mise install --locked --jobs=1
mise run setup
```

Use the repository tasks for development and verification:

```sh
mise run dev
mise run test
mise run check
```

See [DEVELOPING.md](DEVELOPING.md) for the complete development workflow.

Routine and nightly checks run on macOS arm64, Linux x86_64, and Linux arm64.
A pushed `v*` tag builds one archive per plugin executable for the same three
platforms, with a checksum of each archive and of each executable, and
creates a draft GitHub release.
