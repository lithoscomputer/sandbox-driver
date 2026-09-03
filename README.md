# sandbox-driver

A Rust library for driving sandboxes across providers: manage sandboxes,
snapshots, and volumes behind one capability-discoverable interface.

| Crate | Purpose |
| --- | --- |
| `sandbox-driver` | Core traits, types, exec-derived facets, wait/probe helpers |
| `sandbox-driver-host` | Host (local) provider — directories, no isolation |
| `sandbox-driver-docker` | Docker provider — containers, pause/resume, image pulls |
| `sandbox-driver-daytona` | Daytona provider — cloud VMs, snapshots, volumes |
| `sandbox-driver-protocol` | JSON-RPC plugin protocol: serve any provider, adapt any plugin |
| `sandbox-driver-conformance` | Black-box conformance suite every provider must pass |
| `sandbox-driver-cli` | `lithos-sandbox` command for provider diagnostics and sandbox operations |

Host and Docker pass conformance locally (Docker needs a daemon); the
Daytona suite runs live with `DAYTONA_API_KEY` set. The protocol crate
re-runs the same suite through the wire.

See `docs/design.md` for the interface design
and `docs/protocol.md` for the normative plugin wire protocol.

## CLI

Build the `lithos-sandbox` command and inspect the available operations:

```sh
cargo build --locked -p sandbox-driver-cli
target/debug/lithos-sandbox --help
```

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

The host plugin configures a stderr subscriber. It uses `RUST_LOG` when
set and defaults to `info`. Protocol messages remain on stdout.

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
A pushed `v*` tag builds archives for the same three platforms and creates a
draft GitHub release.
