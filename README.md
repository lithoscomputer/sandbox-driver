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

Host and Docker pass conformance locally (Docker needs a daemon); the
Daytona suite runs live with `DAYTONA_API_KEY` set. The protocol crate
re-runs the same suite through the wire.

See `docs/design.md` for the interface design
and `docs/protocol.md` for the normative plugin wire protocol.

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
