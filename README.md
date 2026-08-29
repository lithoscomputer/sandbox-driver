# sandbox-driver

A Rust library for driving sandboxes across providers: manage sandboxes,
snapshots, and volumes behind one capability-discoverable interface.
Initial providers: Daytona, Docker, and Host (local). Additional providers
arrive through a JSON-RPC plugin protocol.

See `.ai/plans/sandbox-driver-trait-design.md` for the interface design.

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
