# sandbox-driver

Create and operate sandboxes through one Rust API, with providers for local processes, Docker containers, and cloud VMs.

[![CI](https://github.com/lithoscomputer/sandbox-driver/actions/workflows/routine.yml/badge.svg)](https://github.com/lithoscomputer/sandbox-driver/actions/workflows/routine.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](#license)

```rust
use sandbox_driver::contract::{Error, ExecControls, ExecSpec};
use sandbox_driver_testing::contract::{FakeExec, FakeProvider};

#[tokio::main]
async fn main() -> Result<(), Error> {
    // Offline preview: script a result; no command runs on the host.
    let fake = FakeProvider::new();
    fake.script(["cargo", "test"], FakeExec::default()).await;
    let sandboxes = fake.sandboxes();
    let sandbox = sandboxes.builder("default").await?
        .label("job", "1842").create().await?;
    let outcome = sandbox.exec(
        ExecSpec::argv(["cargo", "test"]), ExecControls::default(),
    ).await?;
    sandboxes.destroy(&sandbox.reference()).await?;
    sandboxes.shutdown().await?;
    assert_eq!(outcome.exit_code, Some(0));
    Ok(())
}
```

**API preview:** This README introduces the upcoming `Sandboxes` interface.
The examples run today against the in-memory provider in `sandbox-driver-testing`.
Real-provider and plugin integration is still in progress.
See the [target specification](https://github.com/lithoscomputer/sandbox-driver/blob/main/docs/next-api.md)
and the [current provider API](https://github.com/lithoscomputer/sandbox-driver/blob/main/docs/design.md).

Part of [Lithos](#part-of-lithos), a family of Rust building blocks for AI tools.

## Why does this exist?

An application needs the same operations whether its workload runs locally,
in a container, or on a remote machine. Provider SDKs expose different
configuration, lifecycle, and execution APIs. `sandbox-driver` puts those
operations behind one interface and checks which capabilities a provider supports.

## Who is it for?

**Use it if** you are building an agent runner, workflow engine, or development
tool that creates sandboxes, runs commands, and returns to them later.

**Look elsewhere if** you need scheduling, queues, or workflow execution;
[Petri](https://github.com/lithoscomputer/petri) is the workflow engine in this family.
Use a provider's own SDK when you need operations outside the shared contract.

## What does it do?

The target interface provides:

- Named environments: select a workload template and override it for one sandbox.
- Sandbox lifecycle: create, inspect, stop, start, reattach, and destroy.
- Command execution with streamed input and output, timeouts, and cancellation.
- File transfers, port exposure, and optional services and one-shot containers.
- Saved sandbox references and label searches across configured providers.
- Plugin discovery, checksum verification, and supervision for external providers.

An **environment** is a named workload template on a **provider entry**.
The entry defines the connection, credentials, and plugin trust settings.
The environment defines what to run: its source, resources, network, and services.

In the target setup, Docker and [Daytona](https://www.daytona.io/), a cloud sandbox
service, run as in-process providers. Host and third-party providers run as
separately installed plugins. Applications use the same `Sandboxes` API for each.

**Out of scope:** Scheduling, queues, leases, and decisions about when to retry
or delete work belong to the application. Isolation depends on the provider;
Host runs processes in a directory and provides no isolation boundary.

| Crate | Use it when |
| --- | --- |
| `sandbox-driver` | Build against the shared API; the preview lives in `contract` |
| `sandbox-driver-docker` | Embed Docker support or build its provider executable |
| `sandbox-driver-daytona` | Embed Daytona support or build its provider executable |
| `sandbox-driver-host` | Build the Host executable; its current embedding API remains during migration |
| `sandbox-driver-docker-config` | Construct typed Docker options for the current provider API |
| `sandbox-driver-daytona-config` | Construct typed Daytona options for the current provider API |
| `sandbox-driver-protocol` | Serve or connect to providers over the current version 2 protocol |
| `sandbox-driver-conformance` | Check a provider against the shared behavioral contract |
| `sandbox-driver-testing` | Test callers with an in-memory provider and scripted commands |
| `sandbox-driver-cli` | Install the `lithos-sandbox` command |

## How do I use it?

### Install

This workspace is not published to crates.io. Add the core library from Git:

```sh
cargo add sandbox-driver --git https://github.com/lithoscomputer/sandbox-driver
cargo add tokio --features macros,rt-multi-thread,io-util
```

The examples also need the testing crate. Add it as a development dependency
and save each complete program under your application's `examples/` directory:

```sh
cargo add --dev sandbox-driver-testing --git https://github.com/lithoscomputer/sandbox-driver
cargo run --example sandbox
```

Use `examples/sandbox.rs` for the first example. It needs no daemon or credentials.
The library uses the application's Tokio runtime.

### Use it as a library

Create one `Sandboxes` catalog per process. Production callers supply provider
entries, an `EnvironmentSource`, a `Registry`, a `SecretResolver`, and
`CatalogOptions` to `Sandboxes::try_new`. The library ships no default providers
or environments. The fake's `default` environment is a test fixture.

Provider entries stay fixed for the catalog's lifetime. Environments can come
from a static list, a configuration file, or an application store.
Applications register provider adapters explicitly; core does not install them.
See [catalog configuration](https://github.com/lithoscomputer/sandbox-driver/blob/main/docs/next-api.md#configuration)
for the target setup and remaining integration work.

Save a `SandboxRef` to return to a sandbox. It contains the provider entry,
namespace, and sandbox ID, so it does not depend on the environment's name.
This offline example reattaches and reads a file through the shared API:

```rust
use std::io::Cursor;
use tokio::io::AsyncReadExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sandboxes = sandbox_driver_testing::contract::fake();
    let sandbox = sandboxes.builder("default").await?.create().await?;
    sandbox.files().put("result.txt", Box::pin(Cursor::new(b"passed"))).await?;
    let reference = sandbox.reference();
    drop(sandbox);

    let attached = sandboxes.attach(&reference).await?;
    let mut reader = attached.files().get("result.txt", None).await?;
    let mut result = String::new();
    reader.read_to_string(&mut result).await?;
    sandboxes.destroy(&reference).await?;
    sandboxes.shutdown().await?;
    assert_eq!(result, "passed");
    Ok(())
}
```

Use labels to find related work across providers:

```rust
use sandbox_driver::contract::{Error, LabelFilter};

#[tokio::main]
async fn main() -> Result<(), Error> {
    let sandboxes = sandbox_driver_testing::contract::fake();
    let sandbox = sandboxes.builder("default").await?
        .label("job", "1842").create().await?;
    let found = sandboxes.find(LabelFilter::eq("job", "1842")).await?;
    sandboxes.destroy(&sandbox.reference()).await?;
    sandboxes.shutdown().await?;
    assert!(found.unavailable.is_empty());
    assert_eq!(found.sandboxes.len(), 1);
    Ok(())
}
```

`find` returns partial results when a provider cannot be reached. Inspect
`unavailable` and `failures`; missing results do not prove a sandbox was deleted.
The fake executes only scripted commands and advertises no optional capabilities.

With real providers, reattachment depends on their declared durability and access
scope. The target Host plugin promises access only through its owning process.
A lost connection or dropped execution future does not confirm that work stopped.
The library does not replay mutations whose outcome is unknown.

More detail: [client API](https://github.com/lithoscomputer/sandbox-driver/blob/main/docs/next-api.md#client-api),
[provider contract](https://github.com/lithoscomputer/sandbox-driver/blob/main/docs/shared-contract.md),
and [diagnostics](https://github.com/lithoscomputer/sandbox-driver/blob/main/docs/diagnostics.md).

### Use it from the command line

The current CLI still uses the existing provider API and version 2 protocol:

```sh
cargo install --git https://github.com/lithoscomputer/sandbox-driver --locked sandbox-driver-cli
lithos-sandbox --help
lithos-sandbox provider list
```

Sandbox operations also need an installed provider executable and its checksum
configuration. Docker needs a reachable daemon; Daytona needs API credentials.
See the [current CLI guide](https://github.com/lithoscomputer/sandbox-driver/blob/main/docs/cli.md).
The [planned CLI](https://github.com/lithoscomputer/sandbox-driver/blob/main/docs/next-api.md#cli)
will use the environment catalog; those commands are not available yet.

## Status and compatibility

- **Maturity:** Pre-1.0; the public API is changing during the migration.
- **Implemented preview:** The catalog, schema validation, scripted fake, and common conformance suite are available under `contract` modules.
- **Cutover gate:** The shared API, plugin loader, and Docker, Daytona, and Host providers must pass conformance together before real-provider adoption.
- **MSRV:** Rust 1.85, as declared in the workspace manifest.
- **CI platforms:** macOS arm64, Linux x86_64, and Linux arm64.
- **Public formats:** Serialized configuration and sandbox references; plugin protocol version 2 today, version 3 in the target specification.

Current provider integration tests are separate from the new-contract gate.
Host and Docker have in-process and plugin checks; Docker needs a daemon.
Daytona's live checks require `DAYTONA_API_KEY`.
See [development and verification](https://github.com/lithoscomputer/sandbox-driver/blob/main/DEVELOPING.md).

## Part of Lithos

| Crate | Role |
| --- | --- |
| [lithos-llm](https://github.com/lithoscomputer/lithos-llm) | Model access: one client and catalog across LLM providers |
| [pebble](https://github.com/lithoscomputer/pebble) | Agent loop, plus a coding agent and CLI built on it |
| **[sandbox-driver](https://github.com/lithoscomputer/sandbox-driver)** | **Sandboxes (host, Docker, cloud VMs) behind one interface** |
| [petri](https://github.com/lithoscomputer/petri) | Workflow engine that runs CI and agent workflows on the crates above |

## Contributing

Development setup, tests, and conventions are in
[DEVELOPING.md](https://github.com/lithoscomputer/sandbox-driver/blob/main/DEVELOPING.md).

## License

Licensed under the [MIT License](https://github.com/lithoscomputer/sandbox-driver/blob/main/LICENSE).
