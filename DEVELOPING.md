# Developing

The workspace builds the provider libraries, their plugin executables, and
the `lithos-sandbox` CLI. Applications link the bundled provider libraries
in-process or use the providers through JSON-RPC. Petri and fabro are the
primary consumers.

## Setup

Install [Mise](https://mise.jdx.dev/), then install the locked tools and prepare
the pinned Rust Style Guide:

```sh
mise trust
mise install --locked --jobs=1
mise run setup
```

## Common tasks

| Command | Purpose |
| --- | --- |
| `mise run dev` | Build the CLI and all provider executables |
| `mise run plugins:build` | Build provider executables for CLI tests |
| `mise run fmt` | Format Rust code |
| `mise run fmt:check` | Check formatting without changing files |
| `mise run lint` | Run Clippy with warnings denied |
| `mise run test` | Run the test suite |
| `mise run test:doc` | Compile and run core library and README examples |
| `mise run check` | Run the routine verification gate |
| `mise run check:nightly` | Run the extended verification gate |

Run `mise run check` before opening a pull request. The test tasks build
provider executables before CLI tests, including targeted `mise run test:cli`.

For local CLI use after `mise run dev`:

```sh
export SANDBOX_DRIVER_PLUGIN_DEV=1
target/debug/lithos-sandbox --provider host provider health
```

The CLI finds providers beside its own executable, then on `PATH`. Installed
providers require a checksum pin or explicit development mode. See
[the CLI guide](https://github.com/lithoscomputer/sandbox-driver/blob/main/docs/cli.md#provider-executables).

## Rust policy

This project follows the pinned Brynary Rust Style Guide. Run
`mise run setup`, then read `.ai/style-guides/rust-style-guide/SKILL.md` before
changing Rust code, configuration, project structure, or tests.

The project uses Rust 2024 and declares Rust 1.85 as its minimum supported
version. Mise pins the development compiler and the nightly formatter.

## Continuous integration

Routine checks run for pull requests and pushes to `main`. Extended checks run
each night. Both workflows test these native platforms:

- macOS arm64;
- Linux x86_64;
- Linux arm64.

## Releases

Pushing a `v*` tag builds the three plugin executables (`sandbox-driver-host`,
`sandbox-driver-docker`, `sandbox-driver-daytona`) for all three platforms,
one archive and SHA-256 checksum each, plus a checksum of each bare executable
for hosts that pin plugins. The workflow creates a draft GitHub release.
Review the draft before publishing it.

## Provider verification

The current Host and Docker conformance checks exercise both in-process and
plugin access. Docker checks need a running daemon. Daytona's live suite
needs `DAYTONA_API_KEY`.

The hosted nested Docker gate also needs
`SANDBOX_DRIVER_DAYTONA_DIND_SNAPSHOT`. Set it to a runner snapshot with
`start-docker`, the Docker CLI, and Python 3, at least 2 CPUs, and 4 GiB of memory:

```sh
cargo nextest run --locked -p sandbox-driver-daytona --test nested_docker --run-ignored only
```

See the [nested Docker design](https://github.com/lithoscomputer/sandbox-driver/blob/main/docs/design.md#nested-docker-on-daytona)
for the current configuration and restart behavior. Local tests cover command
construction and binary transfers; they do not replace this hosted gate.

## README examples and API migration

The root README follows the Lithos README guide and template. Its examples use
`sandbox_driver::contract` with the in-memory provider, so they can run before
real-provider migration is complete. The core crate includes them as doctests;
`mise run test:doc` and the routine gate compile and execute them.

Keep the [target specification](https://github.com/lithoscomputer/sandbox-driver/blob/main/docs/next-api.md)
as the detailed API contract. Before removing the README's preview notice,
verify the shared API, plugin loader, and all three providers pass conformance
together. Then replace the hero's fake setup with a working provider catalog,
update the CLI installation and examples, and recheck provider packaging and
protocol-version claims. Examples that need a daemon or credentials must use
`rust,no_run` so they still compile as doctests.

The existing [provider API](https://github.com/lithoscomputer/sandbox-driver/blob/main/docs/design.md)
and [version 2 protocol](https://github.com/lithoscomputer/sandbox-driver/blob/main/docs/protocol.md)
remain the references for current consumers during migration.
