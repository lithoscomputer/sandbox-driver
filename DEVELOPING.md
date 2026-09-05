# Developing

The workspace builds the provider executables and the `lithos-sandbox` CLI.
Applications use the providers through JSON-RPC. Petri is the primary consumer.

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
[the CLI guide](docs/cli.md#provider-executables).

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
