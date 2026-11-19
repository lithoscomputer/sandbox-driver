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
| `mise run plugins:build` | Build the provider and fixture plugin executables used by tests |
| `mise run fmt` | Format Rust code |
| `mise run fmt:check` | Check formatting without changing files |
| `mise run lint` | Run Clippy with warnings denied |
| `mise run test` | Run the test suite |
| `mise run test:doc` | Compile and run core library and README examples |
| `mise run check` | Run the routine verification gate |
| `mise run check:nightly` | Run the extended verification gate |

Run `mise run check` before opening a pull request. The test tasks build
the fixture plugins before CLI tests, including targeted `mise run test:cli`.

For local CLI use after `mise run dev`:

```sh
target/debug/lithos-sandbox provider health docker
target/debug/lithos-sandbox run docker -- uname -a
```

Host, Docker and Daytona are linked into the CLI; other providers are
plugin entries in the catalog. See
[the CLI guide](https://github.com/lithoscomputer/sandbox-driver/blob/main/docs/cli.md).

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

Host runs the shared conformance suite in the routine tests. Docker's live
checks need a running daemon: run `mise run test:docker`, which
[Docker lifecycle coordination](https://github.com/lithoscomputer/sandbox-driver/blob/main/docs/docker-lifecycle.md#verification)
describes. Daytona's live suite needs `DAYTONA_API_KEY`: run `mise run test:live`.
Many provider tests still use the old API, including the old conformance
suite, which exercises in-process and protocol 2 plugin access; they are being
ported or removed with it.

The hosted nested Docker gate for Daytona also needs
`SANDBOX_DRIVER_DAYTONA_DIND_SNAPSHOT`. Set it to a runner snapshot with
`start-docker`, the Docker CLI, and Python 3, at least 2 CPUs, and 4 GiB of memory:

```sh
cargo nextest run --locked -p sandbox-driver-daytona --test nested_docker --run-ignored only
```

This gate drives the old Daytona provider's nested Docker configuration, which
is being removed. Local tests cover command construction and binary
transfers; they do not replace it.

## README examples

The root README follows the Lithos README guide and template. Its examples use
the `sandbox_driver` crate root with the in-memory provider from
`sandbox-driver-testing`, so they need no daemon or credentials. The core crate
includes them as doctests; `mise run test:doc` and the routine gate compile and
execute them. Examples that need a daemon or credentials must use `rust,no_run`
so they still compile as doctests.

The [design](https://github.com/lithoscomputer/sandbox-driver/blob/main/docs/design.md)
is the detailed specification of the API the README introduces. Change it in
the same pull request as the code it describes. The
[plugin protocol](https://github.com/lithoscomputer/sandbox-driver/blob/main/docs/protocol.md)
specifies version 3 in section 16; its other sections describe version 2, which
is being removed.
