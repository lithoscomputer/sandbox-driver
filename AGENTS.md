# Repository Instructions

## Project purpose

This repository is `sandbox-driver`: a Rust library for driving sandboxes
(manage sandboxes, snapshots, and volumes) across providers. Reference
providers are Host, Docker, and Daytona; additional providers ship as
plugin binaries speaking a JSON-RPC protocol. Fabro is the first
consumer.

Authoritative documents:

- `docs/design.md` — the Rust interface design: resource model,
  lifecycle actions, facets, capability discovery, and what stays out of
  this library.
- `docs/protocol.md` — the normative plugin wire protocol (version 2),
  written for implementers in any language. The compatibility tests in
  `crates/sandbox-driver-protocol` verify its encodings and tolerance
  rules behaviorally (era-JSON decoding, unknown-value handling) — not
  full-shape pins, which are change-detector tests and unwanted.
- `crates/sandbox-driver-conformance` — the black-box suite defining
  provider correctness; every provider, in-process or plugin, must pass
  it.

The workspace is `crates/sandbox-driver` (core traits and types) plus
`sandbox-driver-{conformance,host,docker,docker-config,daytona,protocol,cli}`
and the plugin executables `sandbox-driver-{host,docker,daytona}-plugin`.

## Rust style

Before changing Rust code, configuration, project structure, or tests:

1. Run `bin/style-guides prepare`.
2. Read `.ai/style-guides/rust-style-guide/SKILL.md` completely.
3. Read each workflow and policy page that the skill routes for the task.

Project requirements and accepted architecture decisions override general
style-guide defaults.

## Repository tasks

- Use `mise run dev` for the normal development path.
- Use `mise run test` for the routine test suite.
- Use `mise run check` for the complete routine verification gate.
- Use `mise run check:nightly` for the extended verification gate.
- Use `mise run fmt` to format Rust with the pinned nightly formatter.

## Safety

- Never install packages less than 24 hours old.
- Never force push, including with `--force-with-lease`.
- Never amend commits. Create a new commit instead.

## Working documents

Save plans under `.ai/plans/` and reviews under `.ai/reviews/`.
