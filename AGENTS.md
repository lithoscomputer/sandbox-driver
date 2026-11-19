# Repository Instructions

## Project purpose

This repository is `sandbox-driver`: one Rust API for creating and operating
sandboxes across providers. Petri and fabro are the primary consumers.

Applications build a `Sandboxes` catalog from provider entries and
environments. Host, Docker, and Daytona are built-in providers: libraries the
application registers with `Registry::builtin` and runs in its own process.
Third-party providers are plugins, executables that the plugin loader in
`sandbox-driver-protocol` launches and supervises over protocol version 3.
Clients see the same `Sandbox` trait either way.

Still in the tree but being removed: the old provider API in the hidden
`sandbox_driver::legacy` module (and the old suites and doubles beside it),
protocol version 2, the Host, Docker, and Daytona provider executables, and
the two `*-config` crates. Do not build new work on them; tag `v2` is the
archive.

Authoritative documents:

- `docs/design.md` — the API and what providers must guarantee: the client API,
  catalog configuration, identity, workloads, lifecycle and fences, the
  `Provider` interface, and writing a plugin.
- `docs/protocol.md` — the plugin wire protocol, written for implementers
  in any language. Section 16 is version 3; the rest describes version 2,
  which is being removed. The compatibility tests in
  `crates/sandbox-driver-protocol` verify its encodings and tolerance
  rules behaviorally (era-JSON decoding, unknown-value handling) — not
  full-shape pins, which are change-detector tests and unwanted.
- `crates/sandbox-driver-conformance` — the black-box suite defining
  provider correctness; every provider, built in or plugin, must pass it.

The workspace is `crates/sandbox-driver` (core traits and types) plus
`sandbox-driver-{conformance,testing,host,docker,daytona,protocol,fixture-plugins,cli}`
and the `sandbox-driver-{docker,daytona}-config` crates being removed.
The CLI builds `lithos-sandbox`, and `sandbox-driver-fixture-plugins` builds
the protocol 3 test plugins.

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

## README.md

Keep README.md focused on what the library is, who it serves, installation,
short examples, scope, compatibility, and the Lithos family. Put API reference
in rustdoc, longer guides in `docs/`, and contributor tasks in `DEVELOPING.md`.
Use absolute GitHub URLs for repository links.

The README introduces the API that `docs/design.md` specifies; keep the two
consistent. Its Rust examples are doctests. Run `mise run test:doc` after
changing them; `mise run check` also runs them. Keep examples complete,
without hidden lines or ignored code blocks.
