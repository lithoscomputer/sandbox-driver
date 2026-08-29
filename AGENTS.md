# Repository Instructions

## Project purpose

This repository is `sandbox-driver`: a Rust library for driving sandboxes
(manage sandboxes, snapshots, and volumes) across providers. Initial
providers are Daytona, Docker, and Host; more arrive later through a
JSON-RPC plugin protocol. Fabro is the first consumer.

Authoritative documents:

- `.ai/plans/sandbox-driver-trait-design.md` — the Rust interface design
  (resource model, lifecycle actions, facets, capability discovery).
- The prior JSON-RPC plugin plan in
  `~/p/fabro-sh/fabro-3/.ai/plans/sandbox-provider-plugins.md` informs the
  upcoming protocol crate.

The workspace layout is `crates/sandbox-driver` (core traits and types)
with `sandbox-driver-{protocol,host,docker,daytona}` siblings added as
they are built.

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
