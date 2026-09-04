# Handoff: sandbox-driver and daytona-sdk-rust

Updated 2026-08-31. Read `docs/design.md` and `docs/protocol.md` first. They are the authoritative interface and wire-protocol documents.

## Repositories

- `sandbox-driver`: `/Users/bhelmkamp/p/lithoscomputer/sandbox-driver`
- `daytona-sdk-rust`: `/Users/bhelmkamp/p/brynary/daytona-sdk-rust`
- Fabro: `/Users/bhelmkamp/p/fabro-sh/fabro`

`sandbox-driver` is a Rust library for Host, Docker, and Daytona sandboxes. Other providers can use plugin binaries over the version 1 JSON-RPC protocol. Fabro is the first planned consumer.

`daytona-sdk-rust` supplies the generated API clients and the handwritten SDK used by the Daytona driver.

## Current revisions

- Driver implementation baseline before this document refresh: `3318bbc` on `main`.
- Driver SDK pin: `7de0d4ce7cede28d4f46bc58aafc8cb9210c122d`.
- SDK branch: `feat/sync-v0207-surface`.
- SDK branch head: `7de0d4c`, pushed to origin.
- SDK PR: `brynary/daytona-sdk-rust#6`, open against `main`.
- Generated SDK clients: Daytona `v0.207.0`, OpenAPI Generator `7.21.0`.

The v0.207.0 main and toolbox OpenAPI documents are byte-for-byte identical to the v0.205.1 documents. Their SHA-256 values did not change. The generation commands now include `enumUnknownDefaultCase=true`, which preserves the checked-in forward-compatible enum behavior.

## Current result

The normalized public surface and the Daytona implementation include:

- start, stop, delete, archive, pause/resume, fork, timers, labels, and activity refresh;
- CPU, memory, disk, GPU, region, sandbox kind, and virtualization requests;
- image, Dockerfile, filesystem, and live-process snapshot modes;
- snapshot get, list, create, build-log streaming, activate, deactivate, and delete;
- volume create, create-time mount, get, list, and delete;
- filesystem, search, and Git operations;
- buffered and streaming execution, finite stdin, cancellation, and bidirectional stdio;
- separate stdout and stderr for non-PTY execution;
- concurrent PTY input, output, resize, close, and wait;
- output modes `Raw`, `StripAnsi`, and `StripAll`;
- preview URLs, signed preview URLs, web terminal, SSH, and VNC;
- create-time and runtime network policy, including CIDR limits;
- provider entrypoint logs and snapshot build logs;
- provider events, health, and the version 1 plugin transport.

Tailscale is not a public sandbox-driver facet. Callers configure it inside a guest through `Exec`. Boxd-only checkpoint, runtime disk, proxy, custom-domain, hibernation, and named-network operations remain outside the public interface.

## Verification completed on 2026-08-31

### Driver

- `mise run check`: 151 tests passed.
- Full live Daytona package run: passed.
- In-process Daytona conformance: passed.
- Daytona wire conformance: passed.
- Focused Daytona live suite: 8 tests passed.
- Shared `Logs::follow` conformance now checks output delivery, sink-error propagation, and cancellation when the follow future is dropped.
- Live timer coverage verifies wall-clock TTL on a container and Daytona's explicit rejection of container auto-pause.

### SDK

- Clippy with `-D warnings`: passed.
- SDK unit tests: 190 passed.
- Forward-compatible permission tests: 4 passed.
- Seven new direct live tests passed. They cover session input with split streams, interactive PTY input/output/resize/wait, Dockerfile snapshot creation and build logs, sandbox snapshot creation, TTL, container auto-pause rejection, runtime network changes, and conditional VM pause/fork.
- The VM test skipped its provider operations because Daytona reported no Linux VM runner for the organization.

All live tests use `DAYTONA_API_KEY`. They create billable resources and delete them in cleanup paths.

## Commits in this final work sequence

Driver:

- `94d9b49` — shared behavioral log-follow conformance.
- `245916b` — live wall-clock TTL and container auto-pause behavior.
- `3318bbc` — pin the regenerated Daytona SDK commit.

SDK:

- `3ee67c1` — direct live SDK surface tests.
- `7de0d4c` — record Daytona v0.207.0 generation and make enum generation reproducible.

## Known limits

- Daytona resize remains disabled. The hosted `POST /sandbox/{id}/resize` route returned a route-level 404 during live verification.
- Pause, fork, and live-process snapshots are class-aware. Daytona supports them on VM classes, not the default container class.
- Positive VM pause, fork, auto-pause, and live-process snapshot proof remains blocked until the Daytona organization has a Linux VM runner.
- Daytona stdio is UTF-8 by transport. It is suitable for ACP JSON lines, but it is not a general binary channel.
- PTY output is a combined terminal stream. Non-PTY execution can preserve separate stdout and stderr.
- Secret references and Daytona secret substitution remain outside the normalized interface.

## Next work

1. Merge SDK PR \#6. Then repin `sandbox-driver` to the merge commit on SDK `main` and run `mise run check` again.
2. Add positive live VM verification when the organization has a Linux VM runner. Cover pause/resume, fork with running process state, automatic pause, and `SnapshotMode::LiveProcessState` with stable PIDs.
3. Report the Daytona resize-route 404 upstream with a minimal reproduction.
4. Plan and implement the Fabro migration. Put the plan in `.ai/plans/` and open it in Quarry before implementation.
5. Add a Boxd plugin only when needed. Do not expand the public API for Boxd-only features.

## Daytona semantics

- Daytona has no separate resume endpoint. `start` resumes a paused sandbox.
- Pause completes when the sandbox leaves `pausing`. The settled result can be paused, stopped, or archived.
- A sandbox snapshot completes when the sandbox leaves `snapshotting`.
- Non-zero auto-stop and auto-pause are mutually exclusive. The driver disables auto-stop before it enables auto-pause when needed.
- Timer zero encodings differ upstream. The driver normalizes `Duration::ZERO` to "never" and performs provider-specific translation.
- Daytona `recover` is undelete within the provider retention window. It maps to provider-level `undelete`, not recovery from `SandboxState::Error`.
- Snapshot activation can race deactivation. The driver retries the documented in-progress rejection within a bounded wait.
- Provider capabilities are an upper bound. Each sandbox handle narrows them using its Daytona sandbox class.

## Execution and wire semantics

- Exec takes a program and arguments and runs them directly, with no shell. `ExecSpec::bash(script)` is the helper for Bash source: `bash -c`, non-login, without implicit `errexit` or `pipefail`, and with `BASH_ENV` blanked. The exec-derived facets use it.
- Dropping a streaming operation must cancel its provider-side work. The plugin transport sends `stream/cancel` for dropped log and build-log follows.
- Plugin stdio and PTY output use sequential long polling. Only one output read per stream ID can be outstanding.
- A caller must drain stdout while waiting for a long-lived process. This matches normal pipe backpressure.
- PTY environment variables use Daytona's base64url subprotocol token. The WebSocket server must negotiate the offered subprotocol.
- `Raw` preserves all bytes. `StripAnsi` removes ANSI escape sequences. `StripAll` also removes standalone C0 and C1 control characters except tab, line feed, and carriage return.
- PTY and long-lived stdio remain raw terminal transports.

## Development commands

- Prepare Rust instructions: `bin/style-guides prepare`.
- Format: `mise run fmt`.
- Routine gate: `mise run check`.
- Extended gate: `mise run check:nightly`.
- Driver live tests require `.env` in the driver repository.
- SDK live tests can use the same `DAYTONA_API_KEY` environment value.

Never amend commits. Never force push.
