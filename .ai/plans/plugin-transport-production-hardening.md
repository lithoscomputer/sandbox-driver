# Plugin transport production hardening

Status: implemented and validated on local `main` (2026-09-05). See [transport validation](../../docs/transport-validation.md) for the functional checks, Linux configuration, workload results, and 30-minute endurance evidence.

This plan prepares sandbox-driver's existing version-2 transport for a demanding CI API server on a single node. The application keeps provider plugins running and serves concurrent requests through them. The platform owns tenant authorization, credentials, and per-tenant quotas.

The [separate data transport decision](done/petri-plugin-data-transport.md) is implemented. This plan adds resource limits, failure handling, security checks, and performance validation. It does not reopen the choice of JSON-RPC for control and one private Unix socket connection per I/O operation.

The authoritative implementation contracts remain [docs/protocol.md](../../docs/protocol.md) and [docs/design.md](../../docs/design.md). Update those contracts as this work lands.

## Agreed deployment and acceptance targets

| Decision | Requirement |
| --- | --- |
| Deployment | Single node. No broker. |
| Tenancy | The CI platform enforces tenant authorization, credential separation, and per-tenant quotas. Do not add tenant identities or authorization policy to the plugin protocol. |
| Plugin lifetime | Reuse each plugin for the application's lifetime. Use separate instances for distinct provider configurations or credential contexts. Bound the number of instances. |
| Concurrent I/O | Validate 1,000 active I/O operations per plugin. Commands, terminals, log streams, and file transfers count. |
| Overload | Test bursts of 10,000 attempted operations. Reject excess work before provider work starts, with a structured overload error. Do not queue new work inside the plugin. |
| Reserved capacity | Keep capacity available for cancellation, hard stop, session close, shutdown, and cleanup when normal work is saturated. |
| Output retention | Streaming keeps no additional stdout/stderr copy by default. Optional capture requires a finite limit and reports truncation. All output still goes to the caller's stream while delivery succeeds. |
| Blocked output | Cancel an operation after 30 seconds without progress while output is waiting for delivery. Make the timeout configurable. A quiet command does not trigger this timeout. |
| Hard cancellation | Allow at most five seconds to drain pending output after hard cancellation, then close that operation's data channel. Make the deadline configurable and report abandoned output. |
| Control latency | Control round trips must remain below 100 ms at p99 with 1,000 active I/O operations, using a test provider with immediate control responses. Measure actual provider latency separately. |
| Reference machine | Linux, 8 vCPU, 16 GiB RAM. Measure the application-side client and plugin together. Evaluate sandbox compute separately. |
| Restart behavior | Fail calls affected by a plugin failure. Restart the plugin for new work. Do not automatically replay commands or mutations whose outcome is uncertain. |

These are validation targets and required behaviors, not measurements of the current implementation. The 10,000-attempt test establishes overload behavior, not support for 10,000 active operations.

## Scope boundaries

The application and its plugins are trusted infrastructure. Tenant code runs behind the selected provider's isolation boundary. A shared plugin can access every sandbox its credentials permit, so the platform must authorize resource IDs before forwarding requests.

Plugin processes, connections, and handle caches are disposable local state. The platform owns any durable resource identity and metadata it needs after a restart. Losing a local connection must not be reported as proof that remote work stopped.

The following work is deferred:

- Broker integration through a later Petri wrapper.
- Durable command ownership, reconnectable execution, and survival across application replacement.
- Routing live operations between API replicas or nodes.
- Distributed tenant quotas and scheduling.
- General hosted GitHub Actions compatibility and ObjectService reachability.

This plan does not require new Daytona VM access. Live provider validation uses the Container offering available to the project.

## Implementation requirements

### 1. Define finite limits and overload semantics

Add one coherent transport limits configuration. It must cover active I/O, pending channel opens, unauthenticated handshakes, in-flight provider requests, control-message size, queued control bytes, and retained output. Keep the current 64 KiB data-frame maximum and validate lengths before allocation.

Enforce admission on both sides of the protocol. Client-side checks improve errors for normal callers; server-side checks remain necessary for other client implementations. Admission must happen before a provider call can create resources or start work. Pending opens consume admission capacity so an unresponsive peer cannot bypass the active-operation limit.

Return a structured overload error that identifies the exhausted limit and establishes that the rejected operation did not start. The caller decides whether and when to retry. Do not classify an ambiguous operation failure as a safe admission rejection.

Reserve bounded capacity for control and cleanup. Ordinary provider requests cannot consume this reserve. Small, bounded transport-delivery queues are permitted; an internal queue waiting to start new provider work is not.

Define finite defaults for the remaining limits during implementation. Document every value and its accounting boundary. The reference configuration must pass the agreed 1,000-operation target. Do not present unmeasured defaults as established capacity.

Acceptance:

- Excess requests fail before observable provider effects.
- Pending opens, blocked writers, and repeated rejected handshakes stay within their limits.
- Cancellation and cleanup remain available during the 10,000-attempt burst.
- Normal work resumes after pressure falls. No request queue accumulates behind the capacity limit.

### 2. Bound memory throughout byte transfer

Reject oversized JSON messages while reading, before collecting an arbitrarily large line. A bounded message count alone does not bound queued bytes. Validate frame kinds, payload lengths, and negotiated limits consistently.

Make streaming capture opt-in with a finite cap. Preserve capture accounting and distinguish deliberately omitted capture bytes from output abandoned during transport failure or cancellation. Do not silently lose buffered output through a result type that cannot report truncation.

Whole-value convenience APIs must also have finite bounds. A call that promises a complete buffered value must return a limit error if it cannot provide that value within its bound. Callers needing large values should use streaming APIs. Explicit partial capture may return the bounded head/tail result with its accounting.

Audit file reads, append writes, writes without a declared length, fixed stdin, and provider fallback methods that collect a complete payload. Stream where the provider supports it. Otherwise, enforce a finite buffer bound before allocating beyond it. A failed write may have changed the destination; report partial or uncertain effects honestly.

Acceptance:

- Large streams make progress with memory independent of total stream length.
- Buffered APIs fail or report partial capture according to their documented contract.
- Truncated headers, premature EOF, excess input, and invalid frame sequences cannot produce a false complete result.
- Memory accounting includes queued messages, capture, pending operations, and cleanup work. Measure kernel socket memory separately from process RSS.

### 3. Keep control handling responsive

Remove application callback waits from the shared JSON-RPC response reader. Deliver events through bounded, ordered delivery paths. Preserve ordering within an event source and define an explicit failure signal when an event subscription cannot keep up. Do not silently drop events or block unrelated responses.

Document the observer contract. Applications requiring durable event persistence must enforce that boundary explicitly; it must not depend on blocking every control response behind an observer.

Prioritize cancellation and cleanup over ordinary work without creating an unbounded priority queue. Keep slow output consumers isolated to their own operations. Small output chunks must not wait for a frame to fill.

Acceptance:

- A blocked output sink and a blocked event observer do not stall unrelated control calls.
- Event order is preserved or an explicit subscription failure is reported.
- Control round trips meet the agreed p99 target with active output, not merely idle open channels.

### 4. Make completion and cancellation bounded and explicit

Keep stop registration ahead of channel acceptance so an early cancellation cannot overtake operation registration.

Track control completion and data completion separately. A successful control response alone does not establish complete output delivery. Unexpected connection closure must become a transport failure or an explicitly incomplete result, according to the operation contract.

Start the blocked-output timer only when bytes are pending and delivery cannot progress. Reset it on actual delivery progress. Quiet execution is governed by the caller's execution deadline, not this timer. Apply the rule to blocking output sinks and channel writes.

After hard cancellation, start the five-second local drain deadline without waiting indefinitely for a provider acknowledgment. At expiry, close only the affected operation's channel and stop its local pump. Report truncated output and distinguish confirmed termination, unconfirmed termination, and incomplete resource cleanup. The deadline bounds local waiting; it does not guarantee a remote process has stopped.

Continue to own cleanup tasks. Keep unresolved work within a fixed budget and expose it to the caller or health reporting. Do not return capacity as though cleanup succeeded while starting an unbounded set of background cleanup tasks. Graceful TERM-to-KILL policy remains the caller's responsibility.

Acceptance:

- Test cancellation before open, during input, during output, after the provider result, and during final EOF delivery.
- Blocked output triggers cancellation after the configured progress timeout; quiet commands remain unaffected.
- Hard cancellation ends local output waiting within the configured drain deadline.
- Report kill acknowledgment, local completion, provider termination, and resource cleanup separately in tests and metrics.
- An operation's failure does not close unrelated healthy data channels.

### 5. Recover from local failures without replay

Handle temporary listener resource exhaustion explicitly. The current accept loop exits on any accept error. Recovery must either resume accepting after bounded backoff or fail the transport and its pending operations clearly. Do not leave a live control connection with an abandoned data listener.

Bound shutdown and join owned tasks. On a dead plugin, fail every affected call and invalidate its local handles. Relaunch once for new work, under the same provider identity and credential context. The application remains responsible for reconciling uncertain provider effects.

Normal attachment must not assume that prior work is dead. Concurrent API requests can reconstruct handles even on one node. Separate ordinary attach/setup from recovery that stops work or sweeps resources. Audit Daytona nested Docker initialization, which currently performs cleanup through a fresh handle. Preserve active action containers and preparation files until their ownership has actually ended.

Acceptance:

- Inject descriptor exhaustion and verify recovery or explicit transport failure, without hung channel expectations.
- Kill the plugin with calls in flight. Assert failure reporting, no automatic replay, and one replacement instance for new work.
- Attach another handle while an action or image preparation is active. Existing work must continue.
- Repeated create/attach/close cycles do not grow handle registries, descriptors, temporary directories, or owned tasks without bound.

### 6. Harden the local socket boundary

Create the socket directory atomically with owner-only permissions and exclusive ownership. Do not rely on creating a permissive directory and changing permissions afterward. Bound and clean up partially initialized listeners.

Keep the random one-use token for each operation. Reject unknown, replayed, or mismatched tokens without consuming a legitimate operation's registration. Redact tokens and credentials from diagnostics.

Validate peer-process credentials against the expected launched plugin or an explicit trusted peer policy. Cover Linux and macOS with their respective mechanisms. These checks supplement platform isolation; they do not authorize tenants or protect against a compromised trusted provider.

Limit unauthenticated connections independently from admitted operations. Retain a bounded handshake timeout. Ensure stalled and malformed handshakes cannot exhaust the listener's tasks or descriptors.

Acceptance:

- Reject an unexpected peer, wrong token, reused token, invalid channel ID, and oversized or malformed open frame.
- Legitimate operations remain usable during invalid-connection bursts.
- Verify private-directory permissions and cleanup on initialization failure and normal shutdown.
- Confirm that diagnostics contain no operation tokens or provider credentials.

## Performance and failure validation

Build a repeatable transport benchmark using a test provider with immediate control responses and generated byte streams. The client and plugin share the 8-vCPU, 16-GiB reference machine. Record CPU model, architecture, kernel, toolchain, build profile, CPU/memory constraints, descriptor limits, transport limits, and the workload manifest.

Measure cold plugin startup separately from warm channel setup. For warm setup, measure from admission to availability of the authenticated channel. Also measure first-byte latency, aggregate throughput, CPU per GiB, client and plugin RSS, kernel socket memory, active tasks, and descriptor counts.

Run these workloads:

| Workload | Required evidence |
| --- | --- |
| 1, 100, and 1,000 active operations | Setup and control latency distributions, throughput, CPU, memory, and descriptors. |
| 1,000 operations producing output | p99 control round trips below 100 ms. Record offered byte rate and sink behavior. Idle channels alone do not satisfy this gate. |
| Bulk transfer near saturation | Show how backpressure or admission preserves control responsiveness. Record the throughput reached; do not invent a speedup requirement. |
| 10,000 attempted operations | Structured rejection before excess work starts, bounded resources, usable reserved controls, and recovery after the burst. |
| Many tiny operations | Connection churn, first-byte latency, and per-operation overhead. |
| Blocked sinks and event floods | Isolation, timeout behavior, cancellation latency, and explicit incomplete results. |
| Invalid peers, malformed input, and descriptor exhaustion | Bounded failure behavior and subsequent availability. |
| Repeated cycles and a sustained run of at least 30 minutes | No persistent growth in live operations, tasks, descriptors, handles, or temporary paths after cleanup; bounded steady-state memory. |

Report p50, p95, and p99, sample counts, repetitions, and workload rates. Distinguish control acknowledgment from complete cleanup. Do not claim a throughput multiplier or a fixed warm-start latency without measurements. Record capacity limits for the tested configuration; smaller machines need their own validation or lower settings.

Use real Host and Docker providers for correctness and end-to-end checks. Run available Daytona Container acceptance separately. Provider network delays, sandbox allocation, and actual command execution must remain visible in those results rather than being attributed to the local socket.

## Delivery sequence

1. Update the normative protocol and API contracts for limits, overload, capture, event delivery, and incomplete outcomes. Add failing behavioral regressions for the concrete defects identified above.
2. Implement bounded admission, frame/message validation, and byte budgets. Integrate the agreed capture behavior across the shared APIs and shipped providers.
3. Implement responsive event delivery, output progress deadlines, bounded hard-cancel draining, and owned cleanup.
4. Fix listener failure handling, attach/recovery separation, and local socket security. Verify lifecycle behavior through spawned plugins.
5. Run the benchmark on the reference machine, tune finite defaults, and publish the exact results and configuration. Update release documentation with the supported deployment and its limits.

Each change must follow the repository Rust style workflow and keep the relevant conformance suites passing. Use the routine verification gate for functional changes. Keep lengthy performance and leak tests in an explicit benchmark or extended gate on a controlled runner, so ordinary CI does not make hardware-dependent capacity claims.

Before marking this plan complete, all functional acceptance cases must pass, the reference configuration must meet the concurrency and latency targets, and the measured startup, throughput, and resource results must be recorded. Completing the plan does not establish broker-backed execution or cross-node recovery.

## Unresolved questions

None. Finite defaults, accounting boundaries, measured resource costs, startup, and throughput are documented in the protocol and transport validation report. The measurements apply to the tested configuration.
