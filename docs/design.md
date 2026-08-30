# sandbox-driver: Rust Interface Design

A library for driving sandboxes. Initial providers: **Daytona**, **Docker**, **Host** (local). Later: boxd, Azure, and third parties via the JSON-RPC plugin protocol. Fabro is the first consumer, so fabro's current `Sandbox` trait (34 methods, `fabro-sandbox/src/sandbox.rs:1237`) is the floor: everything fabro uses must have a home here or a documented home above this crate.

## Inputs

- **fabro** — the de-facto trait: filesystem, exec (buffered / streaming / bidirectional stdio), grep/glob/walk, lifecycle, preview URLs, SSH, auto-stop, events, the Bash contract and probe, plus a git/credential surface we deliberately leave above this crate.
- **Daytona** (docs + `daytona-sdk-rust`) — the richest provider: pause/resume distinct from stop/start, archive, fork with ancestry, resize, live-sandbox snapshots including memory, TTL and four auto-intervals, snapshots and volumes as first-class resources, per-region toolbox daemon (fs/git/process/PTY/LSP/computer-use), preview links with signed URLs, SSH tokens, network block/allow lists.
- **boxd** (deferred) — pause/resume/hibernate, **fork with memory+disk in milliseconds**, **checkpoints (rewind in place)**, snapshots as named images, HTTPS proxies per machine, VM-to-VM private networking. Included now only to make sure the lifecycle vocabulary doesn't need reshaping later.

## Security and trust boundary

"Sandbox" is a resource name here, **not a security claim** — isolation is a per-provider property, declared in `Capabilities` (`isolation: none | container | vm`) and never assumed:

- **Host is not an isolation boundary.** Commands run as the calling user; file operations can reach anything that user can, including outside the working directory. It exists for parity and local development and declares `isolation: none`.
- **Docker isolates filesystem and processes but shares the host kernel**, and the Docker socket is host-root-equivalent — the Docker provider is host-trusted by definition.
- **Daytona and boxd are VM-backed**; their isolation is the vendor's guarantee, reported as declared.

Trust flows as in the fabro plugin plan: **a provider — in-process or JSON-RPC plugin — is inside the trust domain of every sandbox it drives.** It has full exec, so it can read anything the workload can; per-call credential injection is not a defense against that. What the library does enforce is the *host-side* boundary: a provider receives only the secrets explicitly passed in a spec or fetched per-call through the host callback interface — never ambient environment or vault contents — so one provider's compromise does not expose another's credentials. Transport-level trust for plugins (checksum pinning, scrubbed environment, deny-by-default discovery) is host policy, specified in the protocol document, not this trait.

The default network policy is the provider's default (Docker: bridge; Daytona: allow-all); a closed sandbox requires an explicit `NetworkPolicy::Block` in the spec. The capability schema records which network modes a provider supports so callers can preflight the strictness they need.

## Resource model

Three managed resource types, one provider object:

```
SandboxProvider (per backend: daytona, docker, host, …)
 ├── sandboxes: create / attach / list  ──►  Sandbox (handle)
 ├── snapshots: Option<&dyn SnapshotProvider>
 └── volumes:   Option<&dyn VolumeProvider>
```

A `Sandbox` is a **stateless handle**: an ID plus a provider connection. It holds no cached state; `describe()` returns the current observed status. This is what makes the handle serializable across the JSON-RPC boundary and lets a restarted host or plugin re-attach by ID (cloud sandboxes are identified by remote IDs the caller persists).

```rust
pub struct SandboxId(String);     // validated newtypes; also SnapshotId, VolumeId
```

### State model

Adopted from Daytona's split, which is the cleanest of the three: a small **typed state enum** for logic, plus the provider's raw state string for display and debugging.

```rust
#[non_exhaustive]
pub enum SandboxState {
    Creating, Starting, Running, Stopping, Stopped,
    Pausing, Paused, Resuming,
    Archiving, Archived, Restoring,
    Resizing, Forking, Snapshotting,
    Deleting, Deleted,
    Error, Unknown,
}

pub struct SandboxStatus {
    pub id: SandboxId,
    pub state: SandboxState,
    pub provider_state: String,          // raw, e.g. Daytona's "pulling_snapshot"
    pub error_reason: Option<String>,
    pub resources: Option<Resources>,
    pub labels: BTreeMap<String, String>,
    pub created_at: Option<SystemTime>,
    // …timestamps, network summary
}
```

The library ships one generic wait helper (poll `describe`, fail on `Error`, succeed on target state, configurable interval/deadline) instead of N hand-written loops — both the Daytona SDK and fabro grew several of those independently.

## Lifecycle actions

The full vocabulary. **Core** actions are required of every provider. Everything else is optional and capability-gated; calling an unsupported action returns `Error::Unsupported` naming the capability, so callers can preflight instead of failing mid-run.

| Action | Meaning | Core? | Host | Docker | Daytona | boxd |
| --- | --- | --- | --- | --- | --- | --- |
| `create` | Provision from a spec | core | ✔ (dir: designated or managed) | ✔ | ✔ | ✔ |
| `describe` | Observed status | core | ✔ | ✔ | ✔ | ✔ |
| `start` / `stop` | Cold boot / shutdown; disk persists | core¹ | no-op | ✔ | ✔ | ✔ |
| `delete` | Destroy; idempotent (unknown ID succeeds) | core | ✔ (cleanup) | ✔ | ✔ | ✔ |
| `pause` / `resume` | Freeze with memory kept; distinct from stop | opt | — | ✔ (`docker pause`) | ✔ | ✔ (hibernate) |
| `archive` | Stopped → cold storage; `start` restores | opt | — | — | ✔ | — |
| `fork` | Clone a sandbox (disk, optionally memory) → new sandbox | opt | — | — | ✔ (+ ancestry) | ✔ |
| `checkpoint` / `restore` | Save a rewind point; rewind the **same sandbox** in place | opt | — | — | — | ✔ |
| `resize` | Change cpu/memory/disk | opt | — | \~ (`docker update`, cpu/mem only) | ✔ | ? |
| `snapshot_sandbox` | Snapshot a live sandbox (optionally incl. memory) → SnapshotProvider | opt | — | \~ (`docker commit`) | ✔ | ✔ |
| `recover` | Provider-assisted recovery from Error state | opt | — | — | ✔ | — |
| `refresh_activity` | Keepalive; reset idle timers | opt | no-op | no-op | ✔ | ? |
| `set_timers` | auto\_stop, auto\_pause, auto\_archive, auto\_delete, ttl | opt | — | — | ✔ | ? |
| `set_labels` | Replace label map | opt | — | ✔ | ✔ | ✔ (tags) |
| `update_network` | Change network policy on a live sandbox | opt | — | — | ✔ | ✔ |

¹ Host implements `start`/`stop` as no-ops (nothing to boot); they are still in the core so callers never branch on provider kind.

Deliberate merges:

- **`activate` (fabro) is not a provider action.** It is a provided convenience: "ensure running" = describe → start if stopped/archived, or resume if paused → wait → run the health probe. Lives in the library, implemented once over the core.
- **`restore` from archive is implicit in `start`** (Daytona's model); no separate verb.
- **Ephemeral is a first-class spec flag**, not `auto_delete_interval == 0` — Daytona's encoding leaks into every wait loop (`stop` tolerating NotFound); we translate the flag per provider instead.
- **`checkpoint`/`restore` are identity-preserving.** `restore_checkpoint` rewinds the *same* sandbox — same ID, same handle — in place. Daytona cannot do that: its nearest neighbor (live snapshot + fork) produces a *new* sandbox, so it is reported honestly as the separate `snapshot_sandbox` and `fork` capabilities, never as checkpointing. The verb is in the vocabulary now (boxd needs it) so adding boxd later is additive.
- **Host workspace ownership.** A Host sandbox is either a **designated** caller-owned directory or a **managed** temporary workspace the library created; the distinction is set in the spec and visible in `SandboxStatus`. `delete` removes managed workspaces only — on a designated directory it releases the handle and never touches caller data.

### Timers

```rust
pub struct LifecycleTimers {
    pub auto_stop_after_idle: Option<Duration>,
    pub auto_pause_after_idle: Option<Duration>,   // mutually exclusive with auto_stop
    pub auto_archive_after_stop: Option<Duration>,
    pub auto_delete_after_stop: Option<Duration>,
    pub ttl: Option<Duration>,                     // wall clock since create
}
```

## Sandbox features (facets)

Per-sandbox functionality is grouped into small **facet traits** (per the style guide: cohesive, behavior-named, minimal). A sandbox exposes each facet through an accessor; optional facets return `Option`, so *absence is visible in the type system*, and the serializable `Capabilities` struct carries the fine-grained flags inside each facet for preflight and the wire protocol.

| Facet | Contents | Host | Docker | Daytona | boxd |
| --- | --- | --- | --- | --- | --- |
| `Exec` (core) | Buffered run; streaming run (callback sink, stdin, cancel, timeout); Bash contract | ✔ | ✔ | ✔ (streams via log-poll fallback) | ✔ |
| `StdioProcess` | Spawn long-lived bidirectional process (ACP backends) | ✔ | ✔ | ✖ today — the known gap | ? |
| `Filesystem` (core) | read/write/delete/exists/stat/list/move/mkdir/permissions, upload/download (binary-safe, chunked) | native | native | native (toolbox FS) | ✔ |
| `Search` (core, derived) | grep, glob, walk — default impl derived from `Exec` (rg with grep/find fallback); provider may override | derived | derived | derived (native find/replace exists) | derived |
| `Git` | clone, status, add, commit, push, pull, branches, checkout — low-level plumbing only; default impl derived from `Exec`, per-call credentials | derived | derived | derived or native | derived |
| `Pty` | create/resize/kill + bidirectional byte stream (fabro's `TerminalSession`) | ✔ | ✔ (exec+tty) | ✔ (websocket) | ✔ (console) |
| `Logs` | Provider-side logs: build/provision logs, entrypoint output, sandbox event log; streaming follow | — | ✔ (container logs) | ✔ | ? |
| `PreviewUrls` | port → `{ url, headers }`; signed expiring URLs; revocation | \~ (localhost) | future (port map) | ✔ | ✔ (HTTPS proxies) |
| `SshAccess` | Mint/revoke time-limited SSH access; returns ready-to-run command | — | — | ✔ | ✔ |
| `ShellCommand` | A local command string that opens a shell (Docker's `docker exec -it …`) — distinct from real SSH | trivial | ✔ | — | — |
| `WebTerminal` | URL to a browser terminal | — | — | ✔ | ✔ |
| `Vnc` | Desktop viewing: connection URL/credentials. Reserved; no initial provider has it natively (Daytona: computer-use screenshots or self-run VNC behind a preview URL) | — | — | \~ | — |
| `Vpn` | Join a private network (Tailscale, provider VPN); create-time config + status. Reserved capability | — | future | \~ (VPN connections) | \~ (VM-to-VM) |
| `NetworkLimits` | Spec-time: block-all / CIDR allow-list / domain allow-list / outbound proxy. Runtime update where supported | — | \~ (none/bridge only) | ✔ | ✔ |

Legend: ✔ supported · \~ partial/approximated · — unsupported (facet returns `None`) · ? unknown until boxd work starts.

Notes:

- **Search and Git ship as derived implementations** over `Exec` in this crate — fabro's experience shows `glob` was *never* overridden by any provider and git-via-exec is what both remote providers actually do. A provider with a native API can override per method.
- **Git here is plumbing only.** Fabro's credential machinery (`refresh_push_credentials`, `push_token_source`, `git_push_ref` retry/lease engine, `setup_git` intent, clone orchestration and repo layout) stays in fabro, layered on `Exec` + `Git`. Those 6 of fabro's 34 methods do not move into this crate.
- **`Vnc` and `Vpn` are reserved facets**: defined in the capability schema now so the wire protocol doesn't break when a provider adds them, but no trait methods beyond "get connection info" in v1.
- Daytona's **LSP, code interpreter, computer-use input automation, and command sessions** are out of scope for v1 — real surfaces, but no consumer yet. The capability schema reserves names for them.

## Capability discovery

Two complementary mechanisms, by design:

1. **Typed accessors** — `fn pty(&self) -> Option<&dyn Pty>`: absence is unrepresentable-misuse at compile time for in-process consumers.
2. **Serializable `Capabilities`** — a data structure for preflight checks, `Unsupported` error payloads, and the JSON-RPC `initialize` handshake. Fine-grained flags live here (`exec.live_streaming`, `exec.streams_separated`, `fs.native`, `lifecycle.pause`, `snapshots.include_memory`, `network.modes`, …).

```rust
#[non_exhaustive]
pub struct Capabilities {
    pub isolation: Isolation,         // none | container | vm — declared by the provider, never assumed
    pub lifecycle: LifecycleCaps,     // pause, archive, fork, checkpoint, resize, recover, timers…
    pub exec: ExecCaps,               // live_streaming, streams_separated, stdin, cancel, stdio_process
    pub fs: FsCaps,                   // native, upload, download, permissions
    pub git: GitCaps,
    pub pty: Option<PtyCaps>,
    pub logs: Option<LogsCaps>,
    pub access: AccessCaps,           // preview_urls { signed }, ssh, shell_command, web_terminal, vnc, vpn
    pub network: NetworkCaps,         // modes: block_all, allow_all, cidr_allow_list, domain_allow_list, proxy
    pub snapshots: Option<SnapshotCaps>,  // sources: image, dockerfile, live_sandbox, memory
    pub volumes: Option<VolumeCaps>,
}
```

The contract, taken from CSI and the prior fabro plan: **capabilities are load-bearing.** A missing capability changes behavior at *preflight* (the caller adapts, derives, or refuses with a message naming the provider) — never as a mid-run `Err("not supported")`, which is what fabro's silent `Ok(None)` defaults produce today and which is indistinguishable from "supported, nothing to report."

Capabilities are **negotiated metadata, not live state**. They are captured once, at `create`/`attach` (for plugin providers, that is the JSON-RPC `initialize` handshake), and are immutable for the life of the handle — the one piece of data a handle carries besides its ID. Re-attaching yields a fresh set; that is how a provider upgrade is observed. `resize` does not change capabilities: they describe supported operations, not current resources. `SandboxProvider::capabilities()` is the provider's **upper bound** — the union of what it can offer, for pre-create decisions; the per-sandbox set (`Sandbox::capabilities()`) is authoritative and may be narrower depending on the spec (Daytona: linux-vm vs container vs android classes). Preflight catches predictable mismatches, but every capability-gated method still returns a structured `Unsupported` when a stale or misreported capability meets reality — capabilities optimize failure timing; they are not the enforcement mechanism.

### Wire compatibility

The protocol crate owns wire compatibility; domain types never absorb a wire break. The `initialize` handshake negotiates a protocol version and capability set. Readers ignore unknown optional object fields and return a structured protocol error for unknown required semantics. Enums define stable string values and an unknown-value policy. Durations, timestamps, paths, and byte payloads use explicit wire formats. Provider configuration carries a provider kind and schema version and is validated at the provider boundary. In v1 the wire DTOs may share their serde shape with core domain types, pinned by golden-file tests in the protocol crate and by `#[serde(other)]` unknown-variant fallbacks on state enums; when a shape needs to diverge, the protocol crate grows a dedicated DTO and conversion — core types are never broken for wire reasons.

## The traits

Sketches, not final signatures. All async via `async_trait`, all object-safe (`dyn`-usable — required for the plugin boundary), all `Send + Sync`. Open for external implementation (that is the point of the crate), so every public type they touch follows semver discipline: `#[non_exhaustive]` on growable structs/enums, builder-style spec construction.

**Runtime contract.** The crates are async on **Tokio** (1.x); the caller creates the runtime. Tokio appears in the public API deliberately and minimally: `StdioProcess` carries `tokio::io::{AsyncRead, AsyncWrite}` streams, and `ExecControls` carries `tokio_util::sync::CancellationToken`. The core crate spawns exactly one kind of task — the `EventDispatcher` delivery worker, which is owned (ends on drop, joinable via `shutdown`), never detached — and does no blocking I/O. Provider crates document their own spawning and blocking behavior.

**Workspace and dependency rules.** Provider and protocol crates depend on `sandbox-driver` (core); the graph is acyclic and core depends on no provider or protocol crate. Concrete SDK types (Daytona SDK, Docker client) never appear in core's public API — provider detail crosses boundaries as `ProviderError`/`provider_config` values. Features stay minimal and additive; each public item has one canonical path (the crate root re-export). All crates share the workspace MSRV (Rust 1.85) and version; everything is `publish = false` today, and publishability to crates.io is a pending decision recorded in the open questions, not an accident of config.

**Compatibility rule: only the core is required.** Identity accessors, `describe`, `start`/`stop`/`delete`, and the core facets (`exec`, `fs`) are required methods. Every optional lifecycle method ships with a provided default body returning `Error::Unsupported`, and every optional facet accessor defaults to `None` — so adding the next optional action or facet is a **non-breaking** change for external implementors. Adding a required method is a major version.

```rust
#[async_trait]
pub trait SandboxProvider: Send + Sync {
    fn kind(&self) -> &ProviderKind;                     // open string newtype, not an enum
    fn capabilities(&self) -> &Capabilities;

    async fn create(&self, spec: &SandboxSpec, events: Option<EventCallback>)
        -> Result<Arc<dyn Sandbox>, Error>;
    async fn attach(&self, id: &SandboxId, events: Option<EventCallback>)
        -> Result<Arc<dyn Sandbox>, Error>;               // re-attach by persisted ID
    async fn list(&self, filter: &SandboxFilter) -> Result<Vec<SandboxStatus>, Error>;

    fn snapshots(&self) -> Option<&dyn SnapshotProvider>;
    fn volumes(&self) -> Option<&dyn VolumeProvider>;
}
```

`create` **provisions and returns a handle** — this collapses fabro's split between `SandboxProvider::create` (provisions, discards the handle) and `SandboxSpec::build` (builds the handle, doesn't provision), whose two spec types have already drifted apart.

```rust
#[async_trait]
pub trait Sandbox: Send + Sync {
    fn id(&self) -> &SandboxId;
    fn capabilities(&self) -> &Capabilities;
    async fn describe(&self) -> Result<SandboxStatus, Error>;

    // Core lifecycle (required).
    async fn start(&self) -> Result<(), Error>;
    async fn stop(&self) -> Result<(), Error>;
    async fn delete(&self) -> Result<(), Error>;                       // idempotent

    // Optional actions. Each has a provided default body returning
    // Error::Unsupported { capability }; implementing is opt-in.
    async fn pause(&self) -> Result<(), Error>;
    async fn resume(&self) -> Result<(), Error>;
    async fn archive(&self) -> Result<(), Error>;
    async fn fork(&self, opts: &ForkOptions) -> Result<Arc<dyn Sandbox>, Error>;
    async fn checkpoint(&self, opts: &CheckpointOptions) -> Result<CheckpointId, Error>;
    async fn restore_checkpoint(&self, id: &CheckpointId) -> Result<(), Error>;
    async fn resize(&self, resources: &Resources) -> Result<(), Error>;
    async fn snapshot(&self, opts: &SandboxSnapshotOptions) -> Result<SnapshotId, Error>;
    async fn refresh_activity(&self) -> Result<(), Error>;
    async fn set_timers(&self, timers: &LifecycleTimers) -> Result<(), Error>;
    async fn set_labels(&self, labels: &BTreeMap<String, String>) -> Result<(), Error>;
    async fn update_network(&self, policy: &NetworkPolicy) -> Result<(), Error>;

    // Introspection fabro depends on
    fn working_directory(&self) -> &str;
    fn runtime_directory(&self) -> Option<&str>;          // host-tool scratch outside any checkout
    async fn platform_info(&self) -> Result<PlatformInfo, Error>;   // os, arch, version

    // Facets. exec and fs are required; the rest have provided defaults
    // (None, or the library's exec-derived implementation for search/git).
    fn exec(&self) -> &dyn Exec;
    fn fs(&self) -> &dyn Filesystem;
    fn search(&self) -> &dyn Search;                      // default: derived over exec
    fn git(&self) -> &dyn Git;                            // default: derived over exec
    fn pty(&self) -> Option<&dyn Pty>;                    // default: None
    fn logs(&self) -> Option<&dyn Logs>;                  // default: None
    fn preview_urls(&self) -> Option<&dyn PreviewUrls>;   // default: None
    fn ssh(&self) -> Option<&dyn SshAccess>;              // default: None
    fn shell_command(&self) -> Option<&dyn ShellCommand>; // default: None
    fn web_terminal(&self) -> Option<&dyn WebTerminal>;   // default: None
    fn vnc(&self) -> Option<&dyn Vnc>;                    // default: None
    fn vpn(&self) -> Option<&dyn Vpn>;                    // default: None
}
```

Why lifecycle verbs are flat methods rather than one `perform(Action)` method: callers read naturally, signatures differ (`fork` returns a handle, `checkpoint` returns an ID), and the JSON-RPC mapping is one method per verb either way. The `Unsupported` error plus capability flags carries the optionality.

### Exec (and the Bash contract)

```rust
#[async_trait]
pub trait Exec: Send + Sync {
    async fn run(&self, spec: &ExecSpec) -> Result<ExecResult, Error>;
    async fn run_streaming(&self, spec: &ExecSpec, controls: ExecControls)
        -> Result<ExecStreamingResult, Error>;
    async fn spawn_stdio(&self, spec: &SpawnSpec) -> Result<StdioProcess, Error>;  // gated: exec.stdio_process
}
```

Carried over from fabro **verbatim, as normative spec text**, because it is the load-bearing invariant of the whole system:

- `command` is Bash source, evaluated as `bash -c <command>`, non-login, no `errexit`/`pipefail`/POSIX mode, never a fallback to `sh`, never a provider's ambient shell. Callers wanting other semantics write them into the command.
- `BASH_ENV` is stripped before every invocation.
- Buffered and streaming exec must not differ in interpreter or options.
- The library ships the **bash probe** (`fabro-bash-ready` check) as a helper; the `activate` convenience runs it. This goes into the conformance suite.

`ExecSpec` is a plain owned serializable value — command, timeout, working dir, env vars, optional stdin bytes (write-then-EOF) — and is exactly what crosses the JSON-RPC boundary. Process-local control objects travel separately in `ExecControls`: the cancellation token, the async output sink, and the retention cap (head+tail with `omitted_bytes` accounting — fabro's `OutputCaptureBuffer` moves here). On the wire, controls map to negotiated IDs — a host-generated `execId` routes `exec/output` notifications and `exec/cancel` — never to serialized fields, and buffered `run` carries no streaming controls at all.

Control contracts, normative: cancellation resolves the call normally with `termination: Cancelled` after a best-effort process-group kill. The output sink is awaited per chunk — a slow consumer backpressures the read loop rather than growing an unbounded buffer; output beyond the retention cap is still drained (and counted in `omitted_bytes`), never left to block the process. A sink that returns an error cancels the exec and reports it as such. `ExecResult` keeps `streams_separated` and `live_streaming` honesty flags — Daytona's combined-output and log-polling degradations are *reported*, not hidden.

`StdioProcess` keeps fabro's shape: `AsyncWrite` stdin, `AsyncRead` stdout, bounded stderr tail collector, and a handle with `terminate()`/`wait()`. This is the facet the JSON-RPC side-channel transport exists for.

### Snapshots and volumes

```rust
#[async_trait]
pub trait SnapshotProvider: Send + Sync {
    async fn create(&self, spec: &SnapshotSpec) -> Result<SnapshotId, Error>;
        // SnapshotSource::Image(ref) | Dockerfile { content, context } | Sandbox { id, include_memory }
    async fn get(&self, id: &SnapshotId) -> Result<SnapshotStatus, Error>;   // states: building, active, error…
    async fn list(&self, filter: &SnapshotFilter) -> Result<Vec<SnapshotStatus>, Error>;
    async fn delete(&self, id: &SnapshotId) -> Result<(), Error>;
    async fn build_logs(&self, id: &SnapshotId, follow: bool, sink: LogSink) -> Result<(), Error>;
}

#[async_trait]
pub trait VolumeProvider: Send + Sync {
    async fn create(&self, spec: &VolumeSpec) -> Result<VolumeId, Error>;
    async fn get(&self, id: &VolumeId) -> Result<VolumeStatus, Error>;
    async fn list(&self) -> Result<Vec<VolumeStatus>, Error>;
    async fn delete(&self, id: &VolumeId) -> Result<(), Error>;
}
```

Volumes attach at **create time only** (`SandboxSpec.volumes: Vec<VolumeMount { volume, mount_path, subpath }>`) — Daytona has no runtime attach/detach and we don't invent one. Snapshot build progress flows through events and `build_logs`; content-addressed snapshot naming (fabro's HMAC scheme) stays in fabro — this crate takes names.

### The creation spec

```rust
pub struct SandboxSpec {
    pub name: Option<String>,
    pub source: SandboxSource,            // Image(ref) | Dockerfile { content, context } | Snapshot(id/name)
    pub resources: Option<Resources>,     // cpu cores, memory_mb, disk_mb, gpu
    pub env: BTreeMap<String, String>,
    pub labels: BTreeMap<String, String>,
    pub user: Option<String>,
    pub working_directory: Option<String>,
    pub network: NetworkPolicy,           // AllowAll | Block | CidrAllowList | DomainAllowList | proxy
    pub volumes: Vec<VolumeMount>,
    pub timers: LifecycleTimers,
    pub ephemeral: bool,                  // first-class; providers translate
    pub public: Option<bool>,
    pub region: Option<String>,
    pub provider_config: serde_json::Value,   // typed escape hatch, per provider, schema-documented
}
```

`provider_config` is the pressure valve: Daytona's GPU type preference lists, spot instances, linked sandboxes, warm-pool hints, and future boxd golden-image options live there without polluting the common spec. It crosses the JSON-RPC boundary opaquely.

**The spec is an unvalidated wire DTO, by name.** Its fields are public so it round-trips JSON-RPC, and it can express combinations no provider accepts. Validation happens at the provider boundary: every provider calls `SandboxSpec::validate()` (the cross-provider invariants — mutually exclusive idle timers, absolute mount paths, non-empty ids) and layers its own provider-specific checks, returning the typed `Error::InvalidSpec` naming the field. The builder setters are construction convenience, not an invariant guarantee.

**Not in the spec:** clone URLs, branches, tags, commit SHAs, GitHub credentials. Fabro's spec carries these today, but cloning is an orchestration recipe over `Exec` + `Git`, not a provisioning concern — it stays in fabro (with its repo-layout, pinned-revision, and retry logic).

## Events

```rust
#[non_exhaustive]
pub enum SandboxEvent {
    ActionStarted   { action: LifecycleAction },
    ActionCompleted { action: LifecycleAction, duration: Duration },
    ActionFailed    { action: LifecycleAction, error: String, causes: Vec<String> },
    SnapshotBuilding { name: String },
    SnapshotReady    { name: String, duration: Duration },
    SnapshotFailed   { name: String, error: String },
    StateChanged     { from: SandboxState, to: SandboxState },
    Progress         { action: LifecycleAction, message: String },   // image pull, snapshot poll…
}
pub type EventCallback = Arc<dyn Fn(SandboxEvent) + Send + Sync>;
```

Callback-based (fabro's model; each event maps 1:1 to a JSON-RPC notification), and the attachment is explicit in the API: `create` and `attach` take an `Option<EventCallback>` scoped to that handle for its lifetime. Failure payloads are not flat strings: `ActionFailed` and `SnapshotFailed` carry a bounded, serializable `ErrorReport { kind, message, retryable, causes }` projected from the error taxonomy (`kind` is the stable snake\_case code; raw command output never enters it), so the taxonomy survives the event and wire boundary.

Delivery has one concrete mechanism, not a convention: the library's `EventDispatcher`, owned by the provider's sandbox handle. A bounded queue (256) feeds a single worker task that invokes the callback: a slow callback backpressures only the queue, never provider internals; overflow drops only non-terminal events (`Progress`, `StateChanged`) while terminal `ActionCompleted`/`ActionFailed`/`Snapshot*` events await space and are never dropped; a panicking callback stops further delivery while the worker keeps draining so nothing blocks; the worker is owned — it ends when the dispatcher drops and is joinable via `shutdown()` — never detached. Ordering is per-sandbox in-order; no replay on re-attach (events are progress signals, not a durable log — durable state is `describe()`).

This replaces fabro's 20-variant enum with a uniform action-scoped shape; fabro's git-clone events move up with the clone logic, and long operations get `Progress` instead of only start/end.

## Errors

Per the style guide (library errors, taxonomy at layer boundaries):

```rust
#[non_exhaustive]
pub enum Error {
    NotFound { resource: ResourceKind, id: String },
    Unsupported { capability: CapabilityPath },        // machine-readable, preflightable
    InvalidState { current: SandboxState, action: LifecycleAction },
    Timeout { operation: String, elapsed: Duration },
    Auth(AuthError),
    RateLimited { retry_after: Option<Duration> },
    Exec(ExecError),                                    // bounded, classified; raw output behind accessors
    Provider(ProviderError),                            // structured provider detail, serializable
}
```

The `Exec` variant preserves fabro's redaction boundary: `Display` shows bounded classified metadata only; raw stdout/stderr is available through explicit accessors so callers control exposure. Redaction hooks stay caller-side (fabro keeps `fabro_redact`).

## What deliberately stays out of this crate

- Git credentials and push machinery: `refresh_push_credentials`, `push_token_source`, `git_push_ref` (lease/retry engine), `setup_git` intents, `resume_setup_commands`, `origin_url`.
- Clone orchestration: clone-source decisions, repo layout (`/repos/<owner>/<repo>` + symlink), pinned revisions, clone depth, clone events.
- Content-addressed snapshot naming (HMAC of manifest).
- Output redaction policy (this crate sanitizes terminal control sequences; secret redaction is the caller's).
- Fabro's run lifecycle: `initialize`-then-probe sequencing, cleanup scope guards, `--preserve-sandbox`, reconnect. These consume the crate's core + wait helper.

Each of these is implementable over `Exec`/`Git`/core — the fabro survey confirmed both remote providers already implement them via exec today.

## Fabro migration map (34 methods → new home)

| fabro `Sandbox` method(s) | New home |
| --- | --- |
| read/write/delete/exists/list/upload/download | `Filesystem` facet |
| `read_file` (numbered lines), `read_file_text` | fabro-side formatting over `Filesystem` |
| grep / walk\_files / glob | `Search` facet (derived impl in-crate) |
| exec\_command / exec\_command\_streaming / spawn\_stdio\_process | `Exec` facet |
| initialize / activate / start / stop / delete / cleanup | core lifecycle + `activate` convenience + probe helper |
| working\_directory / runtime\_directory / platform / os\_version / sandbox\_info | handle metadata + `describe()` / `platform_info()` |
| snapshot\_info | `SandboxStatus` (source snapshot field) |
| set\_autostop\_interval | `set_timers` |
| ssh\_access\_command | `Access` facet (`SshAccess` / `ShellCommand`, now distinguishable) |
| get\_preview\_url | `Access` facet (`PreviewUrls`) |
| setup\_git, git\_push\_ref, refresh\_push\_credentials, push\_token\_source, resume\_setup\_commands, origin\_url | **stays in fabro**, over `Exec` + `Git` |
| `TerminalSession` (terminal.rs) | `Pty` facet |
| `SandboxEvent` + callback | events (uniform shape) |
| `SandboxProvider` + registry | `SandboxProvider` (create now returns the handle); registry stays caller-side |

## Verification and compatibility gates

- Run a common conformance suite against every provider for lifecycle, Bash, filesystem, cancellation, and capability honesty.
- Test public workflows and JSON-RPC round trips at integration boundaries. Add property tests for protocol decoding, unknown fields, and state-transition invariants where useful.
- Verify Rust 1.85 with default, minimal, and all supported features.
- Before a public release, run semver checks and validate the package artifact. Record MSRV bumps, public dependency changes, and intentional protocol or API breaks.

## Settled (adopted defaults — flag any you disagree with)

1. **Facet accessors are separate small traits** — `Option<&dyn SshAccess>`, `Option<&dyn PreviewUrls>`, `Option<&dyn ShellCommand>`, `Option<&dyn WebTerminal>` — not one `Access` grab-bag. Matches the style guide and the per-method JSON-RPC mapping.
2. **Streaming exec sink is a callback** (object-safe, maps 1:1 to `exec/output` notifications); a `Stream` adapter is provided on top for idiomatic consumption.
3. **`create`/`attach`/`fork` return `Arc<dyn Sandbox>`** — fabro shares handles across tasks.
4. **The bash health probe is a library helper** run by the `activate` convenience, not a trait method. Providers implement exec; the probe is a contract test over it.
5. **Command sessions**: capability name reserved in the schema; no trait in v1.
6. **`Logs` is follow-style streams only** in v1; historical querying is a later capability.
7. **Workspace layout**: `crates/sandbox-driver` (core: types + traits + derived impls + wait helper), with `sandbox-driver-{protocol,host,docker,daytona}` siblings added as they are built.
8. **VNC/VPN v1 surface is "get connection info" only**; VPN join configuration is create-time spec, status via the facet.
