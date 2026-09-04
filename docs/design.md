# sandbox-driver: Rust Interface Design

A library for driving sandboxes. Initial providers: **Daytona**, **Docker**, **Host** (local). Later: boxd, Azure, and third parties via the JSON-RPC plugin protocol. Fabro is the first consumer, so fabro's current `Sandbox` trait (34 methods, `fabro-sandbox/src/sandbox.rs:1237`) is the floor: everything fabro uses must have a home here or a documented home above this crate.

## Inputs

- **fabro** — the de-facto trait: filesystem, exec (buffered / streaming / bidirectional stdio), grep/glob/walk, lifecycle, preview URLs, SSH, auto-stop, events, the bash probe, plus a git/credential surface we deliberately leave above this crate. Fabro's exec took Bash source; this library takes an argument vector and offers Bash as a helper (see Exec below).
- **Daytona** (docs + `daytona-sdk-rust`) — the richest provider: pause/resume distinct from stop/start, archive, fork with ancestry, live-sandbox snapshots including memory, TTL and four auto-intervals, snapshots and volumes as first-class resources, per-region toolbox daemon (fs/git/process/PTY/LSP/computer-use), preview links with signed URLs, SSH tokens, network block/allow lists. The normalized interface includes resize, but the current Daytona API and SDK do not expose a working resize operation.
- **boxd** (deferred) — considered only where its behavior overlaps the normalized interface. Boxd-only capabilities are not included yet.

## Security and trust boundary

"Sandbox" is a resource name here, **not a security claim** — isolation is a per-provider property, declared in `Capabilities` (`isolation: none | container | vm`) and never assumed:

- **Host is not an isolation boundary.** Commands run as the calling user; file operations can reach anything that user can, including outside the working directory. It exists for parity and local development and declares `isolation: none`.
- **Docker isolates filesystem and processes but shares the host kernel**, and the Docker socket is host-root-equivalent — the Docker provider is host-trusted by definition.
- **Daytona and boxd are VM-backed**; their isolation is the vendor's guarantee, reported as declared.

Trust flows as in the fabro plugin plan: **a provider — in-process or JSON-RPC plugin — is inside the trust domain of every sandbox it drives.** It has full exec, so it can read anything the workload can; per-call credential injection is not a defense against that. What the library does enforce is the *host-side* boundary: a provider receives only the secrets explicitly passed in a spec or fetched per-call through the host callback interface — never ambient environment or vault contents — so one provider's compromise does not expose another's credentials. Transport-level trust for plugins (checksum pinning, scrubbed environment, deny-by-default discovery) is host policy, specified in the protocol document, not this trait. The in-process Host provider applies the same posture to its own ambient environment: it clears the process env for every sandboxed command and rebuilds it through a fail-closed secret filter (safelist plus secret-name suffixes), so worker credentials never reach sandboxed code — explicit spec env is the one trusted channel for secrets.

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
    pub name: Option<String>,             // provider display name, distinct from id
    pub state: SandboxState,
    pub provider_state: String,          // raw, e.g. Daytona's "pulling_snapshot"
    pub error_reason: Option<String>,
    pub resources: Option<Resources>,
    pub sandbox_kind: Option<SandboxKind>, // observed container or virtual_machine provisioning form
    pub region: Option<String>,
    pub labels: BTreeMap<String, String>,
    pub web_url: Option<String>,         // provider console page, when one exists
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
| `pause` / `resume` | Freeze with memory kept; distinct from stop | opt | — | ✔ (`docker pause`) | ✔ (VM classes; per-sandbox caps narrow it, resume = Daytona's start) | ✔ (hibernate) |
| `archive` | Stopped → cold storage; `start` restores | opt | — | — | ✔ (container class; per-sandbox caps mask it on VM/android/windows) | — |
| `fork` | Clone a Running sandbox → new Running sandbox; preserve filesystem, memory, running processes, and PIDs | opt | — | — | ✔ (VM classes) | ✔ |
| `resize` | Change cpu/memory/disk | opt | — | \~ (`docker update`, cpu/mem only) | —² | ? |
| `snapshot` | Capture a sandbox in `Filesystem` or `LiveProcessState` mode → SnapshotProvider | opt | — | \~ (`docker commit`) | ✔ (cold/hot) | ✔ |
| `recover` | Provider-assisted recovery from Error state | opt | — | — | — | — |
| `undelete` | Restore a deleted sandbox within the recovery window; provider-level (a deleted sandbox cannot be attached), returns a fresh handle | opt | — | — | ✔ (24h, Daytona's "recover") | — |
| `refresh_activity` | Keepalive; reset idle timers | opt | no-op | no-op | ✔ | ? |
| `set_timers` | auto\_stop, auto\_pause, auto\_archive, auto\_delete, ttl | opt | — | — | ✔ | ? |
| `set_labels` | Replace label map | opt | — | ✔ | ✔ | ✔ (tags) |
| `update_network` | Change network policy on a live sandbox | opt | — | — | ✔ | ✔ |

¹ Host implements `start`/`stop` as no-ops (nothing to boot); they are still in the core so callers never branch on provider kind.

² The current Daytona API returns a route-level 404 for resize, and the
current official SDK leaves resize disabled. Daytona reports
`lifecycle.resize: false`.

Deliberate merges:

- **`activate` (fabro) is not a provider action.** It is a provided convenience: "ensure running" = describe → start if stopped/archived, or resume if paused → wait → run the health probe. Lives in the library, implemented once over the core.
- **`restore` from archive is implicit in `start`** (Daytona's model); no separate verb.
- **Ephemeral is a first-class spec flag**, not `auto_delete_interval == 0` — Daytona's encoding leaks into every wait loop (`stop` tolerating NotFound); we translate the flag per provider instead.
- **Fork has one meaning.** The source and result are Running. The clone preserves filesystem state, memory, running processes, and process IDs. There is no disk-only fork option.
- **Sandbox snapshots have explicit modes.** `Filesystem` captures persistent files without live process state. `LiveProcessState` also captures memory, running processes, and process IDs. Daytona maps these modes to its cold (`includeMemory: false`, source Stopped) and hot (`includeMemory: true`, source Running) snapshots.
- **Checkpoint and in-place restore are not public operations.** They are Boxd-only today. They can be added when Boxd work starts and a consumer needs them.
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

Timer semantics: an unset timer inherits the provider's default — Daytona's server-side auto-stop default is **15 idle minutes**, shorter than a single long inference call, so callers running long commands set it explicitly. `Duration::ZERO` is the explicit "never": it disables the timer where the provider supports disabling. Daytona encodes that per timer — `0` for auto-stop, auto-pause, and ttl, `-1` for auto-delete (whose wire `0` means delete-on-stop and is reserved for the ephemeral flag), and `0` for auto-archive, which Daytona reads as "the maximum interval" rather than disabled. All five timers map on Daytona; auto-stop and auto-pause are mutually exclusive (at most one non-zero), and enabling auto-pause via `set_timers` without mentioning auto-stop disables auto-stop first, the documented upstream sequence.

## Sandbox features (facets)

Per-sandbox functionality is grouped into small **facet traits** (per the style guide: cohesive, behavior-named, minimal). A sandbox exposes each facet through an accessor; optional facets return `Option`, so *absence is visible in the type system*, and the serializable `Capabilities` struct carries the fine-grained flags inside each facet for preflight and the wire protocol.

| Facet | Contents | Host | Docker | Daytona | boxd |
| --- | --- | --- | --- | --- | --- |
| `Exec` (core) | Buffered run; streaming run (callback sink, stdin, term/kill, timeout); literal argv, Bash as a helper | ✔ | ✔ | ✔ (streams via log-poll fallback) | ✔ |
| `StdioProcess` | Spawn long-lived bidirectional process (ACP backends) | ✔ | ✔ | ✔ (command sessions; UTF-8 payloads only — the ACP case) | ? |
| `Filesystem` (core) | read/write/delete/exists/stat/list/move/mkdir/permissions, upload/download (binary-safe, chunked) | native | native | native (toolbox FS) | ✔ |
| `Search` (core, derived) | grep, glob, walk — default impl derived from `Exec` (rg with grep/find fallback); provider may override | derived | derived | derived (native find/replace exists) | derived |
| `Git` | clone, status, add, commit, push, pull, branches, checkout — low-level plumbing only; providers hide native, derived, or hybrid selection; per-call credentials | derived | derived | hybrid: native clone, derived remainder | derived |
| `Services` (derived) | Background processes that outlive their exec (MCP servers, dev servers): spawn / status / logs / stop — default impl derived from `Exec` (`setsid` + pidfile, fabro's proven pattern); state is per-boot | derived | derived | derived | derived |
| `Pty` | create/resize/kill + bidirectional byte stream (fabro's `TerminalSession`) | ✔ | ✔ (exec+tty) | ✔ (websocket) | ✔ (console) |
| `Logs` | Provider-side logs: build/provision logs, entrypoint output, sandbox event log; streaming follow | — | ✔ (container logs) | ✔ | ? |
| `PreviewUrls` | port → `{ url, headers }`; signed expiring URLs; revocation | \~ (localhost) | future (port map) | ✔ | ✔ (HTTPS proxies) |
| `SshAccess` | Return a ready-to-run SSH command; optional exact TTL and token revocation are separate capabilities | — | — | ✔ | ✔ |
| `ShellCommand` | A local command string that opens a shell (Docker's `docker exec -it …`) — distinct from real SSH | trivial | ✔ | — | — |
| `WebTerminal` | URL to a browser terminal | — | — | ✔ | ✔ |
| `Vnc` | Desktop viewing: connection URL/credentials | — | — | ✔ (Computer Use + signed noVNC URL) | — |
| `NetworkLimits` | Spec-time: block-all / CIDR allow-list / domain allow-list / outbound proxy. Runtime update where supported | — | \~ (none/bridge only) | ✔ | ✔ |

Legend: ✔ supported · \~ partial/approximated · — unsupported (facet returns `None`) · ? unknown until boxd work starts.

Notes:

- **Services hide native-versus-derived selection.** `Sandbox::services()` returns one normalized facet or `None`. Host, Docker, and Daytona use the shared exec-derived `setsid`/pidfile implementation; a provider with native service management can override it. Derived services require `bash`, `mktemp`, `basename`, `cat`, `tail`, `seq`, and `sleep`; `setsid` is optional. Service state is per-boot, and ids from before a sandbox restart report not running.
- **Search and Git hide implementation selection.** `Sandbox::search()` and `Sandbox::git()` return normalized facets or `None`; callers never construct a fallback. Host, Docker, and Daytona derive Search through `Exec`. Search requires `find`, `grep`, and `head`; `rg` is optional acceleration. Daytona follows Fabro's battle-tested Git hybrid: native toolbox clone, then exec-derived status, add, commit, push, pull, branch, and checkout operations. Host and Docker derive every Git operation.
- **Git is a sandbox environment prerequisite.** When `git.supported` is true, the image, snapshot, or Host environment must provide a `git` executable on `PATH`. Providers do not probe for it. Daytona also requires it because only clone is native; the remaining operations use the executable. A missing executable is a non-conforming environment, not a reason for callers to choose another implementation.
- **Git here is plumbing only.** Fabro's credential machinery (`refresh_push_credentials`, `push_token_source`, `git_push_ref` retry/lease engine, `setup_git` intent, clone orchestration and repo layout) stays in fabro, layered on `Exec` + `Git`. Those 6 of fabro's 34 methods do not move into this crate.
- **Tailscale and other VPN clients are guest software.** Callers install
  and configure them through `Exec`; they are not sandbox-driver
  resources or facets.
- Daytona's **LSP, code interpreter, and computer-use input automation** are out of scope for v1 — real surfaces, but no consumer yet. The capability schema reserves names for them. Command sessions were originally deferred with them, but the Daytona provider now uses them internally as the transport for streaming, cancellation, and partial-output-on-timeout execs (plain buffered runs keep the cheaper one-shot endpoint); sessions remain unexposed as an API surface.

## Capability discovery

Two complementary mechanisms, by design:

1. **Typed accessors** — `fn pty(&self) -> Option<&dyn Pty>`: absence is unrepresentable-misuse at compile time for in-process consumers.
2. **Serializable `Capabilities`** — a data structure for preflight checks, `Unsupported` error payloads, and the JSON-RPC `initialize` handshake. Fine-grained flags live here (`exec.live_streaming`, `exec.streams_separated`, `fs.native`, `lifecycle.pause`, `snapshots.live_process_state_from_sandbox`, `network.modes`, …).

```rust
#[non_exhaustive]
pub struct Capabilities {
    pub isolation: Isolation,         // none | container | vm — declared by the provider, never assumed
    pub lifecycle: LifecycleCaps,     // pause, archive, fork, resize, recover, undelete, timers…
    pub exec: ExecCaps,               // live_streaming, streams_separated, stdin, stop, stdio_process
    pub fs: FsCaps,                   // native, upload, download, permissions
    pub search: SearchCaps,           // supported plus native diagnostic
    pub git: GitCaps,                 // supported plus native/hybrid diagnostic
    pub services: ServiceCaps,        // supported plus native diagnostic
    pub pty: Option<PtyCaps>,
    pub logs: Option<LogsCaps>,
    pub access: AccessCaps,           // preview_urls { signed }, ssh { ttl, revoke }, shell_command, web_terminal, vnc
    pub network: NetworkCaps,         // modes: block_all, allow_all, cidr_allow_list, domain_allow_list, proxy
    pub snapshots: Option<SnapshotCaps>,  // image/dockerfile × container/VM, sandbox capture modes; activation
    pub volumes: Option<VolumeCaps>,
}
```

The contract, taken from CSI and the prior fabro plan: **capabilities are load-bearing.** A missing capability changes behavior at *preflight* (the caller adapts, derives, or refuses with a message naming the provider) — never as a mid-run `Err("not supported")`, which is what fabro's silent `Ok(None)` defaults produce today and which is indistinguishable from "supported, nothing to report."

Callers use `Capabilities::supports(Capability)` for a consistent preflight check. The method maps the public capability vocabulary to the nested capability fields. Reserved or unknown capabilities return `false`.

Capabilities are **negotiated metadata, not live state**. They are captured once, at `create`/`attach` (for plugin providers, that is the JSON-RPC `initialize` handshake), and are immutable for the life of the handle — the one piece of data a handle carries besides its ID. Re-attaching yields a fresh set; that is how a provider upgrade is observed. `resize` does not change capabilities: they describe supported operations, not current resources. `SandboxProvider::capabilities()` is the provider's **upper bound** — the union of what it can offer, for pre-create decisions; the per-sandbox set (`Sandbox::capabilities()`) is authoritative and may be narrower depending on the spec (Daytona: linux-vm vs container vs android classes). Preflight catches predictable mismatches, but every capability-gated method still returns a structured `Unsupported` when a stale or misreported capability meets reality — capabilities optimize failure timing; they are not the enforcement mechanism.

### Wire compatibility

The protocol crate owns wire compatibility; domain types never absorb a wire break. The `initialize` handshake negotiates a protocol version and capability set. Readers ignore unknown optional object fields and return a structured protocol error for unknown required semantics. Enums define stable string values and an unknown-value policy. Durations, timestamps, paths, and byte payloads use explicit wire formats. Provider configuration carries a provider kind and schema version and is validated at the provider boundary. In v1 the wire DTOs may share their serde shape with core domain types, verified by behavioral compatibility tests in the protocol crate (era-JSON decoding, per-field encoding checks, `#[serde(default)]` field tolerance) and by `#[serde(other)]` unknown-variant fallbacks on state enums; when a shape needs to diverge, the protocol crate grows a dedicated DTO and conversion — core types are never broken for wire reasons.

## The traits

Sketches, not final signatures. All async via `async_trait`, all object-safe (`dyn`-usable — required for the plugin boundary), all `Send + Sync`. Open for external implementation (that is the point of the crate), so every public type they touch follows semver discipline: `#[non_exhaustive]` on growable structs/enums, builder-style spec construction.

**Runtime contract.** The crates are async on **Tokio** (1.x); the caller creates the runtime. Tokio appears in the public API deliberately and minimally: `StdioProcess` carries `tokio::io::{AsyncRead, AsyncWrite}` streams, and `ExecControls` carries `tokio_util::sync::CancellationToken`. The core crate spawns no tasks and does no blocking I/O. Event observation is awaited directly. Provider and protocol crates document their own task and blocking behavior.

**Workspace and dependency rules.** Provider and protocol crates depend on `sandbox-driver` (core); the graph is acyclic and core depends on no provider or protocol crate. Concrete SDK types (Daytona SDK, Docker client) never appear in core's public API — provider detail crosses boundaries as `ProviderError`/`provider_config` values. Features stay minimal and additive; each public item has one canonical path (the crate root re-export). All crates share the workspace MSRV (Rust 1.85) and version; everything is `publish = false` today, and publishability to crates.io is a pending decision recorded in the open questions, not an accident of config.

**Compatibility rule: only the core is required.** Identity accessors, `describe`, `start`/`stop`/`delete`, and the core facets (`exec`, `fs`) are required methods. Every optional lifecycle method ships with a provided default body returning `Error::Unsupported`, and every optional facet accessor defaults to `None` — so adding the next optional action or facet is a **non-breaking** change for external implementors. Adding a required method is a major version.

```rust
#[async_trait]
pub trait SandboxProvider: Send + Sync {
    fn kind(&self) -> &ProviderKind;                     // open string newtype, not an enum
    fn capabilities(&self) -> &Capabilities;

    async fn create(&self, spec: &SandboxSpec, events: Option<EventContext>)
        -> Result<Arc<dyn Sandbox>, Error>;
    async fn attach(&self, id: &SandboxId, events: Option<EventContext>)
        -> Result<Arc<dyn Sandbox>, Error>;               // re-attach by persisted ID
    async fn undelete(&self, id: &SandboxId, events: Option<EventContext>)
        -> Result<Arc<dyn Sandbox>, Error>;               // optional; restore a deleted sandbox
    async fn delete(&self, id: &SandboxId, events: Option<EventContext>)
        -> Result<(), Error>;                             // by id, no handle; idempotent; default = attach + delete
    async fn list(&self, filter: &SandboxFilter) -> Result<Vec<SandboxStatus>, Error>;

    /// Reachability + credential check for preflight and diagnostics.
    /// Always callable; an unhealthy provider is an Ok(report), never Err.
    async fn health(&self) -> Result<ProviderHealth, Error>;
        // ProviderHealth { status: ok|unreachable|unauthorized|unknown,
        //                  message, missing_permissions }

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
    fn search(&self) -> Option<SearchFacet<'_>>;          // provider selects native or derived
    fn git(&self) -> Option<GitFacet<'_>>;                // provider selects native, hybrid, or derived
    fn services(&self) -> Option<ServicesFacet<'_>>;      // provider selects native or derived
    fn pty(&self) -> Option<&dyn Pty>;                    // default: None
    fn logs(&self) -> Option<&dyn Logs>;                  // default: None
    fn preview_urls(&self) -> Option<&dyn PreviewUrls>;   // default: None
    fn ssh(&self) -> Option<&dyn SshAccess>;              // default: None
    fn shell_command(&self) -> Option<&dyn ShellCommand>; // default: None
    fn web_terminal(&self) -> Option<&dyn WebTerminal>;   // default: None
    fn vnc(&self) -> Option<&dyn Vnc>;                    // default: None
}
```

Why lifecycle verbs are flat methods rather than one `perform(Action)` method: callers read naturally, signatures differ (`fork` returns a handle and `snapshot` returns an ID), and the JSON-RPC mapping is one method per verb either way. The `Unsupported` error plus capability flags carries the optionality.

### Exec (and the argv contract)

```rust
#[async_trait]
pub trait Exec: Send + Sync {
    async fn run(&self, spec: &ExecSpec) -> Result<ExecResult, Error>;
    async fn run_streaming(&self, spec: &ExecSpec, controls: ExecControls)
        -> Result<ExecStreamingResult, Error>;
    async fn spawn_stdio(&self, spec: &SpawnSpec) -> Result<StdioProcess, Error>;  // gated: exec.stdio_process
}
```

The normative contract, and the load-bearing invariant of the whole system:

- `ExecSpec` names a `program` and its `args`. A provider executes that vector directly, with `execvp` semantics: the program is resolved through the command's `PATH` when it has no slash, and every argument reaches the process unchanged. No shell is involved anywhere, so nothing is split, globbed, or expanded. A provider whose backend only takes a shell string (Daytona) quotes the vector so it stays literal.
- Buffered and streaming exec must not differ in how the vector is run.
- **Bash is a helper, not a provider rule.** `ExecSpec::bash(script)` is the argv `bash -c <script>`, non-login, with Bash's options untouched (no `errexit`/`pipefail`/POSIX mode) and `BASH_ENV` blanked in the spec env. It is the one place the old Bash contract is written down. The exec-derived facets (filesystem, search, git, services) are Bash scripts and use it, so a sandbox that serves them needs `bash` on `PATH`; a caller that only runs its own programs (Petri's step runner) needs nothing but the program.
- Providers still blank `BASH_ENV` at the sandbox level (Docker container env, Daytona sandbox env, the host's inherited env), because an image can carry the variable and a caller may send `bash -c` by hand.
- The library ships the **bash probe** (`fabro-bash-ready` check) as a helper; the `activate` convenience runs it. It verifies the helper works in a sandbox, and goes into the conformance suite.

This replaced fabro's rule that every command is Bash source. That rule made the primary consumer quote `exec 'prog' 'arg'…` into a script only for the provider to wrap it in a shell again, forced a per-image "which shell" setting on Docker, and made `attach` run a probe exec. An argv contract has none of that.

`ExecSpec` is a plain owned serializable value — program, args, timeout, working dir, env vars, optional stdin bytes (write-then-EOF), and output sanitization — and is exactly what crosses the JSON-RPC boundary. `OutputSanitization` has three policies: `Raw` preserves every byte and is the default; `StripAnsi` removes ANSI terminal escape sequences but preserves standalone control characters; `StripAll` also removes standalone C0/C1 control characters except tab, line feed, and carriage return. Providers apply the policy before output reaches the sink, retained result, or capture statistics. Stateful filtering prevents an escape sequence from leaking when it spans streaming chunks. The policies apply only to `run` and `run_streaming`; PTY sessions and long-lived bidirectional stdio remain raw. Non-raw policies are lossy and callers must use `Raw` for binary output.

A relative working dir resolves against the sandbox working directory on every provider — a conformance case pins it. Process-local control objects travel separately in `ExecControls`: the `term` and `kill` stop tokens, the async output sink, and the retention cap (head+tail with `omitted_bytes` accounting — fabro's `OutputCaptureBuffer` moves here). On the wire, controls map to negotiated IDs — a host-generated `execId` routes `exec/output` notifications and `exec/stop` — never to serialized fields, and buffered `run` carries no streaming controls at all.

Control contracts, normative: **stops are signals, not a policy.** `term` sends SIGTERM to the command's process group once and the call keeps waiting; the command may exit (`termination: Cancelled`) or ignore it until `kill` sends SIGKILL (`termination: Killed`). The escalation ladder — TERM, a grace so traps run and locks release (a killed `git` otherwise leaves `.git/index.lock`), then KILL — belongs to the caller, who knows how long to wait; the library used to run one of its own under a `cancel` token, which made the primary consumer's ladder and the provider's race each other. The provider's own stops (`spec.timeout`, a failing sink) have no caller present to escalate, so they kill. A provider that cannot deliver a signal (Daytona ends a command by deleting its session) ends the command on either token and reports the level it received. A provider that does not support stdin or stops rejects a call that supplies them with `Unsupported` (`exec.stdin` / `exec.stop`) — never runs the command with the input silently dropped. The output sink is awaited per chunk — a slow consumer backpressures the read loop rather than growing an unbounded buffer; output beyond the retention cap is still drained (and counted in `omitted_bytes`), never left to block the process. A sink that returns an error cancels the exec and reports it as such. `ExecResult` keeps `streams_separated` and `live_streaming` honesty flags — Daytona's combined-output and log-polling degradations are *reported*, not hidden.

`StdioProcess` keeps fabro's shape: `AsyncWrite` stdin, `AsyncRead` stdout, bounded stderr tail collector, and a handle with `terminate()`/`wait()`. This is the facet the JSON-RPC side-channel transport exists for.

### Snapshots and volumes

```rust
#[async_trait]
pub trait SnapshotProvider: Send + Sync {
    async fn create(&self, spec: &SnapshotSpec) -> Result<SnapshotId, Error>;
        // SnapshotSource::Image(ref) | Dockerfile { content } | Sandbox { id, mode }
    async fn get(&self, id: &SnapshotId) -> Result<SnapshotStatus, Error>;   // states: building, active, error…
    async fn list(&self, filter: &SnapshotFilter) -> Result<Vec<SnapshotStatus>, Error>;
    async fn delete(&self, id: &SnapshotId) -> Result<(), Error>;
    async fn build_logs(&self, id: &SnapshotId, follow: bool, sink: LogSink) -> Result<(), Error>;
    // Gated on snapshots.activation: Daytona deactivates snapshots unused
    // for two weeks; content-addressed reuse needs a way back.
    async fn activate(&self, id: &SnapshotId) -> Result<(), Error>;
    async fn deactivate(&self, id: &SnapshotId) -> Result<(), Error>;
}

pub struct SnapshotSpec {
    pub name: Option<String>,
    pub source: SnapshotSource,
    pub sandbox_kind: Option<SandboxKind>,
    pub region: Option<String>,
    pub resources: Resources,
    pub provider_config: serde_json::Value,
}

pub struct SnapshotStatus {
    pub id: SnapshotId,
    pub state: SnapshotState,
    pub sandbox_kind: Option<SandboxKind>,
    pub regions: Vec<String>,
    pub resources: Option<Resources>,
    // …name, error, size, timestamps
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

`SandboxKind` selects the provisioning form: `Container` or `VirtualMachine`. It is separate from `Isolation`, which describes the provider's security boundary. `SnapshotSpec.sandbox_kind` selects the snapshot class. `SandboxSpec.sandbox_kind` is a required-result constraint: a provider must honor it or reject the request. It must not silently change the kind or create a hidden intermediate snapshot. Daytona supports image-based snapshots for both kinds and Dockerfile-based snapshots for containers only. A Daytona sandbox created from a snapshot inherits that snapshot's class; the provider validates a requested kind before and after creation.

### The creation spec

```rust
pub struct SandboxSpec {
    pub name: Option<String>,
    pub source: SandboxSource,            // Image(ref) | Dockerfile { content } | Snapshot { id }
    pub resources: Resources,             // optional cpu_cores, memory_mb, disk_mb, gpus fields
    pub sandbox_kind: Option<SandboxKind>, // required result when set
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

`provider_config` is the pressure valve: Daytona's GPU type preference lists, spot instances, linked sandboxes, warm-pool hints, and future boxd golden-image options live there without polluting the common spec. It crosses the JSON-RPC boundary opaquely. Each provider crate exports its shape as a type — the Docker provider's `DockerProviderConfig` with `into_value()` — so an in-process consumer builds it type-checked and the provider parses it back through the same type; only the wire sees untyped JSON.

`working_directory` is the final workspace directory chosen before creation. A provider creates it when needed, uses it as the default for relative file and process operations, and returns the same value from handles created by `attach`. The Host provider treats an explicit path as caller-owned and does not delete it.

When `runtime_directory()` returns a path, the provider creates that directory outside the workspace with owner-only permissions (`0700`) before returning from `create`. The path remains stable across `attach`. Host returns `None`; Docker and Daytona return `/tmp/sandbox-driver/runtime` inside the sandbox.

**The spec is an unvalidated serializable request.** Its fields are public and it can express combinations no provider accepts. The protocol adapter maps it to the stable version-1 wire DTO; in particular, the public typed snapshot `id` still crosses as `source.snapshot.name`. Validation happens at the provider boundary: every provider calls `SandboxSpec::validate()` (the cross-provider invariants — known sandbox kind, mutually exclusive idle timers, absolute mount paths, non-empty ids) and layers its own provider-specific checks, returning the typed `Error::InvalidSpec` naming the field. A provider must reject every explicit value it cannot honor; it must never silently ignore a requested resource, identity, lifecycle, network, access, region, or provider-specific setting. The builder setters are construction convenience, not an invariant guarantee.

**Not in the spec:** clone URLs, branches, tags, commit SHAs, GitHub credentials. Fabro's spec carries these today, but cloning is an orchestration recipe over `Exec` + `Git`, not a provisioning concern — it stays in fabro (with its repo-layout, pinned-revision, and retry logic).

## Events

```rust
#[non_exhaustive]
pub struct Event {
    pub id: EventId,                    // source_id + monotonic sequence
    pub occurred_at: SystemTime,
    pub provider: ProviderKind,
    pub subject: EventSubject,          // provider | sandbox | snapshot | volume
    pub operation_id: Option<OperationId>,
    pub correlation_id: Option<CorrelationId>,
    pub body: EventBody,
}

#[non_exhaustive]
pub enum EventBody {
    OperationStarted { action: Action },
    OperationProgress { action: Action, progress: Progress },
    OperationCompleted { action: Action, duration: Duration },
    OperationFailed { action: Action, duration: Duration, error: ErrorReport },
    StateObserved { previous: Option<ResourceState>, current: ResourceState },
    Notice { code: String, message: String },
    Unknown,
}

#[async_trait]
pub trait EventObserver: Send + Sync {
    async fn observe(&self, event: Event);
}
```

`Event` is the one public event type for all sandbox-driver control-plane facts. Consumers can qualify it as `sandbox_driver::Event` or alias the import. Exec output, PTY bytes, file-transfer chunks, and logs stay on their dedicated streaming APIs.

The attachment is explicit. `create`, `attach`, and `undelete` take an optional `EventContext`, which the returned sandbox handle retains. Snapshot and volume mutation methods also take an optional context. Clones of one context share an event source and sequence space. A consumer can add an opaque `CorrelationId` to associate events with its run, job, or request.

`EventEmitter::run` is the provider-side lifecycle boundary. Once an operation is accepted, it emits `OperationStarted` and exactly one `OperationCompleted` or `OperationFailed` with the same `OperationId`. The terminal event is observed before the method returns. Durations measure the real operation. A create operation starts with a name-only subject when necessary and updates the terminal subject after the provider assigns the resource ID. Long operations use structured `Progress` values with stable codes; display messages are not control data. Failures carry a bounded `ErrorReport { kind, message, retryable, causes }`, so the error taxonomy survives the event and wire boundary.

Delivery is direct and ordered. `EventContext` assigns a monotonic sequence and awaits the async observer. It has no hidden queue, worker, detached task, overflow policy, or silent drop path. A slow observer therefore applies backpressure at the documented handoff boundary. The observer decides whether that handoff means an in-memory enqueue, durable persistence, or immediate processing.

sandbox-driver does not store or replay events. A consumer that needs a durable event log persists events in its observer. Re-attach starts a new live source. `describe()` and the snapshot and volume status methods remain authoritative for current durable resource state. This keeps operation telemetry separate from state reconciliation.

## Errors

Per the style guide (library errors, taxonomy at layer boundaries):

```rust
#[non_exhaustive]
pub enum Error {
    NotFound { resource: ResourceKind, id: String },
    Unsupported { capability: CapabilityPath },        // machine-readable, preflightable
    InvalidState { current: SandboxState, action: Action },
    InvalidSpec { field: String, reason: String },
    Timeout { operation: String, elapsed: Duration },
    Auth(AuthError),
    RateLimited { retry_after: Option<Duration> },
    Exec(ExecError),                                    // bounded, classified; raw output behind accessors
    Provider(ProviderError),                            // structured provider detail, serializable
    Transport(TransportError),                          // out-of-process provider communication
    Io { context: String, source: io::Error },          // local filesystem and process I/O
}
```

The `Exec` variant preserves fabro's redaction boundary: `Display` shows bounded classified metadata only; raw stdout/stderr is available through explicit accessors so callers control exposure. Redaction hooks stay caller-side (fabro keeps `fabro_redact`).

Provider adapters retain SDK errors as opaque sources on `AuthError` and
`ProviderError`. The protocol adapter classifies framing, encoding, and
connection failures as `Transport`. It reconstructs every public error
variant and its rendered remote source chain at the process boundary.

## What deliberately stays out of this crate

- Git credentials and push machinery: `refresh_push_credentials`, `push_token_source`, `git_push_ref` (lease/retry engine), `setup_git` intents, `resume_setup_commands`, `origin_url`.
- Clone orchestration: clone-source decisions, repo layout (`/repos/<owner>/<repo>` + symlink), pinned revisions, clone depth, clone events.
- Content-addressed snapshot naming (HMAC of manifest).
- Secret redaction policy: output sanitization is portable through `ExecSpec`, but provider-independent secret detection and redaction remain the caller's responsibility.
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
| sandbox events + callback | `Event` + `EventObserver` (uniform resource shape) |
| `SandboxProvider` + registry | `SandboxProvider` (create now returns the handle); registry stays caller-side |

## Verification and compatibility gates

- Run a common conformance suite against every provider for lifecycle, Bash, filesystem, term and kill, and capability honesty.
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
8. **VNC v1 returns browser connection information.** VPN clients are
   guest software managed through exec.
9. **The Docker image contract requires `setsid`** alongside bash, `stat`, `find`, and `base64` — reliable kill semantics need a separate session, and an image without it fails every exec with a clear message rather than degrading silently.
10. **`recover` and `undelete` are separate verbs.** `recover` repairs a live sandbox in the `Error` state; `undelete` (provider-level, returns a fresh handle) restores a deleted one. Daytona's "recover" endpoint is our `undelete`; it declares `lifecycle.recover: false`.
11. **Chunked file transfer is `read_range`/`write_append`**, not a streaming transfer protocol: stateless, additive on `fs/read`/`fs/write`, with efficient overrides per provider (seek on Host, `tail`/`>>` on exec-derived) and correct read-and-slice / read-concat-write defaults everywhere else.
12. **The event envelope owns operation identity.** Each accepted operation gets an `OperationId`; a wire-only `route_id` sends early create events to the correct observer before a resource ID exists. The optional consumer `CorrelationId` crosses the wire unchanged. Cancellation of long operations is a later additive step.
13. **Provider health is a report, not an error**: `health()` always answers; non-`ok` statuses (`unreachable`, `unauthorized` with `missing_permissions`) are successful responses, and `Err` is reserved for the check itself failing.
14. **Git is an environment prerequisite when advertised.** Images and snapshots used by Docker or Daytona, and the Host process environment, provide `git` on `PATH`. Providers do not probe for it or change immutable capabilities based on guest package discovery.
15. **Services are normalized when advertised.** `services.supported` reports complete availability; `services.native` is diagnostic only. The sandbox chooses the provider implementation or `DerivedServices`, so consumers never construct the fallback.
16. **Search is normalized when advertised.** `search.supported` reports complete availability; `search.native` is diagnostic only. The sandbox chooses the provider implementation or `DerivedSearch`. Derived Search requires `find`, `grep`, and `head`; `rg` remains optional.
